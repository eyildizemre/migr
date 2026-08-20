#define _GNU_SOURCE

#include "sidecar.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char sidecar_magic[] = SIDECAR_MAGIC;
#define SIDECAR_STRINGIFY_VALUE(value) #value
#define SIDECAR_STRINGIFY(value) SIDECAR_STRINGIFY_VALUE(value)
static const unsigned char sidecar_header_version[] = SIDECAR_STRINGIFY(SIDECAR_VERSION);

static const char tag_entry[] = "ENTRY";
static const char tag_xattr[] = "XATTR";
static const char tag_entry_commit[] = "ENTRY_COMMIT";
static const char tag_delete[] = "DELETE";
static const char tag_claim[] = "CLAIM";

static const char kind_regular[] = "regular";
static const char kind_directory[] = "directory";
static const char kind_fifo[] = "fifo";
static const char kind_symlink[] = "symlink";
static const char kind_hardlink[] = "hardlink";

#ifdef SIDECAR_TEST_HOOKS
static volatile sig_atomic_t sidecar_test_interrupt_point =
    SIDECAR_TEST_INTERRUPT_NONE;

void sidecar_test_set_interrupt(SidecarTestInterruptPoint point)
{
    sidecar_test_interrupt_point = point;
}
#endif

#define SIDECAR_TAG_MAX 32U
#define SIDECAR_KIND_MAX 32U
#define SIDECAR_READ_BUFFER 16384U

typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
} SidecarBuffer;

typedef struct {
    size_t size;
} AllocationHeader;

typedef struct {
    uint64_t current;
    uint64_t peak;
} AllocationTracker;

typedef struct {
    int fd;
    uint64_t limit;
    uint64_t file_position;
    uint64_t consumed;
    unsigned char buffer[SIDECAR_READ_BUFFER];
    size_t buffer_position;
    size_t buffer_length;
    AllocationTracker allocations;
} SidecarReader;

typedef enum {
    FIELD_OK = 0,
    FIELD_EOF,
    FIELD_TAIL,
    FIELD_IO,
    FIELD_LIMIT,
    FIELD_ALLOCATION
} FieldStatus;

static int bytes_equal(SidecarBytes left, const char *right)
{
    size_t length = strlen(right);
    return left.length == length &&
           (length == 0 || memcmp(left.data, right, length) == 0);
}

static int bytes_have_nul(SidecarBytes bytes)
{
    return bytes.length > 0 && memchr(bytes.data, '\0', bytes.length) != NULL;
}

static int validate_bytes(SidecarBytes bytes, size_t maximum, int nonempty)
{
    if (bytes.length > maximum || (bytes.length > 0 && bytes.data == NULL) ||
        (nonempty && bytes.length == 0) || bytes_have_nul(bytes))
        return -1;
    return 0;
}

static void set_size_error(void)
{
    errno = E2BIG;
}

static void set_invalid_error(void)
{
    errno = EINVAL;
}

static void *tracked_alloc(AllocationTracker *tracker, size_t size)
{
    if (tracker == NULL || size == 0 ||
        tracker->current > SIDECAR_MAX_ALLOC_BUDGET ||
        (uint64_t)size > SIDECAR_MAX_ALLOC_BUDGET - tracker->current ||
        size > SIZE_MAX - sizeof(AllocationHeader))
    {
        if (tracker != NULL)
            set_size_error();
        return NULL;
    }

    AllocationHeader *header = malloc(sizeof(*header) + size);
    if (header == NULL)
        return NULL;

    header->size = size;
    tracker->current += size;
    if (tracker->current > tracker->peak)
        tracker->peak = tracker->current;
    return header + 1;
}

static void tracked_free(AllocationTracker *tracker, void *pointer)
{
    if (tracker == NULL || pointer == NULL)
        return;

    AllocationHeader *header = (AllocationHeader *)pointer - 1;
    if (header->size <= tracker->current)
        tracker->current -= header->size;
    else
        tracker->current = 0;
    free(header);
}

static void buffer_free(SidecarBuffer *buffer)
{
    if (buffer == NULL)
        return;
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int buffer_reserve(SidecarBuffer *buffer, size_t additional)
{
    if (buffer == NULL || additional > SIZE_MAX - buffer->length)
    {
        set_size_error();
        return -1;
    }

    size_t needed = buffer->length + additional;
    if ((uint64_t)needed > SIDECAR_MAX_ALLOC_BUDGET ||
        (uint64_t)needed > SIDECAR_MAX_TOTAL_BYTES)
    {
        set_size_error();
        return -1;
    }
    if (needed <= buffer->capacity)
        return 0;

    size_t capacity = buffer->capacity == 0 ? 256U : buffer->capacity;
    while (capacity < needed)
    {
        if (capacity > SIZE_MAX / 2)
        {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    if ((uint64_t)capacity > SIDECAR_MAX_ALLOC_BUDGET)
        capacity = needed;

    unsigned char *data = realloc(buffer->data, capacity);
    if (data == NULL)
        return -1;
    buffer->data = data;
    buffer->capacity = capacity;
    return 0;
}

static int buffer_append(SidecarBuffer *buffer, const void *data, size_t length)
{
    if (length == 0)
        return 0;
    if (data == NULL || buffer_reserve(buffer, length) != 0)
        return -1;
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

static int buffer_append_field(SidecarBuffer *buffer, SidecarBytes field)
{
    unsigned char zero = 0;
    return buffer_append(buffer, field.data, field.length) == 0 &&
           buffer_append(buffer, &zero, 1) == 0 ? 0 : -1;
}

static int buffer_append_tag(SidecarBuffer *buffer, const char *tag)
{
    SidecarBytes field = {
        .data = (const unsigned char *)tag,
        .length = strlen(tag)
    };
    return buffer_append_field(buffer, field);
}

static int buffer_append_uint(SidecarBuffer *buffer, uint64_t value)
{
    char text[3U * sizeof(uint64_t) + 3U];
    int length = snprintf(text, sizeof(text), "%" PRIu64, value);
    if (length < 0 || (size_t)length >= sizeof(text))
        return -1;
    SidecarBytes field = {
        .data = (const unsigned char *)text,
        .length = (size_t)length
    };
    return buffer_append_field(buffer, field);
}

static int buffer_append_int(SidecarBuffer *buffer, int64_t value)
{
    char text[3U * sizeof(uint64_t) + 3U];
    int length = snprintf(text, sizeof(text), "%" PRId64, value);
    if (length < 0 || (size_t)length >= sizeof(text))
        return -1;
    SidecarBytes field = {
        .data = (const unsigned char *)text,
        .length = (size_t)length
    };
    return buffer_append_field(buffer, field);
}

static int write_all(int fd, const unsigned char *data, size_t length)
{
    size_t written = 0;
    while (written < length)
    {
        ssize_t result = write(fd, data + written, length - written);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
        {
            if (result == 0)
                errno = EIO;
            return -1;
        }
        written += (size_t)result;
    }
    return 0;
}

static int append_buffer(int fd, const SidecarBuffer *buffer,
                         int record_type)
{
#ifndef SIDECAR_TEST_HOOKS
    (void)record_type;
#endif
    if (fd < 0 || buffer == NULL || buffer->data == NULL || buffer->length == 0)
    {
        set_invalid_error();
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0)
        return -1;
    uint64_t current = (uint64_t)st.st_size;
    if (current > SIDECAR_MAX_TOTAL_BYTES ||
        (uint64_t)buffer->length > SIDECAR_MAX_TOTAL_BYTES - current)
    {
        set_size_error();
        return -1;
    }

    if (lseek(fd, 0, SEEK_END) < 0)
        return -1;

#ifdef SIDECAR_TEST_HOOKS
    SidecarTestInterruptPoint before = SIDECAR_TEST_INTERRUPT_NONE;
    SidecarTestInterruptPoint after = SIDECAR_TEST_INTERRUPT_NONE;
    SidecarTestInterruptPoint middle = SIDECAR_TEST_INTERRUPT_NONE;
    if (record_type == SIDECAR_RECORD_ENTRY) {
        before = SIDECAR_TEST_BEFORE_ENTRY;
        after = SIDECAR_TEST_AFTER_ENTRY;
        middle = SIDECAR_TEST_MID_ENTRY;
    } else if (record_type == SIDECAR_RECORD_XATTR) {
        before = SIDECAR_TEST_BEFORE_XATTR;
        after = SIDECAR_TEST_AFTER_XATTR;
        middle = SIDECAR_TEST_MID_XATTR;
    } else if (record_type == SIDECAR_RECORD_ENTRY_COMMIT) {
        before = SIDECAR_TEST_BEFORE_ENTRY_COMMIT;
        after = SIDECAR_TEST_AFTER_ENTRY_COMMIT;
        middle = SIDECAR_TEST_MID_ENTRY_COMMIT;
    } else if (record_type == SIDECAR_RECORD_DELETE) {
        before = SIDECAR_TEST_BEFORE_DELETE;
        after = SIDECAR_TEST_AFTER_DELETE;
        middle = SIDECAR_TEST_MID_DELETE;
    } else if (record_type == SIDECAR_RECORD_CLAIM) {
        before = SIDECAR_TEST_BEFORE_CLAIM;
        after = SIDECAR_TEST_AFTER_CLAIM;
        middle = SIDECAR_TEST_MID_CLAIM;
    }
    if (before != SIDECAR_TEST_INTERRUPT_NONE &&
        sidecar_test_interrupt_point == (sig_atomic_t)before)
        (void)kill(getpid(), SIGKILL);
    if (middle != SIDECAR_TEST_INTERRUPT_NONE &&
        sidecar_test_interrupt_point == (sig_atomic_t)middle) {
        size_t partial = buffer->length / 2U;
        if (partial == 0)
            partial = 1U;
        if (write_all(fd, buffer->data, partial) != 0)
            return -1;
        (void)kill(getpid(), SIGKILL);
    }
#endif

    int result = write_all(fd, buffer->data, buffer->length);
#ifdef SIDECAR_TEST_HOOKS
    if (result == 0 && after != SIDECAR_TEST_INTERRUPT_NONE &&
        sidecar_test_interrupt_point == (sig_atomic_t)after)
        (void)kill(getpid(), SIGKILL);
#endif
    return result;
}

static int validate_entry(const SidecarEntry *entry)
{
    if (entry == NULL ||
        validate_bytes(entry->root_id, SIDECAR_MAX_ROOT_ID, 1) != 0 ||
        validate_bytes(entry->logical_path, SIDECAR_MAX_PATH, 0) != 0 ||
        validate_bytes(entry->physical_path, SIDECAR_MAX_PATH, 0) != 0 ||
        validate_bytes(entry->collision_suffix,
                       SIDECAR_MAX_COLLISION_SUFFIX, 0) != 0 ||
        entry->atime_nsec > SIDECAR_MAX_NSEC ||
        entry->mtime_nsec > SIDECAR_MAX_NSEC ||
        entry->mode > SIDECAR_MAX_MODE ||
        entry->xattr_count > SIDECAR_MAX_XATTRS_PER_ENTRY)
    {
        set_invalid_error();
        return -1;
    }

    if (entry->kind < SIDECAR_KIND_REGULAR ||
        entry->kind > SIDECAR_KIND_HARDLINK)
    {
        set_invalid_error();
        return -1;
    }
    if (entry->kind != SIDECAR_KIND_REGULAR && entry->size != 0)
    {
        set_invalid_error();
        return -1;
    }
    if (entry->kind == SIDECAR_KIND_SYMLINK)
    {
        if (validate_bytes(entry->symlink_target,
                           SIDECAR_MAX_SYMLINK_TARGET, 1) != 0 ||
            entry->hardlink_root_id.length != 0 ||
            entry->hardlink_logical_path.length != 0)
        {
            set_invalid_error();
            return -1;
        }
    }
    else if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        if (entry->symlink_target.length != 0 ||
            entry->xattr_count != 0 ||
            validate_bytes(entry->hardlink_root_id, SIDECAR_MAX_ROOT_ID, 1) != 0 ||
            validate_bytes(entry->hardlink_logical_path, SIDECAR_MAX_PATH, 1) != 0)
        {
            set_invalid_error();
            return -1;
        }
    }
    else if (entry->symlink_target.length != 0 ||
             entry->hardlink_root_id.length != 0 ||
             entry->hardlink_logical_path.length != 0)
    {
        set_invalid_error();
        return -1;
    }
    return 0;
}

static int validate_xattr(const SidecarXattr *xattr)
{
    if (xattr == NULL ||
        validate_bytes(xattr->name, SIDECAR_MAX_XATTR_NAME, 1) != 0 ||
        xattr->value.length > SIDECAR_MAX_XATTR_VALUE ||
        (xattr->value.length > 0 && xattr->value.data == NULL))
    {
        set_invalid_error();
        return -1;
    }
    return 0;
}

static int validate_delete(const SidecarDelete *deletion)
{
    if (deletion == NULL ||
        validate_bytes(deletion->root_id, SIDECAR_MAX_ROOT_ID, 1) != 0 ||
        validate_bytes(deletion->logical_path, SIDECAR_MAX_PATH, 0) != 0)
    {
        set_invalid_error();
        return -1;
    }
    return 0;
}

static int claim_kind_valid(SidecarObjectKind kind)
{
    return kind == SIDECAR_KIND_REGULAR ||
           kind == SIDECAR_KIND_DIRECTORY ||
           kind == SIDECAR_KIND_SYMLINK ||
           kind == SIDECAR_KIND_HARDLINK;
}

static int validate_claim(const SidecarClaim *claim)
{
    if (claim == NULL ||
        validate_bytes(claim->root_id, SIDECAR_MAX_ROOT_ID, 1) != 0 ||
        validate_bytes(claim->logical_path, SIDECAR_MAX_PATH, 0) != 0 ||
        validate_bytes(claim->physical_path, SIDECAR_MAX_PATH, 0) != 0 ||
        !claim_kind_valid(claim->kind))
    {
        set_invalid_error();
        return -1;
    }
    return 0;
}

static int build_entry_buffer(const SidecarEntry *entry, SidecarBuffer *buffer)
{
    if (validate_entry(entry) != 0)
        return -1;
    const char *kind = sidecar_object_kind_name(entry->kind);
    if (kind == NULL)
    {
        set_invalid_error();
        return -1;
    }

    if (buffer_append_tag(buffer, tag_entry) != 0 ||
        buffer_append_field(buffer, entry->root_id) != 0 ||
        buffer_append_field(buffer, entry->logical_path) != 0 ||
        buffer_append_field(buffer, entry->physical_path) != 0 ||
        buffer_append_field(buffer, entry->collision_suffix) != 0 ||
        buffer_append_field(buffer, (SidecarBytes){
            (const unsigned char *)kind, strlen(kind) }) != 0 ||
        buffer_append_uint(buffer, entry->mode) != 0 ||
        buffer_append_uint(buffer, entry->uid) != 0 ||
        buffer_append_uint(buffer, entry->gid) != 0 ||
        buffer_append_int(buffer, entry->atime_sec) != 0 ||
        buffer_append_uint(buffer, entry->atime_nsec) != 0 ||
        buffer_append_int(buffer, entry->mtime_sec) != 0 ||
        buffer_append_uint(buffer, entry->mtime_nsec) != 0 ||
        buffer_append_uint(buffer, entry->size) != 0 ||
        buffer_append_uint(buffer, entry->xattr_count) != 0)
        return -1;

    if (entry->kind == SIDECAR_KIND_SYMLINK)
    {
        if (buffer_append_field(buffer, entry->symlink_target) != 0)
            return -1;
    }
    else if (entry->kind == SIDECAR_KIND_HARDLINK &&
             (buffer_append_field(buffer, entry->hardlink_root_id) != 0 ||
              buffer_append_field(buffer, entry->hardlink_logical_path) != 0))
        return -1;
    return 0;
}

static int build_xattr_buffer(const SidecarXattr *xattr, SidecarBuffer *buffer)
{
    if (validate_xattr(xattr) != 0 ||
        buffer_append_tag(buffer, tag_xattr) != 0 ||
        buffer_append_field(buffer, xattr->name) != 0 ||
        buffer_append_uint(buffer, xattr->value.length) != 0 ||
        buffer_append(buffer, xattr->value.data, xattr->value.length) != 0)
        return -1;
    return 0;
}

static int build_claim_buffer(const SidecarClaim *claim, SidecarBuffer *buffer)
{
    if (validate_claim(claim) != 0)
        return -1;
    const char *kind = sidecar_object_kind_name(claim->kind);
    if (kind == NULL)
    {
        set_invalid_error();
        return -1;
    }
    if (buffer_append_tag(buffer, tag_claim) != 0 ||
        buffer_append_field(buffer, claim->root_id) != 0 ||
        buffer_append_field(buffer, claim->logical_path) != 0 ||
        buffer_append_field(buffer, claim->physical_path) != 0 ||
        buffer_append_field(buffer, (SidecarBytes){
            (const unsigned char *)kind, strlen(kind) }) != 0)
        return -1;
    return 0;
}

int sidecar_write_header(int fd)
{
    SidecarBuffer buffer = {0};
    SidecarBytes magic = {
        .data = sidecar_magic,
        .length = sizeof(sidecar_magic) - 1U
    };
    SidecarBytes version = {
        .data = sidecar_header_version,
        .length = sizeof(sidecar_header_version) - 1U
    };
    struct stat st;
    int result = -1;

    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size != 0)
    {
        set_invalid_error();
        return -1;
    }
    if (buffer_append_field(&buffer, magic) == 0 &&
        buffer_append_field(&buffer, version) == 0)
        result = append_buffer(fd, &buffer, -1);
    buffer_free(&buffer);
    return result;
}

int sidecar_write_entry(int fd, const SidecarEntry *entry)
{
    SidecarBuffer buffer = {0};
    int result = -1;
    if (build_entry_buffer(entry, &buffer) == 0)
        result = append_buffer(fd, &buffer, SIDECAR_RECORD_ENTRY);
    buffer_free(&buffer);
    return result;
}

int sidecar_write_xattr(int fd, const SidecarXattr *xattr)
{
    SidecarBuffer buffer = {0};
    int result = -1;
    if (build_xattr_buffer(xattr, &buffer) == 0)
        result = append_buffer(fd, &buffer, SIDECAR_RECORD_XATTR);
    buffer_free(&buffer);
    return result;
}

int sidecar_write_entry_commit(int fd)
{
    SidecarBuffer buffer = {0};
    int result = -1;
    if (buffer_append_tag(&buffer, tag_entry_commit) == 0)
        result = append_buffer(fd, &buffer, SIDECAR_RECORD_ENTRY_COMMIT);
    buffer_free(&buffer);
    return result;
}

int sidecar_write_delete(int fd, const SidecarDelete *deletion)
{
    SidecarBuffer buffer = {0};
    int result = -1;
    if (validate_delete(deletion) == 0 &&
        buffer_append_tag(&buffer, tag_delete) == 0 &&
        buffer_append_field(&buffer, deletion->root_id) == 0 &&
        buffer_append_field(&buffer, deletion->logical_path) == 0)
        result = append_buffer(fd, &buffer, SIDECAR_RECORD_DELETE);
    buffer_free(&buffer);
    return result;
}

int sidecar_write_claim(int fd, const SidecarClaim *claim)
{
    SidecarBuffer buffer = {0};
    int result = -1;
    if (build_claim_buffer(claim, &buffer) == 0)
        result = append_buffer(fd, &buffer, SIDECAR_RECORD_CLAIM);
    buffer_free(&buffer);
    return result;
}

const char *sidecar_status_string(SidecarStatus status)
{
    switch (status)
    {
        case SIDECAR_STATUS_OK: return "ok";
        case SIDECAR_STATUS_TRUNCATED_TAIL: return "truncated tail";
        case SIDECAR_STATUS_INVALID_ARGUMENT: return "invalid argument";
        case SIDECAR_STATUS_IO_ERROR: return "I/O error";
        case SIDECAR_STATUS_CORRUPT: return "corrupt";
        case SIDECAR_STATUS_UNKNOWN_VERSION: return "unknown version";
        case SIDECAR_STATUS_LIMIT: return "resource limit";
        case SIDECAR_STATUS_ALLOCATION: return "allocation failure";
        case SIDECAR_STATUS_UNSUPPORTED_KIND: return "unsupported object kind";
        case SIDECAR_STATUS_CALLBACK: return "callback failure";
    }
    return "unknown status";
}

int sidecar_live_entry_count_allowed(uint64_t count)
{
    return count <= SIDECAR_MAX_LIVE_ENTRIES;
}

const char *sidecar_object_kind_name(SidecarObjectKind kind)
{
    switch (kind)
    {
        case SIDECAR_KIND_REGULAR: return kind_regular;
        case SIDECAR_KIND_DIRECTORY: return kind_directory;
        case SIDECAR_KIND_FIFO: return kind_fifo;
        case SIDECAR_KIND_SYMLINK: return kind_symlink;
        case SIDECAR_KIND_HARDLINK: return kind_hardlink;
    }
    return NULL;
}

int sidecar_object_kind_parse(SidecarBytes field, SidecarObjectKind *out)
{
    if (out == NULL || validate_bytes(field, SIDECAR_KIND_MAX, 1) != 0)
        return -1;
    if (bytes_equal(field, kind_regular))
        *out = SIDECAR_KIND_REGULAR;
    else if (bytes_equal(field, kind_directory))
        *out = SIDECAR_KIND_DIRECTORY;
    else if (bytes_equal(field, kind_fifo))
        *out = SIDECAR_KIND_FIFO;
    else if (bytes_equal(field, kind_symlink))
        *out = SIDECAR_KIND_SYMLINK;
    else if (bytes_equal(field, kind_hardlink))
        *out = SIDECAR_KIND_HARDLINK;
    else
        return -1;
    return 0;
}

static int reader_fill(SidecarReader *reader)
{
    if (reader->file_position >= reader->limit)
        return 0;

    uint64_t remaining = reader->limit - reader->file_position;
    size_t amount = remaining > sizeof(reader->buffer)
        ? sizeof(reader->buffer) : (size_t)remaining;
    off_t offset = (off_t)reader->file_position;
    if (offset < 0 || (uint64_t)offset != reader->file_position)
        return -1;

    ssize_t received;
    do {
        received = pread(reader->fd, reader->buffer, amount, offset);
    } while (received < 0 && errno == EINTR);
    if (received <= 0)
        return received == 0 ? 0 : -1;

    reader->file_position += (uint64_t)received;
    reader->buffer_position = 0;
    reader->buffer_length = (size_t)received;
    return 1;
}

static int reader_get(SidecarReader *reader, unsigned char *out)
{
    if (reader->buffer_position == reader->buffer_length)
    {
        int filled = reader_fill(reader);
        if (filled <= 0)
            return filled;
    }
    *out = reader->buffer[reader->buffer_position++];
    reader->consumed++;
    return 1;
}

static void *reader_alloc(SidecarReader *reader, size_t size)
{
    return tracked_alloc(&reader->allocations, size);
}

static void reader_free(SidecarReader *reader, void *pointer)
{
    tracked_free(&reader->allocations, pointer);
}

static FieldStatus read_field(SidecarReader *reader, size_t maximum,
                              SidecarBytes *out)
{
    if (out == NULL)
        return FIELD_IO;
    memset(out, 0, sizeof(*out));

    unsigned char *data = reader_alloc(reader, maximum + 1U);
    if (data == NULL)
        return FIELD_ALLOCATION;

    size_t length = 0;
    for (;;)
    {
        unsigned char byte = 0;
        int result = reader_get(reader, &byte);
        if (result < 0)
        {
            reader_free(reader, data);
            return FIELD_IO;
        }
        if (result == 0)
        {
            reader_free(reader, data);
            return length == 0 ? FIELD_EOF : FIELD_TAIL;
        }
        if (byte == '\0')
        {
            data[length] = '\0';
            out->data = data;
            out->length = length;
            return FIELD_OK;
        }
        if (length == maximum)
        {
            reader_free(reader, data);
            return FIELD_LIMIT;
        }
        data[length++] = byte;
    }
}

static FieldStatus read_raw(SidecarReader *reader, uint64_t length,
                            SidecarBytes *out)
{
    if (out == NULL)
        return FIELD_IO;
    memset(out, 0, sizeof(*out));
    if (length > SIZE_MAX || length > SIDECAR_MAX_XATTR_VALUE)
        return FIELD_LIMIT;
    if (length == 0)
        return FIELD_OK;

    unsigned char *data = reader_alloc(reader, (size_t)length);
    if (data == NULL)
        return FIELD_ALLOCATION;
    for (uint64_t index = 0; index < length; index++)
    {
        int result = reader_get(reader, &data[index]);
        if (result < 0)
        {
            reader_free(reader, data);
            return FIELD_IO;
        }
        if (result == 0)
        {
            reader_free(reader, data);
            return FIELD_TAIL;
        }
    }
    out->data = data;
    out->length = (size_t)length;
    return FIELD_OK;
}

static SidecarStatus field_status_to_parse(FieldStatus status)
{
    switch (status)
    {
        case FIELD_TAIL: return SIDECAR_STATUS_TRUNCATED_TAIL;
        case FIELD_IO: return SIDECAR_STATUS_IO_ERROR;
        case FIELD_LIMIT: return SIDECAR_STATUS_LIMIT;
        case FIELD_ALLOCATION: return SIDECAR_STATUS_ALLOCATION;
        case FIELD_EOF: return SIDECAR_STATUS_TRUNCATED_TAIL;
        case FIELD_OK: return SIDECAR_STATUS_OK;
    }
    return SIDECAR_STATUS_CORRUPT;
}

static SidecarStatus read_required_field(SidecarReader *reader, size_t maximum,
                                         SidecarBytes *out)
{
    FieldStatus status = read_field(reader, maximum, out);
    if (status == FIELD_OK)
        return SIDECAR_STATUS_OK;
    return field_status_to_parse(status);
}

static SidecarStatus parse_unsigned(SidecarBytes field, uint64_t maximum,
                                    uint64_t *out)
{
    if (out == NULL || field.length == 0 || field.data == NULL)
        return SIDECAR_STATUS_CORRUPT;
    if (field.length > 1 && field.data[0] == '0')
        return SIDECAR_STATUS_CORRUPT;

    uint64_t value = 0;
    for (size_t index = 0; index < field.length; index++)
    {
        unsigned char byte = field.data[index];
        if (byte < '0' || byte > '9')
            return SIDECAR_STATUS_CORRUPT;
        uint64_t digit = (uint64_t)(byte - '0');
        if (digit > maximum || value > (maximum - digit) / 10U)
            return SIDECAR_STATUS_CORRUPT;
        value = value * 10U + digit;
    }
    *out = value;
    return SIDECAR_STATUS_OK;
}

static SidecarStatus parse_signed(SidecarBytes field, int64_t *out)
{
    if (out == NULL || field.length == 0 || field.data == NULL)
        return SIDECAR_STATUS_CORRUPT;

    size_t index = 0;
    int negative = 0;
    if (field.data[0] == '-')
    {
        negative = 1;
        index = 1;
        if (index == field.length)
            return SIDECAR_STATUS_CORRUPT;
    }
    if (field.length - index > 1 && field.data[index] == '0')
        return SIDECAR_STATUS_CORRUPT;

    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1U : (uint64_t)INT64_MAX;
    uint64_t magnitude = 0;
    for (; index < field.length; index++)
    {
        unsigned char byte = field.data[index];
        if (byte < '0' || byte > '9')
            return SIDECAR_STATUS_CORRUPT;
        uint64_t digit = (uint64_t)(byte - '0');
        if (magnitude > (limit - digit) / 10U)
            return SIDECAR_STATUS_CORRUPT;
        magnitude = magnitude * 10U + digit;
    }

    if (negative)
    {
        if (magnitude == (uint64_t)INT64_MAX + 1U)
            *out = INT64_MIN;
        else
            *out = -(int64_t)magnitude;
    }
    else
        *out = (int64_t)magnitude;
    return SIDECAR_STATUS_OK;
}

static SidecarStatus parse_uint_field(SidecarReader *reader, uint64_t maximum,
                                      uint64_t *out)
{
    SidecarBytes field;
    SidecarStatus status = read_required_field(reader, 32U, &field);
    if (status != SIDECAR_STATUS_OK)
        return status;
    status = parse_unsigned(field, maximum, out);
    reader_free(reader, (void *)field.data);
    return status;
}

static SidecarStatus parse_int_field(SidecarReader *reader, int64_t *out)
{
    SidecarBytes field;
    SidecarStatus status = read_required_field(reader, 32U, &field);
    if (status != SIDECAR_STATUS_OK)
        return status;
    status = parse_signed(field, out);
    reader_free(reader, (void *)field.data);
    return status;
}

static void free_entry(SidecarReader *reader, SidecarEntry *entry)
{
    if (entry == NULL)
        return;
    reader_free(reader, (void *)entry->root_id.data);
    reader_free(reader, (void *)entry->logical_path.data);
    reader_free(reader, (void *)entry->physical_path.data);
    reader_free(reader, (void *)entry->collision_suffix.data);
    reader_free(reader, (void *)entry->symlink_target.data);
    reader_free(reader, (void *)entry->hardlink_root_id.data);
    reader_free(reader, (void *)entry->hardlink_logical_path.data);
    memset(entry, 0, sizeof(*entry));
}

static SidecarStatus parse_entry(SidecarReader *reader, SidecarEntry *entry)
{
    memset(entry, 0, sizeof(*entry));
    SidecarStatus status = read_required_field(reader, SIDECAR_MAX_ROOT_ID,
                                               &entry->root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = read_required_field(reader, SIDECAR_MAX_PATH, &entry->logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = read_required_field(reader, SIDECAR_MAX_PATH, &entry->physical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = read_required_field(reader, SIDECAR_MAX_COLLISION_SUFFIX,
                                 &entry->collision_suffix);
    if (status != SIDECAR_STATUS_OK)
        goto fail;

    SidecarBytes kind_field;
    status = read_required_field(reader, SIDECAR_KIND_MAX, &kind_field);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    if (sidecar_object_kind_parse(kind_field, &entry->kind) != 0)
    {
        reader_free(reader, (void *)kind_field.data);
        status = SIDECAR_STATUS_CORRUPT;
        goto fail;
    }
    reader_free(reader, (void *)kind_field.data);

    uint64_t number = 0;
    status = parse_uint_field(reader, SIDECAR_MAX_MODE, &number);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    entry->mode = (uint32_t)number;
    status = parse_uint_field(reader, SIDECAR_MAX_UID_GID, &number);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    entry->uid = (uint32_t)number;
    status = parse_uint_field(reader, SIDECAR_MAX_UID_GID, &number);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    entry->gid = (uint32_t)number;
    status = parse_int_field(reader, &entry->atime_sec);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = parse_uint_field(reader, SIDECAR_MAX_NSEC, &number);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    entry->atime_nsec = (uint32_t)number;
    status = parse_int_field(reader, &entry->mtime_sec);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = parse_uint_field(reader, SIDECAR_MAX_NSEC, &number);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    entry->mtime_nsec = (uint32_t)number;
    status = parse_uint_field(reader, UINT64_MAX, &entry->size);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = parse_uint_field(reader, SIDECAR_MAX_XATTRS_PER_ENTRY, &number);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    entry->xattr_count = (uint32_t)number;

    if (entry->kind != SIDECAR_KIND_REGULAR && entry->size != 0)
    {
        status = SIDECAR_STATUS_CORRUPT;
        goto fail;
    }
    if (entry->kind == SIDECAR_KIND_SYMLINK)
    {
        status = read_required_field(reader, SIDECAR_MAX_SYMLINK_TARGET,
                                     &entry->symlink_target);
        if (status != SIDECAR_STATUS_OK)
            goto fail;
    }
    else if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        status = read_required_field(reader, SIDECAR_MAX_ROOT_ID,
                                     &entry->hardlink_root_id);
        if (status != SIDECAR_STATUS_OK)
            goto fail;
        status = read_required_field(reader, SIDECAR_MAX_PATH,
                                     &entry->hardlink_logical_path);
        if (status != SIDECAR_STATUS_OK)
            goto fail;
        if (entry->hardlink_root_id.length == 0 ||
            entry->hardlink_logical_path.length == 0)
        {
            status = SIDECAR_STATUS_CORRUPT;
            goto fail;
        }
    }
    if (entry->root_id.length == 0)
    {
        status = SIDECAR_STATUS_CORRUPT;
        goto fail;
    }
    return SIDECAR_STATUS_OK;

fail:
    free_entry(reader, entry);
    return status;
}

static SidecarStatus parse_xattr(SidecarReader *reader, SidecarXattr *xattr)
{
    memset(xattr, 0, sizeof(*xattr));
    SidecarStatus status = read_required_field(reader, SIDECAR_MAX_XATTR_NAME,
                                               &xattr->name);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (xattr->name.length == 0)
    {
        reader_free(reader, (void *)xattr->name.data);
        memset(xattr, 0, sizeof(*xattr));
        return SIDECAR_STATUS_CORRUPT;
    }

    uint64_t length = 0;
    status = parse_uint_field(reader, SIDECAR_MAX_XATTR_VALUE, &length);
    if (status != SIDECAR_STATUS_OK)
    {
        reader_free(reader, (void *)xattr->name.data);
        memset(xattr, 0, sizeof(*xattr));
        return status;
    }
    FieldStatus field_status = read_raw(reader, length, &xattr->value);
    if (field_status != FIELD_OK)
    {
        reader_free(reader, (void *)xattr->name.data);
        reader_free(reader, (void *)xattr->value.data);
        memset(xattr, 0, sizeof(*xattr));
        return field_status_to_parse(field_status);
    }
    return SIDECAR_STATUS_OK;
}

static void free_xattr(SidecarReader *reader, SidecarXattr *xattr)
{
    if (xattr == NULL)
        return;
    reader_free(reader, (void *)xattr->name.data);
    reader_free(reader, (void *)xattr->value.data);
    memset(xattr, 0, sizeof(*xattr));
}

static SidecarStatus parse_delete(SidecarReader *reader, SidecarDelete *deletion)
{
    memset(deletion, 0, sizeof(*deletion));
    SidecarStatus status = read_required_field(reader, SIDECAR_MAX_ROOT_ID,
                                               &deletion->root_id);
    if (status != SIDECAR_STATUS_OK)
        return status;
    status = read_required_field(reader, SIDECAR_MAX_PATH,
                                 &deletion->logical_path);
    if (status != SIDECAR_STATUS_OK)
    {
        reader_free(reader, (void *)deletion->root_id.data);
        memset(deletion, 0, sizeof(*deletion));
        return status;
    }
    if (deletion->root_id.length == 0)
    {
        reader_free(reader, (void *)deletion->root_id.data);
        reader_free(reader, (void *)deletion->logical_path.data);
        memset(deletion, 0, sizeof(*deletion));
        return SIDECAR_STATUS_CORRUPT;
    }
    return SIDECAR_STATUS_OK;
}

static void free_delete(SidecarReader *reader, SidecarDelete *deletion)
{
    if (deletion == NULL)
        return;
    reader_free(reader, (void *)deletion->root_id.data);
    reader_free(reader, (void *)deletion->logical_path.data);
    memset(deletion, 0, sizeof(*deletion));
}

static void free_claim(SidecarReader *reader, SidecarClaim *claim);

static SidecarStatus parse_claim(SidecarReader *reader, SidecarClaim *claim)
{
    memset(claim, 0, sizeof(*claim));
    SidecarStatus status = read_required_field(reader, SIDECAR_MAX_ROOT_ID,
                                               &claim->root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = read_required_field(reader, SIDECAR_MAX_PATH,
                                 &claim->logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = read_required_field(reader, SIDECAR_MAX_PATH,
                                 &claim->physical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;

    SidecarBytes kind_field;
    status = read_required_field(reader, SIDECAR_KIND_MAX, &kind_field);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    if (sidecar_object_kind_parse(kind_field, &claim->kind) != 0)
    {
        reader_free(reader, (void *)kind_field.data);
        status = SIDECAR_STATUS_CORRUPT;
        goto fail;
    }
    reader_free(reader, (void *)kind_field.data);
    if (claim->root_id.length == 0 || !claim_kind_valid(claim->kind))
    {
        status = SIDECAR_STATUS_CORRUPT;
        goto fail;
    }
    return SIDECAR_STATUS_OK;

fail:
    free_claim(reader, claim);
    return status;
}

static void free_claim(SidecarReader *reader, SidecarClaim *claim)
{
    if (claim == NULL)
        return;
    reader_free(reader, (void *)claim->root_id.data);
    reader_free(reader, (void *)claim->logical_path.data);
    reader_free(reader, (void *)claim->physical_path.data);
    memset(claim, 0, sizeof(*claim));
}

static SidecarStatus parse_unsigned(SidecarBytes field, uint64_t maximum,
                                    uint64_t *out);

static SidecarStatus parse_header(SidecarReader *reader)
{
    size_t magic_length = sizeof(sidecar_magic) - 1U;
    for (size_t index = 0; index < magic_length + 1U; index++)
    {
        unsigned char byte = 0;
        int result = reader_get(reader, &byte);
        if (result <= 0)
            return SIDECAR_STATUS_CORRUPT;
        unsigned char expected = index < magic_length
            ? sidecar_magic[index] : 0;
        if (byte != expected)
            return SIDECAR_STATUS_CORRUPT;
    }

    SidecarBytes version;
    FieldStatus field_status = read_field(reader, 16U, &version);
    if (field_status != FIELD_OK)
    {
        if (field_status == FIELD_ALLOCATION)
            return SIDECAR_STATUS_ALLOCATION;
        if (field_status == FIELD_LIMIT)
            return SIDECAR_STATUS_LIMIT;
        if (field_status == FIELD_IO)
            return SIDECAR_STATUS_IO_ERROR;
        return SIDECAR_STATUS_CORRUPT;
    }
    int current = bytes_equal(version,
                              (const char *)sidecar_header_version);
    if (!current)
    {
        uint64_t parsed_version = 0;
        SidecarStatus number_status = parse_unsigned(version, UINT64_MAX,
                                                      &parsed_version);
        reader_free(reader, (void *)version.data);
        return number_status == SIDECAR_STATUS_OK
            ? SIDECAR_STATUS_UNKNOWN_VERSION
            : SIDECAR_STATUS_CORRUPT;
    }
    reader_free(reader, (void *)version.data);
    return SIDECAR_STATUS_OK;
}

static SidecarStatus parse_fd_internal(SidecarReader *reader,
                                       SidecarRecordCallback callback,
                                       void *context,
                                       SidecarParseResult *result)
{
    SidecarStatus status = parse_header(reader);
    if (status != SIDECAR_STATUS_OK)
    {
        result->bytes_read = reader->consumed;
        result->allocation_peak = reader->allocations.peak;
        return status;
    }
    result->last_valid_boundary = reader->consumed;

    SidecarEntry pending;
    memset(&pending, 0, sizeof(pending));
    int has_pending = 0;
    uint32_t xattrs_seen = 0;

    for (;;)
    {
        SidecarBytes tag;
        FieldStatus field_status = read_field(reader, SIDECAR_TAG_MAX, &tag);
        if (field_status == FIELD_EOF)
        {
            status = has_pending ? SIDECAR_STATUS_TRUNCATED_TAIL
                                 : SIDECAR_STATUS_OK;
            break;
        }
        if (field_status != FIELD_OK)
        {
            status = field_status_to_parse(field_status);
            break;
        }

        if (bytes_equal(tag, tag_entry))
        {
            reader_free(reader, (void *)tag.data);
            if (has_pending)
            {
                status = SIDECAR_STATUS_CORRUPT;
                break;
            }
            status = parse_entry(reader, &pending);
            if (status != SIDECAR_STATUS_OK)
                break;
            has_pending = 1;
            xattrs_seen = 0;
            result->entry_records++;
            SidecarRecord record = {
                .type = SIDECAR_RECORD_ENTRY,
                .value.entry = pending
            };
            if (callback != NULL && callback(&record, context) != 0)
            {
                status = SIDECAR_STATUS_CALLBACK;
                break;
            }
        }
        else if (bytes_equal(tag, tag_xattr))
        {
            reader_free(reader, (void *)tag.data);
            if (!has_pending || xattrs_seen >= pending.xattr_count)
            {
                status = SIDECAR_STATUS_CORRUPT;
                break;
            }
            SidecarXattr xattr;
            status = parse_xattr(reader, &xattr);
            if (status != SIDECAR_STATUS_OK)
                break;
            xattrs_seen++;
            SidecarRecord record = {
                .type = SIDECAR_RECORD_XATTR,
                .value.xattr = xattr
            };
            if (callback != NULL && callback(&record, context) != 0)
            {
                free_xattr(reader, &xattr);
                status = SIDECAR_STATUS_CALLBACK;
                break;
            }
            free_xattr(reader, &xattr);
        }
        else if (bytes_equal(tag, tag_entry_commit))
        {
            reader_free(reader, (void *)tag.data);
            if (!has_pending || xattrs_seen != pending.xattr_count)
            {
                status = SIDECAR_STATUS_CORRUPT;
                break;
            }
            SidecarRecord record = {
                .type = SIDECAR_RECORD_ENTRY_COMMIT,
                .value.entry = pending
            };
            if (callback != NULL && callback(&record, context) != 0)
            {
                status = SIDECAR_STATUS_CALLBACK;
                break;
            }
            free_entry(reader, &pending);
            has_pending = 0;
            xattrs_seen = 0;
            result->last_valid_boundary = reader->consumed;
        }
        else if (bytes_equal(tag, tag_delete))
        {
            reader_free(reader, (void *)tag.data);
            if (has_pending)
            {
                status = SIDECAR_STATUS_CORRUPT;
                break;
            }
            SidecarDelete deletion;
            status = parse_delete(reader, &deletion);
            if (status != SIDECAR_STATUS_OK)
                break;
            SidecarRecord record = {
                .type = SIDECAR_RECORD_DELETE,
                .value.deletion = deletion
            };
            if (callback != NULL && callback(&record, context) != 0)
            {
                free_delete(reader, &deletion);
                status = SIDECAR_STATUS_CALLBACK;
                break;
            }
            free_delete(reader, &deletion);
            result->last_valid_boundary = reader->consumed;
        }
        else if (bytes_equal(tag, tag_claim))
        {
            reader_free(reader, (void *)tag.data);
            if (has_pending)
            {
                status = SIDECAR_STATUS_CORRUPT;
                break;
            }
            SidecarClaim claim;
            status = parse_claim(reader, &claim);
            if (status != SIDECAR_STATUS_OK)
                break;
            SidecarRecord record = {
                .type = SIDECAR_RECORD_CLAIM,
                .value.claim = claim
            };
            if (callback != NULL && callback(&record, context) != 0)
            {
                free_claim(reader, &claim);
                status = SIDECAR_STATUS_CALLBACK;
                break;
            }
            free_claim(reader, &claim);
            result->last_valid_boundary = reader->consumed;
        }
        else
        {
            reader_free(reader, (void *)tag.data);
            status = SIDECAR_STATUS_CORRUPT;
            break;
        }
        result->records_read++;
    }

    if (has_pending)
        free_entry(reader, &pending);
    result->bytes_read = reader->consumed;
    result->allocation_peak = reader->allocations.peak;
    return status;
}

SidecarStatus sidecar_parse_fd(int fd, SidecarRecordCallback callback,
                               void *context, SidecarParseResult *result)
{
    if (fd < 0 || result == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0)
        return SIDECAR_STATUS_IO_ERROR;
    if (!S_ISREG(st.st_mode))
        return SIDECAR_STATUS_IO_ERROR;
    if ((uint64_t)st.st_size > SIDECAR_MAX_TOTAL_BYTES)
        return SIDECAR_STATUS_LIMIT;

    SidecarReader reader = {
        .fd = fd,
        .limit = (uint64_t)st.st_size
    };
    SidecarStatus status = parse_fd_internal(&reader, callback, context, result);
    if (reader.allocations.current != 0)
    {
        result->allocation_peak = reader.allocations.peak;
        status = SIDECAR_STATUS_ALLOCATION;
    }
    return status;
}
