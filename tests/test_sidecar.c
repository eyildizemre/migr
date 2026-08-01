// Unit tests for the sidecar v1 codec (docs/DECISIONS.md D17): magic/version
// header, ENTRY/XATTR/ENTRY_COMMIT/DELETE record framing, canonical numeric
// parsing, and every SIDECAR_MAX_* ceiling declared there. This is the codec
// alone -- no live-state map, no resume, no adopt; that stateful layer is a
// separate step built on top of this one.
//
// Round-trip coverage writes real records with sidecar_write_*() and reads
// them back through sidecar_parse_fd()'s callback, so a writer bug can never
// mask a reader bug (same split as tests/test_manifest.c). Corruption
// fixtures are raw byte buffers assembled by hand instead, for the same
// reason: a malformed-input test must not depend on the writer refusing to
// produce what it is checking the reader rejects.
//
// Ceiling tests are paired at the boundary (exactly at the limit is
// accepted, one past it is refused) rather than tested with an arbitrary
// value on either side. The total-byte ceiling fixture uses a sparse file
// (ftruncate, no data written) to exercise the real 4 GiB limit without
// actually allocating or writing that much. Tail recovery distinguishes a
// clean EOF mid-record (truncated tail, resumable) from malformed content
// anywhere in the file (interior corruption, unusable) per D17; the reserved
// symlink/hardlink kind fields are confirmed parseable even though
// sidecar.c's own writer refuses to produce them yet.

#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sidecar.h"

static int failures;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  v %s\n", label);
    else
    {
        printf("  x %s\n", label);
        failures++;
    }
}

static int reset_file(int fd)
{
    return ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0 ? 0 : -1;
}

static int write_all_test(int fd, const unsigned char *data, size_t length)
{
    size_t written = 0;
    while (written < length)
    {
        ssize_t result = write(fd, data + written, length - written);
        if (result <= 0)
            return -1;
        written += (size_t)result;
    }
    return 0;
}

static int file_size(int fd, uint64_t *out)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0)
        return -1;
    *out = (uint64_t)st.st_size;
    return 0;
}

typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
} RawBuffer;

static void raw_free(RawBuffer *buffer)
{
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int raw_reserve(RawBuffer *buffer, size_t extra)
{
    if (extra > SIZE_MAX - buffer->length)
        return -1;
    size_t needed = buffer->length + extra;
    if (needed <= buffer->capacity)
        return 0;
    size_t capacity = buffer->capacity == 0 ? 128U : buffer->capacity;
    while (capacity < needed)
        capacity *= 2U;
    unsigned char *data = realloc(buffer->data, capacity);
    if (data == NULL)
        return -1;
    buffer->data = data;
    buffer->capacity = capacity;
    return 0;
}

static int raw_append(RawBuffer *buffer, const void *data, size_t length)
{
    if (raw_reserve(buffer, length) != 0)
        return -1;
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

static int raw_field(RawBuffer *buffer, const void *data, size_t length)
{
    unsigned char zero = 0;
    return raw_append(buffer, data, length) == 0 &&
           raw_append(buffer, &zero, 1) == 0 ? 0 : -1;
}

static int raw_text_field(RawBuffer *buffer, const char *text)
{
    return raw_field(buffer, text, strlen(text));
}

static int raw_tag(RawBuffer *buffer, const char *tag)
{
    return raw_text_field(buffer, tag);
}

static int append_header(RawBuffer *buffer, const char *version)
{
    return raw_text_field(buffer, SIDECAR_MAGIC) == 0 &&
           raw_text_field(buffer, version) == 0 ? 0 : -1;
}

static int append_regular_entry(RawBuffer *buffer, const char *mode,
                                const char *xattr_count)
{
    return raw_tag(buffer, "ENTRY") == 0 &&
           raw_text_field(buffer, "ROOT") == 0 &&
           raw_text_field(buffer, "dir/file") == 0 &&
           raw_text_field(buffer, "payload/file") == 0 &&
           raw_text_field(buffer, "regular") == 0 &&
           raw_text_field(buffer, mode) == 0 &&
           raw_text_field(buffer, "1000") == 0 &&
           raw_text_field(buffer, "1000") == 0 &&
           raw_text_field(buffer, "-7") == 0 &&
           raw_text_field(buffer, "0") == 0 &&
           raw_text_field(buffer, "8") == 0 &&
           raw_text_field(buffer, "123") == 0 &&
           raw_text_field(buffer, "0") == 0 &&
           raw_text_field(buffer, xattr_count) == 0 ? 0 : -1;
}

static int append_commit(RawBuffer *buffer)
{
    return raw_tag(buffer, "ENTRY_COMMIT");
}

static int set_raw_file(int fd, const RawBuffer *buffer)
{
    return reset_file(fd) == 0 &&
           write_all_test(fd, buffer->data, buffer->length) == 0 ? 0 : -1;
}

static SidecarEntry sample_entry(void)
{
    static const unsigned char root[] = "ROOT";
    static const unsigned char logical[] = "dir/file";
    static const unsigned char physical[] = "payload/file";
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = (SidecarBytes){ root, sizeof(root) - 1U };
    entry.logical_path = (SidecarBytes){ logical, sizeof(logical) - 1U };
    entry.physical_path = (SidecarBytes){ physical, sizeof(physical) - 1U };
    entry.kind = SIDECAR_KIND_REGULAR;
    entry.mode = 0644;
    entry.uid = 1000;
    entry.gid = 1000;
    entry.atime_sec = -7;
    entry.atime_nsec = 8;
    entry.mtime_sec = 123;
    entry.mtime_nsec = 456789;
    entry.size = 321;
    entry.xattr_count = 1;
    return entry;
}

typedef struct {
    int entries;
    int xattrs;
    int commits;
    int deletes;
    int valid;
} RoundTripState;

static int roundtrip_callback(const SidecarRecord *record, void *context)
{
    RoundTripState *state = context;
    if (record->type == SIDECAR_RECORD_ENTRY)
    {
        const SidecarEntry *entry = &record->value.entry;
        state->entries++;
        if (entry->kind != SIDECAR_KIND_REGULAR || entry->mode != 0644 ||
            entry->uid != 1000 || entry->gid != 1000 || entry->size != 321 ||
            entry->atime_sec != -7 || entry->mtime_nsec != 456789 ||
            entry->root_id.length != 4 ||
            memcmp(entry->root_id.data, "ROOT", 4) != 0)
            state->valid = 0;
    }
    else if (record->type == SIDECAR_RECORD_XATTR)
    {
        static const unsigned char expected[] = { 0x00, 0x01, 0xff, 0x00 };
        const SidecarXattr *xattr = &record->value.xattr;
        state->xattrs++;
        if (xattr->name.length != 9 ||
            memcmp(xattr->name.data, "user.test", 9) != 0 ||
            xattr->value.length != sizeof(expected) ||
            memcmp(xattr->value.data, expected, sizeof(expected)) != 0)
            state->valid = 0;
    }
    else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT)
        state->commits++;
    else if (record->type == SIDECAR_RECORD_DELETE)
    {
        state->deletes++;
        if (record->value.deletion.root_id.length != 4 ||
            memcmp(record->value.deletion.root_id.data, "ROOT", 4) != 0 ||
            record->value.deletion.logical_path.length != 8 ||
            memcmp(record->value.deletion.logical_path.data, "dir/file", 8) != 0)
            state->valid = 0;
    }
    return 0;
}

static void test_header_and_roundtrip(int fd)
{
    printf(":: sidecar header and record round trip\n");
    check(reset_file(fd) == 0, "temporary sidecar is reset");
    check(sidecar_write_header(fd) == 0, "canonical header writes");

    unsigned char actual[32] = {0};
    ssize_t count = pread(fd, actual, sizeof(actual), 0);
    const unsigned char expected[] = SIDECAR_MAGIC "\0" "1\0";
    check(count == (ssize_t)sizeof(expected) - 1 &&
          memcmp(actual, expected, sizeof(expected) - 1U) == 0,
          "header bytes are byte-exact");

    SidecarEntry entry = sample_entry();
    static const unsigned char xattr_value[] = { 0x00, 0x01, 0xff, 0x00 };
    SidecarXattr xattr = {
        .name = { (const unsigned char *)"user.test", 9 },
        .value = { xattr_value, sizeof(xattr_value) }
    };
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"dir/file", 8 }
    };
    check(sidecar_write_entry(fd, &entry) == 0, "ENTRY writes");
    check(sidecar_write_xattr(fd, &xattr) == 0, "binary XATTR writes");
    check(sidecar_write_entry_commit(fd) == 0, "ENTRY_COMMIT writes");
    check(sidecar_write_delete(fd, &deletion) == 0, "DELETE writes");

    RoundTripState state = { .valid = 1 };
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, roundtrip_callback, &state, &result);
    check(status == SIDECAR_STATUS_OK, "complete log parses successfully");
    check(state.valid && state.entries == 1 && state.xattrs == 1 &&
          state.commits == 1 && state.deletes == 1,
          "all records round-trip through the callback");
    check(result.last_valid_boundary == result.bytes_read &&
          result.records_read == 4,
          "clean EOF boundary is the complete file");
    check(result.allocation_peak > 0 && result.allocation_peak <= SIDECAR_MAX_ALLOC_BUDGET,
          "parser allocation remains within the published budget");
}

static void test_writer_validation(int fd)
{
    printf(":: sidecar writer validation and ceilings\n");
    SidecarEntry entry = sample_entry();
    uint64_t before = 0;

    char *root = malloc(SIDECAR_MAX_ROOT_ID + 1U);
    char *path = malloc(SIDECAR_MAX_PATH + 1U);
    char *name = malloc(SIDECAR_MAX_XATTR_NAME + 1U);
    unsigned char *value = malloc(SIDECAR_MAX_XATTR_VALUE + 1U);
    check(root != NULL && path != NULL && name != NULL && value != NULL,
          "ceiling fixtures allocate");
    if (root == NULL || path == NULL || name == NULL || value == NULL)
        goto done;
    memset(root, 'r', SIDECAR_MAX_ROOT_ID + 1U);
    memset(path, 'p', SIDECAR_MAX_PATH + 1U);
    memset(name, 'n', SIDECAR_MAX_XATTR_NAME + 1U);
    memset(value, 0xa5, SIDECAR_MAX_XATTR_VALUE + 1U);

    entry.root_id = (SidecarBytes){ (unsigned char *)root, SIDECAR_MAX_ROOT_ID };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "root id at its ceiling is accepted");
    entry.root_id.length++;
    check(sidecar_write_entry(fd, &entry) != 0, "root id over ceiling is refused");
    check(file_size(fd, &before) == 0 && before > 0,
          "invalid entry does not truncate the existing file");
    entry.root_id.length = SIDECAR_MAX_ROOT_ID;

    entry.logical_path = (SidecarBytes){ (unsigned char *)path, SIDECAR_MAX_PATH };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "path at its ceiling is accepted");
    entry.logical_path.length++;
    check(sidecar_write_entry(fd, &entry) != 0, "path over ceiling is refused");
    entry.logical_path.length = SIDECAR_MAX_PATH;

    SidecarXattr xattr = {
        .name = { (unsigned char *)name, SIDECAR_MAX_XATTR_NAME },
        .value = { value, SIDECAR_MAX_XATTR_VALUE }
    };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_xattr(fd, &xattr) == 0,
          "xattr name and value at their ceilings are accepted");
    xattr.name.length++;
    check(sidecar_write_xattr(fd, &xattr) != 0, "xattr name over ceiling is refused");
    xattr.name.length = SIDECAR_MAX_XATTR_NAME;
    xattr.value.length++;
    check(sidecar_write_xattr(fd, &xattr) != 0, "xattr value over ceiling is refused");

    entry.xattr_count = SIDECAR_MAX_XATTRS_PER_ENTRY;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "xattr count at its ceiling is accepted");
    entry.xattr_count++;
    check(sidecar_write_entry(fd, &entry) != 0, "xattr count over ceiling is refused");

    entry.xattr_count = 0;
    entry.mode = SIDECAR_MAX_MODE;
    entry.atime_nsec = SIDECAR_MAX_NSEC;
    entry.mtime_nsec = SIDECAR_MAX_NSEC;
    entry.size = UINT64_MAX;
    entry.atime_sec = INT64_MIN;
    entry.mtime_sec = INT64_MAX;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "numeric lower and upper bounds are accepted");
    entry.mode = SIDECAR_MAX_MODE + 1U;
    check(sidecar_write_entry(fd, &entry) != 0, "mode over ceiling is refused");
    entry.mode = SIDECAR_MAX_MODE;
    entry.atime_nsec = SIDECAR_MAX_NSEC + 1U;
    check(sidecar_write_entry(fd, &entry) != 0, "nanoseconds over ceiling are refused");

    entry.atime_nsec = 0;
    entry.root_id = (SidecarBytes){ (const unsigned char *)"bad\0root", 8 };
    check(sidecar_write_entry(fd, &entry) != 0, "NUL-containing fields are refused");
    entry.root_id = (SidecarBytes){ (const unsigned char *)"ROOT", 4 };
    entry.kind = SIDECAR_KIND_SYMLINK;
    check(sidecar_write_entry(fd, &entry) != 0,
          "reserved symlink writer remains disabled");

done:
    free(root);
    free(path);
    free(name);
    free(value);
}

static void test_tail_and_boundary(int fd)
{
    printf(":: sidecar tail recovery and boundaries\n");
    RawBuffer buffer = {0};
    check(append_header(&buffer, "1") == 0 &&
          append_regular_entry(&buffer, "420", "0") == 0 &&
          append_commit(&buffer) == 0,
          "valid prefix fixture is built");
    check(set_raw_file(fd, &buffer) == 0, "valid prefix is written");

    uint64_t boundary = buffer.length;
    static const unsigned char partial_delete[] = "DELETE\0ROOT\0dir/file";
    check(write_all_test(fd, partial_delete, sizeof(partial_delete) - 1U) == 0,
          "partial DELETE is appended");
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_TRUNCATED_TAIL,
          "incomplete EOF record is a truncated tail");
    check(result.last_valid_boundary == boundary,
          "tail recovery returns the last committed boundary");

    check(set_raw_file(fd, &buffer) == 0, "prefix is restored");
    RawBuffer uncommitted = {0};
    check(append_header(&uncommitted, "1") == 0 &&
          append_regular_entry(&uncommitted, "420", "0") == 0 &&
          set_raw_file(fd, &uncommitted) == 0,
          "uncommitted group is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_TRUNCATED_TAIL,
          "complete group without commit is non-live tail state");
    check(result.last_valid_boundary == sizeof(SIDECAR_MAGIC) + 2U,
          "uncommitted group boundary stays at the header");

    raw_free(&uncommitted);
    raw_free(&buffer);
}

static void test_corruption_and_versions(int fd)
{
    printf(":: sidecar corruption classification\n");
    RawBuffer buffer = {0};
    SidecarParseResult result;
    SidecarStatus status;

    check(append_header(&buffer, "2") == 0 && set_raw_file(fd, &buffer) == 0,
          "unknown version fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_UNKNOWN_VERSION,
          "unknown version is not treated as an empty sidecar");

    check(reset_file(fd) == 0 &&
          write_all_test(fd, (const unsigned char *)"MIGR_SIDECAR\0", 13) == 0 &&
          write_all_test(fd, (const unsigned char *)"01\0", 3) == 0,
          "non-canonical version fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "non-canonical version is corruption");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "1") == 0 &&
          append_regular_entry(&buffer, "0420", "0") == 0 &&
          append_commit(&buffer) == 0 && set_raw_file(fd, &buffer) == 0,
          "non-canonical numeric fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "leading-zero numeric field is corruption");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "1") == 0 && raw_tag(&buffer, "UNKNOWN") == 0 &&
          set_raw_file(fd, &buffer) == 0,
          "unknown tag fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "unknown record tag is interior corruption");
    raw_free(&buffer);
}

static int reserved_kind_callback(const SidecarRecord *record, void *context)
{
    int *count = context;
    if (record->type == SIDECAR_RECORD_ENTRY &&
        record->value.entry.kind == SIDECAR_KIND_SYMLINK &&
        record->value.entry.symlink_target.length == 9 &&
        memcmp(record->value.entry.symlink_target.data, "../target", 9) == 0)
        (*count)++;
    return 0;
}

static void test_reserved_kind_parsing(int fd)
{
    printf(":: sidecar reserved kind grammar\n");
    RawBuffer buffer = {0};
    check(append_header(&buffer, "1") == 0 && raw_tag(&buffer, "ENTRY") == 0 &&
          raw_text_field(&buffer, "ROOT") == 0 &&
          raw_text_field(&buffer, "link") == 0 &&
          raw_text_field(&buffer, "payload/link") == 0 &&
          raw_text_field(&buffer, "symlink") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "1000") == 0 &&
          raw_text_field(&buffer, "1000") == 0 &&
          raw_text_field(&buffer, "1") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "2") == 0 &&
          raw_text_field(&buffer, "3") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "../target") == 0 &&
          append_commit(&buffer) == 0 && set_raw_file(fd, &buffer) == 0,
          "reserved symlink record fixture is written");

    int seen = 0;
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, reserved_kind_callback, &seen,
                                            &result);
    check(status == SIDECAR_STATUS_OK && seen == 1,
          "reserved symlink field parses without writer support");
    raw_free(&buffer);
}

static void test_total_limit(int fd)
{
    printf(":: sidecar total-byte ceiling\n");
    if (sizeof(off_t) < 8)
    {
        check(1, "host off_t is too narrow for the four-gigabyte fixture");
        return;
    }
    check(reset_file(fd) == 0 &&
          ftruncate(fd, (off_t)(SIDECAR_MAX_TOTAL_BYTES + 1U)) == 0,
          "oversized sparse fixture is created");
    SidecarParseResult result;
    check(sidecar_parse_fd(fd, NULL, NULL, &result) == SIDECAR_STATUS_LIMIT,
          "sidecar larger than total-byte ceiling is refused before parsing");
    check(reset_file(fd) == 0, "oversized fixture is removed");
}

static void test_live_entry_ceiling(void)
{
    printf(":: sidecar live-entry ceiling helper\n");
    check(sidecar_live_entry_count_allowed(SIDECAR_MAX_LIVE_ENTRIES),
          "live-entry count at its ceiling is accepted");
    check(!sidecar_live_entry_count_allowed(
              (uint64_t)SIDECAR_MAX_LIVE_ENTRIES + 1U),
          "live-entry count over its ceiling is refused");
}

int main(void)
{
    char path[] = "/tmp/migr_sidecar_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
    {
        perror("mkstemp");
        return 1;
    }
    unlink(path);

    test_header_and_roundtrip(fd);
    test_writer_validation(fd);
    test_tail_and_boundary(fd);
    test_corruption_and_versions(fd);
    test_reserved_kind_parsing(fd);
    test_total_limit(fd);
    test_live_entry_ceiling();

    close(fd);
    printf("sidecar tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
