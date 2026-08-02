#define _GNU_SOURCE

#include "sidecar.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    uint64_t bytes;
} StateMemory;

typedef struct {
    SidecarEntry entry;
    SidecarXattr *xattrs;
    uint64_t generation;
} StateEntry;

typedef struct {
    StateEntry *items;
    size_t count;
    size_t capacity;
    uint64_t generation;
} StateMap;

typedef struct {
    StateEntry entry;
    uint32_t xattrs_seen;
} PendingEntry;

typedef struct {
    int fd;
    uint64_t boundary;
    int poisoned;
    StateMemory memory;
    StateMap map;
    PendingEntry pending;
} SidecarLogImplementation;

typedef struct {
    SidecarLogImplementation *log;
    SidecarStatus error;
} LoadContext;

static void set_invalid_error(void)
{
    errno = EINVAL;
}

static int bytes_valid(SidecarBytes bytes, size_t maximum, int nonempty)
{
    return bytes.length <= maximum &&
           (bytes.length == 0 || bytes.data != NULL) &&
           (!nonempty || bytes.length != 0) &&
           (bytes.length == 0 || memchr(bytes.data, '\0', bytes.length) == NULL);
}

static int raw_bytes_valid(SidecarBytes bytes, size_t maximum, int nonempty)
{
    return bytes.length <= maximum &&
           (bytes.length == 0 || bytes.data != NULL) &&
           (!nonempty || bytes.length != 0);
}

static void *state_alloc(StateMemory *memory, size_t size)
{
    if (memory == NULL || size == 0 ||
        memory->bytes > SIDECAR_MAX_ALLOC_BUDGET ||
        (uint64_t)size > SIDECAR_MAX_ALLOC_BUDGET - memory->bytes)
    {
        errno = E2BIG;
        return NULL;
    }

    void *pointer = malloc(size);
    if (pointer == NULL)
        return NULL;
    memory->bytes += (uint64_t)size;
    return pointer;
}

static void state_free(StateMemory *memory, void *pointer, size_t size)
{
    if (pointer == NULL)
        return;
    if (memory != NULL && (uint64_t)size <= memory->bytes)
        memory->bytes -= (uint64_t)size;
    free(pointer);
}

static SidecarStatus status_from_errno(void)
{
    switch (errno)
    {
        case EINVAL: return SIDECAR_STATUS_INVALID_ARGUMENT;
        case E2BIG: return SIDECAR_STATUS_LIMIT;
        case ENOMEM: return SIDECAR_STATUS_ALLOCATION;
        case EOPNOTSUPP: return SIDECAR_STATUS_UNSUPPORTED_KIND;
        default: return SIDECAR_STATUS_IO_ERROR;
    }
}

static SidecarStatus copy_bytes(StateMemory *memory, SidecarBytes source,
                                size_t maximum, int nonempty,
                                SidecarBytes *destination)
{
    if (destination == NULL || !bytes_valid(source, maximum, nonempty))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    destination->data = NULL;
    destination->length = 0;
    if (source.length == 0)
        return SIDECAR_STATUS_OK;

    unsigned char *data = state_alloc(memory, source.length);
    if (data == NULL)
        return errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                               : SIDECAR_STATUS_LIMIT;
    memcpy(data, source.data, source.length);
    destination->data = data;
    destination->length = source.length;
    return SIDECAR_STATUS_OK;
}

static SidecarStatus copy_raw_bytes(StateMemory *memory, SidecarBytes source,
                                    size_t maximum, int nonempty,
                                    SidecarBytes *destination)
{
    if (destination == NULL || !raw_bytes_valid(source, maximum, nonempty))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    destination->data = NULL;
    destination->length = 0;
    if (source.length == 0)
        return SIDECAR_STATUS_OK;

    unsigned char *data = state_alloc(memory, source.length);
    if (data == NULL)
        return errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                               : SIDECAR_STATUS_LIMIT;
    memcpy(data, source.data, source.length);
    destination->data = data;
    destination->length = source.length;
    return SIDECAR_STATUS_OK;
}

static void clear_xattr(StateMemory *memory, SidecarXattr *xattr)
{
    if (xattr == NULL)
        return;
    state_free(memory, (void *)xattr->name.data, xattr->name.length);
    state_free(memory, (void *)xattr->value.data, xattr->value.length);
    memset(xattr, 0, sizeof(*xattr));
}

static void clear_entry(StateMemory *memory, StateEntry *entry)
{
    if (entry == NULL)
        return;
    state_free(memory, (void *)entry->entry.root_id.data,
               entry->entry.root_id.length);
    state_free(memory, (void *)entry->entry.logical_path.data,
               entry->entry.logical_path.length);
    state_free(memory, (void *)entry->entry.physical_path.data,
               entry->entry.physical_path.length);
    state_free(memory, (void *)entry->entry.symlink_target.data,
               entry->entry.symlink_target.length);
    state_free(memory, (void *)entry->entry.hardlink_root_id.data,
               entry->entry.hardlink_root_id.length);
    state_free(memory, (void *)entry->entry.hardlink_logical_path.data,
               entry->entry.hardlink_logical_path.length);
    if (entry->xattrs != NULL)
    {
        for (uint32_t index = 0; index < entry->entry.xattr_count; index++)
            clear_xattr(memory, &entry->xattrs[index]);
        size_t size = (size_t)entry->entry.xattr_count * sizeof(*entry->xattrs);
        state_free(memory, entry->xattrs, size);
    }
    memset(entry, 0, sizeof(*entry));
}

static SidecarStatus copy_xattr(StateMemory *memory, const SidecarXattr *source,
                                SidecarXattr *destination)
{
    if (source == NULL || destination == NULL ||
        !bytes_valid(source->name, SIDECAR_MAX_XATTR_NAME, 1) ||
        !raw_bytes_valid(source->value, SIDECAR_MAX_XATTR_VALUE, 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, sizeof(*destination));
    SidecarStatus status = copy_bytes(memory, source->name,
                                      SIDECAR_MAX_XATTR_NAME, 1,
                                      &destination->name);
    if (status != SIDECAR_STATUS_OK)
        return status;
    status = copy_raw_bytes(memory, source->value, SIDECAR_MAX_XATTR_VALUE,
                            0, &destination->value);
    if (status != SIDECAR_STATUS_OK)
    {
        clear_xattr(memory, destination);
        return status;
    }
    return SIDECAR_STATUS_OK;
}

static SidecarStatus copy_entry(StateMemory *memory, const SidecarEntry *source,
                                StateEntry *destination)
{
    if (source == NULL || destination == NULL ||
        !bytes_valid(source->root_id, SIDECAR_MAX_ROOT_ID, 1) ||
        !bytes_valid(source->logical_path, SIDECAR_MAX_PATH, 0) ||
        !bytes_valid(source->physical_path, SIDECAR_MAX_PATH, 0) ||
        source->atime_nsec > SIDECAR_MAX_NSEC ||
        source->mtime_nsec > SIDECAR_MAX_NSEC ||
        source->mode > SIDECAR_MAX_MODE ||
        source->xattr_count > SIDECAR_MAX_XATTRS_PER_ENTRY ||
        source->kind < SIDECAR_KIND_REGULAR ||
        source->kind > SIDECAR_KIND_HARDLINK)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind != SIDECAR_KIND_REGULAR && source->size != 0)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (!bytes_valid(source->symlink_target, SIDECAR_MAX_SYMLINK_TARGET, 0) ||
        !bytes_valid(source->hardlink_root_id, SIDECAR_MAX_ROOT_ID, 0) ||
        !bytes_valid(source->hardlink_logical_path, SIDECAR_MAX_PATH, 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind == SIDECAR_KIND_SYMLINK &&
        (source->hardlink_root_id.length != 0 ||
         source->hardlink_logical_path.length != 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind == SIDECAR_KIND_HARDLINK &&
        (source->symlink_target.length != 0 ||
         source->hardlink_root_id.length == 0 ||
         source->hardlink_logical_path.length == 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind != SIDECAR_KIND_SYMLINK &&
        source->symlink_target.length != 0)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, sizeof(*destination));
    destination->entry = *source;
    destination->entry.root_id.data = NULL;
    destination->entry.logical_path.data = NULL;
    destination->entry.physical_path.data = NULL;
    destination->entry.symlink_target.data = NULL;
    destination->entry.hardlink_root_id.data = NULL;
    destination->entry.hardlink_logical_path.data = NULL;
    destination->xattrs = NULL;

    SidecarStatus status = copy_bytes(memory, source->root_id,
                                      SIDECAR_MAX_ROOT_ID, 1,
                                      &destination->entry.root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->logical_path, SIDECAR_MAX_PATH, 0,
                        &destination->entry.logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->physical_path, SIDECAR_MAX_PATH, 0,
                        &destination->entry.physical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->symlink_target,
                        SIDECAR_MAX_SYMLINK_TARGET, 0,
                        &destination->entry.symlink_target);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->hardlink_root_id,
                        SIDECAR_MAX_ROOT_ID, 0,
                        &destination->entry.hardlink_root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->hardlink_logical_path,
                        SIDECAR_MAX_PATH, 0,
                        &destination->entry.hardlink_logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;

    if (source->xattr_count != 0)
    {
        size_t size = (size_t)source->xattr_count * sizeof(*destination->xattrs);
        destination->xattrs = state_alloc(memory, size);
        if (destination->xattrs == NULL)
        {
            status = errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                                     : SIDECAR_STATUS_LIMIT;
            goto fail;
        }
        memset(destination->xattrs, 0, size);
    }
    return SIDECAR_STATUS_OK;

fail:
    clear_entry(memory, destination);
    return status;
}

static int key_matches(const SidecarEntry *entry, SidecarBytes root_id,
                       SidecarBytes logical_path)
{
    return entry->root_id.length == root_id.length &&
           entry->logical_path.length == logical_path.length &&
           (root_id.length == 0 ||
            memcmp(entry->root_id.data, root_id.data, root_id.length) == 0) &&
           (logical_path.length == 0 ||
            memcmp(entry->logical_path.data, logical_path.data,
                   logical_path.length) == 0);
}

static int map_find(const StateMap *map, SidecarBytes root_id,
                    SidecarBytes logical_path)
{
    for (size_t index = 0; index < map->count; index++)
    {
        if (key_matches(&map->items[index].entry, root_id, logical_path))
            return (int)index;
    }
    return -1;
}

static SidecarStatus map_resize(StateMemory *memory, StateMap *map,
                                size_t needed, StateEntry **out_items,
                                size_t *out_capacity)
{
    if (out_items == NULL || out_capacity == NULL)
    {
        errno = EINVAL;
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (needed <= map->capacity)
    {
        *out_items = map->items;
        *out_capacity = map->capacity;
        return SIDECAR_STATUS_OK;
    }
    size_t capacity = map->capacity == 0 ? 16U : map->capacity;
    while (capacity < needed)
    {
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES / 2U)
        {
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
            break;
        }
        capacity *= 2U;
    }
    if (capacity < needed || capacity > SIDECAR_MAX_LIVE_ENTRIES ||
        capacity > SIZE_MAX / sizeof(*map->items))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }

    size_t size = capacity * sizeof(*map->items);
    size_t old_size = map->capacity * sizeof(*map->items);
    if (memory == NULL || memory->bytes < (uint64_t)old_size ||
        (uint64_t)size > SIDECAR_MAX_ALLOC_BUDGET -
            (memory->bytes - (uint64_t)old_size))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    StateEntry *items = realloc(map->items, size);
    if (items == NULL)
        return errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                               : SIDECAR_STATUS_LIMIT;
    memory->bytes = memory->bytes - (uint64_t)old_size + (uint64_t)size;
    if (size > old_size)
        memset((unsigned char *)items + old_size, 0, size - old_size);
    *out_items = items;
    *out_capacity = capacity;
    return SIDECAR_STATUS_OK;
}

static void map_free(StateMemory *memory, StateMap *map)
{
    if (map == NULL)
        return;
    for (size_t index = 0; index < map->count; index++)
        clear_entry(memory, &map->items[index]);
    if (map->items != NULL)
    {
        size_t size = map->capacity * sizeof(*map->items);
        if (memory != NULL && (uint64_t)size <= memory->bytes)
            memory->bytes -= (uint64_t)size;
        free(map->items);
    }
    memset(map, 0, sizeof(*map));
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif
static SidecarStatus map_prepare_commit(StateMemory *memory, StateMap *map,
                                        const StateEntry *pending,
                                        size_t *existing_index)
{
    if (map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    int index = map_find(map, pending->entry.root_id,
                         pending->entry.logical_path);
    if (existing_index != NULL)
        *existing_index = index < 0 ? map->count : (size_t)index;
    if (index >= 0)
        return SIDECAR_STATUS_OK;
    if (!sidecar_live_entry_count_allowed((uint64_t)map->count + 1U))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    if (map->count + 1U <= map->capacity)
        return SIDECAR_STATUS_OK;
    StateEntry *items = NULL;
    size_t capacity = 0;
    SidecarStatus status = map_resize(memory, map, map->count + 1U,
                                      &items, &capacity);
    if (status != SIDECAR_STATUS_OK)
        return status;
    map->items = items;
    map->capacity = capacity;
    return SIDECAR_STATUS_OK;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static void map_apply_commit(StateMemory *memory, StateMap *map,
                             PendingEntry *pending, size_t existing_index)
{
    map->generation++;
    size_t target_index = existing_index;
    if (existing_index < map->count)
    {
        clear_entry(memory, &map->items[existing_index]);
        map->items[existing_index] = pending->entry;
    }
    else
    {
        target_index = map->count;
        map->items[map->count++] = pending->entry;
    }
    map->items[target_index].generation = map->generation;
    pending->entry = (StateEntry){0};
    pending->xattrs_seen = 0;
}

static SidecarStatus map_apply_delete(StateMemory *memory, StateMap *map,
                                      SidecarBytes root_id,
                                      SidecarBytes logical_path)
{
    if (map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    int index = map_find(map, root_id, logical_path);
    map->generation++;
    if (index < 0)
        return SIDECAR_STATUS_OK;
    clear_entry(memory, &map->items[index]);
    if ((size_t)index + 1U < map->count)
        memmove(&map->items[index], &map->items[index + 1],
                (map->count - (size_t)index - 1U) * sizeof(*map->items));
    map->count--;
    memset(&map->items[map->count], 0, sizeof(*map->items));
    return SIDECAR_STATUS_OK;
}

static int valid_key(SidecarBytes root_id, SidecarBytes logical_path)
{
    return bytes_valid(root_id, SIDECAR_MAX_ROOT_ID, 1) &&
           bytes_valid(logical_path, SIDECAR_MAX_PATH, 0);
}

static int append_entry_supported(const SidecarEntry *entry)
{
    return entry != NULL && entry->kind != SIDECAR_KIND_SYMLINK &&
           entry->kind != SIDECAR_KIND_HARDLINK;
}

static int update_boundary(SidecarLogImplementation *log)
{
    struct stat st;
    if (fstat(log->fd, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > SIDECAR_MAX_TOTAL_BYTES)
    {
        if (errno == 0)
            errno = E2BIG;
        return -1;
    }
    log->boundary = (uint64_t)st.st_size;
    return 0;
}

static void poison(SidecarLogImplementation *log)
{
    if (log != NULL)
        log->poisoned = 1;
}

static int unusable_open_errno(int error)
{
    return error == ELOOP || error == EISDIR || error == ENOTDIR ||
           error == ENXIO || error == ENODEV || error == EOPNOTSUPP;
}

static void unlink_owned_slot(int container_fd, int fd)
{
    struct stat owned;
    struct stat named;
    if (fstat(fd, &owned) == 0 &&
        fstatat(container_fd, SIDECAR_SLOT_NAME, &named,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        owned.st_dev == named.st_dev && owned.st_ino == named.st_ino)
        (void)unlinkat(container_fd, SIDECAR_SLOT_NAME, 0);
}

static void free_log_implementation(SidecarLogImplementation *log)
{
    if (log == NULL)
        return;
    clear_entry(&log->memory, &log->pending.entry);
    map_free(&log->memory, &log->map);
    free(log);
}

static SidecarOpenStatus classify_parse_failure(SidecarStatus status,
                                                SidecarStatus callback_error)
{
    if (status == SIDECAR_STATUS_IO_ERROR)
        return SIDECAR_OPEN_IO_ERROR;
    if (status == SIDECAR_STATUS_ALLOCATION ||
        callback_error == SIDECAR_STATUS_ALLOCATION)
        return SIDECAR_OPEN_ALLOCATION;
    if (callback_error == SIDECAR_STATUS_IO_ERROR)
        return SIDECAR_OPEN_IO_ERROR;
    return SIDECAR_OPEN_UNUSABLE;
}

static int load_callback(const SidecarRecord *record, void *context)
{
    LoadContext *load = context;
    SidecarLogImplementation *log = load->log;
    SidecarStatus status = SIDECAR_STATUS_OK;

    if (record->type == SIDECAR_RECORD_ENTRY)
    {
        if (log->pending.entry.entry.root_id.data != NULL)
            status = SIDECAR_STATUS_CORRUPT;
        else
            status = copy_entry(&log->memory, &record->value.entry,
                                &log->pending.entry);
        if (status == SIDECAR_STATUS_OK)
            log->pending.xattrs_seen = 0;
    }
    else if (record->type == SIDECAR_RECORD_XATTR)
    {
        if (log->pending.entry.entry.root_id.data == NULL ||
            log->pending.xattrs_seen >= log->pending.entry.entry.xattr_count)
            status = SIDECAR_STATUS_CORRUPT;
        else
            status = copy_xattr(&log->memory, &record->value.xattr,
                                &log->pending.entry.xattrs[
                                    log->pending.xattrs_seen]);
        if (status == SIDECAR_STATUS_OK)
            log->pending.xattrs_seen++;
    }
    else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT)
    {
        size_t existing_index = 0;
        if (log->pending.entry.entry.root_id.data == NULL ||
            log->pending.xattrs_seen != log->pending.entry.entry.xattr_count)
            status = SIDECAR_STATUS_CORRUPT;
        else
            status = map_prepare_commit(&log->memory, &log->map,
                                        &log->pending.entry, &existing_index);
        if (status == SIDECAR_STATUS_OK)
            map_apply_commit(&log->memory, &log->map, &log->pending,
                             existing_index);
    }
    else if (record->type == SIDECAR_RECORD_DELETE)
    {
        if (log->pending.entry.entry.root_id.data != NULL)
            status = SIDECAR_STATUS_CORRUPT;
        else
            status = map_apply_delete(&log->memory, &log->map,
                                      record->value.deletion.root_id,
                                      record->value.deletion.logical_path);
    }
    else
        status = SIDECAR_STATUS_CORRUPT;

    if (status != SIDECAR_STATUS_OK)
    {
        load->error = status;
        return -1;
    }
    return 0;
}

const char *sidecar_open_status_string(SidecarOpenStatus status)
{
    switch (status)
    {
        case SIDECAR_OPEN_FRESH: return "fresh";
        case SIDECAR_OPEN_RESUMABLE: return "resumable";
        case SIDECAR_OPEN_MISSING: return "missing";
        case SIDECAR_OPEN_EXISTS: return "already exists";
        case SIDECAR_OPEN_UNUSABLE: return "unusable";
        case SIDECAR_OPEN_IO_ERROR: return "I/O error";
        case SIDECAR_OPEN_ALLOCATION: return "allocation failure";
        case SIDECAR_OPEN_INVALID_ARGUMENT: return "invalid argument";
    }
    return "unknown status";
}

static SidecarOpenStatus validate_slot_fd(int fd, struct stat *out)
{
    struct stat st;
    if (fstat(fd, &st) != 0)
        return SIDECAR_OPEN_IO_ERROR;
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1)
        return SIDECAR_OPEN_UNUSABLE;
    if (out != NULL)
        *out = st;
    return SIDECAR_OPEN_RESUMABLE;
}

static SidecarLogImplementation *allocate_log(int fd)
{
    SidecarLogImplementation *log = calloc(1, sizeof(*log));
    if (log == NULL)
        return NULL;
    log->fd = fd;
    return log;
}

SidecarOpenStatus sidecar_log_create_at(int container_fd, SidecarLog *out)
{
    if (container_fd < 0 || out == NULL || out->implementation != NULL)
        return SIDECAR_OPEN_INVALID_ARGUMENT;

    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0)
    {
        if (errno == EEXIST)
            return SIDECAR_OPEN_EXISTS;
        return SIDECAR_OPEN_IO_ERROR;
    }

    struct stat st;
    SidecarOpenStatus slot_status = validate_slot_fd(fd, &st);
    if (slot_status != SIDECAR_OPEN_RESUMABLE)
    {
        int saved = errno;
        unlink_owned_slot(container_fd, fd);
        close(fd);
        errno = saved;
        return slot_status;
    }

    SidecarLogImplementation *log = allocate_log(fd);
    if (log == NULL)
    {
        int saved = errno;
        unlink_owned_slot(container_fd, fd);
        close(fd);
        errno = saved;
        return SIDECAR_OPEN_ALLOCATION;
    }
    if (sidecar_write_header(fd) != 0 || update_boundary(log) != 0)
    {
        int saved = errno;
        unlink_owned_slot(container_fd, fd);
        free_log_implementation(log);
        close(fd);
        errno = saved;
        return errno == ENOMEM ? SIDECAR_OPEN_ALLOCATION
                               : SIDECAR_OPEN_IO_ERROR;
    }
    out->implementation = log;
    return SIDECAR_OPEN_FRESH;
}

SidecarOpenStatus sidecar_log_adopt_at(int container_fd, SidecarLog *out)
{
    if (container_fd < 0 || out == NULL || out->implementation != NULL)
        return SIDECAR_OPEN_INVALID_ARGUMENT;

    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        if (errno == ENOENT)
            return SIDECAR_OPEN_MISSING;
        return unusable_open_errno(errno) ? SIDECAR_OPEN_UNUSABLE
                                          : SIDECAR_OPEN_IO_ERROR;
    }

    struct stat initial_stat;
    SidecarOpenStatus slot_status = validate_slot_fd(fd, &initial_stat);
    if (slot_status != SIDECAR_OPEN_RESUMABLE)
    {
        close(fd);
        return slot_status;
    }

    SidecarLogImplementation *log = allocate_log(fd);
    if (log == NULL)
    {
        int saved = errno;
        close(fd);
        errno = saved;
        return SIDECAR_OPEN_ALLOCATION;
    }

    LoadContext load = { .log = log, .error = SIDECAR_STATUS_OK };
    SidecarParseResult result;
    SidecarStatus parse_status = sidecar_parse_fd(fd, load_callback, &load,
                                                  &result);
    struct stat final_stat;
    if (fstat(fd, &final_stat) != 0 || final_stat.st_size != initial_stat.st_size)
    {
        free_log_implementation(log);
        close(fd);
        return SIDECAR_OPEN_IO_ERROR;
    }
    if (parse_status != SIDECAR_STATUS_OK &&
        parse_status != SIDECAR_STATUS_TRUNCATED_TAIL)
    {
        SidecarOpenStatus failure = classify_parse_failure(parse_status,
                                                            load.error);
        free_log_implementation(log);
        close(fd);
        return failure;
    }

    if (parse_status == SIDECAR_STATUS_TRUNCATED_TAIL)
    {
        off_t truncate_offset = (off_t)result.last_valid_boundary;
        if (result.last_valid_boundary > result.bytes_read ||
            result.last_valid_boundary > SIDECAR_MAX_TOTAL_BYTES ||
            truncate_offset < 0 ||
            (uint64_t)truncate_offset != result.last_valid_boundary)
        {
            free_log_implementation(log);
            close(fd);
            return SIDECAR_OPEN_UNUSABLE;
        }
        clear_entry(&log->memory, &log->pending.entry);
        log->pending.xattrs_seen = 0;
        if (ftruncate(fd, truncate_offset) != 0)
        {
            free_log_implementation(log);
            close(fd);
            return SIDECAR_OPEN_IO_ERROR;
        }
    }

    log->boundary = result.last_valid_boundary;
    if (parse_status == SIDECAR_STATUS_OK && update_boundary(log) != 0)
    {
        free_log_implementation(log);
        close(fd);
        return SIDECAR_OPEN_IO_ERROR;
    }
    out->implementation = log;
    return SIDECAR_OPEN_RESUMABLE;
}

SidecarStatus sidecar_log_close(SidecarLog *log)
{
    if (log == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarLogImplementation *implementation = log->implementation;
    if (implementation == NULL)
        return SIDECAR_STATUS_OK;

    int close_result = close(implementation->fd);
    free_log_implementation(implementation);
    log->implementation = NULL;
    return close_result == 0 ? SIDECAR_STATUS_OK : SIDECAR_STATUS_IO_ERROR;
}

static SidecarStatus ready_log(SidecarLog *log,
                               SidecarLogImplementation **out)
{
    if (log == NULL || log->implementation == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarLogImplementation *implementation = log->implementation;
    if (implementation->poisoned)
        return SIDECAR_STATUS_IO_ERROR;
    if (out != NULL)
        *out = implementation;
    return SIDECAR_STATUS_OK;
}

SidecarStatus sidecar_log_append_entry(SidecarLog *log,
                                       const SidecarEntry *entry)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK || entry == NULL)
        return status != SIDECAR_STATUS_OK ? status
                                           : SIDECAR_STATUS_INVALID_ARGUMENT;
    if (implementation->pending.entry.entry.root_id.data != NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    StateEntry copy;
    status = copy_entry(&implementation->memory, entry, &copy);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (!append_entry_supported(entry))
    {
        clear_entry(&implementation->memory, &copy);
        errno = EOPNOTSUPP;
        return SIDECAR_STATUS_UNSUPPORTED_KIND;
    }
    if (sidecar_write_entry(implementation->fd, entry) != 0)
    {
        status = status_from_errno();
        clear_entry(&implementation->memory, &copy);
        poison(implementation);
        return status;
    }
    implementation->pending.entry = copy;
    implementation->pending.xattrs_seen = 0;
    if (update_boundary(implementation) != 0)
    {
        poison(implementation);
        return SIDECAR_STATUS_IO_ERROR;
    }
    return SIDECAR_STATUS_OK;
}

SidecarStatus sidecar_log_append_xattr(SidecarLog *log,
                                       const SidecarXattr *xattr)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (xattr == NULL || implementation->pending.entry.entry.root_id.data == NULL ||
        implementation->pending.xattrs_seen >=
            implementation->pending.entry.entry.xattr_count)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    SidecarXattr copy;
    status = copy_xattr(&implementation->memory, xattr, &copy);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (sidecar_write_xattr(implementation->fd, xattr) != 0)
    {
        status = status_from_errno();
        clear_xattr(&implementation->memory, &copy);
        poison(implementation);
        return status;
    }
    implementation->pending.entry.xattrs[
        implementation->pending.xattrs_seen++] = copy;
    if (update_boundary(implementation) != 0)
    {
        poison(implementation);
        return SIDECAR_STATUS_IO_ERROR;
    }
    return SIDECAR_STATUS_OK;
}

SidecarStatus sidecar_log_append_entry_commit(SidecarLog *log)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (implementation->pending.entry.entry.root_id.data == NULL ||
        implementation->pending.xattrs_seen !=
            implementation->pending.entry.entry.xattr_count)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    size_t existing_index = 0;
    status = map_prepare_commit(&implementation->memory, &implementation->map,
                                &implementation->pending.entry,
                                &existing_index);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (sidecar_write_entry_commit(implementation->fd) != 0)
    {
        status = status_from_errno();
        poison(implementation);
        return status;
    }
    map_apply_commit(&implementation->memory, &implementation->map,
                     &implementation->pending, existing_index);
    if (update_boundary(implementation) != 0)
    {
        poison(implementation);
        return SIDECAR_STATUS_IO_ERROR;
    }
    return SIDECAR_STATUS_OK;
}

SidecarStatus sidecar_log_append_delete(SidecarLog *log,
                                        const SidecarDelete *deletion)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (deletion == NULL || implementation->pending.entry.entry.root_id.data != NULL ||
        !valid_key(deletion->root_id, deletion->logical_path))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (implementation->map.generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    if (sidecar_write_delete(implementation->fd, deletion) != 0)
    {
        status = status_from_errno();
        poison(implementation);
        return status;
    }
    status = map_apply_delete(&implementation->memory, &implementation->map,
                              deletion->root_id, deletion->logical_path);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (update_boundary(implementation) != 0)
    {
        poison(implementation);
        return SIDECAR_STATUS_IO_ERROR;
    }
    return SIDECAR_STATUS_OK;
}

size_t sidecar_log_live_count(const SidecarLog *log)
{
    if (log == NULL || log->implementation == NULL)
        return 0;
    const SidecarLogImplementation *implementation = log->implementation;
    return implementation->map.count;
}

int sidecar_log_find(const SidecarLog *log, SidecarBytes root_id,
                     SidecarBytes logical_path, SidecarLiveView *out)
{
    if (out == NULL)
    {
        set_invalid_error();
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (log == NULL || log->implementation == NULL ||
        !valid_key(root_id, logical_path))
    {
        set_invalid_error();
        return -1;
    }
    const SidecarLogImplementation *implementation = log->implementation;
    int index = map_find(&implementation->map, root_id, logical_path);
    if (index < 0)
        return 0;
    const StateEntry *entry = &implementation->map.items[index];
    out->entry = &entry->entry;
    out->xattrs = entry->xattrs;
    out->xattr_count = entry->entry.xattr_count;
    out->generation = entry->generation;
    return 1;
}
