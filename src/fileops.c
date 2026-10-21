#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <grp.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <limits.h> // to use PATH_MAX
#include <errno.h>
#include <stdint.h>

#include "fileops.h"
#include "container.h"
#include "selection.h"
#include "hash.h"
#include "metadata.h"
#include "portable.h"
#include "sidecar.h"
#include "utils.h" // path_join

typedef enum {
    RESTORE_RESOLVE_ERROR = -1,
    RESTORE_RESOLVE_MISSING = 0,
    RESTORE_RESOLVE_OK = 1
} RestoreResolveResult;

static RestoreResolveResult resolve_parent(int root_fd, const char *rel,
                                           int create_intermediates,
                                           int *out_parent_fd,
                                           char *out_leaf, size_t leaf_size);

/* ========================================================================= */
/* Native backup capture: pathname-based source, FD-anchored destination.   */
/*                                                                          */
/* The source side is read through ordinary paths (it is the user's own     */
/* tree, addressed exactly as they named it). The destination side never is:*/
/* every step down uses openat/mkdirat/fstatat under a directory fd the     */
/* caller owns, with O_NOFOLLOW everywhere, so neither an intermediate nor  */
/* a final symlink inside the container can redirect a write outside it --  */
/* which is what makes resuming into an adopted, previously-written         */
/* container safe (docs/DECISIONS.md D15).                                  */
/* ========================================================================= */

// A destination address this walker accepts is exactly one path component.
// Anything with a '/' would be a path to re-resolve, which is precisely what
// the fd anchoring exists to avoid; "." and ".." address the parent rather
// than a new object.
static int destination_leaf_is_safe(const char *leaf)
{
    return leaf != NULL && leaf[0] != '\0' &&
           strchr(leaf, '/') == NULL &&
           strcmp(leaf, ".") != 0 &&
           strcmp(leaf, "..") != 0;
}

// A root's payload may sit in a folder of data/ (docs/DECISIONS.md D82), so
// the capture entry point takes a relative path of such leaves.
static int destination_path_is_safe(const char *path)
{
    if (path == NULL || strnlen(path, PATH_MAX) >= PATH_MAX)
        return 0;
    char copy[PATH_MAX];
    strcpy(copy, path);
    char *leaf = copy;
    for (char *slash; (slash = strchr(leaf, '/')) != NULL; leaf = slash + 1)
    {
        *slash = '\0';
        if (!destination_leaf_is_safe(leaf))
            return 0;
    }
    return destination_leaf_is_safe(leaf);
}

static void capture_record(BackupCaptureReport *report,
                           BackupCaptureFailureKind kind,
                           const char *source_path, const char *operation,
                           int err)
{
    if (report == NULL ||
        (report->failure_kind != BACKUP_CAPTURE_FAILURE_NONE &&
         (kind == BACKUP_CAPTURE_FAILURE_ITEM ||
          report->failure_kind != BACKUP_CAPTURE_FAILURE_ITEM)))
        return;
    (void)snprintf(report->failed_source_path,
                   sizeof(report->failed_source_path), "%s",
                   source_path != NULL ? source_path : "");
    report->failure_kind = kind;
    report->failure_errno = err;
    report->failed_operation = operation;
}

// Keeps the first item a native capture could not handle, what was being
// done, and err, 0 when operation says why on its own. Called before any
// cleanup that could change errno. It replaces an item failure not listed
// yet: the backup stops, and that is what it says.
static void capture_fail(BackupCaptureReport *report, const char *source_path,
                         const char *operation, int err)
{
    capture_record(report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, source_path,
                   operation, err);
}

// A source item that could not be read (D109): capture_entry_at() lists it
// and the walk goes on.
static BackupCaptureStatus capture_item_fail(BackupCaptureReport *report,
                                             const char *source_path,
                                             const char *operation, int err)
{
    capture_record(report, BACKUP_CAPTURE_FAILURE_ITEM, source_path,
                   operation, err);
    return BACKUP_CAPTURE_ITEM_FAILED;
}

#ifdef BACKUP_TEST_HOOKS
static BackupTestCaptureHook backup_test_capture_hook;
static void *backup_test_capture_context;

void backup_test_set_capture_hook(BackupTestCaptureHook hook, void *context)
{
    backup_test_capture_hook = hook;
    backup_test_capture_context = context;
}

static void backup_test_before_capture_source_open(const char *source_path)
{
    if (backup_test_capture_hook != NULL)
        backup_test_capture_hook(source_path, backup_test_capture_context);
}

static int backup_test_open_fault;

void backup_test_fail_next_source_open(int error)
{
    backup_test_open_fault = error;
}

static int backup_test_write_fault;
static size_t backup_test_write_faults;

void backup_test_fail_content_writes(int error, size_t count)
{
    backup_test_write_fault = error;
    backup_test_write_faults = count;
}

static BackupTestCaptureHook backup_test_after_copy_hook;
static void *backup_test_after_copy_context;

void backup_test_set_after_copy_hook(BackupTestCaptureHook hook,
                                     void *context)
{
    backup_test_after_copy_hook = hook;
    backup_test_after_copy_context = context;
}
#endif

// Opens a capture source; tests can make the next open fail.
static int capture_open_source(const char *path, int flags)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_open_fault != 0)
    {
        errno = backup_test_open_fault;
        backup_test_open_fault = 0;
        return -1;
    }
#endif
    return open(path, flags);
}

static void backup_test_after_capture_copy(const char *source_path)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_after_copy_hook != NULL)
        backup_test_after_copy_hook(source_path,
                                    backup_test_after_copy_context);
#else
    (void)source_path;
#endif
}

typedef struct {
    dev_t device;
    ino_t inode;
    int parent_fd;
    char leaf[NAME_MAX + 1U];
    int used;
} NativeInodeSlot;

typedef struct {
    dev_t device;
    ino_t inode;
    int fd;
    int used;
} NativeDirFdSlot;

typedef struct {
    NativeDirFdSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} NativeDirFdPool;

typedef struct {
    NativeInodeSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
    NativeDirFdPool dir_pool;
} NativeInodeMap;

static uint64_t native_inode_hash(const NativeInodeMap *map, dev_t device,
                                  ino_t inode)
{
    return hash_uint64_pair(map->hash_salt, (uint64_t)device, (uint64_t)inode);
}

static int native_inode_map_rehash(NativeInodeMap *map, size_t capacity)
{
    if (map == NULL || capacity < 16U ||
        (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(*map->slots))
        return -1;

    NativeInodeSlot *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL)
        return -1;

    for (size_t i = 0; i < map->capacity; i++)
    {
        NativeInodeSlot *old_slot = &map->slots[i];
        if (!old_slot->used)
            continue;

        size_t index = (size_t)native_inode_hash(map, old_slot->device,
                                                  old_slot->inode) &
                       (capacity - 1U);
        while (slots[index].used)
            index = (index + 1U) & (capacity - 1U);
        slots[index] = *old_slot;
    }

    free(map->slots);
    map->slots = slots;
    map->capacity = capacity;
    return 0;
}

static void native_inode_map_count_probe(void);

static int native_inode_map_locate(const NativeInodeMap *map,
                                   dev_t device, ino_t inode,
                                   size_t *out_index)
{
    if (map == NULL || out_index == NULL)
        return -1;
    if (map->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)native_inode_hash(map, device, inode) &
                   (map->capacity - 1U);
    for (size_t probes = 0; probes < map->capacity; probes++)
    {
        native_inode_map_count_probe();
        const NativeInodeSlot *slot = &map->slots[index];
        if (!slot->used)
        {
            *out_index = index;
            return 0;
        }
        if (slot->device == device && slot->inode == inode)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (map->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

static uint64_t native_dir_fd_hash(const NativeDirFdPool *pool,
                                   dev_t device, ino_t inode)
{
    return hash_uint64_pair(pool->hash_salt, (uint64_t)device, (uint64_t)inode);
}

static int native_dir_fd_pool_rehash(NativeDirFdPool *pool, size_t capacity)
{
    if (pool == NULL || capacity < 16U ||
        (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(*pool->slots))
        return -1;

    NativeDirFdSlot *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL)
        return -1;

    for (size_t i = 0; i < pool->capacity; i++)
    {
        NativeDirFdSlot *old_slot = &pool->slots[i];
        if (!old_slot->used)
            continue;

        size_t index = (size_t)native_dir_fd_hash(pool, old_slot->device,
                                                   old_slot->inode) &
                       (capacity - 1U);
        while (slots[index].used)
            index = (index + 1U) & (capacity - 1U);
        slots[index] = *old_slot;
    }

    free(pool->slots);
    pool->slots = slots;
    pool->capacity = capacity;
    return 0;
}

static int native_dir_fd_pool_locate(const NativeDirFdPool *pool,
                                     dev_t device, ino_t inode,
                                     size_t *out_index)
{
    if (pool == NULL || out_index == NULL)
        return -1;
    if (pool->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)native_dir_fd_hash(pool, device, inode) &
                   (pool->capacity - 1U);
    for (size_t probes = 0; probes < pool->capacity; probes++)
    {
        const NativeDirFdSlot *slot = &pool->slots[index];
        if (!slot->used)
        {
            *out_index = index;
            return 0;
        }
        if (slot->device == device && slot->inode == inode)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (pool->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

static int native_dir_fd_pool_acquire(NativeDirFdPool *pool, int parent_fd,
                                      int *out_fd)
{
    if (pool == NULL || parent_fd < 0 || out_fd == NULL)
        return -1;

    struct stat dir_st;
    if (fstat(parent_fd, &dir_st) != 0)
        return -1;

    if (pool->capacity == 0 &&
        native_dir_fd_pool_rehash(pool, 16U) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = native_dir_fd_pool_locate(pool, dir_st.st_dev,
                                             dir_st.st_ino, &index);
    if (location < 0)
        return -1;
    if (location == 1)
    {
        *out_fd = pool->slots[index].fd;
        return 0;
    }

    if (pool->count >= pool->capacity - pool->capacity / 3U)
    {
        if (pool->capacity > SIZE_MAX / 2U ||
            native_dir_fd_pool_rehash(pool, pool->capacity * 2U) != 0)
            return -1;
        location = native_dir_fd_pool_locate(pool, dir_st.st_dev,
                                             dir_st.st_ino, &index);
        if (location != 0)
            return -1;
    }

    int duplicate_fd = fcntl(parent_fd, F_DUPFD_CLOEXEC, 0);
    if (duplicate_fd < 0)
        return -1;

    NativeDirFdSlot *slot = &pool->slots[index];
    slot->device = dir_st.st_dev;
    slot->inode = dir_st.st_ino;
    slot->fd = duplicate_fd;
    slot->used = 1;
    pool->count++;
    *out_fd = duplicate_fd;
    return 0;
}

void *native_inode_map_create(void)
{
    NativeInodeMap *map = calloc(1, sizeof(*map));
    if (map == NULL)
        return NULL;
    map->hash_salt = sidecar_process_salt();
    map->dir_pool.hash_salt = sidecar_process_salt();
    if (native_inode_map_rehash(map, 16U) != 0)
    {
        free(map->slots);
        free(map);
        return NULL;
    }
    return map;
}

void native_inode_map_free(void *opaque_map)
{
    NativeInodeMap *map = opaque_map;
    if (map == NULL)
        return;
    for (size_t i = 0; i < map->dir_pool.capacity; i++)
        if (map->dir_pool.slots[i].used)
            close(map->dir_pool.slots[i].fd);
    free(map->dir_pool.slots);
    free(map->slots);
    free(map);
}

static int native_inode_map_find(const NativeInodeMap *map,
                                 dev_t device, ino_t inode,
                                 int *parent_fd_out, char *leaf_out,
                                 size_t leaf_size)
{
    if (map == NULL || parent_fd_out == NULL || leaf_out == NULL ||
        leaf_size == 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = native_inode_map_locate(map, device, inode, &index);
    if (location < 0)
        return -1;
    if (location == 0)
        return 0;

    const NativeInodeSlot *slot = &map->slots[index];
    size_t length = strnlen(slot->leaf, sizeof(slot->leaf));
    if (length >= leaf_size)
        return -1;
    *parent_fd_out = slot->parent_fd;
    memcpy(leaf_out, slot->leaf, length + 1U);
    return 1;
}

static int native_inode_map_insert(NativeInodeMap *map, dev_t device,
                                   ino_t inode, int parent_fd,
                                   const char *leaf)
{
    if (map == NULL || parent_fd < 0 || leaf == NULL)
        return -1;
    size_t leaf_length = strnlen(leaf, NAME_MAX + 1U);
    if (leaf_length == 0 || leaf_length > NAME_MAX)
        return -1;

    size_t index = SIZE_MAX;
    int location = native_inode_map_locate(map, device, inode, &index);
    if (location < 0)
        return -1;
    if (location == 1)
        return 0;

    if (map->count >= map->capacity - map->capacity / 3U)
    {
        if (map->capacity > SIZE_MAX / 2U ||
            native_inode_map_rehash(map, map->capacity * 2U) != 0)
            return -1;
        location = native_inode_map_locate(map, device, inode, &index);
        if (location != 0)
            return -1;
    }

    int pooled_fd = -1;
    if (native_dir_fd_pool_acquire(&map->dir_pool, parent_fd,
                                   &pooled_fd) != 0)
        return -1;
    NativeInodeSlot *slot = &map->slots[index];
    slot->device = device;
    slot->inode = inode;
    slot->parent_fd = pooled_fd;
    memcpy(slot->leaf, leaf, leaf_length + 1U);
    slot->used = 1;
    map->count++;
    return 0;
}

typedef struct {
    dev_t device;
    ino_t inode;
} NativeEstimateInode;

typedef struct {
    NativeEstimateInode *items;
    size_t count;
    size_t items_capacity;
    size_t *slots;
    size_t capacity;
} NativeEstimateSeen;

static uint64_t native_estimate_inode_hash(dev_t device, ino_t inode)
{
    return hash_uint64_pair(0, (uint64_t)device, (uint64_t)inode);
}

static int native_estimate_seen_rehash(NativeEstimateSeen *seen,
                                       size_t capacity)
{
    if (seen == NULL || capacity < 16U ||
        (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(*seen->slots))
        return -1;

    size_t *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL)
        return -1;

    for (size_t item_index = 0; item_index < seen->count; item_index++)
    {
        size_t index = (size_t)native_estimate_inode_hash(
            seen->items[item_index].device, seen->items[item_index].inode) &
                       (capacity - 1U);
        while (slots[index] != 0)
            index = (index + 1U) & (capacity - 1U);
        slots[index] = item_index + 1U;
    }

    free(seen->slots);
    seen->slots = slots;
    seen->capacity = capacity;
    return 0;
}

/* Returns 1 for a match, 0 for an insertion slot, or -1 if full. */
static int native_estimate_seen_locate(const NativeEstimateSeen *seen,
                                       dev_t device, ino_t inode,
                                       size_t *out_index)
{
    if (seen == NULL || out_index == NULL)
        return -1;
    if (seen->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)native_estimate_inode_hash(device, inode) &
                   (seen->capacity - 1U);
    for (size_t probes = 0; probes < seen->capacity; probes++)
    {
        size_t value = seen->slots[index];
        if (value == 0)
        {
            *out_index = index;
            return 0;
        }
        size_t item_index = value - 1U;
        if (item_index < seen->count &&
            seen->items[item_index].device == device &&
            seen->items[item_index].inode == inode)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (seen->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

static int native_estimate_seen_contains(const NativeEstimateSeen *seen,
                                         dev_t device, ino_t inode)
{
    if (seen == NULL || seen->capacity == 0)
        return 0;
    size_t index = SIZE_MAX;
    return native_estimate_seen_locate(seen, device, inode, &index) == 1;
}

static int native_estimate_seen_add(NativeEstimateSeen *seen, dev_t device,
                                    ino_t inode)
{
    if (seen == NULL)
        return -1;

    if (seen->capacity == 0 && native_estimate_seen_rehash(seen, 16U) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = native_estimate_seen_locate(seen, device, inode, &index);
    if (location == 1)
        return 0;
    if (location < 0)
        return -1;

    if (seen->count == SIZE_MAX)
    {
        errno = EOVERFLOW;
        return -1;
    }
    if (seen->count + 1U > seen->capacity / 2U)
    {
        if (seen->capacity > SIZE_MAX / 2U ||
            native_estimate_seen_rehash(seen, seen->capacity * 2U) != 0)
            return -1;
        location = native_estimate_seen_locate(seen, device, inode, &index);
        if (location != 0)
            return -1;
    }

    if (seen->count == seen->items_capacity)
    {
        NativeEstimateInode *items = array_reserve(
            seen->items, &seen->items_capacity, seen->count, 1U,
            sizeof(*items), 16U, SIZE_MAX / sizeof(*items));
        if (items == NULL)
            return -1;
        seen->items = items;
    }

    seen->items[seen->count] = (NativeEstimateInode){
        .device = device, .inode = inode
    };
    seen->slots[index] = seen->count + 1U;
    seen->count++;
    return 0;
}

static void native_estimate_seen_free(NativeEstimateSeen *seen)
{
    if (seen == NULL)
        return;
    free(seen->items);
    free(seen->slots);
    free(seen);
}

void native_restore_estimate_init(NativeRestoreEstimate *estimate)
{
    if (estimate == NULL)
        return;
    memset(estimate, 0, sizeof(*estimate));
}

void native_restore_estimate_free(NativeRestoreEstimate *estimate)
{
    if (estimate == NULL)
        return;
    native_estimate_seen_free(estimate->seen_inodes);
    memset(estimate, 0, sizeof(*estimate));
}

static void native_restore_estimate_add_bytes(NativeRestoreEstimate *estimate,
                                              off_t bytes)
{
    if (estimate == NULL || estimate->had_error)
        return;
    if (bytes < 0 || estimate->estimated_bytes < 0 ||
        (uintmax_t)estimate->estimated_bytes >
            (uintmax_t)INTMAX_MAX - (uintmax_t)bytes)
    {
        estimate->had_error = 1;
        return;
    }
    estimate->estimated_bytes += bytes;
}

static void native_restore_estimate_item(NativeRestoreEstimate *estimate)
{
    if (estimate == NULL)
        return;
    estimate->items++;
    if (estimate->on_item != NULL)
        estimate->on_item(estimate->items, estimate->on_item_context);
}

static void native_restore_estimate_regular(NativeRestoreEstimate *estimate,
                                            const struct stat *st)
{
    if (estimate == NULL || estimate->had_error || st == NULL)
        return;

    NativeEstimateSeen *seen = estimate->seen_inodes;
    if (st->st_nlink > 1)
    {
        if (seen == NULL)
        {
            seen = calloc(1, sizeof(*seen));
            if (seen == NULL)
            {
                estimate->had_error = 1;
                return;
            }
            estimate->seen_inodes = seen;
        }
        if (native_estimate_seen_contains(seen, st->st_dev, st->st_ino))
            return;
        if (native_estimate_seen_add(seen, st->st_dev, st->st_ino) != 0)
        {
            estimate->had_error = 1;
            return;
        }
    }
    native_restore_estimate_add_bytes(estimate, st->st_size);
}

static int native_seed_destination_matches(const CloneContext *ctx,
                                           const struct stat *source,
                                           const struct stat *destination)
{
    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
    return ctx != NULL && source != NULL && destination != NULL &&
           S_ISREG(destination->st_mode) &&
           destination->st_size == source->st_size &&
           destination->st_mtim.tv_sec == source->st_mtim.tv_sec &&
           policy.nsec_exact &&
           destination->st_mtim.tv_nsec == source->st_mtim.tv_nsec;
}

// Restore roots may name a nested relative destination, or the destination
// root itself (""), while native capture always supplies one leaf. Keep the
// seed walk fd-anchored for both shapes and treat a missing intermediate as
// an empty pre-existing subtree rather than creating anything here.
static int native_seed_relative_path_is_safe(const char *rel)
{
    if (rel == NULL || rel[0] == '/')
        return 0;
    if (rel[0] == '\0')
        return 1;

    const char *start = rel;
    for (const char *p = rel;; p++)
    {
        if (p[0] != '/' && p[0] != '\0')
            continue;
        size_t length = (size_t)(p - start);
        if (length == 0 || length > NAME_MAX ||
            (length == 1 && start[0] == '.') ||
            (length == 2 && start[0] == '.' && start[1] == '.'))
            return 0;
        if (p[0] == '\0')
            return 1;
        start = p + 1;
    }
}

static int native_inode_map_seed_existing_at(
    const CloneContext *ctx, const char *source_path, int destination_dir_fd,
    const char *destination_leaf, FailedItem *failed);

static int native_inode_map_seed_existing_directory_at(
    const CloneContext *ctx, const char *source_path, int source_fd,
    int destination_fd, FailedItem *failed)
{
    // What cannot be listed or named is left to the capture pass, which
    // lists it (D109).
    int result = 0;
    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL && scan_fd >= 0)
        close(scan_fd);
    while (directory != NULL)
    {
        struct dirent *entry = readdir(directory);
        if (entry == NULL)
            break;
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_source[PATH_MAX];
        if (path_join(child_source, sizeof(child_source), source_path,
                      entry->d_name) != 0)
            continue;
        if (native_inode_map_seed_existing_at(ctx, child_source,
                                               destination_fd, entry->d_name,
                                               failed) != 0)
        {
            result = -1;
            break;
        }
    }
    if (directory != NULL && closedir(directory) != 0)
    {
        failed_item_note(failed, source_path, "list the folder", errno);
        result = -1;
    }
    if (close(source_fd) != 0)
    {
        failed_item_note(failed, source_path, "close the folder", errno);
        result = -1;
    }
    if (close(destination_fd) != 0)
    {
        failed_item_note(failed, source_path, "close its existing copy",
                         errno);
        result = -1;
    }
    return result;
}

// Opens the source folder already known to be one, for the walk below it;
// 1 to skip it (unreadable, which the capture pass lists, or changed).
static int native_seed_open_folder(const char *source_path,
                                   const struct stat *source_st,
                                   int *source_fd)
{
    *source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                       O_NOATIME | O_CLOEXEC);
    if (*source_fd < 0)
        return 1;
    struct stat opened;
    if (fstat(*source_fd, &opened) != 0 ||
        !metadata_source_unchanged(source_st, &opened))
    {
        close(*source_fd);
        return 1;
    }
    return 0;
}

static int native_inode_map_seed_existing_at(
    const CloneContext *ctx, const char *source_path, int destination_dir_fd,
    const char *destination_leaf, FailedItem *failed)
{
    if (ctx->selection)
    {
        int owned = selection_source_owns(ctx->selection, source_path);
        if (owned < 0)
            failed_item_note(failed, source_path,
                             "it lies outside its root in the selection", 0);
        if (owned <= 0) return owned;
    }
    // Seeding only saves relinking hardlinks on a resume; a source that
    // vanished or changed since is left to the capture pass (D63), and so is
    // one that cannot be read, which it lists (D109).
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        return 0;

    struct stat destination_st;
    if (fstatat(destination_dir_fd, destination_leaf, &destination_st,
                AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (errno == ENOENT)
            return 0;
        failed_item_note(failed, source_path, "inspect its existing copy",
                         errno);
        return -1;
    }

    if (S_ISREG(source_st.st_mode))
    {
        if (source_st.st_nlink <= 1 ||
            !native_seed_destination_matches(ctx, &source_st,
                                              &destination_st))
            return 0;

        int source_fd = open(source_path,
                             O_RDONLY | O_NOATIME | O_CLOEXEC | O_NOFOLLOW);
        if (source_fd < 0)
            return 0;
        struct stat opened;
        int result = 0;
        int changed = fstat(source_fd, &opened) != 0 ||
                      !metadata_source_unchanged(&source_st, &opened);
        if (close(source_fd) != 0)
        {
            failed_item_note(failed, source_path, "close it", errno);
            result = -1;
        }
        if (result != 0 || changed)
            return result;
        if (native_inode_map_insert(ctx->inode_map, source_st.st_dev,
                                    source_st.st_ino, destination_dir_fd,
                                    destination_leaf) != 0)
        {
            failed_item_note(failed, source_path, "record its other names",
                             errno);
            return -1;
        }
        return 0;
    }

    if (!S_ISDIR(source_st.st_mode) || !S_ISDIR(destination_st.st_mode))
        return 0;

    int source_fd;
    if (native_seed_open_folder(source_path, &source_st, &source_fd) != 0)
        return 0;

    int destination_fd = openat(destination_dir_fd, destination_leaf,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                O_CLOEXEC);
    if (destination_fd < 0)
    {
        failed_item_note(failed, source_path, "open its existing copy",
                         errno);
        close(source_fd);
        return -1;
    }
    return native_inode_map_seed_existing_directory_at(
        ctx, source_path, source_fd, destination_fd, failed);
}

static int native_inode_map_seed_existing_root_at(
    const CloneContext *ctx, const char *source_path, int destination_root_fd,
    FailedItem *failed)
{
    if (ctx->selection)
    {
        int owned = selection_source_owns(ctx->selection, source_path);
        if (owned < 0)
            failed_item_note(failed, source_path,
                             "it lies outside its root in the selection", 0);
        if (owned <= 0) return owned;
    }
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        return 0;

    struct stat destination_st;
    if (fstat(destination_root_fd, &destination_st) != 0)
    {
        failed_item_note(failed, source_path, "inspect its existing copy",
                         errno);
        return -1;
    }
    if (!S_ISDIR(destination_st.st_mode) || !S_ISDIR(source_st.st_mode))
        return 0;

    int source_fd;
    if (native_seed_open_folder(source_path, &source_st, &source_fd) != 0)
        return 0;

    int destination_fd = fcntl(destination_root_fd, F_DUPFD_CLOEXEC, 0);
    if (destination_fd < 0)
    {
        failed_item_note(failed, source_path, "open its existing copy",
                         errno);
        close(source_fd);
        return -1;
    }
    return native_inode_map_seed_existing_directory_at(
        ctx, source_path, source_fd, destination_fd, failed);
}

int native_inode_map_seed_existing(const CloneContext *ctx,
                                   const char *source_path,
                                   int destination_root_fd,
                                   const char *destination_rel,
                                   FailedItem *failed)
{
    if (ctx == NULL ||
        (ctx->operation != CLONE_BACKUP && ctx->operation != CLONE_RESTORE) ||
        ctx->representation != CLONE_NATIVE_TREE ||
        source_path == NULL || destination_root_fd < 0 ||
        !native_seed_relative_path_is_safe(destination_rel) ||
        (ctx->selection && ctx->operation != CLONE_BACKUP))
    {
        failed_item_note(failed, source_path != NULL ? source_path : "",
                         "it was given to the hardlink seeding wrongly", 0);
        return -1;
    }
    if (ctx->inode_map == NULL)
        return 0;
    if (destination_rel[0] == '\0')
        return native_inode_map_seed_existing_root_at(
            ctx, source_path, destination_root_fd, failed);

    int destination_parent_fd = -1;
    char destination_leaf[NAME_MAX + 1U];
    RestoreResolveResult resolved = resolve_parent(
        destination_root_fd, destination_rel, 0, &destination_parent_fd,
        destination_leaf, sizeof(destination_leaf));
    if (resolved == RESTORE_RESOLVE_MISSING)
        return 0;
    if (resolved != RESTORE_RESOLVE_OK)
    {
        failed_item_note(failed, source_path,
                         "open the folders above its existing copy", errno);
        return -1;
    }
    int result = native_inode_map_seed_existing_at(
        ctx, source_path, destination_parent_fd, destination_leaf, failed);
    if (close(destination_parent_fd) != 0)
    {
        failed_item_note(failed, source_path,
                         "close the folder above its existing copy", errno);
        result = -1;
    }
    return result;
}

int native_hardlink_identity_matches(const struct stat *linked,
                                     const struct stat *reference)
{
    return linked != NULL && reference != NULL &&
           linked->st_dev == reference->st_dev &&
           linked->st_ino == reference->st_ino;
}

typedef struct {
    char *root_key;
    size_t root_key_length;
    char *rel_path;
    size_t rel_path_length;
    uint64_t hash;
    int kept; /* Could not be read: kept with everything below it (D109). */
} NativeVisitedSlot;

typedef struct {
    NativeVisitedSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} NativeVisitedSet;

#ifdef NATIVE_VISITED_TEST_HOOKS
static uint64_t native_visited_probe_counter;

static void native_visited_count_probe(void)
{
    if (native_visited_probe_counter != UINT64_MAX)
        native_visited_probe_counter++;
}

uint64_t native_visited_test_probe_count(void)
{
    return native_visited_probe_counter;
}

void native_visited_test_reset_probe_count(void)
{
    native_visited_probe_counter = 0;
}

static uint64_t native_inode_map_probe_counter;

static void native_inode_map_count_probe(void)
{
    if (native_inode_map_probe_counter != UINT64_MAX)
        native_inode_map_probe_counter++;
}

uint64_t native_inode_map_test_probe_count(void)
{
    return native_inode_map_probe_counter;
}

void native_inode_map_test_reset_probe_count(void)
{
    native_inode_map_probe_counter = 0;
}
#else
static void native_visited_count_probe(void)
{
}

static void native_inode_map_count_probe(void)
{
}
#endif

#ifdef NATIVE_VISITED_TEST_HOOKS
size_t native_inode_map_test_dir_fd_count(const void *opaque_map)
{
    const NativeInodeMap *map = opaque_map;
    return map == NULL ? 0 : map->dir_pool.count;
}
#endif

static uint64_t native_visited_hash(const NativeVisitedSet *set,
                                    const char *root_key,
                                    size_t root_key_length,
                                    const char *rel_path,
                                    size_t rel_path_length)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ set->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)root_key_length);
    hash = hash_fnv1a_bytes(hash, (const unsigned char *)root_key,
                            root_key_length);
    hash = hash_fnv1a_uint64(hash, (uint64_t)rel_path_length);
    return hash_fnv1a_bytes(hash, (const unsigned char *)rel_path,
                            rel_path_length);
}

static int native_visited_rehash(NativeVisitedSet *set, size_t capacity)
{
    if (set == NULL || capacity < 16U ||
        (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(*set->slots))
        return -1;

    NativeVisitedSlot *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL)
        return -1;

    for (size_t old_index = 0; old_index < set->capacity; old_index++)
    {
        NativeVisitedSlot *old_slot = &set->slots[old_index];
        if (old_slot->root_key == NULL)
            continue;

        size_t index = (size_t)old_slot->hash & (capacity - 1U);
        while (slots[index].root_key != NULL)
            index = (index + 1U) & (capacity - 1U);
        slots[index] = *old_slot;
    }

    free(set->slots);
    set->slots = slots;
    set->capacity = capacity;
    return 0;
}

/* Returns 1 for a matching slot, 0 for an empty insertion slot, -1 if full. */
static int native_visited_locate(const NativeVisitedSet *set,
                                 const char *root_key,
                                 size_t root_key_length,
                                 const char *rel_path,
                                 size_t rel_path_length, uint64_t hash,
                                 size_t *out_index)
{
    if (set == NULL || out_index == NULL)
        return -1;
    if (set->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)hash & (set->capacity - 1U);
    for (size_t probes = 0; probes < set->capacity; probes++)
    {
        native_visited_count_probe();
        const NativeVisitedSlot *slot = &set->slots[index];
        if (slot->root_key == NULL)
        {
            *out_index = index;
            return 0;
        }
        if (slot->hash == hash &&
            slot->root_key_length == root_key_length &&
            slot->rel_path_length == rel_path_length &&
            memcmp(slot->root_key, root_key, root_key_length) == 0 &&
            memcmp(slot->rel_path, rel_path, rel_path_length) == 0)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (set->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

static void native_visited_slot_free(NativeVisitedSlot *slot)
{
    if (slot == NULL)
        return;
    free(slot->root_key);
    free(slot->rel_path);
    memset(slot, 0, sizeof(*slot));
}

void *native_visited_create(void)
{
    NativeVisitedSet *set = calloc(1, sizeof(*set));
    if (set == NULL)
        return NULL;
    set->hash_salt = sidecar_process_salt();
    if (native_visited_rehash(set, 16U) != 0)
    {
        free(set);
        return NULL;
    }
    return set;
}

void native_visited_free(void *opaque_set)
{
    NativeVisitedSet *set = opaque_set;
    if (set == NULL)
        return;
    for (size_t index = 0; index < set->capacity; index++)
        native_visited_slot_free(&set->slots[index]);
    free(set->slots);
    free(set);
}

static int native_visited_add(void *opaque_set, const char *root_key,
                              const char *rel_path, int kept)
{
    NativeVisitedSet *set = opaque_set;
    if (set == NULL || root_key == NULL || rel_path == NULL)
        return -1;

    size_t root_key_length = strlen(root_key);
    size_t rel_path_length = strlen(rel_path);

    uint64_t hash = native_visited_hash(set, root_key, root_key_length,
                                        rel_path, rel_path_length);
    size_t index = SIZE_MAX;
    int location = native_visited_locate(set, root_key, root_key_length,
                                          rel_path, rel_path_length, hash,
                                          &index);
    if (location == 1)
    {
        set->slots[index].kept |= kept;
        return 1;
    }
    if (location < 0)
        return -1;

    if (set->count >= set->capacity - set->capacity / 3U)
    {
        if (set->capacity > SIZE_MAX / 2U ||
            native_visited_rehash(set, set->capacity * 2U) != 0)
            return -1;
        location = native_visited_locate(set, root_key, root_key_length,
                                          rel_path, rel_path_length, hash,
                                          &index);
        if (location != 0)
            return -1;
    }

    char *root_copy = malloc(root_key_length + 1U);
    if (root_copy == NULL)
        return -1;
    char *rel_copy = malloc(rel_path_length + 1U);
    if (rel_copy == NULL)
    {
        free(root_copy);
        return -1;
    }
    memcpy(root_copy, root_key, root_key_length + 1U);
    memcpy(rel_copy, rel_path, rel_path_length + 1U);

    NativeVisitedSlot *slot = &set->slots[index];
    slot->root_key = root_copy;
    slot->root_key_length = root_key_length;
    slot->rel_path = rel_copy;
    slot->rel_path_length = rel_path_length;
    slot->hash = hash;
    slot->kept = kept;
    set->count++;
    return 0;
}

int native_visited_contains(const void *opaque_set, const char *root_key,
                            const char *rel_path)
{
    const NativeVisitedSet *set = opaque_set;
    if (set == NULL || root_key == NULL || rel_path == NULL)
        return -1;
    if (set->capacity == 0)
        return 0;

    size_t root_key_length = strlen(root_key);
    size_t rel_path_length = strlen(rel_path);
    uint64_t hash = native_visited_hash(set, root_key, root_key_length,
                                        rel_path, rel_path_length);
    size_t index = SIZE_MAX;
    int location = native_visited_locate(set, root_key, root_key_length,
                                          rel_path, rel_path_length, hash,
                                          &index);
    if (location < 0)
        return -1;
    if (location == 0)
        return 0;
    return set->slots[index].kept ? 2 : 1;
}

static int append_relative(char *destination, size_t destination_size,
                            const char *parent, const char *name)
{
    if (destination == NULL || parent == NULL || name == NULL)
        return -1;
    size_t parent_length = strnlen(parent, destination_size);
    size_t name_length = strlen(name);
    if (parent_length >= destination_size ||
        name_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0)
    {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, name, name_length + 1U);
    return 0;
}

static BackupCaptureStatus capture_entry_at(const CloneContext *ctx,
                                            const char *src,
                                            int dest_dir_fd, const char *leaf,
                                            const char *root_key,
                                            const char *rel_path,
                                            BackupCaptureReport *report);

static int native_remove_leaf(int parent_fd, const char *leaf);

// Everything at an address in a native backup was captured from the same
// source path (D72), so another kind of item there, or a link to another
// target, is an older copy: it is removed, never written through, and the
// current one takes its place.
static int capture_remove_older_copy(int dest_dir_fd, const char *leaf,
                                     const char *src,
                                     BackupCaptureReport *report)
{
    if (native_remove_leaf(dest_dir_fd, leaf) == 0)
        return 0;
    capture_fail(report, src, "remove its older copy in the backup", errno);
    return -1;
}

static int symlink_has_target_at(int dir_fd, const char *leaf,
                                 const char *target)
{
    char existing[PATH_MAX];
    ssize_t length = readlinkat(dir_fd, leaf, existing, sizeof(existing));
    return length >= 0 && (size_t)length == strlen(target) &&
           memcmp(existing, target, (size_t)length) == 0;
}

// An identical symlink already at this address is work a previous run
// finished, so resuming past it succeeds; anything else there is an older
// copy and is replaced.
static int capture_symlink_at(const char *src, int dest_dir_fd, const char *leaf,
                              const struct stat *st,
                              MetadataTimestampPolicy policy,
                              BackupCaptureReport *report)
{
    char link_target[PATH_MAX];
    ssize_t len = readlink(src, link_target, sizeof(link_target));
    if (len < 0 && (errno == ENOENT || errno == EINVAL))
    {
        // Removed, or no longer a symlink, since it was listed (D63).
        backup_capture_report_note_change(
            report, errno == ENOENT ? BACKUP_SOURCE_VANISHED
                                    : BACKUP_SOURCE_CHANGED, src);
        return BACKUP_CAPTURE_SKIPPED;
    }
    if (len < 0 || (size_t)len >= sizeof(link_target))
        return capture_item_fail(report, src, "read the link",
                                 len < 0 ? errno : ENAMETOOLONG);
    link_target[len] = '\0';

    if (symlinkat(link_target, dest_dir_fd, leaf) != 0)
    {
        if (errno != EEXIST)
        {
            capture_fail(report, src, "create the link in the backup", errno);
            return -1;
        }
        if (!symlink_has_target_at(dest_dir_fd, leaf, link_target))
        {
            if (capture_remove_older_copy(dest_dir_fd, leaf, src, report) != 0)
                return -1;
            if (symlinkat(link_target, dest_dir_fd, leaf) != 0)
            {
                capture_fail(report, src, "create the link in the backup",
                             errno);
                return -1;
            }
        }
    }

    PortableXattrs xattrs = {0};
    const char *operation = NULL;
    struct stat after;
    if (metadata_apply_symlink_ownership_at(dest_dir_fd, leaf, st) != 0)
        operation = "set the owner of its copy";
    else if (collect_symlink_xattrs(src, &xattrs) != 0)
        operation = "read its extended attributes";
    else if (lstat(src, &after) != 0)
        operation = "inspect it again after reading";
    else
    {
        // A symlink retargeted meanwhile keeps the target read (D63).
        if (!metadata_symlink_unchanged(st, &after))
            backup_capture_report_note_change(report, BACKUP_SOURCE_CHANGED,
                                              src);
        if (metadata_apply_xattrs_symlink_at(dest_dir_fd, leaf, xattrs.items,
                                             xattrs.count) != 0)
            operation = "set the extended attributes of its copy";
        else if (metadata_apply_symlink_times_at(dest_dir_fd, leaf, st,
                                                 policy) != 0)
            operation = "set the times of its copy";
    }
    if (operation != NULL)
        capture_fail(report, src, operation, errno);
    xattrs_free(&xattrs);
    return operation != NULL ? -1 : 0;
}

// Names a failed read of the source, as against a write of the copy.
static const char copy_read_step[] = "read the content";

// A write() that reports zero bytes for a non-zero request has made no
// progress and never will on a retry, so it is treated as the failure it is
// rather than spun on forever.
// copied_out != NULL accepts whatever length the source has when read and
// reports it; otherwise a length other than expected_size fails with errno
// 0. *failed_step names the step that failed.
static int copy_file_contents(int src_fd, int dest_fd, off_t expected_size,
                              BackupCaptureReport *report, off_t *copied_out,
                              const char **failed_step)
{
    char buffer[8192];
    off_t copied = 0;
    for (;;)
    {
        ssize_t bytes_read = read(src_fd, buffer, sizeof(buffer));
        if (bytes_read < 0 && errno == EINTR)
            continue;
        if (bytes_read < 0)
        {
            *failed_step = copy_read_step;
            return -1;
        }
        if (bytes_read == 0)
            break;

        if (write_all(dest_fd, buffer, (size_t)bytes_read) != 0)
        {
            *failed_step = "write the content";
            return -1;
        }
        copied += bytes_read;
        if (backup_capture_report_tick(report, bytes_read, dest_fd) != 0)
        {
            *failed_step = "flush the written content to disk";
            return -1;
        }
    }
    if (copied_out != NULL)
    {
        *copied_out = copied;
        return 0;
    }
    if (expected_size < 0 || copied != expected_size)
    {
        *failed_step = "the content's length differs from the recorded size";
        errno = 0;
        return -1;
    }
    return 0;
}

// A source that changed since desired was taken fails the tail, unless
// source_changed is given: a live backup source (D63) then only sets it.
// desired is the source object as snapshotted; owner_map (NULL for none)
// gives the backup user's items to the restoring user (D85). *failed_step
// names the step that failed; errno is 0 when the step says why.
static int apply_fd_metadata_tail(int destination_fd,
                                  const struct stat *desired,
                                  const OwnerMap *owner_map,
                                  int source_fd,
                                  MetadataTimestampPolicy policy,
                                  size_t *out_skipped_security,
                                  int *source_changed,
                                  const char **failed_step)
{
    struct stat target = *desired;
    metadata_owner_map_apply(owner_map, &target);
    PortableXattrs xattrs = {0};
    const char *step = NULL;
    struct stat after;
    if (metadata_apply_ownership_and_mode_fd(destination_fd, &target) != 0)
        step = "set the owner and permissions";
    else if (collect_xattrs(source_fd, &xattrs) != 0)
        step = "read the extended attributes";
    else if (fstat(source_fd, &after) != 0)
        step = "inspect it again after reading";
    else if (!metadata_source_unchanged(desired, &after) &&
             source_changed == NULL)
    {
        step = "it changed while it was read";
        errno = 0;
    }
    else
    {
        if (!metadata_source_unchanged(desired, &after))
            *source_changed = 1;
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_fd_report(
            destination_fd, xattrs.items, xattrs.count, &skipped_security);
        if (out_skipped_security != NULL)
            *out_skipped_security = skipped_security;
        if (xattr_result != 0)
            step = "set the extended attributes";
        else if (metadata_apply_times_fd(destination_fd, &target, policy) != 0)
            step = "set the times";
    }
    int saved_errno = errno;
    xattrs_free(&xattrs);
    errno = saved_errno;
    if (step == NULL)
        return 0;
    *failed_step = step;
    return -1;
}

static BackupCaptureStatus capture_hardlink_at(
    int src_fd, int dest_dir_fd, const char *leaf,
    int representative_parent_fd, const char *representative_leaf,
    const struct stat *source_snapshot, const char *src,
    BackupCaptureReport *report)
{
    if (source_snapshot == NULL || !S_ISREG(source_snapshot->st_mode) ||
        representative_parent_fd < 0 ||
        !destination_leaf_is_safe(leaf) ||
        !destination_leaf_is_safe(representative_leaf))
    {
        capture_fail(report, src, "its name cannot be used in the backup", 0);
        close(src_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    // The link shares its representative's captured content; a change to the
    // source meanwhile is only reported (D63).
    struct stat source_after;
    if (fstat(src_fd, &source_after) != 0)
    {
        capture_item_fail(report, src, "inspect it", errno);
        close(src_fd);
        return BACKUP_CAPTURE_ITEM_FAILED;
    }
    if (!metadata_source_unchanged(source_snapshot, &source_after))
        backup_capture_report_note_change(report, BACKUP_SOURCE_CHANGED, src);
    if (close(src_fd) != 0)
    {
        capture_fail(report, src, "close it", errno);
        return BACKUP_CAPTURE_ERROR;
    }

    // The map records the destination representative, not the source inode:
    // a copied source and its payload necessarily have different identities.
    // The representative's destination inode is therefore the authority for
    // both resume validation and the post-link identity check.
    struct stat representative;
    if (fstatat(representative_parent_fd, representative_leaf,
                &representative, AT_SYMLINK_NOFOLLOW) != 0)
    {
        capture_fail(report, src,
                     "inspect the copy it shares with its other names", errno);
        return BACKUP_CAPTURE_ERROR;
    }
    if (!S_ISREG(representative.st_mode))
    {
        capture_fail(report, src,
                     "the copy it shares with its other names is not a file",
                     0);
        return BACKUP_CAPTURE_ERROR;
    }

    struct stat existing;
    if (fstatat(dest_dir_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (native_hardlink_identity_matches(&existing, &representative))
            return BACKUP_CAPTURE_OK;
        if (capture_remove_older_copy(dest_dir_fd, leaf, src, report) != 0)
            return BACKUP_CAPTURE_ERROR;
    }
    else if (errno != ENOENT)
    {
        capture_fail(report, src, "inspect what the backup holds there", errno);
        return BACKUP_CAPTURE_ERROR;
    }

    if (linkat(representative_parent_fd, representative_leaf, dest_dir_fd,
               leaf, 0) != 0)
    {
        capture_fail(report, src, "link it to its other names in the backup",
                     errno);
        return BACKUP_CAPTURE_ERROR;
    }

    struct stat linked;
    if (fstatat(dest_dir_fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) != 0)
    {
        capture_fail(report, src, "inspect its link in the backup", errno);
        return BACKUP_CAPTURE_ERROR;
    }
    if (!native_hardlink_identity_matches(&linked, &representative))
    {
        capture_fail(report, src,
                     "its link in the backup does not lead to the shared copy",
                     0);
        errno = EIO;
        return BACKUP_CAPTURE_ERROR;
    }
    return BACKUP_CAPTURE_OK;
}

// Writes the content and metadata of src_fd into dest_fd and closes dest_fd.
// A file written while it is read is read again, up to
// BACKUP_CAPTURE_READ_ATTEMPTS times; one still changing after that is kept
// as last read, with that read's length, and *changed set (D63). 0; or -1
// with *step and *err, errno 0 when the step says why, and *source_failed
// set when the source could not be read.
static int capture_write_copy(int src_fd, int dest_fd,
                              struct stat *source_snapshot,
                              MetadataTimestampPolicy policy,
                              const char *src, BackupCaptureReport *report,
                              int *changed, const char **step, int *err,
                              int *source_failed)
{
    off_t copied = 0;
    *source_failed = 0;
    for (unsigned int attempt = 1;; attempt++)
    {
        backup_capture_report_reread(report, copied);
        copied = 0;
        *step = NULL;
        int source_step = 0;
        if (lseek(src_fd, 0, SEEK_SET) != 0)
        {
            *step = "go back to its start";
            source_step = 1;
        }
        else if (ftruncate(dest_fd, 0) != 0 ||
                 lseek(dest_fd, 0, SEEK_SET) != 0)
            *step = "empty its copy in the backup";
        else
        {
            (void)copy_file_contents(src_fd, dest_fd, 0, report, &copied,
                                     step);
            source_step = *step == copy_read_step;
        }
        struct stat after;
        *err = errno;
        if (*step == NULL)
        {
            backup_test_after_capture_copy(src);
            if (fstat(src_fd, &after) != 0)
            {
                *step = "inspect it again after reading";
                source_step = 1;
                *err = errno;
            }
        }
        // Unchanged metadata with a different length read is not a writer
        // but a read that failed.
        int unchanged = *step == NULL &&
            metadata_source_unchanged(source_snapshot, &after);
        if (unchanged && copied != after.st_size)
        {
            *step = "fewer or more bytes were read than its size";
            source_step = 1;
            *err = 0;
        }
        if (*step != NULL)
        {
            *source_failed = source_step;
            break;
        }
        if (unchanged)
        {
            *source_snapshot = after;
            break;
        }
        if (attempt >= BACKUP_CAPTURE_READ_ATTEMPTS)
        {
            // Kept with the times from before this read, not the newer ones
            // it may have missed, so the next update reads it again.
            source_snapshot->st_size = copied;
            *changed = 1;
            break;
        }
        *source_snapshot = after;
        backup_capture_reread_pause(attempt);
    }
    if (*step == NULL &&
        apply_fd_metadata_tail(dest_fd, source_snapshot, NULL, src_fd, policy,
                               NULL, changed, step) != 0)
        *err = errno;
    // A write deferred by the kernel (quota, ENOSPC, a network filesystem)
    // can surface only here, so a failed close means the payload is not
    // actually complete and must be reported as such.
    if (close(dest_fd) != 0 && *step == NULL)
    {
        *step = "finish writing its copy in the backup";
        *err = errno;
    }
    return *step == NULL ? 0 : -1;
}

// recopy: verify found the copy damaged, so it is written again even if it
// looks unchanged (docs/DECISIONS.md D107).
static BackupCaptureStatus capture_regular_at(
    const CloneContext *ctx, const char *src, int dest_dir_fd,
    const char *leaf, const struct stat *st, int recopy,
    BackupCaptureReport *report)
{
    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
#ifdef BACKUP_TEST_HOOKS
    backup_test_before_capture_source_open(src);
#endif
    int src_fd = capture_open_source(src, O_RDONLY | O_NOATIME | O_CLOEXEC |
                                              O_NOFOLLOW);
    if (src_fd < 0)
    {
        // Removed, or replaced by a symlink, since it was listed (D63).
        if (errno == ENOENT || errno == ELOOP)
        {
            backup_capture_report_note_change(
                report, errno == ENOENT ? BACKUP_SOURCE_VANISHED
                                        : BACKUP_SOURCE_CHANGED, src);
            return BACKUP_CAPTURE_SKIPPED;
        }
        // Refused with O_NOATIME: never read without it (D17).
        return capture_item_fail(report, src,
                                 errno == EPERM
                                     ? "open it without changing its access time"
                                     : "open it",
                                 errno);
    }

    // The open fd is what gets captured; a file rewritten since it was
    // listed is simply taken as it is now.
    (void)st;
    struct stat source_snapshot;
    if (fstat(src_fd, &source_snapshot) != 0)
    {
        capture_item_fail(report, src, "inspect it", errno);
        close(src_fd);
        return BACKUP_CAPTURE_ITEM_FAILED;
    }
    if (!S_ISREG(source_snapshot.st_mode))
    {
        close(src_fd);
        backup_capture_report_note_change(report, BACKUP_SOURCE_CHANGED, src);
        return BACKUP_CAPTURE_SKIPPED;
    }

    if (ctx->inode_map != NULL && source_snapshot.st_nlink > 1)
    {
        NativeInodeMap *map = ctx->inode_map;
        int representative_parent_fd = -1;
        char representative_leaf[NAME_MAX + 1U];
        int found = native_inode_map_find(map, source_snapshot.st_dev,
                                          source_snapshot.st_ino,
                                          &representative_parent_fd,
                                          representative_leaf,
                                          sizeof(representative_leaf));
        if (found < 0)
        {
            capture_fail(report, src, "look up its other names", errno);
            close(src_fd);
            return BACKUP_CAPTURE_ERROR;
        }
        if (found > 0)
            return capture_hardlink_at(src_fd, dest_dir_fd, leaf,
                                       representative_parent_fd,
                                       representative_leaf,
                                       &source_snapshot, src, report);
    }

    struct stat dest_st;
    int held = fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) == 0;
    if (!held && errno != ENOENT)
    {
        capture_fail(report, src, "inspect what the backup holds there", errno);
        close(src_fd);
        return BACKUP_CAPTURE_ERROR;
    }
    // A matching size and mtime is the resume signal; another kind of item
    // there is an older copy, never something to truncate. So is a copy that
    // shares its inode with other names, unless it matches a source that is
    // a hardlink too: writing it in place would write them as well.
    int resumable = held && S_ISREG(dest_st.st_mode) && !recopy &&
        dest_st.st_size == source_snapshot.st_size &&
        dest_st.st_mtim.tv_sec == source_snapshot.st_mtim.tv_sec &&
        policy.nsec_exact &&
        dest_st.st_mtim.tv_nsec == source_snapshot.st_mtim.tv_nsec;
    int shared = held && S_ISREG(dest_st.st_mode) && dest_st.st_nlink > 1 &&
        (!resumable || source_snapshot.st_nlink == 1);
    if (resumable && !shared)
    {
        int dest_fd = openat(dest_dir_fd, leaf,
                             O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        if (dest_fd < 0)
        {
            capture_fail(report, src, "open its copy in the backup", errno);
            close(src_fd);
            return BACKUP_CAPTURE_ERROR;
        }
        struct stat opened_dest;
        const char *step = NULL;
        int tail_changed = 0;
        int failed = 1;
        if (fstat(dest_fd, &opened_dest) != 0)
            capture_fail(report, src, "inspect its copy in the backup",
                         errno);
        else if (!S_ISREG(opened_dest.st_mode))
            capture_fail(report, src,
                         "the backup holds another kind of item there", 0);
        else if (apply_fd_metadata_tail(dest_fd, &source_snapshot, NULL,
                                        src_fd, policy, NULL,
                                        &tail_changed, &step) != 0)
            capture_fail(report, src, step, errno);
        else
            failed = 0;
        if (!failed && tail_changed)
            backup_capture_report_note_change(
                report, BACKUP_SOURCE_CHANGED, src);
        if (close(dest_fd) != 0)
        {
            capture_fail(report, src, "close its copy in the backup",
                         errno);
            failed = 1;
        }
        if (close(src_fd) != 0)
        {
            capture_fail(report, src, "close it", errno);
            failed = 1;
        }
        if (failed)
            return BACKUP_CAPTURE_ERROR;
        backup_capture_report_unchanged(report, source_snapshot.st_size,
                                        src);
        if (ctx->inode_map != NULL && source_snapshot.st_nlink > 1 &&
            native_inode_map_insert(ctx->inode_map,
                                    source_snapshot.st_dev,
                                    source_snapshot.st_ino,
                                    dest_dir_fd, leaf) != 0)
        {
            capture_fail(report, src, "record its other names", errno);
            return BACKUP_CAPTURE_ERROR;
        }
        return BACKUP_CAPTURE_OK;
    }

    if (report != NULL)
        snprintf(report->current_path, sizeof(report->current_path), "%s", src);
    // The copy the backup holds stays until the new one is whole: that is
    // written to staging/ and renamed over it, which moves only this name
    // off an inode it shares with others (D110). One with no copy to keep,
    // or no room to stage, is written in place.
    int staged = held && S_ISREG(dest_st.st_mode) && ctx->staging != NULL;
    int staging_fd = -1;
    const struct stat listed = source_snapshot;
    off_t counted = report != NULL ? report->bytes_copied : 0;
    const char *step = NULL;
    int err = 0;
    int source_failed = 0;
    int changed = 0;
    int result;
    for (;;)
    {
        int dest_fd;
        if (staged)
        {
            staging_fd = container_staging_open(ctx->staging->container_fd);
            dest_fd = staging_fd < 0
                ? -1
                : openat(staging_fd, CONTAINER_STAGED_NAME,
                         O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW |
                             O_CLOEXEC,
                         source_snapshot.st_mode & 07777);
        }
        else
        {
            if (held && (!S_ISREG(dest_st.st_mode) || shared) &&
                capture_remove_older_copy(dest_dir_fd, leaf, src,
                                          report) != 0)
            {
                close(src_fd);
                return BACKUP_CAPTURE_ERROR;
            }
            // O_NOFOLLOW makes a symlink planted at this address fail the
            // open with ELOOP instead of being written through; O_TRUNC can
            // therefore only ever apply to the regular file the check above
            // already accepted.
            dest_fd = openat(dest_dir_fd, leaf,
                             O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW |
                                 O_CLOEXEC,
                             source_snapshot.st_mode & 07777);
        }
        if (dest_fd < 0)
        {
            step = staged ? "stage its copy in the backup"
                          : "create its copy in the backup";
            err = errno;
            result = -1;
        }
        else
            result = capture_write_copy(src_fd, dest_fd, &source_snapshot,
                                        policy, src, report, &changed, &step,
                                        &err, &source_failed);
        if (result == 0 || !staged || source_failed || err != ENOSPC)
            break;
        if (verbose)
        {
            progress_line_end();
            printf("  No room to stage a new copy of %s; writing it over "
                   "the old one.\n", src);
        }
        if (staging_fd >= 0)
        {
            (void)unlinkat(staging_fd, CONTAINER_STAGED_NAME, 0);
            close(staging_fd);
            staging_fd = -1;
        }
        staged = 0;
        source_snapshot = listed;
        changed = 0;
        if (report != NULL)
            report->bytes_copied = counted;
    }

    if (result == 0 && staging_fd >= 0 &&
        renameat(staging_fd, CONTAINER_STAGED_NAME, dest_dir_fd, leaf) != 0)
    {
        step = "put its copy in place in the backup";
        err = errno;
        result = -1;
    }
    if (result != 0 && staging_fd >= 0)
        (void)unlinkat(staging_fd, CONTAINER_STAGED_NAME, 0);
    if (staging_fd >= 0)
        close(staging_fd);
    // A read that fails leaves the copy cut short. It is removed and the
    // file listed (D109); a staged one leaves the copy the backup holds, and
    // the other names that share it.
    int failed = 0;
    if (result != 0 && source_failed)
    {
        capture_item_fail(report, src, step, err);
        if (!staged && unlinkat(dest_dir_fd, leaf, 0) != 0)
        {
            capture_fail(report, src,
                         "remove its cut-short copy from the backup", errno);
            failed = 1;
        }
    }
    else if (result != 0)
    {
        capture_fail(report, src, step, err);
        failed = 1;
    }
    if (close(src_fd) != 0)
    {
        capture_fail(report, src, "close it", errno);
        failed = 1;
    }
    if (failed)
        return BACKUP_CAPTURE_ERROR;
    if (result != 0)
        return BACKUP_CAPTURE_ITEM_FAILED;
    if (changed)
        backup_capture_report_note_change(report, BACKUP_SOURCE_CHANGED, src);
    if (ctx->inode_map != NULL && source_snapshot.st_nlink > 1 &&
        native_inode_map_insert(ctx->inode_map, source_snapshot.st_dev,
                                source_snapshot.st_ino, dest_dir_fd, leaf) != 0)
    {
        capture_fail(report, src, "record its other names", errno);
        return BACKUP_CAPTURE_ERROR;
    }
    return BACKUP_CAPTURE_OK;
}

// The directory is created with owner-only access and given the source's real
// mode by metadata_apply_ownership_and_mode_fd() only after its whole subtree
// is written.
// Creating it with the final mode up front would make a read-only source
// directory (e.g. 0555) impossible to descend into and populate, and the
// transient 0700 is never more permissive to group or other than the mode it
// ends up with.
// The folder's copy at leaf, made if missing. O_NOFOLLOW rejects a symlink
// standing there (descending through it would write payload outside the
// container), O_DIRECTORY every other kind of item: errno is then ELOOP or
// ENOTDIR, and the caller replaces it.
static int open_folder_copy_at(int dest_dir_fd, const char *leaf,
                               const char **step)
{
    if (mkdirat(dest_dir_fd, leaf, 0700) != 0 && errno != EEXIST)
    {
        *step = "create the folder in the backup";
        return -1;
    }
    int fd = openat(dest_dir_fd, leaf,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        *step = "open the folder in the backup";
    return fd;
}

static BackupCaptureStatus capture_directory_at(
    const CloneContext *ctx, const char *src, int dest_dir_fd,
    const char *leaf, const struct stat *st, const char *root_key,
    const char *rel_path, BackupCaptureReport *report)
{
#ifdef BACKUP_TEST_HOOKS
    backup_test_before_capture_source_open(src);
#endif
    int source_fd = capture_open_source(src, O_RDONLY | O_DIRECTORY |
                                                 O_NOFOLLOW | O_NOATIME |
                                                 O_CLOEXEC);
    if (source_fd < 0)
    {
        // Removed, or replaced by something else, since it was listed (D63).
        if (errno == ENOENT || errno == ENOTDIR || errno == ELOOP)
        {
            backup_capture_report_note_change(
                report, errno == ENOENT ? BACKUP_SOURCE_VANISHED
                                        : BACKUP_SOURCE_CHANGED, src);
            return BACKUP_CAPTURE_SKIPPED;
        }
        // Refused with O_NOATIME: never read without it (D17).
        return capture_item_fail(
            report, src,
            errno == EPERM ? "open the folder without changing its access time"
                           : "open the folder",
            errno);
    }
    (void)st;
    struct stat source_snapshot;
    int inspect_errno = fstat(source_fd, &source_snapshot) != 0 ? errno
        : S_ISDIR(source_snapshot.st_mode)                       ? 0
                                                                 : ENOTDIR;
    if (inspect_errno != 0)
    {
        capture_item_fail(report, src, "inspect the folder", inspect_errno);
        close(source_fd);
        return BACKUP_CAPTURE_ITEM_FAILED;
    }

    const char *step = NULL;
    int child_fd = open_folder_copy_at(dest_dir_fd, leaf, &step);
    if (child_fd < 0 && (errno == ENOTDIR || errno == ELOOP))
    {
        step = "remove its older copy in the backup";
        if (native_remove_leaf(dest_dir_fd, leaf) == 0)
            child_fd = open_folder_copy_at(dest_dir_fd, leaf, &step);
    }
    if (child_fd < 0)
    {
        capture_fail(report, src, step, errno);
        close(source_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    // A folder that cannot be listed to its end is an item that failed
    // (D109): it gets its metadata, and the backup keeps what it held below.
    BackupCaptureStatus result = BACKUP_CAPTURE_OK;
    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        result = capture_item_fail(report, src, "list the folder", errno);
        if (scan_fd >= 0)
            close(scan_fd);
    }

    struct dirent *entry;
    while (dir != NULL)
    {
        // readdir() reports both "end of directory" and "read failed" as NULL;
        // only errno tells them apart. Without this reset a real read error
        // would look like a complete directory, and the container would be
        // finalized around a silently short subtree.
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
                result = capture_item_fail(report, src, "list the folder",
                                           errno);
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Only the source path grows as we descend; refuse rather than act on
        // a truncated one. The destination never concatenates at all.
        char child_src[PATH_MAX];
        char child_rel[PATH_MAX];
        if (path_join(child_src, sizeof(child_src), src, entry->d_name) != 0 ||
            append_relative(child_rel, sizeof(child_rel), rel_path,
                            entry->d_name) != 0)
        {
            capture_item_fail(report, src, "name an item in the folder",
                              ENAMETOOLONG);
            backup_capture_report_note_failure(report, 0);
            continue;
        }
        BackupCaptureStatus child_status = capture_entry_at(
            ctx, child_src, child_fd, entry->d_name, root_key, child_rel,
            report);
        if (child_status != BACKUP_CAPTURE_OK)
        {
            result = child_status;
            break;
        }
    }

    if (dir != NULL && closedir(dir) != 0)
    {
        capture_fail(report, src, "list the folder", errno);
        result = BACKUP_CAPTURE_ERROR;
    }
    int directory_changed = 0;
    step = NULL;
    if (result != BACKUP_CAPTURE_ERROR &&
        apply_fd_metadata_tail(child_fd, &source_snapshot, NULL, source_fd,
                               metadata_policy_from_context(ctx), NULL,
                               &directory_changed, &step) != 0)
    {
        capture_fail(report, src, step, errno);
        result = BACKUP_CAPTURE_ERROR;
    }
    if (result == BACKUP_CAPTURE_OK && directory_changed)
        backup_capture_report_note_change(report, BACKUP_SOURCE_CHANGED, src);
    if (close(source_fd) != 0)
    {
        capture_fail(report, src, "close the folder", errno);
        result = BACKUP_CAPTURE_ERROR;
    }
    if (close(child_fd) != 0)
    {
        capture_fail(report, src, "close the folder in the backup", errno);
        result = BACKUP_CAPTURE_ERROR;
    }
    return result;
}

// Recreate the node itself, never its contents: reading a FIFO blocks until a
// writer appears, which would hang the whole backup. An existing FIFO at this
// address is accepted so an interrupted backup can resume past it; anything
// else there is an older copy and is replaced.
static int capture_fifo_at(const CloneContext *ctx, const char *src,
                           int dest_dir_fd, const char *leaf,
                           const struct stat *st, BackupCaptureReport *report)
{
    if (mkfifoat(dest_dir_fd, leaf, st->st_mode & 07777) != 0)
    {
        if (errno != EEXIST)
        {
            capture_fail(report, src, "create the FIFO in the backup", errno);
            return -1;
        }
        struct stat dest_st;
        if (fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) != 0)
        {
            capture_fail(report, src, "inspect what the backup holds there",
                         errno);
            return -1;
        }
        if (!S_ISFIFO(dest_st.st_mode))
        {
            if (capture_remove_older_copy(dest_dir_fd, leaf, src, report) != 0)
                return -1;
            if (mkfifoat(dest_dir_fd, leaf, st->st_mode & 07777) != 0)
            {
                capture_fail(report, src, "create the FIFO in the backup",
                             errno);
                return -1;
            }
        }
    }

    // O_RDONLY | O_NONBLOCK is the one way to open a FIFO that returns
    // immediately with no writer on the other end. The fd is opened purely so
    // the metadata below goes through an fd like every other type here, rather
    // than through a path a swap could redirect.
    int fifo_fd = openat(dest_dir_fd, leaf,
                         O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fifo_fd < 0)
    {
        capture_fail(report, src, "open the FIFO in the backup", errno);
        return -1;
    }

    struct stat opened;
    int failed = 1;
    if (fstat(fifo_fd, &opened) != 0)
        capture_fail(report, src, "inspect the FIFO in the backup", errno);
    else if (!S_ISFIFO(opened.st_mode))
        capture_fail(report, src,
                     "the backup holds another kind of item there", 0);
    else if (metadata_apply_fd(fifo_fd, st,
                               metadata_policy_from_context(ctx)) != 0)
        capture_fail(report, src,
                     "set the owner, permissions, and times of its copy",
                     errno);
    else
        failed = 0;
    if (close(fifo_fd) != 0)
    {
        capture_fail(report, src, "close the FIFO in the backup", errno);
        failed = 1;
    }
    return failed ? -1 : 0;
}

// Lists an item capture could not read (D109). What the backup holds at its
// address stays, with everything below it: reconciliation leaves it.
static BackupCaptureStatus capture_list_failed(const CloneContext *ctx,
                                               const char *src,
                                               int dest_dir_fd,
                                               const char *leaf,
                                               const char *root_key,
                                               const char *rel_path,
                                               BackupCaptureReport *report)
{
    struct stat held;
    int kept = fstatat(dest_dir_fd, leaf, &held, AT_SYMLINK_NOFOLLOW) == 0;
    if (!kept && errno != ENOENT)
    {
        capture_fail(report, src, "inspect what the backup holds there",
                     errno);
        return BACKUP_CAPTURE_ERROR;
    }
    if (kept && ctx->visited != NULL &&
        native_visited_add(ctx->visited, root_key, rel_path, 1) < 0)
    {
        capture_fail(report, src, "record it as kept", errno);
        return BACKUP_CAPTURE_ERROR;
    }
    backup_capture_report_note_failure(report, kept);
    return BACKUP_CAPTURE_OK;
}

static BackupCaptureStatus capture_entry_at(const CloneContext *ctx,
                                            const char *src,
                                            int dest_dir_fd, const char *leaf,
                                            const char *root_key,
                                            const char *rel_path,
                                            BackupCaptureReport *report)
{
    if (ctx->selection)
    {
        int owned = selection_source_owns(ctx->selection, src);
        if (owned < 0)
            capture_fail(report, src, "it lies outside its root in the selection",
                         0);
        if (owned <= 0) return owned == 0 ? BACKUP_CAPTURE_OK : BACKUP_CAPTURE_ERROR;
    }
    struct stat st;
    if (lstat(src, &st) != 0)
    {
        if (errno != ENOENT)
        {
            capture_item_fail(report, src, "inspect it", errno);
            return capture_list_failed(ctx, src, dest_dir_fd, leaf, root_key,
                                       rel_path, report);
        }
        // Listed by readdir, gone before it could be read (D63).
        backup_capture_report_note_change(report, BACKUP_SOURCE_VANISHED, src);
        return BACKUP_CAPTURE_OK;
    }

    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
    BackupCaptureStatus status;
    int trackable = 1;
    if (S_ISLNK(st.st_mode))
        status = capture_symlink_at(src, dest_dir_fd, leaf, &st, policy,
                                    report);
    else if (S_ISREG(st.st_mode))
        status = capture_regular_at(
            ctx, src, dest_dir_fd, leaf, &st,
            recopy_list_contains(ctx->recopy, root_key, rel_path), report);
    else if (S_ISDIR(st.st_mode))
        status = capture_directory_at(ctx, src, dest_dir_fd, leaf, &st,
                                      root_key, rel_path, report);
    else if (S_ISFIFO(st.st_mode))
        status = capture_fifo_at(ctx, src, dest_dir_fd, leaf, &st, report);
    else if (S_ISSOCK(st.st_mode))
    {
        // Sockets and device nodes carry no copyable content: a socket is a
        // runtime IPC endpoint, a device node needs root to recreate. Skip
        // either with a warning rather than failing the enclosing directory.
        print_warning("  Warning: skipping socket (runtime-only): %s\n", src);
        trackable = 0;
        status = BACKUP_CAPTURE_OK;
    }
    else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
    {
        print_warning("  Warning: skipping %s device node: %s\n",
                      S_ISCHR(st.st_mode) ? "character" : "block", src);
        trackable = 0;
        status = BACKUP_CAPTURE_OK;
    }
    else
    {
        capture_fail(report, src, "it is of a kind migr cannot back up", 0);
        return BACKUP_CAPTURE_ERROR;
    }

    // Left out, so not visited: a resume then removes its stale payload.
    if (status == BACKUP_CAPTURE_SKIPPED)
        return BACKUP_CAPTURE_OK;
    if (status == BACKUP_CAPTURE_ITEM_FAILED)
        return capture_list_failed(ctx, src, dest_dir_fd, leaf, root_key,
                                   rel_path, report);

    if (status == BACKUP_CAPTURE_OK && trackable && ctx->visited != NULL &&
        native_visited_add(ctx->visited, root_key, rel_path, 0) < 0)
    {
        capture_fail(report, src, "record it as backed up", errno);
        return BACKUP_CAPTURE_ERROR;
    }
    if (status == BACKUP_CAPTURE_OK && trackable && report != NULL)
        report->items++;

    return status;
}

void backup_capture_report_init(BackupCaptureReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

void backup_capture_report_note_change(BackupCaptureReport *report,
                                       BackupSourceChangeKind kind,
                                       const char *location)
{
    if (report == NULL || kind < 0 || kind >= BACKUP_SOURCE_CHANGE_KINDS)
        return;
    static const char *const labels[BACKUP_SOURCE_CHANGE_KINDS] = {
        [BACKUP_SOURCE_CHANGED] = "Changed while read, kept as last read",
        [BACKUP_SOURCE_VANISHED] = "Removed before it could be read",
        [BACKUP_SOURCE_APPEARED] = "Created after its folder was scanned"
    };
    run_log_printf("%s: %s\n", labels[kind], location != NULL ? location : "");
    char *text = example_list_next(&report->source_changes[kind]);
    if (text != NULL)
        snprintf(text, EXAMPLE_TEXT_MAX, "%s",
                 location != NULL ? location : "");
}

void backup_capture_report_note_failure(BackupCaptureReport *report,
                                        int kept)
{
    if (report == NULL || report->failure_kind != BACKUP_CAPTURE_FAILURE_ITEM)
        return;
    int err = report->failure_errno;
    char line[EXAMPLE_TEXT_MAX];
    snprintf(line, sizeof(line), "%s: %s%s%s%s", report->failed_source_path,
             report->failed_operation != NULL ? report->failed_operation
                                              : "read it",
             err != 0 ? ": " : "", err != 0 ? strerror(err) : "",
             kept ? " (the backup keeps the copy it has)" : "");
    run_log_printf("Could not back up: %s\n", line);
    if (err != 0)
    {
        const char *name = strerrorname_np(err);
        run_log_printf("  errno %d (%s)\n", err, name != NULL ? name : "?");
    }
    char *text = example_list_next(&report->failed_items);
    if (text != NULL)
        snprintf(text, EXAMPLE_TEXT_MAX, "%s", line);
    report->failed_source_path[0] = '\0';
    report->failure_kind = BACKUP_CAPTURE_FAILURE_NONE;
    report->failure_errno = 0;
    report->failed_operation = NULL;
}

void backup_capture_reread_pause(unsigned int attempt)
{
    struct timespec pause = { 0, (long)attempt * 50L * 1000L * 1000L };
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR)
        ;
}

void backup_capture_report_reread(BackupCaptureReport *report, off_t bytes)
{
    if (report != NULL)
        report->bytes_copied -= bytes;
}

int backup_capture_report_has_changes(const BackupCaptureReport *report)
{
    if (report == NULL)
        return 0;
    for (int kind = 0; kind < BACKUP_SOURCE_CHANGE_KINDS; kind++)
        if (report->source_changes[kind].count != 0)
            return 1;
    return 0;
}

int backup_capture_report_tick(BackupCaptureReport *report,
                               off_t chunk_size, int destination_fd)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_write_faults > 0)
    {
        backup_test_write_faults--;
        errno = backup_test_write_fault;
        return -1;
    }
#endif
    if (report == NULL)
        return 0;
    report->bytes_copied += chunk_size;
    if (report->progress_cb != NULL &&
        backup_progress_should_fire(&report->progress_last_fired,
                                    report->progress_unthrottled))
        report->progress_cb(report->bytes_copied, report->bytes_unchanged,
                            report->current_path, report->progress_userdata);
    if (report->sync_interval_bytes > 0 &&
        backup_sync_due(&report->bytes_since_sync, chunk_size,
                        report->sync_interval_bytes) &&
        syncfs(destination_fd) != 0)
        return -1;
    return 0;
}

void backup_capture_report_unchanged(BackupCaptureReport *report,
                                     off_t bytes, const char *path)
{
    if (report == NULL)
        return;
    report->bytes_unchanged += bytes;
    snprintf(report->current_path, sizeof(report->current_path), "%s", path);
    if (report->progress_cb != NULL &&
        backup_progress_should_fire(&report->progress_last_fired,
                                    report->progress_unthrottled))
        report->progress_cb(report->bytes_copied, report->bytes_unchanged,
                            report->current_path, report->progress_userdata);
}

static int native_open_relative_parent(int root_fd, const char *rel_path,
                                       int *parent_out, char *leaf_out,
                                       size_t leaf_size);

BackupCaptureStatus backup_capture_at_report(
    const CloneContext *ctx, const char *source_path,
    int destination_root_fd, const char *destination_path,
    BackupCaptureReport *report)
{
    backup_capture_report_init(report);
    return backup_capture_at_report_continue(ctx, source_path,
                                             destination_root_fd,
                                             destination_path, report);
}

BackupCaptureStatus backup_capture_at_report_continue(
    const CloneContext *ctx, const char *source_path,
    int destination_root_fd, const char *destination_path,
    BackupCaptureReport *report)
{
    // Fail closed on a mis-dispatched context rather than running a native clone blindly:
    // a wrong direction or an unimplemented representation must not silently produce a
    // native tree where a sidecar was required.
    const char *label = source_path != NULL ? source_path : "";
    if (ctx == NULL || ctx->operation != CLONE_BACKUP ||
        ctx->representation != CLONE_NATIVE_TREE ||
        source_path == NULL || destination_root_fd < 0 ||
        !destination_path_is_safe(destination_path))
    {
        capture_fail(report, label, "it was given to the capture wrongly", 0);
        return BACKUP_CAPTURE_ERROR;
    }

    int parent_fd;
    char leaf[NAME_MAX + 1U];
    if (fileops_make_parents_at(destination_root_fd, destination_path) != 0 ||
        native_open_relative_parent(destination_root_fd, destination_path,
                                    &parent_fd, leaf, sizeof(leaf)) != 0)
    {
        capture_fail(report, label, "open its place in the backup", errno);
        return BACKUP_CAPTURE_ERROR;
    }
    BackupCaptureStatus status = capture_entry_at(
        ctx, source_path, parent_fd, leaf, destination_path, "", report);
    if (close(parent_fd) != 0)
    {
        capture_fail(report, label, "close its place in the backup", errno);
        if (status == BACKUP_CAPTURE_OK)
            status = BACKUP_CAPTURE_ERROR;
    }
    return status;
}

BackupCaptureStatus backup_capture_at(const CloneContext *ctx,
                                      const char *source_path,
                                      int destination_root_fd,
                                      const char *destination_leaf)
{
    return backup_capture_at_report(ctx, source_path, destination_root_fd,
                                    destination_leaf, NULL);
}

/* ========================================================================= */
/* Native stale reconciliation (docs/DECISIONS.md D23).                      */
/*                                                                          */
/* The visited set is complete only after every root has captured without an */
/* error. Reconciliation therefore scans first and deletes only after all    */
/* directory handles used by that scan have been closed. A root object       */
/* recorded by capture is preserved; an intentionally skipped special root  */
/* is unvisited and is reconciled like any other stale object.               */
/* ========================================================================= */

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} NativeStaleList;

static void native_stale_list_free(NativeStaleList *list)
{
    if (list == NULL)
        return;
    for (size_t index = 0; index < list->count; index++)
        free(list->items[index]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int native_stale_list_append(NativeStaleList *list,
                                    const char *rel_path)
{
    if (list == NULL || rel_path == NULL)
        return -1;
    if (list->count == list->capacity)
    {
        char **items = array_reserve(
            list->items, &list->capacity, list->count, 1U,
            sizeof(*items), 16U, SIZE_MAX / sizeof(*items));
        if (items == NULL)
            return -1;
        list->items = items;
    }
    char *copy = strdup(rel_path);
    if (copy == NULL)
        return -1;
    list->items[list->count++] = copy;
    return 0;
}

// Keeps the first entry reconciliation could not handle, below its root.
static void reconcile_fail(NativeReconcileReport *report, const char *rel_path,
                           const char *operation, int err)
{
    if (report == NULL || report->failed_operation != NULL)
        return;
    (void)snprintf(report->failed_relative_path,
                   sizeof(report->failed_relative_path), "%s", rel_path);
    report->failed_operation = operation;
    report->failure_errno = err;
}

static int native_reconcile_scan_node(const void *visited,
                                      const char *root_key, int parent_fd,
                                      const char *leaf, const char *rel_path,
                                      NativeStaleList *stale,
                                      NativeReconcileReport *report)
{
    int contains = native_visited_contains(visited, root_key, rel_path);
    if (contains < 0)
    {
        reconcile_fail(report, rel_path, "look it up among the items backed up",
                       0);
        return -1;
    }
    if (contains == 0)
    {
        if (native_stale_list_append(stale, rel_path) == 0)
            return 0;
        reconcile_fail(report, rel_path, "list it for removal", errno);
        return -1;
    }
    if (contains == 2)
        return 0;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
    {
        reconcile_fail(report, rel_path, "inspect it", errno);
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
        return 0;

    int child_fd = openat(parent_fd, leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_fd < 0)
    {
        reconcile_fail(report, rel_path, "open the folder", errno);
        return -1;
    }
    int scan_fd = fcntl(child_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        reconcile_fail(report, rel_path, "list the folder", errno);
        if (scan_fd >= 0)
            close(scan_fd);
        close(child_fd);
        return -1;
    }

    int failed = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                reconcile_fail(report, rel_path, "list the folder", errno);
                failed = 1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_rel[PATH_MAX];
        if (append_relative(child_rel, sizeof(child_rel), rel_path,
                            entry->d_name) != 0)
        {
            reconcile_fail(report, rel_path, "name an item in the folder",
                           ENAMETOOLONG);
            failed = 1;
            break;
        }
        if (native_reconcile_scan_node(visited, root_key, child_fd,
                                       entry->d_name, child_rel, stale,
                                       report) != 0)
        {
            failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
    {
        reconcile_fail(report, rel_path, "list the folder", errno);
        failed = 1;
    }
    struct timespec times[2] = {st.st_atim, st.st_mtim};
    if (futimens(child_fd, times) != 0)
    {
        reconcile_fail(report, rel_path, "put back the folder's times", errno);
        failed = 1;
    }
    if (close(child_fd) != 0)
    {
        reconcile_fail(report, rel_path, "close the folder", errno);
        failed = 1;
    }
    return failed ? -1 : 0;
}

static int native_remove_leaf(int parent_fd, const char *leaf);

static int native_remove_directory_tree(int parent_fd, const char *leaf)
{
    int directory_fd = openat(parent_fd, leaf,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;
    int scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        int saved_errno = errno;
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
        errno = saved_errno;
        return -1;
    }

    // errno is that of the first failure, kept through the cleanup below.
    int err = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            err = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (native_remove_leaf(directory_fd, entry->d_name) != 0)
        {
            err = errno != 0 ? errno : EIO;
            break;
        }
    }
    if (closedir(dir) != 0 && err == 0)
        err = errno;
    if (close(directory_fd) != 0 && err == 0)
        err = errno;
    if (err != 0)
    {
        errno = err;
        return -1;
    }
    if (unlinkat(parent_fd, leaf, AT_REMOVEDIR) == 0 || errno == ENOENT)
        return 0;
    return -1;
}

static int native_remove_leaf(int parent_fd, const char *leaf)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (S_ISDIR(st.st_mode))
        return native_remove_directory_tree(parent_fd, leaf);
    if (unlinkat(parent_fd, leaf, 0) == 0 || errno == ENOENT)
        return 0;
    return -1;
}

static int native_open_relative_parent(int root_fd, const char *rel_path,
                                       int *parent_out, char *leaf_out,
                                       size_t leaf_size)
{
    // A ".." component would walk out of root_fd, and the callers remove
    // what this opens.
    if (root_fd < 0 || rel_path == NULL || !destination_path_is_safe(rel_path) ||
        parent_out == NULL || leaf_out == NULL || leaf_size == 0)
    {
        errno = EINVAL;
        return -1;
    }

    size_t length = strlen(rel_path);
    if (length >= PATH_MAX)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    char copy[PATH_MAX];
    memcpy(copy, rel_path, length + 1U);

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    char *cursor = copy;
    for (;;)
    {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL)
        {
            size_t leaf_length = strlen(cursor);
            if (leaf_length >= leaf_size)
            {
                errno = ENAMETOOLONG;
                close(current);
                return -1;
            }
            memcpy(leaf_out, cursor, leaf_length + 1U);
            *parent_out = current;
            return 0;
        }

        int next = openat(current, cursor,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (close(current) != 0)
        {
            if (next >= 0)
                close(next);
            return -1;
        }
        if (next < 0)
            return -1;
        current = next;
        cursor = slash + 1;
    }
}

int fileops_remove_tree_at(int root_fd, const char *rel_path)
{
    int parent_fd;
    char leaf[NAME_MAX + 1];
    if (native_open_relative_parent(root_fd, rel_path, &parent_fd, leaf,
                                    sizeof(leaf)) != 0)
        return errno == ENOENT ? 0 : -1;
    int result = native_remove_leaf(parent_fd, leaf);
    if (close(parent_fd) != 0)
        result = -1;
    return result;
}

int fileops_make_parents_at(int root_fd, const char *rel_path)
{
    if (root_fd < 0 || rel_path == NULL ||
        strnlen(rel_path, PATH_MAX) >= PATH_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    char copy[PATH_MAX];
    strcpy(copy, rel_path);
    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    char *cursor = copy;
    for (char *slash; current >= 0 && (slash = strchr(cursor, '/')) != NULL;
         cursor = slash + 1)
    {
        *slash = '\0';
        int next = -1;
        if (mkdirat(current, cursor, 0700) == 0 || errno == EEXIST)
            next = openat(current, cursor,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int saved = errno;
        close(current);
        errno = saved;
        current = next;
    }
    return current < 0 ? -1 : close(current);
}

int fileops_make_intermediate_dir_at(int parent_fd, const char *leaf)
{
    if (mkdirat(parent_fd, leaf, 0700) != 0)
        return errno == EEXIST ? 0 : -1;
    // Made by root, a folder such as a fresh install's missing ~/.var would
    // shut its user out of everything restored below it.
    struct stat parent, made;
    if (fstat(parent_fd, &parent) != 0 ||
        fstatat(parent_fd, leaf, &made, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (made.st_uid == parent.st_uid && made.st_gid == parent.st_gid)
        return 0;
    return fchownat(parent_fd, leaf, parent.st_uid, parent.st_gid,
                    AT_SYMLINK_NOFOLLOW);
}

void native_reconcile_report_init(NativeReconcileReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

// root_key names the root in the visited set; its payload is leaf beneath
// parent_fd.
static NativeReconcileStatus native_reconcile_root_at(
    const void *visited, const char *root_key, int parent_fd,
    const char *leaf, NativeReconcileReport *report)
{
    int root_visited = native_visited_contains(visited, root_key, "");
    if (root_visited < 0)
    {
        reconcile_fail(report, "", "look it up among the items backed up", 0);
        return NATIVE_RECONCILE_ERROR;
    }

    struct stat root_st;
    if (fstatat(parent_fd, leaf, &root_st, AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (errno == ENOENT)
            return NATIVE_RECONCILE_OK;
        reconcile_fail(report, "", "inspect it", errno);
        return NATIVE_RECONCILE_ERROR;
    }
    if (root_visited == 0)
    {
        if (native_remove_leaf(parent_fd, leaf) == 0)
            return NATIVE_RECONCILE_OK;
        reconcile_fail(report, "", "remove it from the backup", errno);
        return NATIVE_RECONCILE_ERROR;
    }
    if (root_visited == 2 || !S_ISDIR(root_st.st_mode))
        return NATIVE_RECONCILE_OK;

    int root_fd = openat(parent_fd, leaf,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0)
    {
        reconcile_fail(report, "", "open the folder", errno);
        return NATIVE_RECONCILE_ERROR;
    }
    int scan_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        reconcile_fail(report, "", "list the folder", errno);
        if (scan_fd >= 0)
            close(scan_fd);
        close(root_fd);
        return NATIVE_RECONCILE_ERROR;
    }

    NativeStaleList stale = {0};
    int scan_failed = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                reconcile_fail(report, "", "list the folder", errno);
                scan_failed = 1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (native_reconcile_scan_node(visited, root_key, root_fd,
                                       entry->d_name, entry->d_name,
                                       &stale, report) != 0)
        {
            scan_failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
    {
        reconcile_fail(report, "", "list the folder", errno);
        scan_failed = 1;
    }

    NativeReconcileStatus result = NATIVE_RECONCILE_OK;
    if (scan_failed)
        result = NATIVE_RECONCILE_ERROR;
    else
    {
        for (size_t index = 0; index < stale.count; index++)
        {
            const char *item = stale.items[index];
            int parent_fd = -1;
            char leaf[NAME_MAX + 1U];
            int open_result = native_open_relative_parent(
                root_fd, item, &parent_fd, leaf, sizeof(leaf));
            int remove_result;
            if (open_result == 0)
            {
                struct stat parent_st;
                remove_result = fstat(parent_fd, &parent_st);
                if (remove_result != 0)
                    reconcile_fail(report, item, "inspect its folder", errno);
                else
                {
                    remove_result = native_remove_leaf(parent_fd, leaf);
                    if (remove_result != 0)
                        reconcile_fail(report, item,
                                       "remove it from the backup", errno);
                    struct timespec times[2] = {parent_st.st_atim, parent_st.st_mtim};
                    if (futimens(parent_fd, times) != 0)
                    {
                        reconcile_fail(report, item,
                                       "put back its folder's times", errno);
                        remove_result = -1;
                    }
                }
            }
            else
            {
                reconcile_fail(report, item, "open its folder", errno);
                remove_result = errno == ENOENT ? 0 : -1;
            }
            if (open_result != 0 || remove_result != 0)
                result = NATIVE_RECONCILE_ERROR;
            if (parent_fd >= 0 && close(parent_fd) != 0)
            {
                reconcile_fail(report, item, "close its folder", errno);
                result = NATIVE_RECONCILE_ERROR;
            }
        }
    }

    native_stale_list_free(&stale);
    struct timespec times[2] = {root_st.st_atim, root_st.st_mtim};
    if (futimens(root_fd, times) != 0)
    {
        reconcile_fail(report, "", "put back the folder's times", errno);
        result = NATIVE_RECONCILE_ERROR;
    }
    if (close(root_fd) != 0)
    {
        reconcile_fail(report, "", "close the folder", errno);
        result = NATIVE_RECONCILE_ERROR;
    }
    return result;
}

NativeReconcileStatus native_reconcile_stale_at(const void *visited,
                                                const char *root_key,
                                                int data_fd,
                                                NativeReconcileReport *report)
{
    native_reconcile_report_init(report);
    if (visited == NULL || root_key == NULL || data_fd < 0)
    {
        reconcile_fail(report, "", "it was given to reconciliation wrongly", 0);
        return NATIVE_RECONCILE_ERROR;
    }

    int parent_fd;
    char leaf[NAME_MAX + 1U];
    if (native_open_relative_parent(data_fd, root_key, &parent_fd, leaf,
                                    sizeof(leaf)) != 0)
    {
        if (errno == ENOENT)
            return NATIVE_RECONCILE_OK;
        reconcile_fail(report, "", "open its folder", errno);
        return NATIVE_RECONCILE_ERROR;
    }
    NativeReconcileStatus result = native_reconcile_root_at(
        visited, root_key, parent_fd, leaf, report);
    if (close(parent_fd) != 0)
    {
        reconcile_fail(report, "", "close its folder", errno);
        result = NATIVE_RECONCILE_ERROR;
    }
    return result;
}

// Removes the entries of payload_fd whose name is gone from source_fd, and
// does the same in every folder both hold. Only the payload is read item by
// item; the source is asked by name, so its atimes stay as they were.
static int remove_vanished_in(int source_fd, int payload_fd, size_t *removed)
{
    int scan_fd = openat(payload_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (dir == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    NativeStaleList gone = {0}, shared = {0};
    int result = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
        {
            result = errno != 0 ? -1 : 0;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        struct stat source_st, payload_st;
        NativeStaleList *list = NULL;
        if (fstatat(source_fd, entry->d_name, &source_st,
                    AT_SYMLINK_NOFOLLOW) != 0)
            list = errno == ENOENT ? &gone : NULL;
        else if (S_ISDIR(source_st.st_mode) &&
                 fstatat(payload_fd, entry->d_name, &payload_st,
                         AT_SYMLINK_NOFOLLOW) == 0 &&
                 S_ISDIR(payload_st.st_mode))
            list = &shared;
        if (list != NULL && native_stale_list_append(list, entry->d_name) != 0)
        {
            result = -1;
            break;
        }
    }
    closedir(dir);

    for (size_t i = 0; result == 0 && i < gone.count; i++)
    {
        if (fileops_remove_tree_at(payload_fd, gone.items[i]) != 0)
            result = -1;
        else
            (*removed)++;
    }
    for (size_t i = 0; result == 0 && i < shared.count; i++)
    {
        int source_child = openat(source_fd, shared.items[i],
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
        int payload_child = openat(payload_fd, shared.items[i],
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC);
        // A folder that changed or went in the meantime is left as it is.
        if (source_child >= 0 && payload_child >= 0)
            result = remove_vanished_in(source_child, payload_child, removed);
        if (source_child >= 0)
            close(source_child);
        if (payload_child >= 0)
            close(payload_child);
    }
    native_stale_list_free(&gone);
    native_stale_list_free(&shared);
    return result;
}

int native_remove_vanished_at(const char *source_path, int data_fd,
                              const char *payload_path, size_t *removed)
{
    // A root that is a file, or has no payload yet, holds nothing to remove.
    int source_fd = open(source_path,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source_fd < 0)
        return 0;
    int payload_fd = openat(data_fd, payload_path,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int result = payload_fd >= 0
        ? remove_vanished_in(source_fd, payload_fd, removed) : 0;
    if (payload_fd >= 0)
        close(payload_fd);
    close(source_fd);
    return result;
}

/* ========================================================================= */
/* FD-anchored native restore core (docs/DECISIONS.md D15 and D16).          */
/*                                                                          */
/* Separate from the capture walker above because the trust boundaries       */
/* differ: restore treats the backup payload as untrusted too, resolving     */
/* both sides component-by-component under directory fds, and refuses a      */
/* symlink at a final destination address rather than writing through it.    */
/* ========================================================================= */

// A path component can never be longer than NAME_MAX; sizing leaf buffers to
// this (rather than PATH_MAX) is what lets the walker below proceed
// component-by-component without ever concatenating a full path string.
#define RESTORE_LEAF_MAX (NAME_MAX + 1)

typedef enum {
    RESTORE_VALIDATE,
    RESTORE_APPLY
} RestorePass;

typedef enum {
    SOURCE_OPEN_ERROR = -1,
    SOURCE_OPEN_OK = 0,
    SOURCE_OPEN_SAFE_READ = -2
} SourceOpenStatus;

#ifdef FILEOPS_TEST_HOOKS
static RestoreNativeTestSourceReadMode source_read_test_mode;
static size_t source_read_test_apply_successes;
static size_t source_read_test_apply_failure_after = SIZE_MAX;
static RestoreNativeTestApplyHook restore_test_apply_hook;
static void *restore_test_apply_context;

void restore_native_test_set_apply_hook(RestoreNativeTestApplyHook hook,
                                        void *context)
{
    restore_test_apply_hook = hook;
    restore_test_apply_context = context;
}

static void restore_native_test_after_apply(const char *logical_path)
{
    if (restore_test_apply_hook != NULL)
        restore_test_apply_hook(logical_path, restore_test_apply_context);
}

void restore_native_test_set_source_read_mode(
    RestoreNativeTestSourceReadMode mode)
{
    source_read_test_mode = mode;
    source_read_test_apply_successes = 0;
    source_read_test_apply_failure_after =
        mode == RESTORE_TEST_SOURCE_READ_APPLY ? 0 : SIZE_MAX;
}

void restore_native_test_fail_source_read_after(size_t successful_opens)
{
    source_read_test_mode = RESTORE_TEST_SOURCE_READ_APPLY;
    source_read_test_apply_successes = 0;
    source_read_test_apply_failure_after = successful_opens;
}

static int source_read_test_refused(RestorePass pass)
{
    if (pass == RESTORE_VALIDATE &&
        source_read_test_mode == RESTORE_TEST_SOURCE_READ_VALIDATE)
        return 1;
    if (pass != RESTORE_APPLY ||
        source_read_test_mode != RESTORE_TEST_SOURCE_READ_APPLY)
        return 0;
    if (source_read_test_apply_successes >=
        source_read_test_apply_failure_after)
        return 1;
    source_read_test_apply_successes++;
    return 0;
}
#endif

#ifndef FILEOPS_TEST_HOOKS
static void restore_native_test_after_apply(const char *logical_path)
{
    (void)logical_path;
}
#endif

// Counts a failed item and keeps the first: where, what was being done, and
// err, 0 when operation says why on its own. Called before any cleanup that
// could change errno.
static void restore_report_failure(RestoreNativeReport *report,
                                   const char *logical_path,
                                   const char *operation, int err)
{
    if (report == NULL)
        return;
    if (report->failed_count != SIZE_MAX)
        report->failed_count++;
    if (report->failed_count != 1 || logical_path == NULL)
        return;
    (void)snprintf(report->failed_logical_path,
                   sizeof(report->failed_logical_path), "%s", logical_path);
    report->failed_operation = operation;
    report->failure_errno = err;
}

// Keeps the first of several steps that failed, for one report at the end.
static void restore_note_failure(const char **operation, int *err,
                                 const char *text, int value)
{
    if (*operation != NULL)
        return;
    *operation = text;
    *err = value;
}

static void restore_report_applied(RestoreNativeReport *report)
{
    if (report != NULL && report->applied_count != SIZE_MAX)
        report->applied_count++;
}

static void restore_report_security_skipped(RestoreNativeReport *report,
                                            size_t count)
{
    if (report == NULL || count == 0 ||
        report->skipped_security_xattr_count == SIZE_MAX)
        return;
    if (count > SIZE_MAX - report->skipped_security_xattr_count)
        report->skipped_security_xattr_count = SIZE_MAX;
    else
        report->skipped_security_xattr_count += count;
}

// Validates a relative address before any traversal is attempted: a leading
// '/', any ".." component, a bare ".", or an empty interior/trailing
// component (e.g. "a//b" or "a/") are all refused outright -- never
// normalized into some other, unintended address. Does not accept an
// overall empty string; callers special-case "" as "the root object itself"
// before ever reaching this function, since it names zero components, not
// one rejected empty component.
static int relative_path_is_safe(const char *rel)
{
    if (rel[0] == '/')
        return 0;

    size_t start = 0;
    size_t len = strlen(rel);
    for (size_t i = 0; i <= len; i++)
    {
        if (rel[i] == '/' || rel[i] == '\0')
        {
            size_t comp_len = i - start;
            if (comp_len == 0)
                return 0; // "//" or a trailing slash
            if (comp_len == 1 && rel[start] == '.')
                return 0;
            if (comp_len == 2 && rel[start] == '.' && rel[start + 1] == '.')
                return 0;
            start = i + 1;
        }
    }
    return 1;
}

static int fd_is_directory(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
}

static int copy_leaf_name(const char *rel, char *out_leaf, size_t leaf_size)
{
    const char *leaf = strrchr(rel, '/');
    leaf = leaf == NULL ? rel : leaf + 1;
    size_t len = strlen(leaf);
    if (len >= leaf_size)
        return -1;
    memcpy(out_leaf, leaf, len + 1);
    return 0;
}

// Walks every component before rel's leaf from root_fd. An OK result owns
// *out_parent_fd; MISSING means a no-create walk encountered an absent
// intermediate. Existing intermediate symlinks and wrong object types fail.
static RestoreResolveResult resolve_parent(int root_fd, const char *rel,
                                           int create_intermediates,
                                           int *out_parent_fd,
                                           char *out_leaf, size_t leaf_size)
{
    *out_parent_fd = -1;
    if (copy_leaf_name(rel, out_leaf, leaf_size) != 0)
        return RESTORE_RESOLVE_ERROR;

    if (rel[0] == '\0')
    {
        int fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0)
            return RESTORE_RESOLVE_ERROR;
        *out_parent_fd = fd;
        return RESTORE_RESOLVE_OK;
    }

    int cur_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (cur_fd < 0)
        return RESTORE_RESOLVE_ERROR;

    const char *p = rel;
    for (;;)
    {
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);

        char comp[RESTORE_LEAF_MAX];
        if (comp_len >= sizeof(comp))
        {
            close(cur_fd);
            return RESTORE_RESOLVE_ERROR;
        }
        memcpy(comp, p, comp_len);
        comp[comp_len] = '\0';

        if (slash == NULL)
        {
            *out_parent_fd = cur_fd;
            return RESTORE_RESOLVE_OK;
        }

        int next_fd = openat(cur_fd, comp,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0 && errno == ENOENT && create_intermediates)
        {
            if (fileops_make_intermediate_dir_at(cur_fd, comp) != 0)
            {
                close(cur_fd);
                return RESTORE_RESOLVE_ERROR;
            }
            next_fd = openat(cur_fd, comp,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next_fd < 0)
        {
            int saved_errno = errno;
            close(cur_fd);
            errno = saved_errno;
            if (!create_intermediates && saved_errno == ENOENT)
                return RESTORE_RESOLVE_MISSING;
            return RESTORE_RESOLVE_ERROR;
        }

        close(cur_fd);
        cur_fd = next_fd;
        p = slash + 1;
    }
}

// Returns a duplicate fd for the directory in which the destination root will
// actually be created or traversed. Existing directory roots use the root
// directory itself; an absent leaf (or an absent intermediate) uses the
// nearest existing parent. This is deliberately separate from resolve_parent:
// a missing intermediate must remain a missing destination during validation,
// not be mistaken for a shorter path under that parent.
static int destination_metadata_anchor(int root_fd, const char *rel)
{
    if (root_fd < 0 || rel == NULL ||
        (rel[0] != '\0' && !relative_path_is_safe(rel)))
        return -1;

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    if (rel[0] == '\0')
        return current;

    const char *p = rel;
    for (;;)
    {
        const char *slash = strchr(p, '/');
        size_t length = slash == NULL ? strlen(p) : (size_t)(slash - p);
        if (length == 0 || length > NAME_MAX)
        {
            close(current);
            return -1;
        }

        if (slash == NULL)
        {
            struct stat final_st;
            if (fstatat(current, p, &final_st, AT_SYMLINK_NOFOLLOW) != 0)
            {
                if (errno == ENOENT)
                    return current;
                close(current);
                return -1;
            }
            if (!S_ISDIR(final_st.st_mode))
                return current;

            int final_fd = openat(current, p,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
            if (final_fd < 0)
            {
                close(current);
                return -1;
            }
            close(current);
            return final_fd;
        }

        char component[NAME_MAX + 1];
        memcpy(component, p, length);
        component[length] = '\0';
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
        {
            if (errno == ENOENT)
                return current;
            close(current);
            return -1;
        }
        close(current);
        current = next;
        p = slash + 1;
    }
}

static int open_source_object(int source_parent_fd, const char *source_leaf,
                              struct stat *st)
{
    int fd = source_leaf[0] == '\0'
        ? fcntl(source_parent_fd, F_DUPFD_CLOEXEC, 0)
        : openat(source_parent_fd, source_leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, st) != 0)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int destination_status(int dest_parent_fd, const char *dest_leaf,
                              struct stat *st, int *exists)
{
    if (dest_parent_fd < 0)
    {
        *exists = 0;
        return 0;
    }

    if (dest_leaf[0] == '\0')
    {
        if (fstat(dest_parent_fd, st) != 0)
            return -1;
        *exists = 1;
        return 0;
    }

    if (fstatat(dest_parent_fd, dest_leaf, st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        *exists = 1;
        return 0;
    }
    if (errno == ENOENT)
    {
        *exists = 0;
        return 0;
    }
    return -1;
}

static SourceOpenStatus open_source_regular(
    RestorePass pass, int source_parent_fd, const char *source_leaf,
    const struct stat *object_st, struct stat *opened_st, int *out_fd)
{
    *out_fd = -1;
    (void)pass;
#ifdef FILEOPS_TEST_HOOKS
    if (source_read_test_refused(pass))
    {
        errno = EPERM;
        return SOURCE_OPEN_SAFE_READ;
    }
#endif
    int fd = openat(source_parent_fd, source_leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (fd < 0)
        return errno == EPERM ? SOURCE_OPEN_SAFE_READ : SOURCE_OPEN_ERROR;
    int err = fstat(fd, opened_st) != 0 ? errno : 0;
    if (err != 0 || !S_ISREG(opened_st->st_mode) ||
        !native_hardlink_identity_matches(object_st, opened_st))
    {
        close(fd);
        errno = err;
        return SOURCE_OPEN_ERROR;
    }
    *out_fd = fd;
    return SOURCE_OPEN_OK;
}

// errno is 0 when another kind of item stands at the address.
static int open_destination_regular(int dest_parent_fd, const char *dest_leaf,
                                    mode_t mode, struct stat *opened_st,
                                    int *created)
{
    *created = 0;
    for (int attempt = 0; attempt < 2; attempt++)
    {
        int fd = openat(dest_parent_fd, dest_leaf,
                        O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 && errno == ENOENT)
        {
            fd = openat(dest_parent_fd, dest_leaf,
                        O_WRONLY | O_CREAT | O_EXCL | O_NONBLOCK |
                        O_NOFOLLOW | O_CLOEXEC, mode);
            if (fd < 0 && errno == EEXIST)
                continue;
            if (fd >= 0)
                *created = 1;
        }
        if (fd < 0)
        {
            if (errno == ELOOP || errno == EISDIR)
                errno = 0;
            return -1;
        }
        int err = fstat(fd, opened_st) != 0 ? errno : 0;
        if (err == 0 && S_ISREG(opened_st->st_mode))
            return fd;
        close(fd);
        *created = 0;
        errno = err;
        return -1;
    }
    errno = EEXIST;
    return -1;
}

static SourceOpenStatus open_source_directory(
    RestorePass pass, int source_object_fd, const struct stat *object_st,
    struct stat *opened_st, int *out_fd)
{
    *out_fd = -1;
    (void)pass;
#ifdef FILEOPS_TEST_HOOKS
    if (source_read_test_refused(pass))
    {
        errno = EPERM;
        return SOURCE_OPEN_SAFE_READ;
    }
#endif
    int fd = openat(source_object_fd, ".",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (fd < 0)
        return errno == EPERM ? SOURCE_OPEN_SAFE_READ : SOURCE_OPEN_ERROR;
    int err = fstat(fd, opened_st) != 0 ? errno : 0;
    if (err != 0 || !S_ISDIR(opened_st->st_mode) ||
        !native_hardlink_identity_matches(object_st, opened_st))
    {
        close(fd);
        errno = err;
        return SOURCE_OPEN_ERROR;
    }
    *out_fd = fd;
    return SOURCE_OPEN_OK;
}

// -1 with errno 0 when another kind of item stands at the address.
static int open_destination_directory(RestorePass pass,
                                      int dest_parent_fd, const char *dest_leaf)
{
    if (dest_parent_fd < 0)
        return pass == RESTORE_VALIDATE ? -2 : -1;
    if (dest_leaf[0] == '\0')
    {
        int fd = fcntl(dest_parent_fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0)
            return -1;
        if (!fd_is_directory(fd))
        {
            close(fd);
            errno = 0;
            return -1;
        }
        return fd;
    }

    int fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
    {
        if (pass == RESTORE_VALIDATE)
            return -2;
        if (mkdirat(dest_parent_fd, dest_leaf, 0700) != 0 && errno != EEXIST)
            return -1;
        fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0 && (errno == ENOTDIR || errno == ELOOP))
        errno = 0;
    return fd;
}

// errno is 0 when another kind of item stands at the address.
static int open_destination_fifo(int dest_parent_fd, const char *dest_leaf,
                                 mode_t mode, struct stat *opened_st)
{
    int fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
    {
        if (mkfifoat(dest_parent_fd, dest_leaf, mode) != 0 && errno != EEXIST)
            return -1;
        fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0)
    {
        if (errno == ELOOP)
            errno = 0;
        return -1;
    }
    int err = fstat(fd, opened_st) != 0 ? errno : 0;
    if (err == 0 && S_ISFIFO(opened_st->st_mode))
        return fd;
    close(fd);
    errno = err;
    return -1;
}

/* Keep preflight examples useful without making their display path a new
 * traversal constraint. A deeply nested fd-anchored payload can exceed
 * PATH_MAX as a string; in that case retain its leaf as a bounded hint. */
static void metadata_child_path(const char *parent, const char *leaf,
                                char out[PATH_MAX])
{
    if (parent == NULL || parent[0] == '\0')
    {
        (void)snprintf(out, PATH_MAX, "%s", leaf);
        return;
    }

    int n = snprintf(out, PATH_MAX, "%s/%s", parent, leaf);
    if (n >= 0 && n < PATH_MAX)
        return;
    (void)snprintf(out, PATH_MAX, ".../%s", leaf);
}

// A linked sibling receives no independent payload or metadata write: the
// representative inode already carries the source object's complete state.
// Existing independent content at the sibling address is a collision, not a
// reason to unlink or replace it.
static RestoreNativeStatus restore_linked_regular_at(
    int source_fd, int destination_parent_fd, const char *destination_leaf,
    int representative_parent_fd, const char *representative_leaf,
    const struct stat *desired_st, const char *logical_path,
    RestoreNativeReport *restore_report)
{
    const char *operation = NULL;
    int err = 0;
    struct stat source_after;
    if (fstat(source_fd, &source_after) != 0)
        restore_note_failure(&operation, &err,
                             "inspect its copy in the backup", errno);
    else if (!metadata_source_unchanged(desired_st, &source_after))
        restore_note_failure(&operation, &err,
                             "its copy in the backup changed while it was read",
                             0);
    if (close(source_fd) != 0)
        restore_note_failure(&operation, &err,
                             "close its copy in the backup", errno);

    struct stat representative;
    if (operation == NULL)
    {
        if (fstatat(representative_parent_fd, representative_leaf,
                    &representative, AT_SYMLINK_NOFOLLOW) != 0)
            restore_note_failure(&operation, &err,
                                 "inspect the file it shares content with",
                                 errno);
        else if (!S_ISREG(representative.st_mode))
            restore_note_failure(&operation, &err,
                                 "the item it shares content with is not a "
                                 "file", 0);
    }

    if (operation == NULL)
    {
        struct stat existing;
        if (fstatat(destination_parent_fd, destination_leaf, &existing,
                    AT_SYMLINK_NOFOLLOW) == 0)
        {
            if (!native_hardlink_identity_matches(&existing, &representative))
                restore_note_failure(&operation, &err,
                                     "another item is already there", 0);
        }
        else if (errno != ENOENT)
            restore_note_failure(&operation, &err,
                                 "inspect what is already there", errno);
        else if (linkat(representative_parent_fd, representative_leaf,
                        destination_parent_fd, destination_leaf, 0) != 0)
            restore_note_failure(&operation, &err,
                                 "link it to its other names", errno);
        else
        {
            struct stat linked;
            if (fstatat(destination_parent_fd, destination_leaf, &linked,
                        AT_SYMLINK_NOFOLLOW) != 0)
                restore_note_failure(&operation, &err, "inspect its link",
                                     errno);
            else if (!native_hardlink_identity_matches(&linked,
                                                       &representative))
                restore_note_failure(&operation, &err,
                                     "its link does not lead to the shared "
                                     "file", 0);
        }
    }

    if (operation != NULL)
    {
        restore_report_failure(restore_report, logical_path, operation, err);
        return RESTORE_NATIVE_ERROR;
    }
    restore_report_applied(restore_report);
    return RESTORE_NATIVE_OK;
}

// restore_entry_directory() recurses back into the full dispatcher for
// each child, so it needs restore_entry_at() declared before its own
// definition, ahead of restore_entry_at()'s own definition further down.
// restore_entry_at()/restore_entry_directory() mutually recurse once per
// payload directory level, with no other bound (the payload is untrusted,
// per this file's own header comment). depth is the nesting level of the
// entry currently being restored (0 at each restore root); descending past
// RESTORE_MAX_DEPTH fails that one entry closed rather than growing the
// stack without limit -- comfortably above any real directory tree, and
// comfortably below where a default 8MB thread stack would be exhausted by
// several thousand levels of recursion, each frame carrying a PATH_MAX
// buffer plus multiple struct stat locals.
#define RESTORE_MAX_DEPTH 512

static int path_at_or_below(const char *path, const char *top)
{
    size_t length = strlen(top);
    return strncmp(path, top, length) == 0 &&
           (path[length] == '\0' || path[length] == '/');
}

// Whether path is, or lies below, one the apply pass leaves out; the
// inventory checks such an item but does not count it.
static int restore_path_within_skipped(const CloneContext *ctx,
                                       const char *path)
{
    for (size_t index = 0; index < ctx->skipped_count; index++)
        if (path_at_or_below(path, ctx->skipped_paths[index]))
            return 1;
    for (size_t index = 0; index < ctx->left_out_count; index++)
        if (path_at_or_below(path, ctx->left_out_paths[index]))
            return 1;
    return 0;
}

// A subtree the caller restores last (D69), or leaves out (D94), is left
// out of the apply pass; the validate pass still covers it.
static int restore_path_is_skipped(const CloneContext *ctx, const char *path)
{
    for (size_t index = 0; index < ctx->skipped_count; index++)
        if (strcmp(ctx->skipped_paths[index], path) == 0)
            return 1;
    for (size_t index = 0; index < ctx->left_out_count; index++)
        if (strcmp(ctx->left_out_paths[index], path) == 0)
            return 1;
    return 0;
}

static RestoreNativeStatus restore_entry_at(
    const CloneContext *ctx, RestorePass pass, int source_parent_fd,
    const char *source_leaf, int dest_parent_fd, const char *dest_leaf,
    const char *logical_path, MetadataSnapshots *snapshots,
    MetadataProfiles *profiles, NativeRestoreEstimate *estimate,
    MetadataXattrRequirements *xattr_requirements,
    int metadata_anchor_fd,
    int skip_symlink_target_read,
    RestoreNativeReport *restore_report,
    BackupCaptureReport *capture_report, int depth);

static RestoreNativeStatus restore_entry_symlink(
    const CloneContext *ctx, RestorePass pass, int source_parent_fd,
    const char *source_leaf, int dest_parent_fd, const char *dest_leaf,
    const char *logical_path, MetadataProfiles *profiles,
    NativeRestoreEstimate *estimate,
    MetadataXattrRequirements *xattr_requirements,
    int skip_symlink_target_read, RestoreNativeReport *restore_report,
    int source_is_root, int dest_is_root, int dest_exists,
    const struct stat *dest_st, int source_object_fd, struct stat desired_st)
{
        // The backup's symlink takes the place of a file or symlink the new
        // system has there (D96); a folder or anything else stays and fails
        // it.
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISLNK(dest_st->st_mode) &&
             !S_ISREG(dest_st->st_mode)))
        {
            restore_report_failure(restore_report, logical_path,
                                   source_is_root || dest_is_root
                                       ? "a link cannot be restored as a root"
                                       : "a folder or another kind of item is "
                                         "already there",
                                   0);
            close(source_object_fd);
            return -1;
        }

        if (pass == RESTORE_VALIDATE &&
            (profiles != NULL || xattr_requirements != NULL))
        {
            char source_xattr_path[PATH_MAX];
            unsigned int namespaces = 0;
            if (metadata_symlink_xattr_path(source_parent_fd, source_leaf,
                                            source_xattr_path,
                                            sizeof(source_xattr_path)) != 0 ||
                metadata_xattr_namespaces_path(source_xattr_path,
                                               &namespaces) != 0)
            {
                restore_report_failure(
                    restore_report, logical_path,
                    "read the extended attributes of its copy in the backup",
                    errno);
                close(source_object_fd);
                return -1;
            }
            if (xattr_requirements != NULL)
                xattr_requirements->symlink_namespaces |= namespaces;
        }

        if (pass == RESTORE_VALIDATE && skip_symlink_target_read)
        {
            native_restore_estimate_add_bytes(estimate, desired_st.st_size);
            close(source_object_fd);
            return RESTORE_NATIVE_OK;
        }

        char target[PATH_MAX];
        ssize_t len = readlinkat(source_parent_fd, source_leaf,
                                 target, sizeof(target) - 1);
        if (len < 0 || (size_t)len == sizeof(target) - 1)
        {
            restore_report_failure(restore_report, logical_path,
                                   "read its copy in the backup",
                                   len < 0 ? errno : ENAMETOOLONG);
            close(source_object_fd);
            return -1;
        }
        struct stat after;
        if (fstatat(source_parent_fd, source_leaf, &after,
                    AT_SYMLINK_NOFOLLOW) != 0)
        {
            restore_report_failure(restore_report, logical_path,
                                   "inspect its copy in the backup again",
                                   errno);
            close(source_object_fd);
            return -1;
        }
        if (!metadata_symlink_unchanged(&desired_st, &after))
        {
            restore_report_failure(
                restore_report, logical_path,
                "its copy in the backup changed while it was read", 0);
            close(source_object_fd);
            return -1;
        }
        close(source_object_fd);
        if (pass == RESTORE_VALIDATE)
        {
            native_restore_estimate_add_bytes(estimate, desired_st.st_size);
            return RESTORE_NATIVE_OK;
        }

        target[len] = '\0';
        char source_xattr_path[PATH_MAX];
        PortableXattrs xattrs = {0};
        int failed = metadata_symlink_xattr_path(source_parent_fd,
                                                 source_leaf,
                                                 source_xattr_path,
                                                 sizeof(source_xattr_path));
        if (!failed &&
            collect_symlink_xattrs(source_xattr_path, &xattrs) != 0)
            failed = 1;
        if (failed)
        {
            restore_report_failure(
                restore_report, logical_path,
                "read the extended attributes of its copy in the backup",
                errno);
            xattrs_free(&xattrs);
            return RESTORE_NATIVE_ERROR;
        }
        const char *operation = NULL;
        if (dest_exists && unlinkat(dest_parent_fd, dest_leaf, 0) != 0 &&
            errno != ENOENT)
            operation = "remove what is already there";
        else if (symlinkat(target, dest_parent_fd, dest_leaf) != 0)
            operation = "create the link";
        if (operation != NULL)
        {
            restore_report_failure(restore_report, logical_path, operation,
                                   errno);
            xattrs_free(&xattrs);
            return -1;
        }
        struct stat target_st = desired_st;
        metadata_owner_map_apply(&ctx->owner_map, &target_st);
        if (metadata_apply_symlink_ownership_at(dest_parent_fd, dest_leaf,
                                                &target_st) != 0)
            operation = "set the owner of the link";
        else
        {
            size_t skipped_security = 0;
            int xattr_result = metadata_apply_xattrs_symlink_at_report(
                dest_parent_fd, dest_leaf, xattrs.items, xattrs.count,
                &skipped_security);
            restore_report_security_skipped(restore_report, skipped_security);
            if (xattr_result != 0)
                operation = "set the extended attributes of the link";
            else if (metadata_apply_symlink_times_at(
                         dest_parent_fd, dest_leaf, &target_st,
                         metadata_policy_from_context(ctx)) != 0)
                operation = "set the times of the link";
        }
        if (operation == NULL)
            restore_report_applied(restore_report);
        else
            restore_report_failure(restore_report, logical_path, operation,
                                   errno);
        xattrs_free(&xattrs);
        return operation != NULL ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
}

static RestoreNativeStatus restore_entry_regular(
    const CloneContext *ctx, RestorePass pass, int source_parent_fd,
    const char *source_leaf, int dest_parent_fd, const char *dest_leaf,
    const char *logical_path, MetadataProfiles *profiles,
    MetadataXattrRequirements *xattr_requirements,
    NativeRestoreEstimate *estimate, RestoreNativeReport *restore_report,
    BackupCaptureReport *capture_report,
    int source_is_root, int dest_is_root, int dest_exists,
    struct stat dest_st, struct stat source_st, struct stat desired_st,
    int source_object_fd)
{
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISREG(dest_st.st_mode)))
        {
            restore_report_failure(restore_report, logical_path,
                                   source_is_root || dest_is_root
                                       ? "a file cannot be restored as a root"
                                       : "a folder or another kind of item is "
                                         "already there",
                                   0);
            close(source_object_fd);
            return -1;
        }

        struct stat opened_source_st;
        int src_fd;
        SourceOpenStatus source_status = open_source_regular(
            pass, source_parent_fd, source_leaf, &source_st, &opened_source_st,
            &src_fd);
        int open_errno = errno;
        close(source_object_fd);
        if (source_status == SOURCE_OPEN_SAFE_READ)
        {
            restore_report_failure(restore_report, logical_path,
                                   "open its copy in the backup without "
                                   "changing its access time", open_errno);
            return RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (source_status != SOURCE_OPEN_OK)
        {
            restore_report_failure(restore_report, logical_path,
                                   open_errno != 0
                                       ? "open its copy in the backup"
                                       : "its copy in the backup changed "
                                         "while it was opened",
                                   open_errno);
            return RESTORE_NATIVE_ERROR;
        }
        if (!metadata_source_unchanged(&desired_st, &opened_source_st))
        {
            restore_report_failure(restore_report, logical_path,
                                   "its copy in the backup changed since it "
                                   "was checked", 0);
            close(src_fd);
            return RESTORE_NATIVE_ERROR;
        }
        if (pass == RESTORE_VALIDATE)
        {
            if (profiles != NULL || xattr_requirements != NULL)
            {
                unsigned int namespaces = 0;
                if (metadata_xattr_namespaces_fd(src_fd, &namespaces) != 0)
                {
                    restore_report_failure(
                        restore_report, logical_path,
                        "read the extended attributes of its copy in the "
                        "backup", errno);
                    close(src_fd);
                    return RESTORE_NATIVE_ERROR;
                }
                if (xattr_requirements != NULL)
                    xattr_requirements->regular_namespaces |= namespaces;
            }
            native_restore_estimate_regular(estimate, &opened_source_st);
            if (close(src_fd) == 0)
                return RESTORE_NATIVE_OK;
            restore_report_failure(restore_report, logical_path,
                                   "close its copy in the backup", errno);
            return RESTORE_NATIVE_ERROR;
        }

        if (ctx->inode_map != NULL && opened_source_st.st_nlink > 1)
        {
            int representative_parent_fd = -1;
            char representative_leaf[NAME_MAX + 1U];
            int found = native_inode_map_find(
                ctx->inode_map, opened_source_st.st_dev,
                opened_source_st.st_ino, &representative_parent_fd,
                representative_leaf, sizeof(representative_leaf));
            if (found < 0)
            {
                restore_report_failure(restore_report, logical_path,
                                       "look up its other names", errno);
                close(src_fd);
                return RESTORE_NATIVE_ERROR;
            }
            if (found > 0)
                return restore_linked_regular_at(
                    src_fd, dest_parent_fd, dest_leaf,
                    representative_parent_fd, representative_leaf,
                    &desired_st, logical_path, restore_report);
        }

        struct stat opened_dest_st;
        int dest_created;
        int dst_fd = open_destination_regular(dest_parent_fd, dest_leaf,
                                               desired_st.st_mode & 07777,
                                               &opened_dest_st, &dest_created);
        if (dst_fd < 0)
        {
            restore_report_failure(restore_report, logical_path,
                                   errno != 0 ? "open it for writing"
                                              : "a folder or another kind of "
                                                "item is already there",
                                   errno);
            close(src_fd);
            return -1;
        }
        MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
        int content_skip = !dest_created &&
            opened_dest_st.st_size == desired_st.st_size &&
            opened_dest_st.st_mtim.tv_sec == desired_st.st_mtim.tv_sec &&
            policy.nsec_exact &&
            opened_dest_st.st_mtim.tv_nsec == desired_st.st_mtim.tv_nsec;
        const char *operation = NULL;
        int err = 0;
        const char *step = NULL;
        if (!content_skip)
        {
            if (ftruncate(dst_fd, 0) != 0)
            {
                restore_report_failure(restore_report, logical_path,
                                       "empty it before writing", errno);
                close(src_fd);
                close(dst_fd);
                return -1;
            }
            if (capture_report != NULL)
                snprintf(capture_report->current_path,
                         sizeof(capture_report->current_path), "%s",
                         logical_path);
            if (copy_file_contents(src_fd, dst_fd, desired_st.st_size,
                                   capture_report, NULL, &step) != 0)
                restore_note_failure(&operation, &err, step, errno);
        }

        // collect_xattrs() reads the payload's *current* xattrs -- unlike
        // desired_st (a snapshot from an earlier pass), there is no
        // pre-recorded xattr set to fall back on, so this read must fall
        // inside the same before/after window the content copy above is
        // already verified against, not after it.
        size_t skipped_security = 0;
        if (operation == NULL &&
            apply_fd_metadata_tail(dst_fd, &desired_st, &ctx->owner_map,
                                   src_fd, policy, &skipped_security,
                                   NULL, &step) != 0)
            restore_note_failure(&operation, &err, step, errno);
        restore_report_security_skipped(restore_report, skipped_security);

        if (close(src_fd) != 0)
            restore_note_failure(&operation, &err,
                                 "close its copy in the backup", errno);
        if (close(dst_fd) != 0)
            restore_note_failure(&operation, &err, "finish writing it", errno);
        if (operation == NULL && ctx->inode_map != NULL &&
            opened_source_st.st_nlink > 1 &&
            native_inode_map_insert(ctx->inode_map, opened_source_st.st_dev,
                                    opened_source_st.st_ino,
                                    dest_parent_fd, dest_leaf) != 0)
            restore_note_failure(&operation, &err, "record its other names",
                                 errno);
        if (operation == NULL && pass == RESTORE_APPLY)
        {
            restore_report_applied(restore_report);
            restore_native_test_after_apply(logical_path);
        }
        else if (operation != NULL && pass == RESTORE_APPLY)
            restore_report_failure(restore_report, logical_path, operation,
                                   err);
        return operation != NULL ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
}

static RestoreNativeStatus restore_entry_directory(
    const CloneContext *ctx, RestorePass pass, int dest_parent_fd,
    const char *dest_leaf, const char *logical_path,
    MetadataSnapshots *snapshots, MetadataProfiles *profiles,
    NativeRestoreEstimate *estimate,
    MetadataXattrRequirements *xattr_requirements, int metadata_anchor_fd,
    int skip_symlink_target_read, RestoreNativeReport *restore_report,
    BackupCaptureReport *capture_report, int dest_exists,
    struct stat dest_st, struct stat source_st, struct stat desired_st,
    int source_object_fd, int depth)
{
        if (dest_exists && !S_ISDIR(dest_st.st_mode))
        {
            restore_report_failure(restore_report, logical_path,
                                   "a file or another kind of item is "
                                   "already there", 0);
            close(source_object_fd);
            return -1;
        }

        struct stat opened_source_st;
        int source_dir_fd;
        SourceOpenStatus source_status = open_source_directory(
            pass, source_object_fd, &source_st, &opened_source_st,
            &source_dir_fd);
        int open_errno = errno;
        close(source_object_fd);
        if (source_status == SOURCE_OPEN_SAFE_READ)
        {
            restore_report_failure(restore_report, logical_path,
                                   "open its copy in the backup without "
                                   "changing its access time", open_errno);
            return RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (source_status != SOURCE_OPEN_OK)
        {
            restore_report_failure(restore_report, logical_path,
                                   open_errno != 0
                                       ? "open its copy in the backup"
                                       : "its copy in the backup changed "
                                         "while it was opened",
                                   open_errno);
            return RESTORE_NATIVE_ERROR;
        }
        if (!metadata_source_unchanged(&desired_st, &opened_source_st))
        {
            restore_report_failure(restore_report, logical_path,
                                   "its copy in the backup changed since it "
                                   "was checked", 0);
            close(source_dir_fd);
            return RESTORE_NATIVE_ERROR;
        }
        native_restore_estimate_add_bytes(estimate, opened_source_st.st_size);

        if (pass == RESTORE_VALIDATE &&
            (profiles != NULL || xattr_requirements != NULL))
        {
            unsigned int namespaces = 0;
            if (metadata_xattr_namespaces_fd(source_dir_fd, &namespaces) != 0)
            {
                restore_report_failure(
                    restore_report, logical_path,
                    "read the extended attributes of its copy in the backup",
                    errno);
                close(source_dir_fd);
                return RESTORE_NATIVE_ERROR;
            }
            if (xattr_requirements != NULL)
                xattr_requirements->directory_namespaces |= namespaces;
        }

        int dest_dir_fd = open_destination_directory(pass, dest_parent_fd,
                                                     dest_leaf);
        if (dest_dir_fd == -1)
        {
            restore_report_failure(restore_report, logical_path,
                                   errno != 0 ? "create or open the folder"
                                              : "a file or another kind of "
                                                "item is already there",
                                   errno);
            close(source_dir_fd);
            return -1;
        }
        if (dest_dir_fd == -2)
            dest_dir_fd = -1;

        int scan_fd = fcntl(source_dir_fd, F_DUPFD_CLOEXEC, 0);
        DIR *dirp = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (dirp == NULL)
        {
            restore_report_failure(restore_report, logical_path,
                                   "list its copy in the backup", errno);
            if (scan_fd >= 0)
                close(scan_fd);
            close(source_dir_fd);
            if (dest_dir_fd >= 0)
                close(dest_dir_fd);
            return -1;
        }

        const char *operation = NULL;
        int err = 0;
        int failed = 0;
        RestoreNativeStatus subtree_status = RESTORE_NATIVE_OK;
        for (;;)
        {
            errno = 0;
            struct dirent *entry = readdir(dirp);
            if (entry == NULL)
            {
                if (errno != 0)
                {
                    restore_note_failure(&operation, &err,
                                         "list its copy in the backup", errno);
                    failed = 1;
                }
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            char child_logical_path[PATH_MAX];
            metadata_child_path(logical_path, entry->d_name,
                                child_logical_path);
            if (pass == RESTORE_APPLY &&
                restore_path_is_skipped(ctx, child_logical_path))
                continue;
            RestoreNativeStatus child_status = restore_entry_at(
                ctx, pass, source_dir_fd, entry->d_name, dest_dir_fd,
                entry->d_name, child_logical_path, snapshots, profiles,
                estimate, xattr_requirements, metadata_anchor_fd,
                skip_symlink_target_read, restore_report, capture_report,
                depth + 1);
            if (child_status != RESTORE_NATIVE_OK)
            {
                failed = 1;
                subtree_status = child_status;
                break;
            }
        }
        if (closedir(dirp) != 0)
        {
            restore_note_failure(&operation, &err,
                                 "list its copy in the backup", errno);
            failed = 1;
        }

        if (!failed && pass == RESTORE_APPLY)
        {
            // collect_xattrs() reads the payload's *current* xattrs -- unlike
            // desired_st (a snapshot from an earlier pass), there is no
            // pre-recorded xattr set to fall back on, so this read must fall
            // inside the same before/after window the subtree walk above is
            // already verified against, not after it.
            size_t skipped_security = 0;
            const char *step = NULL;
            if (apply_fd_metadata_tail(
                    dest_dir_fd, &desired_st, &ctx->owner_map, source_dir_fd,
                    metadata_policy_from_context(ctx), &skipped_security, NULL,
                    &step) != 0)
            {
                restore_note_failure(&operation, &err, step, errno);
                failed = 1;
            }
            restore_report_security_skipped(restore_report, skipped_security);
        }

        close(source_dir_fd);
        if (dest_dir_fd >= 0)
            close(dest_dir_fd);
        if (!failed && pass == RESTORE_APPLY)
            restore_report_applied(restore_report);
        else if (failed && pass == RESTORE_APPLY &&
                 subtree_status == RESTORE_NATIVE_OK)
            restore_report_failure(restore_report, logical_path, operation,
                                   err);
        if (failed && subtree_status == RESTORE_NATIVE_OK)
            subtree_status = RESTORE_NATIVE_ERROR;
        return failed ? subtree_status : RESTORE_NATIVE_OK;
}

static RestoreNativeStatus restore_entry_fifo(
    const CloneContext *ctx, RestorePass pass, int dest_parent_fd,
    const char *dest_leaf, const char *logical_path,
    RestoreNativeReport *restore_report, int source_is_root,
    int dest_is_root, int dest_exists, struct stat dest_st,
    int source_object_fd, struct stat desired_st)
{
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISFIFO(dest_st.st_mode)))
        {
            restore_report_failure(restore_report, logical_path,
                                   source_is_root || dest_is_root
                                       ? "a FIFO cannot be restored as a root"
                                       : "another kind of item is already "
                                         "there",
                                   0);
            close(source_object_fd);
            return -1;
        }
        close(source_object_fd);

        if (pass == RESTORE_VALIDATE)
            return RESTORE_NATIVE_OK;

        struct stat opened_dest_st;
        int dest_fd = open_destination_fifo(dest_parent_fd, dest_leaf,
                                            desired_st.st_mode & 07777,
                                            &opened_dest_st);
        if (dest_fd < 0)
        {
            restore_report_failure(restore_report, logical_path,
                                   errno != 0 ? "create or open the FIFO"
                                              : "another kind of item is "
                                                "already there",
                                   errno);
            return -1;
        }
        struct stat target_st = desired_st;
        metadata_owner_map_apply(&ctx->owner_map, &target_st);
        const char *operation = NULL;
        int err = 0;
        if (metadata_apply_fd(dest_fd, &target_st,
                              metadata_policy_from_context(ctx)) != 0)
            restore_note_failure(&operation, &err,
                                 "set its owner, permissions, and times",
                                 errno);
        if (close(dest_fd) != 0)
            restore_note_failure(&operation, &err, "close the FIFO", errno);
        if (operation == NULL)
            restore_report_applied(restore_report);
        else
            restore_report_failure(restore_report, logical_path, operation,
                                   err);
        return operation != NULL ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
}

static RestoreNativeStatus restore_entry_socket(
    RestorePass pass, const char *source_leaf, int source_object_fd)
{
        close(source_object_fd);
        if (pass == RESTORE_APPLY)
            print_warning("  Warning: skipping socket (runtime-only)%s%s\n",
                          source_leaf[0] ? ": " : "", source_leaf);
        return RESTORE_NATIVE_OK;
}

static RestoreNativeStatus restore_entry_device(
    RestorePass pass, const char *source_leaf, int source_object_fd,
    struct stat source_st)
{
        close(source_object_fd);
        if (pass == RESTORE_APPLY)
            print_warning("  Warning: skipping %s device node%s%s\n",
                          S_ISCHR(source_st.st_mode) ? "character" : "block",
                          source_leaf[0] ? ": " : "", source_leaf);
        return RESTORE_NATIVE_OK;
}

// The same recursive dispatcher serves mutation-free validation and the
// actual restore. A negative destination parent means the corresponding
// destination subtree does not exist during validation.
// The explicit symlink-read flag keeps metadata inventory from perturbing
// source atime; other validation and apply walks retain target checks (D17).
static RestoreNativeStatus restore_entry_at(
    const CloneContext *ctx, RestorePass pass, int source_parent_fd,
    const char *source_leaf, int dest_parent_fd, const char *dest_leaf,
    const char *logical_path, MetadataSnapshots *snapshots,
    MetadataProfiles *profiles, NativeRestoreEstimate *estimate,
    MetadataXattrRequirements *xattr_requirements,
    int metadata_anchor_fd,
    int skip_symlink_target_read,
    RestoreNativeReport *restore_report,
    BackupCaptureReport *capture_report, int depth)
{
    if (depth > RESTORE_MAX_DEPTH)
    {
        restore_report_failure(restore_report, logical_path,
                               "it is nested deeper than restore follows", 0);
        return -1;
    }

    int source_is_root = source_leaf[0] == '\0';
    int dest_is_root = dest_leaf[0] == '\0';

    struct stat source_st;
    int source_object_fd = open_source_object(source_parent_fd, source_leaf,
                                               &source_st);
    if (source_object_fd < 0)
    {
        restore_report_failure(restore_report, logical_path,
                               "inspect its copy in the backup", errno);
        return -1;
    }

    struct stat dest_st;
    int dest_exists;
    if (destination_status(dest_parent_fd, dest_leaf, &dest_st,
                           &dest_exists) != 0)
    {
        restore_report_failure(restore_report, logical_path,
                               "inspect what is already there", errno);
        close(source_object_fd);
        return -1;
    }
    // Restore never writes through a symlink; only a symlink from the backup
    // may replace one (D96).
    if (dest_exists && S_ISLNK(dest_st.st_mode) && !S_ISLNK(source_st.st_mode))
    {
        print_destination_symlink_refusal(dest_parent_fd, dest_leaf);
        restore_report_failure(restore_report, logical_path,
                               "a symbolic link is already there", 0);
        close(source_object_fd);
        return -1;
    }

    struct stat desired_st = source_st;
    if (pass == RESTORE_VALIDATE)
    {
        if (!restore_path_within_skipped(ctx, logical_path))
            native_restore_estimate_item(estimate);
        if (metadata_snapshot_record(snapshots, &source_st) != 0)
        {
            restore_report_failure(restore_report, logical_path,
                                   "record its metadata", errno);
            close(source_object_fd);
            return -1;
        }
        // One profile anchor governs the whole restore root.  It is the
        // actual destination root when that directory exists, otherwise the
        // nearest existing parent chosen before the walk began.  Descending
        // into payload directories must not turn each child directory into a
        // new probe domain: ACLs and access policy may differ between roots,
        // but the plan deliberately bounds profiles by restore roots.
        // Profiled as restored: the backup user's items go to the
        // restoring user (D85).
        struct stat profile_st = source_st;
        metadata_owner_map_apply(&ctx->owner_map, &profile_st);
        int profile_failed = profiles != NULL && metadata_anchor_fd < 0;
        if (!profile_failed && profiles != NULL &&
            !S_ISSOCK(source_st.st_mode) &&
            !S_ISCHR(source_st.st_mode) &&
            !S_ISBLK(source_st.st_mode) &&
            metadata_profiles_add(profiles, metadata_anchor_fd, &profile_st,
                                  dest_exists ? &dest_st : NULL,
                                  logical_path) != 0)
            profile_failed = 1;
        if (profile_failed)
        {
            restore_report_failure(restore_report, logical_path,
                                   "check what the destination can hold for "
                                   "its metadata",
                                   metadata_anchor_fd < 0 ? 0 : errno);
            close(source_object_fd);
            return -1;
        }
    }
    else
    {
        const MetadataSnapshot *snapshot = metadata_snapshot_find(snapshots,
                                                                   &source_st);
        if (snapshot == NULL || !metadata_snapshot_matches(snapshot, &source_st) ||
            metadata_snapshot_to_stat(snapshot, &desired_st) != 0)
        {
            restore_report_failure(restore_report, logical_path,
                                   "its copy in the backup changed since it "
                                   "was checked", 0);
            close(source_object_fd);
            return -1;
        }
    }

    if (S_ISSOCK(source_st.st_mode))
        return restore_entry_socket(pass, source_leaf, source_object_fd);

    if (S_ISCHR(source_st.st_mode) || S_ISBLK(source_st.st_mode))
        return restore_entry_device(pass, source_leaf, source_object_fd,
                                    source_st);

    RestoreNativeStatus status;
    if (S_ISLNK(source_st.st_mode))
        status = restore_entry_symlink(ctx, pass, source_parent_fd,
                                       source_leaf, dest_parent_fd, dest_leaf,
                                       logical_path, profiles, estimate,
                                       xattr_requirements,
                                       skip_symlink_target_read,
                                       restore_report, source_is_root,
                                       dest_is_root, dest_exists, &dest_st,
                                       source_object_fd, desired_st);
    else if (S_ISREG(source_st.st_mode))
        status = restore_entry_regular(ctx, pass, source_parent_fd,
                                       source_leaf, dest_parent_fd, dest_leaf,
                                       logical_path, profiles,
                                       xattr_requirements, estimate,
                                       restore_report, capture_report,
                                       source_is_root, dest_is_root,
                                       dest_exists, dest_st, source_st,
                                       desired_st, source_object_fd);
    else if (S_ISDIR(source_st.st_mode))
        status = restore_entry_directory(ctx, pass, dest_parent_fd, dest_leaf,
                                         logical_path, snapshots, profiles,
                                         estimate, xattr_requirements,
                                         metadata_anchor_fd,
                                         skip_symlink_target_read,
                                         restore_report, capture_report,
                                         dest_exists, dest_st, source_st,
                                         desired_st, source_object_fd, depth);
    else if (S_ISFIFO(source_st.st_mode))
        status = restore_entry_fifo(ctx, pass, dest_parent_fd, dest_leaf,
                                    logical_path, restore_report,
                                    source_is_root, dest_is_root, dest_exists,
                                    dest_st, source_object_fd, desired_st);
    else
    {
        restore_report_failure(restore_report, logical_path,
                               "it is of a kind migr cannot restore", 0);
        close(source_object_fd);
        return -1;
    }
    // The apply pass counts what it restores; the validate pass counts what
    // it would, which is all a dry run does.
    if (pass == RESTORE_VALIDATE && status == RESTORE_NATIVE_OK)
        restore_report_applied(restore_report);
    return status;
}

static int restore_arguments_valid(const CloneContext *ctx,
                                   int source_root_fd, const char *source_rel,
                                   int destination_root_fd, const char *destination_rel)
{
    if (ctx == NULL || ctx->operation != CLONE_RESTORE || ctx->representation != CLONE_NATIVE_TREE)
        return 0;
    if (source_root_fd < 0 || destination_root_fd < 0 ||
        source_rel == NULL || destination_rel == NULL)
        return 0;
    if (!fd_is_directory(source_root_fd) || !fd_is_directory(destination_root_fd))
        return 0;
    if (source_rel[0] != '\0' && !relative_path_is_safe(source_rel))
        return 0;
    if (destination_rel[0] != '\0' && !relative_path_is_safe(destination_rel))
        return 0;
    return 1;
}

RestoreSourceStatus restore_native_source_status_at(int source_root_fd,
                                                     const char *source_rel)
{
    if (source_root_fd < 0 || source_rel == NULL ||
        !fd_is_directory(source_root_fd) ||
        (source_rel[0] != '\0' && !relative_path_is_safe(source_rel)))
    {
        errno = EINVAL;
        return RESTORE_SOURCE_ERROR;
    }

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult result =
        resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf));
    if (result == RESTORE_RESOLVE_MISSING)
        return RESTORE_SOURCE_MISSING;
    if (result != RESTORE_RESOLVE_OK)
        return RESTORE_SOURCE_ERROR;

    struct stat st;
    int object_fd = open_source_object(source_parent_fd, source_leaf, &st);
    int saved_errno = errno;
    close(source_parent_fd);
    if (object_fd >= 0)
    {
        close(object_fd);
        return RESTORE_SOURCE_PRESENT;
    }
    errno = saved_errno;
    return saved_errno == ENOENT
        ? RESTORE_SOURCE_MISSING
        : RESTORE_SOURCE_ERROR;
}

static void restore_native_report_init(RestoreNativeReport *report)
{
    if (report != NULL)
        memset(report, 0, sizeof(*report));
}

// The parents of one restore root on both sides, and the folder its
// metadata is profiled against. dest_parent_fd is -1 while the root's place
// on this system does not exist yet.
typedef struct {
    int source_parent_fd;
    char source_leaf[RESTORE_LEAF_MAX];
    int dest_parent_fd;
    char dest_leaf[RESTORE_LEAF_MAX];
    int metadata_anchor_fd;
} RestoreRootFds;

static void restore_root_close(RestoreRootFds *fds)
{
    if (fds->source_parent_fd >= 0)
        close(fds->source_parent_fd);
    if (fds->dest_parent_fd >= 0)
        close(fds->dest_parent_fd);
    if (fds->metadata_anchor_fd >= 0)
        close(fds->metadata_anchor_fd);
    fds->source_parent_fd = fds->dest_parent_fd = fds->metadata_anchor_fd = -1;
}

// 0 with fds open, or -1 with the failure in report and nothing open.
static int restore_root_open(const CloneContext *ctx, int source_root_fd,
                             const char *source_rel, int destination_root_fd,
                             const char *destination_rel, RestoreRootFds *fds,
                             RestoreNativeReport *report)
{
    fds->source_parent_fd = fds->dest_parent_fd = fds->metadata_anchor_fd = -1;
    if (!restore_arguments_valid(ctx, source_root_fd, source_rel,
                                 destination_root_fd, destination_rel))
    {
        restore_report_failure(report, source_rel,
                               "it was given to the restore wrongly", 0);
        return -1;
    }
    if (resolve_parent(source_root_fd, source_rel, 0, &fds->source_parent_fd,
                       fds->source_leaf, sizeof(fds->source_leaf)) !=
        RESTORE_RESOLVE_OK)
    {
        restore_report_failure(report, source_rel,
                               "open the folders above its copy in the backup",
                               errno);
        return -1;
    }
    if (resolve_parent(destination_root_fd, destination_rel, 0,
                       &fds->dest_parent_fd, fds->dest_leaf,
                       sizeof(fds->dest_leaf)) == RESTORE_RESOLVE_ERROR)
    {
        int err = errno;
        int not_a_folder = err == ELOOP || err == ENOTDIR;
        restore_report_failure(report, source_rel,
                               not_a_folder
                                   ? "a folder on the way is a symbolic link "
                                     "or not a folder; move it aside and run "
                                     "the restore again"
                                   : "open the folders above it",
                               not_a_folder ? 0 : err);
        restore_root_close(fds);
        return -1;
    }
    fds->metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (fds->metadata_anchor_fd < 0)
    {
        restore_report_failure(report, source_rel,
                               "open the folder it goes into", errno);
        restore_root_close(fds);
        return -1;
    }
    return 0;
}

RestoreNativeStatus restore_native_preflight_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    RestoreNativeReport *report)
{
    restore_native_report_init(report);
    RestoreRootFds fds;
    if (restore_root_open(ctx, source_root_fd, source_rel, destination_root_fd,
                          destination_rel, &fds, report) != 0)
        return -1;

    MetadataSnapshots snapshots;
    MetadataProfiles profiles;
    metadata_snapshots_init(&snapshots);
    metadata_profiles_init(&profiles);
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, fds.source_parent_fd,
                              fds.source_leaf, fds.dest_parent_fd,
                              fds.dest_leaf, source_rel, &snapshots,
                              &profiles, NULL, NULL, fds.metadata_anchor_fd, 0,
                              report, NULL, 0);
    restore_root_close(&fds);
    metadata_snapshots_free(&snapshots);
    metadata_profiles_free(&profiles);
    return rc;
}

RestoreNativeStatus restore_native_metadata_inventory_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    MetadataProfiles *profiles, NativeRestoreEstimate *estimate,
    RestoreNativeReport *report)
{
    restore_native_report_init(report);
    RestoreRootFds fds;
    if (profiles == NULL)
    {
        restore_report_failure(report, source_rel,
                               "it was given to the restore wrongly", 0);
        return -1;
    }
    if (restore_root_open(ctx, source_root_fd, source_rel, destination_root_fd,
                          destination_rel, &fds, report) != 0)
        return -1;

    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, fds.source_parent_fd,
                              fds.source_leaf, fds.dest_parent_fd,
                              fds.dest_leaf, source_rel, &snapshots, profiles,
                              estimate, NULL, fds.metadata_anchor_fd, 1,
                              report, NULL, 0);
    restore_root_close(&fds);
    metadata_snapshots_free(&snapshots);
    return rc;
}

RestoreNativeStatus restore_native_at_report(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    RestoreNativeReport *report, BackupCaptureReport *capture_report)
{
    RestoreNativeReport local_report;
    if (report == NULL)
        report = &local_report;
    restore_native_report_init(report);

    RestoreRootFds fds;
    if (restore_root_open(ctx, source_root_fd, source_rel, destination_root_fd,
                          destination_rel, &fds, report) != 0)
        return -1;

    MetadataSnapshots snapshots;
    MetadataProfiles profiles;
    MetadataXattrRequirements xattr_requirements = {0};
    metadata_snapshots_init(&snapshots);
    metadata_profiles_init(&profiles);
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, fds.source_parent_fd,
                              fds.source_leaf, fds.dest_parent_fd,
                              fds.dest_leaf, source_rel, &snapshots,
                              &profiles, NULL, &xattr_requirements,
                              fds.metadata_anchor_fd, 0, report, NULL, 0);
    MetadataProbeFailure probe_failure;
    if (rc == 0 && !ctx->metadata_preflight_done &&
        metadata_profiles_probe(&profiles, metadata_policy_from_context(ctx),
                                &probe_failure) != 0)
    {
        restore_report_failure(report, source_rel, probe_failure.step.step,
                               probe_failure.step.err);
        rc = -1;
    }
    if (rc == 0 && !ctx->metadata_preflight_done &&
        metadata_xattr_capability_probe(fds.metadata_anchor_fd,
                                        &xattr_requirements) != 0)
    {
        restore_report_failure(report, source_rel,
                               "the destination cannot keep the extended "
                               "attributes it needs", 0);
        rc = -1;
    }
    close(fds.metadata_anchor_fd);
    fds.metadata_anchor_fd = -1;

    if (rc == 0)
    {
        if (fds.dest_parent_fd >= 0)
            close(fds.dest_parent_fd);
        fds.dest_parent_fd = -1;
        if (resolve_parent(destination_root_fd, destination_rel, 1,
                           &fds.dest_parent_fd, fds.dest_leaf,
                           sizeof(fds.dest_leaf)) != RESTORE_RESOLVE_OK)
        {
            restore_report_failure(report, source_rel,
                                   "create the folders above it", errno);
            rc = -1;
        }
    }
    if (rc == 0)
    {
        report->applied_count = 0;
        rc = restore_entry_at(ctx, RESTORE_APPLY, fds.source_parent_fd,
                              fds.source_leaf, fds.dest_parent_fd,
                              fds.dest_leaf, source_rel, &snapshots, NULL,
                              NULL, NULL, destination_root_fd, 0, report,
                              capture_report, 0);
    }
    if (rc != RESTORE_NATIVE_OK && report->failed_count == 0)
        restore_report_failure(report, source_rel, NULL, 0);
    restore_root_close(&fds);
    metadata_snapshots_free(&snapshots);
    metadata_profiles_free(&profiles);
    return rc;
}

RestoreNativeStatus restore_native_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel)
{
    return restore_native_at_report(ctx, source_root_fd, source_rel,
                                    destination_root_fd, destination_rel,
                                    NULL, NULL);
}

int get_dir_size(const char *path, off_t *size)
{
    struct stat st;
    if (lstat(path, &st) != 0)
    {
        return -1;
    }

    // If it's a symlink, we don't follow it, so we just add the size of the link itself
    if (S_ISLNK(st.st_mode))
    {        
        *size += st.st_size;
        return 0;
    }

    // If it's a regular file, add its size to the total
    if (S_ISREG(st.st_mode))
    {
        *size += st.st_size;
        return 0;
    }

    // FIFOs, sockets, and device nodes carry no payload bytes. Contribute nothing
    // and stay silent: measurement feeds the report, which must not be chatty.
    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode) ||
        S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
    {
        return 0;
    }

    // If it's a directory, recursively calculate the size of its contents
    if (S_ISDIR(st.st_mode))
    {
        *size += st.st_size; // add the size of the directory itself

        DIR *dir = opendir(path);
        if (dir == NULL)
        {
            return -1;
        }

        struct dirent *entry;
        for (;;)
        {
            errno = 0;
            entry = readdir(dir);
            if (entry == NULL)
            {
                if (errno != 0)
                {
                    closedir(dir);
                    return -1;
                }
                break;
            }

            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            char new_path[PATH_MAX];
            if (path_join(new_path, sizeof(new_path), path, entry->d_name) != 0)
            {
                closedir(dir);
                return -1;
            }

            if (get_dir_size(new_path, size) != 0)
            {
                closedir(dir);
                return -1;
            }
        }

        if (closedir(dir) != 0)
        {
            return -1;
        }
        return 0;
    }

    return -1; // unknown file type (unreachable on Linux); refuse defensively
}

// A child that points its stdio at a pipe or /dev/null with dup2() and then
// execs or _exit()s hands those descriptors on; GCC's analyzer (13 and later)
// reports them as leaked. Clang does not know the warning.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 13
#define CHILD_REDIRECT_BEGIN                                    \
    _Pragma("GCC diagnostic push")                              \
    _Pragma("GCC diagnostic ignored \"-Wanalyzer-fd-leak\"")
#define CHILD_REDIRECT_END _Pragma("GCC diagnostic pop")
#else
#define CHILD_REDIRECT_BEGIN
#define CHILD_REDIRECT_END
#endif

int run_command(char *const argv[])
{
    // What migr printed so far comes before the command's own output.
    fflush(stdout);
    pid_t pid = fork();

    if (pid == -1)
    {
        return -1; // fork failed
    }
    else if (pid == 0)
    {
        // Child process. No stdio until exec: stdout and stderr may be the
        // run log's streams, whose lock another thread can hold at fork().
        // An exec failure exits with 1 silently; the caller reports it.
        execvp(argv[0], argv);
        _exit(1); // not exit(): it would flush stdio buffers shared with the parent
    }
    else 
    {
        // Parent process
        int status;

        // Wait for the child process to finish so it won't become a zombie process
        pid_t waited;
        do
        {
            waited = waitpid(pid, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited == -1)
        {
            return -1;
        }

        if(WIFEXITED(status))
        {
            return WEXITSTATUS(status); // return the exit status of the child process
        }
    }
    return -1; // should not reach here
}

// Forks a child that runs argv in /, its standard output discarded and its
// standard error on stderr_fd, or discarded too when stderr_fd is -1.
static pid_t spawn_in_root(char *const argv[], int stderr_fd)
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0)
    {
        CHILD_REDIRECT_BEGIN
        // No stdio until exec, as in run_command().
        int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(stderr_fd < 0 ? null_fd : stderr_fd, STDERR_FILENO) < 0 ||
            chdir("/") != 0)
            _exit(1);
        execvp(argv[0], argv);
        _exit(1);
        CHILD_REDIRECT_END
    }
    return pid;
}

static int wait_exit_status(pid_t pid)
{
    int status;
    pid_t waited;
    do
        waited = waitpid(pid, &status, 0);
    while (waited < 0 && errno == EINTR);
    if (waited == -1 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

int run_command_errors(char *const argv[], char *errors, size_t errors_size)
{
    if (errors == NULL || errors_size == 0)
        return -1;
    errors[0] = '\0';
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return -1;
    pid_t pid = spawn_in_root(argv, pipefd[1]);
    close(pipefd[1]);
    if (pid == -1)
    {
        close(pipefd[0]);
        return -1;
    }
    // Only the end is kept: a failing command says why last.
    size_t used = 0;
    char chunk[4096];
    for (;;)
    {
        ssize_t got = read(pipefd[0], chunk, sizeof(chunk));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        size_t length = (size_t)got;
        size_t room = errors_size - 1U;
        if (length >= room)
        {
            memcpy(errors, chunk + length - room, room);
            used = room;
        }
        else
        {
            if (used + length > room)
            {
                size_t drop = used + length - room;
                memmove(errors, errors + drop, used - drop);
                used -= drop;
            }
            memcpy(errors + used, chunk, length);
            used += length;
        }
    }
    errors[used] = '\0';
    close(pipefd[0]);
    return wait_exit_status(pid);
}

int run_command_silent(char *const argv[])
{
    pid_t pid = spawn_in_root(argv, -1);
    return pid == -1 ? -1 : wait_exit_status(pid);
}

// Inherited from the elevated process, these describe root rather than the
// user a dropped child runs as; without them consumers re-derive from HOME.
static const char *const identity_env_dropped[] = {
    "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
    "XDG_STATE_HOME"
};

static int env_entry_is_dropped(const char *entry)
{
    for (size_t i = 0;
         i < sizeof(identity_env_dropped) / sizeof(identity_env_dropped[0]);
         i++)
    {
        size_t name_len = strlen(identity_env_dropped[i]);
        if (strncmp(entry, identity_env_dropped[i], name_len) == 0 &&
            entry[name_len] == '=')
            return 1;
    }
    return 0;
}

static int env_entry_has_name(const char *entry, const char *name,
                              size_t name_len)
{
    return strncmp(entry, name, name_len) == 0 && entry[name_len] == '=';
}

// Builds a child environment before fork so the child only execs. Every base
// entry is kept in order except, when home is non-NULL, the identity-dropped
// names, and any name that overrides sets. HOME=home (if any) and then the
// overrides are appended. The caller frees the array and *home_entry_out (the
// one allocated entry, or NULL); the other entries borrow base or overrides.
static char **build_command_environment(char *const *base, const char *home,
                                        const char *const *overrides,
                                        char **home_entry_out)
{
    if (home_entry_out == NULL || (home != NULL && home[0] != '/'))
    {
        errno = EINVAL;
        return NULL;
    }
    *home_entry_out = NULL;

    size_t override_count = 0;
    while (overrides != NULL && overrides[override_count] != NULL)
    {
        const char *equals = strchr(overrides[override_count], '=');
        if (equals == NULL || equals == overrides[override_count])
        {
            errno = EINVAL;
            return NULL;
        }
        override_count++;
    }

    size_t base_count = 0;
    while (base != NULL && base[base_count] != NULL)
        base_count++;

    char *home_entry = NULL;
    if (home != NULL)
    {
        size_t home_len = strlen(home);
        home_entry = malloc(sizeof("HOME=") + home_len);
        if (home_entry == NULL)
            return NULL;
        memcpy(home_entry, "HOME=", sizeof("HOME=") - 1U);
        memcpy(home_entry + sizeof("HOME=") - 1U, home, home_len + 1U);
    }
    char **env = malloc((base_count + override_count + 2U) * sizeof(*env));
    if (env == NULL)
    {
        free(home_entry);
        return NULL;
    }

    size_t count = 0;
    for (size_t i = 0; i < base_count; i++)
    {
        if (home != NULL && env_entry_is_dropped(base[i]))
            continue;
        int overridden = 0;
        for (size_t j = 0; j < override_count && !overridden; j++)
        {
            size_t name_len = (size_t)(strchr(overrides[j], '=') -
                                       overrides[j]);
            overridden = env_entry_has_name(base[i], overrides[j], name_len);
        }
        if (!overridden)
            env[count++] = base[i];
    }
    if (home_entry != NULL)
        env[count++] = home_entry;
    for (size_t j = 0; j < override_count; j++)
        env[count++] = (char *)overrides[j];
    env[count] = NULL;

    *home_entry_out = home_entry;
    return env;
}

#ifdef FILEOPS_TEST_HOOKS
char **fileops_test_build_identity_environment(char *const *base,
                                               const char *home,
                                               char **home_entry_out)
{
    if (home == NULL)
    {
        errno = EINVAL;
        return NULL;
    }
    return build_command_environment(base, home, NULL, home_entry_out);
}

char **fileops_test_build_command_environment(char *const *base,
                                              const char *home,
                                              const char *const *overrides,
                                              char **home_entry_out)
{
    return build_command_environment(base, home, overrides, home_entry_out);
}
#endif

// Feeds options->stdin_data (if any) while capturing stdout, interleaved with
// poll() so neither side can block the other. SIGPIPE from a child that exits
// without reading its stdin is blocked for the duration and consumed, so it
// cannot terminate migr.
static void run_command_exchange(int out_fd, int in_fd,
                                 const RunCommandOptions *options,
                                 char *output, size_t output_size)
{
    size_t total = 0;
    size_t written = 0;
    const unsigned char *data = options != NULL
        ? (const unsigned char *)options->stdin_data : NULL;
    size_t length = data != NULL ? options->stdin_length : 0;
    if (in_fd >= 0 && written == length)
    {
        close(in_fd);
        in_fd = -1;
    }

    char discard[4096];
    for (;;)
    {
        struct pollfd fds[2] = {
            { .fd = out_fd, .events = POLLIN },
            { .fd = in_fd, .events = POLLOUT }
        };
        int ready = poll(fds, in_fd >= 0 ? 2U : 1U, -1);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (in_fd >= 0 && fds[1].revents != 0)
        {
            ssize_t sent = write(in_fd, data + written, length - written);
            if (sent > 0)
                written += (size_t)sent;
            if ((sent < 0 && errno != EAGAIN && errno != EINTR) ||
                written == length)
            {
                close(in_fd);
                in_fd = -1;
            }
        }
        if (fds[0].revents != 0)
        {
            // Once the buffer is full, keep draining (and discarding) so the
            // child is never killed by SIGPIPE on its own stdout and its real
            // exit status is still reported.
            char *target = total < output_size - 1U ? output + total : discard;
            size_t room = total < output_size - 1U
                ? output_size - 1U - total : sizeof(discard);
            ssize_t bytes_read = read(out_fd, target, room);
            if (bytes_read < 0 && errno == EINTR)
                continue;
            if (bytes_read <= 0)
                break;
            if (target != discard)
                total += (size_t)bytes_read;
        }
    }
    output[total] = '\0';
    if (in_fd >= 0)
        close(in_fd);
}

static int run_command_capture_internal(char *const argv[], char *output,
                                        size_t output_size,
                                        const RunCommandOptions *options)
{
    if (output == NULL || output_size == 0)
    {
        return -1; // nothing safe to write into
    }
    int drop_identity = options != NULL && options->drop_identity;
    if (drop_identity && options->home == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    int feed_stdin = options != NULL && options->stdin_data != NULL;

    char **child_env = NULL;
    char *home_entry = NULL;
    if (drop_identity || (options != NULL && options->env != NULL))
    {
        child_env = build_command_environment(
            environ, drop_identity ? options->home : NULL,
            options->env, &home_entry);
        if (child_env == NULL)
            return -1;
    }

    int pipefd[2];
    int stdin_pipe[2] = { -1, -1 };
    if (pipe(pipefd) == -1)
    {
        free(home_entry);
        free(child_env);
        return -1; // pipe creation failed
    }
    if (feed_stdin && pipe(stdin_pipe) == -1)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        free(home_entry);
        free(child_env);
        return -1;
    }

    sigset_t sigpipe_set, previous_mask;
    sigemptyset(&sigpipe_set);
    sigaddset(&sigpipe_set, SIGPIPE);
    int sigpipe_was_blocked = 1;
    if (feed_stdin &&
        pthread_sigmask(SIG_BLOCK, &sigpipe_set, &previous_mask) == 0)
        sigpipe_was_blocked = sigismember(&previous_mask, SIGPIPE);

    // What migr printed so far comes before the command's own stderr.
    fflush(stdout);
    pid_t pid = fork();
    if (pid == -1)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        if (feed_stdin)
        {
            close(stdin_pipe[0]);
            close(stdin_pipe[1]);
            if (!sigpipe_was_blocked)
                pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
        }
        free(home_entry);
        free(child_env);
        return -1; // fork failed
    }
    else if (pid == 0)
    {
        CHILD_REDIRECT_BEGIN
        // Child process. No stdio until exec, as in run_command().
        close(pipefd[0]); // Close the read end of the pipe

        if (dup2(pipefd[1], STDOUT_FILENO) == -1)
            _exit(1); // Redirect failed; do not exec with the wrong stdout
        close(pipefd[1]); // Close the original write end of the pipe

        if (feed_stdin)
        {
            close(stdin_pipe[1]);
            if (dup2(stdin_pipe[0], STDIN_FILENO) == -1)
                _exit(1);
            close(stdin_pipe[0]);
            if (!sigpipe_was_blocked)
                pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
        }

        if (drop_identity)
        {
            if (setgroups(0, NULL) != 0)
                _exit(125);
            if (setgid(options->gid) != 0)
                _exit(126);
            if (setuid(options->uid) != 0)
                _exit(127);
        }
        if (child_env != NULL)
            execvpe(argv[0], argv, child_env);
        else
            execvp(argv[0], argv); // Execute the command

        _exit(1); // exec failed: an absent optional command stays silent
        CHILD_REDIRECT_END
    }
    else
    {
        // Parent process
        close(pipefd[1]); // Close the write end of the pipe
        free(home_entry); // the child execs from its own copy
        free(child_env);
        int in_fd = -1;
        if (feed_stdin)
        {
            close(stdin_pipe[0]);
            in_fd = stdin_pipe[1];
            int flags = fcntl(in_fd, F_GETFL);
            if (flags >= 0)
                (void)fcntl(in_fd, F_SETFL, flags | O_NONBLOCK);
        }

        run_command_exchange(pipefd[0], in_fd, options, output, output_size);
        close(pipefd[0]); // Close the read end of the pipe

        if (feed_stdin && !sigpipe_was_blocked)
        {
            sigset_t pending;
            struct timespec no_wait = { 0, 0 };
            if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE))
                (void)sigtimedwait(&sigpipe_set, NULL, &no_wait);
            pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
        }

        int status;
        if (waitpid(pid, &status, 0) == -1)
        {
            return -1;
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status); // Return the exit status of the child process
        }
    }
    return -1; // should not reach here
}

int run_command_capture(char *const argv[], char *output, size_t output_size)
{
    return run_command_capture_internal(argv, output, output_size, NULL);
}

int run_command_capture_as_identity(char *const argv[], char *output,
                                    size_t output_size, uid_t uid, gid_t gid,
                                    const char *home)
{
    if (home == NULL || home[0] != '/')
    {
        errno = EINVAL;
        return -1;
    }
    RunCommandOptions options = {
        .drop_identity = 1, .uid = uid, .gid = gid, .home = home
    };
    return run_command_capture_internal(argv, output, output_size, &options);
}

int run_command_capture_with(char *const argv[], char *output,
                             size_t output_size,
                             const RunCommandOptions *options)
{
    return run_command_capture_internal(argv, output, output_size, options);
}
