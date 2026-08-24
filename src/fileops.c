#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <limits.h> // to use PATH_MAX
#include <errno.h>
#include <stdint.h>

#include "fileops.h" // CloneContext
#include "hash.h"
#include "metadata.h"
#include "portable.h"
#include "sidecar.h"
#include "utils.h" // path_join

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

static void capture_report_source_refusal(BackupCaptureReport *report,
                                          const char *source_path)
{
    if (report == NULL || report->failed_source_path[0] != '\0' ||
        source_path == NULL)
        return;
    (void)snprintf(report->failed_source_path,
                   sizeof(report->failed_source_path), "%s", source_path);
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
#endif

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
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ map->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)device);
    return hash_fnv1a_uint64(hash, (uint64_t)inode);
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
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ pool->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)device);
    return hash_fnv1a_uint64(hash, (uint64_t)inode);
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

static int native_seed_destination_matches(const CloneContext *ctx,
                                           const struct stat *source,
                                           const struct stat *destination)
{
    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
    return ctx != NULL && source != NULL && destination != NULL &&
           S_ISREG(destination->st_mode) &&
           destination->st_size == source->st_size &&
           destination->st_mtim.tv_sec == source->st_mtim.tv_sec &&
           (!policy.nsec_exact ||
            destination->st_mtim.tv_nsec == source->st_mtim.tv_nsec);
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

static int native_seed_destination_parent(int destination_root_fd,
                                          const char *destination_rel,
                                          int *parent_fd_out,
                                          char *leaf_out,
                                          size_t leaf_size)
{
    if (destination_root_fd < 0 || destination_rel == NULL ||
        parent_fd_out == NULL || leaf_out == NULL || leaf_size == 0 ||
        !native_seed_relative_path_is_safe(destination_rel))
        return -1;

    *parent_fd_out = -1;
    if (destination_rel[0] == '\0')
        return 1;

    int current_fd = fcntl(destination_root_fd, F_DUPFD_CLOEXEC, 0);
    if (current_fd < 0)
        return -1;

    const char *component = destination_rel;
    for (;;)
    {
        const char *slash = strchr(component, '/');
        size_t length = slash == NULL ? strlen(component)
                                      : (size_t)(slash - component);
        if (slash == NULL)
        {
            if (length >= leaf_size)
            {
                close(current_fd);
                return -1;
            }
            memcpy(leaf_out, component, length + 1U);
            *parent_fd_out = current_fd;
            return 0;
        }

        char child[NAME_MAX + 1U];
        if (length >= sizeof(child))
        {
            close(current_fd);
            return -1;
        }
        memcpy(child, component, length);
        child[length] = '\0';
        int next_fd = openat(current_fd, child,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                 O_CLOEXEC);
        if (next_fd < 0)
        {
            int saved_errno = errno;
            close(current_fd);
            return saved_errno == ENOENT ? 1 : -1;
        }
        close(current_fd);
        current_fd = next_fd;
        component = slash + 1;
    }
}

static int native_inode_map_seed_existing_at(
    const CloneContext *ctx, const char *source_path, int destination_dir_fd,
    const char *destination_leaf);

static int native_inode_map_seed_existing_directory_at(
    const CloneContext *ctx, const char *source_path, int source_fd,
    int destination_fd)
{
    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        close(source_fd);
        close(destination_fd);
        return -1;
    }

    int failed = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL)
        {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_source[PATH_MAX];
        if (path_join(child_source, sizeof(child_source), source_path,
                      entry->d_name) != 0 ||
            native_inode_map_seed_existing_at(ctx, child_source,
                                               destination_fd,
                                               entry->d_name) != 0)
        {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    if (close(destination_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int native_inode_map_seed_existing_at(
    const CloneContext *ctx, const char *source_path, int destination_dir_fd,
    const char *destination_leaf)
{
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        return -1;

    struct stat destination_st;
    if (fstatat(destination_dir_fd, destination_leaf, &destination_st,
                AT_SYMLINK_NOFOLLOW) != 0)
    {
        return errno == ENOENT ? 0 : -1;
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
            return errno == EPERM ? 0 : -1;
        struct stat opened;
        int failed = fstat(source_fd, &opened) != 0 ||
                     !metadata_source_unchanged(&source_st, &opened);
        if (close(source_fd) != 0)
            failed = 1;
        if (failed)
            return -1;
        return native_inode_map_insert(ctx->inode_map, source_st.st_dev,
                                       source_st.st_ino, destination_dir_fd,
                                       destination_leaf);
    }

    if (!S_ISDIR(source_st.st_mode) || !S_ISDIR(destination_st.st_mode))
        return 0;

    int source_fd = open(source_path,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                         O_NOATIME | O_CLOEXEC);
    if (source_fd < 0)
        return errno == EPERM ? 0 : -1;
    struct stat opened;
    int failed = fstat(source_fd, &opened) != 0 ||
                 !metadata_source_unchanged(&source_st, &opened);
    if (failed)
    {
        close(source_fd);
        return -1;
    }

    int destination_fd = openat(destination_dir_fd, destination_leaf,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                O_CLOEXEC);
    if (destination_fd < 0)
    {
        close(source_fd);
        return -1;
    }
    return native_inode_map_seed_existing_directory_at(
        ctx, source_path, source_fd, destination_fd);
}

static int native_inode_map_seed_existing_root_at(
    const CloneContext *ctx, const char *source_path, int destination_root_fd)
{
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        return -1;

    struct stat destination_st;
    if (fstat(destination_root_fd, &destination_st) != 0)
        return -1;
    if (!S_ISDIR(destination_st.st_mode) || !S_ISDIR(source_st.st_mode))
        return 0;

    int source_fd = open(source_path,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                         O_NOATIME | O_CLOEXEC);
    if (source_fd < 0)
        return errno == EPERM ? 0 : -1;
    struct stat opened;
    int failed = fstat(source_fd, &opened) != 0 ||
                 !metadata_source_unchanged(&source_st, &opened);
    if (failed)
    {
        close(source_fd);
        return -1;
    }

    int destination_fd = fcntl(destination_root_fd, F_DUPFD_CLOEXEC, 0);
    if (destination_fd < 0)
    {
        close(source_fd);
        return -1;
    }
    return native_inode_map_seed_existing_directory_at(
        ctx, source_path, source_fd, destination_fd);
}

int native_inode_map_seed_existing(const CloneContext *ctx,
                                   const char *source_path,
                                   int destination_root_fd,
                                   const char *destination_rel)
{
    if (ctx == NULL ||
        (ctx->operation != CLONE_BACKUP && ctx->operation != CLONE_RESTORE) ||
        ctx->representation != CLONE_NATIVE_TREE ||
        source_path == NULL || destination_root_fd < 0 ||
        !native_seed_relative_path_is_safe(destination_rel))
        return -1;
    if (ctx->inode_map == NULL)
        return 0;
    if (destination_rel[0] == '\0')
        return native_inode_map_seed_existing_root_at(
            ctx, source_path, destination_root_fd);

    int destination_parent_fd = -1;
    char destination_leaf[NAME_MAX + 1U];
    int resolved = native_seed_destination_parent(
        destination_root_fd, destination_rel, &destination_parent_fd,
        destination_leaf, sizeof(destination_leaf));
    if (resolved != 0)
        return resolved > 0 ? 0 : -1;
    int result = native_inode_map_seed_existing_at(
        ctx, source_path, destination_parent_fd, destination_leaf);
    if (close(destination_parent_fd) != 0)
        result = -1;
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
                              const char *rel_path)
{
    NativeVisitedSet *set = opaque_set;
    if (set == NULL || root_key == NULL || rel_path == NULL)
        return -1;

    size_t root_key_length = strlen(root_key);
    size_t rel_path_length = strlen(rel_path);
    if (root_key_length == SIZE_MAX || rel_path_length == SIZE_MAX)
        return -1;

    uint64_t hash = native_visited_hash(set, root_key, root_key_length,
                                        rel_path, rel_path_length);
    size_t index = SIZE_MAX;
    int location = native_visited_locate(set, root_key, root_key_length,
                                          rel_path, rel_path_length, hash,
                                          &index);
    if (location == 1)
        return 1;
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
    return location == 1 ? 1 : 0;
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

// An identical symlink already at this address is work a previous run
// finished, so resuming past it succeeds. Any other object there -- a
// symlink to somewhere else included -- is a genuine collision and is
// refused rather than replaced.
static int capture_symlink_at(const char *src, int dest_dir_fd, const char *leaf,
                              const struct stat *st,
                              MetadataTimestampPolicy policy)
{
    char link_target[PATH_MAX];
    ssize_t len = readlink(src, link_target, sizeof(link_target) - 1);
    if (len < 0)
        return -1;
    link_target[len] = '\0';

    if (symlinkat(link_target, dest_dir_fd, leaf) != 0)
    {
        if (errno != EEXIST)
            return -1;

        struct stat dest_st;
        if (fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISLNK(dest_st.st_mode))
            return -1;

        char existing[PATH_MAX];
        ssize_t existing_len = readlinkat(dest_dir_fd, leaf, existing, sizeof(existing) - 1);
        if (existing_len < 0)
            return -1;
        existing[existing_len] = '\0';

        if (strcmp(existing, link_target) != 0)
            return -1;
    }

    PortableXattrs xattrs = {0};
    int failed = metadata_apply_symlink_ownership_at(dest_dir_fd, leaf, st);
    if (!failed && collect_symlink_xattrs(src, &xattrs) != 0)
        failed = 1;

    struct stat after;
    if (!failed &&
        (lstat(src, &after) != 0 || !metadata_symlink_unchanged(st, &after)))
        failed = 1;
    if (!failed && metadata_apply_xattrs_symlink_at(dest_dir_fd, leaf,
                                                    xattrs.items,
                                                    xattrs.count) != 0)
        failed = 1;
    if (!failed && metadata_apply_symlink_times_at(dest_dir_fd, leaf, st,
                                                   policy) != 0)
        failed = 1;
    xattrs_free(&xattrs);
    return failed ? -1 : 0;
}

// A write() that reports zero bytes for a non-zero request has made no
// progress and never will on a retry, so it is treated as the failure it is
// rather than spun on forever.
static int copy_file_contents(int src_fd, int dest_fd,
                              BackupCaptureReport *report)
{
    char buffer[8192];
    ssize_t bytes_read;
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0)
    {
        ssize_t bytes_written = 0;
        while (bytes_written < bytes_read)
        {
            ssize_t res = write(dest_fd, buffer + bytes_written,
                                (size_t)(bytes_read - bytes_written));
            if (res <= 0)
                return -1;
            bytes_written += res;
        }
        if (report != NULL)
        {
            report->bytes_copied += bytes_read;
            if (report->progress_cb != NULL &&
                backup_progress_should_fire(&report->progress_last_fired,
                                            report->progress_unthrottled))
                report->progress_cb(report->bytes_copied,
                                    report->progress_userdata);
        }
    }
    return bytes_read < 0 ? -1 : 0;
}

static BackupCaptureStatus capture_hardlink_at(
    int src_fd, int dest_dir_fd, const char *leaf,
    int representative_parent_fd, const char *representative_leaf,
    const struct stat *source_snapshot)
{
    if (source_snapshot == NULL || !S_ISREG(source_snapshot->st_mode) ||
        representative_parent_fd < 0 ||
        !destination_leaf_is_safe(leaf) ||
        !destination_leaf_is_safe(representative_leaf))
    {
        close(src_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    struct stat source_after;
    int source_failed = fstat(src_fd, &source_after) != 0 ||
                        !metadata_source_unchanged(source_snapshot,
                                                   &source_after);
    if (close(src_fd) != 0)
        source_failed = 1;
    if (source_failed)
        return BACKUP_CAPTURE_ERROR;

    // The map records the destination representative, not the source inode:
    // a copied source and its payload necessarily have different identities.
    // The representative's destination inode is therefore the authority for
    // both resume validation and the post-link identity check.
    struct stat representative;
    if (fstatat(representative_parent_fd, representative_leaf,
                &representative, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(representative.st_mode))
        return BACKUP_CAPTURE_ERROR;

    struct stat existing;
    if (fstatat(dest_dir_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (native_hardlink_identity_matches(&existing, &representative))
            return BACKUP_CAPTURE_OK;
        return BACKUP_CAPTURE_ERROR;
    }
    if (errno != ENOENT)
        return BACKUP_CAPTURE_ERROR;

    if (linkat(representative_parent_fd, representative_leaf, dest_dir_fd,
               leaf, 0) != 0)
        return BACKUP_CAPTURE_ERROR;

    struct stat linked;
    if (fstatat(dest_dir_fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
        !native_hardlink_identity_matches(&linked, &representative))
    {
        errno = EIO;
        return BACKUP_CAPTURE_ERROR;
    }
    return BACKUP_CAPTURE_OK;
}

static BackupCaptureStatus capture_regular_at(
    const CloneContext *ctx, const char *src, int dest_dir_fd,
    const char *leaf, const struct stat *st, BackupCaptureReport *report)
{
    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
#ifdef BACKUP_TEST_HOOKS
    backup_test_before_capture_source_open(src);
#endif
    int src_fd = open(src, O_RDONLY | O_NOATIME | O_CLOEXEC | O_NOFOLLOW);
    if (src_fd < 0)
    {
        if (errno == EPERM)
        {
            capture_report_source_refusal(report, src);
            return BACKUP_CAPTURE_SOURCE_SAFE_READ;
        }
        return BACKUP_CAPTURE_ERROR;
    }

    struct stat source_snapshot;
    if (fstat(src_fd, &source_snapshot) != 0 ||
        !S_ISREG(source_snapshot.st_mode) ||
        !metadata_source_unchanged(st, &source_snapshot))
    {
        close(src_fd);
        return BACKUP_CAPTURE_ERROR;
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
            close(src_fd);
            return BACKUP_CAPTURE_ERROR;
        }
        if (found > 0)
            return capture_hardlink_at(src_fd, dest_dir_fd, leaf,
                                       representative_parent_fd,
                                       representative_leaf,
                                       &source_snapshot);
    }

    struct stat dest_st;
    if (fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        // A matching size and mtime is the resume signal; a different type at
        // the same address is a collision, never something to truncate.
        if (!S_ISREG(dest_st.st_mode))
        {
            close(src_fd);
            return BACKUP_CAPTURE_ERROR;
        }
        if (dest_st.st_size == source_snapshot.st_size &&
            dest_st.st_mtim.tv_sec == source_snapshot.st_mtim.tv_sec &&
            policy.nsec_exact &&
            dest_st.st_mtim.tv_nsec == source_snapshot.st_mtim.tv_nsec)
        {
            int dest_fd = openat(dest_dir_fd, leaf,
                                 O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            if (dest_fd < 0)
            {
                close(src_fd);
                return BACKUP_CAPTURE_ERROR;
            }
            struct stat opened_dest;
            int failed = fstat(dest_fd, &opened_dest) != 0 ||
                         !S_ISREG(opened_dest.st_mode);
            PortableXattrs xattrs = {0};
            if (!failed &&
                metadata_apply_ownership_and_mode_fd(dest_fd,
                                                     &source_snapshot) != 0)
                failed = 1;
            if (!failed && collect_xattrs(src_fd, &xattrs) != 0)
                failed = 1;
            struct stat after;
            if (!failed && (fstat(src_fd, &after) != 0 ||
                            !metadata_source_unchanged(&source_snapshot, &after)))
                failed = 1;
            if (!failed && metadata_apply_xattrs_fd(dest_fd, xattrs.items,
                                                    xattrs.count) != 0)
                failed = 1;
            if (!failed &&
                metadata_apply_times_fd(dest_fd, &source_snapshot, policy) != 0)
                failed = 1;
            xattrs_free(&xattrs);
            if (close(dest_fd) != 0)
                failed = 1;
            if (close(src_fd) != 0)
                failed = 1;
            if (failed)
                return BACKUP_CAPTURE_ERROR;
            if (ctx->inode_map != NULL && source_snapshot.st_nlink > 1 &&
                native_inode_map_insert(ctx->inode_map,
                                        source_snapshot.st_dev,
                                        source_snapshot.st_ino,
                                        dest_dir_fd, leaf) != 0)
                return BACKUP_CAPTURE_ERROR;
            return BACKUP_CAPTURE_OK;
        }
    }
    else if (errno != ENOENT)
    {
        close(src_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    // O_NOFOLLOW makes a symlink planted at this address fail the open with
    // ELOOP instead of being written through; O_TRUNC can therefore only ever
    // apply to the regular file the check above already accepted.
    int dest_fd = openat(dest_dir_fd, leaf,
                         O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                         source_snapshot.st_mode & 07777);
    if (dest_fd < 0)
    {
        close(src_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    int failed = copy_file_contents(src_fd, dest_fd, report) != 0;
    PortableXattrs xattrs = {0};
    if (!failed &&
        metadata_apply_ownership_and_mode_fd(dest_fd, &source_snapshot) != 0)
        failed = 1;
    if (!failed && collect_xattrs(src_fd, &xattrs) != 0)
        failed = 1;
    struct stat after;
    if (!failed && (fstat(src_fd, &after) != 0 ||
                    !metadata_source_unchanged(&source_snapshot, &after)))
        failed = 1;
    if (!failed && metadata_apply_xattrs_fd(dest_fd, xattrs.items,
                                            xattrs.count) != 0)
        failed = 1;
    if (!failed && metadata_apply_times_fd(dest_fd, &source_snapshot, policy) != 0)
        failed = 1;
    xattrs_free(&xattrs);

    // A write deferred by the kernel (quota, ENOSPC, a network filesystem)
    // can surface only here, so a failed close means the payload is not
    // actually complete and must be reported as such.
    if (close(dest_fd) != 0)
        failed = 1;
    if (close(src_fd) != 0)
        failed = 1;
    if (failed)
        return BACKUP_CAPTURE_ERROR;
    if (ctx->inode_map != NULL && source_snapshot.st_nlink > 1 &&
        native_inode_map_insert(ctx->inode_map, source_snapshot.st_dev,
                                source_snapshot.st_ino, dest_dir_fd, leaf) != 0)
        return BACKUP_CAPTURE_ERROR;
    return BACKUP_CAPTURE_OK;
}

// The directory is created with owner-only access and given the source's real
// mode by metadata_apply_ownership_and_mode_fd() only after its whole subtree
// is written.
// Creating it with the final mode up front would make a read-only source
// directory (e.g. 0555) impossible to descend into and populate, and the
// transient 0700 is never more permissive to group or other than the mode it
// ends up with.
static BackupCaptureStatus capture_directory_at(
    const CloneContext *ctx, const char *src, int dest_dir_fd,
    const char *leaf, const struct stat *st, const char *root_key,
    const char *rel_path, BackupCaptureReport *report)
{
#ifdef BACKUP_TEST_HOOKS
    backup_test_before_capture_source_open(src);
#endif
    int source_fd = open(src, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
    if (source_fd < 0)
    {
        if (errno == EPERM)
        {
            capture_report_source_refusal(report, src);
            return BACKUP_CAPTURE_SOURCE_SAFE_READ;
        }
        return BACKUP_CAPTURE_ERROR;
    }
    struct stat source_snapshot;
    if (fstat(source_fd, &source_snapshot) != 0 ||
        !S_ISDIR(source_snapshot.st_mode) ||
        !metadata_source_unchanged(st, &source_snapshot))
    {
        close(source_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    if (mkdirat(dest_dir_fd, leaf, 0700) != 0 && errno != EEXIST)
    {
        close(source_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    // O_NOFOLLOW rejects a symlink standing where the directory should be
    // (descending through it would write payload outside the container);
    // O_DIRECTORY rejects every other wrong type in the same call.
    int child_fd = openat(dest_dir_fd, leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_fd < 0)
    {
        close(source_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        close(source_fd);
        close(child_fd);
        return BACKUP_CAPTURE_ERROR;
    }

    BackupCaptureStatus result = BACKUP_CAPTURE_OK;
    struct dirent *entry;
    for (;;)
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
                result = BACKUP_CAPTURE_ERROR;
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Only the source path grows as we descend; refuse rather than act on
        // a truncated one. The destination never concatenates at all.
        char child_src[PATH_MAX];
        if (path_join(child_src, sizeof(child_src), src, entry->d_name) != 0)
        {
            result = BACKUP_CAPTURE_ERROR;
            break;
        }
        char child_rel[PATH_MAX];
        if (append_relative(child_rel, sizeof(child_rel), rel_path,
                            entry->d_name) != 0)
        {
            result = BACKUP_CAPTURE_ERROR;
            break;
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

    if (closedir(dir) != 0)
    {
        if (result == BACKUP_CAPTURE_OK)
            result = BACKUP_CAPTURE_ERROR;
    }
    PortableXattrs xattrs = {0};
    if (result == BACKUP_CAPTURE_OK &&
        metadata_apply_ownership_and_mode_fd(child_fd, &source_snapshot) != 0)
        result = BACKUP_CAPTURE_ERROR;
    if (result == BACKUP_CAPTURE_OK && collect_xattrs(source_fd, &xattrs) != 0)
        result = BACKUP_CAPTURE_ERROR;
    struct stat after;
    if (result == BACKUP_CAPTURE_OK &&
        (fstat(source_fd, &after) != 0 ||
         !metadata_source_unchanged(&source_snapshot, &after)))
        result = BACKUP_CAPTURE_ERROR;
    if (result == BACKUP_CAPTURE_OK &&
        metadata_apply_xattrs_fd(child_fd, xattrs.items, xattrs.count) != 0)
        result = BACKUP_CAPTURE_ERROR;
    if (result == BACKUP_CAPTURE_OK &&
        metadata_apply_times_fd(child_fd, &source_snapshot,
                                metadata_policy_from_context(ctx)) != 0)
        result = BACKUP_CAPTURE_ERROR;
    xattrs_free(&xattrs);
    if (close(source_fd) != 0)
    {
        if (result == BACKUP_CAPTURE_OK)
            result = BACKUP_CAPTURE_ERROR;
    }
    if (close(child_fd) != 0)
    {
        if (result == BACKUP_CAPTURE_OK)
            result = BACKUP_CAPTURE_ERROR;
    }
    return result;
}

// Recreate the node itself, never its contents: reading a FIFO blocks until a
// writer appears, which would hang the whole backup. An existing FIFO at this
// address is accepted so an interrupted backup can resume past it.
static int capture_fifo_at(const CloneContext *ctx, int dest_dir_fd,
                           const char *leaf, const struct stat *st)
{
    if (mkfifoat(dest_dir_fd, leaf, st->st_mode & 07777) != 0)
    {
        struct stat dest_st;
        if (errno != EEXIST ||
            fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISFIFO(dest_st.st_mode))
            return -1;
    }

    // O_RDONLY | O_NONBLOCK is the one way to open a FIFO that returns
    // immediately with no writer on the other end. The fd is opened purely so
    // the metadata below goes through an fd like every other type here, rather
    // than through a path a swap could redirect.
    int fifo_fd = openat(dest_dir_fd, leaf,
                         O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fifo_fd < 0)
        return -1;

    struct stat opened;
    int failed = fstat(fifo_fd, &opened) != 0 || !S_ISFIFO(opened.st_mode) ||
                 metadata_apply_fd(fifo_fd, st,
                                    metadata_policy_from_context(ctx)) != 0;
    if (close(fifo_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static BackupCaptureStatus capture_entry_at(const CloneContext *ctx,
                                            const char *src,
                                            int dest_dir_fd, const char *leaf,
                                            const char *root_key,
                                            const char *rel_path,
                                            BackupCaptureReport *report)
{
    struct stat st;
    if (lstat(src, &st) != 0)
        return BACKUP_CAPTURE_ERROR;

    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
    BackupCaptureStatus status;
    int trackable = 1;
    if (S_ISLNK(st.st_mode))
        status = capture_symlink_at(src, dest_dir_fd, leaf, &st, policy);
    else if (S_ISREG(st.st_mode))
        status = capture_regular_at(ctx, src, dest_dir_fd, leaf, &st, report);
    else if (S_ISDIR(st.st_mode))
        status = capture_directory_at(ctx, src, dest_dir_fd, leaf, &st,
                                      root_key, rel_path, report);
    else if (S_ISFIFO(st.st_mode))
        status = capture_fifo_at(ctx, dest_dir_fd, leaf, &st);
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
        return BACKUP_CAPTURE_ERROR;

    if (status == BACKUP_CAPTURE_OK && trackable && ctx->visited != NULL &&
        native_visited_add(ctx->visited, root_key, rel_path) < 0)
        return BACKUP_CAPTURE_ERROR;

    return status;
}

void backup_capture_report_init(BackupCaptureReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

BackupCaptureStatus backup_capture_at_report(
    const CloneContext *ctx, const char *source_path,
    int destination_root_fd, const char *destination_leaf,
    BackupCaptureReport *report)
{
    backup_capture_report_init(report);
    return backup_capture_at_report_continue(ctx, source_path,
                                             destination_root_fd,
                                             destination_leaf, report);
}

BackupCaptureStatus backup_capture_at_report_continue(
    const CloneContext *ctx, const char *source_path,
    int destination_root_fd, const char *destination_leaf,
    BackupCaptureReport *report)
{
    // Fail closed on a mis-dispatched context rather than running a native clone blindly:
    // a wrong direction or an unimplemented representation must not silently produce a
    // native tree where a sidecar was required.
    if (ctx == NULL || ctx->operation != CLONE_BACKUP ||
        ctx->representation != CLONE_NATIVE_TREE)
        return BACKUP_CAPTURE_ERROR;
    if (source_path == NULL || destination_root_fd < 0 ||
        !destination_leaf_is_safe(destination_leaf))
        return BACKUP_CAPTURE_ERROR;

    return capture_entry_at(ctx, source_path, destination_root_fd,
                            destination_leaf, destination_leaf, "", report);
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
        size_t capacity = list->capacity == 0 ? 16U : list->capacity * 2U;
        if (capacity < list->capacity ||
            capacity > SIZE_MAX / sizeof(*list->items))
            return -1;
        char **items = realloc(list->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        list->items = items;
        list->capacity = capacity;
    }
    char *copy = strdup(rel_path);
    if (copy == NULL)
        return -1;
    list->items[list->count++] = copy;
    return 0;
}

static int native_reconcile_scan_node(const void *visited,
                                      const char *root_key, int parent_fd,
                                      const char *leaf, const char *rel_path,
                                      NativeStaleList *stale)
{
    int contains = native_visited_contains(visited, root_key, rel_path);
    if (contains < 0)
        return -1;
    if (contains == 0)
        return native_stale_list_append(stale, rel_path);

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (!S_ISDIR(st.st_mode))
        return 0;

    int child_fd = openat(parent_fd, leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_fd < 0)
        return -1;
    int scan_fd = fcntl(child_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
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
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_rel[PATH_MAX];
        if (append_relative(child_rel, sizeof(child_rel), rel_path,
                            entry->d_name) != 0 ||
            native_reconcile_scan_node(visited, root_key, child_fd,
                                       entry->d_name, child_rel, stale) != 0)
        {
            failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
        failed = 1;
    if (close(child_fd) != 0)
        failed = 1;
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
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
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
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (native_remove_leaf(directory_fd, entry->d_name) != 0)
        {
            failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    if (failed)
        return -1;
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
    if (root_fd < 0 || rel_path == NULL || rel_path[0] == '\0' ||
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

void native_reconcile_report_init(NativeReconcileReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

NativeReconcileStatus native_reconcile_stale_at(const void *visited,
                                                const char *root_key,
                                                int data_fd,
                                                NativeReconcileReport *report)
{
    native_reconcile_report_init(report);
    if (visited == NULL || root_key == NULL || data_fd < 0)
        return NATIVE_RECONCILE_ERROR;

    int root_visited = native_visited_contains(visited, root_key, "");
    if (root_visited < 0)
        return NATIVE_RECONCILE_ERROR;

    struct stat root_st;
    if (fstatat(data_fd, root_key, &root_st, AT_SYMLINK_NOFOLLOW) != 0)
        return NATIVE_RECONCILE_ERROR;
    if (root_visited == 0)
    {
        if (native_remove_leaf(data_fd, root_key) == 0)
            return NATIVE_RECONCILE_OK;
        if (report != NULL)
            (void)snprintf(report->failed_relative_path,
                           sizeof(report->failed_relative_path), "%s",
                           root_key);
        return NATIVE_RECONCILE_ERROR;
    }
    if (!S_ISDIR(root_st.st_mode))
        return NATIVE_RECONCILE_OK;

    int root_fd = openat(data_fd, root_key,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0)
        return NATIVE_RECONCILE_ERROR;
    int scan_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
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
                scan_failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (native_reconcile_scan_node(visited, root_key, root_fd,
                                       entry->d_name, entry->d_name,
                                       &stale) != 0)
        {
            scan_failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
        scan_failed = 1;

    NativeReconcileStatus result = NATIVE_RECONCILE_OK;
    if (scan_failed)
        result = NATIVE_RECONCILE_ERROR;
    else
    {
        for (size_t index = 0; index < stale.count; index++)
        {
            int parent_fd = -1;
            char leaf[NAME_MAX + 1U];
            int open_result = native_open_relative_parent(
                root_fd, stale.items[index], &parent_fd, leaf, sizeof(leaf));
            int remove_result;
            if (open_result == 0)
                remove_result = native_remove_leaf(parent_fd, leaf);
            else
                remove_result = errno == ENOENT ? 0 : -1;
            if (open_result != 0 || remove_result != 0)
            {
                result = NATIVE_RECONCILE_ERROR;
                if (report != NULL && report->failed_relative_path[0] == '\0')
                    (void)snprintf(report->failed_relative_path,
                                   sizeof(report->failed_relative_path), "%s",
                                   stale.items[index]);
            }
            if (parent_fd >= 0 && close(parent_fd) != 0)
                result = NATIVE_RECONCILE_ERROR;
        }
    }

    native_stale_list_free(&stale);
    if (close(root_fd) != 0)
        result = NATIVE_RECONCILE_ERROR;
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
    RESTORE_RESOLVE_ERROR = -1,
    RESTORE_RESOLVE_MISSING = 0,
    RESTORE_RESOLVE_OK = 1
} RestoreResolveResult;

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

static void restore_report_failure(RestoreNativeReport *report,
                                   const char *logical_path)
{
    if (report == NULL)
        return;
    if (report->failed_count != SIZE_MAX)
        report->failed_count++;
    if (report->failed_count != 1 || logical_path == NULL)
        return;
    (void)snprintf(report->failed_logical_path,
                   sizeof(report->failed_logical_path), "%s", logical_path);
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

static int same_object(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
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
            if (mkdirat(cur_fd, comp, 0700) != 0 && errno != EEXIST)
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
    if (fstat(fd, opened_st) != 0 || !S_ISREG(opened_st->st_mode) ||
        !same_object(object_st, opened_st))
    {
        close(fd);
        return SOURCE_OPEN_ERROR;
    }
    *out_fd = fd;
    return SOURCE_OPEN_OK;
}

static int open_destination_regular(int dest_parent_fd, const char *dest_leaf,
                                    mode_t mode, struct stat *opened_st,
                                    int *created)
{
    *created = 0;
    for (int attempt = 0; attempt < 2; attempt++)
    {
        int fd = openat(dest_parent_fd, dest_leaf,
                        O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0)
        {
            if (fstat(fd, opened_st) == 0 && S_ISREG(opened_st->st_mode))
                return fd;
            close(fd);
            return -1;
        }
        if (errno != ENOENT)
            return -1;

        fd = openat(dest_parent_fd, dest_leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NONBLOCK |
                    O_NOFOLLOW | O_CLOEXEC, mode);
        if (fd >= 0)
        {
            if (fstat(fd, opened_st) == 0 && S_ISREG(opened_st->st_mode))
            {
                *created = 1;
                return fd;
            }
            close(fd);
            return -1;
        }
        if (errno != EEXIST)
            return -1;
    }
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
    if (fstat(fd, opened_st) != 0 || !S_ISDIR(opened_st->st_mode) ||
        !same_object(object_st, opened_st))
    {
        close(fd);
        return SOURCE_OPEN_ERROR;
    }
    *out_fd = fd;
    return SOURCE_OPEN_OK;
}

static int open_destination_directory(RestorePass pass,
                                      int dest_parent_fd, const char *dest_leaf)
{
    if (dest_parent_fd < 0)
        return pass == RESTORE_VALIDATE ? -2 : -1;
    if (dest_leaf[0] == '\0')
    {
        int fd = fcntl(dest_parent_fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0 || !fd_is_directory(fd))
        {
            if (fd >= 0)
                close(fd);
            return -1;
        }
        return fd;
    }

    int fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0)
        return fd;
    if (errno != ENOENT)
        return -1;
    if (pass == RESTORE_VALIDATE)
        return -2;

    if (mkdirat(dest_parent_fd, dest_leaf, 0700) != 0 && errno != EEXIST)
        return -1;
    return openat(dest_parent_fd, dest_leaf,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

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
        return -1;
    if (fstat(fd, opened_st) == 0 && S_ISFIFO(opened_st->st_mode))
        return fd;
    close(fd);
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
    int failed = 0;
    struct stat source_after;
    if (fstat(source_fd, &source_after) != 0 ||
        !metadata_source_unchanged(desired_st, &source_after))
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;

    struct stat representative;
    if (!failed &&
        (fstatat(representative_parent_fd, representative_leaf,
                 &representative, AT_SYMLINK_NOFOLLOW) != 0 ||
         !S_ISREG(representative.st_mode)))
        failed = 1;

    if (!failed)
    {
        struct stat existing;
        if (fstatat(destination_parent_fd, destination_leaf, &existing,
                    AT_SYMLINK_NOFOLLOW) == 0)
        {
            if (!native_hardlink_identity_matches(&existing, &representative))
                failed = 1;
        }
        else if (errno == ENOENT)
        {
            if (linkat(representative_parent_fd, representative_leaf,
                       destination_parent_fd, destination_leaf, 0) != 0)
                failed = 1;
            else
            {
                struct stat linked;
                if (fstatat(destination_parent_fd, destination_leaf, &linked,
                            AT_SYMLINK_NOFOLLOW) != 0 ||
                    !native_hardlink_identity_matches(&linked,
                                                      &representative))
                    failed = 1;
            }
        }
        else
            failed = 1;
    }

    if (failed)
    {
        restore_report_failure(restore_report, logical_path);
        return RESTORE_NATIVE_ERROR;
    }
    restore_report_applied(restore_report);
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
    MetadataProfiles *profiles, MetadataXattrRequirements *xattr_requirements,
    int metadata_anchor_fd,
    int skip_symlink_target_read,
    RestoreNativeReport *restore_report)
{
    int source_is_root = source_leaf[0] == '\0';
    int dest_is_root = dest_leaf[0] == '\0';

    struct stat source_st;
    int source_object_fd = open_source_object(source_parent_fd, source_leaf,
                                               &source_st);
    if (source_object_fd < 0)
        return -1;

    struct stat dest_st;
    int dest_exists;
    if (destination_status(dest_parent_fd, dest_leaf, &dest_st,
                           &dest_exists) != 0)
    {
        close(source_object_fd);
        return -1;
    }
    if (dest_exists && S_ISLNK(dest_st.st_mode))
    {
        close(source_object_fd);
        return -1;
    }

    struct stat desired_st = source_st;
    if (pass == RESTORE_VALIDATE)
    {
        if (metadata_snapshot_record(snapshots, &source_st) != 0)
        {
            close(source_object_fd);
            return -1;
        }
        // One profile anchor governs the whole restore root.  It is the
        // actual destination root when that directory exists, otherwise the
        // nearest existing parent chosen before the walk began.  Descending
        // into payload directories must not turn each child directory into a
        // new probe domain: ACLs and access policy may differ between roots,
        // but the plan deliberately bounds profiles by restore roots.
        int profile_failed = profiles != NULL && metadata_anchor_fd < 0;
        if (!profile_failed && profiles != NULL &&
            !S_ISSOCK(source_st.st_mode) &&
            !S_ISCHR(source_st.st_mode) &&
            !S_ISBLK(source_st.st_mode) &&
            metadata_profiles_add(profiles, metadata_anchor_fd, &source_st,
                                  dest_exists ? &dest_st : NULL,
                                  logical_path) != 0)
            profile_failed = 1;
        if (profile_failed)
        {
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
            close(source_object_fd);
            return -1;
        }
    }

    if (S_ISLNK(source_st.st_mode))
    {
        if (source_is_root || dest_is_root || dest_exists)
        {
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
                close(source_object_fd);
                return -1;
            }
            if (xattr_requirements != NULL)
                xattr_requirements->symlink_namespaces |= namespaces;
            if (profiles != NULL &&
                (namespaces & METADATA_XATTR_NS_SECURITY) != 0)
                metadata_profiles_note_security_xattr(profiles);
        }

        if (pass == RESTORE_VALIDATE && skip_symlink_target_read)
        {
            close(source_object_fd);
            return RESTORE_NATIVE_OK;
        }

        char target[PATH_MAX];
        ssize_t len = readlinkat(source_parent_fd, source_leaf,
                                 target, sizeof(target) - 1);
        if (len < 0 || (size_t)len == sizeof(target) - 1)
        {
            close(source_object_fd);
            return -1;
        }
        struct stat after;
        if (fstatat(source_parent_fd, source_leaf, &after,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !metadata_symlink_unchanged(&desired_st, &after))
        {
            close(source_object_fd);
            return -1;
        }
        close(source_object_fd);
        if (pass == RESTORE_VALIDATE)
            return RESTORE_NATIVE_OK;

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
            xattrs_free(&xattrs);
            return RESTORE_NATIVE_ERROR;
        }
        if (symlinkat(target, dest_parent_fd, dest_leaf) != 0)
        {
            xattrs_free(&xattrs);
            return -1;
        }
        failed = metadata_apply_symlink_ownership_at(dest_parent_fd, dest_leaf,
                                                     &desired_st) != 0;
        if (!failed)
        {
            size_t skipped_security = 0;
            int xattr_result = metadata_apply_xattrs_symlink_at_report(
                dest_parent_fd, dest_leaf, xattrs.items, xattrs.count,
                &skipped_security);
            restore_report_security_skipped(restore_report, skipped_security);
            if (xattr_result != 0)
                failed = 1;
        }
        if (!failed &&
            metadata_apply_symlink_times_at(
                dest_parent_fd, dest_leaf, &desired_st,
                metadata_policy_from_context(ctx)) != 0)
            failed = 1;
        xattrs_free(&xattrs);
        if (!failed)
            restore_report_applied(restore_report);
        else
            restore_report_failure(restore_report, logical_path);
        return failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
    }

    if (S_ISREG(source_st.st_mode))
    {
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISREG(dest_st.st_mode)))
        {
            close(source_object_fd);
            return -1;
        }

        struct stat opened_source_st;
        int src_fd;
        SourceOpenStatus source_status = open_source_regular(
            pass, source_parent_fd, source_leaf, &source_st, &opened_source_st,
            &src_fd);
        close(source_object_fd);
        if (source_status == SOURCE_OPEN_SAFE_READ)
        {
            restore_report_failure(restore_report, logical_path);
            return RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (source_status != SOURCE_OPEN_OK ||
            !metadata_source_unchanged(&desired_st, &opened_source_st))
        {
            if (src_fd >= 0)
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
                    close(src_fd);
                    return RESTORE_NATIVE_ERROR;
                }
                if (xattr_requirements != NULL)
                    xattr_requirements->regular_namespaces |= namespaces;
                if (profiles != NULL &&
                    (namespaces & METADATA_XATTR_NS_SECURITY) != 0)
                    metadata_profiles_note_security_xattr(profiles);
            }
            return close(src_fd) == 0 ? RESTORE_NATIVE_OK : RESTORE_NATIVE_ERROR;
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
                close(src_fd);
                restore_report_failure(restore_report, logical_path);
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
            close(src_fd);
            return -1;
        }
        MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
        int content_skip = !dest_created &&
            opened_dest_st.st_size == desired_st.st_size &&
            opened_dest_st.st_mtim.tv_sec == desired_st.st_mtim.tv_sec &&
            policy.nsec_exact &&
            opened_dest_st.st_mtim.tv_nsec == desired_st.st_mtim.tv_nsec;
        if (content_skip)
        {
            int failed = metadata_apply_ownership_and_mode_fd(dst_fd,
                                                               &desired_st) != 0;
            PortableXattrs xattrs = {0};
            if (!failed && collect_xattrs(src_fd, &xattrs) != 0)
                failed = 1;
            struct stat after;
            if (!failed && (fstat(src_fd, &after) != 0 ||
                            !metadata_source_unchanged(&desired_st, &after)))
                failed = 1;
            if (!failed)
            {
                size_t skipped_security = 0;
                int xattr_result = metadata_apply_xattrs_fd_report(
                    dst_fd, xattrs.items, xattrs.count, &skipped_security);
                restore_report_security_skipped(restore_report,
                                                skipped_security);
                if (xattr_result != 0)
                    failed = 1;
            }
            if (!failed && metadata_apply_times_fd(dst_fd, &desired_st,
                                                   policy) != 0)
                failed = 1;
            xattrs_free(&xattrs);
            if (close(src_fd) != 0)
                failed = 1;
            if (close(dst_fd) != 0)
                failed = 1;
            if (!failed && ctx->inode_map != NULL &&
                opened_source_st.st_nlink > 1 &&
                native_inode_map_insert(ctx->inode_map,
                                        opened_source_st.st_dev,
                                        opened_source_st.st_ino,
                                        dest_parent_fd, dest_leaf) != 0)
                failed = 1;
            if (!failed && pass == RESTORE_APPLY)
            {
                restore_report_applied(restore_report);
                restore_native_test_after_apply(logical_path);
            }
            else if (failed && pass == RESTORE_APPLY)
                restore_report_failure(restore_report, logical_path);
            return failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
        }
        if (ftruncate(dst_fd, 0) != 0)
        {
            close(src_fd);
            close(dst_fd);
            return -1;
        }

        char buffer[8192];
        int failed = 0;
        for (;;)
        {
            ssize_t bytes_read = read(src_fd, buffer, sizeof(buffer));
            if (bytes_read == 0)
                break;
            if (bytes_read < 0)
            {
                failed = 1;
                break;
            }

            ssize_t written = 0;
            while (written < bytes_read)
            {
                ssize_t res = write(dst_fd, buffer + written, bytes_read - written);
                if (res <= 0)
                {
                    failed = 1;
                    break;
                }
                written += res;
            }
            if (failed)
                break;
        }

        PortableXattrs xattrs = {0};
        if (!failed &&
            metadata_apply_ownership_and_mode_fd(dst_fd, &desired_st) != 0)
            failed = 1;
        // collect_xattrs() reads the payload's *current* xattrs -- unlike
        // desired_st (a snapshot from an earlier pass), there is no
        // pre-recorded xattr set to fall back on, so this read must fall
        // inside the same before/after window the content copy above is
        // already verified against, not after it.
        if (!failed && collect_xattrs(src_fd, &xattrs) != 0)
            failed = 1;
        if (!failed)
        {
            struct stat after;
            if (fstat(src_fd, &after) != 0 ||
                !metadata_source_unchanged(&desired_st, &after))
                failed = 1;
        }
        if (!failed)
        {
            size_t skipped_security = 0;
            int xattr_result = metadata_apply_xattrs_fd_report(
                dst_fd, xattrs.items, xattrs.count, &skipped_security);
            restore_report_security_skipped(restore_report, skipped_security);
            if (xattr_result != 0)
                failed = 1;
        }
        if (!failed && metadata_apply_times_fd(dst_fd, &desired_st, policy) != 0)
            failed = 1;
        xattrs_free(&xattrs);

        if (close(src_fd) != 0)
            failed = 1;
        if (close(dst_fd) != 0)
            failed = 1;
        if (!failed && ctx->inode_map != NULL &&
            opened_source_st.st_nlink > 1 &&
            native_inode_map_insert(ctx->inode_map, opened_source_st.st_dev,
                                    opened_source_st.st_ino,
                                    dest_parent_fd, dest_leaf) != 0)
            failed = 1;
        if (!failed && pass == RESTORE_APPLY)
        {
            restore_report_applied(restore_report);
            restore_native_test_after_apply(logical_path);
        }
        else if (failed && pass == RESTORE_APPLY)
            restore_report_failure(restore_report, logical_path);
        return failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
    }

    if (S_ISDIR(source_st.st_mode))
    {
        if (dest_exists && !S_ISDIR(dest_st.st_mode))
        {
            close(source_object_fd);
            return -1;
        }

        struct stat opened_source_st;
        int source_dir_fd;
        SourceOpenStatus source_status = open_source_directory(
            pass, source_object_fd, &source_st, &opened_source_st,
            &source_dir_fd);
        close(source_object_fd);
        if (source_status == SOURCE_OPEN_SAFE_READ)
        {
            restore_report_failure(restore_report, logical_path);
            return RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (source_status != SOURCE_OPEN_OK ||
            !metadata_source_unchanged(&desired_st, &opened_source_st))
        {
            if (source_dir_fd >= 0)
                close(source_dir_fd);
            return RESTORE_NATIVE_ERROR;
        }

        if (pass == RESTORE_VALIDATE &&
            (profiles != NULL || xattr_requirements != NULL))
        {
            unsigned int namespaces = 0;
            if (metadata_xattr_namespaces_fd(source_dir_fd, &namespaces) != 0)
            {
                close(source_dir_fd);
                return RESTORE_NATIVE_ERROR;
            }
            if (xattr_requirements != NULL)
                xattr_requirements->directory_namespaces |= namespaces;
            if (profiles != NULL &&
                (namespaces & METADATA_XATTR_NS_SECURITY) != 0)
                metadata_profiles_note_security_xattr(profiles);
        }

        int dest_dir_fd = open_destination_directory(pass, dest_parent_fd,
                                                     dest_leaf);
        if (dest_dir_fd == -1)
        {
            close(source_dir_fd);
            return -1;
        }
        if (dest_dir_fd == -2)
            dest_dir_fd = -1;

        int scan_fd = fcntl(source_dir_fd, F_DUPFD_CLOEXEC, 0);
        DIR *dirp = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (dirp == NULL)
        {
            if (scan_fd >= 0)
                close(scan_fd);
            close(source_dir_fd);
            if (dest_dir_fd >= 0)
                close(dest_dir_fd);
            return -1;
        }

        int failed = 0;
        RestoreNativeStatus subtree_status = RESTORE_NATIVE_OK;
        for (;;)
        {
            errno = 0;
            struct dirent *entry = readdir(dirp);
            if (entry == NULL)
            {
                if (errno != 0)
                    failed = 1;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            char child_logical_path[PATH_MAX];
            metadata_child_path(logical_path, entry->d_name,
                                child_logical_path);
            RestoreNativeStatus child_status = restore_entry_at(
                ctx, pass, source_dir_fd, entry->d_name, dest_dir_fd,
                entry->d_name, child_logical_path, snapshots, profiles,
                xattr_requirements, metadata_anchor_fd,
                skip_symlink_target_read, restore_report);
            if (child_status != RESTORE_NATIVE_OK)
            {
                failed = 1;
                subtree_status = child_status;
                break;
            }
        }
        if (closedir(dirp) != 0)
            failed = 1;

        if (!failed && pass == RESTORE_APPLY)
        {
            PortableXattrs xattrs = {0};
            if (!failed &&
                metadata_apply_ownership_and_mode_fd(dest_dir_fd,
                                                      &desired_st) != 0)
                failed = 1;
            // collect_xattrs() reads the payload's *current* xattrs -- unlike
            // desired_st (a snapshot from an earlier pass), there is no
            // pre-recorded xattr set to fall back on, so this read must fall
            // inside the same before/after window the subtree walk above is
            // already verified against, not after it.
            if (!failed && collect_xattrs(source_dir_fd, &xattrs) != 0)
                failed = 1;
            struct stat after;
            if (!failed && (fstat(source_dir_fd, &after) != 0 ||
                            !metadata_source_unchanged(&desired_st, &after)))
                failed = 1;
            if (!failed)
            {
                size_t skipped_security = 0;
                int xattr_result = metadata_apply_xattrs_fd_report(
                    dest_dir_fd, xattrs.items, xattrs.count,
                    &skipped_security);
                restore_report_security_skipped(restore_report,
                                                skipped_security);
                if (xattr_result != 0)
                    failed = 1;
            }
            if (!failed &&
                metadata_apply_times_fd(dest_dir_fd, &desired_st,
                                        metadata_policy_from_context(ctx)) != 0)
                failed = 1;
            xattrs_free(&xattrs);
        }

        close(source_dir_fd);
        if (dest_dir_fd >= 0)
            close(dest_dir_fd);
        if (!failed && pass == RESTORE_APPLY)
            restore_report_applied(restore_report);
        else if (failed && pass == RESTORE_APPLY &&
                 subtree_status == RESTORE_NATIVE_OK)
            restore_report_failure(restore_report, logical_path);
        if (failed && subtree_status == RESTORE_NATIVE_OK)
            subtree_status = RESTORE_NATIVE_ERROR;
        return failed ? subtree_status : RESTORE_NATIVE_OK;
    }

    if (S_ISFIFO(source_st.st_mode))
    {
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISFIFO(dest_st.st_mode)))
        {
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
            return -1;
        int failed = metadata_apply_fd(dest_fd, &desired_st,
                                       metadata_policy_from_context(ctx)) != 0;
        if (close(dest_fd) != 0)
            failed = 1;
        if (!failed)
            restore_report_applied(restore_report);
        else
            restore_report_failure(restore_report, logical_path);
        return failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
    }

    if (S_ISSOCK(source_st.st_mode))
    {
        close(source_object_fd);
        if (pass == RESTORE_APPLY)
            print_warning("  Warning: skipping socket (runtime-only)%s%s\n",
                          source_leaf[0] ? ": " : "", source_leaf);
        return RESTORE_NATIVE_OK;
    }
    if (S_ISCHR(source_st.st_mode) || S_ISBLK(source_st.st_mode))
    {
        close(source_object_fd);
        if (pass == RESTORE_APPLY)
            print_warning("  Warning: skipping %s device node%s%s\n",
                          S_ISCHR(source_st.st_mode) ? "character" : "block",
                          source_leaf[0] ? ": " : "", source_leaf);
        return RESTORE_NATIVE_OK;
    }

    close(source_object_fd);
    return -1;
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
        !fd_is_directory(source_root_fd))
        return RESTORE_SOURCE_ERROR;
    if (source_rel[0] != '\0' && !relative_path_is_safe(source_rel))
        return RESTORE_SOURCE_ERROR;

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
    return saved_errno == ENOENT
        ? RESTORE_SOURCE_MISSING
        : RESTORE_SOURCE_ERROR;
}

RestoreNativeStatus restore_native_preflight_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel)
{
    if (!restore_arguments_valid(ctx, source_root_fd, source_rel,
                                 destination_root_fd, destination_rel))
        return -1;

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    if (resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf)) != RESTORE_RESOLVE_OK)
        return -1;

    int dest_parent_fd = -1;
    char dest_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult dest_result =
        resolve_parent(destination_root_fd, destination_rel, 0,
                       &dest_parent_fd, dest_leaf, sizeof(dest_leaf));
    if (dest_result == RESTORE_RESOLVE_ERROR)
    {
        close(source_parent_fd);
        return -1;
    }

    MetadataSnapshots snapshots;
    MetadataProfiles profiles;
    metadata_snapshots_init(&snapshots);
    metadata_profiles_init(&profiles);
    int metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (metadata_anchor_fd < 0)
    {
        close(source_parent_fd);
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        metadata_snapshots_free(&snapshots);
        metadata_profiles_free(&profiles);
        return -1;
    }
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, &profiles,
                              NULL, metadata_anchor_fd, 0, NULL);
    close(metadata_anchor_fd);
    close(source_parent_fd);
    if (dest_parent_fd >= 0)
        close(dest_parent_fd);
    metadata_snapshots_free(&snapshots);
    metadata_profiles_free(&profiles);
    return rc;
}

RestoreNativeStatus restore_native_metadata_inventory_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    MetadataProfiles *profiles)
{
    if (profiles == NULL || !restore_arguments_valid(ctx, source_root_fd,
                                                     source_rel,
                                                     destination_root_fd,
                                                     destination_rel))
        return -1;

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    if (resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf)) != RESTORE_RESOLVE_OK)
        return -1;

    int dest_parent_fd = -1;
    char dest_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult dest_result =
        resolve_parent(destination_root_fd, destination_rel, 0,
                       &dest_parent_fd, dest_leaf, sizeof(dest_leaf));
    if (dest_result == RESTORE_RESOLVE_ERROR)
    {
        close(source_parent_fd);
        return -1;
    }

    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);
    int metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (metadata_anchor_fd < 0)
    {
        close(source_parent_fd);
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        metadata_snapshots_free(&snapshots);
        return -1;
    }
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, profiles,
                              NULL, metadata_anchor_fd, 1, NULL);
    close(metadata_anchor_fd);
    close(source_parent_fd);
    if (dest_parent_fd >= 0)
        close(dest_parent_fd);
    metadata_snapshots_free(&snapshots);
    return rc;
}

void restore_native_report_init(RestoreNativeReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

RestoreNativeStatus restore_native_at_report(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    RestoreNativeReport *report)
{
    RestoreNativeReport local_report;
    if (report == NULL)
    {
        restore_native_report_init(&local_report);
        report = &local_report;
    }
    else
        restore_native_report_init(report);

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    if (!restore_arguments_valid(ctx, source_root_fd, source_rel,
                                 destination_root_fd, destination_rel) ||
        resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf)) != RESTORE_RESOLVE_OK)
        return -1;

    int dest_parent_fd = -1;
    char dest_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult dest_result =
        resolve_parent(destination_root_fd, destination_rel, 0,
                       &dest_parent_fd, dest_leaf,
                       sizeof(dest_leaf));
    if (dest_result == RESTORE_RESOLVE_ERROR)
    {
        close(source_parent_fd);
        return -1;
    }

    MetadataSnapshots snapshots;
    MetadataProfiles profiles;
    MetadataXattrRequirements xattr_requirements = {0};
    metadata_snapshots_init(&snapshots);
    metadata_profiles_init(&profiles);
    int metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (metadata_anchor_fd < 0)
    {
        close(source_parent_fd);
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        metadata_snapshots_free(&snapshots);
        metadata_profiles_free(&profiles);
        return -1;
    }
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, &profiles,
                              &xattr_requirements, metadata_anchor_fd, 0,
                              report);
    if (rc == 0 && !ctx->metadata_preflight_done &&
        metadata_profiles_probe(&profiles,
                                metadata_policy_from_context(ctx)) != 0)
        rc = -1;
    if (rc == 0 && !ctx->metadata_preflight_done &&
        metadata_xattr_capability_probe(metadata_anchor_fd,
                                        &xattr_requirements) != 0)
        rc = -1;
    close(metadata_anchor_fd);

    if (rc == 0)
    {
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        dest_parent_fd = -1;
        dest_result = resolve_parent(destination_root_fd, destination_rel, 1,
                                     &dest_parent_fd, dest_leaf,
                                     sizeof(dest_leaf));
        if (dest_result != RESTORE_RESOLVE_OK)
            rc = -1;
    }
    if (rc == 0)
        rc = restore_entry_at(ctx, RESTORE_APPLY, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, NULL,
                              NULL, destination_root_fd, 0, report);
    if (rc != RESTORE_NATIVE_OK && report->failed_count == 0)
        restore_report_failure(report, source_rel);
    close(source_parent_fd);
    if (dest_parent_fd >= 0)
        close(dest_parent_fd);
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
                                    NULL);
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
        while ((entry = readdir(dir)) != NULL)
        {
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

        closedir(dir);
        return 0;
    }

    return -1; // unknown file type (unreachable on Linux); refuse defensively
}

int run_command(char *const argv[])
{
    pid_t pid = fork();

    if (pid == -1)
    {
        return -1; // fork failed
    }
    else if (pid == 0)
    {
        // Child process
        execvp(argv[0], argv);
        
        // If execvp returns, it means it failed
        perror("execvp");
        _exit(1); // _exit() is used to exit immediately since we're in a child process. 
                  // exit() could've caused issues because it might flush stdio buffers that are shared with the parent process.
    }
    else 
    {
        // Parent process
        int status;

        // Wait for the child process to finish so it won't become a zombie process
        if (waitpid(pid, &status, 0) == -1)
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

int run_command_capture(char *const argv[], char *output, size_t output_size)
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        return -1; // pipe creation failed
    }

    pid_t pid = fork();
    if (pid == -1)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1; // fork failed
    }
    else if (pid == 0)
    {
        // Child process
        close(pipefd[0]); // Close the read end of the pipe
        
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to the write end of the pipe
        close(pipefd[1]); // Close the original write end of the pipe
        
        execvp(argv[0], argv); // Execute the command

        // If execvp returns, it means it failed
        perror("execvp");
        _exit(1); // Exit immediately since we're in a child process
    }
    else
    {
        // Parent process
        close(pipefd[1]); // Close the write end of the pipe

        size_t total = 0;
        ssize_t bytes_read;
        while ((bytes_read = read(pipefd[0], output + total, output_size - total - 1)) > 0)
        {
            total += bytes_read;
        }
        output[total] = '\0'; // Null-terminate the output string

        close(pipefd[0]); // Close the read end of the pipe
        int status;
        waitpid(pid, &status, 0); // Wait for the child process to finish
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status); // Return the exit status of the child process
        }
    }
    return -1; // should not reach here
}
