#define _GNU_SOURCE

#include "portable_restore_internal.h"
#include "portable_restore_replay_internal.h"
#include "portable_restore.h"
#include "backup.h"
#include "manifest.h"
#include "metadata.h"
#include "portable.h"
#include "sidecar.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    const SidecarEntry *entry;
    const SidecarXattr *xattrs;
    size_t xattr_count;
    size_t root_index;
    size_t hardlink_ref_root_index;
    char destination[PATH_MAX];
    char destination_relative[PATH_MAX];
    char hardlink_ref_relative[PATH_MAX];
    size_t depth;
} ReplayEntry;

typedef struct {
    ReplayEntry *items;
    size_t count;
    size_t capacity;
    PreflightMemory memory;
    const Manifest *manifest;
    RootMap root_map;
    ParentMap parent_map; /* Parent-prefix validation consumes this (D21). */
    const SidecarLog *sidecar;
    int data_fd;
    int destination_home_fd;
    const char * const *destination_xdg_dirs;
    MetadataTimestampPolicy timestamp_policy;
    PortableRestoreReplayReport *report;
    BackupCaptureReport *capture_report;
    MetadataXattrRequirements xattr_requirements;
} ReplayCollection;

void replay_copy_bytes(char *destination, size_t destination_size,
                       SidecarBytes source)
{
    if (destination == NULL || destination_size == 0)
        return;
    if (source.length >= destination_size ||
        (source.length != 0 && source.data == NULL) ||
        (source.length != 0 &&
         memchr(source.data, '\0', source.length) != NULL))
    {
        destination[0] = '\0';
        return;
    }
    if (source.length != 0)
        memcpy(destination, source.data, source.length);
    destination[source.length] = '\0';
}

static void replay_report_failure(PortableRestoreReplayReport *report,
                                  const Manifest *manifest,
                                  size_t root_index,
                                  SidecarBytes logical)
{
    if (report == NULL)
        return;
    if (report->failed_count != SIZE_MAX)
        report->failed_count++;
    if (manifest != NULL && root_index < (size_t)manifest->root_count)
        snprintf(report->failed_root_id, sizeof(report->failed_root_id), "%s",
                 manifest->roots[root_index].id);
    replay_copy_bytes(report->failed_logical_path,
                      sizeof(report->failed_logical_path), logical);
}

static void replay_report_security_skipped(
    PortableRestoreReplayReport *report, size_t count)
{
    if (report == NULL || count == 0 ||
        report->skipped_security_xattr_count == SIZE_MAX)
        return;
    if (count > SIZE_MAX - report->skipped_security_xattr_count)
        report->skipped_security_xattr_count = SIZE_MAX;
    else
        report->skipped_security_xattr_count += count;
}

static int replay_entries_reserve(ReplayCollection *collection, size_t extra)
{
    if (collection == NULL || extra > SIDECAR_MAX_LIVE_ENTRIES -
                                   collection->count)
    {
        errno = E2BIG;
        return -1;
    }
    size_t needed = collection->count + extra;
    if (needed <= collection->capacity)
        return 0;
    size_t capacity = collection->capacity == 0 ? 16U :
        collection->capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > SIDECAR_MAX_LIVE_ENTRIES ||
        capacity > SIZE_MAX / sizeof(*collection->items))
    {
        errno = E2BIG;
        return -1;
    }
    size_t old_size = collection->capacity * sizeof(*collection->items);
    size_t new_size = capacity * sizeof(*collection->items);
    ReplayEntry *items = preflight_realloc(&collection->memory,
                                           collection->items,
                                           old_size, new_size);
    if (items == NULL)
        return -1;
    memset(items + collection->capacity, 0,
           (capacity - collection->capacity) * sizeof(*items));
    collection->items = items;
    collection->capacity = capacity;
    return 0;
}

static void replay_collection_free(ReplayCollection *collection)
{
    if (collection == NULL)
        return;
    preflight_free(&collection->memory, collection->items,
                   collection->capacity * sizeof(*collection->items));
    collection->items = NULL;
    collection->count = 0;
    collection->capacity = 0;
    parent_map_free(&collection->memory, &collection->parent_map);
    root_map_free(&collection->root_map);
}

static int replay_manifest_valid(const Manifest *manifest,
                                 const char * const *xdg_dirs)
{
    if (manifest == NULL || manifest->version != MANIFEST_CURRENT_VERSION ||
        manifest->representation != CLONE_PORTABLE_SIDECAR ||
        manifest->sidecar_version != SIDECAR_VERSION ||
        manifest->root_count < 0 || manifest->root_count > MANIFEST_MAX_ROOTS ||
        (manifest->root_count != 0 && manifest->roots == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    for (int index = 0; index < manifest->root_count; index++)
    {
        const ManifestRoot *root = &manifest->roots[index];
        if (!manifest_text_valid(root->id, sizeof(root->id), 1) ||
            !manifest_text_valid(root->payload_path,
                                 sizeof(root->payload_path), 1) ||
            !manifest_text_valid(root->source_path,
                                 sizeof(root->source_path), 0) ||
            !manifest_text_valid(root->restore_path,
                                 sizeof(root->restore_path), 0) ||
            !relative_path_valid(root->payload_path, 0) ||
            root->policy < ROOT_POLICY_XDG ||
            root->policy > ROOT_POLICY_MANUAL_NATIVE ||
            root->policy == ROOT_POLICY_MANUAL_NATIVE ||
            (root->policy == ROOT_POLICY_XDG &&
             !xdg_destination_valid(xdg_dirs, root)) ||
            (root->policy == ROOT_POLICY_HOME_RELATIVE &&
             (!root->has_restore_path ||
              !relative_path_valid(root->restore_path, 1))) ||
            (root->policy != ROOT_POLICY_HOME_RELATIVE &&
             root->has_restore_path))
        {
            errno = EINVAL;
            return -1;
        }
    }
    return 0;
}

int replay_entry_valid(const SidecarEntry *entry)
{
    if (entry == NULL ||
        (entry->kind != SIDECAR_KIND_REGULAR &&
         entry->kind != SIDECAR_KIND_DIRECTORY &&
         entry->kind != SIDECAR_KIND_SYMLINK &&
         entry->kind != SIDECAR_KIND_HARDLINK) ||
        (entry->kind != SIDECAR_KIND_REGULAR &&
         entry->kind != SIDECAR_KIND_DIRECTORY && entry->size != 0))
        return 0;
    if (entry->kind != SIDECAR_KIND_SYMLINK)
        return 1;
    return entry->symlink_target.data != NULL &&
           entry->symlink_target.length != 0 &&
           entry->symlink_target.length <= SIDECAR_MAX_SYMLINK_TARGET &&
           memchr(entry->symlink_target.data, '\0',
                  entry->symlink_target.length) == NULL;
}

int replay_stat_from_entry(const SidecarEntry *entry, struct stat *desired)
{
    if (entry == NULL || desired == NULL ||
        entry->mode > SIDECAR_MAX_MODE ||
        entry->atime_nsec > SIDECAR_MAX_NSEC ||
        entry->mtime_nsec > SIDECAR_MAX_NSEC ||
        entry->uid > SIDECAR_MAX_UID_GID ||
        entry->gid > SIDECAR_MAX_UID_GID)
    {
        errno = EINVAL;
        return -1;
    }

    memset(desired, 0, sizeof(*desired));
    mode_t type;
    if (sidecar_kind_to_type(entry->kind, &type) != 0)
        return -1;
    desired->st_mode = entry->mode | type;
    desired->st_uid = (uid_t)entry->uid;
    desired->st_gid = (gid_t)entry->gid;
    if ((uintmax_t)desired->st_uid != entry->uid ||
        (uintmax_t)desired->st_gid != entry->gid)
    {
        errno = EOVERFLOW;
        return -1;
    }
    desired->st_atim.tv_sec = (time_t)entry->atime_sec;
    desired->st_atim.tv_nsec = (long)entry->atime_nsec;
    desired->st_mtim.tv_sec = (time_t)entry->mtime_sec;
    desired->st_mtim.tv_nsec = (long)entry->mtime_nsec;
    if ((int64_t)desired->st_atim.tv_sec != entry->atime_sec ||
        (int64_t)desired->st_mtim.tv_sec != entry->mtime_sec)
    {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int replay_entry_compare(const void *left, const void *right)
{
    const ReplayEntry *a = left;
    const ReplayEntry *b = right;
    if (a->depth < b->depth)
        return -1;
    if (a->depth > b->depth)
        return 1;
    return strcmp(a->destination, b->destination);
}

static int replay_open_payload(int data_fd, const ManifestRoot *root,
                               const SidecarEntry *entry, int *out_fd,
                               struct stat *out_stat);

/* Confirms the on-disk placeholder for a symlink or hardlink entry is
 * exactly the convention both kinds share: an empty regular file
 * (docs/DECISIONS.md D18, D22). Deliberately reused for SIDECAR_KIND_HARDLINK
 * as well as SIDECAR_KIND_SYMLINK -- both replay their real content from
 * elsewhere (the sidecar record's target string, or the referenced entry's
 * own payload), so the payload node itself only ever needs to prove it
 * was not tampered with. */
static int replay_symlink_placeholder_valid(const ReplayCollection *collection,
                                            const ManifestRoot *root,
                                            const SidecarEntry *entry)
{
    if (collection == NULL || root == NULL || entry == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    int payload_fd = -1;
    struct stat payload_st;
    if (replay_open_payload(collection->data_fd, root, entry, &payload_fd,
                            &payload_st) != 0)
        return -1;
    int result = S_ISREG(payload_st.st_mode) && payload_st.st_size == 0
        ? 0 : -1;
    int saved = errno;
    if (result != 0)
        saved = EIO;
    if (close(payload_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

/* Maps a sidecar entry kind to the MetadataXattrRequirements field (metadata.h)
 * its xattr namespaces accumulate into. SIDECAR_KIND_HARDLINK deliberately
 * maps to NULL: a hardlink alias carries no independent xattrs of its own
 * (docs/DECISIONS.md D22) -- its representative's REGULAR entry is what
 * accumulates them. If MetadataXattrRequirements ever grows a fourth field,
 * this is the other place that needs it. */
static unsigned int *replay_xattr_requirements_field(
    MetadataXattrRequirements *requirements, SidecarObjectKind kind)
{
    if (requirements == NULL)
        return NULL;
    switch (kind)
    {
    case SIDECAR_KIND_REGULAR:   return &requirements->regular_namespaces;
    case SIDECAR_KIND_DIRECTORY: return &requirements->directory_namespaces;
    case SIDECAR_KIND_SYMLINK:   return &requirements->symlink_namespaces;
    case SIDECAR_KIND_FIFO:
    case SIDECAR_KIND_HARDLINK:  return NULL;
    }
    return NULL;
}

static int replay_collect_entry(const SidecarLiveView *view, void *argument)
{
    ReplayCollection *collection = argument;
    if (collection == NULL || view == NULL || view->entry == NULL)
        return 1;

    const SidecarEntry *entry = view->entry;
    size_t root_index = root_map_find(&collection->root_map,
                                      collection->manifest,
                                      entry->root_id);
    if (root_index == SIZE_MAX ||
        !sidecar_path_valid(entry->logical_path, 1) ||
        !sidecar_path_valid(entry->physical_path, 1) ||
        !replay_entry_valid(entry) ||
        !entry_physical_matches_parent(
            &collection->manifest->roots[root_index],
            &collection->parent_map, entry))
    {
        replay_report_failure(collection->report, collection->manifest,
                              root_index, entry->logical_path);
        return 1;
    }

    const ManifestRoot *root = &collection->manifest->roots[root_index];
    if ((entry->kind == SIDECAR_KIND_SYMLINK ||
         entry->kind == SIDECAR_KIND_HARDLINK) &&
        replay_symlink_placeholder_valid(collection, root, entry) != 0)
    {
        replay_report_failure(collection->report, collection->manifest,
                              root_index, entry->logical_path);
        return 1;
    }

    size_t hardlink_ref_root_index = SIZE_MAX;
    char hardlink_ref_relative[PATH_MAX] = {0};
    if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        SidecarLiveView referenced;
        if (collection->sidecar == NULL ||
            sidecar_log_find(collection->sidecar,
                             entry->hardlink_root_id,
                             entry->hardlink_logical_path, &referenced) <= 0 ||
            referenced.entry == NULL ||
            referenced.entry->kind != SIDECAR_KIND_REGULAR ||
            !sidecar_path_valid(referenced.entry->logical_path, 1) ||
            referenced.entry->logical_path.length >= PATH_MAX)
        {
            replay_report_failure(collection->report, collection->manifest,
                                  root_index, entry->logical_path);
            return 1;
        }
        hardlink_ref_root_index = root_map_find(&collection->root_map,
                                                collection->manifest,
                                                entry->hardlink_root_id);
        if (hardlink_ref_root_index == SIZE_MAX)
        {
            replay_report_failure(collection->report, collection->manifest,
                                  root_index, entry->logical_path);
            return 1;
        }
        char reference_logical[PATH_MAX];
        replay_copy_bytes(reference_logical, sizeof(reference_logical),
                          referenced.entry->logical_path);
        const ManifestRoot *ref_root =
            &collection->manifest->roots[hardlink_ref_root_index];
        if (ref_root->policy == ROOT_POLICY_XDG)
        {
            if (!xdg_destination_valid(collection->destination_xdg_dirs,
                                       ref_root))
            {
                replay_report_failure(collection->report,
                                      collection->manifest, root_index,
                                      entry->logical_path);
                return 1;
            }
            int length = snprintf(hardlink_ref_relative,
                                  sizeof(hardlink_ref_relative), "%s",
                                  reference_logical);
            if (length < 0 || (size_t)length >= sizeof(hardlink_ref_relative))
            {
                replay_report_failure(collection->report,
                                      collection->manifest, root_index,
                                      entry->logical_path);
                return 1;
            }
        }
        else
        {
            char hardlink_ref_destination[PATH_MAX];
            if (destination_path_build(
                    ref_root, reference_logical,
                    collection->destination_xdg_dirs,
                    hardlink_ref_destination,
                    sizeof(hardlink_ref_destination)) != 0)
            {
                replay_report_failure(collection->report,
                                      collection->manifest, root_index,
                                      entry->logical_path);
                return 1;
            }
            int length = snprintf(hardlink_ref_relative,
                                  sizeof(hardlink_ref_relative), "%s",
                                  hardlink_ref_destination);
            if (length < 0 ||
                (size_t)length >= sizeof(hardlink_ref_relative))
            {
                replay_report_failure(collection->report,
                                      collection->manifest, root_index,
                                      entry->logical_path);
                return 1;
            }
        }
    }

    char logical[PATH_MAX];
    replay_copy_bytes(logical, sizeof(logical), entry->logical_path);
    if (entry->logical_path.length >= sizeof(logical) ||
        entry->physical_path.length >= PATH_MAX)
    {
        replay_report_failure(collection->report, collection->manifest,
                              root_index, entry->logical_path);
        return 1;
    }

    struct stat desired;
    if (replay_stat_from_entry(entry, &desired) != 0)
    {
        replay_report_failure(collection->report, collection->manifest,
                              root_index, entry->logical_path);
        return 1;
    }

    if (replay_entries_reserve(collection, 1) != 0)
    {
        replay_report_failure(collection->report, collection->manifest,
                              root_index, entry->logical_path);
        return 1;
    }
    ReplayEntry *replay = &collection->items[collection->count];
    memset(replay, 0, sizeof(*replay));
    if (destination_path_build(root, logical,
                               collection->destination_xdg_dirs,
                               replay->destination,
                               sizeof(replay->destination)) != 0 ||
        (replay->destination[0] == '\0' &&
         entry->kind != SIDECAR_KIND_DIRECTORY))
    {
        replay_report_failure(collection->report, collection->manifest,
                              root_index, entry->logical_path);
        return 1;
    }
    if (root->policy == ROOT_POLICY_XDG)
    {
        int length = snprintf(replay->destination_relative,
                              sizeof(replay->destination_relative), "%s",
                              logical);
        if (length < 0 ||
            (size_t)length >= sizeof(replay->destination_relative))
        {
            replay_report_failure(collection->report, collection->manifest,
                                  root_index, entry->logical_path);
            return 1;
        }
    }
    else
    {
        int length = snprintf(replay->destination_relative,
                              sizeof(replay->destination_relative), "%s",
                              replay->destination);
        if (length < 0 ||
            (size_t)length >= sizeof(replay->destination_relative))
        {
            replay_report_failure(collection->report,
                                  collection->manifest, root_index,
                                  entry->logical_path);
            return 1;
        }
    }
    replay->entry = entry;
    replay->xattrs = view->xattrs;
    replay->xattr_count = view->xattr_count;
    replay->hardlink_ref_root_index = hardlink_ref_root_index;
    memcpy(replay->hardlink_ref_relative, hardlink_ref_relative,
           sizeof(replay->hardlink_ref_relative));
    /*
     * Accumulate the xattr namespace requirements for the pre-mutation
     * capability gate (D20 E-9). The sidecar's xattr names are not
     * NUL-terminated, so the length-aware classifier is required; and the
     * security.* bit is kept for the matrix but masked out by the probe
     * itself (METADATA_XATTR_NS_PROBED), so no branch is needed here.
     */
    if (view->xattr_count != 0)
    {
        unsigned int *kind_namespaces = replay_xattr_requirements_field(
            &collection->xattr_requirements, entry->kind);
        if (kind_namespaces != NULL)
            for (size_t xindex = 0; xindex < view->xattr_count; xindex++)
            {
                unsigned int namespaces = metadata_xattr_namespace_bytes(
                    view->xattrs[xindex].name.data,
                    view->xattrs[xindex].name.length);
                *kind_namespaces |= namespaces;
            }
    }
    replay->root_index = root_index;
    replay->depth = relative_path_depth(replay->destination);
    collection->count++;
    if (collection->report->live_count != SIZE_MAX)
        collection->report->live_count++;
    return 0;
}

static int replay_payload_path_build(const ManifestRoot *root,
                                     SidecarBytes physical,
                                     char *out, size_t out_size)
{
    if (root == NULL || out == NULL || out_size == 0 ||
        !sidecar_path_valid(physical, 1))
    {
        errno = EINVAL;
        return -1;
    }
    size_t root_length = strlen(root->payload_path);
    if (!portable_payload_path_fits(root_length, physical.length, out_size))
    {
        errno = E2BIG;
        return -1;
    }
    memcpy(out, root->payload_path, root_length);
    if (physical.length == 0)
    {
        out[root_length] = '\0';
        return 0;
    }
    out[root_length] = '/';
    memcpy(out + root_length + 1U, physical.data, physical.length);
    out[root_length + 1U + physical.length] = '\0';
    return 0;
}

static int replay_open_existing_relative(int base_fd, const char *relative,
                                          int flags, int *out_fd,
                                          struct stat *out_stat)
{
    if (base_fd < 0 || relative == NULL || out_fd == NULL ||
        !relative_path_valid(relative, 0))
    {
        errno = EINVAL;
        return -1;
    }
    *out_fd = -1;
    char copy[PATH_MAX];
    size_t length = strlen(relative);
    memcpy(copy, relative, length + 1U);
    int current = dup_cloexec(base_fd);
    if (current < 0)
        return -1;

    char *cursor = copy;
    for (;;)
    {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash != NULL)
        {
            int next = openat(current, cursor,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_NOATIME | O_CLOEXEC);
            if (next < 0)
            {
                int saved = errno;
                close(current);
                errno = saved;
                return -1;
            }
            if (close(current) != 0)
            {
                int saved = errno;
                close(next);
                errno = saved;
                return -1;
            }
            current = next;
            cursor = slash + 1U;
            continue;
        }

        int fd = openat(current, cursor, flags | O_NOFOLLOW | O_CLOEXEC);
        int saved = errno;
        if (fd < 0)
        {
            close(current);
            errno = saved;
            return -1;
        }
        if (out_stat != NULL && fstat(fd, out_stat) != 0)
        {
            saved = errno;
            close(fd);
            close(current);
            errno = saved;
            return -1;
        }
        if (close(current) != 0)
        {
            saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        *out_fd = fd;
        return 0;
    }
}

static int replay_open_payload(int data_fd, const ManifestRoot *root,
                               const SidecarEntry *entry, int *out_fd,
                               struct stat *out_stat)
{
    if (data_fd < 0 || root == NULL || entry == NULL || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    char path[PATH_MAX];
    if (replay_payload_path_build(root, entry->physical_path, path,
                                  sizeof(path)) != 0)
        return -1;
    int flags = O_RDONLY | O_NOATIME;
    if (entry->kind == SIDECAR_KIND_DIRECTORY)
        flags |= O_DIRECTORY;
    int fd = -1;
    struct stat st;
    if (replay_open_existing_relative(data_fd, path, flags, &fd, &st) != 0)
        return -1;
    if ((entry->kind == SIDECAR_KIND_DIRECTORY && !S_ISDIR(st.st_mode)) ||
        (entry->kind == SIDECAR_KIND_REGULAR &&
         (!S_ISREG(st.st_mode) || st.st_size < 0 ||
          (uintmax_t)st.st_size != entry->size)))
    {
        int saved = EIO;
        close(fd);
        errno = saved;
        return -1;
    }
    if (out_stat != NULL)
        *out_stat = st;
    *out_fd = fd;
    return 0;
}

static int replay_open_destination_directory(int parent_fd, const char *leaf,
                                              int *out_fd)
{
    if (parent_fd < 0 || leaf == NULL || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (leaf[0] == '\0')
    {
        *out_fd = dup_cloexec(parent_fd);
        return *out_fd < 0 ? -1 : 0;
    }
    if (!text_component_valid(leaf, strlen(leaf)))
    {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            errno = ENOTDIR;
            return -1;
        }
    }
    else if (errno == ENOENT)
    {
        if (mkdirat(parent_fd, leaf, 0700) != 0 && errno != EEXIST)
            return -1;
        if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(st.st_mode))
        {
            errno = ENOTDIR;
            return -1;
        }
    }
    else
        return -1;
    *out_fd = openat(parent_fd, leaf,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return *out_fd < 0 ? -1 : 0;
}

static int replay_open_destination_regular(int parent_fd, const char *leaf,
                                            int *out_fd)
{
    if (parent_fd < 0 || leaf == NULL || leaf[0] == '\0' || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (!S_ISREG(st.st_mode))
        {
            errno = EEXIST;
            return -1;
        }
        int fd = openat(parent_fd, leaf,
                        O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            return -1;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        {
            int saved = errno == 0 ? EIO : errno;
            close(fd);
            errno = saved;
            return -1;
        }
        *out_fd = fd;
        return 0;
    }
    if (errno != ENOENT)
        return -1;
    int fd = openat(parent_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                        O_NONBLOCK | O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        int saved = errno == 0 ? EIO : errno;
        close(fd);
        unlinkat(parent_fd, leaf, 0);
        errno = saved;
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int replay_destination_parent_for_root(
    const ReplayCollection *collection, size_t root_index,
    const char *relative, int *parent_out, char *leaf, size_t leaf_size)
{
    if (collection == NULL || collection->manifest == NULL ||
        relative == NULL || parent_out == NULL || leaf == NULL ||
        root_index >= (size_t)collection->manifest->root_count)
    {
        errno = EINVAL;
        return -1;
    }

    const ManifestRoot *root = &collection->manifest->roots[root_index];
    if (root->policy != ROOT_POLICY_XDG)
        return portable_open_relative_parent(
            collection->destination_home_fd, relative, parent_out, leaf,
            leaf_size);

    if (!xdg_destination_valid(collection->destination_xdg_dirs, root))
    {
        errno = EINVAL;
        return -1;
    }
    int index = xdg_key_index(root->id);
    int xdg_fd = -1;
    char prefix[NAME_MAX + 1U];
    char destination[PATH_MAX];
    if (open_xdg_destination_anchor(
            collection->destination_xdg_dirs[index], &xdg_fd,
            prefix, sizeof(prefix)) != 0 ||
        destination_relative_path_build(prefix, relative, destination,
                                        sizeof(destination)) != 0)
    {
        if (xdg_fd >= 0)
            close(xdg_fd);
        return -1;
    }

    int result = portable_open_relative_parent(
        xdg_fd, destination, parent_out, leaf, leaf_size);
    int saved = errno;
    if (close(xdg_fd) != 0 && result == 0)
    {
        close(*parent_out);
        *parent_out = -1;
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int replay_destination_parent(const ReplayCollection *collection,
                                     const ReplayEntry *replay,
                                     int *parent_out, char *leaf,
                                     size_t leaf_size)
{
    if (collection == NULL || replay == NULL || parent_out == NULL ||
        leaf == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    return replay_destination_parent_for_root(
        collection, replay->root_index, replay->destination_relative,
        parent_out, leaf, leaf_size);
}

static int replay_apply_regular(ReplayCollection *collection,
                                ReplayEntry *replay)
{
    const ManifestRoot *root = &collection->manifest->roots[
        replay->root_index];
    const SidecarEntry *entry = replay->entry;
    if (entry->size > (uint64_t)INTMAX_MAX)
    {
        errno = EOVERFLOW;
        return -1;
    }
    struct stat desired;
    if (replay_stat_from_entry(entry, &desired) != 0)
        return -1;

    int source_fd = -1;
    struct stat source_before;
    if (replay_open_payload(collection->data_fd, root, entry, &source_fd,
                            &source_before) != 0)
        return -1;
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    int destination_fd = -1;
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result == 0)
        result = replay_open_destination_regular(parent_fd, leaf,
                                                 &destination_fd);
    if (result == 0 && collection->capture_report != NULL)
        snprintf(collection->capture_report->current_path,
                 sizeof(collection->capture_report->current_path), "%s",
                 replay->destination_relative);
    if (result == 0)
        result = portable_copy_regular(
            source_fd, destination_fd, (off_t)entry->size,
            collection->capture_report);
    if (result == 0)
    {
        struct stat source_after;
        if (fstat(source_fd, &source_after) != 0 ||
            !metadata_source_unchanged(&source_before, &source_after))
        {
            errno = EIO;
            result = -1;
        }
    }
    if (result == 0)
        result = metadata_apply_ownership_and_mode_fd(destination_fd,
                                                      &desired);
    if (result == 0)
    {
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_fd_report(
            destination_fd, replay->xattrs, replay->xattr_count,
            &skipped_security);
        replay_report_security_skipped(collection->report, skipped_security);
        if (xattr_result != 0)
            result = -1;
    }
    if (result == 0)
        result = metadata_apply_times_fd(destination_fd, &desired,
                                         collection->timestamp_policy);

    int saved = errno;
    if (destination_fd >= 0 && close(destination_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    if (close(source_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int replay_apply_symlink(ReplayCollection *collection,
                                ReplayEntry *replay)
{
    if (collection == NULL || replay == NULL || replay->entry == NULL ||
        replay->entry->kind != SIDECAR_KIND_SYMLINK ||
        !replay_entry_valid(replay->entry))
    {
        errno = EINVAL;
        return -1;
    }

    const SidecarEntry *entry = replay->entry;
    struct stat desired;
    if (replay_stat_from_entry(entry, &desired) != 0)
        return -1;

    size_t target_length = entry->symlink_target.length;
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    memcpy(target, entry->symlink_target.data, target_length);
    target[target_length] = '\0';

    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result == 0)
    {
        struct stat existing;
        if (fstatat(parent_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
        {
            errno = EEXIST;
            result = -1;
        }
        else if (errno != ENOENT)
            result = -1;
    }
    if (result == 0 && symlinkat(target, parent_fd, leaf) != 0)
        result = -1;
    if (result == 0)
        result = metadata_apply_symlink_ownership_at(parent_fd, leaf,
                                                     &desired);
    if (result == 0)
    {
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_symlink_at_report(
            parent_fd, leaf, replay->xattrs, replay->xattr_count,
            &skipped_security);
        replay_report_security_skipped(collection->report, skipped_security);
        if (xattr_result != 0)
            result = -1;
    }
    if (result == 0)
        result = metadata_apply_symlink_times_at(parent_fd, leaf, &desired,
                                                 collection->timestamp_policy);

    int saved = errno;
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

int replay_hardlink_identity_matches(const struct stat *linked,
                                     const struct stat *reference)
{
    return linked != NULL && reference != NULL &&
           linked->st_dev == reference->st_dev &&
           linked->st_ino == reference->st_ino;
}

#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
static void (*hardlink_race_hook)(void);

void portable_restore_replay_test_set_hardlink_race_hook(void (*hook)(void))
{
    hardlink_race_hook = hook;
}
#endif

static int replay_apply_hardlink(ReplayCollection *collection,
                                 ReplayEntry *replay)
{
    if (collection == NULL || replay == NULL || replay->entry == NULL ||
        replay->entry->kind != SIDECAR_KIND_HARDLINK ||
        !replay_entry_valid(replay->entry) ||
        replay->hardlink_ref_root_index >=
            (size_t)collection->manifest->root_count ||
        replay->hardlink_ref_relative[0] == '\0' ||
        !relative_path_valid(replay->hardlink_ref_relative, 0))
    {
        errno = EINVAL;
        return -1;
    }

    int parent_fd = -1;
    int ref_parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    char ref_leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result == 0)
        result = replay_destination_parent_for_root(
            collection, replay->hardlink_ref_root_index,
            replay->hardlink_ref_relative, &ref_parent_fd, ref_leaf,
            sizeof(ref_leaf));

    struct stat reference_before;
    if (result == 0 &&
        (ref_leaf[0] == '\0' ||
         fstatat(ref_parent_fd, ref_leaf, &reference_before,
                 AT_SYMLINK_NOFOLLOW) != 0 ||
         !S_ISREG(reference_before.st_mode)))
    {
        errno = EIO;
        result = -1;
    }
    if (result == 0)
    {
        struct stat existing;
        if (fstatat(parent_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
        {
            errno = EEXIST;
            result = -1;
        }
        else if (errno != ENOENT)
            result = -1;
    }
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (result == 0 && hardlink_race_hook != NULL)
        hardlink_race_hook();
#endif
    if (result == 0 && linkat(ref_parent_fd, ref_leaf, parent_fd, leaf, 0) != 0)
        result = -1;
    if (result == 0)
    {
        struct stat linked;
        if (fstatat(parent_fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
            !replay_hardlink_identity_matches(&linked, &reference_before))
        {
            errno = EIO;
            result = -1;
        }
    }

    int saved = errno;
    if (ref_parent_fd >= 0 && close(ref_parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int replay_prepare_directory(ReplayCollection *collection,
                                     ReplayEntry *replay)
{
    const ManifestRoot *root = &collection->manifest->roots[
        replay->root_index];
    const SidecarEntry *entry = replay->entry;
    int source_fd = -1;
    struct stat source_st;
    if (replay_open_payload(collection->data_fd, root, entry, &source_fd,
                            &source_st) != 0)
        return -1;

    int parent_fd = -1;
    int destination_fd = -1;
    char leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result == 0)
        result = replay_open_destination_directory(parent_fd, leaf,
                                                   &destination_fd);

    int saved = errno;
    if (destination_fd >= 0 && close(destination_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    if (close(source_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int replay_apply_directory_metadata(ReplayCollection *collection,
                                            ReplayEntry *replay)
{
    const SidecarEntry *entry = replay->entry;
    struct stat desired;
    if (replay_stat_from_entry(entry, &desired) != 0)
        return -1;
    int parent_fd = -1;
    int destination_fd = -1;
    char leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result == 0)
    {
        struct stat existing;
        if (leaf[0] == '\0')
            destination_fd = dup_cloexec(parent_fd);
        else if (fstatat(parent_fd, leaf, &existing,
                         AT_SYMLINK_NOFOLLOW) == 0 &&
                 S_ISDIR(existing.st_mode))
            destination_fd = openat(parent_fd, leaf,
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                        O_CLOEXEC);
        else
        {
            errno = ENOTDIR;
            result = -1;
        }
        if (destination_fd < 0 && result == 0)
            result = -1;
    }
    if (result == 0)
        result = metadata_apply_ownership_and_mode_fd(destination_fd,
                                                      &desired);
    if (result == 0)
    {
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_fd_report(
            destination_fd, replay->xattrs, replay->xattr_count,
            &skipped_security);
        replay_report_security_skipped(collection->report, skipped_security);
        if (xattr_result != 0)
            result = -1;
    }
    if (result == 0)
        result = metadata_apply_times_fd(destination_fd, &desired,
                                         collection->timestamp_policy);

    int saved = errno;
    if (destination_fd >= 0 && close(destination_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static void replay_print_verbose_root(const ReplayCollection *collection,
                                      size_t root_index,
                                      unsigned char *printed_roots)
{
    if (!verbose || collection == NULL || collection->manifest == NULL ||
        printed_roots == NULL || root_index >= MANIFEST_MAX_ROOTS ||
        root_index >= (size_t)collection->manifest->root_count ||
        printed_roots[root_index])
        return;

    printf("  Restoring: %s\n",
           collection->manifest->roots[root_index].id);
    printed_roots[root_index] = 1;
}

static int replay_run(ReplayCollection *collection)
{
    if (collection == NULL || collection->report == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    unsigned char printed_roots[MANIFEST_MAX_ROOTS] = { 0 };
    qsort(collection->items, collection->count, sizeof(*collection->items),
          replay_entry_compare);

    /* Three passes over the same sorted set, not one:
     * 1. Every non-HARDLINK entry, in sorted (depth, destination) order.
     * 2. HARDLINK entries only, in a second pass over the same set --
     *    deferred because neither the sidecar's hash-bucket iteration order
     *    nor this sort gives any representative-before-alias guarantee a
     *    single combined pass could rely on (D22 As-built, Phase G).
     * 3. Directory metadata, applied in reverse sorted order so every child
     *    is already on disk before its parent's own metadata (mtime
     *    especially) is set (D17, "directories: children first, then exact
     *    post-order metadata"). */
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        int result;
        if (replay->entry->kind == SIDECAR_KIND_HARDLINK)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        if (replay->entry->kind == SIDECAR_KIND_SYMLINK)
            result = replay_apply_symlink(collection, replay);
        else if (replay->entry->kind == SIDECAR_KIND_DIRECTORY)
            result = replay_prepare_directory(collection, replay);
        else
            result = replay_apply_regular(collection, replay);
        if (result != 0)
        {
            replay_report_failure(collection->report, collection->manifest,
                                  replay->root_index,
                                  replay->entry->logical_path);
            return -1;
        }
        if (replay->entry->kind == SIDECAR_KIND_REGULAR ||
            replay->entry->kind == SIDECAR_KIND_SYMLINK)
        {
            if (collection->report->applied_count != SIZE_MAX)
                collection->report->applied_count++;
        }
    }

    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        if (replay->entry->kind != SIDECAR_KIND_HARDLINK)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        if (replay_apply_hardlink(collection, replay) != 0)
        {
            replay_report_failure(collection->report, collection->manifest,
                                  replay->root_index,
                                  replay->entry->logical_path);
            return -1;
        }
        if (collection->report->applied_count != SIZE_MAX)
            collection->report->applied_count++;
    }

    for (size_t index = collection->count; index != 0; index--)
    {
        ReplayEntry *replay = &collection->items[index - 1U];
        if (replay->entry->kind != SIDECAR_KIND_DIRECTORY)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        if (replay_apply_directory_metadata(collection, replay) != 0)
        {
            replay_report_failure(collection->report, collection->manifest,
                                  replay->root_index,
                                  replay->entry->logical_path);
            return -1;
        }
        if (collection->report->applied_count != SIZE_MAX)
            collection->report->applied_count++;
    }
    return 0;
}

void portable_restore_replay_report_init(PortableRestoreReplayReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

int replay_timestamp_policy(const PortableRestoreRequest *request,
                            MetadataTimestampPolicy *out)
{
    if (request == NULL || out == NULL ||
        !request->destination_timestamp_policy.configured ||
        (request->destination_timestamp_policy.nsec_exact != 0 &&
         request->destination_timestamp_policy.nsec_exact != 1))
    {
        errno = EINVAL;
        return -1;
    }
    *out = request->destination_timestamp_policy;
    return 0;
}

int portable_restore_replay_at(const PortableRestoreRequest *request,
                               PortableRestoreReplayReport *report)
{
    if (request == NULL || report == NULL || request->source_container_fd < 0 ||
        request->destination_home_fd < 0 || request->manifest == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    MetadataTimestampPolicy timestamp_policy;
    if (replay_timestamp_policy(request, &timestamp_policy) != 0 ||
        replay_manifest_valid(request->manifest,
                              request->destination_xdg_dirs) != 0)
    {
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
        return -1;
    }

    ReplayCollection collection = {
        .manifest = request->manifest,
        .data_fd = -1,
        .destination_home_fd = request->destination_home_fd,
        .destination_xdg_dirs = request->destination_xdg_dirs,
        .timestamp_policy = timestamp_policy,
        .report = report,
        .capture_report = request->capture_report
    };
    if (root_map_build(&collection.root_map, request->manifest) != 0)
        goto fail;

    struct stat home_st;
    if (fstat(request->destination_home_fd, &home_st) != 0 ||
        !S_ISDIR(home_st.st_mode))
    {
        errno = ENOTDIR;
        goto fail;
    }
    if (sidecar_is_complete_readonly(request->source_container_fd) != 0)
        goto fail;
    collection.data_fd = openat(request->source_container_fd, "data",
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                    O_NOATIME | O_CLOEXEC);
    if (collection.data_fd < 0)
        goto fail;

    SidecarLog sidecar = {0};
    if (sidecar_log_adopt_at(request->source_container_fd, &sidecar) !=
        SIDECAR_OPEN_RESUMABLE)
    {
        close(collection.data_fd);
        collection.data_fd = -1;
        goto fail;
    }
    if (sidecar_log_claim_count(&sidecar) != 0)
    {
        sidecar_log_close(&sidecar);
        close(collection.data_fd);
        collection.data_fd = -1;
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
        goto fail;
    }
    collection.sidecar = &sidecar;
    if (parent_map_build(&collection.parent_map, &collection.memory,
                         &sidecar) != 0)
    {
        sidecar_log_close(&sidecar);
        close(collection.data_fd);
        collection.data_fd = -1;
        goto fail;
    }
    SidecarStatus status = sidecar_log_foreach(&sidecar,
                                               replay_collect_entry,
                                               &collection);
    /* Past this point the failure carrier is a plain 0/-1, not a
     * SidecarStatus: neither the capability gate below nor replay_run
     * reports a sidecar-log condition, so neither has an honest
     * SidecarStatus to return. */
    int result = status == SIDECAR_STATUS_OK ? 0 : -1;
    /*
     * Pre-mutation xattr capability gate (D20 E-9). A single probe at the
     * destination home cannot observe a subtree on a different mount with
     * different xattr support (e.g. ~/usb on vfat under an ext4 home);
     * such a failure surfaces later through E-3's fail-closed partial
     * result, exactly the class D20 E-9's closing paragraph assigns to
     * post-gate failures.
     */
    if (result == 0 &&
        metadata_xattr_capability_probe(collection.destination_home_fd,
                                        &collection.xattr_requirements) != 0)
        result = -1;
    if (result == 0)
        result = replay_run(&collection);
    int saved_errno = errno;
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
    {
        if (result == 0)
            saved_errno = errno == 0 ? EIO : errno;
        result = -1;
    }
    if (close(collection.data_fd) != 0)
    {
        if (result == 0)
            saved_errno = errno == 0 ? EIO : errno;
        result = -1;
    }
    collection.data_fd = -1;
    errno = saved_errno;
    if (result == 0)
    {
        replay_collection_free(&collection);
        return 0;
    }
    if (report->failed_count == 0)
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
    replay_collection_free(&collection);
    return -1;

fail:
    if (collection.data_fd >= 0)
        close(collection.data_fd);
    if (report->failed_count == 0)
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
    replay_collection_free(&collection);
    return -1;
}
