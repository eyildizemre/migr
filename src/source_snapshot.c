#define _GNU_SOURCE
#include "source_snapshot.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/magic.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "utils.h"

#define SOURCE_SNAPSHOT_REBIND_MAX 256U

typedef struct {
    /* Where it is mounted. */
    char path[PATH_MAX];
    /* What is mounted there: the snapshot, or the live object at path. A
     * bind source must belong to the caller's mount namespace, so it is
     * opened only after the namespace is entered. */
    char source[PATH_MAX + 64];
    int snapshot;
    int fd;
} SnapshotMount;

typedef struct {
    SnapshotMount items[SOURCE_SNAPSHOT_REBIND_MAX + SOURCE_SNAPSHOT_MAX];
    size_t count;
} SnapshotMounts;

void source_snapshot_init(SourceSnapshot *snapshot)
{
    if (snapshot == NULL)
        return;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->saved_namespace_fd = -1;
    for (size_t index = 0; index < SOURCE_SNAPSHOT_MAX; index++)
        snapshot->entries[index].subvolume_fd = -1;
}

void source_snapshot_unescape_mount_path(char *path)
{
    if (path == NULL)
        return;
    char *out = path;
    for (const char *in = path; *in != '\0';)
    {
        if (in[0] == '\\' && in[1] >= '0' && in[1] <= '7' &&
            in[2] >= '0' && in[2] <= '7' && in[3] >= '0' && in[3] <= '7')
        {
            *out++ = (char)(((in[1] - '0') << 6) | ((in[2] - '0') << 3) |
                            (in[3] - '0'));
            in += 4;
        }
        else
            *out++ = *in++;
    }
    *out = '\0';
}

static void note_set(char *note, size_t note_size, const char *format,
                     const char *path, int error)
{
    if (note == NULL || note_size == 0 || note[0] != '\0')
        return;
    char text[PATH_MAX + 64];
    snprintf(text, sizeof(text), format, path);
    if (error != 0)
        snprintf(note, note_size, "%s: %s", text, strerror(error));
    else
        snprintf(note, note_size, "%s", text);
}

static void strip_last_component(char *path)
{
    char *slash = strrchr(path, '/');
    if (slash == NULL || slash == path)
        strcpy(path, "/");
    else
        *slash = '\0';
}

// The directory a source lives in, walked up to the root of its btrfs
// subvolume (always inode 256). Returns 1 with the path, 0 when the source
// is not on btrfs, -1 on error.
static int subvolume_root_of(const char *source, char out[PATH_MAX])
{
    char current[PATH_MAX];
    if (snprintf(current, sizeof(current), "%s", source) >=
        (int)sizeof(current))
        return -1;
    struct stat st;
    if (lstat(current, &st) != 0)
        return -1;
    if (!S_ISDIR(st.st_mode))
        strip_last_component(current);
    struct statfs fs;
    if (statfs(current, &fs) != 0)
        return -1;
    if (fs.f_type != BTRFS_SUPER_MAGIC)
        return 0;
    for (;;)
    {
        if (stat(current, &st) != 0)
            return -1;
        if (st.st_ino == BTRFS_FIRST_FREE_OBJECTID)
        {
            memcpy(out, current, strlen(current) + 1U);
            return 1;
        }
        if (strcmp(current, "/") == 0)
            return 0;
        strip_last_component(current);
    }
}

static int path_is_within(const char *path, const char *root)
{
    size_t length = strlen(root);
    return strncmp(path, root, length) == 0 &&
           (path[length] == '\0' || path[length] == '/' ||
            strcmp(root, "/") == 0);
}

static int snapshot_destroy(int parent_fd, const char *name)
{
    struct btrfs_ioctl_vol_args args;
    memset(&args, 0, sizeof(args));
    snprintf(args.name, sizeof(args.name), "%s", name);
    return ioctl(parent_fd, BTRFS_IOC_SNAP_DESTROY, &args);
}

// A snapshot left by a run that died before it could delete it.
static void remove_stale_snapshots(int subvolume_fd)
{
    int scan_fd = dup(subvolume_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        return;
    }
    size_t prefix_length = strlen(SOURCE_SNAPSHOT_PREFIX);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strncmp(entry->d_name, SOURCE_SNAPSHOT_PREFIX, prefix_length) != 0)
            continue;
        const char *digits = entry->d_name + prefix_length;
        char *end = NULL;
        long pid = strtol(digits, &end, 10);
        struct stat st;
        if (end == digits || *end != '\0' || pid <= 0 ||
            (pid_t)pid == getpid() ||
            (kill((pid_t)pid, 0) == 0 || errno == EPERM) ||
            fstatat(subvolume_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            st.st_ino != BTRFS_FIRST_FREE_OBJECTID)
            continue;
        (void)snapshot_destroy(subvolume_fd, entry->d_name);
    }
    closedir(directory);
}

// The first mount added for a path wins.
static int mounts_add(SnapshotMounts *mounts, const char *path,
                      const char *source, int snapshot)
{
    for (size_t index = 0; index < mounts->count; index++)
        if (strcmp(mounts->items[index].path, path) == 0)
            return 0;
    if (mounts->count >= sizeof(mounts->items) / sizeof(mounts->items[0]))
    {
        errno = E2BIG;
        return -1;
    }
    SnapshotMount *item = &mounts->items[mounts->count++];
    snprintf(item->path, sizeof(item->path), "%s", path);
    snprintf(item->source, sizeof(item->source), "%s", source);
    item->snapshot = snapshot;
    item->fd = -1;
    return 0;
}

// Nested subvolumes appear as empty directories inside a snapshot; each is
// mounted back from the live tree.
static int add_nested_subvolumes(SnapshotMounts *mounts,
                                 const SourceSnapshotEntry *entry)
{
    struct btrfs_ioctl_get_subvol_rootref_args refs;
    memset(&refs, 0, sizeof(refs));
    for (;;)
    {
        // EOVERFLOW: more refs follow, from the updated min_treeid.
        int more = ioctl(entry->subvolume_fd, BTRFS_IOC_GET_SUBVOL_ROOTREF,
                         &refs) != 0;
        if (more && errno != EOVERFLOW)
            return -1;
        for (unsigned int index = 0; index < refs.num_items; index++)
        {
            struct btrfs_ioctl_ino_lookup_user_args lookup;
            memset(&lookup, 0, sizeof(lookup));
            lookup.dirid = refs.rootref[index].dirid;
            lookup.treeid = refs.rootref[index].treeid;
            if (ioctl(entry->subvolume_fd, BTRFS_IOC_INO_LOOKUP_USER,
                      &lookup) != 0)
                return -1;
            if (lookup.path[0] == '\0' &&
                strncmp(lookup.name, SOURCE_SNAPSHOT_PREFIX,
                        strlen(SOURCE_SNAPSHOT_PREFIX)) == 0)
                continue;
            char path[PATH_MAX];
            size_t path_length = strlen(lookup.path);
            int written = snprintf(
                path, sizeof(path), "%s%s%s%s%s", entry->subvolume_path,
                strcmp(entry->subvolume_path, "/") == 0 ? "" : "/",
                lookup.path,
                path_length != 0 && lookup.path[path_length - 1U] != '/'
                    ? "/" : "",
                lookup.name);
            if (written < 0 || (size_t)written >= sizeof(path))
                return -1;
            struct stat st;
            if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
                continue;
            if (mounts_add(mounts, path, path, 0) != 0)
                return -1;
        }
        if (!more)
            return 0;
        refs.num_items = 0;
    }
}

// Mounts below a snapshotted path would be hidden by the snapshot mounted
// over it; each is mounted back from the live tree.
static int add_submounts(SnapshotMounts *mounts, const char *subvolume_path)
{
    FILE *mountinfo = fopen("/proc/self/mountinfo", "re");
    if (mountinfo == NULL)
        return -1;
    char *line = NULL;
    size_t capacity = 0;
    int result = 0;
    while (result == 0 && getline(&line, &capacity, mountinfo) > 0)
    {
        char *save = NULL;
        char *field = strtok_r(line, " ", &save);
        for (int index = 1; field != NULL && index < 5; index++)
            field = strtok_r(NULL, " ", &save);
        if (field == NULL)
            continue;
        source_snapshot_unescape_mount_path(field);
        if (strcmp(field, subvolume_path) == 0 ||
            !path_is_within(field, subvolume_path))
            continue;
        if (mounts_add(mounts, field, field, 0) != 0)
            result = -1;
    }
    free(line);
    fclose(mountinfo);
    return result;
}

static int mount_depth_compare(const void *left_pointer,
                               const void *right_pointer)
{
    const SnapshotMount *left = left_pointer;
    const SnapshotMount *right = right_pointer;
    size_t left_length = strlen(left->path);
    size_t right_length = strlen(right->path);
    if (left_length != right_length)
        return left_length < right_length ? -1 : 1;
    // A snapshot goes on top of a live mount at the same path.
    return left->snapshot - right->snapshot;
}

static void mounts_close(SnapshotMounts *mounts)
{
    for (size_t index = 0; index < mounts->count; index++)
        if (mounts->items[index].fd >= 0)
            close(mounts->items[index].fd);
    mounts->count = 0;
}

static void destroy_snapshots(SourceSnapshot *snapshot)
{
    for (size_t index = 0; index < snapshot->count; index++)
    {
        SourceSnapshotEntry *entry = &snapshot->entries[index];
        if (entry->subvolume_fd < 0)
            continue;
        if (entry->name[0] != '\0')
            (void)snapshot_destroy(entry->subvolume_fd, entry->name);
        close(entry->subvolume_fd);
        entry->subvolume_fd = -1;
        entry->name[0] = '\0';
    }
    snapshot->count = 0;
}

void source_snapshot_end(SourceSnapshot *snapshot)
{
    if (snapshot == NULL)
        return;
    if (snapshot->entered)
    {
        if (setns(snapshot->saved_namespace_fd, CLONE_NEWNS) != 0)
            print_warning("Warning: could not leave the snapshot view: %s\n",
                          strerror(errno));
        snapshot->entered = 0;
    }
    if (snapshot->saved_namespace_fd >= 0)
    {
        close(snapshot->saved_namespace_fd);
        snapshot->saved_namespace_fd = -1;
    }
    destroy_snapshots(snapshot);
}

static int enter_snapshot_view(SourceSnapshot *snapshot,
                               SnapshotMounts *mounts, char *note,
                               size_t note_size)
{
    snapshot->saved_namespace_fd = open("/proc/self/ns/mnt",
                                        O_RDONLY | O_CLOEXEC);
    if (snapshot->saved_namespace_fd < 0 || unshare(CLONE_NEWNS) != 0)
    {
        note_set(note, note_size, "Could not open a private view of %s",
                 snapshot->entries[0].subvolume_path, errno);
        return -1;
    }
    snapshot->entered = 1;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    {
        note_set(note, note_size, "Could not open a private view of %s",
                 snapshot->entries[0].subvolume_path, errno);
        return -1;
    }
    qsort(mounts->items, mounts->count, sizeof(mounts->items[0]),
          mount_depth_compare);
    // Every source is opened before the first mount covers any of them.
    for (size_t index = 0; index < mounts->count; index++)
    {
        SnapshotMount *item = &mounts->items[index];
        item->fd = open(item->source, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (item->fd < 0)
        {
            note_set(note, note_size, "Could not open %s for the snapshot view",
                     item->source, errno);
            return -1;
        }
    }
    for (size_t index = 0; index < mounts->count; index++)
    {
        SnapshotMount *item = &mounts->items[index];
        char source[64];
        snprintf(source, sizeof(source), "/proc/self/fd/%d", item->fd);
        if (mount(source, item->path, NULL,
                  MS_BIND | (item->snapshot ? 0 : MS_REC), NULL) != 0)
        {
            note_set(note, note_size, "Could not mount the snapshot view at %s",
                     item->path, errno);
            return -1;
        }
    }
    return 0;
}

size_t source_snapshot_begin(SourceSnapshot *snapshot,
                             const char *const *source_paths,
                             size_t source_count, const char *destination,
                             char *note, size_t note_size)
{
    if (note != NULL && note_size != 0)
        note[0] = '\0';
    if (snapshot == NULL || source_paths == NULL || geteuid() != 0)
        return 0;

    char destination_real[PATH_MAX] = "";
    if (destination == NULL || realpath(destination, destination_real) == NULL)
        destination_real[0] = '\0';

    for (size_t index = 0; index < source_count; index++)
    {
        char subvolume[PATH_MAX];
        if (source_paths[index] == NULL ||
            subvolume_root_of(source_paths[index], subvolume) != 1 ||
            strcmp(subvolume, "/") == 0)
            continue;
        if (destination_real[0] != '\0' &&
            path_is_within(destination_real, subvolume))
        {
            note_set(note, note_size,
                     "%s holds the backup destination, so it was backed up "
                     "from the live files", subvolume, 0);
            continue;
        }
        int duplicate = 0;
        for (size_t known = 0; known < snapshot->count && !duplicate; known++)
            duplicate = strcmp(snapshot->entries[known].subvolume_path,
                               subvolume) == 0;
        if (duplicate)
            continue;
        if (snapshot->count >= SOURCE_SNAPSHOT_MAX)
            break;

        SourceSnapshotEntry *entry = &snapshot->entries[snapshot->count];
        entry->subvolume_fd = open(subvolume, O_RDONLY | O_DIRECTORY |
                                                  O_NOFOLLOW | O_CLOEXEC);
        if (entry->subvolume_fd < 0)
            continue;
        snprintf(entry->subvolume_path, sizeof(entry->subvolume_path), "%s",
                 subvolume);
        remove_stale_snapshots(entry->subvolume_fd);
        struct btrfs_ioctl_vol_args_v2 args;
        memset(&args, 0, sizeof(args));
        args.fd = entry->subvolume_fd;
        args.flags = BTRFS_SUBVOL_RDONLY;
        snprintf(entry->name, sizeof(entry->name), "%s%ld",
                 SOURCE_SNAPSHOT_PREFIX, (long)getpid());
        snprintf(args.name, sizeof(args.name), "%s", entry->name);
        if (ioctl(entry->subvolume_fd, BTRFS_IOC_SNAP_CREATE_V2, &args) != 0)
        {
            note_set(note, note_size, "Could not snapshot %s", subvolume,
                     errno);
            close(entry->subvolume_fd);
            entry->subvolume_fd = -1;
            entry->name[0] = '\0';
            continue;
        }
        snapshot->count++;
    }
    if (snapshot->count == 0)
        return 0;

    // Snapshots first: a nested subvolume that is itself snapshotted keeps
    // its snapshot, since a later live mount at the same path is dropped.
    SnapshotMounts *mounts = calloc(1, sizeof(*mounts));
    int failed = mounts == NULL;
    for (size_t index = 0; !failed && index < snapshot->count; index++)
    {
        const SourceSnapshotEntry *entry = &snapshot->entries[index];
        char source[PATH_MAX + 64];
        snprintf(source, sizeof(source), "%s%s%s", entry->subvolume_path,
                 strcmp(entry->subvolume_path, "/") == 0 ? "" : "/",
                 entry->name);
        failed = mounts_add(mounts, entry->subvolume_path, source, 1) != 0;
    }
    for (size_t index = 0; !failed && index < snapshot->count; index++)
    {
        const SourceSnapshotEntry *entry = &snapshot->entries[index];
        failed = add_nested_subvolumes(mounts, entry) != 0 ||
                 add_submounts(mounts, entry->subvolume_path) != 0;
        if (failed)
            note_set(note, note_size,
                     "Could not list what is nested inside %s",
                     entry->subvolume_path, errno);
    }
    if (!failed)
        failed = enter_snapshot_view(snapshot, mounts, note, note_size) != 0;
    if (mounts != NULL)
    {
        mounts_close(mounts);
        free(mounts);
    }
    if (failed)
    {
        source_snapshot_end(snapshot);
        return 0;
    }
    return snapshot->count;
}
