#define _GNU_SOURCE
#include "verify.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "container.h"
#include "hash.h"
#include "manifest.h"
#include "portable.h"
#include "portable_fsops_internal.h"
#include "portable_restore_internal.h"
#include "sidecar.h"
#include "utils.h"

typedef struct {
    const SidecarEntry *entry;
    size_t root_index;
} VerifyItem;

typedef struct {
    const Manifest *manifest;
    RootMap roots;
    RestoreAddressIndex address_index;
    PreflightMemory memory;
    int data_fd;

    VerifyItem *items;
    size_t count;
    size_t capacity;

    /* The directory holding the previous item's payload, reused while items
     * stay in the same directory (they are sorted by path). */
    int parent_fd;
    size_t parent_root;
    const unsigned char *parent_logical;
    size_t parent_logical_length;

    size_t checked;
    uint64_t bytes_read;
    uint64_t total_bytes;
    ExampleList failed;

    /* A native backup, checked against its source: the root being walked,
     * whether the walk only counts, and the items compared and not. */
    const char *root_id;
    time_t taken;
    int counting;
    size_t compared;
    size_t unchecked;

    int progress;
    struct timespec started_at;
    struct timespec last_redraw;
} VerifyRun;

static int collect_item(const SidecarLiveView *view, void *context)
{
    VerifyRun *run = context;
    if (run->count == run->capacity)
    {
        size_t capacity = run->capacity == 0 ? 1024U : run->capacity * 2U;
        VerifyItem *items = realloc(run->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        run->items = items;
        run->capacity = capacity;
    }
    const SidecarEntry *entry = view->entry;
    run->items[run->count].entry = entry;
    run->items[run->count].root_index =
        root_map_find(&run->roots, run->manifest, entry->root_id);
    run->count++;
    if (entry->kind == SIDECAR_KIND_REGULAR &&
        entry->size <= UINT64_MAX - run->total_bytes)
        run->total_bytes += entry->size;
    return 0;
}

static int bytes_compare(const unsigned char *left, size_t left_length,
                         const unsigned char *right, size_t right_length)
{
    size_t shorter = left_length < right_length ? left_length : right_length;
    int order = shorter == 0 ? 0 : memcmp(left, right, shorter);
    if (order != 0)
        return order;
    return (left_length > right_length) - (left_length < right_length);
}

static int item_compare(const void *left_pointer, const void *right_pointer)
{
    const VerifyItem *left = left_pointer;
    const VerifyItem *right = right_pointer;
    if (left->root_index != right->root_index)
        return left->root_index < right->root_index ? -1 : 1;
    return bytes_compare(left->entry->logical_path.data,
                         left->entry->logical_path.length,
                         right->entry->logical_path.data,
                         right->entry->logical_path.length);
}

static void verify_progress_render(VerifyRun *run, const struct timespec *now)
{
    char done[32], total[32], elapsed[32];
    format_size((off_t)(run->bytes_read > INT64_MAX ? INT64_MAX
                                                    : run->bytes_read),
                done, sizeof(done));
    format_size((off_t)(run->total_bytes > INT64_MAX ? INT64_MAX
                                                     : run->total_bytes),
                total, sizeof(total));
    double seconds = timespec_elapsed_seconds(&run->started_at, now);
    format_duration(seconds > 0.0 && seconds < (double)LONG_MAX
                        ? (long)seconds : 0,
                    elapsed, sizeof(elapsed));
    char line[192];
    (void)snprintf(line, sizeof(line),
                   "Verifying backup: %zu/%zu items, %s of %s, elapsed %s",
                   run->checked, run->count, done, total, elapsed);
    progress_line_fit(line, sizeof(line));
    printf("\r%s\033[K", line);
    fflush(stdout);
}

static void verify_progress_note(VerifyRun *run, int force)
{
    if (!run->progress ||
        !backup_progress_should_fire(&run->last_redraw, force))
        return;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    run->last_redraw = now;
    verify_progress_render(run, &now);
}

static void verify_record(VerifyRun *run, const VerifyItem *item,
                          const char *format, ...)
    __attribute__((format(printf, 3, 4)));

static void verify_record(VerifyRun *run, const VerifyItem *item,
                          const char *format, ...)
{
    char *text = example_list_next(&run->failed);
    if (text == NULL)
        return;
    char reason[160];
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(reason, sizeof(reason), format, arguments);
    va_end(arguments);
    const SidecarEntry *entry = item->entry;
    (void)snprintf(text, EXAMPLE_TEXT_MAX, "%.*s:%.*s (%s)",
                   (int)entry->root_id.length,
                   (const char *)entry->root_id.data,
                   entry->logical_path.length != 0
                       ? (int)entry->logical_path.length : 1,
                   entry->logical_path.length != 0
                       ? (const char *)entry->logical_path.data : ".",
                   reason);
}

// The payload may be owned by another user (a backup taken under sudo), in
// which case O_NOATIME is refused; reading without it is still correct.
static int open_payload_node(int parent_fd, const char *leaf, int flags)
{
    int fd = openat(parent_fd, leaf,
                    flags | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (fd < 0 && errno == EPERM)
        fd = openat(parent_fd, leaf, flags | O_NOFOLLOW | O_CLOEXEC);
    return fd;
}

static void verify_parent_forget(VerifyRun *run)
{
    if (run->parent_fd >= 0)
        close(run->parent_fd);
    run->parent_fd = -1;
    run->parent_logical = NULL;
    run->parent_logical_length = 0;
}

static int leaf_text(SidecarBytes bytes, char out[NAME_MAX + 1U])
{
    if (bytes.length == 0 || bytes.length > NAME_MAX || bytes.data == NULL ||
        !portable_component_valid((const char *)bytes.data, bytes.length))
    {
        errno = EINVAL;
        return -1;
    }
    memcpy(out, bytes.data, bytes.length);
    out[bytes.length] = '\0';
    return 0;
}

// Opens the payload directory of (root, parent logical path) by following the
// recorded physical leaf of every ancestor, as replay does.
static int verify_open_parent(VerifyRun *run, size_t root_index,
                              SidecarBytes root_id,
                              const unsigned char *parent, size_t length)
{
    if (run->parent_fd >= 0 && run->parent_root == root_index &&
        run->parent_logical_length == length &&
        (length == 0 || memcmp(run->parent_logical, parent, length) == 0))
        return 0;
    verify_parent_forget(run);

    int root_parent = -1;
    char leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(
            run->data_fd, run->manifest->roots[root_index].payload_path,
            &root_parent, leaf, sizeof(leaf)) != 0)
    {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    int current = open_payload_node(root_parent, leaf, O_RDONLY | O_DIRECTORY);
    int saved = errno;
    close(root_parent);
    if (current < 0)
    {
        errno = saved;
        return -1;
    }

    for (size_t end = 0; length != 0 && end <= length; end++)
    {
        if (end != length && parent[end] != '/')
            continue;
        SidecarBytes prefix = { .data = parent, .length = end };
        size_t index = SIZE_MAX;
        const SidecarEntry *ancestor = NULL;
        if (restore_address_index_find_logical(&run->address_index, root_id,
                                               prefix, &index) == 1 &&
            index < run->address_index.count)
            ancestor = run->address_index.entries[index].entry;
        if (ancestor == NULL || ancestor->kind != SIDECAR_KIND_DIRECTORY ||
            leaf_text(ancestor->physical_leaf, leaf) != 0)
        {
            close(current);
            errno = EINVAL;
            return -1;
        }
        int next = open_payload_node(current, leaf, O_RDONLY | O_DIRECTORY);
        saved = errno;
        close(current);
        if (next < 0)
        {
            errno = saved;
            return -1;
        }
        current = next;
    }
    run->parent_fd = current;
    run->parent_root = root_index;
    run->parent_logical = parent;
    run->parent_logical_length = length;
    return 0;
}

static void verify_regular(VerifyRun *run, const VerifyItem *item,
                           const char *leaf, const struct stat *st)
{
    const SidecarEntry *entry = item->entry;
    if ((uint64_t)st->st_size != entry->size)
    {
        verify_record(run, item, "size is %jd bytes, captured as %ju",
                      (intmax_t)st->st_size, (uintmax_t)entry->size);
        return;
    }
    int fd = open_payload_node(run->parent_fd, leaf, O_RDONLY);
    if (fd < 0)
    {
        verify_record(run, item, "could not be read: %s", strerror(errno));
        return;
    }
    unsigned char buffer[65536];
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    uint64_t total = 0;
    ssize_t received;
    for (;;)
    {
        received = read(fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            break;
        hash = hash_fnv1a_bytes(hash, buffer, (size_t)received);
        total += (uint64_t)received;
        run->bytes_read += (uint64_t)received;
        verify_progress_note(run, 0);
    }
    int saved = errno;
    close(fd);
    if (received < 0)
        verify_record(run, item, "could not be read: %s", strerror(saved));
    else if (total != entry->size)
        verify_record(run, item, "size is %ju bytes, captured as %ju",
                      (uintmax_t)total, (uintmax_t)entry->size);
    else if (hash != entry->content_digest)
        verify_record(run, item, "content differs from what was captured");
}

static void verify_item(VerifyRun *run, const VerifyItem *item)
{
    const SidecarEntry *entry = item->entry;
    if (item->root_index == SIZE_MAX)
    {
        verify_record(run, item, "its root is not in the manifest");
        return;
    }

    char leaf[NAME_MAX + 1U];
    int opened;
    if (entry->logical_path.length == 0)
    {
        // A root entry is the root's payload node itself.
        verify_parent_forget(run);
        opened = open_existing_payload_parent(
            run->data_fd, run->manifest->roots[item->root_index].payload_path,
            &run->parent_fd, leaf, sizeof(leaf));
        if (opened != 0 && errno == 0)
            errno = EINVAL;
    }
    else
    {
        const unsigned char *logical = entry->logical_path.data;
        size_t parent_length = entry->logical_path.length;
        while (parent_length != 0 && logical[parent_length - 1U] != '/')
            parent_length--;
        if (parent_length != 0)
            parent_length--;
        opened = verify_open_parent(run, item->root_index, entry->root_id,
                                    logical, parent_length);
        if (opened == 0)
            opened = leaf_text(entry->physical_leaf, leaf);
    }
    if (opened != 0)
    {
        if (errno == ENOENT)
            verify_record(run, item, "missing from the backup");
        else
            verify_record(run, item, "could not be located: %s",
                          strerror(errno));
        verify_parent_forget(run);
        return;
    }

    struct stat st;
    if (fstatat(run->parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (errno == ENOENT)
            verify_record(run, item, "missing from the backup");
        else
            verify_record(run, item, "could not be read: %s",
                          strerror(errno));
    }
    else
    {
        switch (entry->kind)
        {
            case SIDECAR_KIND_REGULAR:
                if (!S_ISREG(st.st_mode))
                    verify_record(run, item, "is no longer a regular file");
                else
                    verify_regular(run, item, leaf, &st);
                break;
            case SIDECAR_KIND_DIRECTORY:
                if (!S_ISDIR(st.st_mode))
                    verify_record(run, item, "is no longer a directory");
                break;
            case SIDECAR_KIND_SYMLINK:
            case SIDECAR_KIND_HARDLINK:
                if (!S_ISREG(st.st_mode) || st.st_size != 0)
                    verify_record(run, item,
                                  "its placeholder is not an empty file");
                break;
            case SIDECAR_KIND_FIFO:
                verify_record(run, item, "records an unsupported kind");
                break;
        }
    }
    if (entry->logical_path.length == 0)
        verify_parent_forget(run);
}

// Opens a finished container and reads its manifest, with a printed reason
// when it is not one.
static int finished_container_open(const char *path, Manifest *manifest,
                                   int *container_fd_out)
{
    char copy[PATH_MAX];
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof(copy))
    {
        print_error("Error: invalid backup path: %s\n", path);
        return -1;
    }
    memcpy(copy, path, length + 1U);
    while (length > 1 && copy[length - 1U] == '/')
        copy[--length] = '\0';
    const char *leaf = strrchr(copy, '/');
    leaf = leaf != NULL ? leaf + 1 : copy;
    if (container_name_is_partial(leaf))
    {
        print_error("Error: %s is an in-progress or abandoned backup "
                    "container, not a finished one.\n", path);
        return -1;
    }

    int container_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
    {
        print_error("Error: Could not open backup directory %s: %s\n", path,
                    strerror(errno));
        return -1;
    }
    ManifestStatus status = manifest_read_v1_at(container_fd, manifest);
    if (status != MANIFEST_STATUS_VALID)
    {
        if (status == MANIFEST_STATUS_UNKNOWN_VERSION)
            print_error("Error: manifest.txt records a format version this "
                        "build does not understand.\n");
        else if (status == MANIFEST_STATUS_MISSING ||
                 status == MANIFEST_STATUS_LEGACY)
            print_error("Error: %s is not a versioned migr backup.\n", path);
        else
            print_error("Error: Could not read manifest.txt in %s.\n", path);
        close(container_fd);
        return -1;
    }
    *container_fd_out = container_fd;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Native backups, checked against their source (docs/DECISIONS.md D106).     */
/* ------------------------------------------------------------------------- */

static void native_record(VerifyRun *run, const char *relative,
                          const char *format, ...)
    __attribute__((format(printf, 3, 4)));

static void native_record(VerifyRun *run, const char *relative,
                          const char *format, ...)
{
    char *text = example_list_next(&run->failed);
    if (text == NULL)
        return;
    char reason[160];
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(reason, sizeof(reason), format, arguments);
    va_end(arguments);
    (void)snprintf(text, EXAMPLE_TEXT_MAX, "%s:%s (%s)", run->root_id,
                   relative[0] != '\0' ? relative : ".", reason);
}

// Whether the source has not been modified since the backup copied it: the
// backup keeps the source's modification time, and a destination without
// nanosecond times keeps whole seconds. A program can set a modification
// time back, but not the change time, which must predate the backup's start.
// A difference between two items of the same time is then the backup's.
static int native_same_time(const VerifyRun *run, const struct stat *backup,
                            const struct stat *source)
{
    return source->st_mtim.tv_sec == backup->st_mtim.tv_sec &&
           (backup->st_mtim.tv_nsec == 0 ||
            source->st_mtim.tv_nsec == backup->st_mtim.tv_nsec) &&
           (run->taken == 0 || source->st_ctim.tv_sec < run->taken);
}

static int stat_unchanged(const struct stat *before, const struct stat *after)
{
    return S_ISREG(after->st_mode) && after->st_size == before->st_size &&
           after->st_mtim.tv_sec == before->st_mtim.tv_sec &&
           after->st_mtim.tv_nsec == before->st_mtim.tv_nsec &&
           after->st_ctim.tv_sec == before->st_ctim.tv_sec &&
           after->st_ctim.tv_nsec == before->st_ctim.tv_nsec;
}

// Reads until size bytes or the end; the count, or -1.
static ssize_t read_full(int fd, unsigned char *buffer, size_t size)
{
    size_t total = 0;
    while (total < size)
    {
        ssize_t received = read(fd, buffer + total, size - total);
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            return -1;
        if (received == 0)
            break;
        total += (size_t)received;
    }
    return (ssize_t)total;
}

static void native_compare_file(VerifyRun *run, int parent_fd,
                                const char *leaf, const struct stat *backup,
                                const char *source, const char *relative)
{
    struct stat before;
    int source_fd = -1;
    if (lstat(source, &before) != 0 || !S_ISREG(before.st_mode) ||
        !native_same_time(run, backup, &before) ||
        (before.st_size == backup->st_size &&
         (source_fd = open_payload_node(AT_FDCWD, source, O_RDONLY)) < 0))
    {
        run->unchecked++;
        run->bytes_read += (uint64_t)backup->st_size;
        return;
    }
    if (before.st_size != backup->st_size)
    {
        native_record(run, relative, "size is %jd bytes, the source has %jd",
                      (intmax_t)backup->st_size, (intmax_t)before.st_size);
        run->bytes_read += (uint64_t)backup->st_size;
        return;
    }
    int backup_fd = open_payload_node(parent_fd, leaf, O_RDONLY);
    if (backup_fd < 0)
    {
        native_record(run, relative, "could not be read: %s",
                      strerror(errno));
        close(source_fd);
        return;
    }
    static unsigned char ours[65536], theirs[65536];
    int differs = 0, backup_error = 0, source_error = 0;
    for (;;)
    {
        ssize_t got = read_full(backup_fd, ours, sizeof(ours));
        if (got < 0)
        {
            backup_error = errno;
            break;
        }
        ssize_t want = read_full(source_fd, theirs, sizeof(theirs));
        if (want < 0)
        {
            source_error = 1;
            break;
        }
        run->bytes_read += (uint64_t)got;
        verify_progress_note(run, 0);
        if (got != want || memcmp(ours, theirs, (size_t)got) != 0)
        {
            differs = 1;
            break;
        }
        if (got == 0)
            break;
    }
    struct stat after;
    int changed = source_error || fstat(source_fd, &after) != 0 ||
                  !stat_unchanged(&before, &after);
    close(backup_fd);
    close(source_fd);
    if (backup_error != 0)
        native_record(run, relative, "could not be read: %s",
                      strerror(backup_error));
    else if (changed)
        run->unchecked++;
    else if (differs)
        native_record(run, relative, "content differs from the source");
    else
        run->compared++;
}

static void native_compare_symlink(VerifyRun *run, int parent_fd,
                                   const char *leaf,
                                   const struct stat *backup,
                                   const char *source, const char *relative)
{
    struct stat source_st;
    if (lstat(source, &source_st) != 0 || !S_ISLNK(source_st.st_mode) ||
        !native_same_time(run, backup, &source_st))
    {
        run->unchecked++;
        return;
    }
    char ours[PATH_MAX], theirs[PATH_MAX];
    ssize_t got = readlinkat(parent_fd, leaf, ours, sizeof(ours));
    if (got < 0 || (size_t)got >= sizeof(ours))
    {
        native_record(run, relative, "could not be read: %s",
                      got < 0 ? strerror(errno) : "target too long");
        return;
    }
    ssize_t want = readlink(source, theirs, sizeof(theirs));
    if (want < 0)
        run->unchecked++;
    else if (want == got && memcmp(ours, theirs, (size_t)got) == 0)
        run->compared++;
    else
        native_record(run, relative, "target differs from the source");
}

static void native_walk(VerifyRun *run, int dir_fd, char *source,
                        size_t source_length, char *relative,
                        size_t relative_length);

// One item of the backup at parent_fd/leaf, whose source is source and whose
// path in its root is relative.
static void native_item(VerifyRun *run, int parent_fd, const char *leaf,
                        char *source, size_t source_length, char *relative,
                        size_t relative_length)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (!run->counting)
            native_record(run, relative, "could not be read: %s",
                          strerror(errno));
        return;
    }
    if (S_ISDIR(st.st_mode))
    {
        int child = open_payload_node(parent_fd, leaf,
                                      O_RDONLY | O_DIRECTORY);
        if (child < 0)
        {
            if (!run->counting)
                native_record(run, relative, "could not be read: %s",
                              strerror(errno));
            return;
        }
        native_walk(run, child, source, source_length, relative,
                    relative_length);
        close(child);
        return;
    }
    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
        return;
    if (run->counting)
    {
        run->count++;
        if (S_ISREG(st.st_mode))
            run->total_bytes += (uint64_t)st.st_size;
        return;
    }
    if (S_ISREG(st.st_mode))
        native_compare_file(run, parent_fd, leaf, &st, source, relative);
    else
        native_compare_symlink(run, parent_fd, leaf, &st, source, relative);
    run->checked++;
    verify_progress_note(run, 0);
}

static void native_walk(VerifyRun *run, int dir_fd, char *source,
                        size_t source_length, char *relative,
                        size_t relative_length)
{
    int fd = dup(dir_fd);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (dir == NULL)
    {
        if (!run->counting)
            native_record(run, relative, "could not be read: %s",
                          strerror(errno));
        if (fd >= 0)
            close(fd);
        return;
    }
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
            break;
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        size_t name_length = strlen(name);
        size_t separator = relative_length != 0;
        if (source_length + 1U + name_length >= PATH_MAX ||
            relative_length + separator + name_length >= PATH_MAX)
        {
            if (!run->counting)
                native_record(run, relative, "holds a path too long to check");
            continue;
        }
        source[source_length] = '/';
        memcpy(source + source_length + 1U, name, name_length + 1U);
        if (separator)
            relative[relative_length] = '/';
        memcpy(relative + relative_length + separator, name, name_length + 1U);
        native_item(run, dir_fd, name, source,
                    source_length + 1U + name_length, relative,
                    relative_length + separator + name_length);
        source[source_length] = '\0';
        relative[relative_length] = '\0';
    }
    if (errno != 0 && !run->counting)
        native_record(run, relative, "could not be read: %s", strerror(errno));
    closedir(dir);
}

// A root's source path; a manifest that does not record the source home
// names home-relative roots against the home of the user running verify.
static int native_root_source(const Manifest *manifest, int index,
                              char out[PATH_MAX])
{
    if (manifest_root_source_path(manifest, index, out) == 0)
        return 0;
    const char *recorded = manifest->roots[index].source_path;
    char home[PATH_MAX];
    if (recorded[0] == '/')
        return snprintf(out, PATH_MAX, "%s", recorded) < PATH_MAX ? 0 : -1;
    if (resolve_target_home(home) != 0)
        return -1;
    if (recorded[0] == '\0')
        return snprintf(out, PATH_MAX, "%s", home) < PATH_MAX ? 0 : -1;
    return path_join(out, PATH_MAX, home, recorded);
}

static void native_walk_roots(VerifyRun *run, const Manifest *manifest)
{
    for (int index = 0; index < manifest->root_count; index++)
    {
        const ManifestRoot *root = &manifest->roots[index];
        char source[PATH_MAX], relative[PATH_MAX] = "";
        run->root_id = root->id;
        if (native_root_source(manifest, index, source) != 0)
        {
            if (!run->counting)
                native_record(run, "", "its source path cannot be named");
            continue;
        }
        native_item(run, run->data_fd, root->payload_path, source,
                    strlen(source), relative, 0);
    }
}

// Compares every file and symlink of a native backup with the source it was
// taken from. Nothing recorded the content, so what changed in the source
// since the backup is counted as not checked, never as a difference (D106).
static int verify_native(const char *path, const Manifest *manifest,
                         int container_fd)
{
    VerifyRun run;
    memset(&run, 0, sizeof(run));
    run.parent_fd = -1;
    run.taken = manifest->updated;
    run.data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (run.data_fd < 0)
    {
        print_error("Error: Could not open data/ in the backup: %s\n",
                    strerror(errno));
        return MIGR_EXIT_FAILURE;
    }
    run.counting = 1;
    native_walk_roots(&run, manifest);
    run.counting = 0;

    char total[32];
    format_size((off_t)(run.total_bytes > INT64_MAX ? INT64_MAX
                                                    : run.total_bytes),
                total, sizeof(total));
    print_backup_time(manifest->updated);
    printf("Verifying %zu item%s (%s) in %s against their source\n",
           run.count, run.count == 1 ? "" : "s", total, path);
    run.progress = isatty(STDOUT_FILENO) &&
                   clock_gettime(CLOCK_MONOTONIC, &run.started_at) == 0;
    run.last_redraw = run.started_at;
    native_walk_roots(&run, manifest);
    close(run.data_fd);
    if (run.progress)
    {
        verify_progress_note(&run, 1);
        putchar('\n');
    }
    fflush(stdout);

    size_t failed = run.failed.count;
    if (failed == 0 && run.compared == 0 && run.unchecked != 0)
    {
        print_error("Error: none of the backup's files could be compared "
                    "with their source. A native backup is checked on the "
                    "system it was taken from, before that system is "
                    "replaced.\n");
        return MIGR_EXIT_FAILURE;
    }
    if (run.unchecked != 0)
        printf("Note: %zu item%s changed in the source since the backup, or "
               "could not be read there, and %s not checked.\n",
               run.unchecked, run.unchecked == 1 ? "" : "s",
               run.unchecked == 1 ? "was" : "were");
    if (failed == 0)
    {
        print_success("Backup verified: all %zu item%s compared match the "
                      "source\n", run.compared,
                      run.compared == 1 ? "" : "s");
        return MIGR_EXIT_OK;
    }
    printf("Verification found %zu item%s that differ%s from the source:\n",
           failed, failed == 1 ? "" : "s", failed == 1 ? "s" : "");
    example_list_print(&run.failed, "  ");
    return MIGR_EXIT_CHANGED;
}

static int journal_version_supported(const char *path,
                                     const Manifest *manifest)
{
    if (manifest->sidecar_version == SIDECAR_VERSION)
        return 1;
    print_error("Error: %s was written with journal version %d; this build "
                "reads version %d.\n", path, manifest->sidecar_version,
                SIDECAR_VERSION);
    return 0;
}

int portable_container_open(const char *path, Manifest *manifest,
                            int *container_fd_out)
{
    int container_fd = -1;
    if (finished_container_open(path, manifest, &container_fd) != 0)
        return -1;
    if (manifest->representation != CLONE_PORTABLE_SIDECAR)
        print_error("Error: %s is a native backup, which has no journal.\n",
                    path);
    if (manifest->representation != CLONE_PORTABLE_SIDECAR ||
        !journal_version_supported(path, manifest))
    {
        manifest_free(manifest);
        close(container_fd);
        return -1;
    }
    *container_fd_out = container_fd;
    return 0;
}

int verify_backup(const char *path)
{
    Manifest manifest;
    int container_fd = -1;
    if (path == NULL ||
        finished_container_open(path, &manifest, &container_fd) != 0)
        return MIGR_EXIT_FAILURE;
    if (manifest.representation == CLONE_NATIVE_TREE ||
        !journal_version_supported(path, &manifest))
    {
        int native = manifest.representation == CLONE_NATIVE_TREE
            ? verify_native(path, &manifest, container_fd)
            : MIGR_EXIT_FAILURE;
        manifest_free(&manifest);
        close(container_fd);
        return native;
    }

    VerifyRun run;
    memset(&run, 0, sizeof(run));
    run.manifest = &manifest;
    run.parent_fd = -1;
    run.data_fd = -1;
    SidecarLog sidecar = {0};
    int sidecar_open = 0;
    int result = MIGR_EXIT_FAILURE;

    uint64_t valid_bytes = 0, file_bytes = 0;
    SidecarStatus complete = sidecar_check_complete_readonly(
        container_fd, &valid_bytes, &file_bytes);
    if (complete != SIDECAR_STATUS_OK)
    {
        sidecar_report_incomplete(complete, valid_bytes, file_bytes);
        goto done;
    }
    if (sidecar_log_open_readonly_at(container_fd, &sidecar) !=
        SIDECAR_OPEN_RESUMABLE)
    {
        print_error("Error: Could not open the backup journal (%s).\n",
                    SIDECAR_SLOT_NAME);
        goto done;
    }
    sidecar_open = 1;
    if (sidecar_log_claim_count(&sidecar) != 0)
    {
        print_error("Error: the backup journal (%s) records %zu item%s whose "
                    "capture never finished; this backup did not complete.\n",
                    SIDECAR_SLOT_NAME, sidecar_log_claim_count(&sidecar),
                    sidecar_log_claim_count(&sidecar) == 1 ? "" : "s");
        goto done;
    }
    run.data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (run.data_fd < 0)
    {
        print_error("Error: Could not open data/ in the backup: %s\n",
                    strerror(errno));
        goto done;
    }
    if (root_map_build(&run.roots, &manifest) != 0 ||
        restore_address_index_build(&run.address_index, &run.memory,
                                    &sidecar, NULL) != 0)
    {
        print_error("Error: the backup journal's paths are inconsistent; "
                    "this backup cannot be restored as it is.\n");
        goto done;
    }
    if (sidecar_log_foreach(&sidecar, collect_item, &run) !=
        SIDECAR_STATUS_OK)
    {
        print_error("Error: Could not read the backup journal: %s\n",
                    strerror(errno));
        goto done;
    }
    if (run.count > 1)
        qsort(run.items, run.count, sizeof(*run.items), item_compare);

    char total[32];
    format_size((off_t)(run.total_bytes > INT64_MAX ? INT64_MAX
                                                    : run.total_bytes),
                total, sizeof(total));
    print_backup_time(manifest.updated);
    printf("Verifying %zu item%s (%s) in %s\n", run.count,
           run.count == 1 ? "" : "s", total, path);
    run.progress = isatty(STDOUT_FILENO) &&
                   clock_gettime(CLOCK_MONOTONIC, &run.started_at) == 0;
    run.last_redraw = run.started_at;
    for (size_t index = 0; index < run.count; index++)
    {
        verify_item(&run, &run.items[index]);
        run.checked++;
        verify_progress_note(&run, 0);
    }
    verify_parent_forget(&run);
    if (run.progress)
    {
        verify_progress_note(&run, 1);
        putchar('\n');
    }

    fflush(stdout);
    size_t failed = run.failed.count;
    if (failed == 0)
    {
        print_success("Backup verified: all %zu item%s match what was "
                      "captured\n", run.count, run.count == 1 ? "" : "s");
        result = MIGR_EXIT_OK;
        goto done;
    }
    // Differences are what verify is for, not a failure to run it; they
    // exit 1, as cmp and diff do (D68).
    result = MIGR_EXIT_CHANGED;
    printf("Verification found %zu item%s that differ%s from what was "
           "captured:\n", failed, failed == 1 ? "" : "s",
           failed == 1 ? "s" : "");
    example_list_print(&run.failed, "  ");

done:
    verify_parent_forget(&run);
    free(run.items);
    restore_address_index_free(&run.memory, &run.address_index);
    root_map_free(&run.roots);
    if (run.data_fd >= 0)
        close(run.data_fd);
    if (sidecar_open)
        sidecar_log_close(&sidecar);
    manifest_free(&manifest);
    close(container_fd);
    return result;
}
