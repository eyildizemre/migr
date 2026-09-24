#define _GNU_SOURCE
#include "verify.h"

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

#define VERIFY_EXAMPLES 8

typedef struct {
    const SidecarEntry *entry;
    size_t root_index;
} VerifyItem;

typedef struct {
    char location[MANIFEST_ID_MAX + PATH_MAX + 2];
    char reason[160];
} VerifyExample;

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
    size_t failed;
    uint64_t bytes_read;
    uint64_t total_bytes;
    VerifyExample examples[VERIFY_EXAMPLES];
    size_t example_count;

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
    if (run->failed != SIZE_MAX)
        run->failed++;
    if (run->example_count >= VERIFY_EXAMPLES)
        return;
    VerifyExample *example = &run->examples[run->example_count++];
    const SidecarEntry *entry = item->entry;
    (void)snprintf(example->location, sizeof(example->location), "%.*s:%.*s",
                   (int)entry->root_id.length,
                   (const char *)entry->root_id.data,
                   entry->logical_path.length != 0
                       ? (int)entry->logical_path.length : 1,
                   entry->logical_path.length != 0
                       ? (const char *)entry->logical_path.data : ".");
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(example->reason, sizeof(example->reason), format,
                    arguments);
    va_end(arguments);
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

int portable_container_open(const char *path, Manifest *manifest,
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
    if (manifest->representation != CLONE_PORTABLE_SIDECAR)
    {
        print_error("Error: %s is a native backup; only portable backups "
                    "record the content digests verify checks against.\n",
                    path);
        manifest_free(manifest);
        close(container_fd);
        return -1;
    }
    if (manifest->sidecar_version != SIDECAR_VERSION)
    {
        print_error("Error: %s was written with journal version %d; this "
                    "build verifies version %d.\n", path,
                    manifest->sidecar_version, SIDECAR_VERSION);
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
    if (path == NULL || portable_container_open(path, &manifest,
                                                &container_fd) != 0)
        return 1;

    VerifyRun run;
    memset(&run, 0, sizeof(run));
    run.manifest = &manifest;
    run.parent_fd = -1;
    run.data_fd = -1;
    SidecarLog sidecar = {0};
    int sidecar_open = 0;
    int result = 1;

    uint64_t valid_bytes = 0, file_bytes = 0;
    SidecarStatus complete = sidecar_check_complete_readonly(
        container_fd, &valid_bytes, &file_bytes);
    if (complete != SIDECAR_STATUS_OK)
    {
        sidecar_report_incomplete(complete, valid_bytes, file_bytes);
        goto done;
    }
    if (sidecar_log_adopt_at(container_fd, &sidecar) !=
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
    printf("Verifying %zu item%s (%s) in %s\n", run.count,
           run.count == 1 ? "" : "s", total, path);
    run.progress = isatty(fileno(stdout)) &&
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
    if (run.failed == 0)
    {
        print_success("Backup verified: all %zu item%s match what was "
                      "captured\n", run.count, run.count == 1 ? "" : "s");
        result = 0;
        goto done;
    }
    printf("Verification found %zu item%s that differ%s from what was "
           "captured:\n", run.failed, run.failed == 1 ? "" : "s",
           run.failed == 1 ? "s" : "");
    for (size_t index = 0; index < run.example_count; index++)
        printf("  %s (%s)\n", run.examples[index].location,
               run.examples[index].reason);
    if (run.failed > run.example_count)
        printf("  ... and %zu more\n", run.failed - run.example_count);

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
