#define _GNU_SOURCE

#include "portable_restore_internal.h"
#include "portable_restore.h"
#include "manifest.h"
#include "metadata.h"
#include "portable.h"
#include "sidecar.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    size_t root_index;
    size_t address_index;
    char *logical;
    SidecarObjectKind kind;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
} PreflightEntry;

typedef struct PreflightEntries {
    PreflightEntry *items;
    size_t count;
    size_t capacity;
} PreflightEntries;

typedef struct RestorePreflightProgress RestorePreflightProgress;
typedef struct PayloadScanPool PayloadScanPool;

typedef struct {
    int fd;
    int root_fd;
    char prefix[PATH_MAX];
} DestinationProfileAnchorCache;

typedef struct {
    const Manifest *manifest;
    PortableRestorePreflightReport *report;
    RootMap root_map;
    RestoreAddressIndex address_index;
    size_t *root_order;
    PreflightEntries *entries;
    int destination_home_fd;
    const char *destination_home_path;
    const char * const *destination_xdg_dirs;
    int xdg_anchor_fd[XDG_KEY_COUNT];
    char xdg_anchor_prefix[XDG_KEY_COUNT][PATH_MAX];
    DestinationProfileAnchorCache home_profile_cache;
    DestinationProfileAnchorCache xdg_profile_cache[XDG_KEY_COUNT];
    PreflightMemory memory;
    RestorePreflightProgress *progress;
} Collection;

typedef struct {
    int data_fd;
    const Collection *collection;
    unsigned char *seen;
    char root_namespace_path[PATH_MAX];
    RestorePreflightProgress *progress;
    PayloadScanPool *pool;
    size_t checked_count;
    int failed;
} PayloadInventory;

#define PAYLOAD_SCAN_MAX_WORKERS 8U
#define PAYLOAD_SCAN_BATCH_SIZE 64U
#define PAYLOAD_SCAN_MIN_PARALLEL_ENTRIES 32U

typedef enum {
    PAYLOAD_SCAN_WORK_READY = 0,
    PAYLOAD_SCAN_WORK_STAT_FAILURE
} PayloadScanWorkStatus;

typedef struct {
    int parent_fd;
    size_t root_index;
    size_t address_index;
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    PayloadScanWorkStatus status;
    struct stat st;
    int failure_errno;
} PayloadScanWork;

struct PayloadScanPool {
    pthread_mutex_t lock;
    pthread_cond_t task_ready;
    pthread_cond_t batch_done;
    pthread_t workers[PAYLOAD_SCAN_MAX_WORKERS];
    PayloadScanWork work[PAYLOAD_SCAN_BATCH_SIZE];
    size_t queue[PAYLOAD_SCAN_BATCH_SIZE];
    size_t queue_head;
    size_t queue_count;
    size_t pending;
    size_t workers_started;
    int shutdown;
    int initialized;
#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    size_t active_workers;
    size_t peak_workers;
#endif
};

struct RestorePreflightProgress {
    size_t total_count;
    struct timespec started_at;
    struct timespec last_real_redraw;
    ProgressTicker ticker;
    int active;
    int ticker_started;
};

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
static int portable_restore_preflight_test_progress_enabled;
static size_t portable_restore_preflight_test_profile_root_walk_counter;
static size_t portable_restore_preflight_test_payload_worker_count = SIZE_MAX;
static unsigned int portable_restore_preflight_test_payload_worker_delay_ms;
static char portable_restore_preflight_test_delayed_payload_leaf[
    SIDECAR_MAX_PHYSICAL_LEAF + 1U];
static char portable_restore_preflight_test_duplicate_payload_leaf[
    SIDECAR_MAX_PHYSICAL_LEAF + 1U];
static size_t portable_restore_preflight_test_last_payload_peak_workers;
static size_t portable_restore_preflight_test_last_payload_checked_count;

void portable_restore_preflight_test_set_progress_enabled(int enabled)
{
    portable_restore_preflight_test_progress_enabled = enabled != 0;
}

void portable_restore_preflight_test_reset_profile_root_walk_count(void)
{
    portable_restore_preflight_test_profile_root_walk_counter = 0;
}

size_t portable_restore_preflight_test_profile_root_walk_count(void)
{
    return portable_restore_preflight_test_profile_root_walk_counter;
}

void portable_restore_preflight_test_configure_payload_pool(
    size_t worker_count, unsigned int worker_delay_ms,
    const char *delayed_payload_leaf,
    const char *duplicate_payload_leaf)
{
    portable_restore_preflight_test_payload_worker_count = worker_count;
    portable_restore_preflight_test_payload_worker_delay_ms = worker_delay_ms;
    portable_restore_preflight_test_delayed_payload_leaf[0] = '\0';
    portable_restore_preflight_test_duplicate_payload_leaf[0] = '\0';
    if (delayed_payload_leaf != NULL)
    {
        size_t length = strnlen(delayed_payload_leaf,
                                SIDECAR_MAX_PHYSICAL_LEAF + 1U);
        if (length <= SIDECAR_MAX_PHYSICAL_LEAF)
            memcpy(portable_restore_preflight_test_delayed_payload_leaf,
                   delayed_payload_leaf, length + 1U);
    }
    if (duplicate_payload_leaf != NULL)
    {
        size_t length = strnlen(duplicate_payload_leaf,
                                SIDECAR_MAX_PHYSICAL_LEAF + 1U);
        if (length <= SIDECAR_MAX_PHYSICAL_LEAF)
            memcpy(portable_restore_preflight_test_duplicate_payload_leaf,
                   duplicate_payload_leaf, length + 1U);
    }
}

void portable_restore_preflight_test_reset_payload_pool(void)
{
    portable_restore_preflight_test_payload_worker_count = SIZE_MAX;
    portable_restore_preflight_test_payload_worker_delay_ms = 0;
    portable_restore_preflight_test_delayed_payload_leaf[0] = '\0';
    portable_restore_preflight_test_duplicate_payload_leaf[0] = '\0';
    portable_restore_preflight_test_last_payload_peak_workers = 0;
    portable_restore_preflight_test_last_payload_checked_count = 0;
}

size_t portable_restore_preflight_test_payload_peak_workers(void)
{
    return portable_restore_preflight_test_last_payload_peak_workers;
}

size_t portable_restore_preflight_test_payload_checked_count(void)
{
    return portable_restore_preflight_test_last_payload_checked_count;
}
#endif

static int preflight_progress_should_install(void)
{
#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    return portable_restore_preflight_test_progress_enabled;
#else
    return isatty(fileno(stdout));
#endif
}

static int preflight_progress_should_fire(RestorePreflightProgress *display,
                                          int force)
{
    if (display == NULL)
        return 0;
#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    if (portable_restore_preflight_test_progress_enabled)
        force = 1;
#endif
    return backup_progress_should_fire(&display->last_real_redraw, force);
}

static long preflight_progress_elapsed_seconds(const struct timespec *started_at,
                                               const struct timespec *now)
{
    double elapsed = timespec_elapsed_seconds(started_at, now);
    if (elapsed <= 0.0)
        return 0;
    if (elapsed >= (double)LONG_MAX)
        return LONG_MAX;
    return (long)elapsed;
}

static void preflight_progress_render(const RestorePreflightProgress *display,
                                      size_t checked_count,
                                      const char *phase,
                                      const struct timespec *now)
{
    if (display == NULL || phase == NULL || phase[0] == '\0' || now == NULL)
        return;

    char elapsed_text[32];
    format_duration(preflight_progress_elapsed_seconds(&display->started_at, now),
                    elapsed_text, sizeof(elapsed_text));
    char line[192];
    (void)snprintf(
        line, sizeof(line),
        "Verifying backup contents: %s %zu/%zu checked, elapsed %s",
        phase, checked_count, display->total_count, elapsed_text);
    progress_line_fit(line, sizeof(line));
    printf("\r%s\033[K", line);
    fflush(stdout);
}

static void preflight_progress_ticker_redraw(
    const ProgressTickerSnapshot *snapshot, const struct timespec *now,
    void *context)
{
    RestorePreflightProgress *display = context;
    if (snapshot == NULL || snapshot->bytes < 0 || snapshot->path[0] == '\0')
        return;
    preflight_progress_render(display, (size_t)snapshot->bytes, snapshot->path,
                              now);
}

static void preflight_progress_stop_ticker(RestorePreflightProgress *display)
{
    if (display == NULL || !display->ticker_started)
        return;
    if (progress_ticker_stop(&display->ticker) == 0)
    {
        display->ticker_started = 0;
        return;
    }

    print_error("Error: Could not stop the restore preflight progress thread: %s\n",
                strerror(errno));
    /* Returning would leave a live thread retaining a pointer to this stack
     * display after portable_restore_preflight_at() returns. */
    abort();
}

static int preflight_progress_size_to_off_t(size_t value, off_t *out)
{
    if (out == NULL)
        return -1;
    off_t converted = (off_t)value;
    if (converted < 0 || (size_t)converted != value)
        return -1;
    *out = converted;
    return 0;
}

static int preflight_progress_snapshot(RestorePreflightProgress *display,
                                       size_t checked_count,
                                       const char *phase,
                                       const struct timespec *now)
{
    if (display == NULL || phase == NULL || now == NULL ||
        !display->ticker_started)
        return 0;

    off_t checked_as_off_t = 0;
    if (preflight_progress_size_to_off_t(checked_count, &checked_as_off_t) != 0)
    {
        preflight_progress_stop_ticker(display);
        return 0;
    }
    return progress_ticker_snapshot(&display->ticker, checked_as_off_t, 0, 0, 0,
                                    phase, now);
}

static void preflight_progress_disable_ticker(RestorePreflightProgress *display,
                                              int saved_errno)
{
    preflight_progress_stop_ticker(display);
    putchar('\n');
    print_warning("  Warning: restore preflight stall redraw was disabled: %s\n",
                  strerror(saved_errno));
}

static void preflight_progress_start(RestorePreflightProgress *display,
                                     size_t total_count, const char *phase)
{
    if (display == NULL || phase == NULL || phase[0] == '\0')
        return;
    memset(display, 0, sizeof(*display));
    if (!preflight_progress_should_install())
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    {
        printf("Verifying backup contents before restoring...\n");
        fflush(stdout);
        return;
    }

    display->total_count = total_count;
    display->started_at = now;
    display->last_real_redraw = now;
    display->active = 1;

    if (progress_ticker_start(&display->ticker, preflight_progress_ticker_redraw,
                              display) == 0)
        display->ticker_started = 1;
    else
        print_warning("  Warning: restore preflight stall redraw is unavailable: %s\n",
                      strerror(errno));

    preflight_progress_render(display, 0, phase, &now);
    if (preflight_progress_snapshot(display, 0, phase, &now) != 0)
    {
        int saved_errno = errno;
        preflight_progress_disable_ticker(display, saved_errno);
        preflight_progress_render(display, 0, phase, &now);
    }
}

static void preflight_progress_note(RestorePreflightProgress *display,
                                    size_t checked_count, const char *phase,
                                    int force)
{
    if (display == NULL || phase == NULL || !display->active)
        return;
    if (!preflight_progress_should_fire(display, force))
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    display->last_real_redraw = now;
    if (preflight_progress_snapshot(display, checked_count, phase, &now) != 0)
    {
        int saved_errno = errno;
        preflight_progress_disable_ticker(display, saved_errno);
    }
    preflight_progress_render(display, checked_count, phase, &now);
}

static void preflight_progress_finish(RestorePreflightProgress *display,
                                      size_t checked_count, const char *phase)
{
    if (display == NULL || phase == NULL || !display->active)
        return;
    preflight_progress_stop_ticker(display);

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        preflight_progress_render(display, checked_count, phase, &now);
    putchar('\n');
    fflush(stdout);
    display->active = 0;
}

static void preflight_progress_cancel(RestorePreflightProgress *display)
{
    if (display == NULL || !display->active)
        return;
    preflight_progress_stop_ticker(display);
    putchar('\n');
    fflush(stdout);
    display->active = 0;
}

static void report_violation(PortableRestorePreflightReport *report,
                             size_t root_index, const char *logical)
{
    if (report == NULL)
        return;
    if (report->violation_count != SIZE_MAX)
        report->violation_count++;
    if (root_index < report->root_count && report->roots != NULL)
    {
        if (report->roots[root_index].violation_count != SIZE_MAX)
            report->roots[root_index].violation_count++;
    }
    if (logical != NULL && report->profiles.example_count <
                               METADATA_MAX_PREFLIGHT_EXAMPLES)
    {
        int length = snprintf(
            report->profiles.examples[report->profiles.example_count],
            sizeof(report->profiles.examples[0]), "%s", logical);
        if (length >= 0 && (size_t)length <
                               sizeof(report->profiles.examples[0]))
            report->profiles.example_count++;
    }
}

static int root_order_compare(const void *left, const void *right, void *arg)
{
    const Manifest *manifest = arg;
    size_t a = *(const size_t *)left;
    size_t b = *(const size_t *)right;
    return strcmp(manifest->roots[a].payload_path,
                  manifest->roots[b].payload_path);
}

static int collection_validate_manifest(Collection *collection)
{
    const Manifest *manifest = collection->manifest;
    PortableRestorePreflightReport *report = collection->report;
    if (manifest == NULL || !manifest_selection_valid(manifest) ||
        manifest->representation != CLONE_PORTABLE_SIDECAR ||
        manifest->sidecar_version != SIDECAR_VERSION ||
        manifest->root_count < 0 || manifest->root_count > MANIFEST_MAX_ROOTS ||
        (manifest->root_count != 0 && manifest->roots == NULL))
    {
        report_violation(report, SIZE_MAX, "manifest");
        errno = EINVAL;
        return -1;
    }
    if (manifest->version == MANIFEST_SELECTION_VERSION &&
        (collection->destination_home_path == NULL ||
         collection->destination_home_path[0] != '/'))
    {
        report_violation(report, SIZE_MAX, "destination-home");
        errno = EINVAL;
        return -1;
    }
    report->root_count = (size_t)manifest->root_count;
    if (report->root_count != 0)
    {
        report->roots = calloc(report->root_count, sizeof(*report->roots));
        if (report->roots == NULL)
            return -1;
    }
    for (size_t index = 0; index < report->root_count; index++)
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
            (root->policy == ROOT_POLICY_XDG &&
             !xdg_destination_valid(collection->destination_xdg_dirs, root)) ||
            (root->policy == ROOT_POLICY_HOME_RELATIVE &&
             (!root->has_restore_path ||
              !relative_path_valid(root->restore_path, 1))) ||
            (root->policy != ROOT_POLICY_HOME_RELATIVE &&
             root->has_restore_path))
        {
            report_violation(report, index, "manifest-root");
            continue;
        }
        if (snprintf(report->roots[index].id,
                     sizeof(report->roots[index].id), "%s", root->id) < 0)
            return -1;
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            report_violation(report, index, root->id);
    }
    if (report->violation_count != 0)
        return -1;
    if (root_map_build(&collection->root_map, manifest) != 0)
        return -1;
    if (report->root_count != 0)
    {
        collection->root_order = calloc(report->root_count,
                                        sizeof(*collection->root_order));
        if (collection->root_order == NULL)
            return -1;
        for (size_t index = 0; index < report->root_count; index++)
            collection->root_order[index] = index;
        qsort_r(collection->root_order, report->root_count,
                sizeof(*collection->root_order), root_order_compare,
                (void *)manifest);
        /* strcmp adjacency does not preserve path ancestry: a sibling whose
         * next byte sorts before '/' can sit between an ancestor and child.
         * Root counts are bounded, and capture validates the same relation
         * pairwise, so validate every pair here as well. */
        for (size_t left = 0; left < report->root_count; left++)
            for (size_t right = left + 1U; right < report->root_count; right++)
                if (relative_paths_overlap(manifest->roots[left].payload_path,
                                           manifest->roots[right].payload_path))
                    report_violation(report, right, manifest->roots[right].id);
    }
    return report->violation_count == 0 ? 0 : -1;
}

static int copy_sidecar_path(PreflightMemory *memory, SidecarBytes bytes,
                             char **out)
{
    if (memory == NULL || out == NULL || bytes.length >= PATH_MAX ||
        (bytes.length != 0 && bytes.data == NULL) ||
        (bytes.length != 0 && memchr(bytes.data, '\0', bytes.length) != NULL))
    {
        errno = EINVAL;
        return -1;
    }
    char *copy = preflight_alloc(memory, bytes.length + 1U);
    if (copy == NULL)
        return -1;
    if (bytes.length != 0)
        memcpy(copy, bytes.data, bytes.length);
    copy[bytes.length] = '\0';
    *out = copy;
    return 0;
}

static int entries_reserve(PreflightMemory *memory, PreflightEntries *entries,
                           size_t extra)
{
    if (entries == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    PreflightEntry *items = preflight_array_reserve(
        memory, entries->items, &entries->capacity, entries->count, extra,
        sizeof(*items), 16U, SIDECAR_MAX_LIVE_ENTRIES, 1);
    if (items == NULL)
        return -1;
    entries->items = items;
    return 0;
}

static void entries_free(PreflightMemory *memory, PreflightEntries *entries)
{
    if (entries == NULL)
        return;
    for (size_t index = 0; index < entries->count; index++)
    {
        preflight_free(memory, entries->items[index].logical,
                       entries->items[index].logical == NULL ? 0
                           : strlen(entries->items[index].logical) + 1U);
    }
    preflight_free(memory, entries->items,
                   entries->capacity * sizeof(*entries->items));
    memset(entries, 0, sizeof(*entries));
}

static void destination_profile_cache_init(DestinationProfileAnchorCache *cache)
{
    if (cache == NULL)
        return;
    memset(cache, 0, sizeof(*cache));
    cache->fd = -1;
    cache->root_fd = -1;
}

static void destination_profile_cache_invalidate(
    DestinationProfileAnchorCache *cache)
{
    if (cache == NULL)
        return;
    if (cache->fd >= 0)
        (void)close(cache->fd);
    destination_profile_cache_init(cache);
}

static size_t destination_profile_parent_length(const char *relative)
{
    const char *slash = strrchr(relative, '/');
    return slash == NULL ? 0U : (size_t)(slash - relative);
}

static int destination_profile_cache_matches(
    const DestinationProfileAnchorCache *cache, int root_fd,
    const char *relative)
{
    if (cache == NULL || cache->fd < 0 || cache->root_fd != root_fd ||
        cache->prefix[0] == '\0')
        return 0;

    size_t prefix_length = strlen(cache->prefix);
    size_t parent_length = destination_profile_parent_length(relative);
    if (prefix_length > parent_length ||
        memcmp(cache->prefix, relative, prefix_length) != 0)
        return 0;
    return prefix_length == parent_length || relative[prefix_length] == '/';
}

static void destination_profile_cache_store(
    DestinationProfileAnchorCache *cache, int root_fd, const char *relative,
    size_t prefix_length, int directory_fd)
{
    if (cache == NULL || directory_fd < 0 || relative == NULL ||
        prefix_length >= PATH_MAX)
        return;

    int saved = errno;
    if (prefix_length == 0)
    {
        destination_profile_cache_invalidate(cache);
        errno = saved;
        return;
    }

    if (cache->fd >= 0 && cache->root_fd == root_fd &&
        strlen(cache->prefix) == prefix_length &&
        memcmp(cache->prefix, relative, prefix_length) == 0)
    {
        errno = saved;
        return;
    }

    int cached_fd = dup_cloexec(directory_fd);
    if (cached_fd < 0)
    {
        destination_profile_cache_invalidate(cache);
        errno = saved;
        return;
    }
    if (cache->fd >= 0)
        (void)close(cache->fd);
    cache->fd = cached_fd;
    cache->root_fd = root_fd;
    memcpy(cache->prefix, relative, prefix_length);
    cache->prefix[prefix_length] = '\0';
    errno = saved;
}

static void destination_profile_note_root_walk(void)
{
#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    if (portable_restore_preflight_test_profile_root_walk_counter != SIZE_MAX)
        portable_restore_preflight_test_profile_root_walk_counter++;
#endif
}

static int open_destination_profile_anchor(int home_fd, const char *relative,
                                           DestinationProfileAnchorCache *cache,
                                           int *anchor_out,
                                           struct stat *existing,
                                           int *has_existing)
{
    if (home_fd < 0 || relative == NULL || anchor_out == NULL ||
        existing == NULL || has_existing == NULL || cache == NULL ||
        !relative_path_valid(relative, 1))
    {
        errno = EINVAL;
        return -1;
    }
    *anchor_out = -1;
    *has_existing = 0;

    if (cache->fd >= 0 && cache->root_fd != home_fd)
        destination_profile_cache_invalidate(cache);

    int current = -1;
    size_t current_prefix_length = 0;
    size_t cursor_offset = 0;
    if (destination_profile_cache_matches(cache, home_fd, relative))
    {
        current = dup_cloexec(cache->fd);
        if (current >= 0)
        {
            current_prefix_length = strlen(cache->prefix);
            cursor_offset = current_prefix_length + 1U;
        }
        else
            destination_profile_cache_invalidate(cache);
    }
    else if (cache->fd >= 0)
        destination_profile_cache_invalidate(cache);

    if (current < 0)
    {
        destination_profile_note_root_walk();
        current = dup_cloexec(home_fd);
    }
    if (current < 0)
        return -1;
    if (relative[0] == '\0')
    {
        if (fstat(current, existing) != 0)
        {
            int saved = errno;
            close(current);
            errno = saved;
            return -1;
        }
        *has_existing = 1;
        *anchor_out = current;
        return 0;
    }

    char copy[PATH_MAX];
    memcpy(copy, relative, strlen(relative) + 1U);
    char *cursor = copy + cursor_offset;
    for (;;)
    {
        char *slash = strchr(cursor, '/');
        size_t component_end = slash == NULL
            ? strlen(relative)
            : (size_t)(slash - copy);
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL)
        {
            struct stat st;
            if (fstatat(current, cursor, &st, AT_SYMLINK_NOFOLLOW) == 0)
            {
                if (S_ISLNK(st.st_mode))
                {
                    int saved = ELOOP;
                    close(current);
                    errno = saved;
                    return -1;
                }
                *existing = st;
                *has_existing = 1;
                if (S_ISDIR(st.st_mode))
                {
                    int final_fd = openat(
                        current, cursor,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                            O_NOATIME | O_CLOEXEC);
                    if (final_fd < 0)
                    {
                        int saved = errno;
                        close(current);
                        errno = saved;
                        return -1;
                    }
                    if (close(current) != 0)
                    {
                        int saved = errno;
                        close(final_fd);
                        errno = saved;
                        return -1;
                    }
                    destination_profile_cache_store(
                        cache, home_fd, relative, strlen(relative), final_fd);
                    *anchor_out = final_fd;
                    return 0;
                }
            }
            else if (errno != ENOENT)
            {
                int saved = errno;
                close(current);
                errno = saved;
                return -1;
            }
            destination_profile_cache_store(
                cache, home_fd, relative, current_prefix_length, current);
            *anchor_out = current;
            return 0;
        }

        int next = openat(current, cursor,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
        if (next < 0)
        {
            if (errno == ENOENT)
            {
                destination_profile_cache_store(
                    cache, home_fd, relative, current_prefix_length, current);
                *anchor_out = current;
                return 0;
            }
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
        current_prefix_length = component_end;
        cursor = slash + 1U;
    }
}

static int collection_destination_route(Collection *collection,
                                        size_t root_index,
                                        const char *logical,
                                        int *anchor_out,
                                        DestinationProfileAnchorCache **cache_out,
                                        char *relative,
                                        size_t relative_size)
{
    if (collection == NULL || cache_out == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    *cache_out = NULL;
    if (destination_identity_route(
        collection->manifest, root_index, logical,
        collection->destination_home_fd, collection->destination_xdg_dirs,
        collection->xdg_anchor_fd, collection->xdg_anchor_prefix, anchor_out,
        relative, relative_size) != 0)
        return -1;

    const ManifestRoot *root = &collection->manifest->roots[root_index];
    if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        *cache_out = &collection->home_profile_cache;
    else if (root->policy == ROOT_POLICY_XDG)
    {
        int index = xdg_key_index(root->id);
        if (index < 0 || index >= XDG_KEY_COUNT)
        {
            errno = EINVAL;
            return -1;
        }
        *cache_out = &collection->xdg_profile_cache[index];
    }
    else
    {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Returns 0 on success, -1 for a per-entry violation (already recorded via
 * report_violation(), safe for the caller to log and keep scanning past),
 * or -2 for an internal/unexpected failure unrelated to this entry's data
 * (no violation recorded; the caller should abort the scan). */
static int collect_metadata_profile(Collection *collection,
                                    const ManifestRoot *root,
                                    size_t root_index,
                                    const PreflightEntry *entry)
{
    if (collection == NULL || root == NULL || entry == NULL ||
        collection->report == NULL)
        return -2;

    struct stat desired;
    memset(&desired, 0, sizeof(desired));
    desired.st_uid = (uid_t)entry->uid;
    desired.st_gid = (gid_t)entry->gid;
    if ((uintmax_t)desired.st_uid != entry->uid ||
        (uintmax_t)desired.st_gid != entry->gid)
    {
        errno = E2BIG;
        return -2;
    }
    mode_t type;
    if (sidecar_kind_to_type(entry->kind, &type) != 0)
        return -2;
    desired.st_mode = entry->mode | type;

    int route_anchor = -1;
    DestinationProfileAnchorCache *profile_cache = NULL;
    char relative[PATH_MAX];
    if (collection_destination_route(collection, root_index, entry->logical,
                                     &route_anchor, &profile_cache, relative,
                                     sizeof(relative)) != 0)
    {
        report_violation(collection->report, root_index, entry->logical);
        return -1;
    }

    int anchor = -1;
    struct stat existing;
    memset(&existing, 0, sizeof(existing));
    int has_existing = 0;
    if (open_destination_profile_anchor(route_anchor, relative, profile_cache,
                                        &anchor,
                                        &existing, &has_existing) != 0)
    {
        report_violation(collection->report, root_index, entry->logical);
        return -1;
    }

    int result = metadata_profiles_add(&collection->report->profiles, anchor,
                                       &desired,
                                       has_existing ? &existing : NULL,
                                       entry->logical);
    int saved = errno;
    if (close(anchor) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    if (result != 0)
        report_violation(collection->report, root_index, entry->logical);
    return result;
}

static void portable_restore_estimate_add(
    PortableRestorePreflightReport *report, uint64_t bytes)
{
    if (report == NULL || report->estimated_bytes < 0)
        return;
    if (bytes > (uintmax_t)INTMAX_MAX ||
        (uintmax_t)report->estimated_bytes >
            (uintmax_t)INTMAX_MAX - (uintmax_t)bytes)
    {
        report->estimated_bytes = -1;
        return;
    }
    report->estimated_bytes += (off_t)bytes;
}

static int metadata_profile_order_compare(const void *left, const void *right)
{
    const PreflightEntry *first = *(PreflightEntry * const *)left;
    const PreflightEntry *second = *(PreflightEntry * const *)right;
    if (first->root_index < second->root_index)
        return -1;
    if (first->root_index > second->root_index)
        return 1;
    return strcmp(first->logical, second->logical);
}

static int collect_metadata_profiles(Collection *collection)
{
    if (collection == NULL || collection->entries == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    size_t count = collection->entries->count;
    if (count == 0)
        return 0;
    if (count > SIZE_MAX / sizeof(PreflightEntry *))
    {
        errno = E2BIG;
        return -1;
    }

    size_t order_size = count * sizeof(PreflightEntry *);
    PreflightEntry **order = preflight_alloc(&collection->memory, order_size);
    if (order == NULL)
        return -1;
    for (size_t index = 0; index < count; index++)
        order[index] = &collection->entries->items[index];

    /* Sidecar live-state iteration is hash-table order.  Profile collection
     * uses a sorted view so one pinned ancestor per destination root can serve
     * consecutive siblings without changing the retained entry order. */
    qsort(order, count, sizeof(*order), metadata_profile_order_compare);

    for (size_t index = 0; index < count; index++)
    {
        PreflightEntry *entry = order[index];
        int result = collect_metadata_profile(
            collection, &collection->manifest->roots[entry->root_index],
            entry->root_index, entry);
        preflight_progress_note(collection->progress, index + 1U, "entries", 0);
        if (result < -1)
        {
            int saved = errno;
            preflight_free(&collection->memory, order, order_size);
            errno = saved;
            return -1;
        }
    }

    preflight_free(&collection->memory, order, order_size);
    return 0;
}

static int collect_entry(const SidecarLiveView *view, void *argument)
{
    Collection *collection = argument;
    if (collection == NULL || view == NULL || view->entry == NULL)
        return 1;
    const SidecarEntry *entry = view->entry;
    PortableRestorePreflightReport *report = collection->report;
    if (report->live_count != SIZE_MAX)
        report->live_count++;

    size_t root_index = root_map_find(&collection->root_map,
                                      collection->manifest, entry->root_id);
    if (root_index == SIZE_MAX)
    {
        report_violation(report, SIZE_MAX, "external-root");
        return 0;
    }
    if (report->roots[root_index].live_count != SIZE_MAX)
        report->roots[root_index].live_count++;

    int logical_valid = sidecar_path_valid(entry->logical_path, 1);
    if (logical_valid <= 0)
    {
        report_violation(report, root_index, "invalid-path");
        if (logical_valid < 0)
            return 1;
        return 0;
    }
    size_t address_index = SIZE_MAX;
    int address_valid = restore_address_index_entry_valid(
        &collection->address_index, entry, &address_index);
    if (address_valid != 1)
    {
        report_violation(report, root_index, "physical-mismatch");
        return address_valid < 0 ? 1 : 0;
    }
    char logical[PATH_MAX];
    if (entry->logical_path.length >= sizeof(logical))
    {
        report_violation(report, root_index, "invalid-path");
        return 0;
    }
    if (entry->logical_path.length != 0)
        memcpy(logical, entry->logical_path.data, entry->logical_path.length);
    logical[entry->logical_path.length] = '\0';
    if (manifest_entry_owned(collection->manifest, (int)root_index,
                             logical) != 1)
    {
        report_violation(report, root_index, logical);
        return 0;
    }
    if (entry->kind != SIDECAR_KIND_REGULAR &&
        entry->kind != SIDECAR_KIND_DIRECTORY &&
        entry->kind != SIDECAR_KIND_SYMLINK &&
        entry->kind != SIDECAR_KIND_HARDLINK)
    {
        report_violation(report, root_index, "unsupported-kind");
        return 0;
    }
    if (entry->kind != SIDECAR_KIND_REGULAR &&
        entry->kind != SIDECAR_KIND_DIRECTORY && entry->size != 0)
    {
        report_violation(report, root_index, "invalid-size");
        return 0;
    }
    if (entry->kind == SIDECAR_KIND_REGULAR ||
        entry->kind == SIDECAR_KIND_DIRECTORY)
        portable_restore_estimate_add(report, entry->size);
    else if (entry->kind == SIDECAR_KIND_SYMLINK)
        portable_restore_estimate_add(report, entry->symlink_target.length);

    PreflightEntries *entries = collection->entries;
    if (entries == NULL)
        return 1;
    if (entries_reserve(&collection->memory, entries, 1) != 0)
        return 1;
    PreflightEntry *destination = &entries->items[entries->count];
    memset(destination, 0, sizeof(*destination));
    if (copy_sidecar_path(&collection->memory, entry->logical_path,
                          &destination->logical) != 0)
    {
        preflight_free(&collection->memory, destination->logical,
                       destination->logical == NULL ? 0
                           : strlen(destination->logical) + 1U);
        destination->logical = NULL;
        return 1;
    }
    destination->root_index = root_index;
    destination->address_index = address_index;
    destination->kind = entry->kind;
    destination->mode = entry->mode;
    destination->uid = entry->uid;
    destination->gid = entry->gid;
    destination->size = entry->size;
    entries->count++;

    int carries_security_xattr = 0;
    for (size_t xindex = 0; xindex < view->xattr_count; xindex++)
        if ((metadata_xattr_namespace_bytes(
                 view->xattrs[xindex].name.data,
                 view->xattrs[xindex].name.length) &
             METADATA_XATTR_NS_SECURITY) != 0)
        {
            carries_security_xattr = 1;
            break;
        }
    if (carries_security_xattr)
        metadata_profiles_note_security_xattr(&report->profiles);
    return 0;
}

static void collection_identity_entry(void *context, size_t index,
                                      DestinationIdentityEntryView *view)
{
    Collection *collection = context;
    PreflightEntry *entry = &collection->entries->items[index];
    view->root_index = entry->root_index;
    view->logical = (const unsigned char *)entry->logical;
    view->logical_length = strlen(entry->logical);
    view->claim = entry->kind == SIDECAR_KIND_DIRECTORY
        ? DESTINATION_IDENTITY_DIRECTORY
        : DESTINATION_IDENTITY_NON_DIRECTORY;
    view->placement = NULL;
}

static void collection_identity_failure(void *context, size_t index)
{
    Collection *collection = context;
    PreflightEntry *entry = &collection->entries->items[index];
    report_violation(collection->report, entry->root_index, entry->logical);
}

static void collection_identity_progress(void *context, size_t checked_count)
{
    Collection *collection = context;
    preflight_progress_note(collection->progress, checked_count, "identity", 0);
}

static int validate_destination_identity(Collection *collection)
{
    DestinationIdentityGraph graph;
    destination_identity_graph_init(&graph, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    DestinationIdentityStatus anchor_status =
        destination_identity_graph_register_anchor(
            &graph, collection->destination_home_fd);
    if (anchor_status != DESTINATION_IDENTITY_OK)
    {
        if (anchor_status == DESTINATION_IDENTITY_RESOURCE_ERROR &&
            errno == E2BIG)
            print_error("Error: Portable restore destination identity budget exceeded while registering destination HOME ancestry\n");
        else
            print_error("Error: Could not inspect destination HOME ancestry for portable restore\n");
        report_violation(collection->report, SIZE_MAX, "destination HOME");
        destination_identity_graph_free(&graph);
        return -1;
    }
    if (destination_identity_graph_add_entries(
            &graph, collection->manifest, collection->entries->count,
            collection->destination_home_fd,
            collection->destination_home_path,
            collection->destination_xdg_dirs, collection->xdg_anchor_fd,
            collection->xdg_anchor_prefix, collection_identity_entry,
            collection_identity_failure, collection_identity_progress,
            collection,
            DESTINATION_IDENTITY_AGGREGATE_COLLISIONS) != 0)
    {
        destination_identity_graph_free(&graph);
        return -1;
    }

    DestinationIdentityStatus status =
        destination_identity_graph_finalize(&graph);
    if (status != DESTINATION_IDENTITY_OK)
    {
        if (status == DESTINATION_IDENTITY_RESOURCE_ERROR && errno == E2BIG)
            print_error("Error: Portable restore destination identity budget exceeded while ordering the destination namespace\n");
        else
            print_error("Error: Could not order the portable restore destination namespace\n");
        report_violation(collection->report, SIZE_MAX,
                         "destination namespace");
        destination_identity_graph_free(&graph);
        return -1;
    }
    destination_identity_graph_free(&graph);
    return collection->report->violation_count == 0 ? 0 : -1;
}


static size_t root_order_lower_bound(const Collection *collection,
                                     const char *path)
{
    size_t left = 0;
    size_t right = collection->report->root_count;
    while (left < right)
    {
        size_t middle = left + (right - left) / 2U;
        const char *candidate = collection->manifest->roots[
            collection->root_order[middle]].payload_path;
        if (strcmp(candidate, path) < 0)
            left = middle + 1U;
        else
            right = middle;
    }
    return left;
}

static size_t root_order_find_exact(const Collection *collection,
                                    const char *path)
{
    size_t position = root_order_lower_bound(collection, path);
    if (position == collection->report->root_count)
        return SIZE_MAX;
    size_t root_index = collection->root_order[position];
    return strcmp(collection->manifest->roots[root_index].payload_path, path) == 0
        ? root_index : SIZE_MAX;
}

static int root_has_descendant(const Collection *collection, const char *path)
{
    if (collection->report->root_count == 0)
        return 0;
    size_t length = strlen(path);
    if (length == 0)
        return 1;
    /* All strings sharing path as a byte prefix form one contiguous block in
     * strcmp order; inspect that block until the prefix stops matching. */
    size_t position = root_order_lower_bound(collection, path);
    for (; position < collection->report->root_count; position++)
    {
        const char *candidate = collection->manifest->roots[
            collection->root_order[position]].payload_path;
        if (strncmp(candidate, path, length) != 0)
            break;
        if (candidate[length] == '/')
            return 1;
    }
    return 0;
}

static SidecarBytes manifest_root_id_bytes(const ManifestRoot *root)
{
    return (SidecarBytes){
        .data = (const unsigned char *)root->id,
        .length = strlen(root->id)
    };
}

static size_t payload_scan_worker_count(const PayloadInventory *inventory)
{
    if (inventory == NULL || inventory->collection == NULL)
        return 0;
    size_t entry_count = inventory->collection->address_index.count;
    if (entry_count < 2U)
        return 0;

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    if (portable_restore_preflight_test_payload_worker_count != SIZE_MAX)
    {
        size_t requested = portable_restore_preflight_test_payload_worker_count;
        if (requested > PAYLOAD_SCAN_MAX_WORKERS)
            requested = PAYLOAD_SCAN_MAX_WORKERS;
        return requested;
    }
#endif

    if (entry_count < PAYLOAD_SCAN_MIN_PARALLEL_ENTRIES)
        return 0;

    long online = sysconf(_SC_NPROCESSORS_ONLN);
    size_t workers = online > 0 ? (size_t)online : 2U;
    if (workers < 2U)
        workers = 2U;
    if (workers > PAYLOAD_SCAN_MAX_WORKERS)
        workers = PAYLOAD_SCAN_MAX_WORKERS;
    if (workers > entry_count)
        workers = entry_count;
    return workers;
}

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
static void payload_scan_test_delay(const PayloadScanWork *work)
{
    unsigned int delay_ms = portable_restore_preflight_test_payload_worker_delay_ms;
    if (delay_ms == 0 ||
        (portable_restore_preflight_test_delayed_payload_leaf[0] != '\0' &&
         (work == NULL ||
          strcmp(portable_restore_preflight_test_delayed_payload_leaf,
                 work->physical_leaf) != 0)))
        return;
    struct timespec delay = {
        .tv_sec = delay_ms / 1000U,
        .tv_nsec = (long)(delay_ms % 1000U) * 1000000L
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
    {
    }
}
#endif

static void payload_scan_work_execute(PayloadScanWork *work)
{
    work->status = PAYLOAD_SCAN_WORK_READY;
    work->failure_errno = 0;
    memset(&work->st, 0, sizeof(work->st));

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    payload_scan_test_delay(work);
#endif

    if (fstatat(work->parent_fd, work->physical_leaf, &work->st,
                AT_SYMLINK_NOFOLLOW) != 0)
    {
        work->status = PAYLOAD_SCAN_WORK_STAT_FAILURE;
        work->failure_errno = errno;
    }
}

static void *payload_scan_worker(void *argument)
{
    PayloadScanPool *pool = argument;
    for (;;)
    {
        int rc = pthread_mutex_lock(&pool->lock);
        if (rc != 0)
            abort();
        while (pool->queue_count == 0 && !pool->shutdown)
        {
            rc = pthread_cond_wait(&pool->task_ready, &pool->lock);
            if (rc != 0)
                abort();
        }
        if (pool->shutdown && pool->queue_count == 0)
        {
            if (pthread_mutex_unlock(&pool->lock) != 0)
                abort();
            return NULL;
        }

        size_t slot = pool->queue[pool->queue_head];
        pool->queue_head = (pool->queue_head + 1U) % PAYLOAD_SCAN_BATCH_SIZE;
        pool->queue_count--;
#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
        pool->active_workers++;
        if (pool->active_workers > pool->peak_workers)
            pool->peak_workers = pool->active_workers;
#endif
        if (pthread_mutex_unlock(&pool->lock) != 0)
            abort();

        payload_scan_work_execute(&pool->work[slot]);

        rc = pthread_mutex_lock(&pool->lock);
        if (rc != 0)
            abort();
#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
        if (pool->active_workers == 0)
            abort();
        pool->active_workers--;
#endif
        if (pool->pending == 0)
            abort();
        pool->pending--;
        if (pool->pending == 0)
            rc = pthread_cond_signal(&pool->batch_done);
        else
            rc = 0;
        if (rc != 0 || pthread_mutex_unlock(&pool->lock) != 0)
            abort();
    }
}

static void payload_scan_pool_stop(PayloadScanPool *pool)
{
    if (pool == NULL || !pool->initialized)
        return;
    int rc = pthread_mutex_lock(&pool->lock);
    if (rc != 0)
        abort();
    pool->shutdown = 1;
    rc = pthread_cond_broadcast(&pool->task_ready);
    int unlock_rc = pthread_mutex_unlock(&pool->lock);
    if (rc != 0 || unlock_rc != 0)
        abort();
    for (size_t index = 0; index < pool->workers_started; index++)
    {
        rc = pthread_join(pool->workers[index], NULL);
        if (rc != 0)
            abort();
    }
    rc = pthread_cond_destroy(&pool->batch_done);
    if (rc != 0)
        abort();
    rc = pthread_cond_destroy(&pool->task_ready);
    if (rc != 0)
        abort();
    rc = pthread_mutex_destroy(&pool->lock);
    if (rc != 0)
        abort();
    memset(pool, 0, sizeof(*pool));
}

static int payload_scan_pool_start(PayloadScanPool *pool,
                                   size_t worker_count)
{
    if (pool == NULL || worker_count < 2U ||
        worker_count > PAYLOAD_SCAN_MAX_WORKERS)
    {
        errno = EINVAL;
        return -1;
    }
    memset(pool, 0, sizeof(*pool));
    int rc = pthread_mutex_init(&pool->lock, NULL);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }
    rc = pthread_cond_init(&pool->task_ready, NULL);
    if (rc != 0)
    {
        (void)pthread_mutex_destroy(&pool->lock);
        errno = rc;
        return -1;
    }
    rc = pthread_cond_init(&pool->batch_done, NULL);
    if (rc != 0)
    {
        (void)pthread_cond_destroy(&pool->task_ready);
        (void)pthread_mutex_destroy(&pool->lock);
        errno = rc;
        return -1;
    }

    pool->initialized = 1;
    for (size_t index = 0; index < worker_count; index++)
    {
        rc = pthread_create(&pool->workers[index], NULL, payload_scan_worker,
                            pool);
        if (rc != 0)
        {
            int saved = rc;
            payload_scan_pool_stop(pool);
            errno = saved;
            return -1;
        }
        pool->workers_started++;
    }
    return 0;
}

static int payload_scan_pool_submit(PayloadScanPool *pool, size_t slot)
{
    if (pool == NULL || !pool->initialized || slot >= PAYLOAD_SCAN_BATCH_SIZE)
    {
        errno = EINVAL;
        return -1;
    }
    int rc = pthread_mutex_lock(&pool->lock);
    if (rc != 0)
        abort();
    if (pool->queue_count >= PAYLOAD_SCAN_BATCH_SIZE ||
        pool->pending >= PAYLOAD_SCAN_BATCH_SIZE)
    {
        if (pthread_mutex_unlock(&pool->lock) != 0)
            abort();
        errno = EBUSY;
        return -1;
    }
    size_t tail = (pool->queue_head + pool->queue_count) %
                  PAYLOAD_SCAN_BATCH_SIZE;
    pool->queue[tail] = slot;
    pool->queue_count++;
    pool->pending++;
    rc = pthread_cond_signal(&pool->task_ready);
    int unlock_rc = pthread_mutex_unlock(&pool->lock);
    if (rc != 0 || unlock_rc != 0)
        abort();
    return 0;
}

static int payload_scan_pool_wait(PayloadScanPool *pool)
{
    if (pool == NULL || !pool->initialized)
    {
        errno = EINVAL;
        return -1;
    }
    int rc = pthread_mutex_lock(&pool->lock);
    if (rc != 0)
        abort();
    while (pool->pending != 0)
    {
        rc = pthread_cond_wait(&pool->batch_done, &pool->lock);
        if (rc != 0)
            abort();
    }
    rc = pthread_mutex_unlock(&pool->lock);
    if (rc != 0)
        abort();
    return 0;
}

static void report_address_entry_violation(PayloadInventory *inventory,
                                           size_t root_index,
                                           const SidecarEntry *entry)
{
    if (entry == NULL || entry->logical_path.length >= PATH_MAX)
    {
        report_violation(inventory->collection->report, root_index,
                         "payload-address");
        return;
    }
    char logical[PATH_MAX];
    if (entry->logical_path.length != 0)
        memcpy(logical, entry->logical_path.data, entry->logical_path.length);
    logical[entry->logical_path.length] = '\0';
    report_violation(inventory->collection->report, root_index, logical);
}

static int mark_payload_entry(PayloadInventory *inventory, size_t root_index,
                              size_t address_index, const struct stat *st)
{
    const RestoreAddressIndex *addresses = &inventory->collection->address_index;
    if (address_index >= addresses->count || st == NULL ||
        addresses->entries[address_index].entry == NULL)
    {
        report_violation(inventory->collection->report, root_index,
                         "payload-address");
        return -1;
    }
    const SidecarEntry *entry = addresses->entries[address_index].entry;
    if (inventory->seen[address_index] != 0)
    {
        report_address_entry_violation(inventory, root_index, entry);
        return -1;
    }
    if (S_ISLNK(st->st_mode) ||
        (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)))
    {
        report_address_entry_violation(inventory, root_index, entry);
        return -1;
    }
    int is_directory = S_ISDIR(st->st_mode);
    if ((entry->kind == SIDECAR_KIND_DIRECTORY) != is_directory ||
        (entry->kind == SIDECAR_KIND_REGULAR &&
         (st->st_size < 0 || (uintmax_t)st->st_size != entry->size)))
    {
        report_address_entry_violation(inventory, root_index, entry);
        return -1;
    }
    inventory->seen[address_index] = 1;
    if (inventory->checked_count != SIZE_MAX)
        inventory->checked_count++;
    preflight_progress_note(inventory->progress, inventory->checked_count,
                            "payload", 0);
    return 0;
}

static int scan_root_payload_directory(PayloadInventory *inventory,
                                       int directory_fd, size_t root_index,
                                       SidecarBytes logical_parent);
static int scan_root_payload_node(PayloadInventory *inventory, int parent_fd,
                                  size_t root_index,
                                  SidecarBytes logical_parent,
                                  const char *physical_leaf);

static int payload_scan_process_batch(PayloadInventory *inventory,
                                      size_t batch_count)
{
    if (inventory == NULL || inventory->pool == NULL ||
        batch_count > PAYLOAD_SCAN_BATCH_SIZE)
    {
        errno = EINVAL;
        return -1;
    }
    if (batch_count == 0)
        return 0;
    if (payload_scan_pool_wait(inventory->pool) != 0)
        return -1;

    for (size_t index = 0; index < batch_count; index++)
    {
        PayloadScanWork *work = &inventory->pool->work[index];
        if (work->status == PAYLOAD_SCAN_WORK_STAT_FAILURE)
        {
            errno = work->failure_errno != 0 ? work->failure_errno : EIO;
            return -1;
        }
        if (work->status != PAYLOAD_SCAN_WORK_READY ||
            mark_payload_entry(inventory, work->root_index,
                               work->address_index, &work->st) != 0)
        {
            errno = EINVAL;
            return -1;
        }
    }
    return 0;
}

static int scan_root_payload_directory_parallel(
    PayloadInventory *inventory, int directory_fd, size_t root_index,
    SidecarBytes logical_parent)
{
    if (inventory == NULL || inventory->pool == NULL || directory_fd < 0)
    {
        errno = EINVAL;
        return -1;
    }

    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL)
    {
        int saved = errno;
        if (scan_fd >= 0)
            (void)close(scan_fd);
        errno = saved;
        return -1;
    }

    PayloadScanPool *pool = inventory->pool;
    const ManifestRoot *root = &inventory->collection->manifest->roots[root_index];
    size_t batch_count = 0;
    int result = 0;
    int saved = 0;
    for (;;)
    {
        if (batch_count >= PAYLOAD_SCAN_BATCH_SIZE - 1U)
        {
            if (payload_scan_process_batch(inventory, batch_count) != 0)
            {
                result = -1;
                saved = errno;
                break;
            }
            batch_count = 0;
        }

        errno = 0;
        struct dirent *dirent = readdir(directory);
        if (dirent == NULL)
        {
            saved = errno;
            if (payload_scan_process_batch(inventory, batch_count) != 0)
            {
                result = -1;
                saved = errno;
            }
            else if (saved != 0)
                result = -1;
            break;
        }
        if (strcmp(dirent->d_name, ".") == 0 ||
            strcmp(dirent->d_name, "..") == 0)
            continue;

        size_t name_length = strlen(dirent->d_name);
        if (!text_component_valid(dirent->d_name, name_length) ||
            name_length > SIDECAR_MAX_PHYSICAL_LEAF)
        {
            if (payload_scan_process_batch(inventory, batch_count) != 0)
                saved = errno;
            else
                saved = EINVAL;
            result = -1;
            break;
        }

        SidecarBytes leaf = {
            .data = (const unsigned char *)dirent->d_name,
            .length = name_length
        };
        size_t address_index = SIZE_MAX;
        /* The address index is fully built before payload inventory starts and
         * remains immutable until the pool has been joined. */
        int found = restore_address_index_find_physical(
            &inventory->collection->address_index,
            manifest_root_id_bytes(root), logical_parent, leaf,
            &address_index);
        if (found != 1)
        {
            if (payload_scan_process_batch(inventory, batch_count) != 0)
                saved = errno;
            else
            {
                report_violation(inventory->collection->report,
                                 root_index, dirent->d_name);
                saved = found < 0 ? errno : EINVAL;
            }
            result = -1;
            break;
        }

        const SidecarEntry *address_entry =
            inventory->collection->address_index.entries[address_index].entry;
        if (address_entry == NULL)
        {
            if (payload_scan_process_batch(inventory, batch_count) != 0)
                saved = errno;
            else
            {
                report_violation(inventory->collection->report, root_index,
                                 "payload-address");
                saved = EINVAL;
            }
            result = -1;
            break;
        }

        if (address_entry->kind == SIDECAR_KIND_DIRECTORY)
        {
            if (payload_scan_process_batch(inventory, batch_count) != 0)
            {
                result = -1;
                saved = errno;
                break;
            }
            batch_count = 0;
            if (scan_root_payload_node(inventory, directory_fd, root_index,
                                       logical_parent, dirent->d_name) != 0)
            {
                result = -1;
                saved = errno;
                break;
            }
            continue;
        }

        PayloadScanWork *work = &pool->work[batch_count];
        memset(work, 0, sizeof(*work));
        work->parent_fd = directory_fd;
        work->root_index = root_index;
        work->address_index = address_index;
        memcpy(work->physical_leaf, dirent->d_name, name_length + 1U);
        if (payload_scan_pool_submit(pool, batch_count) != 0)
        {
            int submit_error = errno;
            if (payload_scan_process_batch(inventory, batch_count) != 0)
                submit_error = errno;
            result = -1;
            saved = submit_error;
            break;
        }
        batch_count++;

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
        if (portable_restore_preflight_test_duplicate_payload_leaf[0] != '\0' &&
            strcmp(portable_restore_preflight_test_duplicate_payload_leaf,
                   dirent->d_name) == 0)
        {
            PayloadScanWork *duplicate = &pool->work[batch_count];
            memset(duplicate, 0, sizeof(*duplicate));
            duplicate->parent_fd = directory_fd;
            duplicate->root_index = root_index;
            duplicate->address_index = address_index;
            memcpy(duplicate->physical_leaf, dirent->d_name,
                   name_length + 1U);
            if (payload_scan_pool_submit(pool, batch_count) != 0)
            {
                int submit_error = errno;
                if (payload_scan_process_batch(inventory, batch_count) != 0)
                    submit_error = errno;
                result = -1;
                saved = submit_error;
                break;
            }
            batch_count++;
        }
#endif
    }

    if (closedir(directory) != 0 && result == 0)
    {
        result = -1;
        saved = errno != 0 ? errno : EIO;
    }
    if (result != 0)
        errno = saved != 0 ? saved : EIO;
    return result;
}

static int scan_root_payload_node(PayloadInventory *inventory, int parent_fd,
                                  size_t root_index,
                                  SidecarBytes logical_parent,
                                  const char *physical_leaf)
{
    const ManifestRoot *root = &inventory->collection->manifest->roots[root_index];
    SidecarBytes leaf = {
        .data = (const unsigned char *)physical_leaf,
        .length = strlen(physical_leaf)
    };
    size_t address_index = SIZE_MAX;
    int found = restore_address_index_find_physical(
        &inventory->collection->address_index, manifest_root_id_bytes(root),
        logical_parent, leaf, &address_index);
    if (found != 1)
    {
        report_violation(inventory->collection->report, root_index,
                         physical_leaf);
        return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, physical_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        mark_payload_entry(inventory, root_index, address_index, &st) != 0)
        return -1;
    const SidecarEntry *entry = inventory->collection->address_index
                                    .entries[address_index].entry;
    if (entry->kind != SIDECAR_KIND_DIRECTORY)
        return 0;

    int child_fd = openat(parent_fd, physical_leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
    if (child_fd < 0)
        return -1;
    int result = scan_root_payload_directory(inventory, child_fd, root_index,
                                             entry->logical_path);
    int saved = errno;
    if (close(child_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int scan_root_payload_directory(PayloadInventory *inventory,
                                       int directory_fd, size_t root_index,
                                       SidecarBytes logical_parent)
{
    if (inventory != NULL && inventory->pool != NULL)
        return scan_root_payload_directory_parallel(
            inventory, directory_fd, root_index, logical_parent);

    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    int result = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL)
        {
            if (errno != 0)
                result = -1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        size_t name_length = strlen(entry->d_name);
        if (!text_component_valid(entry->d_name, name_length))
        {
            result = -1;
            break;
        }
        if (scan_root_payload_node(inventory, directory_fd, root_index,
                                   logical_parent, entry->d_name) != 0)
        {
            result = -1;
            break;
        }
    }
    if (closedir(directory) != 0)
        result = -1;
    return result;
}

static int scan_root_anchor(PayloadInventory *inventory, int parent_fd,
                            const char *name, size_t root_index,
                            const struct stat *st)
{
    const ManifestRoot *root = &inventory->collection->manifest->roots[root_index];
    size_t address_index = SIZE_MAX;
    int found = restore_address_index_find_logical(
        &inventory->collection->address_index, manifest_root_id_bytes(root),
        (SidecarBytes){0}, &address_index);
    if (found != 1 ||
        mark_payload_entry(inventory, root_index, address_index, st) != 0)
        return -1;
    const SidecarEntry *entry = inventory->collection->address_index
                                    .entries[address_index].entry;
    if (entry->kind != SIDECAR_KIND_DIRECTORY)
        return 0;
    int child_fd = openat(parent_fd, name,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
    if (child_fd < 0)
        return -1;
    int result = scan_root_payload_directory(inventory, child_fd, root_index,
                                             entry->logical_path);
    int saved = errno;
    if (close(child_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int scan_root_namespace_directory(PayloadInventory *inventory,
                                         int directory_fd,
                                         size_t path_length);

static int scan_root_namespace_node(PayloadInventory *inventory, int parent_fd,
                                    const char *name, size_t path_length)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    size_t root_index = root_order_find_exact(
        inventory->collection, inventory->root_namespace_path);
    if (root_index != SIZE_MAX)
        return scan_root_anchor(inventory, parent_fd, name, root_index, &st);

    if (!root_has_descendant(inventory->collection,
                             inventory->root_namespace_path) ||
        !S_ISDIR(st.st_mode))
    {
        report_violation(inventory->collection->report, SIZE_MAX,
                         inventory->root_namespace_path);
        return -1;
    }
    int child_fd = openat(parent_fd, name,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
    if (child_fd < 0)
        return -1;
    int result = scan_root_namespace_directory(inventory, child_fd,
                                               path_length);
    int saved = errno;
    if (close(child_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int scan_root_namespace_directory(PayloadInventory *inventory,
                                         int directory_fd,
                                         size_t path_length)
{
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    int result = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL)
        {
            if (errno != 0)
                result = -1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        size_t name_length = strlen(entry->d_name);
        if (!text_component_valid(entry->d_name, name_length) ||
            path_length > PATH_MAX - name_length - 2U)
        {
            result = -1;
            break;
        }
        size_t child_length = path_length;
        if (child_length != 0)
            inventory->root_namespace_path[child_length++] = '/';
        memcpy(inventory->root_namespace_path + child_length, entry->d_name,
               name_length + 1U);
        if (scan_root_namespace_node(inventory, directory_fd, entry->d_name,
                                     child_length + name_length) != 0)
        {
            result = -1;
            break;
        }
        inventory->root_namespace_path[path_length] = '\0';
    }
    if (closedir(directory) != 0)
        result = -1;
    return result;
}

static int scan_payload_inventory(PayloadInventory *inventory)
{
    if (inventory == NULL || inventory->data_fd < 0)
        return -1;

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    portable_restore_preflight_test_last_payload_peak_workers = 0;
    portable_restore_preflight_test_last_payload_checked_count = 0;
#endif

    PayloadScanPool pool;
    memset(&pool, 0, sizeof(pool));
    size_t worker_count = payload_scan_worker_count(inventory);
    if (worker_count >= 2U &&
        payload_scan_pool_start(&pool, worker_count) == 0)
        inventory->pool = &pool;

    int result = scan_root_namespace_directory(
        inventory, inventory->data_fd, 0);

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
    if (inventory->pool != NULL)
        portable_restore_preflight_test_last_payload_peak_workers =
            pool.peak_workers;
    portable_restore_preflight_test_last_payload_checked_count =
        inventory->checked_count;
#endif

    if (inventory->pool != NULL)
    {
        inventory->pool = NULL;
        payload_scan_pool_stop(&pool);
    }
    if (result != 0)
        return -1;

    const RestoreAddressIndex *addresses = &inventory->collection->address_index;
    for (size_t index = 0; index < addresses->count; index++)
        if (inventory->seen[index] == 0)
        {
            const SidecarEntry *entry = addresses->entries[index].entry;
            size_t root_index = root_map_find(
                &inventory->collection->root_map,
                inventory->collection->manifest, entry->root_id);
            report_address_entry_violation(inventory, root_index, entry);
            inventory->failed = 1;
        }
    return inventory->failed ? -1 : 0;
}

static void report_print(const PortableRestorePreflightReport *report)
{
    if (report == NULL || report->violation_count == 0)
        return;
    printf("Portable restore preflight refused: %zu violation(s), %zu live entr%s\n",
           report->violation_count, report->live_count,
           report->live_count == 1 ? "y" : "ies");
    for (size_t index = 0; index < report->root_count; index++)
        if (report->roots[index].live_count != 0 ||
            report->roots[index].violation_count != 0)
            printf("  root %s: %zu live, %zu violation(s)\n",
                   report->roots[index].id,
                   report->roots[index].live_count,
                   report->roots[index].violation_count);
    for (size_t index = 0; index < report->profiles.example_count; index++)
        printf("  preflight example: %s\n",
               report->profiles.examples[index]);
    if (report->profiles.example_count == METADATA_MAX_PREFLIGHT_EXAMPLES)
        printf("  ... additional examples omitted\n");
}

static void collection_free(Collection *collection, PreflightEntries *entries)
{
    if (collection == NULL)
        return;
    destination_profile_cache_invalidate(&collection->home_profile_cache);
    for (int index = 0; index < XDG_KEY_COUNT; index++)
    {
        destination_profile_cache_invalidate(
            &collection->xdg_profile_cache[index]);
        if (collection->xdg_anchor_fd[index] >= 0)
        {
            (void)close(collection->xdg_anchor_fd[index]);
            collection->xdg_anchor_fd[index] = -1;
        }
    }
    entries_free(&collection->memory, entries);
    preflight_free(&collection->memory, collection->root_order,
                   collection->report == NULL ? 0
                       : collection->report->root_count * sizeof(size_t));
    collection->root_order = NULL;
    restore_address_index_free(&collection->memory,
                               &collection->address_index);
    root_map_free(&collection->root_map);
}

void portable_restore_preflight_report_init(
    PortableRestorePreflightReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
    metadata_profiles_init(&report->profiles);
}

void portable_restore_preflight_report_free(
    PortableRestorePreflightReport *report)
{
    if (report == NULL)
        return;
    free(report->roots);
    report->roots = NULL;
    metadata_profiles_free(&report->profiles);
    memset(report, 0, sizeof(*report));
}

int portable_restore_preflight_at(
    const PortableRestoreRequest *request,
    PortableRestorePreflightReport *report)
{
    if (request == NULL || report == NULL || request->source_container_fd < 0 ||
        request->destination_home_fd < 0 || request->manifest == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    struct stat home_st;
    if (fstat(request->destination_home_fd, &home_st) != 0 ||
        !S_ISDIR(home_st.st_mode))
    {
        errno = ENOTDIR;
        return -1;
    }

    PreflightEntries entries = {0};
    RestorePreflightProgress progress = {0};
    Collection collection = {
        .manifest = request->manifest,
        .report = report,
        .entries = &entries,
        .destination_home_fd = request->destination_home_fd,
        .destination_home_path = request->destination_home_path,
        .destination_xdg_dirs = request->destination_xdg_dirs,
        .progress = &progress
    };
    destination_profile_cache_init(&collection.home_profile_cache);
    for (int index = 0; index < XDG_KEY_COUNT; index++)
    {
        collection.xdg_anchor_fd[index] = -1;
        destination_profile_cache_init(&collection.xdg_profile_cache[index]);
    }
    if (collection_validate_manifest(&collection) != 0)
        goto fail;

    int data_fd = openat(request->source_container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                             O_NOATIME | O_CLOEXEC);
    if (data_fd < 0)
        goto fail;

    /* Adoption repairs a truncated EOF tail in place.  Preflight is a
     * rejection-only gate, so require a complete sidecar before opening the
     * state log through that API. */
    if (sidecar_is_complete_readonly(request->source_container_fd) != 0)
    {
        close(data_fd);
        report_violation(report, SIZE_MAX, "sidecar");
        goto fail;
    }

    SidecarLog sidecar = {0};
    SidecarOpenStatus sidecar_status = sidecar_log_adopt_at(
        request->source_container_fd, &sidecar);
    if (sidecar_status != SIDECAR_OPEN_RESUMABLE)
    {
        close(data_fd);
        errno = EINVAL;
        goto fail;
    }
    if (sidecar_log_claim_count(&sidecar) != 0)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        report_violation(report, SIZE_MAX, "sidecar");
        goto fail;
    }

    size_t sidecar_live_count = sidecar_log_live_count(&sidecar);
    preflight_progress_start(&progress, sidecar_live_count, "entries");
    if (restore_address_index_build(&collection.address_index,
                                    &collection.memory, &sidecar, NULL) != 0)
    {
        report_violation(report, SIZE_MAX, "sidecar-address");
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }
    SidecarStatus status = sidecar_log_foreach(&sidecar, collect_entry,
                                               &collection);
    if (status != SIDECAR_STATUS_OK)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }
    if (collect_metadata_profiles(&collection) != 0)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }
    for (size_t index = 0; index < report->root_count; index++)
        if (report->roots[index].live_count == 0)
        {
            report_violation(report, index, report->roots[index].id);
        }
        else
            report->mapped_root_count++;
    preflight_progress_note(&progress, 0, "identity", 1);
    if (validate_destination_identity(&collection) != 0)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }
    if (report->violation_count != 0)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }

    unsigned char *seen = calloc(collection.address_index.count == 0
                                     ? 1 : collection.address_index.count,
                                 1);
    if (seen == NULL)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }
    preflight_progress_note(&progress, 0, "payload", 1);
    PayloadInventory inventory = {
        .data_fd = data_fd,
        .collection = &collection,
        .seen = seen,
        .progress = &progress
    };
    int result = scan_payload_inventory(&inventory);
    preflight_progress_finish(&progress, inventory.checked_count, "payload");
    free(seen);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (close(data_fd) != 0)
        result = -1;
    if (result != 0)
        goto fail;
    collection_free(&collection, &entries);
    return report->violation_count == 0 ? 0 : (report_print(report), -1);

fail:
    preflight_progress_cancel(&progress);
    collection_free(&collection, &entries);
    if (report->violation_count == 0)
        report_violation(report, SIZE_MAX, "preflight");
    report_print(report);
    return -1;
}
