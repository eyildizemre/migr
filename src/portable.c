#define _GNU_SOURCE

#include "portable.h"
#include "portable_hashset_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <signal.h>
#include <unistd.h>

#include "encoding.h"
#include "metadata.h"
#include "utils.h"

typedef struct {
    char *root_id;
    char *physical_path;
    char *logical_path;
} PortableOwnedPath;

typedef struct {
    PortableOwnedPath *items;
    size_t count;
    size_t capacity;
    int sorted;
} PortableOwnedPaths;

typedef struct {
    char *root_id;
    char *physical_path;
    char *logical_path;
} PortableClaimedPath;

typedef struct {
    PortableClaimedPath *items;
    size_t count;
    size_t capacity;
    int sorted;
} PortableClaimedPaths;

#define PORTABLE_MAX_READBACK_NAMES SIDECAR_MAX_LIVE_ENTRIES

void portable_prescan_report_init(PortablePrescanReport *report)
{
    if (report != NULL)
        memset(report, 0, sizeof(*report));
}

void portable_prescan_report_free(PortablePrescanReport *report)
{
    if (report == NULL)
        return;
    free(report->examples);
    portable_collision_plan_free(&report->collision_plan);
    if (report->inode_seen != NULL)
    {
        prescan_inode_set_free(report->inode_seen);
        report->inode_seen = NULL;
    }
    memset(report, 0, sizeof(*report));
}

int prescan_report_add(PortablePrescanReport *report,
                       const PortablePrescanViolation *violation)
{
    if (report == NULL || violation == NULL)
        return -1;
    if (report->total_count != SIZE_MAX)
        report->total_count++;
    if (report->example_count >= PORTABLE_PRESCAN_MAX_EXAMPLES)
        return 0;

    if (report->example_count == report->example_capacity) {
        size_t capacity = report->example_capacity == 0
            ? 8U : report->example_capacity * 2U;
        if (capacity > PORTABLE_PRESCAN_MAX_EXAMPLES)
            capacity = PORTABLE_PRESCAN_MAX_EXAMPLES;
        PortablePrescanViolation *examples = realloc(
            report->examples, capacity * sizeof(*examples));
        if (examples == NULL)
            return -1;
        report->examples = examples;
        report->example_capacity = capacity;
    }
    report->examples[report->example_count++] = *violation;
    return 0;
}

static void prescan_report_refresh_unresolved(PortablePrescanReport *report)
{
    if (report == NULL || report->total_count < report->collision_count)
        return;
    report->unresolved_count = report->total_count - report->collision_count;
}

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static uint64_t portable_test_probe_count;
static uint64_t portable_test_readback_scan_count;
static uint64_t portable_test_case_probe_count;
static uint64_t portable_test_case_fs_probe_count;
static uint64_t portable_test_relocation_scan_count;
static uint64_t portable_test_relocation_remove_count;
static uint64_t portable_test_inode_map_probe_count;
static uint64_t portable_test_prescan_inode_probe_count;
static uint64_t portable_test_sticky_seed_lstat_count;

void visited_count_probe(void)
{
    if (portable_test_probe_count != UINT64_MAX)
        portable_test_probe_count++;
}

uint64_t portable_capture_test_probe_count(void)
{
    return portable_test_probe_count;
}

void portable_capture_test_reset_probe_count(void)
{
    portable_test_probe_count = 0;
}

uint64_t portable_capture_test_readback_scan_count(void)
{
    return portable_test_readback_scan_count;
}

void portable_capture_test_reset_readback_scan_count(void)
{
    portable_test_readback_scan_count = 0;
}

uint64_t portable_capture_test_case_probe_count(void)
{
    return portable_test_case_probe_count;
}

void portable_capture_test_reset_case_probe_count(void)
{
    portable_test_case_probe_count = 0;
}

uint64_t portable_capture_test_case_fs_probe_count(void)
{
    return portable_test_case_fs_probe_count;
}

void portable_capture_test_reset_case_fs_probe_count(void)
{
    portable_test_case_fs_probe_count = 0;
}

uint64_t portable_capture_test_inode_map_probe_count(void)
{
    return portable_test_inode_map_probe_count;
}

void portable_capture_test_reset_inode_map_probe_count(void)
{
    portable_test_inode_map_probe_count = 0;
}

uint64_t portable_capture_test_prescan_inode_probe_count(void)
{
    return portable_test_prescan_inode_probe_count;
}

void portable_capture_test_reset_prescan_inode_probe_count(void)
{
    portable_test_prescan_inode_probe_count = 0;
}

uint64_t portable_capture_test_sticky_seed_lstat_count(void)
{
    return portable_test_sticky_seed_lstat_count;
}

void portable_capture_test_reset_sticky_seed_lstat_count(void)
{
    portable_test_sticky_seed_lstat_count = 0;
}

uint64_t portable_capture_test_relocation_scan_count(void)
{
    return portable_test_relocation_scan_count;
}

void portable_capture_test_reset_relocation_scan_count(void)
{
    portable_test_relocation_scan_count = 0;
    portable_test_relocation_remove_count = 0;
}

uint64_t portable_capture_test_relocation_remove_count(void)
{
    return portable_test_relocation_remove_count;
}

static void case_probe_count(void)
{
    if (portable_test_case_probe_count != UINT64_MAX)
        portable_test_case_probe_count++;
}

static void case_fs_probe_count(void)
{
    if (portable_test_case_fs_probe_count != UINT64_MAX)
        portable_test_case_fs_probe_count++;
}

void inode_map_count_probe(void)
{
    if (portable_test_inode_map_probe_count != UINT64_MAX)
        portable_test_inode_map_probe_count++;
}

void prescan_inode_count_probe(void)
{
    if (portable_test_prescan_inode_probe_count != UINT64_MAX)
        portable_test_prescan_inode_probe_count++;
}

static void sticky_seed_count_lstat(void)
{
    if (portable_test_sticky_seed_lstat_count != UINT64_MAX)
        portable_test_sticky_seed_lstat_count++;
}

static void relocation_scan_count(void)
{
    if (portable_test_relocation_scan_count != UINT64_MAX)
        portable_test_relocation_scan_count++;
}

static void relocation_remove_count(void)
{
    if (portable_test_relocation_remove_count != UINT64_MAX)
        portable_test_relocation_remove_count++;
}
#else
void visited_count_probe(void)
{
}

static void case_probe_count(void)
{
}

static void case_fs_probe_count(void)
{
}

void inode_map_count_probe(void)
{
}

void prescan_inode_count_probe(void)
{
}

static void sticky_seed_count_lstat(void)
{
}

static void relocation_scan_count(void)
{
}

static void relocation_remove_count(void)
{
}
#endif

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static void portable_readback_scan_count(void)
{
    if (portable_test_readback_scan_count != UINT64_MAX)
        portable_test_readback_scan_count++;
}
#else
static void portable_readback_scan_count(void)
{
}
#endif

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static volatile sig_atomic_t portable_test_interrupt_point =
    PORTABLE_TEST_INTERRUPT_NONE;

void portable_capture_test_set_interrupt(PortableTestInterruptPoint point)
{
    portable_test_interrupt_point = point;
}

static void portable_test_interrupt_if(PortableTestInterruptPoint point)
{
    if (portable_test_interrupt_point == (sig_atomic_t)point)
        (void)kill(getpid(), SIGKILL);
}
#else
static void portable_test_interrupt_if(int point)
{
    (void)point;
}
#endif

static size_t bounded_strlen(const char *value, size_t maximum)
{
    if (value == NULL)
        return 0;
    return strnlen(value, maximum + 1U);
}

static int copy_text(char *destination, size_t destination_size,
                     const char *source)
{
    if (destination == NULL || destination_size == 0 || source == NULL)
        return -1;
    size_t length = bounded_strlen(source, destination_size - 1U);
    if (length >= destination_size)
        return -1;
    memcpy(destination, source, length + 1U);
    return 0;
}

void portable_collision_plan_init(PortableCollisionPlan *plan)
{
    if (plan != NULL)
        memset(plan, 0, sizeof(*plan));
}

void portable_collision_plan_free(PortableCollisionPlan *plan)
{
    if (plan == NULL)
        return;
    free(plan->entries);
    memset(plan, 0, sizeof(*plan));
}

static int portable_collision_plan_compare(const void *left, const void *right)
{
    const PortableCollisionPlanEntry *left_entry = left;
    const PortableCollisionPlanEntry *right_entry = right;
    int root_result = strcmp(left_entry->root_id, right_entry->root_id);
    if (root_result != 0)
        return root_result;
    return strcmp(left_entry->logical_path, right_entry->logical_path);
}

static void portable_collision_plan_sort(PortableCollisionPlan *plan)
{
    if (plan == NULL || plan->sorted)
        return;
    if (plan->count > 1U)
        qsort(plan->entries, plan->count, sizeof(*plan->entries),
              portable_collision_plan_compare);
    plan->sorted = 1;
}

static int prescan_record_violation(PortablePrescanReport *report,
                                    const char *root_id,
                                    const char *logical_path,
                                    PortablePrescanViolationKind kind,
                                    size_t limit, size_t actual);
int append_physical(char *destination, size_t destination_size,
                    const char *parent, const char *encoded_leaf);
void skeleton_copy(char *destination, size_t destination_size,
                   const char *source);

static const PortableRootSpec *portable_collision_plan_root(
    const PortableCaptureRequest *request, const char *root_id)
{
    if (request == NULL || root_id == NULL)
        return NULL;
    for (size_t index = 0; index < request->root_count; index++)
        if (strcmp(request->roots[index].id, root_id) == 0)
            return &request->roots[index];
    return NULL;
}

static int portable_collision_plan_rewrite_parents(
    PortablePrescanReport *report, const PortableCaptureRequest *request)
{
    if (report == NULL || request == NULL)
        return -1;
    PortableCollisionPlan *plan = &report->collision_plan;
    if (!plan->sorted)
        portable_collision_plan_sort(plan);

    /* Recursion discovers child groups before its parent receives a suffix.
     * Rebind descendants to the nearest planned ancestor after the complete
     * deterministic plan is sorted (docs/DECISIONS.md D21, F-3). */
    for (size_t index = 0; index < plan->count; index++) {
        PortableCollisionPlanEntry *entry = &plan->entries[index];
        const char *slash = strrchr(entry->logical_path, '/');
        if (slash == NULL)
            continue;

        char parent_logical[SIDECAR_MAX_PATH + 1U];
        size_t parent_length = (size_t)(slash - entry->logical_path);
        const PortableCollisionPlanEntry *parent = NULL;
        while (parent_length != 0) {
            if (parent_length > SIDECAR_MAX_PATH)
                return -1;
            memcpy(parent_logical, entry->logical_path, parent_length);
            parent_logical[parent_length] = '\0';
            parent = portable_collision_plan_find(
                plan, entry->root_id, parent_logical);
            if (parent != NULL)
                break;
            const char *previous_slash = strrchr(parent_logical, '/');
            parent_length = previous_slash == NULL
                ? 0U
                : (size_t)(previous_slash - parent_logical);
        }
        if (parent == NULL)
            continue;

        size_t ancestor_depth = 1U;
        for (const char *cursor = parent_logical; *cursor != '\0'; cursor++)
            if (*cursor == '/')
                ancestor_depth++;
        const char *leaf = entry->physical_path;
        for (size_t component = 0; component < ancestor_depth; component++) {
            const char *component_slash = strchr(leaf, '/');
            if (component_slash == NULL)
                return -1;
            leaf = component_slash + 1;
        }
        if (*leaf == '\0')
            return -1;

        char rewritten[SIDECAR_MAX_PATH + 1U];
        if (append_physical(rewritten, sizeof(rewritten), parent->physical_path,
                            leaf) != 0)
            return -1;
        const PortableRootSpec *root =
            portable_collision_plan_root(request, entry->root_id);
        if (root == NULL)
            return -1;
        size_t payload_length = strlen(root->payload_path);
        size_t physical_length = strlen(rewritten);
        if (payload_length > SIZE_MAX - 1U ||
            physical_length > SIZE_MAX - payload_length - 1U)
            return -1;
        size_t actual_path = payload_length + 1U + physical_length;
        if (actual_path >= PATH_MAX) {
            if (prescan_record_violation(
                    report, entry->root_id, entry->logical_path,
                    PORTABLE_PRESCAN_PATH_TOO_LONG, PATH_MAX,
                    actual_path) != 0)
                return -1;
            return -1;
        }
        if (copy_text(entry->physical_path, sizeof(entry->physical_path),
                      rewritten) != 0)
            return -1;
    }
    return 0;
}

static int portable_collision_plan_add(PortableCollisionPlan *plan,
                                       const char *root_id,
                                       const char *logical_path,
                                       const char *physical_path,
                                       const char *collision_suffix)
{
    if (plan == NULL || root_id == NULL || logical_path == NULL ||
        physical_path == NULL || collision_suffix == NULL ||
        plan->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;

    if (plan->count == plan->capacity) {
        size_t capacity = plan->capacity == 0 ? 8U : plan->capacity * 2U;
        if (capacity < plan->capacity ||
            capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity > SIZE_MAX / sizeof(*plan->entries))
            return -1;
        PortableCollisionPlanEntry *entries = realloc(
            plan->entries, capacity * sizeof(*entries));
        if (entries == NULL)
            return -1;
        plan->entries = entries;
        plan->capacity = capacity;
    }

    PortableCollisionPlanEntry *entry = &plan->entries[plan->count];
    memset(entry, 0, sizeof(*entry));
    if (copy_text(entry->root_id, sizeof(entry->root_id), root_id) != 0 ||
        copy_text(entry->logical_path, sizeof(entry->logical_path),
                  logical_path) != 0 ||
        copy_text(entry->physical_path, sizeof(entry->physical_path),
                  physical_path) != 0 ||
        copy_text(entry->collision_suffix, sizeof(entry->collision_suffix),
                  collision_suffix) != 0)
        return -1;
    plan->count++;
    plan->sorted = 0;
    return 0;
}

const PortableCollisionPlanEntry *portable_collision_plan_find(
    const PortableCollisionPlan *plan, const char *root_id,
    const char *logical_path)
{
    if (plan == NULL || root_id == NULL || logical_path == NULL ||
        !plan->sorted)
        return NULL;

    size_t low = 0;
    size_t high = plan->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        const PortableCollisionPlanEntry *entry = &plan->entries[middle];
        int root_result = strcmp(entry->root_id, root_id);
        if (root_result < 0 ||
            (root_result == 0 &&
             strcmp(entry->logical_path, logical_path) < 0))
            low = middle + 1U;
        else
            high = middle;
    }
    if (low < plan->count &&
        strcmp(plan->entries[low].root_id, root_id) == 0 &&
        strcmp(plan->entries[low].logical_path, logical_path) == 0)
        return &plan->entries[low];
    return NULL;
}

static int safe_id(const char *id)
{
    if (id == NULL || id[0] == '\0' || strlen(id) >= MANIFEST_ID_MAX)
        return 0;
    for (size_t index = 0; id[index] != '\0'; index++)
        if (!(id[index] >= 'a' && id[index] <= 'z') &&
            !(id[index] >= 'A' && id[index] <= 'Z') &&
            !(id[index] >= '0' && id[index] <= '9') &&
            id[index] != '_' && id[index] != '-')
            return 0;
    return 1;
}

int portable_component_valid(const char *component, size_t length)
{
    return component != NULL && length != 0 && length <= NAME_MAX &&
           memchr(component, '/', length) == NULL &&
           memchr(component, '\0', length) == NULL &&
           !(length == 1 && component[0] == '.') &&
           !(length == 2 && component[0] == '.' && component[1] == '.');
}

int portable_relative_bytes_valid(const char *data, size_t length,
                                  int allow_empty)
{
    if (length >= PATH_MAX || (length != 0 && data == NULL))
        return 0;
    if (length == 0)
        return allow_empty;
    if (data[0] == '/' || data[length - 1U] == '/')
        return 0;

    size_t component_start = 0;
    for (size_t index = 0; index <= length; index++)
    {
        if (index != length && data[index] != '/')
            continue;
        if (!portable_component_valid(data + component_start,
                                      index - component_start))
            return 0;
        component_start = index + 1U;
    }
    return 1;
}

static int safe_component(const char *component)
{
    return component != NULL &&
           portable_component_valid(component, strlen(component));
}

static int safe_relative_path(const char *path)
{
    if (path == NULL || path[0] == '\0' || path[0] == '/')
        return 0;
    size_t length = bounded_strlen(path, PATH_MAX);
    return portable_relative_bytes_valid(path, length, 0);
}

int portable_payload_path_fits(size_t root_length, size_t physical_length,
                               size_t capacity)
{
    return root_length != 0 && root_length < capacity &&
           physical_length <= capacity - root_length - 1U;
}

int portable_collision_suffix_parse(const char *data, size_t length,
                                    uint64_t *out_value)
{
    if (data == NULL || out_value == NULL || length < 4U ||
        length > SIDECAR_MAX_COLLISION_SUFFIX || data[0] != '%' ||
        data[1] != '7' || data[2] != 'E' || data[3] < '1' ||
        data[3] > '9')
        return 0;

    uint64_t value = (uint64_t)(data[3] - '0');
    for (size_t index = 4U; index < length; index++)
    {
        if (data[index] < '0' || data[index] > '9' ||
            value > (UINT64_MAX - (uint64_t)(data[index] - '0')) /
                UINT64_C(10))
            return 0;
        value = value * UINT64_C(10) +
                (uint64_t)(data[index] - '0');
    }
    *out_value = value;
    return value != 0;
}

static int append_logical(char *destination, size_t destination_size,
                          const char *parent, const char *name)
{
    if (destination == NULL || parent == NULL || !safe_component(name))
        return -1;
    size_t parent_length = bounded_strlen(parent, destination_size);
    size_t name_length = strlen(name);
    if (parent_length >= destination_size ||
        name_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0) {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, name, name_length + 1U);
    return 0;
}

int append_physical(char *destination, size_t destination_size,
                    const char *parent, const char *encoded_leaf)
{
    if (destination == NULL || parent == NULL || encoded_leaf == NULL)
        return -1;
    size_t parent_length = bounded_strlen(parent, destination_size);
    size_t leaf_length = strlen(encoded_leaf);
    if (parent_length >= destination_size ||
        leaf_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0) {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, encoded_leaf, leaf_length + 1U);
    return 0;
}

static int open_child_directory(int parent_fd, const char *name)
{
    return openat(parent_fd, name,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int remove_leaf(int parent_fd, const char *name);

static int remove_directory_tree(int parent_fd, const char *name)
{
    int directory_fd = openat(parent_fd, name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (remove_leaf(directory_fd, entry->d_name) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    if (failed)
        return -1;
    return unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 ? 0 : -1;
}

static int remove_leaf(int parent_fd, const char *name)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (S_ISDIR(st.st_mode))
        return remove_directory_tree(parent_fd, name);
    return unlinkat(parent_fd, name, 0) == 0 ? 0 : -1;
}

int portable_open_relative_parent(int base_fd, const char *relative,
                                  int *parent_out, char *leaf,
                                  size_t leaf_size)
{
    if (base_fd < 0 || relative == NULL || parent_out == NULL ||
        leaf == NULL || leaf_size == 0 ||
        (relative[0] != '\0' && !safe_relative_path(relative)))
    {
        errno = EINVAL;
        return -1;
    }

    int current = dup_cloexec(base_fd);
    if (current < 0)
        return -1;
    if (relative[0] == '\0')
    {
        leaf[0] = '\0';
        *parent_out = current;
        return 0;
    }

    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);

    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL) {
            if (copy_text(leaf, leaf_size, cursor) == 0) {
                *parent_out = current;
                return 0;
            }
            int saved = EINVAL;
            (void)close(current);
            errno = saved;
            return -1;
        }

        struct stat st;
        if (fstatat(current, cursor, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                int saved = ENOTDIR;
                (void)close(current);
                errno = saved;
                return -1;
            }
        } else if (errno == ENOENT) {
            if (mkdirat(current, cursor, 0700) != 0 && errno != EEXIST) {
                int saved = errno;
                (void)close(current);
                errno = saved;
                return -1;
            }
            if (fstatat(current, cursor, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISDIR(st.st_mode)) {
                int saved = ENOTDIR;
                (void)close(current);
                errno = saved;
                return -1;
            }
        } else {
            int saved = errno;
            (void)close(current);
            errno = saved;
            return -1;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0) {
            int saved = errno;
            (void)close(current);
            errno = saved;
            return -1;
        }
        if (close(current) != 0) {
            int saved = errno;
            (void)close(next);
            errno = saved;
            return -1;
        }
        current = next;
        cursor = slash + 1;
    }
}

/* Opens an existing payload parent without creating any component. */
static int open_existing_payload_parent(int data_fd, const char *relative,
                                        int *parent_out, char *leaf,
                                        size_t leaf_size)
{
    if (data_fd < 0 || parent_out == NULL || leaf == NULL ||
        !safe_relative_path(relative) || leaf_size == 0)
        return -1;

    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);
    int current = dup_cloexec(data_fd);
    if (current < 0)
        return -1;

    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL) {
            int result = copy_text(leaf, leaf_size, cursor);
            if (result == 0) {
                *parent_out = current;
                return 0;
            }
            close(current);
            return -1;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0) {
            int saved = errno;
            close(current);
            errno = saved;
            return -1;
        }
        close(current);
        current = next;
        cursor = slash + 1;
    }
}

static int ensure_directory_leaf(int parent_fd, const char *leaf, int *out_fd)
{
    if (parent_fd < 0 || !safe_component(leaf) || out_fd == NULL)
        return -1;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISDIR(st.st_mode)) {
            *out_fd = open_child_directory(parent_fd, leaf);
            return *out_fd < 0 ? -1 : 0;
        }
        if (remove_leaf(parent_fd, leaf) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    if (mkdirat(parent_fd, leaf, 0700) != 0 && errno != EEXIST)
        return -1;
    *out_fd = open_child_directory(parent_fd, leaf);
    return *out_fd < 0 ? -1 : 0;
}

static int ensure_regular_leaf(int parent_fd, const char *leaf, int *out_fd)
{
    if (parent_fd < 0 || !safe_component(leaf) || out_fd == NULL)
        return -1;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (remove_leaf(parent_fd, leaf) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    int fd = openat(parent_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK |
                        O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int saved = errno == 0 ? EIO : errno;
        close(fd);
        unlinkat(parent_fd, leaf, 0);
        errno = saved;
        return -1;
    }
    *out_fd = fd;
    return 0;
}

void xattrs_free(PortableXattrs *xattrs)
{
    if (xattrs == NULL)
        return;
    for (size_t index = 0; index < xattrs->count; index++) {
        free((void *)xattrs->items[index].name.data);
        free((void *)xattrs->items[index].value.data);
    }
    free(xattrs->items);
    memset(xattrs, 0, sizeof(*xattrs));
}

static int xattrs_reserve(PortableXattrs *xattrs, size_t extra)
{
    if (extra > SIDECAR_MAX_XATTRS_PER_ENTRY - xattrs->count)
        return -1;
    size_t needed = xattrs->count + extra;
    if (needed <= xattrs->capacity)
        return 0;
    size_t capacity = xattrs->capacity == 0 ? 4U : xattrs->capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > SIDECAR_MAX_XATTRS_PER_ENTRY)
        capacity = SIDECAR_MAX_XATTRS_PER_ENTRY;
    SidecarXattr *items = realloc(xattrs->items, capacity * sizeof(*items));
    if (items == NULL)
        return -1;
    memset(items + xattrs->capacity, 0,
           (capacity - xattrs->capacity) * sizeof(*items));
    xattrs->items = items;
    xattrs->capacity = capacity;
    return 0;
}

typedef struct {
    char **names;
    size_t count;
    size_t capacity;
} PendingReadbackNames;

static void pending_readback_names_free(PendingReadbackNames *pending)
{
    if (pending == NULL)
        return;
    for (size_t index = 0; index < pending->count; index++)
        free(pending->names[index]);
    free(pending->names);
    memset(pending, 0, sizeof(*pending));
}

static int pending_readback_names_reserve(PendingReadbackNames *pending,
                                          size_t extra)
{
    if (pending == NULL ||
        extra > PORTABLE_MAX_READBACK_NAMES - pending->count)
        return -1;
    size_t needed = pending->count + extra;
    if (needed <= pending->capacity)
        return 0;

    size_t capacity = pending->capacity == 0 ? 16U : pending->capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > PORTABLE_MAX_READBACK_NAMES)
        capacity = PORTABLE_MAX_READBACK_NAMES;
    if (capacity > SIZE_MAX / sizeof(*pending->names))
        return -1;

    char **names = realloc(pending->names, capacity * sizeof(*names));
    if (names == NULL)
        return -1;
    memset(names + pending->capacity, 0,
           (capacity - pending->capacity) * sizeof(*names));
    pending->names = names;
    pending->capacity = capacity;
    return 0;
}

static int pending_readback_names_add(PendingReadbackNames *pending,
                                      const char *name)
{
    if (pending == NULL || name == NULL ||
        pending_readback_names_reserve(pending, 1) != 0)
        return -1;
    size_t length = strlen(name);
    char *copy = malloc(length + 1U);
    if (copy == NULL)
        return -1;
    memcpy(copy, name, length + 1U);
    pending->names[pending->count++] = copy;
    return 0;
}

static int encoded_name_has_raw_high_byte(const char *encoded)
{
    if (encoded == NULL)
        return 0;
    for (size_t index = 0; encoded[index] != '\0'; index++)
        if ((unsigned char)encoded[index] >= 0x80U)
            return 1;
    return 0;
}

static int verify_pending_readback_names(int destination_fd,
                                         const PendingReadbackNames *pending)
{
    if (destination_fd < 0 || pending == NULL)
        return -1;
    if (pending->count == 0)
        return 0;

    unsigned char *found = calloc(pending->count, sizeof(*found));
    if (found == NULL)
        return -1;
    int scan_fd = dup_cloexec(destination_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        free(found);
        return -1;
    }
    portable_readback_scan_count();

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        for (size_t index = 0; index < pending->count; index++) {
            if (!found[index] &&
                strcmp(entry->d_name, pending->names[index]) == 0) {
                found[index] = 1;
                break;
            }
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    for (size_t index = 0; index < pending->count; index++)
        if (!found[index]) {
            failed = 1;
        }
    free(found);
    return failed ? -1 : 0;
}

int collect_xattrs(int fd, PortableXattrs *out)
{
    if (fd < 0 || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    errno = 0;
    ssize_t length = flistxattr(fd, NULL, 0);
    if (length < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENODATA)
            return 0;
        return -1;
    }
    if ((uint64_t)length > SIDECAR_MAX_XATTRS_PER_ENTRY *
                           (uint64_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (length == 0)
        return 0;

    char *names = malloc((size_t)length);
    if (names == NULL)
        return -1;
    ssize_t received = flistxattr(fd, names, (size_t)length);
    if (received != length) {
        free(names);
        return -1;
    }

    size_t offset = 0;
    while (offset < (size_t)received) {
        size_t name_length = strnlen(names + offset,
                                    (size_t)received - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == (size_t)received - offset) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        if (xattrs_reserve(out, 1) != 0) {
            free(names);
            xattrs_free(out);
            return -1;
        }

        unsigned char *name_copy = malloc(name_length);
        if (name_copy == NULL) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        memcpy(name_copy, names + offset, name_length);

        errno = 0;
        ssize_t value_length = fgetxattr(fd, names + offset, NULL, 0);
        if (value_length < 0 || (uint64_t)value_length > SIDECAR_MAX_XATTR_VALUE) {
            free(name_copy);
            free(names);
            xattrs_free(out);
            return -1;
        }
        unsigned char *value_copy = NULL;
        if (value_length > 0) {
            value_copy = malloc((size_t)value_length);
            if (value_copy == NULL) {
                free(name_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
            ssize_t reread = fgetxattr(fd, names + offset, value_copy,
                                       (size_t)value_length);
            if (reread != value_length) {
                free(name_copy);
                free(value_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
        }
        out->items[out->count++] = (SidecarXattr){
            .name = { name_copy, name_length },
            .value = { value_copy, (size_t)value_length }
        };
        offset += name_length + 1U;
    }
    free(names);
    return 0;
}

int collect_symlink_xattrs(const char *path, PortableXattrs *out)
{
    if (path == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    errno = 0;
    ssize_t length = llistxattr(path, NULL, 0);
    if (length < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENODATA)
            return 0;
        return -1;
    }
    if ((uint64_t)length > SIDECAR_MAX_XATTRS_PER_ENTRY *
                           (uint64_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (length == 0)
        return 0;

    char *names = malloc((size_t)length);
    if (names == NULL)
        return -1;
    ssize_t received = llistxattr(path, names, (size_t)length);
    if (received != length) {
        free(names);
        return -1;
    }

    size_t offset = 0;
    while (offset < (size_t)received) {
        size_t name_length = strnlen(names + offset,
                                    (size_t)received - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == (size_t)received - offset) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        if (xattrs_reserve(out, 1) != 0) {
            free(names);
            xattrs_free(out);
            return -1;
        }

        unsigned char *name_copy = malloc(name_length);
        if (name_copy == NULL) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        memcpy(name_copy, names + offset, name_length);

        errno = 0;
        ssize_t value_length = lgetxattr(path, names + offset, NULL, 0);
        if (value_length < 0 ||
            (uint64_t)value_length > SIDECAR_MAX_XATTR_VALUE) {
            free(name_copy);
            free(names);
            xattrs_free(out);
            return -1;
        }
        unsigned char *value_copy = NULL;
        if (value_length > 0) {
            value_copy = malloc((size_t)value_length);
            if (value_copy == NULL) {
                free(name_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
            ssize_t reread = lgetxattr(path, names + offset, value_copy,
                                       (size_t)value_length);
            if (reread != value_length) {
                free(name_copy);
                free(value_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
        }
        out->items[out->count++] = (SidecarXattr){
            .name = { name_copy, name_length },
            .value = { value_copy, (size_t)value_length }
        };
        offset += name_length + 1U;
    }
    free(names);
    return 0;
}

static int time_to_i64(time_t value, int64_t *out)
{
    if (out == NULL)
        return -1;
    intmax_t converted = (intmax_t)value;
    if ((time_t)converted != value || converted < INT64_MIN ||
        converted > INT64_MAX)
        return -1;
    *out = (int64_t)converted;
    return 0;
}

int entry_from_stat(const char *root_id, const char *logical,
                    const char *physical, const char *collision_suffix,
                    const struct stat *st, int nsec_exact,
                    PortableXattrs *xattrs, SidecarEntry *out,
                    const SidecarBytes *symlink_target,
                    const SidecarBytes *hardlink_root_id,
                    const SidecarBytes *hardlink_logical_path)
{
    int64_t atime_sec;
    int64_t mtime_sec;
    int hardlink_requested = hardlink_root_id != NULL ||
                             hardlink_logical_path != NULL;
    if (root_id == NULL || logical == NULL || physical == NULL ||
        collision_suffix == NULL ||
        st == NULL || out == NULL ||
        (st->st_mode & 07777) > SIDECAR_MAX_MODE || st->st_uid > UINT32_MAX ||
        st->st_gid > UINT32_MAX || st->st_size < 0 ||
        (uintmax_t)st->st_size > UINT64_MAX ||
        time_to_i64(st->st_atim.tv_sec, &atime_sec) != 0 ||
        time_to_i64(st->st_mtim.tv_sec, &mtime_sec) != 0)
        return -1;
    if (st->st_atim.tv_nsec < 0 || st->st_atim.tv_nsec > SIDECAR_MAX_NSEC ||
        st->st_mtim.tv_nsec < 0 || st->st_mtim.tv_nsec > SIDECAR_MAX_NSEC)
        return -1;
    if (hardlink_requested &&
        (hardlink_root_id == NULL || hardlink_logical_path == NULL ||
         !S_ISREG(st->st_mode) || symlink_target != NULL ||
         (xattrs != NULL && xattrs->count != 0) ||
         hardlink_root_id->data == NULL || hardlink_root_id->length == 0 ||
         hardlink_root_id->length > SIDECAR_MAX_ROOT_ID ||
         memchr(hardlink_root_id->data, '\0', hardlink_root_id->length) != NULL ||
         hardlink_logical_path->data == NULL ||
         hardlink_logical_path->length == 0 ||
         hardlink_logical_path->length > SIDECAR_MAX_PATH ||
         memchr(hardlink_logical_path->data, '\0',
                hardlink_logical_path->length) != NULL))
        return -1;

    memset(out, 0, sizeof(*out));
    out->root_id = (SidecarBytes){ (const unsigned char *)root_id,
                                   strlen(root_id) };
    out->logical_path = (SidecarBytes){ (const unsigned char *)logical,
                                        strlen(logical) };
    out->physical_path = (SidecarBytes){ (const unsigned char *)physical,
                                         strlen(physical) };
    out->collision_suffix = (SidecarBytes){
        (const unsigned char *)collision_suffix, strlen(collision_suffix) };
    if (hardlink_requested)
        out->kind = SIDECAR_KIND_HARDLINK;
    else if (S_ISLNK(st->st_mode))
        out->kind = SIDECAR_KIND_SYMLINK;
    else if (S_ISREG(st->st_mode))
        out->kind = SIDECAR_KIND_REGULAR;
    else
        out->kind = SIDECAR_KIND_DIRECTORY;
    out->mode = (uint32_t)(st->st_mode & 07777);
    out->uid = (uint32_t)st->st_uid;
    out->gid = (uint32_t)st->st_gid;
    out->atime_sec = atime_sec;
    out->mtime_sec = mtime_sec;
    out->atime_nsec = nsec_exact ? (uint32_t)st->st_atim.tv_nsec : 0;
    out->mtime_nsec = nsec_exact ? (uint32_t)st->st_mtim.tv_nsec : 0;
    out->size = out->kind == SIDECAR_KIND_HARDLINK
                    ? 0U
                    : ((S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))
                           ? (uint64_t)st->st_size : 0U);
    out->xattr_count = out->kind == SIDECAR_KIND_HARDLINK
                           ? 0U
                           : (xattrs == NULL ? 0U : (uint32_t)xattrs->count);
    if (out->kind == SIDECAR_KIND_HARDLINK) {
        out->hardlink_root_id = *hardlink_root_id;
        out->hardlink_logical_path = *hardlink_logical_path;
    } else if (out->kind == SIDECAR_KIND_SYMLINK) {
        if (symlink_target == NULL || symlink_target->data == NULL ||
            symlink_target->length == 0)
            return -1;
        out->symlink_target = *symlink_target;
    }
    return 0;
}

static int sidecar_bytes_equal(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 ||
            (left.data != NULL && right.data != NULL &&
             memcmp(left.data, right.data, left.length) == 0));
}

static int xattrs_equal(const PortableXattrs *current,
                        const SidecarLiveView *previous)
{
    if (current == NULL || previous == NULL ||
        current->count != previous->xattr_count)
        return 0;
    unsigned char matched[SIDECAR_MAX_XATTRS_PER_ENTRY] = {0};
    for (size_t index = 0; index < current->count; index++) {
        SidecarBytes name = current->items[index].name;
        SidecarBytes value = current->items[index].value;
        int found = 0;
        for (size_t candidate = 0; candidate < previous->xattr_count;
             candidate++) {
            if (matched[candidate])
                continue;
            if (sidecar_bytes_equal(name, previous->xattrs[candidate].name) &&
                sidecar_bytes_equal(value,
                                    previous->xattrs[candidate].value)) {
                matched[candidate] = 1;
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    return 1;
}

int entries_equal(const SidecarEntry *current,
                  const SidecarLiveView *previous,
                  const PortableXattrs *xattrs)
{
    if (current == NULL || previous == NULL || previous->entry == NULL)
        return 0;
    const SidecarEntry *entry = previous->entry;
    /* Reading a symlink target may update its source atime; D18 does not
     * promise source-symlink atime preservation, so atime is not a resume key. */
    return sidecar_bytes_equal(current->root_id, entry->root_id) &&
           sidecar_bytes_equal(current->logical_path, entry->logical_path) &&
           sidecar_bytes_equal(current->physical_path, entry->physical_path) &&
           sidecar_bytes_equal(current->collision_suffix,
                               entry->collision_suffix) &&
           current->kind == entry->kind && current->mode == entry->mode &&
           current->uid == entry->uid && current->gid == entry->gid &&
           (current->kind == SIDECAR_KIND_SYMLINK ||
            (current->atime_sec == entry->atime_sec &&
             current->atime_nsec == entry->atime_nsec)) &&
           current->mtime_sec == entry->mtime_sec &&
           current->mtime_nsec == entry->mtime_nsec &&
           (current->kind != SIDECAR_KIND_REGULAR ||
            current->size == entry->size) &&
           sidecar_bytes_equal(current->symlink_target, entry->symlink_target) &&
           sidecar_bytes_equal(current->hardlink_root_id,
                               entry->hardlink_root_id) &&
           sidecar_bytes_equal(current->hardlink_logical_path,
                               entry->hardlink_logical_path) &&
           xattrs_equal(xattrs, previous);
}

static int existing_payload_matches(int data_fd, const char *payload_path,
                                    int destination_parent,
                                    const char *destination_leaf,
                                    int destination_is_root,
                                    uint64_t expected_size)
{
    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (open_existing_payload_parent(data_fd, payload_path, &parent_fd,
                                         root_leaf, sizeof(root_leaf)) != 0)
            return errno == ENOENT ? 0 : -1;
        destination_leaf = root_leaf;
    }

    struct stat st;
    int result = fstatat(parent_fd, destination_leaf, &st,
                         AT_SYMLINK_NOFOLLOW);
    int saved = errno;
    if (destination_is_root && close(parent_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    if (result != 0) {
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size != expected_size)
        return 0;
    return 1;
}

typedef struct {
    char *logical;
    char *physical;
} StaleKey;

typedef struct {
    StaleKey *items;
    size_t count;
    size_t capacity;
    int failed;
} StaleKeys;

typedef struct {
    char *logical;
    char *physical;
    SidecarObjectKind kind;
} StaleClaim;

typedef struct {
    StaleClaim *items;
    size_t count;
    size_t capacity;
    int failed;
} StaleClaims;

static void stale_keys_free(StaleKeys *keys)
{
    if (keys == NULL)
        return;
    for (size_t index = 0; index < keys->count; index++) {
        free(keys->items[index].logical);
        free(keys->items[index].physical);
    }
    free(keys->items);
    memset(keys, 0, sizeof(*keys));
}

static void stale_claims_free(StaleClaims *claims)
{
    if (claims == NULL)
        return;
    for (size_t index = 0; index < claims->count; index++) {
        free(claims->items[index].logical);
        free(claims->items[index].physical);
    }
    free(claims->items);
    memset(claims, 0, sizeof(*claims));
}

static int sidecar_bytes_to_text(SidecarBytes bytes, char **out)
{
    if (out == NULL || bytes.length >= PATH_MAX ||
        (bytes.length != 0 && bytes.data == NULL) ||
        (bytes.length != 0 && memchr(bytes.data, '\0', bytes.length) != NULL))
        return -1;
    char *copy = malloc(bytes.length + 1U);
    if (copy == NULL)
        return -1;
    if (bytes.length != 0)
        memcpy(copy, bytes.data, bytes.length);
    copy[bytes.length] = '\0';
    *out = copy;
    return 0;
}

static int stale_claims_append(StaleClaims *claims, SidecarBytes logical,
                               SidecarBytes physical, SidecarObjectKind kind)
{
    if (claims == NULL || claims->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (claims->count == claims->capacity) {
        size_t capacity = claims->capacity == 0 ? 16U : claims->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < claims->capacity ||
            capacity > SIZE_MAX / sizeof(*claims->items))
            return -1;
        StaleClaim *items = realloc(claims->items,
                                    capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        claims->items = items;
        claims->capacity = capacity;
    }

    StaleClaim item = { .kind = kind };
    if (sidecar_bytes_to_text(logical, &item.logical) != 0 ||
        sidecar_bytes_to_text(physical, &item.physical) != 0) {
        free(item.logical);
        free(item.physical);
        return -1;
    }
    claims->items[claims->count++] = item;
    return 0;
}

typedef struct {
    PortableInodeMap *inode_map;
    const PortableCaptureRequest *request;
    int failed;
} StickySeedState;

static int sticky_seed_callback(const SidecarLiveView *view, void *argument)
{
    StickySeedState *state = argument;
    if (state == NULL || state->inode_map == NULL || state->request == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (view->entry->kind != SIDECAR_KIND_REGULAR)
        return 0;

    char *root_id = NULL;
    char *logical = NULL;
    if (sidecar_bytes_to_text(view->entry->root_id, &root_id) != 0 ||
        sidecar_bytes_to_text(view->entry->logical_path, &logical) != 0) {
        free(root_id);
        free(logical);
        state->failed = 1;
        return 1;
    }

    const PortableRootSpec *root = portable_collision_plan_root(state->request,
                                                                root_id);
    char source_path[PATH_MAX];
    int source_path_ready = 0;
    if (root != NULL) {
        if (logical[0] == '\0') {
            int length = snprintf(source_path, sizeof(source_path), "%s",
                                  root->capture_path);
            source_path_ready = length >= 0 &&
                                 (size_t)length < sizeof(source_path);
        } else {
            source_path_ready = path_join(source_path, sizeof(source_path),
                                          root->capture_path, logical) == 0;
        }
    }

    struct stat source_stat;
    int source_exists = 0;
    if (source_path_ready) {
        sticky_seed_count_lstat();
        source_exists = lstat(source_path, &source_stat) == 0;
    }
    if (source_exists && S_ISREG(source_stat.st_mode)) {
        const PortableInodeSlot *slot = NULL;
        if (inode_map_find_or_insert(state->inode_map, source_stat.st_dev,
                                     source_stat.st_ino, root_id, logical,
                                     &slot) < 0) {
            state->failed = 1;
            free(root_id);
            free(logical);
            return 1;
        }
    }

    free(root_id);
    free(logical);
    return 0;
}

static int sticky_seed_inode_map(PortableInodeMap *inode_map,
                                 const PortableCaptureRequest *request,
                                 SidecarLog *sidecar)
{
    if (inode_map == NULL || request == NULL || sidecar == NULL)
        return -1;
    StickySeedState state = {
        .inode_map = inode_map,
        .request = request,
        .failed = 0
    };
    SidecarStatus status = sidecar_log_foreach(sidecar, sticky_seed_callback,
                                               &state);
    return status == SIDECAR_STATUS_OK && state.failed == 0 ? 0 : -1;
}

static void portable_owned_paths_free(PortableOwnedPaths *paths)
{
    if (paths == NULL)
        return;
    for (size_t index = 0; index < paths->count; index++) {
        free(paths->items[index].root_id);
        free(paths->items[index].physical_path);
        free(paths->items[index].logical_path);
    }
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static int portable_owned_paths_append(PortableOwnedPaths *paths,
                                       const SidecarLiveView *view)
{
    if (paths == NULL || view == NULL || view->entry == NULL ||
        paths->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (paths->count == paths->capacity) {
        size_t capacity = paths->capacity == 0 ? 16U : paths->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < paths->capacity ||
            capacity > SIZE_MAX / sizeof(*paths->items))
            return -1;
        PortableOwnedPath *items = realloc(paths->items,
                                           capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        paths->items = items;
        paths->capacity = capacity;
    }

    PortableOwnedPath item = {0};
    if (sidecar_bytes_to_text(view->entry->root_id, &item.root_id) != 0 ||
        sidecar_bytes_to_text(view->entry->physical_path,
                              &item.physical_path) != 0 ||
        sidecar_bytes_to_text(view->entry->logical_path,
                              &item.logical_path) != 0) {
        free(item.root_id);
        free(item.physical_path);
        free(item.logical_path);
        return -1;
    }
    paths->items[paths->count++] = item;
    return 0;
}

static int portable_owned_paths_callback(const SidecarLiveView *view,
                                         void *argument)
{
    PortableOwnedPaths *paths = argument;
    return portable_owned_paths_append(paths, view) == 0 ? 0 : 1;
}

static int portable_owned_path_compare(const void *left, const void *right)
{
    const PortableOwnedPath *left_path = left;
    const PortableOwnedPath *right_path = right;
    int result = strcmp(left_path->root_id, right_path->root_id);
    if (result != 0)
        return result;
    return strcmp(left_path->physical_path, right_path->physical_path);
}

static int portable_owned_paths_load(PortableOwnedPaths *paths,
                                     SidecarLog *sidecar)
{
    if (paths == NULL || sidecar == NULL)
        return -1;
    SidecarStatus status = sidecar_log_foreach(
        sidecar, portable_owned_paths_callback, paths);
    if (status != SIDECAR_STATUS_OK)
        return -1;
    if (paths->count > 1U)
        qsort(paths->items, paths->count, sizeof(*paths->items),
              portable_owned_path_compare);
    for (size_t index = 1; index < paths->count; index++) {
        PortableOwnedPath *previous = &paths->items[index - 1U];
        PortableOwnedPath *current = &paths->items[index];
        if (strcmp(previous->root_id, current->root_id) == 0 &&
            strcmp(previous->physical_path, current->physical_path) == 0)
            return -1;
    }
    paths->sorted = 1;
    return 0;
}

static const char *portable_owned_paths_owner(
    const PortableOwnedPaths *paths, const char *root_id,
    const char *physical_path)
{
    if (paths == NULL || !paths->sorted || root_id == NULL ||
        physical_path == NULL)
        return NULL;
    size_t low = 0;
    size_t high = paths->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        const PortableOwnedPath *item = &paths->items[middle];
        int result = strcmp(item->root_id, root_id);
        if (result == 0)
            result = strcmp(item->physical_path, physical_path);
        if (result < 0)
            low = middle + 1U;
        else
            high = middle;
    }
    if (low == paths->count)
        return NULL;
    const PortableOwnedPath *item = &paths->items[low];
    return strcmp(item->root_id, root_id) == 0 &&
                   strcmp(item->physical_path, physical_path) == 0
               ? item->logical_path
               : NULL;
}

static void portable_claimed_paths_free(PortableClaimedPaths *paths)
{
    if (paths == NULL)
        return;
    for (size_t index = 0; index < paths->count; index++) {
        free(paths->items[index].root_id);
        free(paths->items[index].physical_path);
        free(paths->items[index].logical_path);
    }
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static int portable_claimed_paths_append(PortableClaimedPaths *paths,
                                         const SidecarClaimView *view)
{
    if (paths == NULL || view == NULL || view->claim == NULL ||
        paths->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (paths->count == paths->capacity) {
        size_t capacity = paths->capacity == 0 ? 16U : paths->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < paths->capacity ||
            capacity > SIZE_MAX / sizeof(*paths->items))
            return -1;
        PortableClaimedPath *items = realloc(paths->items,
                                             capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        paths->items = items;
        paths->capacity = capacity;
    }

    PortableClaimedPath item = {0};
    if (sidecar_bytes_to_text(view->claim->root_id, &item.root_id) != 0 ||
        sidecar_bytes_to_text(view->claim->physical_path,
                              &item.physical_path) != 0 ||
        sidecar_bytes_to_text(view->claim->logical_path,
                              &item.logical_path) != 0) {
        free(item.root_id);
        free(item.physical_path);
        free(item.logical_path);
        return -1;
    }
    paths->items[paths->count++] = item;
    return 0;
}

static int portable_claimed_paths_callback(const SidecarClaimView *view,
                                           void *argument)
{
    PortableClaimedPaths *paths = argument;
    return portable_claimed_paths_append(paths, view) == 0 ? 0 : 1;
}

static int portable_claimed_path_compare(const void *left, const void *right)
{
    const PortableClaimedPath *left_path = left;
    const PortableClaimedPath *right_path = right;
    int result = strcmp(left_path->root_id, right_path->root_id);
    if (result != 0)
        return result;
    return strcmp(left_path->physical_path, right_path->physical_path);
}

static int portable_claimed_paths_load(PortableClaimedPaths *paths,
                                       SidecarLog *sidecar)
{
    if (paths == NULL || sidecar == NULL)
        return -1;
    SidecarStatus status = sidecar_log_claim_foreach(
        sidecar, portable_claimed_paths_callback, paths);
    if (status != SIDECAR_STATUS_OK)
        return -1;
    if (paths->count > 1U)
        qsort(paths->items, paths->count, sizeof(*paths->items),
              portable_claimed_path_compare);
    for (size_t index = 1; index < paths->count; index++) {
        PortableClaimedPath *previous = &paths->items[index - 1U];
        PortableClaimedPath *current = &paths->items[index];
        if (strcmp(previous->root_id, current->root_id) == 0 &&
            strcmp(previous->physical_path, current->physical_path) == 0)
            return -1;
    }
    paths->sorted = 1;
    return 0;
}

static const PortableClaimedPath *portable_claimed_paths_owner(
    const PortableClaimedPaths *paths, const char *root_id,
    const char *physical_path)
{
    if (paths == NULL || !paths->sorted || root_id == NULL ||
        physical_path == NULL)
        return NULL;
    size_t low = 0;
    size_t high = paths->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        const PortableClaimedPath *item = &paths->items[middle];
        int result = strcmp(item->root_id, root_id);
        if (result == 0)
            result = strcmp(item->physical_path, physical_path);
        if (result < 0)
            low = middle + 1U;
        else
            high = middle;
    }
    if (low == paths->count)
        return NULL;
    const PortableClaimedPath *item = &paths->items[low];
    return strcmp(item->root_id, root_id) == 0 &&
                   strcmp(item->physical_path, physical_path) == 0
               ? item
               : NULL;
}

int relative_path_prefix_match(const char *prefix, const char *path,
                               const char **relative_out)
{
    if (prefix == NULL || path == NULL)
        return 0;
    size_t prefix_length = strlen(prefix);
    if (strcmp(prefix, path) == 0)
    {
        if (relative_out != NULL)
            *relative_out = path + prefix_length;
        return 1;
    }
    if (strncmp(prefix, path, prefix_length) == 0 &&
        path[prefix_length] == '/')
    {
        if (relative_out != NULL)
            *relative_out = path + prefix_length + 1U;
        return 1;
    }
    return 0;
}

static int stale_keys_append(StaleKeys *keys, SidecarBytes logical,
                             SidecarBytes physical)
{
    if (keys == NULL)
        return -1;
    if (keys->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (keys->count == keys->capacity) {
        size_t capacity = keys->capacity == 0 ? 16U : keys->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < keys->capacity || capacity > SIZE_MAX / sizeof(*keys->items))
            return -1;
        StaleKey *items = realloc(keys->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        keys->items = items;
        keys->capacity = capacity;
    }

    StaleKey item = {0};
    if (sidecar_bytes_to_text(logical, &item.logical) != 0 ||
        sidecar_bytes_to_text(physical, &item.physical) != 0) {
        free(item.logical);
        free(item.physical);
        return -1;
    }
    keys->items[keys->count++] = item;
    return 0;
}

typedef struct {
    PortableCaptureContext *context;
    const char *root_id;
    StaleKeys *stale;
} StaleCollection;

static int collect_stale_key(const SidecarLiveView *view, void *argument)
{
    StaleCollection *collection = argument;
    if (collection == NULL || collection->context == NULL ||
        collection->root_id == NULL || collection->stale == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->entry->root_id,
            (SidecarBytes){ (const unsigned char *)collection->root_id,
                            strlen(collection->root_id) }))
        return 0;

    char *logical = NULL;
    if (sidecar_bytes_to_text(view->entry->logical_path, &logical) != 0) {
        collection->stale->failed = 1;
        return 1;
    }
    int present = visited_contains(collection->context->visited,
                                   collection->root_id, logical);
    free(logical);
    if (present < 0) {
        collection->stale->failed = 1;
        return 1;
    }
    if (present == 0) {
        if (stale_keys_append(collection->stale, view->entry->logical_path,
                              view->entry->physical_path) != 0)
            collection->stale->failed = 1;
    }
    return collection->stale->failed;
}

typedef struct {
    PortableCaptureContext *context;
    const char *root_id;
    StaleClaims *stale;
} StaleClaimCollection;

static int collect_stale_claim(const SidecarClaimView *view, void *argument)
{
    StaleClaimCollection *collection = argument;
    if (collection == NULL || collection->context == NULL ||
        collection->root_id == NULL || collection->stale == NULL ||
        view == NULL || view->claim == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->claim->root_id,
            (SidecarBytes){ (const unsigned char *)collection->root_id,
                            strlen(collection->root_id) }))
        return 0;

    char *logical = NULL;
    if (sidecar_bytes_to_text(view->claim->logical_path, &logical) != 0) {
        collection->stale->failed = 1;
        return 1;
    }
    int present = visited_contains(collection->context->visited,
                                   collection->root_id, logical);
    free(logical);
    if (present < 0) {
        collection->stale->failed = 1;
        return 1;
    }
    if (present == 0 && stale_claims_append(
                           collection->stale, view->claim->logical_path,
                           view->claim->physical_path, view->claim->kind) != 0)
        collection->stale->failed = 1;
    return collection->stale->failed;
}

static int key_is_live(PortableCaptureContext *context,
                       const char *root_id, const char *logical)
{
    SidecarLiveView view;
    SidecarBytes root = { (const unsigned char *)root_id, strlen(root_id) };
    SidecarBytes path = { (const unsigned char *)logical, strlen(logical) };
    int found = sidecar_log_find(context->sidecar, root, path, &view);
    return found < 0 ? -1 : found;
}

static int remove_payload_relative(int data_fd, const char *payload_root,
                                   const char *physical);

static int capture_destination_is_safe(const PortableCaptureContext *context,
                                       const PortableRootSpec *root,
                                       const char *logical,
                                       const char *physical,
                                       int parent_fd, const char *leaf)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL || parent_fd < 0 || !safe_component(leaf))
        return -1;
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    if (!context->resume_mode)
        return 0;
    if (context->owned_paths == NULL)
        return -1;
    const PortableOwnedPaths *owned = context->owned_paths;
    const char *owner = portable_owned_paths_owner(owned, root->id,
                                                   physical);
    if (owner != NULL && strcmp(owner, logical) == 0)
        return 0;

    /* A resume may have been interrupted after its DELETE record was
     * committed but before the replacement payload was published.  The
     * matching tombstone is still this container's ownership proof for the
     * old physical name; a missing or mismatching tombstone remains foreign. */
    SidecarLiveView deleted;
    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    int found = sidecar_log_find_deleted(context->sidecar, root_key,
                                         logical_key, &deleted);
    if (found < 0)
        return -1;
    return found == 1 &&
                   sidecar_bytes_equal(
                       deleted.entry->physical_path,
                       (SidecarBytes){
                           (const unsigned char *)physical,
                           strlen(physical) })
               ? 0
               : -1;
}

/* During resume, an interrupted claim is also ownership proof for the
 * payload that was created after the claim and before its ENTRY_COMMIT.
 * Keep the existing owned-path and tombstone checks intact.  A same-key,
 * same-physical claim remains ownership proof even when the source kind has
 * changed; append_capture_claim() then reconciles that old kind before
 * publishing the replacement claim. */
static int capture_destination_is_safe_or_claimed(
    const PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, const char *physical, int parent_fd,
    const char *leaf)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL)
        return -1;

    int result = capture_destination_is_safe(context, root, logical, physical,
                                             parent_fd, leaf);
    if (result == 0 || !context->resume_mode)
        return result;

    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarBytes physical_key = {
        (const unsigned char *)physical, strlen(physical)
    };
    SidecarClaimView claim_view = {0};
    int found = sidecar_log_find_claim(context->sidecar, root_key,
                                       logical_key, &claim_view);
    if (found < 0)
        return -1;
    if (found == 1 && claim_view.claim != NULL &&
        sidecar_bytes_equal(claim_view.claim->root_id, root_key) &&
        sidecar_bytes_equal(claim_view.claim->logical_path, logical_key) &&
        sidecar_bytes_equal(claim_view.claim->physical_path, physical_key))
        return 0;
    return result;
}

static int tombstone_if_live(PortableCaptureContext *context,
                             const char *root_id, const char *logical)
{
    int live = key_is_live(context, root_id, logical);
    if (live < 0)
        return -1;
    if (!live)
        return 0;
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)root_id, strlen(root_id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) }
    };
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE);
    int result = sidecar_log_append_delete(context->sidecar, &deletion) ==
                         SIDECAR_STATUS_OK ? 0 : -1;
    if (result == 0)
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_REPLACEMENT_DELETE);
    return result;
}

static int replace_live_capture(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical,
                                const char *physical)
{
    if (context == NULL || root == NULL || logical == NULL ||
        root->payload_path == NULL)
        return -1;

    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView previous;
    int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                &previous);
    if (live < 0)
        return -1;
    if (!live)
        return 0;

    int remove_old = physical != NULL &&
        !sidecar_bytes_equal(previous.entry->physical_path,
                             (SidecarBytes){
                                 (const unsigned char *)physical,
                                 strlen(physical) });
    char *old_physical = NULL;
    if (remove_old &&
        sidecar_bytes_to_text(previous.entry->physical_path, &old_physical) != 0)
        return -1;

    SidecarDelete deletion = {
        .root_id = root_key,
        .logical_path = logical_key
    };
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE);
    if (sidecar_log_append_delete(context->sidecar, &deletion) !=
        SIDECAR_STATUS_OK) {
        free(old_physical);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_REPLACEMENT_DELETE);

    if (remove_old) {
        int result = remove_payload_relative(context->data_fd,
                                             root->payload_path,
                                             old_physical);
        free(old_physical);
        if (result != 0)
            return -1;
    }
    return 0;
}

static int tombstone_destination_children(PortableCaptureContext *context,
                                          const char *root_id,
                                          const char *logical,
                                          int parent_fd,
                                          const char *leaf)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return 0;

    int directory_fd = open_child_directory(parent_fd, leaf);
    if (directory_fd < 0)
        return -1;
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0 ||
            tombstone_if_live(context, root_id, child_logical) != 0 ||
            tombstone_destination_children(context, root_id, child_logical,
                                           directory_fd, entry->d_name) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int append_group(PortableCaptureContext *context,
                        const SidecarEntry *entry,
                        const PortableXattrs *xattrs)
{
    SidecarStatus status = sidecar_log_append_entry(context->sidecar, entry);
    if (status != SIDECAR_STATUS_OK)
        return -1;
    for (size_t index = 0; xattrs != NULL && index < xattrs->count; index++)
        if (sidecar_log_append_xattr(context->sidecar, &xattrs->items[index]) !=
            SIDECAR_STATUS_OK)
            return -1;
    status = sidecar_log_append_entry_commit(context->sidecar);
    return status == SIDECAR_STATUS_OK ? 0 : -1;
}

static int reconcile_stale_claim(PortableCaptureContext *context,
                                 const PortableRootSpec *root,
                                 const char *logical,
                                 const SidecarClaim *claim);

static int append_capture_claim(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical, const char *physical,
                                SidecarObjectKind kind)
{
    if (context == NULL || root == NULL || root->id == NULL ||
        logical == NULL || physical == NULL)
        return -1;
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)root->id, strlen(root->id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) },
        .physical_path = { (const unsigned char *)physical, strlen(physical) },
        .kind = kind
    };
    SidecarClaimView existing = {0};
    int found = sidecar_log_find_claim(context->sidecar, claim.root_id,
                                       claim.logical_path, &existing);
    if (found < 0)
        return -1;
    if (found == 1) {
        if (existing.claim != NULL &&
            sidecar_bytes_equal(existing.claim->root_id, claim.root_id) &&
            sidecar_bytes_equal(existing.claim->logical_path,
                                claim.logical_path) &&
            sidecar_bytes_equal(existing.claim->physical_path,
                                claim.physical_path) &&
            existing.claim->kind == claim.kind)
            return 0;
        if (reconcile_stale_claim(context, root, logical, existing.claim) != 0)
            return -1;
    }
    return sidecar_log_append_claim(context->sidecar, &claim) ==
                   SIDECAR_STATUS_OK
               ? 0
               : -1;
}

static int remove_payload_relative(int data_fd, const char *payload_root,
                                   const char *physical)
{
    if (data_fd < 0 || payload_root == NULL || physical == NULL)
        return -1;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(data_fd, payload_root, &root_parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return errno == ENOENT ? 0 : -1;

    if (physical[0] == '\0') {
        int result = remove_leaf(root_parent, root_leaf);
        int saved = errno;
        if (close(root_parent) != 0 && result == 0) {
            result = -1;
            saved = EIO;
        }
        errno = saved;
        return result;
    }

    int payload_fd = open_child_directory(root_parent, root_leaf);
    int saved = errno;
    if (payload_fd >= 0) {
        if (close(root_parent) != 0) {
            saved = errno;
            close(payload_fd);
            errno = saved;
            return -1;
        }
    } else if (close(root_parent) != 0) {
        saved = errno;
    }
    if (payload_fd < 0) {
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }

    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(payload_fd, physical, &parent_fd,
                                     leaf, sizeof(leaf)) != 0) {
        saved = errno;
        if (close(payload_fd) != 0)
            return -1;
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }
    int result = remove_leaf(parent_fd, leaf);
    saved = errno;
    if (close(parent_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    if (close(payload_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

/* Remove one owned payload entry without recursively touching its children.
 * The collision relocation pass removes descendants first; a non-empty
 * directory therefore fails closed instead of deleting an unowned entry. */
static int remove_owned_payload_relative(int data_fd, const char *payload_root,
                                         const char *physical)
{
    if (data_fd < 0 || payload_root == NULL || physical == NULL ||
        (physical[0] != '\0' && !safe_relative_path(physical)))
        return -1;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(data_fd, payload_root, &root_parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return errno == ENOENT ? 0 : -1;

    if (physical[0] == '\0') {
        struct stat st;
        int result = 0;
        if (fstatat(root_parent, root_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
            result = errno == ENOENT ? 0 : -1;
        else
            result = unlinkat(root_parent, root_leaf,
                              S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0) == 0
                         ? 0
                         : -1;
        int saved = errno;
        if (close(root_parent) != 0 && result == 0) {
            result = -1;
            saved = EIO;
        }
        errno = saved;
        return result;
    }

    int payload_fd = open_child_directory(root_parent, root_leaf);
    int saved = errno;
    if (close(root_parent) != 0) {
        if (payload_fd >= 0)
            close(payload_fd);
        return -1;
    }
    if (payload_fd < 0) {
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }

    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(payload_fd, physical, &parent_fd,
                                     leaf, sizeof(leaf)) != 0) {
        saved = errno;
        close(payload_fd);
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }

    struct stat st;
    int result = 0;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        result = errno == ENOENT ? 0 : -1;
    } else {
        result = unlinkat(parent_fd, leaf, S_ISDIR(st.st_mode)
                                      ? AT_REMOVEDIR : 0) == 0 ? 0 : -1;
    }
    saved = errno;
    if (close(parent_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    if (close(payload_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

typedef struct {
    const PortableOwnedPaths *owned;
    const PortableClaimedPaths *claimed;
} ClaimOwnershipPaths;

static int open_claim_node(int data_fd, const char *payload_root,
                           const char *physical, int *parent_out,
                           char *leaf, size_t leaf_size, struct stat *out_stat)
{
    if (data_fd < 0 || payload_root == NULL || physical == NULL ||
        parent_out == NULL || leaf == NULL || leaf_size == 0 ||
        out_stat == NULL ||
        (physical[0] != '\0' && !safe_relative_path(physical)))
        return -1;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(data_fd, payload_root, &root_parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return errno == ENOENT ? 1 : -1;

    int parent_fd = root_parent;
    if (physical[0] != '\0') {
        int payload_fd = open_child_directory(root_parent, root_leaf);
        int saved = errno;
        if (close(root_parent) != 0) {
            if (payload_fd >= 0)
                close(payload_fd);
            return -1;
        }
        if (payload_fd < 0) {
            errno = saved;
            return errno == ENOENT ? 1 : -1;
        }
        if (open_existing_payload_parent(payload_fd, physical, &parent_fd,
                                         leaf, leaf_size) != 0) {
            saved = errno;
            close(payload_fd);
            errno = saved;
            return errno == ENOENT ? 1 : -1;
        }
        if (close(payload_fd) != 0) {
            close(parent_fd);
            return -1;
        }
    } else if (copy_text(leaf, leaf_size, root_leaf) != 0) {
        close(parent_fd);
        return -1;
    }

    if (fstatat(parent_fd, leaf, out_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved = errno;
        close(parent_fd);
        errno = saved;
        return errno == ENOENT ? 1 : -1;
    }
    *parent_out = parent_fd;
    return 0;
}

static int reconcile_claim_owner(const ClaimOwnershipPaths *paths,
                                 const char *root_id,
                                 const char *physical,
                                 const char **live_logical,
                                 const PortableClaimedPath **claim)
{
    if (paths == NULL || root_id == NULL || physical == NULL ||
        live_logical == NULL || claim == NULL)
        return -1;
    *live_logical = portable_owned_paths_owner(paths->owned, root_id,
                                               physical);
    *claim = portable_claimed_paths_owner(paths->claimed, root_id, physical);
    if ((*live_logical != NULL) == (*claim != NULL))
        return -1;
    return 0;
}

static int reconcile_claim_validate_node(PortableCaptureContext *context,
                                         const PortableRootSpec *root,
                                         const char *physical,
                                         const ClaimOwnershipPaths *paths)
{
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    struct stat st;
    int present = open_claim_node(context->data_fd, root->payload_path,
                                  physical, &parent_fd, leaf, sizeof(leaf),
                                  &st);
    if (present != 0)
        return present < 0 ? -1 : 0;
    if (!S_ISDIR(st.st_mode)) {
        int result = close(parent_fd);
        return result == 0 ? 0 : -1;
    }

    int directory_fd = open_child_directory(parent_fd, leaf);
    int saved = errno;
    if (close(parent_fd) != 0) {
        if (directory_fd >= 0)
            close(directory_fd);
        return -1;
    }
    if (directory_fd < 0) {
        errno = saved;
        return -1;
    }
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_physical[SIDECAR_MAX_PATH + 1U];
        if (append_physical(child_physical, sizeof(child_physical), physical,
                            entry->d_name) != 0) {
            failed = 1;
            break;
        }
        struct stat child_stat;
        if (fstatat(directory_fd, entry->d_name, &child_stat,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            failed = 1;
            break;
        }
        const char *live_logical = NULL;
        const PortableClaimedPath *claim = NULL;
        if (reconcile_claim_owner(paths, root->id, child_physical,
                                   &live_logical, &claim) != 0) {
            failed = 1;
            break;
        }
        const char *owner_logical = claim != NULL ? claim->logical_path
                                                   : live_logical;
        int visited = visited_contains(context->visited, root->id,
                                       owner_logical);
        if (visited != 0) {
            failed = 1;
            break;
        }
        if (S_ISDIR(child_stat.st_mode) &&
            reconcile_claim_validate_node(context, root, child_physical,
                                          paths) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int append_claim_delete(PortableCaptureContext *context,
                               const PortableRootSpec *root,
                               const char *logical)
{
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)root->id, strlen(root->id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) }
    };
    return sidecar_log_append_delete(context->sidecar, &deletion) ==
                   SIDECAR_STATUS_OK
               ? 0
               : -1;
}

static int reconcile_mutate_known_node(PortableCaptureContext *context,
                                       const PortableRootSpec *root,
                                       const char *logical,
                                       const char *physical,
                                       int claim_owned,
                                       const ClaimOwnershipPaths *paths)
{
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    struct stat st;
    int present = open_claim_node(context->data_fd, root->payload_path,
                                  physical, &parent_fd, leaf, sizeof(leaf),
                                  &st);
    if (present < 0)
        return -1;
    if (present == 1)
        return claim_owned ? append_claim_delete(context, root, logical)
                           : tombstone_if_live(context, root->id, logical);

    if (S_ISDIR(st.st_mode)) {
        int directory_fd = open_child_directory(parent_fd, leaf);
        int saved = errno;
        if (close(parent_fd) != 0) {
            if (directory_fd >= 0)
                close(directory_fd);
            return -1;
        }
        if (directory_fd < 0) {
            errno = saved;
            return -1;
        }
        int scan_fd = dup_cloexec(directory_fd);
        DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (directory == NULL) {
            if (scan_fd >= 0)
                close(scan_fd);
            close(directory_fd);
            return -1;
        }

        int failed = 0;
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(directory);
            if (entry == NULL) {
                if (errno != 0)
                    failed = 1;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            char child_physical[SIDECAR_MAX_PATH + 1U];
            if (append_physical(child_physical, sizeof(child_physical),
                                physical, entry->d_name) != 0) {
                failed = 1;
                break;
            }
            struct stat child_stat;
            if (fstatat(directory_fd, entry->d_name, &child_stat,
                        AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT)
                    continue;
                failed = 1;
                break;
            }
            const char *live_logical = NULL;
            const PortableClaimedPath *claim = NULL;
            if (reconcile_claim_owner(paths, root->id, child_physical,
                                       &live_logical, &claim) != 0) {
                failed = 1;
                break;
            }
            const char *owner_logical = claim != NULL ? claim->logical_path
                                                       : live_logical;
            if (visited_contains(context->visited, root->id,
                                 owner_logical) != 0) {
                failed = 1;
                break;
            }
            if (reconcile_mutate_known_node(
                    context, root, owner_logical, child_physical,
                    claim != NULL, paths) != 0) {
                failed = 1;
                break;
            }
        }
        if (closedir(directory) != 0)
            failed = 1;
        if (close(directory_fd) != 0)
            failed = 1;
        if (failed)
            return -1;
    } else if (close(parent_fd) != 0) {
        return -1;
    }

    if (claim_owned) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_owned_payload_relative(context->data_fd,
                                          root->payload_path, physical) != 0)
            return -1;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
        return append_claim_delete(context, root, logical);
    }
    if (tombstone_if_live(context, root->id, logical) != 0)
        return -1;
    return remove_owned_payload_relative(context->data_fd, root->payload_path,
                                         physical);
}

static int reconcile_stale_claim_with_paths(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, const char *physical, SidecarObjectKind kind,
    const ClaimOwnershipPaths *paths)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL || paths == NULL ||
        (physical[0] == '\0' && logical[0] != '\0') ||
        (kind != SIDECAR_KIND_REGULAR && kind != SIDECAR_KIND_DIRECTORY &&
         kind != SIDECAR_KIND_SYMLINK && kind != SIDECAR_KIND_HARDLINK))
        return -1;
    if (reconcile_claim_validate_node(context, root, physical, paths) != 0)
        return -1;
    return reconcile_mutate_known_node(context, root, logical, physical, 1,
                                       paths);
}

static int reconcile_stale_claim(PortableCaptureContext *context,
                                 const PortableRootSpec *root,
                                 const char *logical,
                                 const SidecarClaim *claim)
{
    if (context == NULL || root == NULL || logical == NULL || claim == NULL ||
        !sidecar_bytes_equal(
            claim->root_id,
            (SidecarBytes){ (const unsigned char *)root->id,
                            strlen(root->id) }) ||
        !sidecar_bytes_equal(
            claim->logical_path,
            (SidecarBytes){ (const unsigned char *)logical,
                            strlen(logical) }))
        return -1;

    char *physical = NULL;
    if (sidecar_bytes_to_text(claim->physical_path, &physical) != 0)
        return -1;

    PortableOwnedPaths owned = {0};
    PortableClaimedPaths claimed = {0};
    int result = -1;
    if (portable_owned_paths_load(&owned, context->sidecar) == 0 &&
        portable_claimed_paths_load(&claimed, context->sidecar) == 0) {
        ClaimOwnershipPaths paths = {
            .owned = &owned,
            .claimed = &claimed
        };
        result = reconcile_stale_claim_with_paths(
            context, root, logical, physical, claim->kind, &paths);
    }
    portable_claimed_paths_free(&claimed);
    portable_owned_paths_free(&owned);
    free(physical);
    return result;
}

static int prepare_collision_relocations(PortableCaptureContext *context,
                                          const PortableRootSpec *root)
{
    if (context == NULL || root == NULL)
        return -1;
    if (!context->resume_mode || context->collision_plan == NULL)
        return 0;
    if (context->owned_paths == NULL || context->claimed_paths == NULL)
        return -1;

    PortableOwnedPaths *owned = context->owned_paths;
    PortableClaimedPaths *claimed = context->claimed_paths;
    const PortableCollisionPlan *plan = context->collision_plan;
    for (size_t plan_index = 0; plan_index < plan->count; plan_index++) {
        const PortableCollisionPlanEntry *planned = &plan->entries[plan_index];
        if (strcmp(planned->root_id, root->id) != 0)
            continue;

        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)planned->logical_path,
            strlen(planned->logical_path)
        };
        SidecarLiveView previous = {0};
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0)
            return -1;
        SidecarClaimView previous_claim = {0};
        int claim_found = sidecar_log_find_claim(context->sidecar, root_key,
                                                 logical_key,
                                                 &previous_claim);
        if (claim_found < 0)
            return -1;
        if (live == 1 && claim_found == 1)
            return -1;
        if (!live && !claim_found)
            continue;

        SidecarBytes old_physical_bytes = live == 1
            ? previous.entry->physical_path
            : previous_claim.claim->physical_path;
        if (sidecar_bytes_equal(
                old_physical_bytes,
                (SidecarBytes){
                    (const unsigned char *)planned->physical_path,
                    strlen(planned->physical_path) }))
            continue;

        char *old_physical = NULL;
        if (sidecar_bytes_to_text(old_physical_bytes, &old_physical) != 0 ||
            old_physical[0] == '\0' ||
            !safe_relative_path(old_physical) ||
            !safe_relative_path(planned->physical_path)) {
            free(old_physical);
            return -1;
        }

        if (live == 1) {
            size_t candidate_count = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) != 0 ||
                    !relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    continue;
                if (!relative_path_prefix_match(
                        old_physical, candidate->physical_path, NULL) ||
                    !safe_relative_path(candidate->physical_path)) {
                    free(old_physical);
                    return -1;
                }
                candidate_count++;
            }
            if (candidate_count == 0) {
                free(old_physical);
                return -1;
            }

            unsigned char *selected = calloc(owned->count,
                                             sizeof(*selected));
            if (selected == NULL) {
                free(old_physical);
                return -1;
            }
            int failed = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) == 0 &&
                    relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL)) {
                    selected[index] = 1;
                    if (tombstone_if_live(context, root->id,
                                          candidate->logical_path) != 0) {
                        failed = 1;
                        break;
                    }
                }
            }

            for (size_t removed = 0; !failed && removed < candidate_count;
                 removed++) {
                size_t selected_index = SIZE_MAX;
                size_t selected_depth = 0;
                for (size_t index = 0; index < owned->count; index++) {
                    relocation_scan_count();
                    if (selected[index] != 1)
                        continue;
                    size_t depth = relative_path_depth(
                        owned->items[index].physical_path);
                    if (selected_index == SIZE_MAX || depth > selected_depth) {
                        selected_index = index;
                        selected_depth = depth;
                    }
                }
                if (selected_index == SIZE_MAX) {
                    failed = 1;
                    break;
                }
                relocation_remove_count();
                if (remove_owned_payload_relative(
                        context->data_fd, root->payload_path,
                        owned->items[selected_index].physical_path) != 0) {
                    failed = 1;
                    break;
                }
                selected[selected_index] = 2;
            }
            free(selected);
            if (failed) {
                free(old_physical);
                return -1;
            }
        }

        if (claim_found == 1) {
            /* A directory CLAIM owns only its node; known live and claimed
             * descendants must be removed deepest-first.  Unknown children
             * make the non-recursive removal fail closed. */
            size_t owned_candidate_count = 0;
            size_t claimed_candidate_count = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) != 0 ||
                    !relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    continue;
                if (!relative_path_prefix_match(
                        old_physical, candidate->physical_path, NULL) ||
                    !safe_relative_path(candidate->physical_path)) {
                    free(old_physical);
                    return -1;
                }
                owned_candidate_count++;
            }
            for (size_t index = 0; index < claimed->count; index++) {
                relocation_scan_count();
                PortableClaimedPath *candidate = &claimed->items[index];
                if (strcmp(candidate->root_id, root->id) != 0 ||
                    !relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    continue;
                if (!relative_path_prefix_match(
                        old_physical, candidate->physical_path, NULL) ||
                    !safe_relative_path(candidate->physical_path)) {
                    free(old_physical);
                    return -1;
                }
                claimed_candidate_count++;
            }
            if (claimed_candidate_count == 0) {
                free(old_physical);
                return -1;
            }

            unsigned char *selected_owned = owned->count == 0
                ? NULL : calloc(owned->count, sizeof(*selected_owned));
            unsigned char *selected_claimed = claimed->count == 0
                ? NULL : calloc(claimed->count, sizeof(*selected_claimed));
            if ((owned->count != 0 && selected_owned == NULL) ||
                (claimed->count != 0 && selected_claimed == NULL)) {
                free(selected_owned);
                free(selected_claimed);
                free(old_physical);
                return -1;
            }

            int failed = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) == 0 &&
                    relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL)) {
                    selected_owned[index] = 1;
                    if (tombstone_if_live(context, root->id,
                                          candidate->logical_path) != 0) {
                        failed = 1;
                        break;
                    }
                }
            }
            for (size_t index = 0; index < claimed->count; index++) {
                if (failed)
                    break;
                relocation_scan_count();
                PortableClaimedPath *candidate = &claimed->items[index];
                if (strcmp(candidate->root_id, root->id) == 0 &&
                    relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    selected_claimed[index] = 1;
            }

            size_t remaining = owned_candidate_count + claimed_candidate_count;
            for (size_t removed = 0; !failed && removed < remaining; removed++) {
                int selected_is_owned = 0;
                size_t selected_index = SIZE_MAX;
                size_t selected_depth = 0;
                for (size_t index = 0; index < owned->count; index++) {
                    relocation_scan_count();
                    if (selected_owned[index] != 1)
                        continue;
                    size_t depth = relative_path_depth(
                        owned->items[index].physical_path);
                    if (selected_index == SIZE_MAX || depth > selected_depth) {
                        selected_index = index;
                        selected_depth = depth;
                        selected_is_owned = 1;
                    }
                }
                for (size_t index = 0; index < claimed->count; index++) {
                    relocation_scan_count();
                    if (selected_claimed[index] != 1)
                        continue;
                    size_t depth = relative_path_depth(
                        claimed->items[index].physical_path);
                    if (selected_index == SIZE_MAX || depth > selected_depth) {
                        selected_index = index;
                        selected_depth = depth;
                        selected_is_owned = 0;
                    }
                }
                if (selected_index == SIZE_MAX) {
                    failed = 1;
                    break;
                }
                relocation_remove_count();
                if (selected_is_owned) {
                    if (remove_owned_payload_relative(
                            context->data_fd, root->payload_path,
                            owned->items[selected_index].physical_path) != 0) {
                        failed = 1;
                        break;
                    }
                    selected_owned[selected_index] = 2;
                } else {
                    PortableClaimedPath *candidate =
                        &claimed->items[selected_index];
                    if (remove_owned_payload_relative(
                            context->data_fd, root->payload_path,
                            candidate->physical_path) != 0 ||
                        append_claim_delete(context, root,
                                            candidate->logical_path) != 0) {
                        failed = 1;
                        break;
                    }
                    selected_claimed[selected_index] = 2;
                }
            }
            free(selected_owned);
            free(selected_claimed);
            if (failed) {
                free(old_physical);
                return -1;
            }
        }

        free(old_physical);
    }
    return 0;
}

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} InventoryOrphans;

static void inventory_orphans_free(InventoryOrphans *orphans)
{
    if (orphans == NULL)
        return;
    for (size_t index = 0; index < orphans->count; index++)
        free(orphans->items[index]);
    free(orphans->items);
    memset(orphans, 0, sizeof(*orphans));
}

static int inventory_orphans_append(InventoryOrphans *orphans,
                                    const char *relative)
{
    if (orphans == NULL || relative == NULL)
        return -1;
    if (orphans->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (orphans->count == orphans->capacity) {
        size_t capacity = orphans->capacity == 0 ? 16U : orphans->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < orphans->capacity ||
            capacity > SIZE_MAX / sizeof(*orphans->items))
            return -1;
        char **items = realloc(orphans->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        orphans->items = items;
        orphans->capacity = capacity;
    }
    char *copy = strdup(relative);
    if (copy == NULL)
        return -1;
    orphans->items[orphans->count++] = copy;
    return 0;
}

typedef struct {
    PortableCaptureContext *context;
    const char *root_id;
    PortableVisited live_paths;
    PortableVisited physical_directories;
    PortableVisited seen_paths;
    InventoryOrphans orphans;
    int orphan_root;
    int failed;
    size_t live_count;
} InventoryState;

static int inventory_live_callback(const SidecarLiveView *view, void *argument)
{
    InventoryState *inventory = argument;
    if (inventory == NULL || inventory->root_id == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->entry->root_id,
            (SidecarBytes){ (const unsigned char *)inventory->root_id,
                            strlen(inventory->root_id) }))
        return 0;
    char *physical = NULL;
    if (sidecar_bytes_to_text(view->entry->physical_path, &physical) != 0) {
        inventory->failed = 1;
        return 1;
    }
    int inserted = visited_add(&inventory->live_paths, inventory->root_id,
                               physical);
    if (inserted != 0) {
        inventory->failed = 1;
        free(physical);
        return 1;
    }
    if (view->entry->kind == SIDECAR_KIND_DIRECTORY &&
        visited_add(&inventory->physical_directories, inventory->root_id,
                    physical) != 0) {
        inventory->failed = 1;
        free(physical);
        return 1;
    }
    inventory->live_count++;
    free(physical);
    return 0;
}

static int inventory_scan_node(InventoryState *inventory,
                               int parent_fd, const char *leaf,
                               const char *relative, int is_root)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    SidecarBytes key = {
        (const unsigned char *)relative, strlen(relative)
    };
    SidecarLiveView live_view;
    int live = sidecar_log_find(inventory->context->sidecar,
                                (SidecarBytes){
                                    (const unsigned char *)inventory->root_id,
                                    strlen(inventory->root_id)
                                }, key, &live_view);
    if (live < 0)
        return -1;
    SidecarObjectKind expected_kind = SIDECAR_KIND_REGULAR;
    if (live == 1 &&
        sidecar_bytes_equal(live_view.entry->physical_path, key))
        expected_kind = live_view.entry->kind;
    else {
        int physical_present = visited_contains(&inventory->live_paths,
                                                inventory->root_id, relative);
        if (physical_present < 0)
            return -1;
        if (physical_present == 1) {
            int is_directory = visited_contains(
                &inventory->physical_directories, inventory->root_id,
                relative);
            if (is_directory < 0)
                return -1;
            live = 1;
            expected_kind = is_directory == 1 ? SIDECAR_KIND_DIRECTORY :
                                                SIDECAR_KIND_REGULAR;
        } else if (live == 1) {
            live = 0;
        }
    }
    if (live == 0) {
        int deleted = sidecar_log_find_deleted(
            inventory->context->sidecar,
            (SidecarBytes){ (const unsigned char *)inventory->root_id,
                            strlen(inventory->root_id) },
            key, &live_view);
        if (deleted < 0)
            return -1;
        if (deleted == 1) {
            if (is_root)
                inventory->orphan_root = 1;
            else if (inventory_orphans_append(&inventory->orphans,
                                              relative) != 0)
                return -1;
            return 0;
        }
        inventory->failed = 1;
        return -1;
    }

    if (visited_add(&inventory->seen_paths, inventory->root_id, relative) != 0)
        return -1;
    if ((expected_kind == SIDECAR_KIND_DIRECTORY) !=
        (S_ISDIR(st.st_mode) != 0))
        return -1;
    if (!S_ISDIR(st.st_mode))
        return 0;

    int directory_fd = open_child_directory(parent_fd, leaf);
    if (directory_fd < 0)
        return -1;
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char child_relative[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_relative, sizeof(child_relative), relative,
                           entry->d_name) != 0 ||
            inventory_scan_node(inventory, directory_fd, entry->d_name,
                                child_relative, 0) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int inventory_seen_callback(const SidecarLiveView *view,
                                   void *argument)
{
    InventoryState *inventory = argument;
    if (inventory == NULL || inventory->root_id == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->entry->root_id,
            (SidecarBytes){ (const unsigned char *)inventory->root_id,
                            strlen(inventory->root_id) }))
        return 0;
    char *physical = NULL;
    if (sidecar_bytes_to_text(view->entry->physical_path, &physical) != 0) {
        inventory->failed = 1;
        return 1;
    }
    int present = visited_contains(&inventory->seen_paths,
                                   inventory->root_id, physical);
    free(physical);
    if (present != 1) {
        inventory->failed = 1;
        return 1;
    }
    return 0;
}

static int reconcile_inventory(PortableCaptureContext *context,
                               const PortableRootSpec *root)
{
    InventoryState inventory;
    memset(&inventory, 0, sizeof(inventory));
    inventory.context = context;
    inventory.root_id = root->id;
    inventory.live_paths.hash_salt = sidecar_process_salt();
    inventory.physical_directories.hash_salt = inventory.live_paths.hash_salt;
    inventory.seen_paths.hash_salt = inventory.live_paths.hash_salt;

    SidecarStatus status = sidecar_log_foreach(context->sidecar,
                                               inventory_live_callback,
                                               &inventory);
    if (status != SIDECAR_STATUS_OK || inventory.failed)
        goto fail;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(context->data_fd, root->payload_path,
                                     &root_parent, root_leaf,
                                     sizeof(root_leaf)) != 0) {
        if (errno == ENOENT && inventory.live_count == 0) {
            inventory_orphans_free(&inventory.orphans);
            visited_dispose(&inventory.live_paths);
            visited_dispose(&inventory.physical_directories);
            visited_dispose(&inventory.seen_paths);
            return 0;
        }
        goto fail;
    }

    if (inventory_scan_node(&inventory, root_parent, root_leaf, "", 1) != 0)
        goto close_fail;
    if (close(root_parent) != 0)
        goto fail;
    root_parent = -1;

    if (inventory.orphan_root) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_payload_relative(context->data_fd, root->payload_path,
                                     "") != 0)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
    }
    for (size_t index = 0; index < inventory.orphans.count; index++) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_payload_relative(context->data_fd, root->payload_path,
                                     inventory.orphans.items[index]) != 0)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
    }

    status = sidecar_log_foreach(context->sidecar, inventory_seen_callback,
                                 &inventory);
    if (status != SIDECAR_STATUS_OK || inventory.failed)
        goto fail;

    inventory_orphans_free(&inventory.orphans);
    visited_dispose(&inventory.live_paths);
    visited_dispose(&inventory.physical_directories);
    visited_dispose(&inventory.seen_paths);
    return 0;

close_fail:
    {
        int saved = errno;
        close(root_parent);
        errno = saved;
    }
fail:
    inventory_orphans_free(&inventory.orphans);
    visited_dispose(&inventory.live_paths);
    visited_dispose(&inventory.physical_directories);
    visited_dispose(&inventory.seen_paths);
    return -1;
}

static int reconcile_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    StaleKeys stale;
    StaleClaims stale_claims;
    PortableOwnedPaths owned;
    PortableClaimedPaths claimed;
    memset(&stale, 0, sizeof(stale));
    memset(&stale_claims, 0, sizeof(stale_claims));
    memset(&owned, 0, sizeof(owned));
    memset(&claimed, 0, sizeof(claimed));
    StaleCollection collection = {
        .context = context,
        .root_id = root->id,
        .stale = &stale
    };
    SidecarStatus status = sidecar_log_foreach(context->sidecar,
                                               collect_stale_key,
                                               &collection);
    if (status != SIDECAR_STATUS_OK || stale.failed)
        goto fail;

    for (size_t index = 0; index < stale.count; index++) {
        SidecarDelete deletion = {
            .root_id = { (const unsigned char *)root->id,
                        strlen(root->id) },
            .logical_path = { (const unsigned char *)stale.items[index].logical,
                              strlen(stale.items[index].logical) }
        };
        if (sidecar_log_append_delete(context->sidecar, &deletion) !=
            SIDECAR_STATUS_OK)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_DELETE);
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_payload_relative(context->data_fd, root->payload_path,
                                    stale.items[index].physical) != 0)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
    }

    stale_keys_free(&stale);
    StaleClaimCollection claim_collection = {
        .context = context,
        .root_id = root->id,
        .stale = &stale_claims
    };
    status = sidecar_log_claim_foreach(context->sidecar, collect_stale_claim,
                                       &claim_collection);
    if (status != SIDECAR_STATUS_OK || stale_claims.failed)
        goto fail;
    if (portable_owned_paths_load(&owned, context->sidecar) != 0 ||
        portable_claimed_paths_load(&claimed, context->sidecar) != 0)
        goto fail;

    ClaimOwnershipPaths paths = {
        .owned = &owned,
        .claimed = &claimed
    };
    for (size_t index = 0; index < stale_claims.count; index++) {
        StaleClaim *claim = &stale_claims.items[index];
        if (reconcile_stale_claim_with_paths(
                context, root, claim->logical, claim->physical, claim->kind,
                &paths) != 0)
            goto fail;
    }

    portable_claimed_paths_free(&claimed);
    portable_owned_paths_free(&owned);
    stale_claims_free(&stale_claims);
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_FINAL_INVENTORY);
    return reconcile_inventory(context, root);

fail:
    stale_keys_free(&stale);
    portable_claimed_paths_free(&claimed);
    portable_owned_paths_free(&owned);
    stale_claims_free(&stale_claims);
    return -1;
}

static int read_source_stat(int source_parent, const char *source_name,
                            const char *root_path, struct stat *out)
{
    if (out == NULL)
        return -1;
    if (source_parent >= 0)
        return fstatat(source_parent, source_name, out, AT_SYMLINK_NOFOLLOW);
    return lstat(root_path, out);
}

static int source_symlink_target(int source_parent, const char *source_name,
                                 const char *root_path, char *target,
                                 size_t target_size)
{
    if (target == NULL || target_size == 0)
        return -1;
    ssize_t length;
    if (source_parent >= 0) {
        if (source_name == NULL)
            return -1;
        length = readlinkat(source_parent, source_name, target, target_size);
    } else {
        if (root_path == NULL)
            return -1;
        length = readlink(root_path, target, target_size);
    }
    if (length <= 0 || (size_t)length >= target_size)
        return -1;
    target[length] = '\0';
    return (int)length;
}

static int source_symlink_xattr_path(int source_parent,
                                     const char *source_name,
                                     const char *root_path, char *path,
                                     size_t path_size)
{
    if (path == NULL || path_size == 0)
        return -1;
    if (source_parent < 0)
        return copy_text(path, path_size, root_path);
    if (source_name == NULL || !safe_component(source_name))
        return -1;
    int length = snprintf(path, path_size, "/proc/self/fd/%d/%s",
                          source_parent, source_name);
    return length < 0 || (size_t)length >= path_size ? -1 : 0;
}

static int open_source_node(int source_parent, const char *source_name,
                            const char *root_path, const struct stat *st)
{
    int flags = O_RDONLY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC;
    if (S_ISDIR(st->st_mode))
        flags |= O_DIRECTORY;
    if (source_parent >= 0)
        return openat(source_parent, source_name, flags);
    return open(root_path, flags);
}

int portable_copy_regular(int source_fd, int destination_fd, off_t expected_size,
                          BackupCaptureReport *report)
{
    if (source_fd < 0 || destination_fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (ftruncate(destination_fd, 0) != 0)
        return -1;

    unsigned char buffer[65536];
    uint64_t copied = 0;
    for (;;) {
        ssize_t received = read(source_fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            return -1;
        if (received == 0)
            break;
        if ((uint64_t)received > UINT64_MAX - copied)
        {
            errno = EOVERFLOW;
            return -1;
        }

        size_t offset = 0;
        while (offset < (size_t)received) {
            ssize_t written = write(destination_fd, buffer + offset,
                                     (size_t)received - offset);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0)
                return -1;
            offset += (size_t)written;
        }
        copied += (uint64_t)received;
        if (backup_capture_report_tick(report, received, destination_fd) != 0)
            return -1;
    }
    if (expected_size < 0 || copied != (uint64_t)expected_size)
    {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int physical_path_parent_matches(const char *physical,
                                        const char *parent)
{
    if (physical == NULL || parent == NULL)
        return 0;
    const char *slash = strrchr(physical, '/');
    if (slash == NULL)
        return parent[0] == '\0';
    size_t parent_length = (size_t)(slash - physical);
    return strlen(parent) == parent_length &&
           memcmp(physical, parent, parent_length) == 0;
}

static int physical_path_leaf(const char *physical, char *leaf,
                              size_t leaf_size)
{
    if (physical == NULL || leaf == NULL || leaf_size == 0 ||
        physical[0] == '\0')
        return -1;
    const char *slash = strrchr(physical, '/');
    const char *name = slash == NULL ? physical : slash + 1;
    if (!safe_component(name))
        return -1;
    return copy_text(leaf, leaf_size, name);
}

static int capture_plan_child(const PortableCaptureContext *context,
                              const PortableRootSpec *root,
                              const char *logical, const char *parent_physical,
                              const char *encoded_leaf,
                              char *physical, size_t physical_size,
                              char *leaf, size_t leaf_size)
{
    if (context == NULL || root == NULL || logical == NULL ||
        parent_physical == NULL || encoded_leaf == NULL || physical == NULL ||
        leaf == NULL)
        return -1;

    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(context->collision_plan, root->id,
                                     logical);
    if (planned == NULL) {
        if (append_physical(physical, physical_size, parent_physical,
                            encoded_leaf) != 0 ||
            copy_text(leaf, leaf_size, encoded_leaf) != 0)
            return -1;
        return 0;
    }

    if (!physical_path_parent_matches(planned->physical_path,
                                      parent_physical) ||
        copy_text(physical, physical_size, planned->physical_path) != 0 ||
        physical_path_leaf(planned->physical_path, leaf, leaf_size) != 0)
        return -1;
    return 0;
}

static int capture_plan_entries_seen(const PortableCaptureContext *context,
                                    const PortableRootSpec *root)
{
    if (context == NULL || root == NULL)
        return -1;
    const PortableCollisionPlan *plan = context->collision_plan;
    if (plan == NULL)
        return 0;
    for (size_t index = 0; index < plan->count; index++) {
        const PortableCollisionPlanEntry *entry = &plan->entries[index];
        if (strcmp(entry->root_id, root->id) != 0)
            continue;
        int present = visited_contains(context->visited, root->id,
                                       entry->logical_path);
        if (present != 1)
            return -1;
    }
    return 0;
}

static int capture_node(PortableCaptureContext *context,
                        const PortableRootSpec *root,
                        const char *logical, const char *physical,
                        int source_parent,
                        const char *source_name, const char *root_path,
                        int destination_parent, const char *destination_leaf);

static int capture_directory(PortableCaptureContext *context,
                             const PortableRootSpec *root,
                             const char *logical, const char *physical,
                             int source_fd,
                             const struct stat *before, int destination_fd,
                             PortableXattrs *xattrs,
                             const char *collision_suffix)
{
    PendingReadbackNames pending = {0};
    int scan_fd = dup_cloexec(source_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    int failed = 0;
    PortableCaseFoldSet observed_skeletons = {0};
    PortableCaseFoldSet observed_ascii = {0};
    if (!context->case_sensitive)
        observed_skeletons.hash_salt = sidecar_process_salt();
    if (!context->case_sensitive)
        observed_ascii.hash_salt = sidecar_process_salt();
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0) {
            failed = 1;
            break;
        }

        char encoded_leaf[NAME_MAX + 1U];
        if (encoding_percent_encode(ENCODING_MODE_COMPONENT, entry->d_name,
                                    encoded_leaf, sizeof(encoded_leaf)) != 0) {
            failed = 1;
            break;
        }

        if (!context->case_sensitive) {
            char skeleton[NAME_MAX + 1U];
            char ascii_skeleton[NAME_MAX + 1U];
            skeleton_copy(skeleton, sizeof(skeleton), encoded_leaf);
            ascii_fold_copy(ascii_skeleton, sizeof(ascii_skeleton),
                            encoded_leaf);
            char *existing_logical = NULL;
            int duplicate = case_fold_set_find_or_insert(
                &observed_skeletons, skeleton, child_logical,
                &existing_logical);
            char *existing_ascii_logical = NULL;
            int ascii_duplicate = case_fold_set_find_or_insert(
                &observed_ascii, ascii_skeleton, child_logical,
                &existing_ascii_logical);
            const PortableCollisionPlanEntry *current_plan =
                portable_collision_plan_find(context->collision_plan,
                                              root->id, child_logical);
            const PortableCollisionPlanEntry *existing_plan =
                duplicate == 1
                    ? portable_collision_plan_find(context->collision_plan,
                                                   root->id, existing_logical)
                    : NULL;
            const PortableCollisionPlanEntry *existing_ascii_plan =
                ascii_duplicate == 1
                    ? portable_collision_plan_find(
                          context->collision_plan, root->id,
                          existing_ascii_logical)
                    : NULL;
            /* A case-folded sibling group is valid only when the pre-scan
             * planned both members.  ASCII folding is authoritative for the
             * deterministic collision class; the broader skeleton catches a
             * newly added non-ASCII twin only when the pre-scan had planned
             * that candidate group, avoiding false refusals for distinct
             * names that the destination probe kept separate (D21, F-8). */
            if (duplicate < 0 || ascii_duplicate < 0 ||
                (ascii_duplicate == 1 &&
                 (current_plan == NULL || existing_ascii_plan == NULL)) ||
                (duplicate == 1 &&
                 (current_plan != NULL || existing_plan != NULL) &&
                 (current_plan == NULL || existing_plan == NULL))) {
                failed = 1;
                break;
            }
        }

        char child_physical[SIDECAR_MAX_PATH + 1U];
        char child_leaf[NAME_MAX + 1U];
        if (capture_plan_child(context, root, child_logical, physical,
                               encoded_leaf, child_physical,
                               sizeof(child_physical), child_leaf,
                               sizeof(child_leaf)) != 0) {
            failed = 1;
            break;
        }

        size_t payload_root_length = strlen(root->payload_path);
        size_t physical_length = strlen(child_physical);
        if (!portable_payload_path_fits(payload_root_length, physical_length,
                                        PATH_MAX)) {
            failed = 1;
            break;
        }

        if (encoded_name_has_raw_high_byte(child_leaf) &&
            pending_readback_names_add(&pending, child_leaf) != 0) {
            failed = 1;
            break;
        }

        if (capture_node(context, root, child_logical, child_physical,
                         source_fd, entry->d_name, NULL, destination_fd,
                         child_leaf) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;

    case_fold_set_free(&observed_skeletons);
    case_fold_set_free(&observed_ascii);

    struct stat after;
    if (!failed && (fstat(source_fd, &after) != 0 ||
                    !metadata_source_unchanged(before, &after)))
        failed = 1;

    if (!failed && verify_pending_readback_names(destination_fd, &pending) != 0)
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    if (failed) {
        pending_readback_names_free(&pending);
        xattrs_free(xattrs);
        close(destination_fd);
        return -1;
    }

    SidecarEntry sidecar_entry;
    if (entry_from_stat(root->id, logical, physical, collision_suffix, before,
                        context->nsec_exact,
                        xattrs, &sidecar_entry, NULL, NULL, NULL) != 0 ||
        append_group(context, &sidecar_entry, xattrs) != 0) {
        pending_readback_names_free(&pending);
        xattrs_free(xattrs);
        close(destination_fd);
        return -1;
    }
    pending_readback_names_free(&pending);
    xattrs_free(xattrs);
    return close(destination_fd) == 0 ? 0 : -1;
}

static int capture_regular(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical,
                           const char *collision_suffix,
                           int source_fd,
                           const struct stat *before,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           PortableXattrs *xattrs)
{
    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_REGULAR) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_WRITE);
    if (context->progress_report != NULL)
        snprintf(context->progress_report->current_path,
                 sizeof(context->progress_report->current_path), "%s", physical);
    if (portable_copy_regular(source_fd, destination_fd, before->st_size,
                              context->progress_report) != 0) {
        close(destination_fd);
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_WRITE);

    struct stat after;
    int failed = fstat(source_fd, &after) != 0 ||
                 !metadata_source_unchanged(before, &after);
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE);
    if (close(destination_fd) != 0)
        failed = 1;
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_CLOSE);
    if (close(source_fd) != 0)
        failed = 1;
    if (destination_is_root)
        close(parent_fd);
    if (failed) {
        xattrs_free(xattrs);
        return -1;
    }

    SidecarEntry sidecar_entry;
    failed = entry_from_stat(root->id, logical, physical, collision_suffix,
                             before,
                             context->nsec_exact,
                             xattrs, &sidecar_entry, NULL, NULL, NULL) != 0 ||
             append_group(context, &sidecar_entry, xattrs) != 0;
    xattrs_free(xattrs);
    return failed ? -1 : 0;
}

static int capture_special(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root, const struct stat *st)
{
    if (visited_add(context->visited, root->id, logical) != 0)
        return -1;

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0)
            return -1;
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe(context, root, logical, physical,
                                    parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (remove_leaf(parent_fd, destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (destination_is_root)
        close(parent_fd);

    const char *kind = S_ISSOCK(st->st_mode) ? "socket" : "device";
    print_warning("Warning: skipping unsupported %s %s\n", kind,
           logical[0] == '\0' ? root->capture_path : logical);
    return 0;
}

static int capture_symlink(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical,
                           const char *collision_suffix,
                           int source_parent,
                           const char *source_name, const char *root_path,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           const struct stat *before)
{
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    int target_length = source_symlink_target(source_parent, source_name,
                                              root_path, target,
                                              sizeof(target));
    if (target_length < 0)
        return -1;

    char source_path[PATH_MAX];
    if (source_symlink_xattr_path(source_parent, source_name, root_path,
                                  source_path, sizeof(source_path)) != 0)
        return -1;
    PortableXattrs xattrs;
    if (collect_symlink_xattrs(source_path, &xattrs) != 0)
        return -1;

    // The final consistency check runs after every path-based read (target,
    // then xattrs) rather than right after the target read: symlinks have no
    // usable fd (open_source_node's O_NOFOLLOW would hit ELOOP), so each read
    // above re-resolves the path independently and nothing pins them to one
    // inode the way capture_regular's single fd does. One check positioned
    // last covers the read window for both.
    struct stat after;
    if (read_source_stat(source_parent, source_name, root_path, &after) != 0 ||
        !metadata_symlink_unchanged(before, &after)) {
        xattrs_free(&xattrs);
        return -1;
    }

    if (visited_add(context->visited, root->id, logical) != 0) {
        xattrs_free(&xattrs);
        return -1;
    }

    SidecarBytes target_bytes = {
        (const unsigned char *)target, (size_t)target_length
    };
    SidecarEntry entry;
    if (entry_from_stat(root->id, logical, physical, collision_suffix, before,
                        context->nsec_exact,
                        &xattrs, &entry, &target_bytes, NULL, NULL) != 0) {
        xattrs_free(&xattrs);
        return -1;
    }

    if (context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView previous;
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0) {
            xattrs_free(&xattrs);
            return -1;
        }
        if (live == 1 && entries_equal(&entry, &previous, &xattrs)) {
            int payload = existing_payload_matches(
                context->data_fd, root->payload_path, destination_parent,
                destination_leaf, destination_is_root, 0);
            if (payload < 0) {
                xattrs_free(&xattrs);
                return -1;
            }
            if (payload == 1) {
                xattrs_free(&xattrs);
                return 0;
            }
        }
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(&xattrs);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }

    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_SYMLINK) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf,
                            &destination_fd) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);
    int failed = close(destination_fd) != 0;
    if (destination_is_root && close(parent_fd) != 0)
        failed = 1;
    if (failed) {
        xattrs_free(&xattrs);
        return -1;
    }

    failed = append_group(context, &entry, &xattrs) != 0;
    xattrs_free(&xattrs);
    return failed ? -1 : 0;
}

static int capture_hardlink(PortableCaptureContext *context,
                            const PortableRootSpec *root,
                            const char *logical, const char *physical,
                            const char *collision_suffix,
                            int source_fd, const struct stat *before,
                            int destination_parent,
                            const char *destination_leaf,
                            int destination_is_root,
                            const PortableInodeSlot *representative)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL || collision_suffix == NULL || source_fd < 0 ||
        before == NULL || representative == NULL)
        return -1;

    SidecarBytes hardlink_root_id = {
        (const unsigned char *)representative->root_id,
        representative->root_length
    };
    SidecarBytes hardlink_logical_path = {
        (const unsigned char *)representative->logical_path,
        representative->logical_length
    };
    SidecarEntry entry;
    PortableXattrs empty_xattrs = {0};
    if (entry_from_stat(root->id, logical, physical, collision_suffix, before,
                        context->nsec_exact, &empty_xattrs, &entry, NULL,
                        &hardlink_root_id, &hardlink_logical_path) != 0) {
        close(source_fd);
        return -1;
    }

    if (context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView previous;
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0) {
            close(source_fd);
            return -1;
        }
        if (live == 1 && entries_equal(&entry, &previous, &empty_xattrs)) {
            int payload = existing_payload_matches(
                context->data_fd, root->payload_path, destination_parent,
                destination_leaf, destination_is_root, 0);
            if (payload < 0) {
                close(source_fd);
                return -1;
            }
            if (payload == 1)
                return close(source_fd) == 0 ? 0 : -1;
        }
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_HARDLINK) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);

    struct stat after;
    int failed = fstat(source_fd, &after) != 0 ||
                 !metadata_source_unchanged(before, &after);
    if (close(destination_fd) != 0)
        failed = 1;
    if (destination_is_root && close(parent_fd) != 0)
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    if (failed)
        return -1;

    return append_group(context, &entry, NULL) == 0 ? 0 : -1;
}

static int capture_node(PortableCaptureContext *context,
                        const PortableRootSpec *root,
                        const char *logical, const char *physical,
                        int source_parent,
                        const char *source_name, const char *root_path,
                        int destination_parent, const char *destination_leaf)
{
    struct stat before;
    if (read_source_stat(source_parent, source_name, root_path, &before) != 0)
        return -1;

    const char *collision_suffix = "";
    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(context->collision_plan, root->id,
                                     logical);
    if (planned != NULL) {
        if (strcmp(planned->physical_path, physical) != 0)
            return -1;
        collision_suffix = planned->collision_suffix;
    }

    int is_root = source_parent < 0;
    if (S_ISSOCK(before.st_mode) || S_ISCHR(before.st_mode) ||
        S_ISBLK(before.st_mode))
        return capture_special(context, root, logical, physical,
                               destination_parent, destination_leaf, is_root,
                               &before);
    if (S_ISFIFO(before.st_mode)) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (S_ISLNK(before.st_mode))
        return capture_symlink(context, root, logical, physical,
                               collision_suffix, source_parent,
                               source_name, root_path, destination_parent,
                               destination_leaf, is_root, &before);
    if (!S_ISREG(before.st_mode) && !S_ISDIR(before.st_mode)) {
        errno = EOPNOTSUPP;
        return -1;
    }

    int source_fd = open_source_node(source_parent, source_name, root_path,
                                     &before);
    if (source_fd < 0)
        return -1;
    struct stat opened;
    if (fstat(source_fd, &opened) != 0 ||
        !metadata_source_unchanged(&before, &opened)) {
        close(source_fd);
        return -1;
    }

    if (visited_add(context->visited, root->id, logical) != 0) {
        close(source_fd);
        return -1;
    }

    const PortableInodeSlot *representative = NULL;
    if (S_ISREG(before.st_mode)) {
        int inode_state = inode_map_find_or_insert(
            context->inode_map, opened.st_dev, opened.st_ino, root->id,
            logical, &representative);
        if (inode_state < 0) {
            close(source_fd);
            return -1;
        }
        int same_logical_entry = inode_state == 1 && representative != NULL &&
                                 strcmp(representative->root_id, root->id) == 0 &&
                                 strcmp(representative->logical_path, logical) == 0;
        if (inode_state == 1 && !same_logical_entry) {
            return capture_hardlink(context, root, logical, physical,
                                    collision_suffix, source_fd, &before,
                                    destination_parent, destination_leaf,
                                    is_root, representative);
        }
    }

    PortableXattrs xattrs;
    if (collect_xattrs(source_fd, &xattrs) != 0) {
        close(source_fd);
        return -1;
    }

    if (S_ISREG(before.st_mode) && context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView previous;
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0) {
            xattrs_free(&xattrs);
            close(source_fd);
            return -1;
        }
        if (live == 1) {
            SidecarEntry current;
            int matches = entry_from_stat(root->id, logical, physical,
                                          collision_suffix, &before,
                                          context->nsec_exact, &xattrs,
                                          &current, NULL, NULL, NULL) == 0 &&
                          entries_equal(&current, &previous, &xattrs);
            if (matches) {
                int payload = existing_payload_matches(
                    context->data_fd, root->payload_path, destination_parent,
                    destination_leaf, is_root, current.size);
                if (payload < 0) {
                    xattrs_free(&xattrs);
                    close(source_fd);
                    return -1;
                }
                if (payload == 1) {
                    xattrs_free(&xattrs);
                    return close(source_fd) == 0 ? 0 : -1;
                }
            }
        }
    }

    if (S_ISREG(before.st_mode))
        return capture_regular(context, root, logical, physical,
                               collision_suffix, source_fd,
                               &before,
                               destination_parent, destination_leaf, is_root,
                               &xattrs);

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(&xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }

    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_DIRECTORY) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    if (ensure_directory_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }
    if (capture_directory(context, root, logical, physical, source_fd, &before,
                          destination_fd, &xattrs, collision_suffix) != 0) {
        if (is_root)
            close(parent_fd);
        return -1;
    }
    if (is_root)
        close(parent_fd);
    return 0;
}

static int root_spec_valid(const PortableRootSpec *root)
{
    if (root == NULL || !safe_id(root->id) || root->capture_path == NULL ||
        root->capture_path[0] != '/' || !safe_relative_path(root->payload_path) ||
        root->source_path == NULL)
        return 0;
    if (root->policy < ROOT_POLICY_XDG ||
        root->policy > ROOT_POLICY_MANUAL_NATIVE)
        return 0;
    if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
        return 0;
    if (root->policy == ROOT_POLICY_HOME_RELATIVE) {
        if (!root->has_restore_path || root->restore_path == NULL)
            return 0;
    } else if (root->has_restore_path) {
        return 0;
    }
    if (root->has_restore_path && root->restore_path == NULL)
        return 0;
    if (root->has_restore_path && root->restore_path[0] != '\0' &&
        !safe_relative_path(root->restore_path))
        return 0;
    return strlen(root->capture_path) < PATH_MAX &&
           strlen(root->source_path) < PATH_MAX &&
           (!root->has_restore_path || strlen(root->restore_path) < PATH_MAX);
}

static int prescan_record_violation(PortablePrescanReport *report,
                                    const char *root_id,
                                    const char *logical_path,
                                    PortablePrescanViolationKind kind,
                                    size_t limit, size_t actual)
{
    PortablePrescanViolation violation = {
        .kind = kind,
        .limit = limit,
        .actual = actual
    };
    if (copy_text(violation.root_id, sizeof(violation.root_id), root_id) != 0 ||
        copy_text(violation.logical_path, sizeof(violation.logical_path),
                  logical_path) != 0)
        return -1;
    return prescan_report_add(report, &violation);
}

static int prescan_record_case_collision(PortablePrescanReport *report,
                                         const char *root_id,
                                         const char *logical_path,
                                         const char *collides_with)
{
    PortablePrescanViolation violation = {
        .kind = PORTABLE_PRESCAN_CASE_COLLISION
    };
    if (copy_text(violation.root_id, sizeof(violation.root_id), root_id) != 0 ||
        copy_text(violation.logical_path, sizeof(violation.logical_path),
                  logical_path) != 0 ||
        copy_text(violation.collides_with_logical_path,
                  sizeof(violation.collides_with_logical_path),
                  collides_with) != 0)
        return -1;
    if (report == NULL)
        return -1;
    if (report->collision_count != SIZE_MAX)
        report->collision_count++;
    return prescan_report_add(report, &violation);
}

#define PORTABLE_CASE_PROBE_DIR ".migr-case-probe"
#define PORTABLE_SKELETON_PLACEHOLDER '\001'

/*
 * The encoded component alphabet is ASCII alnum/._-% plus valid UTF-8 bytes;
 * invalid bytes are percent-encoded.  A control byte therefore cannot occur
 * in an encoded name.  Replacing every non-ASCII byte with that one marker
 * yields a sound candidate filter: vfat NLS tables and exFAT/NTFS up-case
 * tables map one code unit to one code unit, so a folding rule cannot change a
 * component's length or make two different skeletons equal.
 */
void skeleton_copy(char *destination, size_t destination_size,
                   const char *source)
{
    if (destination == NULL || destination_size == 0)
        return;
    size_t index = 0;
    if (source != NULL) {
        for (; source[index] != '\0' && index + 1U < destination_size;
             index++) {
            unsigned char byte = (unsigned char)source[index];
            if (byte >= 0x80U)
                destination[index] = PORTABLE_SKELETON_PLACEHOLDER;
            else if (byte >= 'A' && byte <= 'Z')
                destination[index] = (char)(byte + ('a' - 'A'));
            else
                destination[index] = source[index];
        }
    }
    destination[index] = '\0';
}

typedef struct {
    char **encoded_names;
    char **logical_paths;
    size_t count;
    size_t capacity;
    int ascii_collision;
} PortableCaseProbeGroup;

typedef struct {
    PortableCaseProbeGroup *items;
    size_t count;
    size_t capacity;
} PortableCaseProbeGroups;

typedef struct {
    int container_fd;
    int scratch_fd;
    int scratch_created;
} PortableCaseProbeState;

static char *portable_text_duplicate(const char *text)
{
    if (text == NULL)
        return NULL;
    size_t length = strlen(text);
    if (length == SIZE_MAX)
        return NULL;
    char *copy = malloc(length + 1U);
    if (copy == NULL)
        return NULL;
    memcpy(copy, text, length + 1U);
    return copy;
}

static void case_probe_group_free(PortableCaseProbeGroup *group)
{
    if (group == NULL)
        return;
    for (size_t index = 0; index < group->count; index++) {
        free(group->encoded_names[index]);
        free(group->logical_paths[index]);
    }
    free(group->encoded_names);
    free(group->logical_paths);
    memset(group, 0, sizeof(*group));
}

static void case_probe_groups_free(PortableCaseProbeGroups *groups)
{
    if (groups == NULL)
        return;
    for (size_t index = 0; index < groups->count; index++)
        case_probe_group_free(&groups->items[index]);
    free(groups->items);
    memset(groups, 0, sizeof(*groups));
}

static int case_probe_group_append(PortableCaseProbeGroup *group,
                                  const char *encoded,
                                  const char *logical)
{
    if (group == NULL || encoded == NULL || logical == NULL ||
        group->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (group->count == group->capacity) {
        size_t capacity = group->capacity == 0 ? 4U : group->capacity * 2U;
        if (capacity < group->capacity ||
            capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity > SIZE_MAX / sizeof(*group->encoded_names) ||
            capacity > SIZE_MAX / sizeof(*group->logical_paths))
            return -1;
        char **encoded_names = realloc(group->encoded_names,
                                       capacity * sizeof(*encoded_names));
        if (encoded_names == NULL)
            return -1;
        char **logical_paths = realloc(group->logical_paths,
                                       capacity * sizeof(*logical_paths));
        if (logical_paths == NULL) {
            group->encoded_names = encoded_names;
            return -1;
        }
        group->encoded_names = encoded_names;
        group->logical_paths = logical_paths;
        group->capacity = capacity;
    }

    char *encoded_copy = portable_text_duplicate(encoded);
    if (encoded_copy == NULL)
        return -1;
    char *logical_copy = portable_text_duplicate(logical);
    if (logical_copy == NULL) {
        free(encoded_copy);
        return -1;
    }
    group->encoded_names[group->count] = encoded_copy;
    group->logical_paths[group->count] = logical_copy;
    group->count++;
    return 0;
}

static int case_probe_groups_add(PortableCaseProbeGroups *groups,
                                 const char *encoded, const char *logical,
                                 size_t *out_index)
{
    if (groups == NULL || out_index == NULL ||
        groups->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (groups->count == groups->capacity) {
        size_t capacity = groups->capacity == 0 ? 8U : groups->capacity * 2U;
        if (capacity < groups->capacity ||
            capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity > SIZE_MAX / sizeof(*groups->items))
            return -1;
        PortableCaseProbeGroup *items = realloc(
            groups->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        memset(items + groups->capacity, 0,
               (capacity - groups->capacity) * sizeof(*items));
        groups->items = items;
        groups->capacity = capacity;
    }

    size_t index = groups->count++;
    if (case_probe_group_append(&groups->items[index], encoded, logical) != 0) {
        groups->count--;
        case_probe_group_free(&groups->items[index]);
        return -1;
    }
    *out_index = index;
    return 0;
}

static int case_probe_prepare(PortableCaseProbeState *state)
{
    if (state == NULL || state->container_fd < 0)
        return -1;
    if (state->scratch_fd >= 0)
        return 0;
    case_fs_probe_count();
    if (mkdirat(state->container_fd, PORTABLE_CASE_PROBE_DIR, 0700) != 0)
        return -1;
    state->scratch_created = 1;
    case_fs_probe_count();
    state->scratch_fd = openat(state->container_fd, PORTABLE_CASE_PROBE_DIR,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC);
    if (state->scratch_fd >= 0)
        return 0;
    int saved = errno;
    if (unlinkat(state->container_fd, PORTABLE_CASE_PROBE_DIR,
                 AT_REMOVEDIR) != 0) {
        saved = EIO;
        state->scratch_created = 1;
    } else {
        state->scratch_created = 0;
    }
    errno = saved;
    return -1;
}

static int case_probe_cleanup(PortableCaseProbeState *state)
{
    if (state == NULL)
        return -1;
    int failed = 0;
    if (state->scratch_fd >= 0 && close(state->scratch_fd) != 0)
        failed = 1;
    state->scratch_fd = -1;
    if (state->scratch_created) {
        if (remove_directory_tree(state->container_fd,
                                  PORTABLE_CASE_PROBE_DIR) != 0)
            failed = 1;
        state->scratch_created = 0;
    }
    return failed ? -1 : 0;
}

/* Read back one scratch-directory component exactly as the filesystem
 * reports it.  A successful mkdirat() that is only reachable through a
 * differently-spelled directory entry is not a trustworthy no-collision
 * result, so root-namespace probing treats that as a collision or an I/O
 * failure rather than guessing (docs/DECISIONS.md D21, F-5). */
static int root_probe_exact_name(int directory_fd, const char *name)
{
    if (directory_fd < 0 || !safe_component(name))
        return -1;
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }

    rewinddir(directory);

    int found = 0;
    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (strcmp(entry->d_name, name) == 0) {
            found = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    return failed ? -1 : found;
}

/* Creates a relative scratch path component by component.  Return values:
 * 0 means every component was created or already existed with the exact
 * spelling, 1 means the destination folded a component to another spelling,
 * and -1 means the probe could not establish a reliable result. */
static int root_probe_make_path(int root_fd, const char *relative)
{
    if (root_fd < 0 || !safe_relative_path(relative))
        return -1;
    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);
    int current = dup_cloexec(root_fd);
    if (current < 0)
        return -1;

    char *cursor = copy;
    int result = 0;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';

        int made = mkdirat(current, cursor, 0700);
        if (made != 0) {
            if (errno != EEXIST) {
                result = -1;
                break;
            }
            int exact = root_probe_exact_name(current, cursor);
            if (exact < 0) {
                result = -1;
                break;
            }
            if (exact == 0) {
                result = 1;
                break;
            }
        } else if (root_probe_exact_name(current, cursor) != 1) {
            result = -1;
            break;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0) {
            result = -1;
            break;
        }
        if (close(current) != 0) {
            close(next);
            result = -1;
            break;
        }
        current = next;
        if (slash == NULL)
            break;
        cursor = slash + 1;
    }
    if (close(current) != 0 && result == 0)
        result = -1;
    return result;
}

static int root_probe_pair(PortableCaseProbeState *state,
                           const PortableRootSpec *left,
                           const PortableRootSpec *right,
                           size_t pair_index)
{
    if (state == NULL || left == NULL || right == NULL ||
        !root_spec_valid(left) || !root_spec_valid(right) ||
        state->container_fd < 0 || case_probe_prepare(state) != 0)
        return -1;

    char probe_name[64];
    int name_length = snprintf(probe_name, sizeof(probe_name),
                               "root-pair-%zu", pair_index);
    if (name_length < 0 || (size_t)name_length >= sizeof(probe_name) ||
        mkdirat(state->scratch_fd, probe_name, 0700) != 0)
        return -1;

    int probe_fd = open_child_directory(state->scratch_fd, probe_name);
    if (probe_fd < 0) {
        (void)remove_directory_tree(state->scratch_fd, probe_name);
        return -1;
    }

    int first = root_probe_make_path(probe_fd, left->payload_path);
    int second = first == 0
        ? root_probe_make_path(probe_fd, right->payload_path)
        : -1;
    int failed = close(probe_fd) != 0;
    if (remove_directory_tree(state->scratch_fd, probe_name) != 0)
        failed = 1;
    if (failed || first < 0 || second < 0)
        return -1;
    return second == 1 ? 1 : 0;
}

static int root_payload_path_has_non_ascii(const char *path)
{
    if (path == NULL)
        return 0;
    for (size_t index = 0; path[index] != '\0'; index++)
        if ((unsigned char)path[index] >= 0x80U)
            return 1;
    return 0;
}

typedef struct {
    const char *encoded;
    const char *logical;
    char suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
} PortableCollisionAssignment;

static int portable_collision_assignment_compare(const void *left,
                                                 const void *right)
{
    const PortableCollisionAssignment *left_entry = left;
    const PortableCollisionAssignment *right_entry = right;
    int encoded_result = strcmp(left_entry->encoded, right_entry->encoded);
    if (encoded_result != 0)
        return encoded_result;
    return strcmp(left_entry->logical, right_entry->logical);
}

static int collision_suffix_format(uint64_t number, char *out,
                                   size_t out_size)
{
    if (out == NULL || out_size == 0)
        return -1;
    if (number == 0) {
        out[0] = '\0';
        return 0;
    }
    int length = snprintf(out, out_size, "%%7E%" PRIu64, number);
    if (length < 0 || (size_t)length >= out_size ||
        (size_t)length > SIDECAR_MAX_COLLISION_SUFFIX)
        return -1;

    uint64_t parsed = 0;
    if (!portable_collision_suffix_parse(out, (size_t)length, &parsed) ||
        parsed != number)
        return -1;
    return 0;
}

/* Returns 0 for a valid path, 1 for a NAME_MAX overflow, 2 for PATH_MAX. */
static int collision_paths_build(const char *parent_physical,
                                 const char *payload_path,
                                 const char *encoded, const char *suffix,
                                 char *leaf, size_t leaf_size,
                                 char *physical, size_t physical_size,
                                 size_t *actual_name, size_t *actual_path)
{
    if (parent_physical == NULL || payload_path == NULL || encoded == NULL ||
        suffix == NULL || leaf == NULL || physical == NULL ||
        actual_name == NULL || actual_path == NULL)
        return -1;
    size_t encoded_length = strlen(encoded);
    size_t suffix_length = strlen(suffix);
    if (encoded_length > SIZE_MAX - suffix_length)
        return -1;
    *actual_name = encoded_length + suffix_length;
    if (*actual_name > NAME_MAX || *actual_name >= leaf_size)
        return 1;

    size_t parent_length = bounded_strlen(parent_physical, physical_size);
    if (parent_length >= physical_size)
        return -1;
    size_t separator_length = parent_length == 0 ? 0U : 1U;
    if (parent_length > SIZE_MAX - separator_length ||
        parent_length + separator_length >
            SIZE_MAX - *actual_name)
        return -1;
    size_t physical_length = parent_length + separator_length + *actual_name;
    size_t payload_length = strlen(payload_path);
    if (payload_length > SIZE_MAX - 1U ||
        physical_length > SIZE_MAX - payload_length - 1U)
        return -1;
    *actual_path = payload_length + 1U + physical_length;
    if (physical_length >= physical_size || *actual_path >= PATH_MAX)
        return 2;

    memcpy(leaf, encoded, encoded_length);
    memcpy(leaf + encoded_length, suffix, suffix_length + 1U);
    if (append_physical(physical, physical_size, parent_physical, leaf) != 0)
        return -1;
    return 0;
}

static int case_probe_readback_matches(const PortableCaseFoldSet *expected,
                                       int directory_fd)
{
    if (expected == NULL || directory_fd < 0)
        return -1;
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    rewinddir(directory);

    size_t observed = 0;
    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (!case_fold_set_contains(expected, entry->d_name)) {
            failed = 1;
            break;
        }
        observed++;
    }
    if (closedir(directory) != 0)
        failed = 1;
    return failed || observed != expected->count ? -1 : 0;
}

static int case_probe_reserved_name_contains(
    const PortableCaseFoldSet *reserved_names, const char *payload_path,
    const char *physical)
{
    if (reserved_names == NULL || payload_path == NULL || physical == NULL)
        return 0;
    char full_path[SIDECAR_MAX_PATH + 1U];
    if (append_physical(full_path, sizeof(full_path), payload_path,
                        physical) != 0)
        return 0;
    char reservation_key[SIDECAR_MAX_PATH + 1U];
    ascii_fold_copy(reservation_key, sizeof(reservation_key), full_path);
    return case_fold_set_contains(reserved_names, reservation_key);
}

static int case_probe_source_name_contains(
    const PortableCaseFoldSet *source_names, const char *physical)
{
    if (source_names == NULL || physical == NULL)
        return 0;
    char reservation_key[SIDECAR_MAX_PATH + 1U];
    skeleton_copy(reservation_key, sizeof(reservation_key), physical);
    return case_fold_set_contains(source_names, reservation_key);
}

static int case_probe_reserve_name(PortableCaseFoldSet *reserved_names,
                                   const char *payload_path,
                                   const char *parent_physical,
                                   const char *leaf, char *physical,
                                   size_t physical_size)
{
    if (reserved_names == NULL || payload_path == NULL ||
        parent_physical == NULL ||
        leaf == NULL || physical == NULL ||
        append_physical(physical, physical_size, parent_physical, leaf) != 0)
        return -1;
    char full_path[SIDECAR_MAX_PATH + 1U];
    if (append_physical(full_path, sizeof(full_path), payload_path,
                        physical) != 0)
        return -1;

    char reservation_key[SIDECAR_MAX_PATH + 1U];
    ascii_fold_copy(reservation_key, sizeof(reservation_key), full_path);
    char *existing = NULL;
    int result = case_fold_set_find_or_insert(reserved_names,
                                              reservation_key, physical,
                                              &existing);
    return result < 0 ? -1 : result == 1 ? 1 : 0;
}

static int case_probe_group_names_free(PortableCaseProbeState *state,
                                       const PortableCaseFoldSet *names)
{
    if (state == NULL || names == NULL || state->scratch_fd < 0)
        return -1;
    int failed = 0;
    for (size_t index = 0; index < names->capacity; index++) {
        const PortableCaseFoldSlot *slot = &names->slots[index];
        if (slot->folded_key != NULL &&
            unlinkat(state->scratch_fd, slot->folded_key, 0) != 0 &&
            errno != ENOENT)
            failed = 1;
    }
    return failed ? -1 : 0;
}

static int case_probe_group(PortableCaseProbeState *state,
                            const PortableCaseProbeGroup *group,
                            const char *root_id,
                            const char *parent_physical,
                            const char *payload_path,
                            const PortableCaseFoldSet *source_names,
                            PortableCaseFoldSet *reserved_names,
                            PortablePrescanReport *report)
{
    if (state == NULL || group == NULL || root_id == NULL ||
        parent_physical == NULL || payload_path == NULL || source_names == NULL ||
        reserved_names == NULL || report == NULL || group->count < 2U ||
        case_probe_prepare(state) != 0)
        return -1;
    case_probe_count();

    PortableCollisionAssignment *assignments = calloc(
        group->count, sizeof(*assignments));
    int failed = assignments == NULL;
    if (!failed) {
        for (size_t index = 0; index < group->count; index++) {
            assignments[index].encoded = group->encoded_names[index];
            assignments[index].logical = group->logical_paths[index];
        }
        qsort(assignments, group->count, sizeof(*assignments),
              portable_collision_assignment_compare);
    }

    PortableCaseFoldSet initial_names = {0};
    int collision = group->ascii_collision;
    for (size_t index = 0; index < group->count && !failed; index++) {
        char leaf[SIDECAR_MAX_PATH + 1U];
        char physical[SIDECAR_MAX_PATH + 1U];
        size_t actual_name = 0;
        size_t actual_path = 0;
        int path_status = collision_paths_build(
            parent_physical, payload_path, assignments[index].encoded, "",
            leaf, sizeof(leaf), physical, sizeof(physical), &actual_name,
            &actual_path);
        if (path_status != 0) {
            if (path_status == 1)
                (void)prescan_record_violation(
                    report, root_id, assignments[index].logical,
                    PORTABLE_PRESCAN_NAME_TOO_LONG, NAME_MAX, actual_name);
            else if (path_status == 2)
                (void)prescan_record_violation(
                    report, root_id, assignments[index].logical,
                    PORTABLE_PRESCAN_PATH_TOO_LONG, PATH_MAX, actual_path);
            failed = 1;
            break;
        }
        if (case_probe_reserved_name_contains(reserved_names, payload_path,
                                              physical)) {
            collision = 1;
            continue;
        }

        case_fs_probe_count();
        int fd = openat(state->scratch_fd, leaf,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
        if (fd >= 0) {
            if (close(fd) != 0) {
                failed = 1;
                break;
            }
            char *existing = NULL;
            if (case_fold_set_find_or_insert(&initial_names, leaf, leaf,
                                             &existing) < 0) {
                failed = 1;
                break;
            }
        } else if (errno == EEXIST) {
            collision = 1;
        } else {
            failed = 1;
            break;
        }
    }

    if (!failed && case_probe_readback_matches(&initial_names,
                                                state->scratch_fd) != 0)
        failed = 1;
    if (!failed && initial_names.count != group->count)
        collision = 1;

    if (!failed && !collision) {
        for (size_t index = 0; index < group->count && !failed; index++) {
            char physical[SIDECAR_MAX_PATH + 1U];
            if (case_probe_reserve_name(reserved_names, payload_path,
                                        parent_physical,
                                        assignments[index].encoded, physical,
                                        sizeof(physical)) != 0)
                failed = 1;
        }
    }

    if (case_probe_group_names_free(state, &initial_names) != 0)
        failed = 1;
    case_fold_set_free(&initial_names);

    PortableCaseFoldSet names = {0};
    PortableCaseFoldSet reserved_leaves = {0};
    if (!failed && collision) {
        for (size_t index = 0; index < group->count && !failed; index++) {
            uint64_t suffix_number = index == 0 ? 0 : 1;
            for (;;) {
                if (collision_suffix_format(
                        suffix_number, assignments[index].suffix,
                        sizeof(assignments[index].suffix)) != 0) {
                    failed = 1;
                    break;
                }
                char leaf[SIDECAR_MAX_PATH + 1U];
                char physical[SIDECAR_MAX_PATH + 1U];
                size_t actual_name = 0;
                size_t actual_path = 0;
                int path_status = collision_paths_build(
                    parent_physical, payload_path, assignments[index].encoded,
                    assignments[index].suffix, leaf, sizeof(leaf), physical,
                    sizeof(physical), &actual_name, &actual_path);
                if (path_status != 0) {
                    if (path_status == 1)
                        (void)prescan_record_violation(
                            report, root_id, assignments[index].logical,
                            PORTABLE_PRESCAN_NAME_TOO_LONG, NAME_MAX,
                            actual_name);
                    else if (path_status == 2)
                        (void)prescan_record_violation(
                            report, root_id, assignments[index].logical,
                            PORTABLE_PRESCAN_PATH_TOO_LONG, PATH_MAX,
                            actual_path);
                    failed = 1;
                    break;
                }
                char reservation_key[SIDECAR_MAX_PATH + 1U];
                skeleton_copy(reservation_key, sizeof(reservation_key), leaf);
                if (case_fold_set_contains(&reserved_leaves,
                                           reservation_key) ||
                    (assignments[index].suffix[0] != '\0' &&
                     case_probe_source_name_contains(source_names, physical)) ||
                     case_probe_reserved_name_contains(reserved_names,
                                                       payload_path,
                                                       physical)) {
                    if (suffix_number == UINT64_MAX) {
                        failed = 1;
                        break;
                    }
                    suffix_number++;
                    continue;
                }

                case_fs_probe_count();
                int fd = openat(state->scratch_fd, leaf,
                                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                    O_CLOEXEC,
                                0600);
                if (fd >= 0) {
                    if (close(fd) != 0) {
                        failed = 1;
                        break;
                    }
                    char *existing = NULL;
                    if (case_fold_set_find_or_insert(
                            &reserved_leaves, reservation_key, reservation_key,
                            &existing) < 0 ||
                        case_fold_set_find_or_insert(&names, leaf, leaf,
                                                     &existing) < 0 ||
                        case_probe_reserve_name(reserved_names, payload_path,
                                                parent_physical, leaf, physical,
                                                sizeof(physical)) != 0) {
                        failed = 1;
                        break;
                    }
                    break;
                }
                if (errno != EEXIST || suffix_number == UINT64_MAX) {
                    failed = 1;
                    break;
                }
                suffix_number++;
            }
        }

        if (!failed && case_probe_readback_matches(&names,
                                                    state->scratch_fd) != 0)
            failed = 1;
    }

    if (!failed && collision) {
        size_t representative = SIZE_MAX;
        for (size_t index = 0; index < group->count; index++)
            if (assignments[index].suffix[0] == '\0') {
                representative = index;
                break;
            }
        if (representative == SIZE_MAX)
            representative = 0;
        for (size_t index = 0; index < group->count && !failed; index++) {
            char leaf[SIDECAR_MAX_PATH + 1U];
            char physical[SIDECAR_MAX_PATH + 1U];
            size_t actual_name = 0;
            size_t actual_path = 0;
            int path_status = collision_paths_build(
                parent_physical, payload_path, assignments[index].encoded,
                assignments[index].suffix, leaf, sizeof(leaf), physical,
                sizeof(physical), &actual_name, &actual_path);
            if (path_status != 0 || portable_collision_plan_add(
                                        &report->collision_plan, root_id,
                                        assignments[index].logical, physical,
                                        assignments[index].suffix) != 0) {
                failed = 1;
                break;
            }
            if (index != representative && !group->ascii_collision &&
                prescan_record_case_collision(
                    report, root_id, assignments[index].logical,
                    assignments[representative].logical) != 0)
                failed = 1;
        }
    }

    if (case_probe_group_names_free(state, &names) != 0)
        failed = 1;
    case_fold_set_free(&names);
    case_fold_set_free(&reserved_leaves);
    free(assignments);
    return failed ? -1 : 0;
}

static int case_probe_reserve_singleton(PortableCaseProbeState *state,
                                        const PortableCaseProbeGroup *group,
                                        const char *parent_physical,
                                        const char *payload_path,
                                        const PortableCaseFoldSet *source_names,
                                        PortableCaseFoldSet *reserved_names)
{
    if (state == NULL || group == NULL || parent_physical == NULL ||
        payload_path == NULL || source_names == NULL || reserved_names == NULL ||
        group->count != 1U)
        return -1;
    char physical[SIDECAR_MAX_PATH + 1U];
    if (append_physical(physical, sizeof(physical), parent_physical,
                        group->encoded_names[0]) != 0)
        return -1;
    if (!case_probe_source_name_contains(source_names, physical))
        return -1;
    return case_probe_reserve_name(reserved_names, payload_path,
                                   parent_physical, group->encoded_names[0],
                                   physical, sizeof(physical)) != 0
               ? -1
               : 0;
}

static int prescan_directory(int source_fd, const char *logical,
                             const char *physical, const char *root_id,
                             const char *payload_path,
                             PortablePrescanReport *report,
                             int case_sensitive,
                             PortableCaseProbeState *probe_state)
{
    if (source_fd < 0 || logical == NULL || physical == NULL ||
        root_id == NULL || payload_path == NULL || report == NULL ||
        probe_state == NULL)
        return -1;

    int scan_fd = dup_cloexec(source_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }

    PortableCaseFoldSet siblings = {0};
    PortableCaseFoldSet skeletons = {0};
    PortableCaseProbeGroups groups = {0};
    if (!case_sensitive)
        siblings.hash_salt = sidecar_process_salt();

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0) {
            failed = 1;
            break;
        }

        char scratch[3U * NAME_MAX + 4U];
        if (encoding_percent_encode(ENCODING_MODE_COMPONENT, entry->d_name,
                                    scratch, sizeof(scratch)) != 0) {
            failed = 1;
            break;
        }

        size_t encoded_length = strlen(scratch);
        if (encoded_length > NAME_MAX) {
            if (prescan_record_violation(
                    report, root_id, child_logical,
                    PORTABLE_PRESCAN_NAME_TOO_LONG, NAME_MAX,
                    encoded_length) != 0)
                failed = 1;
            if (failed)
                break;
            continue;
        }

        char child_physical[SIDECAR_MAX_PATH + 1U];
        if (append_physical(child_physical, sizeof(child_physical), physical,
                            scratch) != 0) {
            failed = 1;
            break;
        }

        size_t payload_root_length = strlen(payload_path);
        size_t physical_length = strlen(child_physical);
        if (!portable_payload_path_fits(payload_root_length, physical_length,
                                        PATH_MAX)) {
            if (payload_root_length > SIZE_MAX - 1U ||
                physical_length > SIZE_MAX - payload_root_length - 1U)
                failed = 1;
            else if (prescan_record_violation(
                         report, root_id, child_logical,
                         PORTABLE_PRESCAN_PATH_TOO_LONG, PATH_MAX,
                         payload_root_length + 1U + physical_length) != 0)
                failed = 1;
            if (failed)
                break;
            continue;
        }

        size_t skeleton_group_index = SIZE_MAX;
        if (!case_sensitive) {
            char skeleton[NAME_MAX + 1U];
            skeleton_copy(skeleton, sizeof(skeleton), scratch);
            size_t new_group_index = groups.count;
            if (case_probe_groups_add(&groups, scratch, child_logical,
                                      &new_group_index) != 0) {
                failed = 1;
                break;
            }
            size_t existing_group_index = SIZE_MAX;
            char *existing_skeleton_path = NULL;
            int skeleton_found = case_fold_set_find_or_insert_value(
                &skeletons, skeleton, child_logical, new_group_index,
                &existing_group_index, &existing_skeleton_path);
            if (skeleton_found < 0) {
                failed = 1;
                break;
            }
            if (skeleton_found == 0) {
                skeleton_group_index = new_group_index;
            } else {
                case_probe_group_free(&groups.items[new_group_index]);
                groups.count--;
                skeleton_group_index = existing_group_index;
                if (skeleton_group_index >= groups.count ||
                    case_probe_group_append(
                        &groups.items[skeleton_group_index], scratch,
                        child_logical) != 0) {
                    failed = 1;
                    break;
                }
            }

            char folded[NAME_MAX + 1U];
            ascii_fold_copy(folded, sizeof(folded), scratch);
            char *existing_logical = NULL;
            int found = case_fold_set_find_or_insert(
                &siblings, folded, child_logical, &existing_logical);
            if (found < 0) {
                failed = 1;
                break;
            }
            if (found == 1) {
                groups.items[skeleton_group_index].ascii_collision = 1;
                if (prescan_record_case_collision(
                        report, root_id, child_logical,
                        existing_logical) != 0) {
                    failed = 1;
                    break;
                }
            }
        }

        struct stat child_stat;
        if (read_source_stat(source_fd, entry->d_name, NULL, &child_stat) != 0) {
            failed = 1;
            break;
        }
        if (S_ISDIR(child_stat.st_mode)) {
            int child_fd = open_source_node(source_fd, entry->d_name, NULL,
                                            &child_stat);
            if (child_fd < 0) {
                failed = 1;
                break;
            }
            int child_result = prescan_directory(
                child_fd, child_logical, child_physical, root_id,
                payload_path, report, case_sensitive, probe_state);
            if (close(child_fd) != 0)
                child_result = -1;
            if (child_result != 0) {
                failed = 1;
                break;
            }
        }
        else if (S_ISREG(child_stat.st_mode)) {
            int already_counted = 0;
            if (child_stat.st_nlink > 1) {
                PrescanInodeSet *seen = report->inode_seen;
                if (seen == NULL) {
                    seen = calloc(1, sizeof(*seen));
                    report->inode_seen = seen;
                    if (seen == NULL ||
                        prescan_inode_set_rehash(
                            seen, VISITED_INITIAL_CAPACITY) != 0) {
                        failed = 1;
                        break;
                    }
                    seen->hash_salt = sidecar_process_salt();
                }
                int seen_status = prescan_inode_set_find_or_insert(
                    seen, child_stat.st_dev, child_stat.st_ino);
                if (seen_status < 0) {
                    failed = 1;
                    break;
                }
                already_counted = seen_status == 1;
            }
            if (!already_counted) {
                if (child_stat.st_size < 0 ||
                    report->total_size >
                        UINT64_MAX - (uint64_t)child_stat.st_size) {
                    failed = 1;
                    break;
                }
                report->total_size += (uint64_t)child_stat.st_size;
            }
        }
        else if (S_ISFIFO(child_stat.st_mode)) {
            if (prescan_record_violation(
                    report, root_id, child_logical,
                    PORTABLE_PRESCAN_UNSUPPORTED_KIND, 0, 0) != 0) {
                failed = 1;
                break;
            }
        }
        else if (S_ISSOCK(child_stat.st_mode) ||
                 S_ISCHR(child_stat.st_mode) || S_ISBLK(child_stat.st_mode)) {
            if (report->skipped_kind_count != SIZE_MAX)
                report->skipped_kind_count++;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;

    PortableCaseFoldSet source_names = {0};
    PortableCaseFoldSet reserved_names = {0};
    if (!failed) {
        /* Reserve every unsuffixed source name before allocating suffixes so
         * a generated %7EN cannot depend on group/readdir order (D21 F-1/F-2d). */
        for (size_t group_index = 0;
             group_index < groups.count && !failed; group_index++) {
            PortableCaseProbeGroup *group = &groups.items[group_index];
            for (size_t index = 0; index < group->count; index++) {
                char source_physical[SIDECAR_MAX_PATH + 1U];
                if (append_physical(source_physical, sizeof(source_physical),
                                    physical,
                                    group->encoded_names[index]) != 0) {
                    failed = 1;
                    break;
                }
                char source_key[SIDECAR_MAX_PATH + 1U];
                skeleton_copy(source_key, sizeof(source_key), source_physical);
                char *existing = NULL;
                if (case_fold_set_find_or_insert(
                        &source_names, source_key, source_physical,
                        &existing) < 0) {
                    failed = 1;
                    break;
                }
            }
        }
    }
    if (!failed && !case_sensitive) {
        for (size_t index = 0; index < groups.count; index++) {
            PortableCaseProbeGroup *group = &groups.items[index];
            int group_result = group->count == 1U
                ? case_probe_reserve_singleton(probe_state, group, physical,
                                               payload_path,
                                               &source_names, &reserved_names)
                : case_probe_group(probe_state, group, root_id, physical,
                                   payload_path, &source_names, &reserved_names,
                                   report);
            if (group_result != 0) {
                failed = 1;
                break;
            }
        }
    }
    case_fold_set_free(&siblings);
    case_fold_set_free(&skeletons);
    case_fold_set_free(&source_names);
    case_fold_set_free(&reserved_names);
    case_probe_groups_free(&groups);
    return failed ? -1 : 0;
}

int relative_paths_overlap(const char *left, const char *right)
{
    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    if (left_length <= right_length &&
        strncmp(left, right, left_length) == 0 &&
        (left_length == right_length || right[left_length] == '/'))
        return 1;
    if (right_length < left_length &&
        strncmp(left, right, right_length) == 0 &&
        left[right_length] == '/')
        return 1;
    return 0;
}

static int root_payload_paths_ascii_overlap(const char *left,
                                            const char *right)
{
    if (left == NULL || right == NULL)
        return 0;
    char left_folded[PATH_MAX];
    char right_folded[PATH_MAX];
    ascii_fold_copy(left_folded, sizeof(left_folded), left);
    ascii_fold_copy(right_folded, sizeof(right_folded), right);
    return relative_paths_overlap(left_folded, right_folded);
}

/* Root payload paths do not participate in the leaf suffix plan.  Their
 * namespace is checked here, before manifest/data/sidecar mutation: ASCII
 * folding is deterministic, while plausible non-ASCII pairs are verified by
 * the same scratch mkdir/readback authority used for destination probing
 * (docs/DECISIONS.md D21, F-5). */
static int prescan_root_payload_namespace(
    const PortableCaptureRequest *request, PortablePrescanReport *report,
    PortableCaseProbeState *probe_state)
{
    if (request == NULL || report == NULL || probe_state == NULL)
        return -1;

    int failed = 0;
    for (size_t right_index = 0; right_index < request->root_count;
         right_index++) {
        const PortableRootSpec *right = &request->roots[right_index];
        if (!root_spec_valid(right)) {
            failed = 1;
            continue;
        }
        for (size_t left_index = 0; left_index < right_index;
             left_index++) {
            const PortableRootSpec *left = &request->roots[left_index];
            if (!root_spec_valid(left)) {
                failed = 1;
                continue;
            }
            if (!relative_paths_overlap(left->payload_path,
                                        right->payload_path) &&
                !root_payload_paths_ascii_overlap(left->payload_path,
                                                   right->payload_path))
                continue;

            PortablePrescanViolation violation = {
                .kind = PORTABLE_PRESCAN_CASE_COLLISION
            };
            if (copy_text(violation.root_id, sizeof(violation.root_id),
                          right->id) != 0 ||
                copy_text(violation.logical_path,
                          sizeof(violation.logical_path),
                          right->payload_path) != 0 ||
                copy_text(violation.collides_with_logical_path,
                          sizeof(violation.collides_with_logical_path),
                          left->payload_path) != 0 ||
                prescan_report_add(report, &violation) != 0)
                failed = 1;
        }
    }

    if (failed)
        return -1;

    for (size_t right_index = 0; right_index < request->root_count;
         right_index++) {
        const PortableRootSpec *right = &request->roots[right_index];
        if (!root_payload_path_has_non_ascii(right->payload_path))
            continue;
        char right_skeleton[PATH_MAX];
        skeleton_copy(right_skeleton, sizeof(right_skeleton),
                      right->payload_path);
        for (size_t left_index = 0; left_index < right_index;
             left_index++) {
            const PortableRootSpec *left = &request->roots[left_index];
            if (!root_payload_path_has_non_ascii(left->payload_path))
                continue;
            if (relative_paths_overlap(left->payload_path,
                                       right->payload_path) ||
                root_payload_paths_ascii_overlap(left->payload_path,
                                                 right->payload_path))
                continue;
            char left_skeleton[PATH_MAX];
            skeleton_copy(left_skeleton, sizeof(left_skeleton),
                          left->payload_path);
            if (strcmp(left_skeleton, right_skeleton) != 0)
                continue;
            int probe = root_probe_pair(probe_state, left, right,
                                        left_index + right_index);
            if (probe < 0) {
                failed = 1;
                break;
            }
            if (probe == 1) {
                PortablePrescanViolation violation = {
                    .kind = PORTABLE_PRESCAN_CASE_COLLISION
                };
                if (copy_text(violation.root_id,
                              sizeof(violation.root_id), right->id) != 0 ||
                    copy_text(violation.logical_path,
                              sizeof(violation.logical_path),
                              right->payload_path) != 0 ||
                    copy_text(violation.collides_with_logical_path,
                              sizeof(violation.collides_with_logical_path),
                              left->payload_path) != 0 ||
                    prescan_report_add(report, &violation) != 0)
                    failed = 1;
                break;
            }
        }
        if (failed)
            break;
    }
    return failed ? -1 : 0;
}

static int prescan_root(const PortableRootSpec *root,
                        PortablePrescanReport *report, int case_sensitive,
                        PortableCaseProbeState *probe_state)
{
    if (!root_spec_valid(root) || report == NULL || probe_state == NULL)
        return -1;

    struct stat st;
    if (read_source_stat(-1, NULL, root->capture_path, &st) != 0)
        return -1;
    if (S_ISFIFO(st.st_mode))
        return prescan_record_violation(report, root->id, "",
                                        PORTABLE_PRESCAN_UNSUPPORTED_KIND,
                                        0, 0);
    if (S_ISSOCK(st.st_mode) || S_ISCHR(st.st_mode) ||
        S_ISBLK(st.st_mode)) {
        if (report->skipped_kind_count != SIZE_MAX)
            report->skipped_kind_count++;
        return 0;
    }
    if (!S_ISDIR(st.st_mode))
        return 0;

    int root_fd = open_source_node(-1, NULL, root->capture_path, &st);
    if (root_fd < 0)
        return -1;
    int result = prescan_directory(root_fd, "", "", root->id,
                                   root->payload_path, report, case_sensitive,
                                   probe_state);
    if (close(root_fd) != 0)
        result = -1;
    return result;
}

static int prescan_request_internal(int container_fd,
                                    const PortableCaptureRequest *request,
                                    PortablePrescanReport *report,
                                    int reject_violations)
{
    if (container_fd < 0 || request == NULL || report == NULL)
        return -1;
    PortableCaseProbeState probe_state = {
        .container_fd = container_fd,
        .scratch_fd = -1
    };
    int failed = 0;
    for (size_t index = 0; index < request->root_count; index++)
        if (prescan_root(&request->roots[index], report,
                         request->case_sensitive, &probe_state) != 0)
            failed = 1;
    if (prescan_root_payload_namespace(request, report, &probe_state) != 0)
        failed = 1;
    if (case_probe_cleanup(&probe_state) != 0)
        failed = 1;
    portable_collision_plan_sort(&report->collision_plan);
    if (!failed && portable_collision_plan_rewrite_parents(report, request) != 0)
        failed = 1;
    if (!failed)
        prescan_report_refresh_unresolved(report);
    return failed || (reject_violations && report->unresolved_count != 0)
               ? -1
               : 0;
}

static int prescan_request(int container_fd,
                           const PortableCaptureRequest *request,
                           PortablePrescanReport *report)
{
    return prescan_request_internal(container_fd, request, report, 1);
}

int portable_collision_plan_build(int container_fd,
                                  const PortableCaptureRequest *request,
                                  PortablePrescanReport *report)
{
    if (container_fd < 0 || request == NULL || report == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
        return -1;
    return prescan_request_internal(container_fd, request, report, 0);
}

static int build_manifest(const PortableCaptureRequest *request,
                          Manifest *manifest)
{
    memset(manifest, 0, sizeof(*manifest));
    manifest->version = MANIFEST_CURRENT_VERSION;
    manifest->representation = CLONE_PORTABLE_SIDECAR;
    manifest->scope = request->scope;
    manifest->sidecar_version = SIDECAR_VERSION;
    manifest->has_source_identity = request->has_source_identity != 0;
    if (manifest->has_source_identity) {
        if (request->machine_id == NULL ||
            copy_text(manifest->machine_id, sizeof(manifest->machine_id),
                      request->machine_id) != 0)
            return -1;
        manifest->source_uid = request->source_uid;
    }

    if (request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
        return -1;
    manifest->root_count = (int)request->root_count;
    if (request->root_count == 0)
        return 0;
    manifest->roots = calloc(request->root_count, sizeof(*manifest->roots));
    if (manifest->roots == NULL)
        return -1;

    for (size_t index = 0; index < request->root_count; index++) {
        const PortableRootSpec *source = &request->roots[index];
        ManifestRoot *destination = &manifest->roots[index];
        if (!root_spec_valid(source))
            goto fail;
        for (size_t previous = 0; previous < index; previous++) {
            if (strcmp(request->roots[previous].id, source->id) == 0 ||
                relative_paths_overlap(request->roots[previous].payload_path,
                                       source->payload_path))
                goto fail;
        }
        if (copy_text(destination->id, sizeof(destination->id), source->id) != 0 ||
            copy_text(destination->payload_path, sizeof(destination->payload_path),
                      source->payload_path) != 0 ||
            copy_text(destination->source_path, sizeof(destination->source_path),
                      source->source_path) != 0)
            goto fail;
        destination->policy = source->policy;
        destination->has_restore_path = source->has_restore_path;
        if (source->has_restore_path &&
            copy_text(destination->restore_path, sizeof(destination->restore_path),
                      source->restore_path) != 0)
            goto fail;
    }
    return 0;

fail:
    manifest_free(manifest);
    return -1;
}

int portable_capture_prepare(int scratch_fd,
                             const PortableCaptureRequest *request,
                             PortablePreparedCapture *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    if (scratch_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
        return -1;

    portable_prescan_report_init(&out->report);
    if (prescan_request(scratch_fd, request, &out->report) != 0)
        return -1;
    if (build_manifest(request, &out->manifest) != 0)
        return -1;
    out->ready = 1;
    return 0;
}

void portable_prepared_capture_free(PortablePreparedCapture *prepared)
{
    if (prepared == NULL)
        return;
    manifest_free(&prepared->manifest);
    portable_prescan_report_free(&prepared->report);
    memset(prepared, 0, sizeof(*prepared));
}

static int data_namespace_is_empty(int data_fd)
{
    if (data_fd < 0)
        return -1;
    struct stat st;
    if (fstat(data_fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    int empty = 1;
    int scan_fd = dup_cloexec(data_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                empty = 0;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = 0;
            break;
        }
    }
    if (closedir(directory) != 0)
        empty = 0;
    return empty ? 0 : -1;
}

static int fresh_namespace_is_empty(int container_fd)
{
    struct stat st;
    if (fstatat(container_fd, "manifest.txt", &st, AT_SYMLINK_NOFOLLOW) == 0)
        return -1;
    if (errno != ENOENT)
        return -1;
    if (fstatat(container_fd, SIDECAR_SLOT_NAME, &st,
                AT_SYMLINK_NOFOLLOW) == 0)
        return -1;
    if (errno != ENOENT)
        return -1;
    if (fstatat(container_fd, "data", &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return -1;
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0)
        return -1;
    int result = data_namespace_is_empty(data_fd);
    if (close(data_fd) != 0)
        result = -1;
    return result;
}

int portable_capture_context_init(PortableCaptureContext *context,
                                  int data_fd, SidecarLog *sidecar,
                                  int nsec_exact, int case_sensitive)
{
    if (context == NULL || data_fd < 0 || sidecar == NULL ||
        sidecar->implementation == NULL)
        return -1;
    struct stat st;
    if (fstat(data_fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    memset(context, 0, sizeof(*context));
    PortableVisited *visited = calloc(1, sizeof(*visited));
    if (visited == NULL)
        return -1;
    PortableOwnedPaths *owned_paths = calloc(1, sizeof(*owned_paths));
    if (owned_paths == NULL) {
        free(visited);
        return -1;
    }
    PortableClaimedPaths *claimed_paths = calloc(1, sizeof(*claimed_paths));
    if (claimed_paths == NULL) {
        free(owned_paths);
        free(visited);
        return -1;
    }
    PortableInodeMap *inode_map = calloc(1, sizeof(*inode_map));
    if (inode_map == NULL) {
        free(claimed_paths);
        free(owned_paths);
        free(visited);
        return -1;
    }
    context->data_fd = data_fd;
    context->sidecar = sidecar;
    context->nsec_exact = nsec_exact != 0;
    context->case_sensitive = case_sensitive != 0;
    visited->hash_salt = sidecar_process_salt();
    inode_map->hash_salt = sidecar_process_salt();
    context->visited = visited;
    context->inode_map = inode_map;
    context->owned_paths = owned_paths;
    context->claimed_paths = claimed_paths;
    return 0;
}

void portable_capture_context_close(PortableCaptureContext *context)
{
    if (context == NULL)
        return;
    visited_free(context->visited);
    inode_map_free(context->inode_map);
    portable_owned_paths_free(context->owned_paths);
    free(context->owned_paths);
    portable_claimed_paths_free(context->claimed_paths);
    free(context->claimed_paths);
    memset(context, 0, sizeof(*context));
}

int portable_capture_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    if (context == NULL || context->visited == NULL ||
        context->inode_map == NULL ||
        context->data_fd < 0 || context->sidecar == NULL ||
        !root_spec_valid(root))
        return -1;
    /* visited is root-local; inode_map spans every root in this context. */
    PortableVisited *visited = context->visited;
    if (visited_reset(visited) != 0)
        return -1;
    if (prepare_collision_relocations(context, root) != 0)
        return -1;
    int result = capture_node(context, root, "", "", -1, NULL,
                              root->capture_path, -1, NULL);
    if (result != 0)
        return result;
    return capture_plan_entries_seen(context, root);
}

int portable_capture_fresh_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL) ||
        prepared == NULL || !prepared->ready ||
        fresh_namespace_is_empty(container_fd) != 0)
        return -1;

    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = -1;
    int sidecar_ready = 0;
    int context_ready = 0;
    int result = -1;

    if (manifest_write_v1_at(container_fd, &prepared->manifest) != 0)
        goto done;
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_MANIFEST);

    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST) {
        goto done;
    }
    data_fd = openat(container_fd, "data",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0) {
        goto done;
    }

    if (sidecar_log_create_at(container_fd, &sidecar) != SIDECAR_OPEN_FRESH) {
        goto done;
    }
    sidecar_ready = 1;

    int failed = portable_capture_context_init(&context, data_fd, &sidecar,
                                               request->nsec_exact,
                                               request->case_sensitive) != 0;
    if (!failed) {
        context_ready = 1;
        context.progress_report = progress_report;
        context.collision_plan = &prepared->report.collision_plan;
        if (portable_owned_paths_load(context.owned_paths, &sidecar) != 0 ||
            portable_claimed_paths_load(context.claimed_paths, &sidecar) != 0 ||
            sticky_seed_inode_map(context.inode_map, request, &sidecar) != 0)
            failed = 1;
    }
    for (size_t index = 0; !failed && index < request->root_count; index++)
    {
        if (verbose)
            printf("  Capturing: %s -> data/%s\n",
                   request->roots[index].capture_path,
                   request->roots[index].payload_path);
        if (portable_capture_root(&context, &request->roots[index]) != 0 ||
            reconcile_root(&context, &request->roots[index]) != 0)
            failed = 1;
    }
    if (!failed && sidecar_log_claim_count(&sidecar) != 0)
        failed = 1;
    if (!failed && live_count != NULL)
        *live_count = sidecar_log_live_count(&sidecar);
    result = failed ? -1 : 0;

done:
    if (context_ready)
        portable_capture_context_close(&context);
    if (sidecar_ready && sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (data_fd >= 0 && close(data_fd) != 0)
        result = -1;
    return result;
}

int portable_capture_fresh_at(int container_fd,
                              const PortableCaptureRequest *request,
                              PortablePrescanReport *report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL) ||
        fresh_namespace_is_empty(container_fd) != 0)
        return -1;

    PortablePreparedCapture prepared;
    if (portable_capture_prepare(container_fd, request, &prepared) != 0) {
        if (report != NULL) {
            *report = prepared.report;
            memset(&prepared.report, 0, sizeof(prepared.report));
        }
        portable_prepared_capture_free(&prepared);
        return -1;
    }

    int result = portable_capture_fresh_prepared_at(container_fd, request,
                                                    &prepared, NULL, NULL);
    if (report != NULL) {
        *report = prepared.report;
        memset(&prepared.report, 0, sizeof(prepared.report));
    }
    portable_prepared_capture_free(&prepared);
    return result;
}

/* Returns 0 with an open data directory, 1 when data is absent, -1 otherwise. */
static int open_existing_data(int container_fd, int *out_fd)
{
    if (container_fd < 0 || out_fd == NULL)
        return -1;
    *out_fd = -1;
    struct stat st;
    if (fstatat(container_fd, "data", &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 1 : -1;
    if (!S_ISDIR(st.st_mode))
        return -1;
    int fd = openat(container_fd, "data",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    *out_fd = fd;
    return 0;
}

static int create_resume_data(int container_fd, int *out_fd)
{
    if (container_fd < 0 || out_fd == NULL)
        return -1;
    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST)
        return -1;
    int state = open_existing_data(container_fd, out_fd);
    return state == 0 ? 0 : -1;
}

int portable_capture_resume_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL) ||
        prepared == NULL || !prepared->ready)
        return -1;

    Manifest existing = {0};
    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = -1;
    int context_ready = 0;
    int result = -1;

    ManifestStatus manifest_status = manifest_read_v1_at(container_fd,
                                                         &existing);
    if (manifest_status != MANIFEST_STATUS_VALID) {
        goto done;
    }
    ManifestIdentityComparison identity =
        manifest_resume_identity_compare(&existing, &prepared->manifest);
    if (identity != MANIFEST_IDENTITY_EQUAL) {
        goto done;
    }

    int data_state = open_existing_data(container_fd, &data_fd);
    if (data_state < 0)
        goto done;
    int data_missing = data_state == 1;

    SidecarOpenStatus sidecar_status = sidecar_log_adopt_at(container_fd,
                                                            &sidecar);
    int failed = 0;
    if (sidecar_status == SIDECAR_OPEN_MISSING) {
        if (data_missing) {
            if (create_resume_data(container_fd, &data_fd) != 0)
                failed = 1;
        }
        if (!failed && data_namespace_is_empty(data_fd) != 0)
            failed = 1;
        if (!failed &&
            sidecar_log_create_at(container_fd, &sidecar) !=
                SIDECAR_OPEN_FRESH)
            failed = 1;
    } else if (sidecar_status != SIDECAR_OPEN_RESUMABLE || data_missing) {
        failed = 1;
    }

    if (!failed && portable_capture_context_init(&context, data_fd, &sidecar,
                                                request->nsec_exact,
                                                request->case_sensitive) != 0)
        failed = 1;
    if (!failed) {
        context_ready = 1;
        context.progress_report = progress_report;
        context.resume_mode = 1;
        context.collision_plan = &prepared->report.collision_plan;
        if (portable_owned_paths_load(context.owned_paths, &sidecar) != 0 ||
            portable_claimed_paths_load(context.claimed_paths, &sidecar) != 0 ||
            sticky_seed_inode_map(context.inode_map, request, &sidecar) != 0)
            failed = 1;
        for (size_t index = 0; !failed && index < request->root_count;
             index++) {
            if (verbose)
                printf("  Capturing: %s -> data/%s\n",
                       request->roots[index].capture_path,
                       request->roots[index].payload_path);
            if (portable_capture_root(&context, &request->roots[index]) != 0 ||
                reconcile_root(&context, &request->roots[index]) != 0) {
                failed = 1;
                break;
            }
        }
    }
    if (!failed && sidecar_log_claim_count(&sidecar) != 0)
        failed = 1;
    if (!failed && live_count != NULL)
        *live_count = sidecar_log_live_count(&sidecar);
    result = failed ? -1 : 0;

done:
    if (context_ready)
        portable_capture_context_close(&context);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (data_fd >= 0 && close(data_fd) != 0)
        result = -1;
    manifest_free(&existing);
    return result;
}

int portable_capture_resume_at(int container_fd,
                               const PortableCaptureRequest *request,
                               PortablePrescanReport *report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
        return -1;

    PortablePreparedCapture prepared;
    if (portable_capture_prepare(container_fd, request, &prepared) != 0) {
        if (report != NULL) {
            *report = prepared.report;
            memset(&prepared.report, 0, sizeof(prepared.report));
        }
        portable_prepared_capture_free(&prepared);
        return -1;
    }

    int result = portable_capture_resume_prepared_at(container_fd, request,
                                                     &prepared, NULL, NULL);
    if (report != NULL) {
        *report = prepared.report;
        memset(&prepared.report, 0, sizeof(prepared.report));
    }
    portable_prepared_capture_free(&prepared);
    return result;
}
