#define _GNU_SOURCE

#include "portable_prescan_internal.h"
#include "portable_hashset_internal.h"
#include "portable.h"
#include "encoding.h"
#include "sidecar.h"
#include "utils.h"

#include <assert.h>
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
#include <unistd.h>

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

const PortableRootSpec *portable_collision_plan_root(
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
    if (mkdirat(state->container_fd, PORTABLE_CASE_PROBE_DIR, 0700) != 0) {
        /* A prior capture may have been killed after creating this scratch
         * directory but before case_probe_cleanup() removed it.  Clear a
         * stale leftover and retry once instead of treating it as fatal
         * forever; remove_directory_tree() safely fails without touching
         * anything if this isn't actually our own directory (e.g. an
         * unrelated file occupies the name). */
        if (errno != EEXIST ||
            remove_directory_tree(state->container_fd,
                                  PORTABLE_CASE_PROBE_DIR) != 0)
            return -1;
        case_fs_probe_count();
        if (mkdirat(state->container_fd, PORTABLE_CASE_PROBE_DIR, 0700) != 0)
            return -1;
    }
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

#ifdef PORTABLE_PRESCAN_TEST_HOOKS
static size_t root_probe_test_close_successes;
static size_t root_probe_test_close_fail_after = SIZE_MAX;
static size_t root_probe_test_post_loop_close_count;

void portable_prescan_test_fail_root_probe_close_after(size_t successful_closes)
{
    root_probe_test_close_fail_after = successful_closes;
    root_probe_test_close_successes = 0;
    root_probe_test_post_loop_close_count = 0;
}

size_t portable_prescan_test_root_probe_post_loop_close_count(void)
{
    return root_probe_test_post_loop_close_count;
}

static int root_probe_test_close_should_fail(void)
{
    if (root_probe_test_close_successes >= root_probe_test_close_fail_after)
        return 1;
    root_probe_test_close_successes++;
    return 0;
}
#endif

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
        int closed = close(current);
#ifdef PORTABLE_PRESCAN_TEST_HOOKS
        if (root_probe_test_close_should_fail())
            closed = -1;
#endif
        if (closed != 0) {
            close(next);
            result = -1;
            current = -1;
            break;
        }
        current = next;
        if (slash == NULL)
            break;
        cursor = slash + 1;
    }
    if (current >= 0) {
#ifdef PORTABLE_PRESCAN_TEST_HOOKS
        root_probe_test_post_loop_close_count++;
#endif
        if (close(current) != 0 && result == 0)
            result = -1;
    }
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
    int *excluded = calloc(group->count, sizeof(*excluded));
    int failed = assignments == NULL || excluded == NULL;
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
            excluded[index] = 1;
            continue;
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
            if (excluded[index])
                continue;
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
                    excluded[index] = 1;
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
            if (!excluded[index] && assignments[index].suffix[0] == '\0') {
                representative = index;
                break;
            }
        if (representative == SIZE_MAX)
            representative = 0;
        for (size_t index = 0; index < group->count && !failed; index++) {
            if (excluded[index])
                continue;
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
    free(excluded);
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
    assert(case_probe_source_name_contains(source_names, physical) &&
           "case_probe_reserve_singleton: singleton's own physical name "
           "missing from source_names (should already be reserved by "
           "prescan_directory's unsuffixed-name pass)");
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
    if (container_fd < 0 || request == NULL || report == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
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

int prescan_request(int container_fd,
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
