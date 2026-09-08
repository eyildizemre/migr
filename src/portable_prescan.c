#define _GNU_SOURCE

#include "portable_prescan_internal.h"
#include "portable_hashset_internal.h"
#include "portable.h"
#include "encoding.h"
#include "portable_name.h"
#include "selection.h"
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

static void prescan_record_operational_failure(PortablePrescanReport *report,
                                               const char *logical_path,
                                               int err)
{
    if (report == NULL || report->operational_failure)
        return;
    report->operational_failure = 1;
    report->operational_failure_errno = err != 0 ? err : EIO;
    (void)copy_text(report->operational_failure_path,
                    sizeof(report->operational_failure_path),
                    logical_path != NULL ? logical_path : "");
}

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

static int portable_collision_plan_add(PortableCollisionPlan *plan,
                                       const char *root_id,
                                       const char *logical_path,
                                       const char *physical_leaf,
                                       const char *collision_suffix)
{
    if (plan == NULL || root_id == NULL || logical_path == NULL ||
        physical_leaf == NULL || collision_suffix == NULL ||
        plan->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;

    if (plan->count == plan->capacity) {
        PortableCollisionPlanEntry *entries = array_reserve(
            plan->entries, &plan->capacity, plan->count, 1U,
            sizeof(*entries), 8U, SIDECAR_MAX_LIVE_ENTRIES);
        if (entries == NULL)
            return -1;
        plan->entries = entries;
    }

    PortableCollisionPlanEntry *entry = &plan->entries[plan->count];
    memset(entry, 0, sizeof(*entry));
    if (copy_text(entry->root_id, sizeof(entry->root_id), root_id) != 0 ||
        copy_text(entry->logical_path, sizeof(entry->logical_path),
                  logical_path) != 0 ||
        copy_text(entry->physical_leaf, sizeof(entry->physical_leaf),
                  physical_leaf) != 0 ||
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
        PortablePrescanViolation *examples = array_reserve(
            report->examples, &report->example_capacity,
            report->example_count, 1U, sizeof(*examples), 8U,
            PORTABLE_PRESCAN_MAX_EXAMPLES);
        if (examples == NULL)
            return -1;
        report->examples = examples;
    }
    report->examples[report->example_count++] = *violation;
    return 0;
}

static void prescan_report_refresh_unresolved(PortablePrescanReport *report)
{
    if (report == NULL)
        return;
    if (report->collision_count > report->total_count ||
        report->shortening_count >
            report->total_count - report->collision_count) {
        report->unresolved_count = report->total_count;
        return;
    }
    report->unresolved_count = report->total_count - report->collision_count -
                               report->shortening_count;
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
        .kind = PORTABLE_PRESCAN_CASE_COLLISION,
        .resolved = 1
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

static int prescan_record_shortening(PortablePrescanReport *report,
                                     const char *root_id,
                                     const char *logical_path,
                                     const char *logical_component,
                                     const char *collision_suffix)
{
    if (report == NULL || logical_component == NULL || collision_suffix == NULL)
        return -1;

    char encoded[3U * NAME_MAX + 4U];
    if (encoding_percent_encode(ENCODING_MODE_COMPONENT, logical_component,
                                encoded, sizeof(encoded)) != 0)
        return -1;
    size_t encoded_length = strlen(encoded);
    size_t suffix_length = strlen(collision_suffix);
    if (encoded_length > SIZE_MAX - suffix_length)
        return -1;

    PortablePrescanViolation violation = {
        .kind = PORTABLE_PRESCAN_NAME_TOO_LONG,
        .resolved = 1,
        .limit = NAME_MAX,
        .actual = encoded_length + suffix_length
    };
    if (copy_text(violation.root_id, sizeof(violation.root_id), root_id) != 0 ||
        copy_text(violation.logical_path, sizeof(violation.logical_path),
                  logical_path) != 0 ||
        prescan_report_add(report, &violation) != 0)
        return -1;
    if (report->shortening_count != SIZE_MAX)
        report->shortening_count++;
    return 0;
}

#ifdef PORTABLE_PRESCAN_TEST_HOOKS
static int name_fingerprint_override_active;
static uint64_t name_fingerprint_override;

void portable_prescan_test_force_name_fingerprint(uint64_t fingerprint)
{
    name_fingerprint_override = fingerprint;
    name_fingerprint_override_active = 1;
}

void portable_prescan_test_clear_name_fingerprint(void)
{
    name_fingerprint_override = 0;
    name_fingerprint_override_active = 0;
}
#endif

static int prescan_map_physical_name(const char *logical_component,
                                     uint64_t collision_number,
                                     PortablePhysicalName *out)
{
#if defined(PORTABLE_PRESCAN_TEST_HOOKS) && defined(PORTABLE_NAME_TEST_HOOKS)
    if (name_fingerprint_override_active)
        return portable_physical_name_map_with_fingerprint_for_test(
            logical_component, collision_number, name_fingerprint_override,
            out);
#endif
    return portable_physical_name_map(logical_component, collision_number, out);
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
    char *logical_component;
    char *logical_path;
    PortablePhysicalName unsuffixed;
} PortableSiblingCandidate;

typedef struct {
    PortableSiblingCandidate *items;
    size_t count;
    size_t capacity;
    int ascii_collision;
    int collision;
    size_t natural_probe_successes;
    size_t assigned_count;
    const char *representative_logical_path;
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
        free(group->items[index].logical_component);
        free(group->items[index].logical_path);
    }
    free(group->items);
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
                                   const char *logical_component,
                                   const char *logical_path,
                                   const PortablePhysicalName *unsuffixed)
{
    if (group == NULL || logical_component == NULL || logical_path == NULL ||
        unsuffixed == NULL ||
        group->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (group->count == group->capacity) {
        PortableSiblingCandidate *items = array_reserve(
            group->items, &group->capacity, group->count, 1U,
            sizeof(*items), 4U, SIDECAR_MAX_LIVE_ENTRIES);
        if (items == NULL)
            return -1;
        group->items = items;
    }

    char *component_copy = portable_text_duplicate(logical_component);
    if (component_copy == NULL)
        return -1;
    char *logical_copy = portable_text_duplicate(logical_path);
    if (logical_copy == NULL) {
        free(component_copy);
        return -1;
    }
    group->items[group->count] = (PortableSiblingCandidate){
        .logical_component = component_copy,
        .logical_path = logical_copy,
        .unsuffixed = *unsuffixed
    };
    group->count++;
    return 0;
}

static int case_probe_groups_add(PortableCaseProbeGroups *groups,
                                 const char *logical_component,
                                 const char *logical_path,
                                 const PortablePhysicalName *unsuffixed,
                                 size_t *out_index)
{
    if (groups == NULL || logical_component == NULL || logical_path == NULL ||
        unsuffixed == NULL || out_index == NULL ||
        groups->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (groups->count == groups->capacity) {
        PortableCaseProbeGroup *items = array_reserve(
            groups->items, &groups->capacity, groups->count, 1U,
            sizeof(*items), 8U, SIDECAR_MAX_LIVE_ENTRIES);
        if (items == NULL)
            return -1;
        groups->items = items;
    }

    size_t index = groups->count++;
    if (case_probe_group_append(&groups->items[index], logical_component,
                                logical_path, unsuffixed) != 0) {
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
    const PortableSiblingCandidate *candidate;
    PortableCaseProbeGroup *group;
    PortablePhysicalName final_name;
} PortableCollisionAssignment;

static int unsigned_text_compare(const char *left, const char *right)
{
    if (left == NULL || right == NULL)
        return left == right ? 0 : left == NULL ? -1 : 1;
    size_t index = 0;
    for (;;) {
        unsigned char left_byte = (unsigned char)left[index];
        unsigned char right_byte = (unsigned char)right[index];
        if (left_byte != right_byte)
            return left_byte < right_byte ? -1 : 1;
        if (left_byte == '\0')
            return 0;
        index++;
    }
}

static int portable_collision_assignment_compare(const void *left,
                                                 const void *right)
{
    const PortableCollisionAssignment *left_entry = left;
    const PortableCollisionAssignment *right_entry = right;
    int candidate_result = unsigned_text_compare(
        left_entry->candidate->unsuffixed.physical_leaf,
        right_entry->candidate->unsuffixed.physical_leaf);
    if (candidate_result != 0)
        return candidate_result;
    return unsigned_text_compare(left_entry->candidate->logical_component,
                                 right_entry->candidate->logical_component);
}

static int portable_collision_assignments_build(
    PortableCaseProbeGroups *groups, PortableCollisionAssignment **out,
    size_t *out_count)
{
    if (groups == NULL || out == NULL || out_count == NULL)
        return -1;

    size_t count = 0;
    for (size_t group_index = 0; group_index < groups->count; group_index++) {
        if (groups->items[group_index].count >
            SIDECAR_MAX_LIVE_ENTRIES - count)
            return -1;
        count += groups->items[group_index].count;
    }

    PortableCollisionAssignment *assignments =
        count == 0 ? NULL : calloc(count, sizeof(*assignments));
    if (count != 0 && assignments == NULL)
        return -1;

    size_t assignment_index = 0;
    for (size_t group_index = 0; group_index < groups->count; group_index++) {
        PortableCaseProbeGroup *group = &groups->items[group_index];
        for (size_t index = 0; index < group->count; index++) {
            assignments[assignment_index].candidate = &group->items[index];
            assignments[assignment_index].group = group;
            assignment_index++;
        }
    }
    if (count > 1U)
        qsort(assignments, count, sizeof(*assignments),
              portable_collision_assignment_compare);
    *out = assignments;
    *out_count = count;
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
    const PortableCaseFoldSet *reserved_names, const char *leaf,
    int case_sensitive)
{
    if (reserved_names == NULL || leaf == NULL)
        return 0;
    char reservation_key[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    if (case_sensitive) {
        if (copy_text(reservation_key, sizeof(reservation_key), leaf) != 0)
            return 0;
    } else {
        ascii_fold_copy(reservation_key, sizeof(reservation_key), leaf);
    }
    return case_fold_set_contains(reserved_names, reservation_key);
}

static int case_probe_reserve_name(PortableCaseFoldSet *reserved_names,
                                   const char *leaf, int case_sensitive)
{
    if (reserved_names == NULL || leaf == NULL)
        return -1;
    char reservation_key[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    if (case_sensitive) {
        if (copy_text(reservation_key, sizeof(reservation_key), leaf) != 0)
            return -1;
    } else {
        ascii_fold_copy(reservation_key, sizeof(reservation_key), leaf);
    }
    char *existing = NULL;
    int result = case_fold_set_find_or_insert(reserved_names,
                                              reservation_key, leaf,
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

static int sibling_source_names_build(
    const PortableCollisionAssignment *assignments, size_t assignment_count,
    int case_sensitive, PortableCaseFoldSet *source_names)
{
    if ((assignments == NULL && assignment_count != 0) || source_names == NULL)
        return -1;

    for (size_t index = 0; index < assignment_count; index++) {
        const char *leaf =
            assignments[index].candidate->unsuffixed.physical_leaf;
        char key[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
        if (case_sensitive) {
            if (copy_text(key, sizeof(key), leaf) != 0)
                return -1;
        } else {
            ascii_fold_copy(key, sizeof(key), leaf);
        }
        char *existing = NULL;
        if (case_fold_set_find_or_insert(source_names, key, leaf,
                                         &existing) < 0)
            return -1;
    }
    return 0;
}

static int sibling_natural_names_probe(
    PortableCaseProbeState *state, PortableCollisionAssignment *assignments,
    size_t assignment_count, PortableCaseProbeGroups *groups,
    PortableCaseFoldSet *scratch_names)
{
    if (state == NULL || (assignments == NULL && assignment_count != 0) ||
        groups == NULL || scratch_names == NULL)
        return -1;

    int needs_probe = 0;
    for (size_t index = 0; index < groups->count; index++) {
        PortableCaseProbeGroup *group = &groups->items[index];
        group->collision = group->ascii_collision;
        group->natural_probe_successes = 0;
        group->assigned_count = 0;
        group->representative_logical_path = NULL;
        if (group->count > 1U) {
            needs_probe = 1;
            case_probe_count();
        }
    }
    if (!needs_probe)
        return 0;
    if (case_probe_prepare(state) != 0)
        return -1;

    for (size_t index = 0; index < assignment_count; index++) {
        PortableCollisionAssignment *assignment = &assignments[index];
        const char *leaf = assignment->candidate->unsuffixed.physical_leaf;
        case_fs_probe_count();
        int fd = openat(state->scratch_fd, leaf,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                            O_CLOEXEC,
                        0600);
        if (fd >= 0) {
            if (close(fd) != 0)
                return -1;
            assignment->group->natural_probe_successes++;
            char *existing = NULL;
            if (case_fold_set_find_or_insert(scratch_names, leaf, leaf,
                                             &existing) < 0)
                return -1;
            continue;
        }
        if (errno != EEXIST ||
            assignment->group->natural_probe_successes == 0)
            return -1;
        assignment->group->collision = 1;
    }

    return case_probe_readback_matches(scratch_names, state->scratch_fd);
}

static int prescan_store_final_name(PortablePrescanReport *report,
                                    const char *root_id,
                                    const PortableSiblingCandidate *candidate,
                                    const PortablePhysicalName *final_name,
                                    int force_plan_entry)
{
    if (report == NULL || root_id == NULL || candidate == NULL ||
        final_name == NULL)
        return -1;
    if (force_plan_entry || final_name->shortened) {
        if (portable_collision_plan_add(
                &report->collision_plan, root_id, candidate->logical_path,
                final_name->physical_leaf,
                final_name->collision_suffix) != 0)
            return -1;
    }
    if (final_name->shortened &&
        prescan_record_shortening(report, root_id, candidate->logical_path,
                                  candidate->logical_component,
                                  final_name->collision_suffix) != 0)
        return -1;
    return 0;
}

static int sibling_namespace_plan(
    PortableCaseProbeState *state, PortableCollisionAssignment *assignments,
    size_t assignment_count, const char *root_id, int case_sensitive,
    const PortableCaseFoldSet *source_names,
    PortableCaseFoldSet *reserved_names, PortableCaseFoldSet *scratch_names,
    PortablePrescanReport *report)
{
    if (state == NULL || (assignments == NULL && assignment_count != 0) ||
        root_id == NULL || source_names == NULL || reserved_names == NULL ||
        scratch_names == NULL || report == NULL)
        return -1;

    int failed = 0;
    for (size_t index = 0; index < assignment_count && !failed; index++) {
        PortableCollisionAssignment *assignment = &assignments[index];
        PortableCaseProbeGroup *group = assignment->group;
        if (group == NULL || group->count == 0) {
            failed = 1;
            break;
        }

        if (!case_sensitive && group->count == 1U)
            group->collision = 0;
        if (case_sensitive)
            group->collision = group->count > 1U;

        if (!group->collision) {
            assignment->final_name = assignment->candidate->unsuffixed;
        } else if (group->assigned_count == 0) {
            assignment->final_name = assignment->candidate->unsuffixed;
            group->representative_logical_path =
                assignment->candidate->logical_path;
        } else {
            uint64_t collision_number = 1;
            for (;;) {
                PortablePhysicalName mapped;
                if (prescan_map_physical_name(
                        assignment->candidate->logical_component,
                        collision_number, &mapped) != 0) {
                    failed = 1;
                    break;
                }

                int unavailable =
                    case_probe_reserved_name_contains(
                        source_names, mapped.physical_leaf, case_sensitive) ||
                    case_probe_reserved_name_contains(
                        reserved_names, mapped.physical_leaf, case_sensitive);

                if (!unavailable && !case_sensitive) {
                    if (state->scratch_fd < 0) {
                        failed = 1;
                        break;
                    }
                    case_fs_probe_count();
                    int fd = openat(state->scratch_fd, mapped.physical_leaf,
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
                                scratch_names, mapped.physical_leaf,
                                mapped.physical_leaf, &existing) < 0) {
                            failed = 1;
                            break;
                        }
                        assignment->final_name = mapped;
                        break;
                    }
                    if (errno != EEXIST)
                        failed = 1;
                    else
                        unavailable = 1;
                } else if (!unavailable) {
                    assignment->final_name = mapped;
                    break;
                }

                if (failed)
                    break;
                if (!unavailable) {
                    failed = 1;
                    break;
                }
                if (collision_number == UINT64_MAX) {
                    failed = 1;
                    break;
                }
                collision_number++;
            }
        }
        if (failed)
            break;

        if (case_probe_reserve_name(
                reserved_names, assignment->final_name.physical_leaf,
                case_sensitive) != 0 ||
            prescan_store_final_name(
                report, root_id, assignment->candidate,
                &assignment->final_name, group->collision) != 0) {
            failed = 1;
            break;
        }
        group->assigned_count++;
    }

    if (!failed && !case_sensitive && state->scratch_fd >= 0 &&
        case_probe_readback_matches(scratch_names, state->scratch_fd) != 0)
        failed = 1;

    if (!failed && !case_sensitive) {
        for (size_t index = 0; index < assignment_count; index++) {
            PortableCollisionAssignment *assignment = &assignments[index];
            PortableCaseProbeGroup *group = assignment->group;
            if (!group->collision || group->ascii_collision ||
                assignment->candidate->logical_path ==
                    group->representative_logical_path)
                continue;
            if (group->representative_logical_path == NULL ||
                prescan_record_case_collision(
                    report, root_id, assignment->candidate->logical_path,
                    group->representative_logical_path) != 0) {
                failed = 1;
                break;
            }
        }
    }

    return failed ? -1 : 0;
}

typedef struct {
    char root_id[MANIFEST_ID_MAX];
    char *logical_path;
} PortableCompatibilityPath;

typedef struct {
    PortableCompatibilityPath *items;
    size_t count;
    size_t capacity;
} PortableCompatibilityPaths;

static void compatibility_paths_free(PortableCompatibilityPaths *paths)
{
    if (paths == NULL)
        return;
    for (size_t index = 0; index < paths->count; index++)
        free(paths->items[index].logical_path);
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static int compatibility_paths_add(PortableCompatibilityPaths *paths,
                                   const char *root_id,
                                   const char *logical_path)
{
    if (paths == NULL || root_id == NULL || logical_path == NULL ||
        paths->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (paths->count == paths->capacity) {
        PortableCompatibilityPath *items = array_reserve(
            paths->items, &paths->capacity, paths->count, 1U,
            sizeof(*items), 64U, SIDECAR_MAX_LIVE_ENTRIES);
        if (items == NULL)
            return -1;
        paths->items = items;
    }

    PortableCompatibilityPath *item = &paths->items[paths->count];
    memset(item, 0, sizeof(*item));
    item->logical_path = portable_text_duplicate(logical_path);
    if (item->logical_path == NULL ||
        copy_text(item->root_id, sizeof(item->root_id), root_id) != 0) {
        free(item->logical_path);
        memset(item, 0, sizeof(*item));
        return -1;
    }
    paths->count++;
    return 0;
}

static int prescan_directory(int source_fd, const char *logical,
                             const char *root_id,
                             PortablePrescanReport *report,
                             int case_sensitive,
                             PortableCaseProbeState *probe_state,
                             const SelectionRoot *selection,
                             PortableCompatibilityPaths *compatibility_paths)
{
    if (source_fd < 0 || logical == NULL || root_id == NULL || report == NULL ||
        probe_state == NULL || compatibility_paths == NULL)
        return -1;

    int scan_fd = dup_cloexec(source_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        int saved_errno = errno;
        prescan_record_operational_failure(report, logical, saved_errno);
        if (scan_fd >= 0)
            close(scan_fd);
        errno = saved_errno;
        return -1;
    }

    PortableCaseFoldSet siblings = {0};
    PortableCaseFoldSet group_keys = {0};
    PortableCaseProbeGroups groups = {0};
    int failed = 0;

    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                int saved_errno = errno;
                prescan_record_operational_failure(report, logical,
                                                   saved_errno);
                errno = saved_errno;
                failed = 1;
            }
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
        if (selection != NULL) {
            int owned = selection_root_owns(selection, child_logical);
            if (owned < 0) {
                failed = 1;
                break;
            }
            if (owned == 0)
                continue;
        }

        size_t raw_length = strlen(entry->d_name);
        if (raw_length > NAME_MAX) {
            if (prescan_record_violation(
                    report, root_id, child_logical,
                    PORTABLE_PRESCAN_NAME_TOO_LONG, NAME_MAX,
                    raw_length) != 0)
                failed = 1;
            if (failed)
                break;
            continue;
        }

        PortablePhysicalName unsuffixed;
        if (prescan_map_physical_name(entry->d_name, 0, &unsuffixed) != 0 ||
            compatibility_paths_add(compatibility_paths, root_id,
                                    child_logical) != 0) {
            failed = 1;
            break;
        }

        char group_key[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
        if (case_sensitive) {
            if (copy_text(group_key, sizeof(group_key),
                          unsuffixed.physical_leaf) != 0) {
                failed = 1;
                break;
            }
        } else {
            skeleton_copy(group_key, sizeof(group_key),
                          unsuffixed.physical_leaf);
        }

        size_t new_group_index = groups.count;
        if (case_probe_groups_add(&groups, entry->d_name, child_logical,
                                  &unsuffixed, &new_group_index) != 0) {
            failed = 1;
            break;
        }
        size_t existing_group_index = SIZE_MAX;
        char *existing_group_logical = NULL;
        int group_found = case_fold_set_find_or_insert_value(
            &group_keys, group_key, child_logical, new_group_index,
            &existing_group_index, &existing_group_logical);
        if (group_found < 0) {
            failed = 1;
            break;
        }

        size_t group_index = new_group_index;
        if (group_found == 1) {
            case_probe_group_free(&groups.items[new_group_index]);
            groups.count--;
            group_index = existing_group_index;
            if (group_index >= groups.count ||
                case_probe_group_append(&groups.items[group_index],
                                        entry->d_name, child_logical,
                                        &unsuffixed) != 0) {
                failed = 1;
                break;
            }
        }

        if (!case_sensitive) {
            char folded[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
            ascii_fold_copy(folded, sizeof(folded),
                            unsuffixed.physical_leaf);
            char *existing_logical = NULL;
            int found = case_fold_set_find_or_insert(
                &siblings, folded, child_logical, &existing_logical);
            if (found < 0) {
                failed = 1;
                break;
            }
            if (found == 1) {
                groups.items[group_index].ascii_collision = 1;
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
            int saved_errno = errno;
            prescan_record_operational_failure(report, child_logical,
                                               saved_errno);
            errno = saved_errno;
            failed = 1;
            break;
        }
        if (S_ISDIR(child_stat.st_mode)) {
            int child_fd = open_source_node(source_fd, entry->d_name, NULL,
                                            &child_stat);
            if (child_fd < 0) {
                int saved_errno = errno;
                prescan_record_operational_failure(report, child_logical,
                                                   saved_errno);
                errno = saved_errno;
                failed = 1;
                break;
            }
            int child_result = prescan_directory(
                child_fd, child_logical, root_id, report, case_sensitive,
                probe_state, selection, compatibility_paths);
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

    if (closedir(directory) != 0) {
        int saved_errno = errno;
        prescan_record_operational_failure(report, logical, saved_errno);
        errno = saved_errno;
        failed = 1;
    }

    PortableCollisionAssignment *assignments = NULL;
    size_t assignment_count = 0;
    PortableCaseFoldSet source_names = {0};
    PortableCaseFoldSet reserved_names = {0};
    PortableCaseFoldSet scratch_names = {0};
    if (!failed &&
        (portable_collision_assignments_build(
             &groups, &assignments, &assignment_count) != 0 ||
         sibling_source_names_build(assignments, assignment_count,
                                    case_sensitive, &source_names) != 0))
        failed = 1;

    if (!failed && !case_sensitive &&
        sibling_natural_names_probe(probe_state, assignments,
                                    assignment_count, &groups,
                                    &scratch_names) != 0)
        failed = 1;

    if (!failed &&
        sibling_namespace_plan(probe_state, assignments, assignment_count,
                               root_id, case_sensitive, &source_names,
                               &reserved_names, &scratch_names, report) != 0)
        failed = 1;

    if (!case_sensitive && scratch_names.count != 0 &&
        case_probe_group_names_free(probe_state, &scratch_names) != 0)
        failed = 1;

    case_fold_set_free(&siblings);
    case_fold_set_free(&group_keys);
    case_fold_set_free(&source_names);
    case_fold_set_free(&reserved_names);
    case_fold_set_free(&scratch_names);
    free(assignments);
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
                        PortableCaseProbeState *probe_state,
                        PortableCompatibilityPaths *compatibility_paths)
{
    if (!root_spec_valid(root) || report == NULL || probe_state == NULL ||
        compatibility_paths == NULL)
        return -1;

    struct stat st;
    if (read_source_stat(-1, NULL, root->capture_path, &st) != 0) {
        int saved_errno = errno;
        prescan_record_operational_failure(report, root->capture_path,
                                           saved_errno);
        errno = saved_errno;
        return -1;
    }
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
    if (root_fd < 0) {
        int saved_errno = errno;
        prescan_record_operational_failure(report, root->capture_path,
                                           saved_errno);
        errno = saved_errno;
        return -1;
    }
    int result = prescan_directory(root_fd, "", root->id, report,
                                   case_sensitive, probe_state,
                                   root->selection, compatibility_paths);
    if (close(root_fd) != 0)
        result = -1;
    return result;
}

static int compatibility_path_build(
    const PortableCollisionPlan *plan, const char *root_id,
    const char *logical_path, char physical[SIDECAR_MAX_PATH + 1U],
    size_t *physical_length_out)
{
    if (plan == NULL || root_id == NULL || logical_path == NULL ||
        logical_path[0] == '\0' || physical == NULL ||
        physical_length_out == NULL || !plan->sorted)
        return -1;

    char logical_prefix[SIDECAR_MAX_PATH + 1U] = {0};
    char joined[SIDECAR_MAX_PATH + 1U] = {0};
    int joined_available = 1;
    size_t physical_length = 0;
    const char *cursor = logical_path;

    while (*cursor != '\0') {
        const char *slash = strchr(cursor, '/');
        size_t component_length = slash == NULL
            ? strlen(cursor)
            : (size_t)(slash - cursor);
        if (component_length == 0 || component_length > NAME_MAX)
            return -1;

        char component[NAME_MAX + 1U];
        memcpy(component, cursor, component_length);
        component[component_length] = '\0';

        char next_prefix[SIDECAR_MAX_PATH + 1U];
        if (append_logical(next_prefix, sizeof(next_prefix), logical_prefix,
                           component) != 0)
            return -1;

        const PortableCollisionPlanEntry *planned =
            portable_collision_plan_find(plan, root_id, next_prefix);
        PortablePhysicalName ordinary;
        const char *leaf = NULL;
        if (planned != NULL) {
            if (planned->physical_leaf[0] == '\0')
                return -1;
            leaf = planned->physical_leaf;
        } else {
            if (prescan_map_physical_name(component, 0, &ordinary) != 0 ||
                ordinary.shortened)
                return -1;
            leaf = ordinary.physical_leaf;
        }

        size_t leaf_length = strlen(leaf);
        size_t separator_length = physical_length == 0 ? 0U : 1U;
        if (physical_length > SIZE_MAX - separator_length ||
            physical_length + separator_length > SIZE_MAX - leaf_length)
            return -1;
        physical_length += separator_length + leaf_length;

        if (joined_available) {
            char next_joined[SIDECAR_MAX_PATH + 1U];
            if (append_physical(next_joined, sizeof(next_joined), joined,
                                leaf) != 0) {
                joined_available = 0;
                joined[0] = '\0';
            } else if (copy_text(joined, sizeof(joined), next_joined) != 0) {
                return -1;
            }
        }

        if (copy_text(logical_prefix, sizeof(logical_prefix), next_prefix) != 0)
            return -1;
        if (slash == NULL)
            break;
        cursor = slash + 1;
    }

    if (joined_available && copy_text(physical, SIDECAR_MAX_PATH + 1U,
                                      joined) != 0)
        return -1;
    if (!joined_available)
        physical[0] = '\0';
    *physical_length_out = physical_length;
    return 0;
}

static int compatibility_paths_derive(
    PortablePrescanReport *report, const PortableCaptureRequest *request,
    const PortableCompatibilityPaths *paths)
{
    if (report == NULL || request == NULL || paths == NULL ||
        !report->collision_plan.sorted)
        return -1;

    for (size_t index = 0; index < paths->count; index++) {
        const PortableCompatibilityPath *item = &paths->items[index];
        const PortableRootSpec *root =
            portable_collision_plan_root(request, item->root_id);
        if (root == NULL)
            return -1;

        char physical[SIDECAR_MAX_PATH + 1U];
        size_t physical_length = 0;
        if (compatibility_path_build(&report->collision_plan, item->root_id,
                                     item->logical_path, physical,
                                     &physical_length) != 0)
            return -1;

        const PortableCollisionPlanEntry *planned =
            portable_collision_plan_find(&report->collision_plan,
                                         item->root_id,
                                         item->logical_path);
        if (planned != NULL && physical[0] != '\0') {
            size_t plan_index = (size_t)(planned - report->collision_plan.entries);
            if (plan_index >= report->collision_plan.count ||
                copy_text(report->collision_plan.entries[plan_index].physical_path,
                          sizeof(report->collision_plan.entries[plan_index].physical_path),
                          physical) != 0)
                return -1;
        }

        size_t payload_length = strlen(root->payload_path);
        if (payload_length > SIZE_MAX - 1U ||
            physical_length > SIZE_MAX - payload_length - 1U)
            return -1;
        size_t actual_path = payload_length + 1U + physical_length;
        if (!portable_payload_path_fits(payload_length, physical_length,
                                        PATH_MAX) &&
            prescan_record_violation(
                report, item->root_id, item->logical_path,
                PORTABLE_PRESCAN_PATH_TOO_LONG, PATH_MAX, actual_path) != 0)
            return -1;
    }
    return 0;
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
    PortableCompatibilityPaths compatibility_paths = {0};
    int failed = 0;
    for (size_t index = 0; index < request->root_count; index++)
        if (prescan_root(&request->roots[index], report,
                         request->case_sensitive, &probe_state,
                         &compatibility_paths) != 0)
            failed = 1;
    if (prescan_root_payload_namespace(request, report, &probe_state) != 0)
        failed = 1;
    if (case_probe_cleanup(&probe_state) != 0)
        failed = 1;
    portable_collision_plan_sort(&report->collision_plan);
    if (!failed && compatibility_paths_derive(report, request,
                                              &compatibility_paths) != 0)
        failed = 1;
    if (!failed)
        prescan_report_refresh_unresolved(report);
    compatibility_paths_free(&compatibility_paths);
    return failed ||
                   (reject_violations &&
                    (report->unresolved_count != 0 ||
                     report->shortening_count != 0))
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
