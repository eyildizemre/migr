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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    size_t root_index;
    char *logical;
    char *physical;
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

typedef struct {
    const Manifest *manifest;
    PortableRestorePreflightReport *report;
    RootMap root_map;
    ParentMap parent_map; /* Parent-prefix validation consumes this (D21). */
    size_t *root_order;
    PreflightEntries *entries;
    int destination_home_fd;
    const char * const *destination_xdg_dirs;
    PreflightMemory memory;
} Collection;

typedef struct {
    PreflightEntry **logical;
    PreflightEntry **physical;
    size_t count;
} EntryOrders;

typedef struct {
    int data_fd;
    const Collection *collection;
    const PreflightEntries *entries;
    const EntryOrders *orders;
    unsigned char *seen;
    char path[PATH_MAX];
    int failed;
} PayloadInventory;

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
    if (manifest == NULL || manifest->version != MANIFEST_CURRENT_VERSION ||
        manifest->representation != CLONE_PORTABLE_SIDECAR ||
        manifest->sidecar_version != SIDECAR_VERSION ||
        manifest->root_count < 0 || manifest->root_count > MANIFEST_MAX_ROOTS ||
        (manifest->root_count != 0 && manifest->roots == NULL))
    {
        report_violation(report, SIZE_MAX, "manifest");
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
    if (entries == NULL || extra > SIDECAR_MAX_LIVE_ENTRIES - entries->count)
    {
        errno = E2BIG;
        return -1;
    }
    size_t needed = entries->count + extra;
    if (needed <= entries->capacity)
        return 0;
    size_t capacity = entries->capacity == 0 ? 16U : entries->capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > SIDECAR_MAX_LIVE_ENTRIES ||
        capacity > SIZE_MAX / sizeof(*entries->items))
    {
        errno = E2BIG;
        return -1;
    }
    size_t old_size = entries->capacity * sizeof(*entries->items);
    size_t new_size = capacity * sizeof(*entries->items);
    PreflightEntry *items = preflight_realloc(memory, entries->items,
                                              old_size, new_size);
    if (items == NULL)
        return -1;
    memset(items + entries->capacity, 0,
           (capacity - entries->capacity) * sizeof(*items));
    entries->items = items;
    entries->capacity = capacity;
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
        preflight_free(memory, entries->items[index].physical,
                       entries->items[index].physical == NULL ? 0
                           : strlen(entries->items[index].physical) + 1U);
    }
    preflight_free(memory, entries->items,
                   entries->capacity * sizeof(*entries->items));
    memset(entries, 0, sizeof(*entries));
}

static int open_destination_profile_anchor(int home_fd, const char *relative,
                                           int *anchor_out,
                                           struct stat *existing,
                                           int *has_existing)
{
    if (home_fd < 0 || relative == NULL || anchor_out == NULL ||
        existing == NULL || has_existing == NULL ||
        !relative_path_valid(relative, 1))
    {
        errno = EINVAL;
        return -1;
    }
    *anchor_out = -1;
    *has_existing = 0;
    int current = dup_cloexec(home_fd);
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
    char *cursor = copy;
    for (;;)
    {
        char *slash = strchr(cursor, '/');
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
        cursor = slash + 1U;
    }
}

/* Match native restore's XDG anchor: an existing destination directory is
 * the anchor itself; an absent final component is created later beneath its
 * existing parent, after the confirmation/probe gate. */
static int open_xdg_profile_anchor(const Collection *collection,
                                   const ManifestRoot *root,
                                   const char *logical,
                                   int *anchor_out,
                                   struct stat *existing,
                                   int *has_existing)
{
    if (collection == NULL || root == NULL || logical == NULL ||
        anchor_out == NULL || existing == NULL || has_existing == NULL ||
        !xdg_destination_valid(collection->destination_xdg_dirs, root))
    {
        errno = EINVAL;
        return -1;
    }

    int index = xdg_key_index(root->id);
    int xdg_fd = -1;
    char prefix[NAME_MAX + 1U];
    char relative[PATH_MAX];
    if (open_xdg_destination_anchor(
            collection->destination_xdg_dirs[index], &xdg_fd,
            prefix, sizeof(prefix)) != 0 ||
        destination_relative_path_build(prefix, logical, relative,
                                        sizeof(relative)) != 0)
    {
        if (xdg_fd >= 0)
            close(xdg_fd);
        return -1;
    }

    int result = open_destination_profile_anchor(
        xdg_fd, relative, anchor_out, existing, has_existing);
    int saved = errno;
    if (close(xdg_fd) != 0 && result == 0)
    {
        close(*anchor_out);
        *anchor_out = -1;
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

/* Returns 0 on success, -1 for a per-entry violation (already recorded via
 * report_violation(), safe for the caller to log and keep scanning past),
 * or -2 for an internal/unexpected failure unrelated to this entry's data
 * (no violation recorded; the caller should abort the scan). */
static int collect_metadata_profile(const Collection *collection,
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

    int anchor = -1;
    struct stat existing;
    memset(&existing, 0, sizeof(existing));
    int has_existing = 0;
    char destination[PATH_MAX];
    if (root->policy == ROOT_POLICY_HOME_RELATIVE)
    {
        if (destination_path_build(root, entry->logical,
                                   collection->destination_xdg_dirs,
                                   destination,
                                   sizeof(destination)) != 0 ||
            open_destination_profile_anchor(
                collection->destination_home_fd, destination, &anchor,
                &existing, &has_existing) != 0)
        {
            report_violation(collection->report, root_index, entry->logical);
            return -1;
        }
    }
    else if (root->policy == ROOT_POLICY_XDG)
    {
        if (destination_path_build(root, entry->logical,
                                   collection->destination_xdg_dirs,
                                   destination, sizeof(destination)) != 0 ||
            open_xdg_profile_anchor(collection, root, entry->logical,
                                    &anchor, &existing, &has_existing) != 0)
        {
            report_violation(collection->report, root_index, entry->logical);
            return -1;
        }
    }
    else
    {
        /* MANUAL_NATIVE is rejected by manifest validation before entries
         * reach this path. Keep the fallback fail-closed if that invariant
         * changes. */
        anchor = dup_cloexec(collection->destination_home_fd);
        if (anchor < 0)
            return -2;
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
    int physical_valid = sidecar_path_valid(entry->physical_path, 1);
    if (logical_valid <= 0 || physical_valid <= 0)
    {
        report_violation(report, root_index, "invalid-path");
        if (logical_valid < 0 || physical_valid < 0)
            return 1;
        return 0;
    }
    if (!entry_physical_matches_parent(
            &collection->manifest->roots[root_index],
            &collection->parent_map, entry))
    {
        report_violation(report, root_index, "physical-mismatch");
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
                          &destination->logical) != 0 ||
        copy_sidecar_path(&collection->memory, entry->physical_path,
                          &destination->physical) != 0)
    {
        preflight_free(&collection->memory, destination->logical,
                       destination->logical == NULL ? 0
                           : strlen(destination->logical) + 1U);
        destination->logical = NULL;
        return 1;
    }
    destination->root_index = root_index;
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

    if (collect_metadata_profile(collection,
                                 &collection->manifest->roots[root_index],
                                 root_index, destination) < -1)
        return 1;
    return 0;
}

static int logical_order_compare(const void *left, const void *right)
{
    const PreflightEntry *a = *(const PreflightEntry *const *)left;
    const PreflightEntry *b = *(const PreflightEntry *const *)right;
    if (a->root_index < b->root_index)
        return -1;
    if (a->root_index > b->root_index)
        return 1;
    return strcmp(a->logical, b->logical);
}

static int physical_order_compare(const void *left, const void *right)
{
    const PreflightEntry *a = *(const PreflightEntry *const *)left;
    const PreflightEntry *b = *(const PreflightEntry *const *)right;
    if (a->root_index < b->root_index)
        return -1;
    if (a->root_index > b->root_index)
        return 1;
    return strcmp(a->physical, b->physical);
}

static void entry_orders_free(PreflightMemory *memory, EntryOrders *orders)
{
    if (orders == NULL)
        return;
    preflight_free(memory, orders->logical,
                   orders->count * sizeof(*orders->logical));
    preflight_free(memory, orders->physical,
                   orders->count * sizeof(*orders->physical));
    memset(orders, 0, sizeof(*orders));
}

static PreflightEntry *find_physical(const EntryOrders *orders,
                                     size_t root_index, const char *physical);

static PreflightEntry *find_logical(const EntryOrders *orders,
                                    size_t root_index, const char *logical)
{
    size_t left = 0;
    size_t right = orders->count;
    while (left < right)
    {
        size_t middle = left + (right - left) / 2U;
        PreflightEntry *entry = orders->logical[middle];
        int comparison;
        if (entry->root_index < root_index)
            comparison = -1;
        else if (entry->root_index > root_index)
            comparison = 1;
        else
            comparison = strcmp(entry->logical, logical);
        if (comparison < 0)
            left = middle + 1U;
        else
            right = middle;
    }
    if (left == orders->count)
        return NULL;
    PreflightEntry *entry = orders->logical[left];
    return entry->root_index == root_index &&
           strcmp(entry->logical, logical) == 0 ? entry : NULL;
}

/* collect_entry() already requires every non-root entry's immediate logical
 * parent to exist (D21). Exact parent lookup therefore catches every
 * non-directory ancestor without relying on strcmp adjacency. */
static int entry_ancestor_conflict(const EntryOrders *orders,
                                   const PreflightEntry *entry, int physical)
{
    const char *path = physical ? entry->physical : entry->logical;
    const char *slash = strrchr(path, '/');
    if (slash == NULL || (size_t)(slash - path) >= PATH_MAX)
        return 0;

    char parent[PATH_MAX];
    size_t parent_length = (size_t)(slash - path);
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    PreflightEntry *found = physical
        ? find_physical(orders, entry->root_index, parent)
        : find_logical(orders, entry->root_index, parent);
    return found != NULL && found->kind != SIDECAR_KIND_DIRECTORY;
}

static int analyze_entries(PreflightMemory *memory,
                           PreflightEntries *entries,
                           EntryOrders *orders,
                           PortableRestorePreflightReport *report)
{
    memset(orders, 0, sizeof(*orders));
    if (entries->count == 0)
        return 0;
    if (entries->count > SIZE_MAX / sizeof(*orders->logical))
    {
        errno = E2BIG;
        return -1;
    }
    size_t size = entries->count * sizeof(*orders->logical);
    orders->logical = preflight_alloc(memory, size);
    orders->physical = preflight_alloc(memory, size);
    if (orders->logical == NULL || orders->physical == NULL)
        return -1;
    orders->count = entries->count;
    for (size_t index = 0; index < entries->count; index++)
    {
        orders->logical[index] = &entries->items[index];
        orders->physical[index] = &entries->items[index];
    }
    qsort(orders->logical, orders->count, sizeof(*orders->logical),
          logical_order_compare);
    qsort(orders->physical, orders->count, sizeof(*orders->physical),
          physical_order_compare);

    for (size_t index = 1; index < orders->count; index++)
    {
        PreflightEntry *previous = orders->logical[index - 1U];
        PreflightEntry *current = orders->logical[index];
        if (previous->root_index == current->root_index &&
            strcmp(previous->logical, current->logical) == 0)
            report_violation(report, current->root_index, current->logical);
    }
    for (size_t index = 0; index < orders->count; index++)
    {
        PreflightEntry *current = orders->logical[index];
        if (entry_ancestor_conflict(orders, current, 0))
            report_violation(report, current->root_index, current->logical);
    }
    for (size_t index = 1; index < orders->count; index++)
    {
        PreflightEntry *previous = orders->physical[index - 1U];
        PreflightEntry *current = orders->physical[index];
        if (previous->root_index == current->root_index &&
            strcmp(previous->physical, current->physical) == 0)
        {
            /* Unreachable via collect_entry() as of D.4b: every entry that
             * reaches this array has already passed the physical/logical
             * validator, and component_percent_encode() is injective, so two
             * different logical paths can no longer produce the same physical
             * path. Kept as defense-in-depth in case that upstream guarantee
             * changes. */
            if (strcmp(previous->logical, current->logical) != 0)
                report_violation(report, current->root_index,
                                 current->logical);
        }
    }
    for (size_t index = 0; index < orders->count; index++)
    {
        PreflightEntry *current = orders->physical[index];
        if (entry_ancestor_conflict(orders, current, 1))
            report_violation(report, current->root_index, current->logical);
    }
    return 0;
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

static size_t root_for_payload_path(const Collection *collection,
                                    const char *path,
                                    const char **relative_out)
{
    if (collection->report->root_count == 0)
        return SIZE_MAX;
    /* An owning root must be an exact slash-delimited prefix of path. Walk
     * those prefixes directly instead of trusting a lexical predecessor. */
    size_t length = strlen(path);
    for (;;)
    {
        if (length >= PATH_MAX)
            return SIZE_MAX;
        char candidate[PATH_MAX];
        memcpy(candidate, path, length);
        candidate[length] = '\0';
        size_t root_index = root_order_find_exact(collection, candidate);
        if (root_index != SIZE_MAX)
        {
            const ManifestRoot *root = &collection->manifest->roots[root_index];
            relative_path_prefix_match(root->payload_path, path, relative_out);
            return root_index;
        }
        const char *slash = memrchr(path, '/', length);
        if (slash == NULL)
            return SIZE_MAX;
        length = (size_t)(slash - path);
    }
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

static PreflightEntry *find_physical(const EntryOrders *orders,
                                     size_t root_index, const char *physical)
{
    size_t left = 0;
    size_t right = orders->count;
    while (left < right)
    {
        size_t middle = left + (right - left) / 2U;
        PreflightEntry *entry = orders->physical[middle];
        int comparison;
        if (entry->root_index < root_index)
            comparison = -1;
        else if (entry->root_index > root_index)
            comparison = 1;
        else
            comparison = strcmp(entry->physical, physical);
        if (comparison < 0)
            left = middle + 1U;
        else
            right = middle;
    }
    if (left == orders->count)
        return NULL;
    PreflightEntry *entry = orders->physical[left];
    return entry->root_index == root_index &&
           strcmp(entry->physical, physical) == 0 ? entry : NULL;
}

static int mark_payload_node(PayloadInventory *inventory, size_t root_index,
                             const char *physical, const struct stat *st)
{
    PreflightEntry *entry = find_physical(inventory->orders, root_index,
                                          physical);
    if (entry == NULL)
    {
        report_violation(inventory->collection->report, root_index, physical);
        return -1;
    }
    size_t entry_index = (size_t)(entry - inventory->entries->items);
    if (inventory->seen[entry_index] != 0)
    {
        report_violation(inventory->collection->report, root_index, physical);
        return -1;
    }
    int is_directory = S_ISDIR(st->st_mode);
    if ((entry->kind == SIDECAR_KIND_DIRECTORY) != is_directory ||
        (entry->kind == SIDECAR_KIND_REGULAR &&
         (st->st_size < 0 || (uintmax_t)st->st_size != entry->size)))
    {
        report_violation(inventory->collection->report, root_index, physical);
        return -1;
    }
    inventory->seen[entry_index] = 1;
    return 0;
}

static int scan_payload_directory(PayloadInventory *inventory, int directory_fd,
                                   size_t path_length);

static int scan_payload_node(PayloadInventory *inventory, int parent_fd,
                             const char *name, size_t path_length)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    const char *physical = NULL;
    size_t root_index = root_for_payload_path(inventory->collection,
                                               inventory->path, &physical);
    if (root_index == SIZE_MAX)
    {
        if (!root_has_descendant(inventory->collection, inventory->path))
        {
            report_violation(inventory->collection->report, SIZE_MAX,
                             inventory->path);
            return -1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            report_violation(inventory->collection->report, SIZE_MAX,
                             inventory->path);
            return -1;
        }
    }
    else
    {
        if (S_ISLNK(st.st_mode) ||
            (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)))
        {
            report_violation(inventory->collection->report, root_index,
                             physical);
            return -1;
        }
        if (mark_payload_node(inventory, root_index, physical, &st) != 0)
            return -1;
    }
    if (!S_ISDIR(st.st_mode))
        return 0;

    int child_fd = openat(parent_fd, name,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
    if (child_fd < 0)
        return -1;
    int result = scan_payload_directory(inventory, child_fd, path_length);
    int saved = errno;
    if (close(child_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

static int scan_payload_directory(PayloadInventory *inventory, int directory_fd,
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
            inventory->path[child_length++] = '/';
        memcpy(inventory->path + child_length, entry->d_name,
               name_length + 1U);
        if (scan_payload_node(inventory, directory_fd, entry->d_name,
                              child_length + name_length) != 0)
        {
            result = -1;
            break;
        }
        inventory->path[path_length] = '\0';
    }
    if (closedir(directory) != 0)
        result = -1;
    return result;
}

static int scan_payload_inventory(PayloadInventory *inventory)
{
    if (inventory == NULL || inventory->data_fd < 0)
        return -1;
    if (scan_payload_directory(inventory, inventory->data_fd, 0) != 0)
        return -1;
    for (size_t index = 0; index < inventory->entries->count; index++)
        if (inventory->seen[index] == 0)
        {
            report_violation(inventory->collection->report,
                             inventory->entries->items[index].root_index,
                             inventory->entries->items[index].physical);
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

static void collection_free(Collection *collection, PreflightEntries *entries,
                            EntryOrders *orders)
{
    if (collection == NULL)
        return;
    entry_orders_free(&collection->memory, orders);
    entries_free(&collection->memory, entries);
    preflight_free(&collection->memory, collection->root_order,
                   collection->report == NULL ? 0
                       : collection->report->root_count * sizeof(size_t));
    collection->root_order = NULL;
    parent_map_free(&collection->memory, &collection->parent_map);
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
    EntryOrders orders = {0};
    Collection collection = {
        .manifest = request->manifest,
        .report = report,
        .entries = &entries,
        .destination_home_fd = request->destination_home_fd,
        .destination_xdg_dirs = request->destination_xdg_dirs
    };
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

    if (parent_map_build(&collection.parent_map, &collection.memory,
                         &sidecar) != 0)
    {
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
    for (size_t index = 0; index < report->root_count; index++)
        if (report->roots[index].live_count == 0)
        {
            report_violation(report, index, report->roots[index].id);
        }
        else
            report->mapped_root_count++;
    if (analyze_entries(&collection.memory, &entries, &orders, report) != 0)
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

    unsigned char *seen = calloc(entries.count == 0 ? 1 : entries.count, 1);
    if (seen == NULL)
    {
        sidecar_log_close(&sidecar);
        close(data_fd);
        goto fail;
    }
    PayloadInventory inventory = {
        .data_fd = data_fd,
        .collection = &collection,
        .entries = &entries,
        .orders = &orders,
        .seen = seen
    };
    int result = scan_payload_inventory(&inventory);
    free(seen);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (close(data_fd) != 0)
        result = -1;
    if (result != 0)
        goto fail;
    collection_free(&collection, &entries, &orders);
    return report->violation_count == 0 ? 0 : (report_print(report), -1);

fail:
    collection_free(&collection, &entries, &orders);
    if (report->violation_count == 0)
        report_violation(report, SIZE_MAX, "preflight");
    report_print(report);
    return -1;
}
