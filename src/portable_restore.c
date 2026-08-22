#define _GNU_SOURCE

#include "portable_restore.h"

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

#include "encoding.h"
#include "fsprobe.h"
#include "hash.h"
#include "sidecar.h"
#include "utils.h"

typedef struct {
    uint64_t bytes;
} PreflightMemory;

typedef struct {
    size_t index;
    int used;
} RootMapSlot;

typedef struct {
    RootMapSlot *slots;
    size_t capacity;
} RootMap;

typedef struct {
    SidecarBytes root_id;
    SidecarBytes logical_path;
    SidecarBytes physical_path;
    int used;
} ParentMapSlot;

typedef struct {
    ParentMapSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} ParentMap;

typedef struct {
    size_t root_index;
    char *logical;
    char *physical;
    SidecarObjectKind kind;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint32_t xattr_count;
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
    MetadataXattrRequirements xattr_requirements;
} ReplayCollection;

static int xdg_destination_valid(const char * const *xdg_dirs,
                                 const ManifestRoot *root);

static void *preflight_alloc(PreflightMemory *memory, size_t size)
{
    if (memory == NULL || size == 0 ||
        (uint64_t)size > SIDECAR_MAX_ALLOC_BUDGET -
            (memory->bytes > SIDECAR_MAX_ALLOC_BUDGET
                 ? SIDECAR_MAX_ALLOC_BUDGET : memory->bytes))
    {
        errno = E2BIG;
        return NULL;
    }
    void *result = malloc(size);
    if (result == NULL)
        return NULL;
    memory->bytes += (uint64_t)size;
    return result;
}

static void *preflight_realloc(PreflightMemory *memory, void *pointer,
                               size_t old_size, size_t new_size)
{
    if (memory == NULL || new_size == 0 || old_size > new_size ||
        (uint64_t)(new_size - old_size) > SIDECAR_MAX_ALLOC_BUDGET -
            (memory->bytes > SIDECAR_MAX_ALLOC_BUDGET
                 ? SIDECAR_MAX_ALLOC_BUDGET : memory->bytes))
    {
        errno = E2BIG;
        return NULL;
    }
    void *result = realloc(pointer, new_size);
    if (result == NULL)
        return NULL;
    memory->bytes += (uint64_t)(new_size - old_size);
    return result;
}

static void preflight_free(PreflightMemory *memory, void *pointer,
                           size_t size)
{
    if (pointer == NULL)
        return;
    if (memory != NULL && (uint64_t)size <= memory->bytes)
        memory->bytes -= (uint64_t)size;
    free(pointer);
}

static uint64_t fnv1a_text(const char *text)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t index = 0; text[index] != '\0'; index++)
    {
        hash ^= (unsigned char)text[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t parent_map_hash(const ParentMap *map,
                                SidecarBytes root_id,
                                SidecarBytes logical_path)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ map->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)root_id.length);
    hash = hash_fnv1a_bytes(hash, root_id.data, root_id.length);
    hash = hash_fnv1a_uint64(hash, (uint64_t)logical_path.length);
    return hash_fnv1a_bytes(hash, logical_path.data, logical_path.length);
}

static int parent_map_find(const ParentMap *map, SidecarBytes root_id,
                           SidecarBytes logical_path,
                           SidecarBytes *physical_out);

static int text_component_valid(const char *component, size_t length)
{
    return component != NULL && length != 0 && length <= NAME_MAX &&
           !(length == 1 && component[0] == '.') &&
           !(length == 2 && component[0] == '.' && component[1] == '.') &&
           memchr(component, '\0', length) == NULL;
}

static int relative_path_valid(const char *path, int allow_empty)
{
    if (path == NULL)
        return 0;
    size_t length = strnlen(path, PATH_MAX + 1U);
    if (length >= PATH_MAX)
        return 0;
    if (length == 0)
        return allow_empty;
    if (path[0] == '/' || path[length - 1U] == '/')
        return 0;

    size_t component_start = 0;
    for (size_t index = 0; index <= length; index++)
    {
        if (index != length && path[index] != '/')
            continue;
        if (!text_component_valid(path + component_start,
                                  index - component_start))
            return 0;
        component_start = index + 1U;
    }
    return 1;
}

static int manifest_text_valid(const char *text, size_t capacity, int nonempty)
{
    if (text == NULL || capacity == 0)
        return 0;
    size_t length = strnlen(text, capacity);
    return length < capacity && (!nonempty || length != 0);
}

static int sidecar_path_valid(SidecarBytes bytes, int allow_empty)
{
    if (bytes.length >= PATH_MAX ||
        (bytes.length != 0 && bytes.data == NULL) ||
        (bytes.length != 0 && memchr(bytes.data, '\0', bytes.length) != NULL))
        return 0;
    if (bytes.length == 0)
        return allow_empty;
    if (bytes.data[0] == '/' || bytes.data[bytes.length - 1U] == '/')
        return 0;

    size_t component_start = 0;
    for (size_t index = 0; index <= bytes.length; index++)
    {
        if (index != bytes.length && bytes.data[index] != '/')
            continue;
        if (!text_component_valid(
                (const char *)bytes.data + component_start,
                index - component_start))
            return 0;
        component_start = index + 1U;
    }
    return 1;
}

static int collision_suffix_valid(SidecarBytes suffix)
{
    if (suffix.length == 0)
        return 1;
    if (suffix.data == NULL || suffix.length < 4U ||
        suffix.length > SIDECAR_MAX_COLLISION_SUFFIX ||
        suffix.data[0] != '%' || suffix.data[1] != '7' ||
        suffix.data[2] != 'E' || suffix.data[3] < '1' ||
        suffix.data[3] > '9')
        return 0;

    uint64_t value = (uint64_t)(suffix.data[3] - '0');
    for (size_t index = 4U; index < suffix.length; index++)
    {
        if (suffix.data[index] < '0' || suffix.data[index] > '9' ||
            value > (UINT64_MAX - (uint64_t)(suffix.data[index] - '0')) /
                UINT64_C(10))
            return 0;
        value = value * UINT64_C(10) +
                (uint64_t)(suffix.data[index] - '0');
    }
    return value != 0;
}

static int physical_matches_logical_with_suffix(
    SidecarBytes logical, SidecarBytes physical, SidecarBytes suffix)
{
    size_t logical_index = 0;
    size_t physical_index = 0;

    for (;;) {
        if (logical_index == logical.length ||
            physical_index == physical.length)
            return logical_index == logical.length &&
                   physical_index == physical.length;

        size_t logical_start = logical_index;
        while (logical_index < logical.length &&
               logical.data[logical_index] != '/')
            logical_index++;
        size_t logical_component_length = logical_index - logical_start;

        size_t physical_start = physical_index;
        while (physical_index < physical.length &&
               physical.data[physical_index] != '/')
            physical_index++;
        size_t physical_component_length = physical_index - physical_start;

        if (logical_component_length == 0 ||
            logical_component_length > NAME_MAX ||
            physical_component_length == 0 ||
            physical_component_length > NAME_MAX)
            return 0;

        char raw[NAME_MAX + 1U];
        memcpy(raw, logical.data + logical_start, logical_component_length);
        raw[logical_component_length] = '\0';

        char encoded[NAME_MAX + 1U];
        if (encoding_percent_encode(ENCODING_MODE_COMPONENT, raw, encoded,
                                    sizeof(encoded)) != 0)
            return 0;

        size_t encoded_length = strlen(encoded);
        int last_component = logical_index == logical.length;
        if (last_component && suffix.length > NAME_MAX - encoded_length)
            return 0;
        size_t expected_length = encoded_length +
                                 (last_component ? suffix.length : 0U);
        if (physical_component_length != expected_length ||
            memcmp(physical.data + physical_start, encoded,
                   encoded_length) != 0 ||
            (last_component && suffix.length != 0 &&
             memcmp(physical.data + physical_start + encoded_length,
                    suffix.data, suffix.length) != 0))
            return 0;

        if (logical_index < logical.length)
            logical_index++;
        if (physical_index < physical.length)
            physical_index++;
    }
}

/*
 * True only when physical is the per-component
 * ENCODING_MODE_COMPONENT encoding of logical, joined with '/'.
 * Callers validate both paths with sidecar_path_valid() first.
 * docs/DECISIONS.md D21 (F-2b/F-3) defines the suffix-aware leaf form and
 * the parent-prefix relationship used by the restore gates below.
 */
int physical_matches_logical(SidecarBytes logical, SidecarBytes physical)
{
    return physical_matches_logical_with_suffix(logical, physical,
                                                 (SidecarBytes){0});
}

static int entry_physical_matches_parent(const ManifestRoot *root,
                                         const ParentMap *parent_map,
                                         const SidecarEntry *entry)
{
    if (root == NULL || parent_map == NULL || entry == NULL ||
        !collision_suffix_valid(entry->collision_suffix) ||
        !sidecar_path_valid(entry->logical_path, 1) ||
        !sidecar_path_valid(entry->physical_path, 1) ||
        root->payload_path[0] == '\0')
        return 0;

    if (entry->logical_path.length == 0)
        return entry->collision_suffix.length == 0 &&
               entry->physical_path.length == 0;

    size_t logical_leaf_start = 0;
    for (size_t index = entry->logical_path.length; index > 0; index--)
        if (entry->logical_path.data[index - 1U] == '/')
        {
            logical_leaf_start = index;
            break;
        }

    SidecarBytes logical_parent = {
        .data = entry->logical_path.data,
        .length = logical_leaf_start == 0 ? 0 : logical_leaf_start - 1U
    };
    SidecarBytes logical_leaf = {
        .data = entry->logical_path.data + logical_leaf_start,
        .length = entry->logical_path.length - logical_leaf_start
    };
    SidecarBytes physical_leaf = entry->physical_path;

    if (logical_parent.length != 0)
    {
        SidecarBytes parent_physical = {0};
        int found = parent_map_find(parent_map, entry->root_id,
                                    logical_parent, &parent_physical);
        if (found != 1 || parent_physical.length == 0 ||
            parent_physical.data == NULL ||
            parent_physical.length >= entry->physical_path.length ||
            entry->physical_path.data == NULL ||
            memcmp(entry->physical_path.data, parent_physical.data,
                   parent_physical.length) != 0 ||
            entry->physical_path.data[parent_physical.length] != '/')
            return 0;
        physical_leaf.data = entry->physical_path.data +
                             parent_physical.length + 1U;
        physical_leaf.length = entry->physical_path.length -
                               parent_physical.length - 1U;
    }

    return physical_matches_logical_with_suffix(logical_leaf, physical_leaf,
                                                 entry->collision_suffix);
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

static int root_id_equal(const ManifestRoot *root, SidecarBytes id)
{
    size_t length = strlen(root->id);
    return length == id.length &&
           (length == 0 || memcmp(root->id, id.data, length) == 0);
}

static int root_map_build(RootMap *map, const Manifest *manifest)
{
    if (map == NULL || manifest == NULL || manifest->root_count < 0 ||
        manifest->root_count > MANIFEST_MAX_ROOTS ||
        (manifest->root_count != 0 && manifest->roots == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    memset(map, 0, sizeof(*map));
    size_t capacity = 16U;
    while (capacity < (size_t)manifest->root_count * 2U)
    {
        if (capacity > SIZE_MAX / 2U)
        {
            errno = E2BIG;
            return -1;
        }
        capacity *= 2U;
    }
    map->slots = calloc(capacity, sizeof(*map->slots));
    if (map->slots == NULL)
        return -1;
    map->capacity = capacity;

    for (int root_index = 0; root_index < manifest->root_count; root_index++)
    {
        const ManifestRoot *root = &manifest->roots[root_index];
        size_t index = (size_t)fnv1a_text(root->id) & (capacity - 1U);
        while (map->slots[index].used)
        {
            if (strcmp(manifest->roots[map->slots[index].index].id,
                       root->id) == 0)
            {
                errno = EINVAL;
                free(map->slots);
                memset(map, 0, sizeof(*map));
                return -1;
            }
            index = (index + 1U) & (capacity - 1U);
        }
        map->slots[index].used = 1;
        map->slots[index].index = (size_t)root_index;
    }
    return 0;
}

static void root_map_free(RootMap *map)
{
    if (map == NULL)
        return;
    free(map->slots);
    memset(map, 0, sizeof(*map));
}

static size_t root_map_find(const RootMap *map, const Manifest *manifest,
                            SidecarBytes id)
{
    if (map == NULL || manifest == NULL || map->capacity == 0 ||
        id.length == 0 || id.data == NULL)
        return SIZE_MAX;
    uint64_t hash = hash_fnv1a_bytes(HASH_FNV1A_OFFSET_BASIS, id.data,
                                     id.length);
    size_t index = (size_t)hash & (map->capacity - 1U);
    for (size_t probes = 0; probes < map->capacity; probes++)
    {
        if (!map->slots[index].used)
            return SIZE_MAX;
        if (root_id_equal(&manifest->roots[map->slots[index].index], id))
            return map->slots[index].index;
        index = (index + 1U) & (map->capacity - 1U);
    }
    return SIZE_MAX;
}

static int parent_map_key_valid(SidecarBytes root_id,
                                SidecarBytes logical_path)
{
    return root_id.length <= SIDECAR_MAX_ROOT_ID && root_id.length != 0 &&
           root_id.data != NULL && logical_path.length <= SIDECAR_MAX_PATH &&
           (logical_path.length == 0 || logical_path.data != NULL);
}

static int parent_map_find(const ParentMap *map, SidecarBytes root_id,
                           SidecarBytes logical_path,
                           SidecarBytes *physical_out)
{
    if (physical_out == NULL || !parent_map_key_valid(root_id, logical_path))
    {
        errno = EINVAL;
        return -1;
    }
    *physical_out = (SidecarBytes){0};
    if (map == NULL || map->capacity == 0 || map->slots == NULL)
        return 0;

    size_t index = (size_t)parent_map_hash(map, root_id, logical_path) &
                   (map->capacity - 1U);
    for (size_t probes = 0; probes < map->capacity; probes++)
    {
        const ParentMapSlot *slot = &map->slots[index];
        if (!slot->used)
            return 0;
        if (slot->root_id.length == root_id.length &&
            slot->logical_path.length == logical_path.length &&
            (root_id.length == 0 ||
             memcmp(slot->root_id.data, root_id.data, root_id.length) == 0) &&
            (logical_path.length == 0 ||
             memcmp(slot->logical_path.data, logical_path.data,
                    logical_path.length) == 0))
        {
            *physical_out = slot->physical_path;
            return 1;
        }
        index = (index + 1U) & (map->capacity - 1U);
    }
    return 0;
}

static int parent_map_init(ParentMap *map, PreflightMemory *memory,
                           size_t expected)
{
    if (map == NULL || memory == NULL || expected > SIDECAR_MAX_LIVE_ENTRIES)
    {
        errno = E2BIG;
        return -1;
    }
    memset(map, 0, sizeof(*map));
    map->hash_salt = sidecar_process_salt();
    if (expected > SIZE_MAX / 2U)
    {
        errno = E2BIG;
        return -1;
    }
    size_t minimum = expected * 2U;
    size_t capacity = 16U;
    while (capacity < minimum)
    {
        if (capacity > SIZE_MAX / 2U)
        {
            errno = E2BIG;
            return -1;
        }
        capacity *= 2U;
    }
    if (capacity > SIZE_MAX / sizeof(*map->slots))
    {
        errno = E2BIG;
        return -1;
    }
    size_t size = capacity * sizeof(*map->slots);
    map->slots = preflight_alloc(memory, size);
    if (map->slots == NULL)
        return -1;
    memset(map->slots, 0, size);
    map->capacity = capacity;
    return 0;
}

static void parent_map_free(PreflightMemory *memory, ParentMap *map)
{
    if (map == NULL)
        return;
    preflight_free(memory, map->slots,
                   map->capacity * sizeof(*map->slots));
    memset(map, 0, sizeof(*map));
}

static int parent_map_insert(ParentMap *map, SidecarBytes root_id,
                             SidecarBytes logical_path,
                             SidecarBytes physical_path)
{
    SidecarBytes existing = {0};
    int found = parent_map_find(map, root_id, logical_path, &existing);
    if (found != 0)
    {
        errno = found < 0 ? errno : EINVAL;
        return -1;
    }
    if (!parent_map_key_valid(root_id, logical_path) ||
        physical_path.length > SIDECAR_MAX_PATH ||
        (physical_path.length != 0 && physical_path.data == NULL) ||
        map == NULL || map->slots == NULL || map->capacity == 0 ||
        map->count >= map->capacity)
    {
        errno = E2BIG;
        return -1;
    }

    size_t index = (size_t)parent_map_hash(map, root_id, logical_path) &
                   (map->capacity - 1U);
    for (size_t probes = 0; probes < map->capacity; probes++)
    {
        ParentMapSlot *slot = &map->slots[index];
        if (!slot->used)
        {
            slot->root_id = root_id;
            slot->logical_path = logical_path;
            slot->physical_path = physical_path;
            slot->used = 1;
            map->count++;
            return 0;
        }
        index = (index + 1U) & (map->capacity - 1U);
    }
    errno = E2BIG;
    return -1;
}

static int parent_map_collect(const SidecarLiveView *view, void *argument)
{
    ParentMap *map = argument;
    if (map == NULL || view == NULL || view->entry == NULL)
    {
        errno = EINVAL;
        return 1;
    }
    return parent_map_insert(map, view->entry->root_id,
                             view->entry->logical_path,
                             view->entry->physical_path) == 0 ? 0 : 1;
}

static int parent_map_build(ParentMap *map, PreflightMemory *memory,
                            SidecarLog *sidecar)
{
    if (map == NULL || memory == NULL || sidecar == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    size_t live_count = sidecar_log_live_count(sidecar);
    if (parent_map_init(map, memory, live_count) != 0)
        return -1;
    SidecarStatus status = sidecar_log_foreach(sidecar, parent_map_collect,
                                               map);
    if (status != SIDECAR_STATUS_OK)
    {
        int saved = errno;
        parent_map_free(memory, map);
        errno = saved == 0 ? EIO : saved;
        return -1;
    }
    return 0;
}

static int root_order_compare(const void *left, const void *right,
                              void *argument)
{
    const Manifest *manifest = argument;
    size_t a = *(const size_t *)left;
    size_t b = *(const size_t *)right;
    return strcmp(manifest->roots[a].payload_path,
                  manifest->roots[b].payload_path);
}

static const Manifest *root_order_manifest;

static int root_order_compare_global(const void *left, const void *right)
{
    return root_order_compare(left, right, (void *)root_order_manifest);
}

static int payload_paths_disjoint(const Manifest *manifest, size_t left,
                                  size_t right)
{
    const char *a = manifest->roots[left].payload_path;
    const char *b = manifest->roots[right].payload_path;
    size_t a_length = strlen(a);
    size_t b_length = strlen(b);
    if (a_length == b_length && strcmp(a, b) == 0)
        return 0;
    if (a_length < b_length && strncmp(a, b, a_length) == 0 &&
        b[a_length] == '/')
        return 0;
    if (b_length < a_length && strncmp(b, a, b_length) == 0 &&
        a[b_length] == '/')
        return 0;
    return 1;
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
        root_order_manifest = manifest;
        qsort(collection->root_order, report->root_count,
              sizeof(*collection->root_order), root_order_compare_global);
        root_order_manifest = NULL;
        for (size_t index = 1; index < report->root_count; index++)
            if (!payload_paths_disjoint(manifest,
                                        collection->root_order[index - 1U],
                                        collection->root_order[index]))
                report_violation(report,
                                 collection->root_order[index],
                                 manifest->roots[collection->root_order[index]].id);
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

static int xdg_key_index(const char *id)
{
    if (id == NULL)
        return -1;
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        if (strcmp(id, xdg_keys[index]) == 0)
            return index;
    return -1;
}

static int xdg_destination_valid(const char * const *xdg_dirs,
                                 const ManifestRoot *root)
{
    if (root == NULL || xdg_dirs == NULL)
        return 0;
    int index = xdg_key_index(root->id);
    if (index < 0 || xdg_dirs[index] == NULL ||
        xdg_dirs[index][0] != '/')
        return 0;
    return strnlen(xdg_dirs[index], PATH_MAX) < PATH_MAX;
}

static int destination_path_build(const ManifestRoot *root,
                                  const char *logical,
                                  const char * const *xdg_dirs,
                                  char *out, size_t out_size)
{
    if (root == NULL || logical == NULL || out == NULL || out_size == 0)
        return -1;

    if (root->policy == ROOT_POLICY_XDG)
    {
        if (!xdg_destination_valid(xdg_dirs, root))
            return -1;
        const char *xdg = xdg_dirs[xdg_key_index(root->id)];
        if (logical[0] == '\0')
        {
            int length = snprintf(out, out_size, "%s", xdg);
            return length >= 0 && (size_t)length < out_size ? 0 : -1;
        }
        int length = snprintf(out, out_size, "%s/%s", xdg, logical);
        return length >= 0 && (size_t)length < out_size ? 0 : -1;
    }

    const char *restore = root->restore_path;
    if (!root->has_restore_path)
        restore = "";
    if (restore[0] == '\0')
        return snprintf(out, out_size, "%s", logical) >= 0 &&
               strlen(logical) < out_size ? 0 : -1;
    if (logical[0] == '\0')
        return snprintf(out, out_size, "%s", restore) >= 0 &&
               strlen(restore) < out_size ? 0 : -1;
    int length = snprintf(out, out_size, "%s/%s", restore, logical);
    return length >= 0 && (size_t)length < out_size ? 0 : -1;
}

static int destination_relative_path_build(const char *prefix,
                                           const char *logical,
                                           char *out, size_t out_size)
{
    if (prefix == NULL || logical == NULL || out == NULL || out_size == 0)
        return -1;
    if (prefix[0] == '\0')
        return snprintf(out, out_size, "%s", logical) >= 0 &&
               strlen(logical) < out_size ? 0 : -1;
    if (logical[0] == '\0')
        return snprintf(out, out_size, "%s", prefix) >= 0 &&
               strlen(prefix) < out_size ? 0 : -1;
    int length = snprintf(out, out_size, "%s/%s", prefix, logical);
    return length >= 0 && (size_t)length < out_size ? 0 : -1;
}

static int duplicate_noatime_directory(int fd)
{
    int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    return duplicate;
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
    int current = duplicate_noatime_directory(home_fd);
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
static int open_xdg_destination_anchor(const char *path, int *out_fd,
                                       char *out_rel, size_t rel_size)
{
    if (path == NULL || out_fd == NULL || out_rel == NULL || rel_size == 0 ||
        path[0] != '/' || strnlen(path, PATH_MAX) >= PATH_MAX)
    {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0)
    {
        *out_fd = fd;
        out_rel[0] = '\0';
        return 0;
    }
    if (errno != ENOENT)
        return -1;

    char copy[PATH_MAX];
    size_t length = strlen(path);
    memcpy(copy, path, length + 1U);
    while (length > 1U && copy[length - 1U] == '/')
        copy[--length] = '\0';

    char *slash = strrchr(copy, '/');
    const char *leaf = slash == NULL ? copy : slash + 1U;
    size_t leaf_length = strlen(leaf);
    if (leaf_length == 0 || leaf_length >= rel_size)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out_rel, leaf, leaf_length + 1U);

    const char *parent;
    if (slash == NULL)
        parent = ".";
    else if (slash == copy)
    {
        slash[1] = '\0';
        parent = copy;
    }
    else
    {
        *slash = '\0';
        parent = copy;
    }

    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    *out_fd = fd;
    return 0;
}

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

static int collect_metadata_profile(const Collection *collection,
                                    const ManifestRoot *root,
                                    size_t root_index,
                                    const PreflightEntry *entry)
{
    if (collection == NULL || root == NULL || entry == NULL ||
        collection->report == NULL)
        return -1;

    struct stat desired;
    memset(&desired, 0, sizeof(desired));
    desired.st_uid = (uid_t)entry->uid;
    desired.st_gid = (gid_t)entry->gid;
    if ((uintmax_t)desired.st_uid != entry->uid ||
        (uintmax_t)desired.st_gid != entry->gid)
    {
        errno = E2BIG;
        return -1;
    }
    mode_t type = S_IFREG;
    if (entry->kind == SIDECAR_KIND_SYMLINK)
        type = S_IFLNK;
    else if (entry->kind == SIDECAR_KIND_DIRECTORY)
        type = S_IFDIR;
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
        anchor = duplicate_noatime_directory(
            collection->destination_home_fd);
        if (anchor < 0)
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
    if (entry->kind != SIDECAR_KIND_REGULAR && entry->size != 0)
    {
        report_violation(report, root_index, "invalid-size");
        return 0;
    }

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
    destination->xattr_count = entry->xattr_count;
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
                                 root_index, destination) != 0)
        return 1;
    return 0;
}

static int path_is_ancestor(const char *parent, const char *child)
{
    size_t parent_length = strlen(parent);
    size_t child_length = strlen(child);
    return parent_length < child_length &&
           strncmp(parent, child, parent_length) == 0 &&
           child[parent_length] == '/';
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
        if (previous->root_index != current->root_index)
            continue;
        if (strcmp(previous->logical, current->logical) == 0 ||
            (previous->kind != SIDECAR_KIND_DIRECTORY &&
             path_is_ancestor(previous->logical, current->logical)))
            report_violation(report, current->root_index, current->logical);
    }
    for (size_t index = 1; index < orders->count; index++)
    {
        PreflightEntry *previous = orders->physical[index - 1U];
        PreflightEntry *current = orders->physical[index];
        if (previous->root_index != current->root_index)
            continue;
        if (strcmp(previous->physical, current->physical) == 0)
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
        else if (previous->kind != SIDECAR_KIND_DIRECTORY &&
                 path_is_ancestor(previous->physical, current->physical))
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

static int root_path_prefix(const char *root_path, const char *path,
                            const char **relative_out)
{
    size_t root_length = strlen(root_path);
    if (strcmp(root_path, path) == 0)
    {
        *relative_out = path + root_length;
        return 1;
    }
    if (strncmp(root_path, path, root_length) == 0 &&
        path[root_length] == '/')
    {
        *relative_out = path + root_length + 1U;
        return 1;
    }
    return 0;
}

static size_t root_for_payload_path(const Collection *collection,
                                    const char *path,
                                    const char **relative_out)
{
    if (collection->report->root_count == 0)
        return SIZE_MAX;
    size_t position = root_order_lower_bound(collection, path);
    if (position < collection->report->root_count &&
        strcmp(collection->manifest->roots[
                   collection->root_order[position]].payload_path, path) == 0)
    {
        const ManifestRoot *root = &collection->manifest->roots[
            collection->root_order[position]];
        root_path_prefix(root->payload_path, path, relative_out);
        return collection->root_order[position];
    }
    if (position == 0)
        return SIZE_MAX;
    position--;
    const ManifestRoot *root = &collection->manifest->roots[
        collection->root_order[position]];
    if (root_path_prefix(root->payload_path, path, relative_out))
        return collection->root_order[position];
    return SIZE_MAX;
}

static int root_has_descendant(const Collection *collection, const char *path)
{
    if (collection->report->root_count == 0)
        return 0;
    size_t position = root_order_lower_bound(collection, path);
    if (position == collection->report->root_count)
        return 0;
    const char *candidate = collection->manifest->roots[
        collection->root_order[position]].payload_path;
    size_t length = strlen(path);
    return (length == 0 ||
            (strncmp(candidate, path, length) == 0 &&
             candidate[length] == '/'));
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
    int scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
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

static int sidecar_is_complete_readonly(int container_fd)
{
    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOATIME |
                        O_CLOEXEC);
    if (fd < 0)
        return -1;

    SidecarParseResult parse;
    SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &parse);
    int saved = errno;
    if (close(fd) != 0 && status == SIDECAR_STATUS_OK)
    {
        status = SIDECAR_STATUS_IO_ERROR;
        saved = EIO;
    }
    errno = saved;
    return status == SIDECAR_STATUS_OK ? 0 : -1;
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

static void replay_copy_bytes(char *destination, size_t destination_size,
                              SidecarBytes source)
{
    if (destination == NULL || destination_size == 0)
        return;
    size_t length = source.length < destination_size - 1U
        ? source.length : destination_size - 1U;
    if (length != 0 && source.data != NULL)
        memcpy(destination, source.data, length);
    destination[length] = '\0';
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
        (entry->kind != SIDECAR_KIND_REGULAR && entry->size != 0))
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
    mode_t type = S_IFREG;
    if (entry->kind == SIDECAR_KIND_SYMLINK)
        type = S_IFLNK;
    else if (entry->kind == SIDECAR_KIND_DIRECTORY)
        type = S_IFDIR;
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

static size_t replay_path_depth(const char *path)
{
    if (path == NULL || path[0] == '\0')
        return 0;
    size_t depth = 1;
    for (const char *cursor = path; *cursor != '\0'; cursor++)
        if (*cursor == '/')
            depth++;
    return depth;
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
    char hardlink_ref_destination[PATH_MAX] = {0};
    char hardlink_ref_relative[PATH_MAX] = {0};
    if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        SidecarLiveView referenced;
        if (collection->sidecar == NULL ||
            !sidecar_log_find(collection->sidecar,
                              entry->hardlink_root_id,
                              entry->hardlink_logical_path, &referenced) ||
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
        if (destination_path_build(
                &collection->manifest->roots[hardlink_ref_root_index],
                reference_logical, collection->destination_xdg_dirs,
                hardlink_ref_destination,
                sizeof(hardlink_ref_destination)) != 0)
        {
            replay_report_failure(collection->report, collection->manifest,
                                  root_index, entry->logical_path);
            return 1;
        }
        if (collection->manifest->roots[hardlink_ref_root_index].policy ==
                ROOT_POLICY_XDG)
        {
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
        unsigned int *kind_namespaces =
            entry->kind == SIDECAR_KIND_REGULAR
                ? &collection->xattr_requirements.regular_namespaces
                : entry->kind == SIDECAR_KIND_DIRECTORY
                    ? &collection->xattr_requirements.directory_namespaces
                    : entry->kind == SIDECAR_KIND_SYMLINK
                        ? &collection->xattr_requirements.symlink_namespaces
                        : NULL;
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
    replay->depth = replay_path_depth(replay->destination);
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
    if (root_length == 0 || root_length >= out_size ||
        physical.length > out_size - root_length - 1U)
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
    int current = duplicate_noatime_directory(base_fd);
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

static int replay_ensure_parent_directory(int parent_fd, const char *name,
                                           int *out_fd)
{
    if (parent_fd < 0 || name == NULL || !text_component_valid(
            name, strlen(name)) || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            errno = ENOTDIR;
            return -1;
        }
        *out_fd = openat(parent_fd, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        return *out_fd < 0 ? -1 : 0;
    }
    if (errno != ENOENT)
        return -1;
    if (mkdirat(parent_fd, name, 0700) != 0 && errno != EEXIST)
        return -1;
    *out_fd = openat(parent_fd, name,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return *out_fd < 0 ? -1 : 0;
}

static int replay_open_destination_parent(int home_fd, const char *path,
                                           int *parent_out, char *leaf,
                                           size_t leaf_size)
{
    if (home_fd < 0 || path == NULL || parent_out == NULL || leaf == NULL ||
        leaf_size == 0 || !relative_path_valid(path, 1))
    {
        errno = EINVAL;
        return -1;
    }
    int current = duplicate_noatime_directory(home_fd);
    if (current < 0)
        return -1;
    if (path[0] == '\0')
    {
        leaf[0] = '\0';
        *parent_out = current;
        return 0;
    }

    char copy[PATH_MAX];
    memcpy(copy, path, strlen(path) + 1U);
    char *cursor = copy;
    for (;;)
    {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL)
        {
            size_t length = strlen(cursor);
            if (length == 0 || length >= leaf_size)
            {
                int saved = EINVAL;
                close(current);
                errno = saved;
                return -1;
            }
            memcpy(leaf, cursor, length + 1U);
            *parent_out = current;
            return 0;
        }

        int next = -1;
        if (replay_ensure_parent_directory(current, cursor, &next) != 0)
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
    }
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
        *out_fd = duplicate_noatime_directory(parent_fd);
        return *out_fd < 0 ? -1 : 0;
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

static int replay_copy_regular(int source_fd, int destination_fd,
                               uint64_t expected_size)
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
    for (;;)
    {
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
        copied += (uint64_t)received;
        size_t offset = 0;
        while (offset < (size_t)received)
        {
            ssize_t written = write(destination_fd, buffer + offset,
                                     (size_t)received - offset);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0)
                return -1;
            offset += (size_t)written;
        }
    }
    if (copied != expected_size)
    {
        errno = EIO;
        return -1;
    }
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
        return replay_open_destination_parent(
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

    int result = replay_open_destination_parent(
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
    if (result == 0)
        result = replay_copy_regular(source_fd, destination_fd, entry->size);
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
    if (result == 0 && linkat(ref_parent_fd, ref_leaf, parent_fd, leaf, 0) != 0)
        result = -1;
    if (result == 0)
    {
        struct stat linked;
        struct stat reference_after;
        if (fstatat(parent_fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
            fstatat(ref_parent_fd, ref_leaf, &reference_after,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !replay_hardlink_identity_matches(&linked, &reference_after))
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
            destination_fd = duplicate_noatime_directory(parent_fd);
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

static int replay_run(ReplayCollection *collection)
{
    if (collection == NULL || collection->report == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    qsort(collection->items, collection->count, sizeof(*collection->items),
          replay_entry_compare);

    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        int result;
        if (replay->entry->kind == SIDECAR_KIND_HARDLINK)
            continue;
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

static int replay_timestamp_policy(const PortableRestoreRequest *request,
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
        .report = report
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
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (close(collection.data_fd) != 0)
        result = -1;
    collection.data_fd = -1;
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

static void portable_restore_preview(
    const PortableRestorePreflightReport *report)
{
    if (report == NULL)
        return;
    printf("Portable restore dry run: %zu live entr%s would be applied\n",
           report->live_count, report->live_count == 1 ? "y" : "ies");
    if (report->profiles.security_xattr_entry_count != 0)
        printf("  %zu item(s) carry security.* attributes; whether they can "
               "be applied here is measured, not predicted, and is only "
               "found out on a live run\n",
               report->profiles.security_xattr_entry_count);
    for (size_t index = 0; index < report->root_count; index++)
        if (report->roots[index].live_count != 0)
            printf("  root %s: %zu live entr%s\n",
                   report->roots[index].id,
                   report->roots[index].live_count,
                   report->roots[index].live_count == 1 ? "y" : "ies");
}

static int portable_restore_confirm(size_t security_xattr_entries)
{
    const char *ordinary_message =
        "This will restore portable files to the destination. Continue?";
    if (security_xattr_entries == 0)
        return confirm_action(ordinary_message);

    char message[768];
    int length = snprintf(
        message, sizeof(message),
        "This restore includes %zu item(s) carrying security.* attributes "
        "(e.g. SELinux labels); if this destination or account cannot "
        "apply one, that item's other content and metadata will still be "
        "restored and only the attribute will be skipped. Continue?",
        security_xattr_entries);
    if (length < 0 || (size_t)length >= sizeof(message))
        return confirm_action(
            "This restore includes security.* attributes; an attribute "
            "that cannot be applied will be skipped while the item's other "
            "content and metadata are restored. Continue?");
    return confirm_action(message);
}

static PortableRestoreOutcome portable_restore_orchestrate_impl(
    const PortableRestoreRequest *request,
    PortableRestoreReplayReport *report,
    int measure_policy)
{
    if (request == NULL || report == NULL || request->source_container_fd < 0 ||
        request->destination_home_fd < 0 || request->manifest == NULL)
    {
        errno = EINVAL;
        return PORTABLE_RESTORE_ERROR;
    }

    portable_restore_replay_report_init(report);
    PortableRestoreRequest replay_request = *request;
    MetadataTimestampPolicy policy;
    if (!measure_policy && replay_timestamp_policy(request, &policy) != 0)
        return PORTABLE_RESTORE_ERROR;
    PortableRestorePreflightReport preflight;
    portable_restore_preflight_report_init(&preflight);
    int result = portable_restore_preflight_at(request, &preflight);
    if (result != 0)
    {
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_ERROR;
    }

    if (dry_run)
    {
        report->live_count = preflight.live_count;
        portable_restore_preview(&preflight);
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_DRY_RUN;
    }

    metadata_profiles_report(&preflight.profiles);
    if (!portable_restore_confirm(
            preflight.profiles.security_xattr_entry_count))
    {
        printf("Cancelled.\n");
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_CANCELLED;
    }

    if (measure_policy)
    {
        int nsec_exact = 0;
        if (fsprobe_timestamps_fd(request->destination_home_fd,
                                  &nsec_exact) != 0)
        {
            printf("Error: could not measure destination timestamp support; "
                   "no destination was changed\n");
            portable_restore_preflight_report_free(&preflight);
            return PORTABLE_RESTORE_ERROR;
        }
        policy = (MetadataTimestampPolicy){
            .nsec_exact = nsec_exact,
            .configured = 1
        };
        replay_request.destination_timestamp_policy = policy;
    }

    if (metadata_profiles_probe(&preflight.profiles, policy) != 0)
    {
        report->live_count = preflight.live_count;
        printf("Error: portable metadata probe failed; no destination was changed\n");
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_ERROR;
    }

    result = portable_restore_replay_at(&replay_request, report);
    if (result != 0)
        printf("Portable restore stopped: %zu applied, %zu failed\n",
               report->applied_count, report->failed_count);
    portable_restore_preflight_report_free(&preflight);
    return result == 0 ? PORTABLE_RESTORE_COMPLETE : PORTABLE_RESTORE_ERROR;
}

PortableRestoreOutcome portable_restore_orchestrate_at(
    const PortableRestoreRequest *request,
    PortableRestoreReplayReport *report)
{
    return portable_restore_orchestrate_impl(request, report, 1);
}

int portable_restore_at(const PortableRestoreRequest *request,
                        PortableRestoreReplayReport *report)
{
    PortableRestoreOutcome outcome =
        portable_restore_orchestrate_impl(request, report, 0);
    if (outcome == PORTABLE_RESTORE_COMPLETE)
    {
        printf("Portable restore complete: %zu applied\n",
               report->applied_count);
        if (report->skipped_security_xattr_count != 0)
            printf("Portable restore skipped %zu security.* attribute(s) "
                   "that the destination could not apply\n",
                   report->skipped_security_xattr_count);
    }
    return outcome == PORTABLE_RESTORE_ERROR ? -1 : 0;
}
