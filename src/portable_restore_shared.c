#define _GNU_SOURCE

#include "portable_restore_internal.h"
#include "portable.h"
#include "encoding.h"
#include "hash.h"
#include "manifest.h"
#include "sidecar.h"
#include "utils.h"
#include "xdg.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void *preflight_alloc(PreflightMemory *memory, size_t size)
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

void *preflight_realloc(PreflightMemory *memory, void *pointer,
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

void preflight_free(PreflightMemory *memory, void *pointer,
                           size_t size)
{
    if (pointer == NULL)
        return;
    if (memory != NULL && (uint64_t)size <= memory->bytes)
        memory->bytes -= (uint64_t)size;
    free(pointer);
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

int text_component_valid(const char *component, size_t length)
{
    return portable_component_valid(component, length);
}

int relative_path_valid(const char *path, int allow_empty)
{
    if (path == NULL)
        return 0;
    size_t length = strnlen(path, PATH_MAX + 1U);
    return portable_relative_bytes_valid(path, length, allow_empty);
}

int manifest_text_valid(const char *text, size_t capacity, int nonempty)
{
    if (text == NULL || capacity == 0)
        return 0;
    size_t length = strnlen(text, capacity);
    return length < capacity && (!nonempty || length != 0);
}

int sidecar_path_valid(SidecarBytes bytes, int allow_empty)
{
    if (bytes.length != 0 && bytes.data == NULL)
        return 0;
    return portable_relative_bytes_valid((const char *)bytes.data,
                                          bytes.length, allow_empty);
}

static int collision_suffix_valid(SidecarBytes suffix)
{
    if (suffix.length == 0)
        return 1;
    uint64_t value = 0;
    return portable_collision_suffix_parse((const char *)suffix.data,
                                           suffix.length, &value);
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

int entry_physical_matches_parent(const ManifestRoot *root,
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

static int root_id_equal(const ManifestRoot *root, SidecarBytes id)
{
    size_t length = strlen(root->id);
    return length == id.length &&
           (length == 0 || memcmp(root->id, id.data, length) == 0);
}

int root_map_build(RootMap *map, const Manifest *manifest)
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
        size_t index = (size_t)hash_fnv1a_bytes(
            HASH_FNV1A_OFFSET_BASIS, (const unsigned char *)root->id,
            strlen(root->id)) & (capacity - 1U);
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

void root_map_free(RootMap *map)
{
    if (map == NULL)
        return;
    free(map->slots);
    memset(map, 0, sizeof(*map));
}

size_t root_map_find(const RootMap *map, const Manifest *manifest,
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

void parent_map_free(PreflightMemory *memory, ParentMap *map)
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

int parent_map_build(ParentMap *map, PreflightMemory *memory,
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

int xdg_key_index(const char *id)
{
    if (id == NULL)
        return -1;
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        if (strcmp(id, xdg_keys[index]) == 0)
            return index;
    return -1;
}

int xdg_destination_valid(const char * const *xdg_dirs,
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

int destination_path_build(const ManifestRoot *root,
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

int destination_absolute_path_build(
    const ManifestRoot *root, const char *logical,
    const char * const *xdg_dirs, const char *destination_home,
    char *out, size_t out_size)
{
    if (destination_home == NULL || destination_home[0] != '/' ||
        strnlen(destination_home, PATH_MAX) >= PATH_MAX)
        return -1;

    char mapped[PATH_MAX];
    if (destination_path_build(root, logical, xdg_dirs, mapped,
                               sizeof(mapped)) != 0)
        return -1;
    if (mapped[0] == '/')
    {
        int length = snprintf(out, out_size, "%s", mapped);
        return length >= 0 && (size_t)length < out_size ? 0 : -1;
    }
    if (mapped[0] == '\0')
    {
        int length = snprintf(out, out_size, "%s", destination_home);
        return length >= 0 && (size_t)length < out_size ? 0 : -1;
    }
    return path_join(out, out_size, destination_home, mapped);
}

int destination_relative_path_build(const char *prefix,
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

int open_xdg_destination_anchor(const char *path, int *out_fd,
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
    memcpy(copy, path, strlen(path) + 1U);
    size_t length = strlen(copy);
    while (length > 1U && copy[length - 1U] == '/')
        copy[--length] = '\0';

    out_rel[0] = '\0';
    for (;;)
    {
        char *slash = strrchr(copy, '/');
        const char *leaf = slash == NULL ? copy : slash + 1U;
        size_t leaf_length = strlen(leaf);
        if (leaf_length == 0)
        {
            errno = EINVAL;
            return -1;
        }

        size_t relative_length = strlen(out_rel);
        size_t separator = relative_length == 0 ? 0U : 1U;
        if (leaf_length + separator + relative_length >= rel_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        memmove(out_rel + leaf_length + separator, out_rel,
                relative_length + 1U);
        memcpy(out_rel, leaf, leaf_length);
        if (separator != 0)
            out_rel[leaf_length] = '/';

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
        if (fd >= 0)
        {
            *out_fd = fd;
            return 0;
        }
        if (errno != ENOENT || slash == NULL)
            return -1;
    }
}

#define DESTINATION_IDENTITY_MAX_NODES \
    (2U * SIDECAR_MAX_LIVE_ENTRIES + MANIFEST_MAX_ROOTS)
#define DESTINATION_IDENTITY_MAX_NAMESPACE \
    (4U * SIDECAR_MAX_LIVE_ENTRIES + 2U * MANIFEST_MAX_ROOTS)

typedef struct {
    dev_t dev;
    ino_t ino;
    size_t metadata_owner;
    size_t topo_order;
    uint64_t mount_id;
    int existing;
    int mount_id_known;
    int unknown_mount_view;
} DestinationIdentityNode;

typedef struct {
    dev_t dev;
    ino_t ino;
    size_t node;
    int used;
} DestinationIdentitySlot;

typedef struct {
    size_t parent;
    size_t child;
    size_t non_directory_owner;
    char *component;
    size_t component_length;
    uint64_t hash;
    int used;
} DestinationNamespaceSlot;

typedef struct {
    size_t node;
    uint64_t mount_id;
    int known;
} DestinationMountView;

typedef struct {
    size_t parent;
    size_t child;
    uint64_t hash;
    int used;
} DestinationTopologySlot;

static uint64_t destination_identity_hash(dev_t dev, ino_t ino)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    hash = hash_fnv1a_uint64(hash, (uint64_t)dev);
    return hash_fnv1a_uint64(hash, (uint64_t)ino);
}

static uint64_t destination_namespace_hash(const DestinationIdentityGraph *graph,
                                           size_t parent,
                                           const char *component,
                                           size_t length)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ graph->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)parent);
    hash = hash_fnv1a_uint64(hash, (uint64_t)length);
    return hash_fnv1a_bytes(hash, (const unsigned char *)component, length);
}

static void destination_mount_view_read(int fd, uint64_t *mount_id, int *known)
{
    *mount_id = 0;
    *known = 0;
#ifdef STATX_MNT_ID
    struct statx sx;
    memset(&sx, 0, sizeof(sx));
    if (statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC,
              STATX_MNT_ID, &sx) == 0 &&
        (sx.stx_mask & STATX_MNT_ID) != 0)
    {
        *mount_id = sx.stx_mnt_id;
        *known = 1;
    }
#else
    (void)fd;
#endif
}

void destination_identity_graph_init(DestinationIdentityGraph *graph)
{
    if (graph == NULL)
        return;
    memset(graph, 0, sizeof(*graph));
    graph->hash_salt = sidecar_process_salt();
}

static int destination_nodes_reserve(DestinationIdentityGraph *graph,
                                     size_t extra)
{
    if (graph == NULL || extra > DESTINATION_IDENTITY_MAX_NODES -
                                  graph->node_count)
    {
        errno = E2BIG;
        return -1;
    }
    size_t needed = graph->node_count + extra;
    if (needed <= graph->node_capacity)
        return 0;
    size_t capacity = graph->node_capacity == 0 ? 32U :
                      graph->node_capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > DESTINATION_IDENTITY_MAX_NODES ||
        capacity > SIZE_MAX / sizeof(DestinationIdentityNode))
    {
        errno = E2BIG;
        return -1;
    }
    size_t old_size = graph->node_capacity * sizeof(DestinationIdentityNode);
    size_t new_size = capacity * sizeof(DestinationIdentityNode);
    DestinationIdentityNode *nodes = preflight_realloc(
        &graph->memory, graph->nodes, old_size, new_size);
    if (nodes == NULL)
        return -1;
    memset(nodes + graph->node_capacity, 0,
           (capacity - graph->node_capacity) * sizeof(*nodes));
    graph->nodes = nodes;
    graph->node_capacity = capacity;
    return 0;
}

static int destination_views_reserve(DestinationIdentityGraph *graph,
                                     size_t extra)
{
    if (extra > DESTINATION_IDENTITY_MAX_NAMESPACE - graph->mount_view_count)
    {
        errno = E2BIG;
        return -1;
    }
    size_t needed = graph->mount_view_count + extra;
    if (needed <= graph->mount_view_capacity)
        return 0;
    size_t capacity = graph->mount_view_capacity == 0 ? 16U :
                      graph->mount_view_capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > DESTINATION_IDENTITY_MAX_NAMESPACE ||
        capacity > SIZE_MAX / sizeof(DestinationMountView))
    {
        errno = E2BIG;
        return -1;
    }
    size_t old_size = graph->mount_view_capacity * sizeof(DestinationMountView);
    size_t new_size = capacity * sizeof(DestinationMountView);
    DestinationMountView *views = preflight_realloc(
        &graph->memory, graph->mount_views, old_size, new_size);
    if (views == NULL)
        return -1;
    graph->mount_views = views;
    graph->mount_view_capacity = capacity;
    return 0;
}

static int destination_note_mount_view(DestinationIdentityGraph *graph,
                                       size_t node_index, int fd)
{
    DestinationIdentityNode *nodes = graph->nodes;
    DestinationIdentityNode *node = &nodes[node_index];
    uint64_t mount_id;
    int known;
    destination_mount_view_read(fd, &mount_id, &known);
    if (!known)
    {
        if (node->unknown_mount_view)
            return 0;
        node->unknown_mount_view = 1;
    }
    else if (!node->mount_id_known)
    {
        node->mount_id = mount_id;
        node->mount_id_known = 1;
        return 0;
    }
    else if (node->mount_id == mount_id)
        return 0;

    if (destination_views_reserve(graph, 1U) != 0)
        return -1;
    DestinationMountView *views = graph->mount_views;
    views[graph->mount_view_count++] = (DestinationMountView){
        .node = node_index,
        .mount_id = mount_id,
        .known = known
    };
    return 0;
}

static int destination_identity_rehash(DestinationIdentityGraph *graph,
                                       size_t capacity)
{
    if (capacity < 32U || (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(DestinationIdentitySlot))
    {
        errno = E2BIG;
        return -1;
    }
    size_t new_size = capacity * sizeof(DestinationIdentitySlot);
    DestinationIdentitySlot *slots =
        preflight_alloc(&graph->memory, new_size);
    if (slots == NULL)
        return -1;
    memset(slots, 0, new_size);

    DestinationIdentitySlot *old = graph->identity_slots;
    size_t old_capacity = graph->identity_capacity;
    for (size_t i = 0; i < old_capacity; i++)
        if (old[i].used)
        {
            uint64_t hash = destination_identity_hash(old[i].dev, old[i].ino);
            size_t index = (size_t)hash & (capacity - 1U);
            while (slots[index].used)
                index = (index + 1U) & (capacity - 1U);
            slots[index] = old[i];
        }

    preflight_free(&graph->memory, old,
                   old_capacity * sizeof(DestinationIdentitySlot));
    graph->identity_slots = slots;
    graph->identity_capacity = capacity;
    return 0;
}

static int destination_identity_ensure(DestinationIdentityGraph *graph)
{
    if (graph->identity_capacity == 0)
        return destination_identity_rehash(graph, 32U);
    if (graph->node_count * 2U < graph->identity_capacity)
        return 0;
    if (graph->identity_capacity > SIZE_MAX / 2U)
    {
        errno = E2BIG;
        return -1;
    }
    return destination_identity_rehash(graph, graph->identity_capacity * 2U);
}

static int destination_existing_node(DestinationIdentityGraph *graph,
                                     int fd, size_t *node_out)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        if (errno == 0)
            errno = ENOTDIR;
        return -1;
    }
    if (destination_identity_ensure(graph) != 0)
        return -1;

    DestinationIdentitySlot *slots = graph->identity_slots;
    uint64_t hash = destination_identity_hash(st.st_dev, st.st_ino);
    size_t index = (size_t)hash & (graph->identity_capacity - 1U);
    for (size_t probes = 0; probes < graph->identity_capacity; probes++)
    {
        DestinationIdentitySlot *slot = &slots[index];
        if (!slot->used)
            break;
        if (slot->dev == st.st_dev && slot->ino == st.st_ino)
        {
            if (destination_note_mount_view(graph, slot->node, fd) != 0)
                return -1;
            *node_out = slot->node;
            return 0;
        }
        index = (index + 1U) & (graph->identity_capacity - 1U);
    }

    if (destination_nodes_reserve(graph, 1U) != 0)
        return -1;
    size_t node_index = graph->node_count++;
    DestinationIdentityNode *nodes = graph->nodes;
    nodes[node_index] = (DestinationIdentityNode){
        .dev = st.st_dev,
        .ino = st.st_ino,
        .metadata_owner = SIZE_MAX,
        .topo_order = SIZE_MAX,
        .existing = 1
    };
    if (destination_note_mount_view(graph, node_index, fd) != 0)
        return -1;

    slots = graph->identity_slots;
    index = (size_t)hash & (graph->identity_capacity - 1U);
    while (slots[index].used)
        index = (index + 1U) & (graph->identity_capacity - 1U);
    slots[index] = (DestinationIdentitySlot){
        .dev = st.st_dev,
        .ino = st.st_ino,
        .node = node_index,
        .used = 1
    };
    *node_out = node_index;
    return 0;
}

static int destination_namespace_rehash(DestinationIdentityGraph *graph,
                                        size_t capacity)
{
    if (capacity < 32U || (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(DestinationNamespaceSlot))
    {
        errno = E2BIG;
        return -1;
    }
    size_t new_size = capacity * sizeof(DestinationNamespaceSlot);
    DestinationNamespaceSlot *slots =
        preflight_alloc(&graph->memory, new_size);
    if (slots == NULL)
        return -1;
    memset(slots, 0, new_size);

    DestinationNamespaceSlot *old = graph->namespace_slots;
    size_t old_capacity = graph->namespace_capacity;
    for (size_t i = 0; i < old_capacity; i++)
        if (old[i].used)
        {
            size_t index = (size_t)old[i].hash & (capacity - 1U);
            while (slots[index].used)
                index = (index + 1U) & (capacity - 1U);
            slots[index] = old[i];
        }

    preflight_free(&graph->memory, old,
                   old_capacity * sizeof(DestinationNamespaceSlot));
    graph->namespace_slots = slots;
    graph->namespace_capacity = capacity;
    return 0;
}

static int destination_namespace_ensure(DestinationIdentityGraph *graph)
{
    if (graph->namespace_capacity == 0)
        return destination_namespace_rehash(graph, 32U);
    if (graph->namespace_count * 2U < graph->namespace_capacity)
        return 0;
    if (graph->namespace_capacity > SIZE_MAX / 2U)
    {
        errno = E2BIG;
        return -1;
    }
    return destination_namespace_rehash(graph,
                                        graph->namespace_capacity * 2U);
}

static DestinationNamespaceSlot *destination_namespace_slot(
    DestinationIdentityGraph *graph, size_t parent, const char *component,
    size_t length, int create)
{
    if (length == 0 || length > NAME_MAX ||
        graph->namespace_count >= DESTINATION_IDENTITY_MAX_NAMESPACE)
    {
        errno = E2BIG;
        return NULL;
    }
    if (destination_namespace_ensure(graph) != 0)
        return NULL;

    uint64_t hash = destination_namespace_hash(graph, parent, component, length);
    DestinationNamespaceSlot *slots = graph->namespace_slots;
    size_t index = (size_t)hash & (graph->namespace_capacity - 1U);
    for (size_t probes = 0; probes < graph->namespace_capacity; probes++)
    {
        DestinationNamespaceSlot *slot = &slots[index];
        if (!slot->used)
        {
            if (!create)
                return NULL;
            char *copy = preflight_alloc(&graph->memory, length + 1U);
            if (copy == NULL)
                return NULL;
            memcpy(copy, component, length);
            copy[length] = '\0';
            *slot = (DestinationNamespaceSlot){
                .parent = parent,
                .child = SIZE_MAX,
                .non_directory_owner = SIZE_MAX,
                .component = copy,
                .component_length = length,
                .hash = hash,
                .used = 1
            };
            graph->namespace_count++;
            return slot;
        }
        if (slot->hash == hash && slot->parent == parent &&
            slot->component_length == length &&
            memcmp(slot->component, component, length) == 0)
            return slot;
        index = (index + 1U) & (graph->namespace_capacity - 1U);
    }
    errno = E2BIG;
    return NULL;
}

static int destination_planned_node(DestinationIdentityGraph *graph,
                                    DestinationNamespaceSlot *slot,
                                    size_t *node_out)
{
    DestinationIdentityNode *nodes = graph->nodes;
    if (slot->child != SIZE_MAX)
    {
        if (slot->child >= graph->node_count || nodes[slot->child].existing)
        {
            errno = ESTALE;
            return -1;
        }
        *node_out = slot->child;
        return 0;
    }
    if (destination_nodes_reserve(graph, 1U) != 0)
        return -1;
    size_t index = graph->node_count++;
    nodes = graph->nodes;
    nodes[index] = (DestinationIdentityNode){
        .metadata_owner = SIZE_MAX,
        .topo_order = SIZE_MAX
    };
    slot->child = index;
    *node_out = index;
    return 0;
}


static DestinationIdentityStatus destination_graph_path_error(int saved);

static uint64_t destination_topology_hash(const DestinationIdentityGraph *graph,
                                          size_t parent, size_t child)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ graph->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)parent);
    return hash_fnv1a_uint64(hash, (uint64_t)child);
}

static int destination_topology_rehash(DestinationIdentityGraph *graph,
                                       size_t capacity)
{
    if (capacity < 32U || (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(DestinationTopologySlot))
    {
        errno = E2BIG;
        return -1;
    }
    size_t new_size = capacity * sizeof(DestinationTopologySlot);
    DestinationTopologySlot *slots =
        preflight_alloc(&graph->memory, new_size);
    if (slots == NULL)
        return -1;
    memset(slots, 0, new_size);

    DestinationTopologySlot *old = graph->topology_slots;
    size_t old_capacity = graph->topology_capacity;
    for (size_t index = 0; index < old_capacity; index++)
        if (old[index].used)
        {
            size_t position =
                (size_t)old[index].hash & (capacity - 1U);
            while (slots[position].used)
                position = (position + 1U) & (capacity - 1U);
            slots[position] = old[index];
        }

    preflight_free(&graph->memory, old,
                   old_capacity * sizeof(DestinationTopologySlot));
    graph->topology_slots = slots;
    graph->topology_capacity = capacity;
    return 0;
}

static int destination_topology_add(DestinationIdentityGraph *graph,
                                    size_t parent, size_t child)
{
    if (parent == child)
        return 0;
    if (graph->topology_count >= DESTINATION_IDENTITY_MAX_NAMESPACE)
    {
        errno = E2BIG;
        return -1;
    }
    if (graph->topology_capacity == 0)
    {
        if (destination_topology_rehash(graph, 32U) != 0)
            return -1;
    }
    else if (graph->topology_count * 2U >= graph->topology_capacity)
    {
        if (graph->topology_capacity > SIZE_MAX / 2U ||
            destination_topology_rehash(
                graph, graph->topology_capacity * 2U) != 0)
            return -1;
    }

    uint64_t hash = destination_topology_hash(graph, parent, child);
    DestinationTopologySlot *slots = graph->topology_slots;
    size_t position =
        (size_t)hash & (graph->topology_capacity - 1U);
    for (size_t probes = 0; probes < graph->topology_capacity; probes++)
    {
        DestinationTopologySlot *slot = &slots[position];
        if (!slot->used)
        {
            *slot = (DestinationTopologySlot){
                .parent = parent,
                .child = child,
                .hash = hash,
                .used = 1
            };
            graph->topology_count++;
            return 0;
        }
        if (slot->hash == hash && slot->parent == parent &&
            slot->child == child)
            return 0;
        position = (position + 1U) & (graph->topology_capacity - 1U);
    }
    errno = E2BIG;
    return -1;
}

DestinationIdentityStatus destination_identity_graph_register_anchor(
    DestinationIdentityGraph *graph, int anchor_fd)
{
    if (graph == NULL || anchor_fd < 0 || graph->finalized)
    {
        errno = EINVAL;
        return DESTINATION_IDENTITY_PATH_ERROR;
    }

    int current_fd = dup_cloexec(anchor_fd);
    if (current_fd < 0)
        return destination_graph_path_error(errno);

    size_t child;
    if (destination_existing_node(graph, current_fd, &child) != 0)
    {
        int saved = errno;
        close(current_fd);
        return destination_graph_path_error(saved);
    }

    for (;;)
    {
        int parent_fd = openat(current_fd, "..",
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC);
        if (parent_fd < 0)
        {
            int saved = errno;
            close(current_fd);
            return destination_graph_path_error(saved);
        }

        size_t parent;
        if (destination_existing_node(graph, parent_fd, &parent) != 0)
        {
            int saved = errno;
            close(parent_fd);
            close(current_fd);
            return destination_graph_path_error(saved);
        }
        if (parent == child)
        {
            int failed = close(parent_fd) != 0;
            if (close(current_fd) != 0)
                failed = 1;
            if (failed)
                return destination_graph_path_error(errno);
            return DESTINATION_IDENTITY_OK;
        }
        if (destination_topology_add(graph, parent, child) != 0)
        {
            int saved = errno;
            close(parent_fd);
            close(current_fd);
            return destination_graph_path_error(saved);
        }

        if (close(current_fd) != 0)
        {
            int saved = errno;
            close(parent_fd);
            return destination_graph_path_error(saved);
        }
        current_fd = parent_fd;
        child = parent;
    }
}

static DestinationIdentityStatus destination_graph_path_error(int saved)
{
    errno = saved == 0 ? EIO : saved;
    return saved == ENOMEM || saved == E2BIG
        ? DESTINATION_IDENTITY_RESOURCE_ERROR
        : DESTINATION_IDENTITY_PATH_ERROR;
}

DestinationIdentityStatus destination_identity_graph_add(
    DestinationIdentityGraph *graph, int anchor_fd, const char *relative,
    DestinationIdentityClaim claim, size_t owner,
    DestinationIdentityPlacement *placement)
{
    if (graph == NULL || anchor_fd < 0 || relative == NULL ||
        placement == NULL || graph->finalized ||
        (claim != DESTINATION_IDENTITY_STRUCTURAL &&
         claim != DESTINATION_IDENTITY_DIRECTORY &&
         claim != DESTINATION_IDENTITY_NON_DIRECTORY))
    {
        errno = EINVAL;
        return DESTINATION_IDENTITY_PATH_ERROR;
    }

    size_t length = strnlen(relative, PATH_MAX);
    if (length >= PATH_MAX)
    {
        errno = ENAMETOOLONG;
        return DESTINATION_IDENTITY_PATH_ERROR;
    }

    int current_fd = dup_cloexec(anchor_fd);
    if (current_fd < 0)
        return destination_graph_path_error(errno);

    size_t current_node;
    if (destination_existing_node(graph, current_fd, &current_node) != 0)
    {
        int saved = errno;
        close(current_fd);
        return destination_graph_path_error(saved);
    }

    if (length == 0)
    {
        if (claim == DESTINATION_IDENTITY_NON_DIRECTORY)
        {
            close(current_fd);
            errno = EINVAL;
            return DESTINATION_IDENTITY_PATH_ERROR;
        }
        if (claim == DESTINATION_IDENTITY_DIRECTORY)
        {
            DestinationIdentityNode *nodes = graph->nodes;
            if (nodes[current_node].metadata_owner != SIZE_MAX &&
                nodes[current_node].metadata_owner != owner)
            {
                close(current_fd);
                errno = EEXIST;
                return DESTINATION_IDENTITY_COLLISION;
            }
            nodes[current_node].metadata_owner = owner;
        }
        placement->node = current_node;
        placement->is_directory = 1;
        if (close(current_fd) != 0)
            return destination_graph_path_error(errno);
        return DESTINATION_IDENTITY_OK;
    }

    char path[PATH_MAX];
    memcpy(path, relative, length + 1U);
    char *cursor = path;
    for (;;)
    {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        size_t component_length = strlen(cursor);
        int final = slash == NULL;
        if (component_length == 0 || component_length > NAME_MAX ||
            !strcmp(cursor, ".") || !strcmp(cursor, ".."))
        {
            close(current_fd);
            errno = EINVAL;
            return DESTINATION_IDENTITY_PATH_ERROR;
        }

        int needs_directory = !final ||
            claim != DESTINATION_IDENTITY_NON_DIRECTORY;
        DestinationNamespaceSlot *slot = NULL;

        if (!needs_directory)
        {
            slot = destination_namespace_slot(graph, current_node, cursor,
                                              component_length, 1);
            if (slot == NULL)
            {
                int saved = errno;
                close(current_fd);
                return destination_graph_path_error(saved);
            }
            if (current_fd >= 0)
            {
                struct stat st;
                errno = 0;
                if (fstatat(current_fd, cursor, &st,
                            AT_SYMLINK_NOFOLLOW) == 0)
                {
                    if (S_ISDIR(st.st_mode))
                    {
                        close(current_fd);
                        errno = EISDIR;
                        return DESTINATION_IDENTITY_COLLISION;
                    }
                }
                else if (errno != ENOENT)
                {
                    int saved = errno;
                    close(current_fd);
                    return destination_graph_path_error(saved);
                }
            }
            if (slot->child != SIZE_MAX ||
                slot->non_directory_owner != SIZE_MAX)
            {
                if (current_fd >= 0)
                    close(current_fd);
                errno = EEXIST;
                return DESTINATION_IDENTITY_COLLISION;
            }
            slot->non_directory_owner = owner;
            placement->node = current_node;
            placement->is_directory = 0;
            if (current_fd >= 0 && close(current_fd) != 0)
                return destination_graph_path_error(errno);
            return DESTINATION_IDENTITY_OK;
        }

        slot = destination_namespace_slot(graph, current_node, cursor,
                                          component_length, 1);
        if (slot == NULL)
        {
            int saved = errno;
            if (current_fd >= 0)
                close(current_fd);
            return destination_graph_path_error(saved);
        }
        if (slot->non_directory_owner != SIZE_MAX)
        {
            if (current_fd >= 0)
                close(current_fd);
            errno = EEXIST;
            return DESTINATION_IDENTITY_COLLISION;
        }

        size_t child_node;
        int next_fd = -1;
        if (current_fd >= 0)
        {
            struct stat st;
            errno = 0;
            if (fstatat(current_fd, cursor, &st, AT_SYMLINK_NOFOLLOW) == 0)
            {
                if (!S_ISDIR(st.st_mode))
                {
                    close(current_fd);
                    errno = ENOTDIR;
                    return DESTINATION_IDENTITY_PATH_ERROR;
                }
                next_fd = openat(current_fd, cursor,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_NOATIME | O_CLOEXEC);
                if (next_fd < 0 ||
                    destination_existing_node(graph, next_fd,
                                              &child_node) != 0)
                {
                    int saved = errno;
                    if (next_fd >= 0)
                        close(next_fd);
                    close(current_fd);
                    return destination_graph_path_error(saved);
                }
                if (slot->child != SIZE_MAX && slot->child != child_node)
                {
                    close(next_fd);
                    close(current_fd);
                    errno = ESTALE;
                    return DESTINATION_IDENTITY_PATH_ERROR;
                }
                slot->child = child_node;
            }
            else if (errno == ENOENT)
            {
                if (destination_planned_node(graph, slot, &child_node) != 0)
                {
                    int saved = errno;
                    close(current_fd);
                    return destination_graph_path_error(saved);
                }
            }
            else
            {
                int saved = errno;
                close(current_fd);
                return destination_graph_path_error(saved);
            }
        }
        else if (destination_planned_node(graph, slot, &child_node) != 0)
            return destination_graph_path_error(errno);

        if (current_fd >= 0 && close(current_fd) != 0)
        {
            int saved = errno;
            if (next_fd >= 0)
                close(next_fd);
            return destination_graph_path_error(saved);
        }
        current_fd = next_fd;
        current_node = child_node;

        if (final)
        {
            if (claim == DESTINATION_IDENTITY_DIRECTORY)
            {
                DestinationIdentityNode *nodes = graph->nodes;
                if (nodes[current_node].metadata_owner != SIZE_MAX &&
                    nodes[current_node].metadata_owner != owner)
                {
                    if (current_fd >= 0)
                        close(current_fd);
                    errno = EEXIST;
                    return DESTINATION_IDENTITY_COLLISION;
                }
                nodes[current_node].metadata_owner = owner;
            }
            placement->node = current_node;
            placement->is_directory = 1;
            if (current_fd >= 0 && close(current_fd) != 0)
                return destination_graph_path_error(errno);
            return DESTINATION_IDENTITY_OK;
        }
        cursor = slash + 1U;
    }
}

DestinationIdentityStatus destination_identity_graph_finalize(
    DestinationIdentityGraph *graph)
{
    if (graph == NULL || graph->finalized)
    {
        errno = EINVAL;
        return DESTINATION_IDENTITY_PATH_ERROR;
    }
    if (graph->node_count == 0)
    {
        graph->finalized = 1;
        return DESTINATION_IDENTITY_OK;
    }
    if (graph->node_count > SIZE_MAX / sizeof(size_t) ||
        graph->namespace_count > SIZE_MAX / sizeof(size_t))
    {
        errno = E2BIG;
        return DESTINATION_IDENTITY_RESOURCE_ERROR;
    }

    if (graph->topology_count > SIZE_MAX - graph->namespace_count)
    {
        errno = E2BIG;
        return DESTINATION_IDENTITY_RESOURCE_ERROR;
    }
    size_t edge_capacity = graph->namespace_count + graph->topology_count;
    size_t node_bytes = graph->node_count * sizeof(size_t);
    if (edge_capacity > SIZE_MAX / sizeof(size_t))
    {
        errno = E2BIG;
        return DESTINATION_IDENTITY_RESOURCE_ERROR;
    }
    size_t edge_bytes = edge_capacity * sizeof(size_t);
    size_t *indegree = preflight_alloc(&graph->memory, node_bytes);
    size_t *first = preflight_alloc(&graph->memory, node_bytes);
    size_t *queue = preflight_alloc(&graph->memory, node_bytes);
    size_t *next = edge_capacity == 0 ? NULL :
                   preflight_alloc(&graph->memory, edge_bytes);
    size_t *child = edge_capacity == 0 ? NULL :
                    preflight_alloc(&graph->memory, edge_bytes);
    if (indegree == NULL || first == NULL || queue == NULL ||
        (edge_capacity != 0 && (next == NULL || child == NULL)))
    {
        preflight_free(&graph->memory, indegree, node_bytes);
        preflight_free(&graph->memory, first, node_bytes);
        preflight_free(&graph->memory, queue, node_bytes);
        preflight_free(&graph->memory, next, edge_bytes);
        preflight_free(&graph->memory, child, edge_bytes);
        return DESTINATION_IDENTITY_RESOURCE_ERROR;
    }
    memset(indegree, 0, node_bytes);
    for (size_t i = 0; i < graph->node_count; i++)
        first[i] = SIZE_MAX;

    DestinationNamespaceSlot *slots = graph->namespace_slots;
    size_t edge_count = 0;
    for (size_t i = 0; i < graph->namespace_capacity; i++)
        if (slots[i].used && slots[i].child != SIZE_MAX)
        {
            if (slots[i].parent >= graph->node_count ||
                slots[i].child >= graph->node_count ||
                indegree[slots[i].child] == SIZE_MAX)
            {
                errno = E2BIG;
                goto resource_fail;
            }
            indegree[slots[i].child]++;
            child[edge_count] = slots[i].child;
            next[edge_count] = first[slots[i].parent];
            first[slots[i].parent] = edge_count++;
        }

    DestinationTopologySlot *topology = graph->topology_slots;
    for (size_t i = 0; i < graph->topology_capacity; i++)
        if (topology[i].used)
        {
            if (topology[i].parent >= graph->node_count ||
                topology[i].child >= graph->node_count ||
                indegree[topology[i].child] == SIZE_MAX)
            {
                errno = E2BIG;
                goto resource_fail;
            }
            indegree[topology[i].child]++;
            child[edge_count] = topology[i].child;
            next[edge_count] = first[topology[i].parent];
            first[topology[i].parent] = edge_count++;
        }

    size_t head = 0;
    size_t tail = 0;
    for (size_t i = 0; i < graph->node_count; i++)
        if (indegree[i] == 0)
            queue[tail++] = i;

    DestinationIdentityNode *nodes = graph->nodes;
    size_t ordered = 0;
    while (head < tail)
    {
        size_t node = queue[head++];
        nodes[node].topo_order = ordered++;
        for (size_t edge = first[node]; edge != SIZE_MAX; edge = next[edge])
        {
            size_t destination = child[edge];
            if (indegree[destination] == 0)
            {
                errno = EINVAL;
                goto resource_fail;
            }
            indegree[destination]--;
            if (indegree[destination] == 0)
                queue[tail++] = destination;
        }
    }

    preflight_free(&graph->memory, indegree, node_bytes);
    preflight_free(&graph->memory, first, node_bytes);
    preflight_free(&graph->memory, queue, node_bytes);
    preflight_free(&graph->memory, next, edge_bytes);
    preflight_free(&graph->memory, child, edge_bytes);
    if (ordered != graph->node_count)
    {
        errno = ELOOP;
        return DESTINATION_IDENTITY_CYCLE;
    }
    graph->finalized = 1;
    return DESTINATION_IDENTITY_OK;

resource_fail:
    preflight_free(&graph->memory, indegree, node_bytes);
    preflight_free(&graph->memory, first, node_bytes);
    preflight_free(&graph->memory, queue, node_bytes);
    preflight_free(&graph->memory, next, edge_bytes);
    preflight_free(&graph->memory, child, edge_bytes);
    return DESTINATION_IDENTITY_RESOURCE_ERROR;
}

int destination_identity_graph_order(
    const DestinationIdentityGraph *graph,
    const DestinationIdentityPlacement *placement, size_t *order_out)
{
    if (graph == NULL || placement == NULL || order_out == NULL ||
        !graph->finalized || placement->node >= graph->node_count)
    {
        errno = EINVAL;
        return -1;
    }
    const DestinationIdentityNode *nodes = graph->nodes;
    size_t order = nodes[placement->node].topo_order;
    if (order == SIZE_MAX || order > (SIZE_MAX - 1U) / 2U)
    {
        errno = E2BIG;
        return -1;
    }
    *order_out = order * 2U + (placement->is_directory ? 0U : 1U);
    return 0;
}

void destination_identity_graph_free(DestinationIdentityGraph *graph)
{
    if (graph == NULL)
        return;
    DestinationNamespaceSlot *slots = graph->namespace_slots;
    for (size_t i = 0; i < graph->namespace_capacity; i++)
        if (slots != NULL && slots[i].used)
            preflight_free(&graph->memory, slots[i].component,
                           slots[i].component_length + 1U);
    preflight_free(&graph->memory, graph->nodes,
                   graph->node_capacity * sizeof(DestinationIdentityNode));
    preflight_free(&graph->memory, graph->identity_slots,
                   graph->identity_capacity * sizeof(DestinationIdentitySlot));
    preflight_free(&graph->memory, graph->namespace_slots,
                   graph->namespace_capacity * sizeof(DestinationNamespaceSlot));
    preflight_free(&graph->memory, graph->mount_views,
                   graph->mount_view_capacity * sizeof(DestinationMountView));
    preflight_free(&graph->memory, graph->topology_slots,
                   graph->topology_capacity * sizeof(DestinationTopologySlot));
    memset(graph, 0, sizeof(*graph));
}

int sidecar_kind_to_type(SidecarObjectKind kind, mode_t *type)
{
    if (type == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    switch (kind)
    {
        case SIDECAR_KIND_REGULAR:
        case SIDECAR_KIND_HARDLINK:
            *type = S_IFREG;
            return 0;
        case SIDECAR_KIND_DIRECTORY:
            *type = S_IFDIR;
            return 0;
        case SIDECAR_KIND_SYMLINK:
            *type = S_IFLNK;
            return 0;
        case SIDECAR_KIND_FIFO:
        default:
            errno = EINVAL;
            return -1;
    }
}

int sidecar_is_complete_readonly(int container_fd)
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
