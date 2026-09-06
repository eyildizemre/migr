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

void *preflight_array_reserve(
    PreflightMemory *memory, void *items, size_t *capacity, size_t count,
    size_t extra, size_t element_size, size_t initial_capacity,
    size_t max_capacity, int clear_new)
{
    if (memory == NULL || capacity == NULL || extra == 0 || element_size == 0 ||
        initial_capacity == 0 || max_capacity == 0)
    {
        errno = EINVAL;
        return NULL;
    }
    if (count > max_capacity || extra > max_capacity - count)
    {
        errno = E2BIG;
        return NULL;
    }

    size_t needed = count + extra;
    if (needed <= *capacity)
        return items;

    size_t next = *capacity == 0 ? initial_capacity : *capacity * 2U;
    if (next < *capacity)
        next = max_capacity;
    if (next < needed)
        next = needed;
    if (next > max_capacity)
        next = max_capacity;
    if (next < needed || next > SIZE_MAX / element_size)
    {
        errno = E2BIG;
        return NULL;
    }

    size_t old_size = *capacity * element_size;
    size_t new_size = next * element_size;
    void *grown = preflight_realloc(memory, items, old_size, new_size);
    if (grown == NULL)
        return NULL;
    if (clear_new)
        memset((unsigned char *)grown + old_size, 0, new_size - old_size);
    *capacity = next;
    return grown;
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

int destination_identity_route(
    const Manifest *manifest, size_t root_index, const char *logical,
    int destination_home_fd, const char * const *destination_xdg_dirs,
    int *xdg_anchor_fd, char (*xdg_anchor_prefix)[PATH_MAX], int *anchor_out,
    char *relative, size_t relative_size)
{
    if (manifest == NULL || logical == NULL || destination_home_fd < 0 ||
        destination_xdg_dirs == NULL || xdg_anchor_fd == NULL ||
        xdg_anchor_prefix == NULL || anchor_out == NULL || relative == NULL ||
        relative_size == 0 || root_index >= (size_t)manifest->root_count)
    {
        errno = EINVAL;
        return -1;
    }

    const ManifestRoot *root = &manifest->roots[root_index];
    if (root->policy == ROOT_POLICY_HOME_RELATIVE)
    {
        if (destination_path_build(root, logical, destination_xdg_dirs,
                                   relative, relative_size) != 0)
            return -1;
        *anchor_out = destination_home_fd;
        return 0;
    }
    if (root->policy != ROOT_POLICY_XDG ||
        !xdg_destination_valid(destination_xdg_dirs, root))
    {
        errno = EINVAL;
        return -1;
    }

    int index = xdg_key_index(root->id);
    if (index < 0 || index >= XDG_KEY_COUNT)
    {
        errno = EINVAL;
        return -1;
    }
    if (xdg_anchor_fd[index] < 0 &&
        open_xdg_destination_anchor(destination_xdg_dirs[index],
                                    &xdg_anchor_fd[index],
                                    xdg_anchor_prefix[index], PATH_MAX) != 0)
        return -1;
    if (destination_relative_path_build(xdg_anchor_prefix[index], logical,
                                        relative, relative_size) != 0)
        return -1;
    *anchor_out = xdg_anchor_fd[index];
    return 0;
}

#define DESTINATION_IDENTITY_PORTABLE_MAX_NODES \
    (2U * SIDECAR_MAX_LIVE_ENTRIES + MANIFEST_MAX_ROOTS)
#define DESTINATION_IDENTITY_PORTABLE_MAX_NAMESPACE \
    (4U * SIDECAR_MAX_LIVE_ENTRIES + 2U * MANIFEST_MAX_ROOTS)

typedef struct {
    size_t metadata_owner;
    size_t topo_order;
    uint64_t mount_id;
    int existing;
    int mount_id_known;
    int unknown_mount_view;
} DestinationIdentityNode;

typedef struct {
    uint64_t key_a;
    uint64_t key_b;
    size_t value;
    uint64_t hash;
    int used;
} DestinationFixedSlot;

typedef struct {
    size_t parent;
    size_t child;
    size_t non_directory_owner;
    char *component;
    size_t component_length;
    uint64_t hash;
    int used;
} DestinationNamespaceSlot;

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

static size_t destination_budget_capacity(size_t element_size)
{
    uint64_t capacity = SIDECAR_MAX_ALLOC_BUDGET / (uint64_t)element_size;
    return capacity > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)capacity;
}

void destination_identity_graph_init(DestinationIdentityGraph *graph,
                                     DestinationIdentityBounds bounds)
{
    if (graph == NULL)
        return;
    memset(graph, 0, sizeof(*graph));
    if (bounds == DESTINATION_IDENTITY_NATIVE_BOUNDS)
    {
        /* Native payloads have no sidecar entry-count ceiling. Bound their
         * graph by the allocator's byte budget and the actual element sizes
         * instead of importing the portable format's live-entry limit. */
        graph->node_limit = destination_budget_capacity(
            sizeof(DestinationIdentityNode));
        graph->namespace_limit = destination_budget_capacity(
            sizeof(DestinationNamespaceSlot) + 2U);
    }
    else
    {
        graph->node_limit = DESTINATION_IDENTITY_PORTABLE_MAX_NODES;
        graph->namespace_limit = DESTINATION_IDENTITY_PORTABLE_MAX_NAMESPACE;
    }
    graph->hash_salt = sidecar_process_salt();
}

static int destination_nodes_reserve(DestinationIdentityGraph *graph,
                                     size_t extra)
{
    if (graph == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    DestinationIdentityNode *nodes = preflight_array_reserve(
        &graph->memory, graph->nodes, &graph->node_capacity,
        graph->node_count, extra, sizeof(*nodes), 32U, graph->node_limit, 0);
    if (nodes == NULL)
        return -1;
    graph->nodes = nodes;
    return 0;
}

static void destination_note_mount_view(DestinationIdentityGraph *graph,
                                        size_t node_index, int fd)
{
    DestinationIdentityNode *nodes = graph->nodes;
    DestinationIdentityNode *node = &nodes[node_index];
    uint64_t mount_id;
    int known;
    destination_mount_view_read(fd, &mount_id, &known);
    if (!known)
        node->unknown_mount_view = 1;
    else if (!node->mount_id_known)
    {
        node->mount_id = mount_id;
        node->mount_id_known = 1;
    }
    else if (node->mount_id != mount_id)
        node->unknown_mount_view = 1;
}

static int destination_fixed_rehash(DestinationIdentityGraph *graph,
                                    void **table, size_t *table_capacity,
                                    size_t capacity)
{
    if (capacity < 32U || (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(DestinationFixedSlot))
    {
        errno = E2BIG;
        return -1;
    }
    size_t new_size = capacity * sizeof(DestinationFixedSlot);
    DestinationFixedSlot *slots =
        preflight_alloc(&graph->memory, new_size);
    if (slots == NULL)
        return -1;
    memset(slots, 0, new_size);

    DestinationFixedSlot *old = *table;
    size_t old_capacity = *table_capacity;
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
                   old_capacity * sizeof(DestinationFixedSlot));
    *table = slots;
    *table_capacity = capacity;
    return 0;
}

static int destination_fixed_ensure(DestinationIdentityGraph *graph,
                                    void **table, size_t *capacity,
                                    size_t count)
{
    if (*capacity == 0)
        return destination_fixed_rehash(graph, table, capacity, 32U);
    if (count < *capacity / 2U)
        return 0;
    if (*capacity > SIZE_MAX / 2U)
    {
        errno = E2BIG;
        return -1;
    }
    return destination_fixed_rehash(graph, table, capacity, *capacity * 2U);
}

static int destination_existing_node(DestinationIdentityGraph *graph,
                                     int fd, const struct stat *known_stat,
                                     size_t *node_out)
{
    struct stat read_stat;
    if (known_stat == NULL)
    {
        errno = 0;
        if (fstat(fd, &read_stat) != 0)
            return -1;
        known_stat = &read_stat;
    }
    if (!S_ISDIR(known_stat->st_mode))
    {
        errno = ENOTDIR;
        return -1;
    }

    uint64_t hash = destination_identity_hash(known_stat->st_dev,
                                              known_stat->st_ino);
    DestinationFixedSlot *slots = graph->identity_slots;
    if (graph->identity_capacity != 0)
    {
        size_t index = (size_t)hash & (graph->identity_capacity - 1U);
        for (size_t probes = 0; probes < graph->identity_capacity; probes++)
        {
            DestinationFixedSlot *slot = &slots[index];
            if (!slot->used)
                break;
            if (slot->hash == hash &&
                slot->key_a == (uint64_t)known_stat->st_dev &&
                slot->key_b == (uint64_t)known_stat->st_ino)
            {
                destination_note_mount_view(graph, slot->value, fd);
                *node_out = slot->value;
                return 1;
            }
            index = (index + 1U) & (graph->identity_capacity - 1U);
        }
    }

    if (destination_fixed_ensure(graph, &graph->identity_slots,
                                 &graph->identity_capacity,
                                 graph->node_count) != 0)
        return -1;
    if (destination_nodes_reserve(graph, 1U) != 0)
        return -1;
    size_t node_index = graph->node_count++;
    DestinationIdentityNode *nodes = graph->nodes;
    nodes[node_index] = (DestinationIdentityNode){
        .metadata_owner = SIZE_MAX,
        .topo_order = SIZE_MAX,
        .existing = 1
    };
    destination_note_mount_view(graph, node_index, fd);

    slots = graph->identity_slots;
    size_t index = (size_t)hash & (graph->identity_capacity - 1U);
    while (slots[index].used)
        index = (index + 1U) & (graph->identity_capacity - 1U);
    slots[index] = (DestinationFixedSlot){
        .key_a = (uint64_t)known_stat->st_dev,
        .key_b = (uint64_t)known_stat->st_ino,
        .value = node_index,
        .hash = hash,
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
    size_t length)
{
    if (length == 0 || length > NAME_MAX)
    {
        errno = E2BIG;
        return NULL;
    }

    uint64_t hash = destination_namespace_hash(graph, parent, component, length);
    DestinationNamespaceSlot *slots = graph->namespace_slots;
    if (graph->namespace_capacity != 0)
    {
        size_t index = (size_t)hash & (graph->namespace_capacity - 1U);
        while (slots[index].used)
        {
            if (slots[index].hash == hash && slots[index].parent == parent &&
                slots[index].component_length == length &&
                memcmp(slots[index].component, component, length) == 0)
                return &slots[index];
            index = (index + 1U) & (graph->namespace_capacity - 1U);
        }
    }
    if (graph->namespace_count >= graph->namespace_limit)
    {
        errno = E2BIG;
        return NULL;
    }
    if (destination_namespace_ensure(graph) != 0)
        return NULL;

    slots = graph->namespace_slots;
    size_t index = (size_t)hash & (graph->namespace_capacity - 1U);
    while (slots[index].used)
        index = (index + 1U) & (graph->namespace_capacity - 1U);
    char *copy = preflight_alloc(&graph->memory, length + 1U);
    if (copy == NULL)
        return NULL;
    memcpy(copy, component, length);
    copy[length] = '\0';
    slots[index] = (DestinationNamespaceSlot){
        .parent = parent,
        .child = SIZE_MAX,
        .non_directory_owner = SIZE_MAX,
        .component = copy,
        .component_length = length,
        .hash = hash,
        .used = 1
    };
    graph->namespace_count++;
    return &slots[index];
}

static int destination_planned_node(DestinationIdentityGraph *graph,
                                    DestinationNamespaceSlot *slot,
                                    size_t *node_out)
{
    if (destination_nodes_reserve(graph, 1U) != 0)
        return -1;
    size_t index = graph->node_count++;
    DestinationIdentityNode *nodes = graph->nodes;
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

static int destination_topology_add(DestinationIdentityGraph *graph,
                                    size_t parent, size_t child)
{
    if (parent == child)
        return 0;
    if (graph->topology_count >= graph->namespace_limit)
    {
        errno = E2BIG;
        return -1;
    }
    if (destination_fixed_ensure(graph, &graph->topology_slots,
                                 &graph->topology_capacity,
                                 graph->topology_count) != 0)
        return -1;

    uint64_t hash = destination_topology_hash(graph, parent, child);
    DestinationFixedSlot *slots = graph->topology_slots;
    size_t position =
        (size_t)hash & (graph->topology_capacity - 1U);
    for (size_t probes = 0; probes < graph->topology_capacity; probes++)
    {
        DestinationFixedSlot *slot = &slots[position];
        if (!slot->used)
        {
            *slot = (DestinationFixedSlot){
                .key_a = (uint64_t)parent,
                .key_b = (uint64_t)child,
                .value = SIZE_MAX,
                .hash = hash,
                .used = 1
            };
            graph->topology_count++;
            return 0;
        }
        if (slot->hash == hash && slot->key_a == (uint64_t)parent &&
            slot->key_b == (uint64_t)child)
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
    if (destination_existing_node(graph, current_fd, NULL, &child) < 0)
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
        int parent_known = destination_existing_node(
            graph, parent_fd, NULL, &parent);
        if (parent_known < 0)
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

        /* A bind-mounted child can already be interned through another
         * parent; only a known parent proves the remaining chain is present. */
        if (parent_known)
        {
            int failed = close(parent_fd) != 0;
            if (close(current_fd) != 0)
                failed = 1;
            if (failed)
                return destination_graph_path_error(errno);
            return DESTINATION_IDENTITY_OK;
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
    DestinationIdentityPlacement *placement,
    size_t *conflicting_owner)
{
    if (conflicting_owner != NULL)
        *conflicting_owner = SIZE_MAX;
    if (graph == NULL || anchor_fd < 0 || relative == NULL ||
        placement == NULL || conflicting_owner == NULL || graph->finalized ||
        owner == SIZE_MAX ||
        (claim != DESTINATION_IDENTITY_DIRECTORY &&
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
    if (destination_existing_node(graph, current_fd, NULL,
                                  &current_node) < 0)
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
                *conflicting_owner = nodes[current_node].metadata_owner;
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

        int needs_directory = !final || claim == DESTINATION_IDENTITY_DIRECTORY;
        DestinationNamespaceSlot *slot = destination_namespace_slot(
            graph, current_node, cursor, component_length);
        if (slot == NULL)
        {
            int saved = errno;
            if (current_fd >= 0)
                close(current_fd);
            return destination_graph_path_error(saved);
        }
        if (slot->non_directory_owner != SIZE_MAX)
        {
            *conflicting_owner = slot->non_directory_owner;
            if (current_fd >= 0)
                close(current_fd);
            errno = EEXIST;
            return DESTINATION_IDENTITY_COLLISION;
        }

        if (!needs_directory)
        {
            if (slot->child != SIZE_MAX)
            {
                DestinationIdentityNode *nodes = graph->nodes;
                if (slot->child >= graph->node_count)
                {
                    if (current_fd >= 0)
                        close(current_fd);
                    errno = ESTALE;
                    return DESTINATION_IDENTITY_PATH_ERROR;
                }
                if (nodes[slot->child].metadata_owner != SIZE_MAX)
                    *conflicting_owner =
                        nodes[slot->child].metadata_owner;
                if (current_fd >= 0)
                    close(current_fd);
                errno = EEXIST;
                return DESTINATION_IDENTITY_COLLISION;
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
            slot->non_directory_owner = owner;
            placement->node = current_node;
            placement->is_directory = 0;
            if (current_fd >= 0 && close(current_fd) != 0)
                return destination_graph_path_error(errno);
            return DESTINATION_IDENTITY_OK;
        }

        size_t child_node;
        int next_fd = -1;
        if (slot->child != SIZE_MAX)
        {
            DestinationIdentityNode *nodes = graph->nodes;
            if (slot->child >= graph->node_count ||
                (current_fd < 0 && nodes[slot->child].existing))
            {
                if (current_fd >= 0)
                    close(current_fd);
                errno = ESTALE;
                return DESTINATION_IDENTITY_PATH_ERROR;
            }
            child_node = slot->child;
            if (current_fd >= 0 && nodes[child_node].existing && !final)
            {
                next_fd = openat(current_fd, cursor,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_NOATIME | O_CLOEXEC);
                if (next_fd < 0)
                {
                    int saved = errno;
                    close(current_fd);
                    return destination_graph_path_error(saved);
                }
            }
        }
        else if (current_fd >= 0)
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
                    destination_existing_node(graph, next_fd, &st,
                                              &child_node) < 0)
                {
                    int saved = errno;
                    if (next_fd >= 0)
                        close(next_fd);
                    close(current_fd);
                    return destination_graph_path_error(saved);
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
                    *conflicting_owner =
                        nodes[current_node].metadata_owner;
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

static int destination_identity_logical_copy(
    const DestinationIdentityEntryView *view, char logical[PATH_MAX])
{
    if (view == NULL || view->logical_length >= PATH_MAX ||
        (view->logical_length != 0 && view->logical == NULL) ||
        (view->logical_length != 0 &&
         memchr(view->logical, '\0', view->logical_length) != NULL))
    {
        errno = EINVAL;
        return -1;
    }
    if (view->logical_length != 0)
        memcpy(logical, view->logical, view->logical_length);
    logical[view->logical_length] = '\0';
    return 0;
}

int destination_identity_graph_add_entries(
    DestinationIdentityGraph *graph, const Manifest *manifest,
    size_t entry_count, int destination_home_fd,
    const char *destination_home_path,
    const char * const *destination_xdg_dirs, int *xdg_anchor_fd,
    char (*xdg_anchor_prefix)[PATH_MAX], DestinationIdentityEntryReader reader,
    DestinationIdentityFailureReporter report_failure, void *context,
    DestinationIdentityCollisionPolicy collision_policy)
{
    if (graph == NULL || manifest == NULL || destination_home_fd < 0 ||
        destination_xdg_dirs == NULL || xdg_anchor_fd == NULL ||
        xdg_anchor_prefix == NULL || reader == NULL || report_failure == NULL ||
        context == NULL || graph->finalized ||
        (collision_policy != DESTINATION_IDENTITY_AGGREGATE_COLLISIONS &&
         collision_policy != DESTINATION_IDENTITY_STOP_ON_COLLISION))
    {
        errno = EINVAL;
        return -1;
    }

    unsigned char registered_xdg[XDG_KEY_COUNT] = {0};
    for (size_t index = 0; index < entry_count; index++)
    {
        DestinationIdentityEntryView view;
        char logical[PATH_MAX];
        reader(context, index, &view);
        if (view.root_index >= (size_t)manifest->root_count ||
            destination_identity_logical_copy(&view, logical) != 0)
        {
            print_error("Error: Could not read portable restore destination entry %zu\n",
                        index);
            report_failure(context, index);
            return -1;
        }

        int anchor = -1;
        char relative[PATH_MAX];
        if (destination_identity_route(
                manifest, view.root_index, logical, destination_home_fd,
                destination_xdg_dirs, xdg_anchor_fd, xdg_anchor_prefix,
                &anchor, relative, sizeof(relative)) != 0)
        {
            print_error("Error: Could not resolve portable restore destination for manifest root %s entry %s\n",
                        manifest->roots[view.root_index].id,
                        logical[0] == '\0' ? "." : logical);
            report_failure(context, index);
            return -1;
        }

        const ManifestRoot *root = &manifest->roots[view.root_index];
        if (root->policy == ROOT_POLICY_XDG)
        {
            int key = xdg_key_index(root->id);
            if (key < 0 || key >= XDG_KEY_COUNT)
            {
                print_error("Error: Could not identify XDG restore destination for manifest root %s\n",
                            root->id);
                report_failure(context, index);
                return -1;
            }
            if (!registered_xdg[key])
            {
                DestinationIdentityStatus anchor_status =
                    destination_identity_graph_register_anchor(graph, anchor);
                if (anchor_status != DESTINATION_IDENTITY_OK)
                {
                    if (anchor_status == DESTINATION_IDENTITY_RESOURCE_ERROR &&
                        errno == E2BIG)
                        print_error("Error: Portable restore destination identity budget exceeded while registering XDG ancestry for manifest root %s\n",
                                    root->id);
                    else
                        print_error("Error: Could not inspect XDG destination ancestry for manifest root %s\n",
                                    root->id);
                    report_failure(context, index);
                    return -1;
                }
                registered_xdg[key] = 1;
            }
        }

        DestinationIdentityPlacement discard;
        size_t conflicting_owner;
        DestinationIdentityStatus status = destination_identity_graph_add(
            graph, anchor, relative, view.claim, index,
            view.placement == NULL ? &discard : view.placement,
            &conflicting_owner);
        if (status == DESTINATION_IDENTITY_COLLISION)
        {
            char destination[PATH_MAX];
            if (destination_absolute_path_build(
                    root, logical, destination_xdg_dirs,
                    destination_home_path, destination,
                    sizeof(destination)) != 0)
                snprintf(destination, sizeof(destination), "%s", relative);

            DestinationIdentityEntryView previous;
            char previous_logical[PATH_MAX];
            if (conflicting_owner < entry_count)
                reader(context, conflicting_owner, &previous);
            if (conflicting_owner < entry_count &&
                previous.root_index < (size_t)manifest->root_count &&
                destination_identity_logical_copy(
                    &previous, previous_logical) == 0)
                print_error("Error: Manifest root %s entry %s and manifest root %s entry %s map to the same restore destination: %s\n",
                            manifest->roots[previous.root_index].id,
                            previous_logical[0] == '\0' ? "." :
                                previous_logical,
                            root->id, logical[0] == '\0' ? "." : logical,
                            destination);
            else
                print_error("Error: Manifest root %s entry %s conflicts with an existing directory at restore destination: %s\n",
                            root->id, logical[0] == '\0' ? "." : logical,
                            destination);
            report_failure(context, index);
            if (collision_policy == DESTINATION_IDENTITY_STOP_ON_COLLISION)
                return -1;
            continue;
        }
        if (status != DESTINATION_IDENTITY_OK)
        {
            if (status == DESTINATION_IDENTITY_RESOURCE_ERROR &&
                errno == E2BIG)
                print_error("Error: Portable restore destination identity budget exceeded while mapping manifest root %s entry %s\n",
                            root->id, logical[0] == '\0' ? "." : logical);
            else
                print_error("Error: Could not inspect mapped restore destination for manifest root %s entry %s\n",
                            root->id, logical[0] == '\0' ? "." : logical);
            report_failure(context, index);
            return -1;
        }
    }
    return 0;
}

DestinationIdentityStatus destination_identity_graph_finalize(
    DestinationIdentityGraph *graph, int *nested_claims_out)
{
    if (nested_claims_out != NULL)
        *nested_claims_out = 0;
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
    unsigned char *claimed_ancestor = nested_claims_out == NULL ? NULL :
        preflight_alloc(&graph->memory, graph->node_count);
    size_t *next = edge_capacity == 0 ? NULL :
                   preflight_alloc(&graph->memory, edge_bytes);
    size_t *child = edge_capacity == 0 ? NULL :
                    preflight_alloc(&graph->memory, edge_bytes);
    if (indegree == NULL || first == NULL || queue == NULL ||
        (nested_claims_out != NULL && claimed_ancestor == NULL) ||
        (edge_capacity != 0 && (next == NULL || child == NULL)))
    {
        preflight_free(&graph->memory, indegree, node_bytes);
        preflight_free(&graph->memory, first, node_bytes);
        preflight_free(&graph->memory, queue, node_bytes);
        preflight_free(&graph->memory, claimed_ancestor, graph->node_count);
        preflight_free(&graph->memory, next, edge_bytes);
        preflight_free(&graph->memory, child, edge_bytes);
        return DESTINATION_IDENTITY_RESOURCE_ERROR;
    }
    memset(indegree, 0, node_bytes);
    if (claimed_ancestor != NULL)
        memset(claimed_ancestor, 0, graph->node_count);
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

    DestinationFixedSlot *topology = graph->topology_slots;
    for (size_t i = 0; i < graph->topology_capacity; i++)
        if (topology[i].used)
        {
            size_t parent = (size_t)topology[i].key_a;
            size_t destination = (size_t)topology[i].key_b;
            if (parent >= graph->node_count ||
                destination >= graph->node_count ||
                indegree[destination] == SIZE_MAX)
            {
                errno = E2BIG;
                goto resource_fail;
            }
            indegree[destination]++;
            child[edge_count] = destination;
            next[edge_count] = first[parent];
            first[parent] = edge_count++;
        }

    size_t head = 0;
    size_t tail = 0;
    for (size_t i = 0; i < graph->node_count; i++)
        if (indegree[i] == 0)
            queue[tail++] = i;

    DestinationIdentityNode *nodes = graph->nodes;
    size_t ordered = 0;
    int nested_claims = 0;
    while (head < tail)
    {
        size_t node = queue[head++];
        nodes[node].topo_order = ordered++;
        int carries_claim = claimed_ancestor != NULL &&
            (claimed_ancestor[node] ||
             nodes[node].metadata_owner != SIZE_MAX);
        for (size_t edge = first[node]; edge != SIZE_MAX; edge = next[edge])
        {
            size_t destination = child[edge];
            if (carries_claim)
            {
                if (nodes[destination].metadata_owner != SIZE_MAX)
                    nested_claims = 1;
                claimed_ancestor[destination] = 1;
            }
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
    if (claimed_ancestor != NULL)
        for (size_t i = 0; i < graph->namespace_capacity; i++)
            if (slots[i].used && slots[i].non_directory_owner != SIZE_MAX)
            {
                if (slots[i].parent >= graph->node_count)
                {
                    errno = EINVAL;
                    goto resource_fail;
                }
                size_t parent = slots[i].parent;
                if (claimed_ancestor[parent] ||
                    nodes[parent].metadata_owner != SIZE_MAX)
                    nested_claims = 1;
            }

    preflight_free(&graph->memory, indegree, node_bytes);
    preflight_free(&graph->memory, first, node_bytes);
    preflight_free(&graph->memory, queue, node_bytes);
    preflight_free(&graph->memory, claimed_ancestor, graph->node_count);
    preflight_free(&graph->memory, next, edge_bytes);
    preflight_free(&graph->memory, child, edge_bytes);
    if (ordered != graph->node_count)
    {
        errno = ELOOP;
        return DESTINATION_IDENTITY_CYCLE;
    }
    graph->finalized = 1;
    if (nested_claims_out != NULL)
        *nested_claims_out = nested_claims;
    return DESTINATION_IDENTITY_OK;

resource_fail:
    preflight_free(&graph->memory, indegree, node_bytes);
    preflight_free(&graph->memory, first, node_bytes);
    preflight_free(&graph->memory, queue, node_bytes);
    preflight_free(&graph->memory, claimed_ancestor, graph->node_count);
    preflight_free(&graph->memory, next, edge_bytes);
    preflight_free(&graph->memory, child, edge_bytes);
    return DESTINATION_IDENTITY_RESOURCE_ERROR;
}

int destination_identity_graph_resume(DestinationIdentityGraph *graph)
{
    if (graph == NULL || !graph->finalized)
    {
        errno = EINVAL;
        return -1;
    }
    graph->finalized = 0;
    return 0;
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
                   graph->identity_capacity * sizeof(DestinationFixedSlot));
    preflight_free(&graph->memory, graph->namespace_slots,
                   graph->namespace_capacity * sizeof(DestinationNamespaceSlot));
    preflight_free(&graph->memory, graph->topology_slots,
                   graph->topology_capacity * sizeof(DestinationFixedSlot));
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
