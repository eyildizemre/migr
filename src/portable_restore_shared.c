#define _GNU_SOURCE

#include "portable_restore_internal.h"
#include "portable.h"
#include "encoding.h"
#include "hash.h"
#include "manifest.h"
#include "sidecar.h"
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
