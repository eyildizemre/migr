#define _GNU_SOURCE

#include "portable_restore_internal.h"
#include "portable.h"
#include "portable_name.h"
#include "hash.h"
#include "manifest.h"
#include "sidecar.h"
#include "utils.h"
#include "xdg.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

static int sidecar_bytes_equal(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 ||
            memcmp(left.data, right.data, left.length) == 0);
}

static int logical_parent_and_leaf(SidecarBytes logical,
                                   SidecarBytes *parent_out,
                                   SidecarBytes *leaf_out)
{
    if (parent_out == NULL || leaf_out == NULL ||
        !sidecar_path_valid(logical, 1))
        return 0;
    *parent_out = (SidecarBytes){0};
    *leaf_out = (SidecarBytes){0};
    if (logical.length == 0)
        return 1;

    size_t leaf_start = 0;
    for (size_t index = logical.length; index > 0; index--)
        if (logical.data[index - 1U] == '/')
        {
            leaf_start = index;
            break;
        }
    parent_out->data = logical.data;
    parent_out->length = leaf_start == 0 ? 0 : leaf_start - 1U;
    leaf_out->data = logical.data + leaf_start;
    leaf_out->length = logical.length - leaf_start;
    return leaf_out->length != 0 && leaf_out->length <= NAME_MAX;
}

#ifdef PORTABLE_RESTORE_ADDRESS_TEST_HOOKS
static int restore_address_forced_fingerprint;
static uint64_t restore_address_fingerprint;

void restore_address_test_force_name_fingerprint(uint64_t fingerprint)
{
    restore_address_forced_fingerprint = 1;
    restore_address_fingerprint = fingerprint;
}

void restore_address_test_clear_name_fingerprint(void)
{
    restore_address_forced_fingerprint = 0;
    restore_address_fingerprint = 0;
}
#endif

static int restore_name_map(const char *logical_leaf, uint64_t collision_number,
                            PortablePhysicalName *mapped)
{
#ifdef PORTABLE_RESTORE_ADDRESS_TEST_HOOKS
    if (restore_address_forced_fingerprint)
        return portable_physical_name_map_with_fingerprint_for_test(
            logical_leaf, collision_number, restore_address_fingerprint, mapped);
#endif
    return portable_physical_name_map(logical_leaf, collision_number, mapped);
}

int restore_entry_physical_leaf_authentic(const SidecarEntry *entry)
{
    if (entry == NULL || !sidecar_path_valid(entry->logical_path, 1) ||
        !sidecar_physical_leaf_valid(entry->logical_path,
                                     entry->physical_leaf))
        return 0;
    if (entry->logical_path.length == 0)
        return entry->collision_suffix.length == 0;

    SidecarBytes logical_parent = {0};
    SidecarBytes logical_leaf = {0};
    if (!logical_parent_and_leaf(entry->logical_path, &logical_parent,
                                 &logical_leaf))
        return 0;
    (void)logical_parent;

    uint64_t collision_number = 0;
    if (entry->collision_suffix.length != 0 &&
        !portable_collision_suffix_parse(
            (const char *)entry->collision_suffix.data,
            entry->collision_suffix.length, &collision_number))
        return 0;

    char logical_leaf_text[NAME_MAX + 1U];
    memcpy(logical_leaf_text, logical_leaf.data, logical_leaf.length);
    logical_leaf_text[logical_leaf.length] = '\0';
    PortablePhysicalName mapped;
    if (restore_name_map(logical_leaf_text, collision_number, &mapped) != 0)
        return 0;

    SidecarBytes mapped_leaf = {
        .data = (const unsigned char *)mapped.physical_leaf,
        .length = strlen(mapped.physical_leaf)
    };
    SidecarBytes mapped_suffix = {
        .data = (const unsigned char *)mapped.collision_suffix,
        .length = strlen(mapped.collision_suffix)
    };
    return sidecar_bytes_equal(mapped_leaf, entry->physical_leaf) &&
           sidecar_bytes_equal(mapped_suffix, entry->collision_suffix);
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

static int restore_root_id_valid(SidecarBytes root_id)
{
    return root_id.length != 0 && root_id.length <= SIDECAR_MAX_ROOT_ID &&
           root_id.data != NULL &&
           memchr(root_id.data, '\0', root_id.length) == NULL;
}

static uint64_t restore_address_logical_hash(const RestoreAddressIndex *index,
                                             SidecarBytes root_id,
                                             SidecarBytes logical_path)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ index->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)root_id.length);
    hash = hash_fnv1a_bytes(hash, root_id.data, root_id.length);
    hash = hash_fnv1a_uint64(hash, (uint64_t)logical_path.length);
    return hash_fnv1a_bytes(hash, logical_path.data, logical_path.length);
}

static uint64_t restore_address_physical_hash(const RestoreAddressIndex *index,
                                              SidecarBytes root_id,
                                              SidecarBytes logical_parent,
                                              SidecarBytes physical_leaf)
{
    uint64_t hash = restore_address_logical_hash(index, root_id,
                                                 logical_parent);
    hash = hash_fnv1a_uint64(hash, (uint64_t)physical_leaf.length);
    return hash_fnv1a_bytes(hash, physical_leaf.data, physical_leaf.length);
}

static int restore_address_capacity(size_t expected, size_t *out)
{
    if (out == NULL || expected > SIDECAR_MAX_LIVE_ENTRIES ||
        expected > SIZE_MAX / 2U)
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
    *out = capacity;
    return 0;
}

static int restore_address_index_init(RestoreAddressIndex *index,
                                      PreflightMemory *memory,
                                      size_t expected)
{
    if (index == NULL || memory == NULL || expected > SIDECAR_MAX_LIVE_ENTRIES)
    {
        errno = expected > SIDECAR_MAX_LIVE_ENTRIES ? E2BIG : EINVAL;
        return -1;
    }
    memset(index, 0, sizeof(*index));
    index->hash_salt = sidecar_process_salt();
    if (expected == 0)
        return 0;
    if (expected > SIZE_MAX / sizeof(*index->entries))
    {
        errno = E2BIG;
        return -1;
    }
    index->entries = preflight_alloc(memory,
                                     expected * sizeof(*index->entries));
    if (index->entries == NULL)
        return -1;
    memset(index->entries, 0, expected * sizeof(*index->entries));
    index->capacity = expected;

    size_t table_capacity = 0;
    if (restore_address_capacity(expected, &table_capacity) != 0 ||
        table_capacity > SIZE_MAX / sizeof(*index->logical_slots))
    {
        errno = E2BIG;
        restore_address_index_free(memory, index);
        return -1;
    }
    size_t table_size = table_capacity * sizeof(*index->logical_slots);
    index->logical_capacity = table_capacity;
    index->physical_capacity = table_capacity;
    index->logical_slots = preflight_alloc(memory, table_size);
    index->physical_slots = preflight_alloc(memory, table_size);
    if (index->logical_slots == NULL || index->physical_slots == NULL)
    {
        int saved = errno;
        restore_address_index_free(memory, index);
        errno = saved;
        return -1;
    }
    memset(index->logical_slots, 0, table_size);
    memset(index->physical_slots, 0, table_size);
    return 0;
}

void restore_address_index_free(PreflightMemory *memory,
                                RestoreAddressIndex *index)
{
    if (index == NULL)
        return;
    preflight_free(memory, index->entries,
                   index->capacity * sizeof(*index->entries));
    preflight_free(memory, index->logical_slots,
                   index->logical_capacity * sizeof(*index->logical_slots));
    preflight_free(memory, index->physical_slots,
                   index->physical_capacity * sizeof(*index->physical_slots));
    memset(index, 0, sizeof(*index));
}

int restore_address_index_find_logical(const RestoreAddressIndex *index,
                                       SidecarBytes root_id,
                                       SidecarBytes logical_path,
                                       size_t *entry_index_out)
{
    if (entry_index_out == NULL || !restore_root_id_valid(root_id) ||
        !sidecar_path_valid(logical_path, 1))
    {
        errno = EINVAL;
        return -1;
    }
    *entry_index_out = SIZE_MAX;
    if (index == NULL || index->logical_capacity == 0 ||
        index->logical_slots == NULL)
        return 0;

    size_t slot_index = (size_t)restore_address_logical_hash(
        index, root_id, logical_path) & (index->logical_capacity - 1U);
    for (size_t probes = 0; probes < index->logical_capacity; probes++)
    {
        const RestoreAddressSlot *slot = &index->logical_slots[slot_index];
        if (!slot->used)
            return 0;
        if (slot->entry_index >= index->count)
        {
            errno = EINVAL;
            return -1;
        }
        const SidecarEntry *entry = index->entries[slot->entry_index].entry;
        if (entry != NULL && sidecar_bytes_equal(entry->root_id, root_id) &&
            sidecar_bytes_equal(entry->logical_path, logical_path))
        {
            *entry_index_out = slot->entry_index;
            return 1;
        }
        slot_index = (slot_index + 1U) & (index->logical_capacity - 1U);
    }
    return 0;
}

int restore_address_index_find_physical(const RestoreAddressIndex *index,
                                        SidecarBytes root_id,
                                        SidecarBytes logical_parent,
                                        SidecarBytes physical_leaf,
                                        size_t *entry_index_out)
{
    if (entry_index_out == NULL || !restore_root_id_valid(root_id) ||
        !sidecar_path_valid(logical_parent, 1) ||
        physical_leaf.length == 0 ||
        physical_leaf.length > SIDECAR_MAX_PHYSICAL_LEAF ||
        physical_leaf.data == NULL ||
        !portable_component_valid((const char *)physical_leaf.data,
                                  physical_leaf.length))
    {
        errno = EINVAL;
        return -1;
    }
    *entry_index_out = SIZE_MAX;
    if (index == NULL || index->physical_capacity == 0 ||
        index->physical_slots == NULL)
        return 0;

    size_t slot_index = (size_t)restore_address_physical_hash(
        index, root_id, logical_parent, physical_leaf) &
        (index->physical_capacity - 1U);
    for (size_t probes = 0; probes < index->physical_capacity; probes++)
    {
        const RestoreAddressSlot *slot = &index->physical_slots[slot_index];
        if (!slot->used)
            return 0;
        if (slot->entry_index >= index->count)
        {
            errno = EINVAL;
            return -1;
        }
        const RestoreAddressEntry *address = &index->entries[slot->entry_index];
        const SidecarEntry *entry = address->entry;
        if (entry != NULL && sidecar_bytes_equal(entry->root_id, root_id) &&
            sidecar_bytes_equal(address->logical_parent, logical_parent) &&
            sidecar_bytes_equal(entry->physical_leaf, physical_leaf))
        {
            *entry_index_out = slot->entry_index;
            return 1;
        }
        slot_index = (slot_index + 1U) & (index->physical_capacity - 1U);
    }
    return 0;
}

static int restore_address_insert_logical(RestoreAddressIndex *index,
                                          size_t entry_index)
{
    const SidecarEntry *entry = index->entries[entry_index].entry;
    size_t existing = SIZE_MAX;
    int found = restore_address_index_find_logical(
        index, entry->root_id, entry->logical_path, &existing);
    if (found != 0)
    {
        errno = found < 0 ? errno : EINVAL;
        return -1;
    }
    size_t slot_index = (size_t)restore_address_logical_hash(
        index, entry->root_id, entry->logical_path) &
        (index->logical_capacity - 1U);
    for (size_t probes = 0; probes < index->logical_capacity; probes++)
    {
        RestoreAddressSlot *slot = &index->logical_slots[slot_index];
        if (!slot->used)
        {
            slot->used = 1;
            slot->entry_index = entry_index;
            return 0;
        }
        slot_index = (slot_index + 1U) & (index->logical_capacity - 1U);
    }
    errno = E2BIG;
    return -1;
}

static int restore_address_insert_physical(RestoreAddressIndex *index,
                                           size_t entry_index)
{
    const RestoreAddressEntry *address = &index->entries[entry_index];
    const SidecarEntry *entry = address->entry;
    size_t existing = SIZE_MAX;
    int found = restore_address_index_find_physical(
        index, entry->root_id, address->logical_parent,
        entry->physical_leaf, &existing);
    if (found != 0)
    {
        errno = found < 0 ? errno : EINVAL;
        return -1;
    }
    size_t slot_index = (size_t)restore_address_physical_hash(
        index, entry->root_id, address->logical_parent,
        entry->physical_leaf) & (index->physical_capacity - 1U);
    for (size_t probes = 0; probes < index->physical_capacity; probes++)
    {
        RestoreAddressSlot *slot = &index->physical_slots[slot_index];
        if (!slot->used)
        {
            slot->used = 1;
            slot->entry_index = entry_index;
            return 0;
        }
        slot_index = (slot_index + 1U) & (index->physical_capacity - 1U);
    }
    errno = E2BIG;
    return -1;
}

static int restore_address_index_finalize(
    RestoreAddressIndex *index, const SidecarEntry **failure_entry_out)
{
    if (failure_entry_out != NULL)
        *failure_entry_out = NULL;
    if (index == NULL || index->count > index->capacity)
    {
        errno = EINVAL;
        return -1;
    }
    for (size_t entry_index = 0; entry_index < index->count; entry_index++)
    {
        RestoreAddressEntry *address = &index->entries[entry_index];
        const SidecarEntry *entry = address->entry;
        SidecarBytes logical_leaf = {0};
        if (entry == NULL || !restore_root_id_valid(entry->root_id) ||
            !logical_parent_and_leaf(entry->logical_path,
                                     &address->logical_parent,
                                     &logical_leaf) ||
            !restore_entry_physical_leaf_authentic(entry) ||
            restore_address_insert_logical(index, entry_index) != 0)
        {
            if (failure_entry_out != NULL)
                *failure_entry_out = entry;
            errno = errno == 0 ? EINVAL : errno;
            return -1;
        }
    }

    for (size_t entry_index = 0; entry_index < index->count; entry_index++)
    {
        RestoreAddressEntry *address = &index->entries[entry_index];
        const SidecarEntry *entry = address->entry;
        if (entry->logical_path.length == 0)
            continue;
        size_t parent_index = SIZE_MAX;
        int found = restore_address_index_find_logical(
            index, entry->root_id, address->logical_parent, &parent_index);
        if (found != 1 || parent_index >= index->count ||
            index->entries[parent_index].entry == NULL ||
            index->entries[parent_index].entry->kind != SIDECAR_KIND_DIRECTORY ||
            restore_address_insert_physical(index, entry_index) != 0)
        {
            if (failure_entry_out != NULL)
                *failure_entry_out = entry;
            errno = found < 0 ? errno : EINVAL;
            return -1;
        }
    }
    return 0;
}

int restore_address_index_entry_valid(const RestoreAddressIndex *index,
                                      const SidecarEntry *entry,
                                      size_t *entry_index_out)
{
    if (entry == NULL || entry_index_out == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    *entry_index_out = SIZE_MAX;
    size_t entry_index = SIZE_MAX;
    int found = restore_address_index_find_logical(
        index, entry->root_id, entry->logical_path, &entry_index);
    if (found != 1)
        return found;
    if (entry_index >= index->count || index->entries[entry_index].entry != entry)
        return 0;
    *entry_index_out = entry_index;
    return 1;
}

typedef struct {
    RestoreAddressIndex *index;
} RestoreAddressCollect;

static int restore_address_collect(const SidecarLiveView *view, void *argument)
{
    RestoreAddressCollect *collect = argument;
    if (collect == NULL || collect->index == NULL || view == NULL ||
        view->entry == NULL || collect->index->count >= collect->index->capacity)
    {
        errno = EINVAL;
        return 1;
    }
    collect->index->entries[collect->index->count++].entry = view->entry;
    return 0;
}

int restore_address_index_build(RestoreAddressIndex *index,
                                PreflightMemory *memory, SidecarLog *sidecar,
                                const SidecarEntry **failure_entry_out)
{
    if (failure_entry_out != NULL)
        *failure_entry_out = NULL;
    if (index == NULL || memory == NULL || sidecar == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    size_t live_count = sidecar_log_live_count(sidecar);
    if (restore_address_index_init(index, memory, live_count) != 0)
        return -1;
    RestoreAddressCollect collect = { .index = index };
    SidecarStatus status = sidecar_log_foreach(sidecar, restore_address_collect,
                                               &collect);
    if (status != SIDECAR_STATUS_OK || index->count != live_count ||
        restore_address_index_finalize(index, failure_entry_out) != 0)
    {
        int saved = errno;
        restore_address_index_free(memory, index);
        errno = saved == 0 ? EIO : saved;
        return -1;
    }
    return 0;
}

#ifdef PORTABLE_RESTORE_ADDRESS_TEST_HOOKS
int restore_address_index_build_from_entries_for_test(
    RestoreAddressIndex *index, PreflightMemory *memory,
    const SidecarEntry *entries, size_t count)
{
    if (index == NULL || memory == NULL || (entries == NULL && count != 0))
    {
        errno = EINVAL;
        return -1;
    }
    if (restore_address_index_init(index, memory, count) != 0)
        return -1;
    for (size_t entry_index = 0; entry_index < count; entry_index++)
        index->entries[index->count++].entry = &entries[entry_index];
    if (restore_address_index_finalize(index, NULL) != 0)
    {
        int saved = errno;
        restore_address_index_free(memory, index);
        errno = saved;
        return -1;
    }
    return 0;
}
#endif

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
    size_t owner;
    char *component;
    size_t component_length;
    uint64_t hash;
    size_t name_member;
    int resolved;
    int existing_on_disk;
    int used;
} DestinationNamespaceSlot;

/* Candidate lookup is keyed by the parent plus ASCII-folded component. The
 * chained members preserve all exact spellings in a folded class; the
 * filesystem capability check below remains the authority on equivalence. */
typedef struct {
    size_t parent;
    size_t head_member;
    const char *component;
    size_t component_length;
    uint64_t hash;
    int used;
} DestinationNameSlot;

typedef struct {
    const char *component;
    size_t component_length;
    size_t next;
} DestinationNameMember;

#ifdef PORTABLE_RESTORE_ADDRESS_TEST_HOOKS
static size_t destination_identity_test_name_probe_counter;
static int destination_identity_test_casefold_forced;

void destination_identity_test_reset_name_probe_count(void)
{
    destination_identity_test_name_probe_counter = 0;
}

size_t destination_identity_test_name_probe_count(void)
{
    return destination_identity_test_name_probe_counter;
}

void destination_identity_test_force_casefold(int enabled)
{
    destination_identity_test_casefold_forced = enabled != 0;
}
#endif

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

static unsigned char destination_ascii_fold(unsigned char value)
{
    if (value >= 'A' && value <= 'Z')
        return (unsigned char)(value + ('a' - 'A'));
    return value;
}

static uint64_t destination_name_hash(const DestinationIdentityGraph *graph,
                                      size_t parent, const char *component,
                                      size_t length)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ graph->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)parent);
    hash = hash_fnv1a_uint64(hash, (uint64_t)length);
    for (size_t index = 0; index < length; index++)
    {
        unsigned char folded = destination_ascii_fold(
            (unsigned char)component[index]);
        hash = hash_fnv1a_bytes(hash, &folded, 1U);
    }
    return hash;
}

static int destination_names_fold_equal(const char *first, size_t first_length,
                                        const char *second,
                                        size_t second_length)
{
    if (first == NULL || second == NULL || first_length != second_length)
        return 0;
    for (size_t index = 0; index < first_length; index++)
        if (destination_ascii_fold((unsigned char)first[index]) !=
            destination_ascii_fold((unsigned char)second[index]))
            return 0;
    return 1;
}

static DestinationIdentityStatus destination_graph_path_error(int saved);

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

static int destination_name_rehash(DestinationIdentityGraph *graph,
                                   size_t capacity)
{
    if (capacity < 32U || (capacity & (capacity - 1U)) != 0 ||
        capacity > SIZE_MAX / sizeof(DestinationNameSlot))
    {
        errno = E2BIG;
        return -1;
    }

    size_t new_size = capacity * sizeof(DestinationNameSlot);
    DestinationNameSlot *slots = preflight_alloc(&graph->memory, new_size);
    if (slots == NULL)
        return -1;
    memset(slots, 0, new_size);

    DestinationNameSlot *old = graph->name_slots;
    size_t old_capacity = graph->name_capacity;
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
                   old_capacity * sizeof(DestinationNameSlot));
    graph->name_slots = slots;
    graph->name_capacity = capacity;
    return 0;
}

static int destination_name_ensure(DestinationIdentityGraph *graph)
{
    if (graph->name_capacity == 0)
        return destination_name_rehash(graph, 32U);
    if (graph->name_count * 2U < graph->name_capacity)
        return 0;
    if (graph->name_capacity > SIZE_MAX / 2U)
    {
        errno = E2BIG;
        return -1;
    }
    return destination_name_rehash(graph, graph->name_capacity * 2U);
}

static DestinationNameSlot *destination_name_slot_find(
    const DestinationIdentityGraph *graph, size_t parent,
    const char *component, size_t length, uint64_t hash)
{
    DestinationNameSlot *slots = graph->name_slots;
    if (graph->name_capacity == 0)
        return NULL;

    size_t index = (size_t)hash & (graph->name_capacity - 1U);
    while (slots[index].used)
    {
        if (slots[index].hash == hash && slots[index].parent == parent &&
            slots[index].component_length == length &&
            destination_names_fold_equal(
                slots[index].component, slots[index].component_length,
                component, length))
            return &slots[index];
        index = (index + 1U) & (graph->name_capacity - 1U);
    }
    return NULL;
}

static int destination_name_index_add(DestinationIdentityGraph *graph,
                                      size_t parent, const char *component,
                                      size_t length, size_t *member_out)
{
    if (graph == NULL || component == NULL || member_out == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (graph->name_member_count >= graph->namespace_limit)
    {
        errno = E2BIG;
        return -1;
    }

    uint64_t hash = destination_name_hash(graph, parent, component, length);
    DestinationNameSlot *name_slot = destination_name_slot_find(
        graph, parent, component, length, hash);
    if (name_slot == NULL)
    {
        if (destination_name_ensure(graph) != 0)
            return -1;
        name_slot = destination_name_slot_find(
            graph, parent, component, length, hash);
    }

    DestinationNameMember *members = preflight_array_reserve(
        &graph->memory, graph->name_members, &graph->name_member_capacity,
        graph->name_member_count, 1U, sizeof(*members), 32U,
        graph->namespace_limit, 0);
    if (members == NULL)
        return -1;
    graph->name_members = members;

    if (name_slot == NULL)
    {
        DestinationNameSlot *slots = graph->name_slots;
        size_t index = (size_t)hash & (graph->name_capacity - 1U);
        while (slots[index].used)
            index = (index + 1U) & (graph->name_capacity - 1U);
        slots[index] = (DestinationNameSlot){
            .parent = parent,
            .head_member = SIZE_MAX,
            .component = component,
            .component_length = length,
            .hash = hash,
            .used = 1
        };
        name_slot = &slots[index];
        graph->name_count++;
    }

    size_t member_index = graph->name_member_count++;
    members[member_index] = (DestinationNameMember){
        .component = component,
        .component_length = length,
        .next = name_slot->head_member
    };
    name_slot->head_member = member_index;
    *member_out = member_index;
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

static DestinationNamespaceSlot *destination_namespace_find(
    const DestinationIdentityGraph *graph, size_t parent,
    const char *component, size_t length)
{
    if (graph == NULL || component == NULL || graph->namespace_capacity == 0)
        return NULL;

    uint64_t hash = destination_namespace_hash(graph, parent, component, length);
    DestinationNamespaceSlot *slots = graph->namespace_slots;
    size_t index = (size_t)hash & (graph->namespace_capacity - 1U);
    while (slots[index].used)
    {
        if (slots[index].hash == hash && slots[index].parent == parent &&
            slots[index].component_length == length &&
            memcmp(slots[index].component, component, length) == 0)
            return &slots[index];
        index = (index + 1U) & (graph->namespace_capacity - 1U);
    }
    return NULL;
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

    DestinationNamespaceSlot *found = destination_namespace_find(
        graph, parent, component, length);
    if (found != NULL)
        return found;
    if (graph->namespace_count >= graph->namespace_limit)
    {
        errno = E2BIG;
        return NULL;
    }
    if (destination_namespace_ensure(graph) != 0)
        return NULL;

    uint64_t hash = destination_namespace_hash(graph, parent, component, length);
    DestinationNamespaceSlot *slots = graph->namespace_slots;
    size_t index = (size_t)hash & (graph->namespace_capacity - 1U);
    while (slots[index].used)
        index = (index + 1U) & (graph->namespace_capacity - 1U);
    char *copy = preflight_alloc(&graph->memory, length + 1U);
    if (copy == NULL)
        return NULL;
    memcpy(copy, component, length);
    copy[length] = '\0';

    size_t name_member = SIZE_MAX;
    if (destination_name_index_add(graph, parent, copy, length,
                                   &name_member) != 0)
    {
        int saved = errno;
        preflight_free(&graph->memory, copy, length + 1U);
        errno = saved;
        return NULL;
    }
    slots[index] = (DestinationNamespaceSlot){
        .parent = parent,
        .child = SIZE_MAX,
        .non_directory_owner = SIZE_MAX,
        .owner = SIZE_MAX,
        .component = copy,
        .component_length = length,
        .hash = hash,
        .name_member = name_member,
        .resolved = 0,
        .existing_on_disk = 0,
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

/* This is only a conservative trigger. It never decides that two names are
 * equal: the directory's kernel-reported lookup capability makes that
 * decision boundary explicit below. Keeping the trigger ASCII-only avoids
 * pretending that this restore path implements Unicode collation. */
static int destination_names_may_casefold(const char *first, size_t first_length,
                                          const char *second,
                                          size_t second_length)
{
    if (first == NULL || second == NULL || first_length != second_length)
        return 0;
    return memcmp(first, second, first_length) != 0 &&
           destination_names_fold_equal(first, first_length,
                                        second, second_length);
}

static int destination_name_conflict_slot(
    const DestinationIdentityGraph *graph, size_t parent,
    const DestinationNamespaceSlot *current,
    DestinationNamespaceSlot **conflict_out)
{
    if (graph == NULL || current == NULL || conflict_out == NULL ||
        current->name_member == SIZE_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    *conflict_out = NULL;

    uint64_t hash = destination_name_hash(
        graph, parent, current->component, current->component_length);
    DestinationNameSlot *name_slot = destination_name_slot_find(
        graph, parent, current->component, current->component_length, hash);
    if (name_slot == NULL)
    {
        errno = ESTALE;
        return -1;
    }

    DestinationNameMember *members = graph->name_members;
    for (size_t member_index = name_slot->head_member;
         member_index != SIZE_MAX;
         member_index = members[member_index].next)
    {
        if (member_index >= graph->name_member_count)
        {
            errno = ESTALE;
            return -1;
        }
#ifdef PORTABLE_RESTORE_ADDRESS_TEST_HOOKS
        if (destination_identity_test_name_probe_counter != SIZE_MAX)
            destination_identity_test_name_probe_counter++;
#endif
        if (member_index == current->name_member)
            continue;
        DestinationNameMember *member = &members[member_index];
        DestinationNamespaceSlot *candidate = destination_namespace_find(
            graph, parent, member->component, member->component_length);
        if (candidate == NULL)
        {
            errno = ESTALE;
            return -1;
        }
        if (candidate == current || !candidate->resolved ||
            (candidate->existing_on_disk && current->existing_on_disk) ||
            !destination_names_may_casefold(
                candidate->component, candidate->component_length,
                current->component, current->component_length))
            continue;
        *conflict_out = candidate;
        return 0;
    }
    return 0;
}

static DestinationIdentityStatus destination_name_equivalence_check(
    const DestinationIdentityGraph *graph, size_t parent,
    const DestinationNamespaceSlot *current, int nearest_existing_fd,
    DestinationIdentityNameConflict *conflict)
{
    DestinationNamespaceSlot *candidate = NULL;
    if (destination_name_conflict_slot(graph, parent, current,
                                       &candidate) != 0)
        return destination_graph_path_error(errno);
    if (candidate == NULL)
        return DESTINATION_IDENTITY_OK;

    *conflict = (DestinationIdentityNameConflict){
        .owner = candidate->owner,
        .prior_component = candidate->component,
        .prior_component_length = candidate->component_length,
        .current_component = current->component,
        .current_component_length = current->component_length,
        .failure = DESTINATION_NAME_FAILURE_UNKNOWN
    };

#ifdef PORTABLE_RESTORE_ADDRESS_TEST_HOOKS
    if (destination_identity_test_casefold_forced)
    {
        conflict->failure = DESTINATION_NAME_FAILURE_CASEFOLD;
        errno = EOPNOTSUPP;
        return DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR;
    }
#endif

    if (nearest_existing_fd < 0)
    {
        errno = EIO;
        return DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR;
    }

    unsigned long flags = 0;
    if (ioctl(nearest_existing_fd, FS_IOC_GETFLAGS, &flags) != 0)
        return DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR;
    if ((flags & (unsigned long)FS_CASEFOLD_FL) == 0)
        return DESTINATION_IDENTITY_OK;

    conflict->failure = DESTINATION_NAME_FAILURE_CASEFOLD;
    errno = EOPNOTSUPP;
    return DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR;
}

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

static int destination_route_fds_close(int *current_fd,
                                       int *nearest_existing_fd)
{
    int saved = 0;
    if (current_fd != NULL && *current_fd >= 0)
    {
        if (close(*current_fd) != 0 && saved == 0)
            saved = errno;
        *current_fd = -1;
    }
    if (nearest_existing_fd != NULL && *nearest_existing_fd >= 0)
    {
        if (close(*nearest_existing_fd) != 0 && saved == 0)
            saved = errno;
        *nearest_existing_fd = -1;
    }
    if (saved != 0)
    {
        errno = saved;
        return -1;
    }
    return 0;
}

DestinationIdentityStatus destination_identity_graph_add(
    DestinationIdentityGraph *graph, int anchor_fd, const char *relative,
    DestinationIdentityClaim claim, size_t owner,
    DestinationIdentityPlacement *placement,
    size_t *conflicting_owner,
    DestinationIdentityNameConflict *name_conflict)
{
    if (conflicting_owner != NULL)
        *conflicting_owner = SIZE_MAX;
    if (name_conflict != NULL)
        *name_conflict = (DestinationIdentityNameConflict){
            .owner = SIZE_MAX
        };
    if (graph == NULL || anchor_fd < 0 || relative == NULL ||
        placement == NULL || conflicting_owner == NULL ||
        name_conflict == NULL || graph->finalized ||
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
    int nearest_existing_fd = -1;

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
            if (current_fd >= 0)
                close(current_fd);
            if (nearest_existing_fd >= 0)
                close(nearest_existing_fd);
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
            if (nearest_existing_fd >= 0)
                close(nearest_existing_fd);
            return destination_graph_path_error(saved);
        }
        if (slot->owner == SIZE_MAX)
            slot->owner = owner;
        if (slot->non_directory_owner != SIZE_MAX)
        {
            *conflicting_owner = slot->non_directory_owner;
            if (current_fd >= 0)
                close(current_fd);
            if (nearest_existing_fd >= 0)
                close(nearest_existing_fd);
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
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
                    errno = ESTALE;
                    return DESTINATION_IDENTITY_PATH_ERROR;
                }
                if (nodes[slot->child].metadata_owner != SIZE_MAX)
                    *conflicting_owner =
                        nodes[slot->child].metadata_owner;
                if (current_fd >= 0)
                    close(current_fd);
                if (nearest_existing_fd >= 0)
                    close(nearest_existing_fd);
                errno = EEXIST;
                return DESTINATION_IDENTITY_COLLISION;
            }
            int existing_on_disk = 0;
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
                        if (nearest_existing_fd >= 0)
                            close(nearest_existing_fd);
                        errno = EISDIR;
                        return DESTINATION_IDENTITY_COLLISION;
                    }
                    existing_on_disk = 1;
                }
                else if (errno != ENOENT)
                {
                    int saved = errno;
                    close(current_fd);
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
                    return destination_graph_path_error(saved);
                }
            }
            slot->resolved = 1;
            slot->existing_on_disk = existing_on_disk;
            DestinationIdentityStatus name_status =
                destination_name_equivalence_check(
                    graph, current_node, slot,
                    current_fd >= 0 ? current_fd : nearest_existing_fd,
                    name_conflict);
            if (name_status != DESTINATION_IDENTITY_OK)
            {
                *conflicting_owner = name_conflict->owner;
                if (current_fd >= 0)
                    close(current_fd);
                if (nearest_existing_fd >= 0)
                    close(nearest_existing_fd);
                return name_status;
            }
            slot->non_directory_owner = owner;
            placement->node = current_node;
            placement->is_directory = 0;
            if (destination_route_fds_close(&current_fd,
                                            &nearest_existing_fd) != 0)
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
                if (nearest_existing_fd >= 0)
                    close(nearest_existing_fd);
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
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
                    return destination_graph_path_error(saved);
                }
                /* The node may already be interned through another route.
                 * Record this route's view, while keeping its fd for the
                 * descendant traversal below. */
                destination_note_mount_view(graph, child_node, next_fd);
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
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
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
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
                    return destination_graph_path_error(saved);
                }
                slot->child = child_node;
                slot->resolved = 1;
                slot->existing_on_disk = 1;
            }
            else if (errno == ENOENT)
            {
                if (destination_planned_node(graph, slot, &child_node) != 0)
                {
                    int saved = errno;
                    close(current_fd);
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
                    return destination_graph_path_error(saved);
                }
                slot->resolved = 1;
                slot->existing_on_disk = 0;
            }
            else
            {
                int saved = errno;
                close(current_fd);
                if (nearest_existing_fd >= 0)
                    close(nearest_existing_fd);
                return destination_graph_path_error(saved);
            }
        }
        else if (destination_planned_node(graph, slot, &child_node) != 0)
        {
            int saved = errno;
            if (nearest_existing_fd >= 0)
                close(nearest_existing_fd);
            return destination_graph_path_error(saved);
        }
        else
        {
            slot->resolved = 1;
            slot->existing_on_disk = 0;
        }

        DestinationIdentityStatus name_status =
            destination_name_equivalence_check(
                graph, current_node, slot,
                current_fd >= 0 ? current_fd : nearest_existing_fd,
                name_conflict);
        if (name_status != DESTINATION_IDENTITY_OK)
        {
            *conflicting_owner = name_conflict->owner;
            if (current_fd >= 0)
                close(current_fd);
            if (nearest_existing_fd >= 0)
                close(nearest_existing_fd);
            return name_status;
        }

        if (current_fd >= 0 && next_fd < 0)
        {
            nearest_existing_fd = current_fd;
            current_fd = -1;
        }
        else if (current_fd >= 0 && close(current_fd) != 0)
        {
            int saved = errno;
            if (next_fd >= 0)
                close(next_fd);
            if (nearest_existing_fd >= 0)
                close(nearest_existing_fd);
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
                    if (nearest_existing_fd >= 0)
                        close(nearest_existing_fd);
                    errno = EEXIST;
                    return DESTINATION_IDENTITY_COLLISION;
                }
                nodes[current_node].metadata_owner = owner;
            }
            placement->node = current_node;
            placement->is_directory = 1;
            if (destination_route_fds_close(&current_fd,
                                            &nearest_existing_fd) != 0)
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
    DestinationIdentityFailureReporter report_failure,
    DestinationIdentityProgressReporter report_progress, void *context,
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
        DestinationIdentityNameConflict name_conflict;
        DestinationIdentityStatus status = destination_identity_graph_add(
            graph, anchor, relative, view.claim, index,
            view.placement == NULL ? &discard : view.placement,
            &conflicting_owner, &name_conflict);
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
            if (report_progress != NULL)
                report_progress(context, index + 1U);
            continue;
        }
        if (status == DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR)
        {
            const char *reason =
                name_conflict.failure == DESTINATION_NAME_FAILURE_CASEFOLD
                    ? "casefold name lookup"
                    : "name lookup capability is unknown";
            char destination[PATH_MAX];
            if (destination_absolute_path_build(
                    root, logical, destination_xdg_dirs,
                    destination_home_path, destination,
                    sizeof(destination)) != 0)
                snprintf(destination, sizeof(destination), "%s", relative);

            DestinationIdentityEntryView previous;
            char previous_logical[PATH_MAX];
            if (name_conflict.owner < entry_count)
                reader(context, name_conflict.owner, &previous);
            if (name_conflict.owner < entry_count &&
                previous.root_index < (size_t)manifest->root_count &&
                destination_identity_logical_copy(
                    &previous, previous_logical) == 0)
                print_error("Error: Manifest root %s entry %s and manifest root %s entry %s have potentially equivalent destination names %.*s and %.*s under %s; refusing because %s\n",
                            manifest->roots[previous.root_index].id,
                            previous_logical[0] == '\0' ? "." :
                                previous_logical,
                            root->id, logical[0] == '\0' ? "." : logical,
                            (int)name_conflict.prior_component_length,
                            name_conflict.prior_component,
                            (int)name_conflict.current_component_length,
                            name_conflict.current_component,
                            destination, reason);
            else
                print_error("Error: Manifest root %s entry %s has potentially equivalent destination names %.*s and %.*s under %s; refusing because %s\n",
                            root->id, logical[0] == '\0' ? "." : logical,
                            (int)name_conflict.prior_component_length,
                            name_conflict.prior_component,
                            (int)name_conflict.current_component_length,
                            name_conflict.current_component,
                            destination, reason);
            report_failure(context, index);
            if (collision_policy == DESTINATION_IDENTITY_STOP_ON_COLLISION)
                return -1;
            if (report_progress != NULL)
                report_progress(context, index + 1U);
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
        if (report_progress != NULL)
            report_progress(context, index + 1U);
    }
    return 0;
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
                   graph->identity_capacity * sizeof(DestinationFixedSlot));
    preflight_free(&graph->memory, graph->namespace_slots,
                   graph->namespace_capacity * sizeof(DestinationNamespaceSlot));
    preflight_free(&graph->memory, graph->name_slots,
                   graph->name_capacity * sizeof(DestinationNameSlot));
    preflight_free(&graph->memory, graph->name_members,
                   graph->name_member_capacity * sizeof(DestinationNameMember));
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
