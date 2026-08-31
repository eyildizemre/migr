#define _GNU_SOURCE

#include "portable_hashset_internal.h"
#include "sidecar.h"
#include "hash.h"

#include <stdlib.h>
#include <string.h>

static uint64_t visited_hash(const PortableVisited *visited,
                             const char *root_id, size_t root_length,
                             const char *logical, size_t logical_length)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ visited->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)root_length);
    hash = hash_fnv1a_bytes(hash, (const unsigned char *)root_id,
                            root_length);
    hash = hash_fnv1a_uint64(hash, (uint64_t)logical_length);
    return hash_fnv1a_bytes(hash, (const unsigned char *)logical,
                            logical_length);
}

static size_t visited_max_capacity(void)
{
    if (SIDECAR_MAX_LIVE_ENTRIES > SIZE_MAX / 2U)
        return SIZE_MAX & ~(SIZE_MAX >> 1);
    return (size_t)SIDECAR_MAX_LIVE_ENTRIES * 2U;
}

static int visited_capacity_valid(size_t capacity)
{
    return capacity >= VISITED_INITIAL_CAPACITY &&
           (capacity & (capacity - 1U)) == 0;
}

static int visited_rehash(PortableVisited *visited, size_t new_capacity)
{
    if (visited == NULL || !visited_capacity_valid(new_capacity) ||
        new_capacity > visited_max_capacity() ||
        new_capacity > SIZE_MAX / sizeof(*visited->slots))
        return -1;

    PortableVisitedSlot *new_slots = calloc(new_capacity,
                                            sizeof(*new_slots));
    if (new_slots == NULL)
        return -1;

    for (size_t old_index = 0; old_index < visited->capacity; old_index++)
    {
        PortableVisitedSlot *old_slot = &visited->slots[old_index];
        if (old_slot->root_id == NULL)
            continue;
        size_t index = (size_t)old_slot->hash & (new_capacity - 1U);
        while (new_slots[index].root_id != NULL)
            index = (index + 1U) & (new_capacity - 1U);
        new_slots[index] = *old_slot;
    }

    free(visited->slots);
    visited->slots = new_slots;
    visited->capacity = new_capacity;
    return 0;
}

/* Returns 1 for a matching slot, 0 for an empty insertion slot, -1 if full. */
static int visited_locate(const PortableVisited *visited,
                          const char *root_id, size_t root_length,
                          const char *logical, size_t logical_length,
                          uint64_t hash, size_t *out_index)
{
    if (visited == NULL || out_index == NULL)
        return -1;
    if (visited->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)hash & (visited->capacity - 1U);
    for (size_t probes = 0; probes < visited->capacity; probes++)
    {
        visited_count_probe();
        const PortableVisitedSlot *slot = &visited->slots[index];
        if (slot->root_id == NULL)
        {
            *out_index = index;
            return 0;
        }
        if (slot->hash == hash && slot->root_length == root_length &&
            slot->logical_length == logical_length &&
            memcmp(slot->root_id, root_id, root_length) == 0 &&
            memcmp(slot->logical_path, logical, logical_length) == 0)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (visited->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

static void visited_slot_free(PortableVisitedSlot *slot)
{
    if (slot == NULL)
        return;
    free(slot->root_id);
    free(slot->logical_path);
    memset(slot, 0, sizeof(*slot));
}

int visited_reset(PortableVisited *visited)
{
    if (visited == NULL)
        return -1;
    for (size_t index = 0; index < visited->capacity; index++)
        visited_slot_free(&visited->slots[index]);
    visited->count = 0;
    return 0;
}

void visited_dispose(PortableVisited *visited)
{
    if (visited == NULL)
        return;
    visited_reset(visited);
    free(visited->slots);
    memset(visited, 0, sizeof(*visited));
}

void visited_free(PortableVisited *visited)
{
    if (visited == NULL)
        return;
    visited_dispose(visited);
    free(visited);
}

int visited_add(PortableVisited *visited, const char *root_id,
                       const char *logical)
{
    if (visited == NULL || root_id == NULL || logical == NULL)
        return -1;
    size_t root_length = strlen(root_id);
    size_t logical_length = strlen(logical);
    if (root_length == SIZE_MAX || logical_length == SIZE_MAX)
        return -1;

    uint64_t hash = visited_hash(visited, root_id, root_length, logical,
                                 logical_length);
    if (visited->capacity == 0 &&
        visited_rehash(visited, VISITED_INITIAL_CAPACITY) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = visited_locate(visited, root_id, root_length, logical,
                                  logical_length, hash, &index);
    if (location == 1)
        return 1;

    if (location < 0 || visited->count + 1U > visited->capacity / 2U)
    {
        if (visited->count >= SIDECAR_MAX_LIVE_ENTRIES ||
            visited->capacity > visited_max_capacity() / 2U ||
            visited_rehash(visited, visited->capacity * 2U) != 0)
            return -1;
        index = (size_t)hash & (visited->capacity - 1U);
        while (visited->slots[index].root_id != NULL)
            index = (index + 1U) & (visited->capacity - 1U);
    }

    char *root_copy = malloc(root_length + 1U);
    if (root_copy == NULL)
        return -1;
    char *logical_copy = malloc(logical_length + 1U);
    if (logical_copy == NULL)
    {
        free(root_copy);
        return -1;
    }
    memcpy(root_copy, root_id, root_length + 1U);
    memcpy(logical_copy, logical, logical_length + 1U);

    PortableVisitedSlot *slot = &visited->slots[index];
    slot->root_id = root_copy;
    slot->logical_path = logical_copy;
    slot->root_length = root_length;
    slot->logical_length = logical_length;
    slot->hash = hash;
    visited->count++;
    return 0;
}

int visited_contains(const PortableVisited *visited,
                            const char *root_id, const char *logical)
{
    if (visited == NULL || root_id == NULL || logical == NULL)
        return -1;
    if (visited->capacity == 0)
        return 0;

    size_t root_length = strlen(root_id);
    size_t logical_length = strlen(logical);
    uint64_t hash = visited_hash(visited, root_id, root_length, logical,
                                 logical_length);
    size_t index = SIZE_MAX;
    int location = visited_locate(visited, root_id, root_length, logical,
                                  logical_length, hash, &index);
    if (location < 0)
        return -1;
    return location == 1 ? 1 : 0;
}

static uint64_t prescan_inode_hash(const PrescanInodeSet *set,
                                   dev_t device, ino_t inode)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ set->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)device);
    return hash_fnv1a_uint64(hash, (uint64_t)inode);
}

int prescan_inode_set_rehash(PrescanInodeSet *set,
                                    size_t new_capacity)
{
    if (set == NULL || !visited_capacity_valid(new_capacity) ||
        new_capacity > visited_max_capacity() ||
        new_capacity > SIZE_MAX / sizeof(*set->slots))
        return -1;

    PrescanInodeSlot *new_slots = calloc(new_capacity,
                                         sizeof(*new_slots));
    if (new_slots == NULL)
        return -1;

    for (size_t old_index = 0; old_index < set->capacity; old_index++)
    {
        PrescanInodeSlot *old_slot = &set->slots[old_index];
        if (!old_slot->used)
            continue;
        size_t index = (size_t)old_slot->hash & (new_capacity - 1U);
        while (new_slots[index].used)
            index = (index + 1U) & (new_capacity - 1U);
        new_slots[index] = *old_slot;
    }

    free(set->slots);
    set->slots = new_slots;
    set->capacity = new_capacity;
    return 0;
}

/* Returns 1 for an existing inode, 0 for an empty insertion slot, -1 if full. */
static int prescan_inode_set_locate(const PrescanInodeSet *set,
                                    dev_t device, ino_t inode, uint64_t hash,
                                    size_t *out_index)
{
    if (set == NULL || out_index == NULL)
        return -1;
    if (set->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)hash & (set->capacity - 1U);
    for (size_t probes = 0; probes < set->capacity; probes++)
    {
        prescan_inode_count_probe();
        const PrescanInodeSlot *slot = &set->slots[index];
        if (!slot->used)
        {
            *out_index = index;
            return 0;
        }
        if (slot->hash == hash && slot->device == device &&
            slot->inode == inode)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (set->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

/* Returns 0 for a newly seen inode and 1 when it was already counted. */
int prescan_inode_set_find_or_insert(PrescanInodeSet *set,
                                            dev_t device, ino_t inode)
{
    if (set == NULL)
        return -1;

    uint64_t hash = prescan_inode_hash(set, device, inode);
    if (set->capacity == 0 &&
        prescan_inode_set_rehash(set, VISITED_INITIAL_CAPACITY) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = prescan_inode_set_locate(set, device, inode, hash, &index);
    if (location == 1)
        return 1;

    if (location < 0 || set->count + 1U > set->capacity / 2U)
    {
        if (set->count >= SIDECAR_MAX_LIVE_ENTRIES ||
            set->capacity > visited_max_capacity() / 2U ||
            prescan_inode_set_rehash(set, set->capacity * 2U) != 0)
            return -1;
        index = (size_t)hash & (set->capacity - 1U);
        while (set->slots[index].used)
            index = (index + 1U) & (set->capacity - 1U);
    }

    set->slots[index] = (PrescanInodeSlot){
        .device = device,
        .inode = inode,
        .hash = hash,
        .used = 1
    };
    set->count++;
    return 0;
}

void prescan_inode_set_free(void *opaque)
{
    PrescanInodeSet *set = opaque;
    if (set == NULL)
        return;
    free(set->slots);
    free(set);
}

static uint64_t inode_map_hash(const PortableInodeMap *map, dev_t device,
                               ino_t inode)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ map->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)device);
    return hash_fnv1a_uint64(hash, (uint64_t)inode);
}

static int inode_map_rehash(PortableInodeMap *map, size_t new_capacity)
{
    if (map == NULL || !visited_capacity_valid(new_capacity) ||
        new_capacity > visited_max_capacity() ||
        new_capacity > SIZE_MAX / sizeof(*map->slots))
        return -1;

    PortableInodeSlot *new_slots = calloc(new_capacity,
                                          sizeof(*new_slots));
    if (new_slots == NULL)
        return -1;

    for (size_t old_index = 0; old_index < map->capacity; old_index++) {
        PortableInodeSlot *old_slot = &map->slots[old_index];
        if (old_slot->root_id == NULL)
            continue;
        size_t index = (size_t)old_slot->hash & (new_capacity - 1U);
        while (new_slots[index].root_id != NULL)
            index = (index + 1U) & (new_capacity - 1U);
        new_slots[index] = *old_slot;
    }

    free(map->slots);
    map->slots = new_slots;
    map->capacity = new_capacity;
    return 0;
}

static int inode_map_locate(const PortableInodeMap *map, dev_t device,
                            ino_t inode, uint64_t hash, size_t *out_index)
{
    if (map == NULL || out_index == NULL)
        return -1;
    if (map->capacity == 0) {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)hash & (map->capacity - 1U);
    for (size_t probes = 0; probes < map->capacity; probes++) {
        inode_map_count_probe();
        const PortableInodeSlot *slot = &map->slots[index];
        if (slot->root_id == NULL) {
            *out_index = index;
            return 0;
        }
        if (slot->hash == hash && slot->device == device &&
            slot->inode == inode) {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (map->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

/* Returns 0 for a new representative and 1 for a hardlink member. */
int inode_map_find_or_insert(PortableInodeMap *map, dev_t device,
                                    ino_t inode, const char *root_id,
                                    const char *logical,
                                    const PortableInodeSlot **out_slot)
{
    if (map == NULL || root_id == NULL || logical == NULL || out_slot == NULL)
        return -1;
    *out_slot = NULL;
    size_t root_length = strlen(root_id);
    size_t logical_length = strlen(logical);
    if (root_length == SIZE_MAX || logical_length == SIZE_MAX ||
        root_length > SIDECAR_MAX_ROOT_ID || logical_length > SIDECAR_MAX_PATH)
        return -1;

    uint64_t hash = inode_map_hash(map, device, inode);
    if (map->capacity == 0 &&
        inode_map_rehash(map, VISITED_INITIAL_CAPACITY) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = inode_map_locate(map, device, inode, hash, &index);
    if (location == 1) {
        *out_slot = &map->slots[index];
        return 1;
    }

    if (location < 0 || map->count + 1U > map->capacity / 2U) {
        if (map->count >= SIDECAR_MAX_LIVE_ENTRIES ||
            map->capacity > visited_max_capacity() / 2U ||
            inode_map_rehash(map, map->capacity * 2U) != 0)
            return -1;
        index = (size_t)hash & (map->capacity - 1U);
        while (map->slots[index].root_id != NULL)
            index = (index + 1U) & (map->capacity - 1U);
    }

    char *root_copy = malloc(root_length + 1U);
    if (root_copy == NULL)
        return -1;
    char *logical_copy = malloc(logical_length + 1U);
    if (logical_copy == NULL) {
        free(root_copy);
        return -1;
    }
    memcpy(root_copy, root_id, root_length + 1U);
    memcpy(logical_copy, logical, logical_length + 1U);

    PortableInodeSlot *slot = &map->slots[index];
    *slot = (PortableInodeSlot){
        .device = device,
        .inode = inode,
        .root_id = root_copy,
        .logical_path = logical_copy,
        .root_length = root_length,
        .logical_length = logical_length,
        .hash = hash
    };
    map->count++;
    *out_slot = slot;
    return 0;
}

void inode_map_free(PortableInodeMap *map)
{
    if (map == NULL)
        return;
    for (size_t index = 0; index < map->capacity; index++) {
        free(map->slots[index].root_id);
        free(map->slots[index].logical_path);
    }
    free(map->slots);
    free(map);
}

static uint64_t case_fold_hash(const PortableCaseFoldSet *set,
                               const char *folded_key, size_t key_length)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ set->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)key_length);
    return hash_fnv1a_bytes(hash, (const unsigned char *)folded_key,
                            key_length);
}

static int case_fold_set_rehash(PortableCaseFoldSet *set,
                                size_t new_capacity)
{
    if (set == NULL || !visited_capacity_valid(new_capacity) ||
        new_capacity > visited_max_capacity() ||
        new_capacity > SIZE_MAX / sizeof(*set->slots) ||
        (set->capacity != 0 && set->slots == NULL))
        return -1;

    PortableCaseFoldSlot *new_slots = calloc(new_capacity,
                                             sizeof(*new_slots));
    if (new_slots == NULL)
        return -1;

    for (size_t old_index = 0; old_index < set->capacity; old_index++) {
        PortableCaseFoldSlot *old_slot = &set->slots[old_index];
        if (old_slot->folded_key == NULL)
            continue;
        size_t index = (size_t)old_slot->hash & (new_capacity - 1U);
        while (new_slots[index].folded_key != NULL)
            index = (index + 1U) & (new_capacity - 1U);
        new_slots[index] = *old_slot;
    }

    free(set->slots);
    set->slots = new_slots;
    set->capacity = new_capacity;
    return 0;
}

/* Returns 1 for a matching slot, 0 for an empty insertion slot, -1 if full. */
static int case_fold_set_locate(const PortableCaseFoldSet *set,
                                const char *key, size_t key_length,
                                uint64_t hash, size_t *out_index)
{
    if (set == NULL || out_index == NULL)
        return -1;
    if (set->capacity == 0) {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)hash & (set->capacity - 1U);
    for (size_t probes = 0; probes < set->capacity; probes++) {
        const PortableCaseFoldSlot *slot = &set->slots[index];
        if (slot->folded_key == NULL) {
            *out_index = index;
            return 0;
        }
        if (slot->hash == hash && slot->key_length == key_length &&
            memcmp(slot->folded_key, key, key_length) == 0) {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (set->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

void ascii_fold_copy(char *destination, size_t destination_size,
                     const char *source)
{
    if (destination == NULL || destination_size == 0)
        return;
    size_t index = 0;
    if (source != NULL) {
        for (; source[index] != '\0' && index + 1U < destination_size;
             index++)
            destination[index] = (source[index] >= 'A' &&
                                  source[index] <= 'Z')
                ? (char)(source[index] + ('a' - 'A'))
                : source[index];
    }
    destination[index] = '\0';
}

int case_fold_set_find_or_insert_value(
    PortableCaseFoldSet *set, const char *folded_key,
    const char *logical_path, size_t value_index, size_t *out_value_index,
    char **out_logical_path)
{
    if (set == NULL || folded_key == NULL || logical_path == NULL ||
        out_value_index == NULL || out_logical_path == NULL)
        return -1;
    *out_value_index = SIZE_MAX;
    *out_logical_path = NULL;

    size_t key_length = strlen(folded_key);
    size_t logical_length = strlen(logical_path);
    if (key_length == SIZE_MAX || logical_length == SIZE_MAX)
        return -1;
    if (set->capacity == 0) {
        if (set->hash_salt == 0)
            set->hash_salt = sidecar_process_salt();
        if (case_fold_set_rehash(set, VISITED_INITIAL_CAPACITY) != 0)
            return -1;
    }

    uint64_t hash = case_fold_hash(set, folded_key, key_length);
    size_t index = SIZE_MAX;
    int location = case_fold_set_locate(set, folded_key, key_length, hash,
                                        &index);
    if (location == 1) {
        const PortableCaseFoldSlot *slot = &set->slots[index];
        *out_value_index = slot->value_index;
        *out_logical_path = slot->logical_path;
        return 1;
    }

    if (location < 0 || set->count + 1U > set->capacity / 2U) {
        if (set->count >= SIDECAR_MAX_LIVE_ENTRIES ||
            set->capacity > visited_max_capacity() / 2U ||
            case_fold_set_rehash(set, set->capacity * 2U) != 0)
            return -1;
        index = (size_t)hash & (set->capacity - 1U);
        while (set->slots[index].folded_key != NULL)
            index = (index + 1U) & (set->capacity - 1U);
    }

    if (key_length > SIZE_MAX - 1U || logical_length > SIZE_MAX - 1U)
        return -1;
    char *key_copy = malloc(key_length + 1U);
    if (key_copy == NULL)
        return -1;
    char *logical_copy = malloc(logical_length + 1U);
    if (logical_copy == NULL) {
        free(key_copy);
        return -1;
    }
    memcpy(key_copy, folded_key, key_length + 1U);
    memcpy(logical_copy, logical_path, logical_length + 1U);

    set->slots[index] = (PortableCaseFoldSlot){
        .folded_key = key_copy,
        .logical_path = logical_copy,
        .key_length = key_length,
        .hash = hash,
        .value_index = value_index
    };
    set->count++;
    return 0;
}

int case_fold_set_find_or_insert(PortableCaseFoldSet *set,
                                 const char *folded_key,
                                 const char *logical_path,
                                 char **out_logical_path)
{
    size_t value_index = SIZE_MAX;
    return case_fold_set_find_or_insert_value(set, folded_key, logical_path,
                                              SIZE_MAX, &value_index,
                                              out_logical_path);
}

int case_fold_set_contains(const PortableCaseFoldSet *set,
                                  const char *key)
{
    if (set == NULL || key == NULL || set->capacity == 0 ||
        set->slots == NULL)
        return 0;

    size_t key_length = strlen(key);
    uint64_t hash = case_fold_hash(set, key, key_length);
    size_t index = SIZE_MAX;
    int location = case_fold_set_locate(set, key, key_length, hash, &index);
    return location == 1 ? 1 : 0;
}

void case_fold_set_free(PortableCaseFoldSet *set)
{
    if (set == NULL)
        return;
    for (size_t index = 0; index < set->capacity; index++) {
        free(set->slots[index].folded_key);
        free(set->slots[index].logical_path);
    }
    free(set->slots);
    memset(set, 0, sizeof(*set));
}
