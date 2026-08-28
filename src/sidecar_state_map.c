#define _GNU_SOURCE

#include "sidecar_state_internal.h"
#include "hash.h"

#include <errno.h>
#include <string.h>

#define MAP_INITIAL_CAPACITY 16U

static int bytes_equal(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 ||
            (left.data != NULL && right.data != NULL &&
             memcmp(left.data, right.data, left.length) == 0));
}

static int key_matches(SidecarBytes entry_root, SidecarBytes entry_logical,
                       SidecarBytes root_id, SidecarBytes logical_path)
{
    return bytes_equal(entry_root, root_id) &&
           bytes_equal(entry_logical, logical_path);
}

static SidecarBytes map_slot_root_id(const StateMap *map,
                                     const MapSlot *slot)
{
    return map->value_kind == MAP_VALUE_CLAIM
        ? slot->value.claim.claim.root_id
        : slot->value.entry.entry.root_id;
}

static SidecarBytes map_slot_logical_path(const StateMap *map,
                                          const MapSlot *slot)
{
    return map->value_kind == MAP_VALUE_CLAIM
        ? slot->value.claim.claim.logical_path
        : slot->value.entry.entry.logical_path;
}

uint64_t map_hash(const StateMap *map, SidecarBytes root_id,
                  SidecarBytes logical_path);

#ifdef SIDECAR_STATE_TEST_HOOKS
static uint64_t state_test_probe_count;

static void count_probe(void)
{
    if (state_test_probe_count != UINT64_MAX)
        state_test_probe_count++;
}

uint64_t sidecar_state_test_probe_count(void)
{
    return state_test_probe_count;
}

void sidecar_state_test_reset_probe_count(void)
{
    state_test_probe_count = 0;
}

size_t sidecar_state_test_entry_probe_index(const SidecarLog *log,
                                            SidecarBytes root_id,
                                            SidecarBytes logical_path)
{
    if (log == NULL || log->implementation == NULL)
        return MAP_INDEX_NONE;
    const SidecarLogImplementation *implementation = log->implementation;
    const StateMap *map = &implementation->map;
    if (map->capacity == 0)
        return MAP_INDEX_NONE;
    return (size_t)map_hash(map, root_id, logical_path) &
           (map->capacity - 1U);
}

uint64_t sidecar_state_test_entry_used_count(const SidecarLog *log)
{
    if (log == NULL || log->implementation == NULL)
        return 0;
    const SidecarLogImplementation *implementation = log->implementation;
    const StateMap *map = &implementation->map;
    return (uint64_t)map->count + (uint64_t)map->tombstones;
}
#else
static void count_probe(void)
{
}
#endif

uint64_t map_hash(const StateMap *map, SidecarBytes root_id,
                  SidecarBytes logical_path)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ map->hash_salt;
    hash = hash_fnv1a_uint64(hash, (uint64_t)root_id.length);
    hash = hash_fnv1a_bytes(hash, root_id.data, root_id.length);
    hash = hash_fnv1a_uint64(hash, (uint64_t)logical_path.length);
    return hash_fnv1a_bytes(hash, logical_path.data, logical_path.length);
}

static size_t map_max_capacity(void)
{
    if (SIDECAR_MAX_LIVE_ENTRIES > SIZE_MAX / 2U)
        return SIZE_MAX & ~(SIZE_MAX >> 1);
    return (size_t)SIDECAR_MAX_LIVE_ENTRIES * 2U;
}

static int map_capacity_valid(size_t capacity)
{
    return capacity >= MAP_INITIAL_CAPACITY &&
           (capacity & (capacity - 1U)) == 0;
}

static SidecarStatus map_rehash(StateMemory *memory, StateMap *map,
                                size_t new_capacity)
{
    if (memory == NULL || map == NULL || !map_capacity_valid(new_capacity) ||
        new_capacity > map_max_capacity() ||
        new_capacity > SIZE_MAX / sizeof(MapSlot))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }

    size_t new_size = new_capacity * sizeof(MapSlot);
    MapSlot *new_slots = state_alloc(memory, new_size);
    if (new_slots == NULL)
        return errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                               : SIDECAR_STATUS_LIMIT;
    memset(new_slots, 0, new_size);

    size_t carried_tombstones = 0;
    for (size_t old_index = 0; old_index < map->capacity; old_index++)
    {
        MapSlot *old_slot = &map->slots[old_index];
        int carry = old_slot->state == MAP_SLOT_LIVE ||
                    (old_slot->state == MAP_SLOT_TOMBSTONE &&
                     map->value_kind == MAP_VALUE_ENTRY);
        if (!carry)
            continue;
        size_t index = (size_t)old_slot->hash & (new_capacity - 1U);
        while (new_slots[index].state != MAP_SLOT_EMPTY)
            index = (index + 1U) & (new_capacity - 1U);
        new_slots[index] = *old_slot;
        if (old_slot->state == MAP_SLOT_TOMBSTONE)
            carried_tombstones++;
    }

    if (map->slots != NULL)
        state_free(memory, map->slots,
                   map->capacity * sizeof(*map->slots));
    map->slots = new_slots;
    map->capacity = new_capacity;
    map->tombstones = carried_tombstones;
    return SIDECAR_STATUS_OK;
}

/* Returns 1 for live, 2 for a matching tombstone, 0 for insertion, -1 full. */
int map_locate(const StateMap *map, SidecarBytes root_id,
               SidecarBytes logical_path, uint64_t hash, size_t *out_index)
{
    if (out_index == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (map == NULL || map->capacity == 0)
    {
        *out_index = MAP_INDEX_NONE;
        return 0;
    }

    size_t first_tombstone = MAP_INDEX_NONE;
    size_t index = (size_t)hash & (map->capacity - 1U);
    for (size_t probes = 0; probes < map->capacity; probes++)
    {
        count_probe();
        const MapSlot *slot = &map->slots[index];
        if (slot->state == MAP_SLOT_EMPTY)
        {
            *out_index = map->value_kind == MAP_VALUE_ENTRY ||
                         first_tombstone == MAP_INDEX_NONE
                ? index : first_tombstone;
            return 0;
        }
        if (slot->state == MAP_SLOT_TOMBSTONE)
        {
            if (slot->hash == hash &&
                key_matches(map_slot_root_id(map, slot),
                            map_slot_logical_path(map, slot),
                            root_id, logical_path))
            {
                *out_index = index;
                return 2;
            }
            if (first_tombstone == MAP_INDEX_NONE)
                first_tombstone = index;
        }
        else if (slot->hash == hash &&
                 key_matches(map_slot_root_id(map, slot),
                             map_slot_logical_path(map, slot),
                             root_id, logical_path))
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (map->capacity - 1U);
    }

    if (map->value_kind == MAP_VALUE_ENTRY)
    {
        *out_index = MAP_INDEX_NONE;
        return -1;
    }
    *out_index = first_tombstone;
    return first_tombstone == MAP_INDEX_NONE ? -1 : 0;
}

size_t map_find(const StateMap *map, SidecarBytes root_id,
                SidecarBytes logical_path)
{
    size_t index = MAP_INDEX_NONE;
    if (map_locate(map, root_id, logical_path,
                   map_hash(map, root_id, logical_path), &index) == 1)
        return index;
    return MAP_INDEX_NONE;
}

static SidecarStatus map_prepare_insert(StateMemory *memory, StateMap *map)
{
    if (map->capacity == 0)
        return map_rehash(memory, map, MAP_INITIAL_CAPACITY);

    size_t used = map->count + map->tombstones;
    if (used == SIZE_MAX || used + 1U <= map->capacity / 2U)
        return SIDECAR_STATUS_OK;

    size_t new_capacity = map->capacity;
    int must_grow = map->value_kind == MAP_VALUE_ENTRY ||
                    map->count + 1U > map->capacity / 2U;
    if (must_grow)
    {
        if (new_capacity > map_max_capacity() / 2U)
        {
            errno = E2BIG;
            return SIDECAR_STATUS_LIMIT;
        }
        new_capacity *= 2U;
    }
    return map_rehash(memory, map, new_capacity);
}

void map_free(StateMemory *memory, StateMap *map)
{
    if (map == NULL)
        return;
    for (size_t index = 0; index < map->capacity; index++)
    {
        if (map->slots[index].state != MAP_SLOT_EMPTY)
        {
            if (map->value_kind == MAP_VALUE_CLAIM)
                clear_claim(memory, &map->slots[index].value.claim);
            else
                clear_entry(memory, &map->slots[index].value.entry);
        }
    }
    if (map->slots != NULL)
        state_free(memory, map->slots,
                   map->capacity * sizeof(*map->slots));
    memset(map, 0, sizeof(*map));
}

/* Shared by map_prepare_commit()/map_prepare_claim() once each has decided
 * its first map_locate() result means "insert a new slot": grows the map if
 * needed, re-locates (capacity may have changed), and writes the resulting
 * index. Callers pass the hash they already computed for their own initial
 * map_locate() call.
 */
static SidecarStatus map_prepare_slot(StateMemory *memory, StateMap *map,
                                      SidecarBytes root_id,
                                      SidecarBytes logical_path,
                                      uint64_t hash, size_t *out_index)
{
    SidecarStatus status = map_prepare_insert(memory, map);
    if (status != SIDECAR_STATUS_OK)
        return status;
    size_t index = MAP_INDEX_NONE;
    int location = map_locate(map, root_id, logical_path, hash, &index);
    if (location != 0 || index == MAP_INDEX_NONE)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    if (out_index != NULL)
        *out_index = index;
    return SIDECAR_STATUS_OK;
}

SidecarStatus map_prepare_commit(StateMemory *memory, StateMap *map,
                                 const StateEntry *pending,
                                 size_t *existing_index,
                                 uint64_t *out_hash)
{
    if (map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    uint64_t hash = map_hash(map, pending->entry.root_id,
                             pending->entry.logical_path);
    if (out_hash != NULL)
        *out_hash = hash;
    size_t index = MAP_INDEX_NONE;
    int location = map_locate(map, pending->entry.root_id,
                              pending->entry.logical_path, hash, &index);
    if (location == 1 || location == 2)
    {
        if (existing_index != NULL)
            *existing_index = index;
        return SIDECAR_STATUS_OK;
    }
    if (!sidecar_live_entry_count_allowed((uint64_t)map->count +
                                          (uint64_t)map->tombstones + 1U))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    return map_prepare_slot(memory, map, pending->entry.root_id,
                            pending->entry.logical_path, hash,
                            existing_index);
}

SidecarStatus map_prepare_claim(StateMemory *memory, StateMap *map,
                                SidecarBytes root_id,
                                SidecarBytes logical_path,
                                size_t *claim_index,
                                uint64_t *out_hash)
{
    if (map == NULL || map->value_kind != MAP_VALUE_CLAIM ||
        map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    uint64_t hash = map_hash(map, root_id, logical_path);
    if (out_hash != NULL)
        *out_hash = hash;
    size_t index = MAP_INDEX_NONE;
    int location = map_locate(map, root_id, logical_path, hash, &index);
    if (location != 0)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (!sidecar_live_entry_count_allowed((uint64_t)map->count + 1U))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    return map_prepare_slot(memory, map, root_id, logical_path, hash,
                            claim_index);
}

void map_apply_claim(StateMemory *memory, StateMap *map,
                     StateClaim *claim, size_t claim_index,
                     uint64_t hash)
{
    map->generation++;
    MapSlot *slot = &map->slots[claim_index];
    if (slot->state == MAP_SLOT_TOMBSTONE)
    {
        clear_claim(memory, &slot->value.claim);
        map->tombstones--;
    }
    map->count++;
    slot->value.claim = *claim;
    slot->hash = hash;
    slot->state = MAP_SLOT_LIVE;
    slot->value.claim.generation = map->generation;
    *claim = (StateClaim){0};
}

SidecarStatus map_apply_remove(StateMemory *memory, StateMap *map,
                               size_t index)
{
    if (map == NULL || map->value_kind != MAP_VALUE_CLAIM)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (index == MAP_INDEX_NONE || index >= map->capacity ||
        map->slots[index].state != MAP_SLOT_LIVE)
        return SIDECAR_STATUS_OK;
    if (map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    clear_claim(memory, &map->slots[index].value.claim);
    map->slots[index].state = MAP_SLOT_TOMBSTONE;
    map->count--;
    map->tombstones++;
    map->generation++;
    return SIDECAR_STATUS_OK;
}

void map_apply_commit(StateMemory *memory, StateMap *map,
                      PendingEntry *pending, size_t existing_index,
                      uint64_t hash)
{
    map->generation++;
    MapSlot *slot = &map->slots[existing_index];
    if (slot->state == MAP_SLOT_LIVE)
        clear_entry(memory, &slot->value.entry);
    else
    {
        if (slot->state == MAP_SLOT_TOMBSTONE)
        {
            clear_entry(memory, &slot->value.entry);
            map->tombstones--;
        }
        map->count++;
    }
    slot->value.entry = pending->entry;
    slot->hash = hash;
    slot->state = MAP_SLOT_LIVE;
    slot->value.entry.generation = map->generation;
    pending->entry = (StateEntry){0};
    pending->xattrs_seen = 0;
}

SidecarStatus map_apply_delete(StateMemory *memory, StateMap *map,
                               SidecarBytes root_id,
                               SidecarBytes logical_path)
{
    (void)memory;
    if (map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    size_t index = MAP_INDEX_NONE;
    int location = map_locate(map, root_id, logical_path,
                              map_hash(map, root_id, logical_path), &index);
    map->generation++;
    if (location != 1 || index == MAP_INDEX_NONE)
        return SIDECAR_STATUS_OK;
    MapSlot *slot = &map->slots[index];
    slot->state = MAP_SLOT_TOMBSTONE;
    map->count--;
    map->tombstones++;
    return SIDECAR_STATUS_OK;
}

static int claim_matches_entry(const StateClaim *claim,
                               const SidecarEntry *entry)
{
    return claim != NULL && entry != NULL &&
           bytes_equal(claim->claim.root_id, entry->root_id) &&
           bytes_equal(claim->claim.logical_path, entry->logical_path) &&
           bytes_equal(claim->claim.physical_path, entry->physical_path) &&
           claim->claim.kind == entry->kind;
}

SidecarStatus prepare_claim_consumption(const StateMap *claim_map,
                                        const SidecarEntry *entry,
                                        size_t *claim_index)
{
    if (claim_index == NULL || claim_map == NULL || entry == NULL)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    *claim_index = MAP_INDEX_NONE;
    size_t index = map_find(claim_map, entry->root_id,
                            entry->logical_path);
    if (index == MAP_INDEX_NONE)
        return SIDECAR_STATUS_CORRUPT;
    if (!claim_matches_entry(&claim_map->slots[index].value.claim, entry))
        return SIDECAR_STATUS_CORRUPT;
    if (claim_map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    *claim_index = index;
    return SIDECAR_STATUS_OK;
}

int valid_key(SidecarBytes root_id, SidecarBytes logical_path)
{
    return bytes_valid(root_id, SIDECAR_MAX_ROOT_ID, 1) &&
           bytes_valid(logical_path, SIDECAR_MAX_PATH, 0);
}
