#define _GNU_SOURCE

#include "sidecar.h"
#include "hash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint64_t bytes;
} StateMemory;

typedef struct {
    SidecarEntry entry;
    SidecarXattr *xattrs;
    uint64_t generation;
} StateEntry;

typedef struct {
    SidecarClaim claim;
    uint64_t generation;
} StateClaim;

typedef enum {
    MAP_SLOT_EMPTY = 0,
    MAP_SLOT_LIVE,
    MAP_SLOT_TOMBSTONE
} MapSlotState;

typedef enum {
    MAP_VALUE_ENTRY = 0,
    MAP_VALUE_CLAIM
} MapValueKind;

typedef union {
    StateEntry entry;
    StateClaim claim;
} MapValue;

typedef struct {
    MapValue value;
    uint64_t hash;
    MapSlotState state;
} MapSlot;

typedef struct {
    MapSlot *slots;
    size_t count;
    size_t tombstones;
    size_t capacity;
    uint64_t generation;
    uint64_t hash_salt;
    MapValueKind value_kind;
} StateMap;

typedef struct {
    StateEntry entry;
    uint32_t xattrs_seen;
} PendingEntry;

typedef struct {
    int fd;
    int poisoned;
    StateMemory memory;
    StateMap map;
    StateMap claim_map;
    PendingEntry pending;
} SidecarLogImplementation;

typedef struct {
    SidecarLogImplementation *log;
    SidecarStatus error;
} LoadContext;

static void set_invalid_error(void)
{
    errno = EINVAL;
}

static int bytes_valid(SidecarBytes bytes, size_t maximum, int nonempty)
{
    return bytes.length <= maximum &&
           (bytes.length == 0 || bytes.data != NULL) &&
           (!nonempty || bytes.length != 0) &&
           (bytes.length == 0 || memchr(bytes.data, '\0', bytes.length) == NULL);
}

static int raw_bytes_valid(SidecarBytes bytes, size_t maximum, int nonempty)
{
    return bytes.length <= maximum &&
           (bytes.length == 0 || bytes.data != NULL) &&
           (!nonempty || bytes.length != 0);
}

static void *state_alloc(StateMemory *memory, size_t size)
{
    if (memory == NULL || size == 0 ||
        memory->bytes > SIDECAR_MAX_ALLOC_BUDGET ||
        (uint64_t)size > SIDECAR_MAX_ALLOC_BUDGET - memory->bytes)
    {
        errno = E2BIG;
        return NULL;
    }

    void *pointer = malloc(size);
    if (pointer == NULL)
        return NULL;
    memory->bytes += (uint64_t)size;
    return pointer;
}

static void state_free(StateMemory *memory, void *pointer, size_t size)
{
    if (pointer == NULL)
        return;
    if (memory != NULL && (uint64_t)size <= memory->bytes)
        memory->bytes -= (uint64_t)size;
    free(pointer);
}

static SidecarStatus status_from_errno(void)
{
    switch (errno)
    {
        case EINVAL: return SIDECAR_STATUS_INVALID_ARGUMENT;
        case E2BIG: return SIDECAR_STATUS_LIMIT;
        case ENOMEM: return SIDECAR_STATUS_ALLOCATION;
        case EOPNOTSUPP: return SIDECAR_STATUS_UNSUPPORTED_KIND;
        default: return SIDECAR_STATUS_IO_ERROR;
    }
}

static SidecarStatus copy_bytes(StateMemory *memory, SidecarBytes source,
                                size_t maximum, int nonempty, int allow_nul,
                                SidecarBytes *destination)
{
    int valid = allow_nul ? raw_bytes_valid(source, maximum, nonempty)
                          : bytes_valid(source, maximum, nonempty);
    if (destination == NULL || !valid)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    destination->data = NULL;
    destination->length = 0;
    if (source.length == 0)
        return SIDECAR_STATUS_OK;

    unsigned char *data = state_alloc(memory, source.length);
    if (data == NULL)
        return errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                               : SIDECAR_STATUS_LIMIT;
    memcpy(data, source.data, source.length);
    destination->data = data;
    destination->length = source.length;
    return SIDECAR_STATUS_OK;
}

static void clear_xattr(StateMemory *memory, SidecarXattr *xattr)
{
    if (xattr == NULL)
        return;
    state_free(memory, (void *)xattr->name.data, xattr->name.length);
    state_free(memory, (void *)xattr->value.data, xattr->value.length);
    memset(xattr, 0, sizeof(*xattr));
}

static void clear_entry(StateMemory *memory, StateEntry *entry)
{
    if (entry == NULL)
        return;
    state_free(memory, (void *)entry->entry.root_id.data,
               entry->entry.root_id.length);
    state_free(memory, (void *)entry->entry.logical_path.data,
               entry->entry.logical_path.length);
    state_free(memory, (void *)entry->entry.physical_path.data,
               entry->entry.physical_path.length);
    state_free(memory, (void *)entry->entry.collision_suffix.data,
               entry->entry.collision_suffix.length);
    state_free(memory, (void *)entry->entry.symlink_target.data,
               entry->entry.symlink_target.length);
    state_free(memory, (void *)entry->entry.hardlink_root_id.data,
               entry->entry.hardlink_root_id.length);
    state_free(memory, (void *)entry->entry.hardlink_logical_path.data,
               entry->entry.hardlink_logical_path.length);
    if (entry->xattrs != NULL)
    {
        for (uint32_t index = 0; index < entry->entry.xattr_count; index++)
            clear_xattr(memory, &entry->xattrs[index]);
        size_t size = (size_t)entry->entry.xattr_count * sizeof(*entry->xattrs);
        state_free(memory, entry->xattrs, size);
    }
    memset(entry, 0, sizeof(*entry));
}

static void clear_claim(StateMemory *memory, StateClaim *claim)
{
    if (claim == NULL)
        return;
    state_free(memory, (void *)claim->claim.root_id.data,
               claim->claim.root_id.length);
    state_free(memory, (void *)claim->claim.logical_path.data,
               claim->claim.logical_path.length);
    state_free(memory, (void *)claim->claim.physical_path.data,
               claim->claim.physical_path.length);
    memset(claim, 0, sizeof(*claim));
}

static SidecarStatus copy_claim(StateMemory *memory,
                                const SidecarClaim *source,
                                StateClaim *destination)
{
    if (source == NULL || destination == NULL ||
        !bytes_valid(source->root_id, SIDECAR_MAX_ROOT_ID, 1) ||
        !bytes_valid(source->logical_path, SIDECAR_MAX_PATH, 0) ||
        !bytes_valid(source->physical_path, SIDECAR_MAX_PATH, 0) ||
        !sidecar_claim_kind_valid(source->kind))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, sizeof(*destination));
    destination->claim.kind = source->kind;
    SidecarStatus status = copy_bytes(memory, source->root_id,
                                      SIDECAR_MAX_ROOT_ID, 1, 0,
                                      &destination->claim.root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->logical_path, SIDECAR_MAX_PATH, 0, 0,
                        &destination->claim.logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->physical_path, SIDECAR_MAX_PATH, 0, 0,
                        &destination->claim.physical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    return SIDECAR_STATUS_OK;

fail:
    clear_claim(memory, destination);
    return status;
}

static SidecarStatus copy_xattr(StateMemory *memory, const SidecarXattr *source,
                                SidecarXattr *destination)
{
    if (source == NULL || destination == NULL ||
        !bytes_valid(source->name, SIDECAR_MAX_XATTR_NAME, 1) ||
        !raw_bytes_valid(source->value, SIDECAR_MAX_XATTR_VALUE, 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, sizeof(*destination));
    SidecarStatus status = copy_bytes(memory, source->name,
                                      SIDECAR_MAX_XATTR_NAME, 1, 0,
                                      &destination->name);
    if (status != SIDECAR_STATUS_OK)
        return status;
    status = copy_bytes(memory, source->value, SIDECAR_MAX_XATTR_VALUE,
                        0, 1, &destination->value);
    if (status != SIDECAR_STATUS_OK)
    {
        clear_xattr(memory, destination);
        return status;
    }
    return SIDECAR_STATUS_OK;
}

static SidecarStatus copy_entry(StateMemory *memory, const SidecarEntry *source,
                                StateEntry *destination)
{
    if (source == NULL || destination == NULL ||
        !bytes_valid(source->root_id, SIDECAR_MAX_ROOT_ID, 1) ||
        !bytes_valid(source->logical_path, SIDECAR_MAX_PATH, 0) ||
        !bytes_valid(source->physical_path, SIDECAR_MAX_PATH, 0) ||
        !bytes_valid(source->collision_suffix,
                     SIDECAR_MAX_COLLISION_SUFFIX, 0) ||
        source->atime_nsec > SIDECAR_MAX_NSEC ||
        source->mtime_nsec > SIDECAR_MAX_NSEC ||
        source->mode > SIDECAR_MAX_MODE ||
        source->xattr_count > SIDECAR_MAX_XATTRS_PER_ENTRY ||
        source->kind < SIDECAR_KIND_REGULAR ||
        source->kind > SIDECAR_KIND_HARDLINK)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind != SIDECAR_KIND_REGULAR &&
        source->kind != SIDECAR_KIND_DIRECTORY && source->size != 0)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (!bytes_valid(source->symlink_target, SIDECAR_MAX_SYMLINK_TARGET,
                     source->kind == SIDECAR_KIND_SYMLINK) ||
        !bytes_valid(source->hardlink_root_id, SIDECAR_MAX_ROOT_ID, 0) ||
        !bytes_valid(source->hardlink_logical_path, SIDECAR_MAX_PATH, 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind == SIDECAR_KIND_SYMLINK &&
        (source->hardlink_root_id.length != 0 ||
         source->hardlink_logical_path.length != 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind == SIDECAR_KIND_HARDLINK &&
        (source->symlink_target.length != 0 ||
         source->hardlink_root_id.length == 0 ||
         source->hardlink_logical_path.length == 0))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind == SIDECAR_KIND_HARDLINK && source->xattr_count != 0)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (source->kind != SIDECAR_KIND_SYMLINK &&
        source->symlink_target.length != 0)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    memset(destination, 0, sizeof(*destination));
    destination->entry = *source;
    destination->entry.root_id.data = NULL;
    destination->entry.logical_path.data = NULL;
    destination->entry.physical_path.data = NULL;
    destination->entry.collision_suffix.data = NULL;
    destination->entry.symlink_target.data = NULL;
    destination->entry.hardlink_root_id.data = NULL;
    destination->entry.hardlink_logical_path.data = NULL;
    destination->xattrs = NULL;

    SidecarStatus status = copy_bytes(memory, source->root_id,
                                      SIDECAR_MAX_ROOT_ID, 1, 0,
                                      &destination->entry.root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->logical_path, SIDECAR_MAX_PATH, 0, 0,
                        &destination->entry.logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->physical_path, SIDECAR_MAX_PATH, 0, 0,
                        &destination->entry.physical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->collision_suffix,
                        SIDECAR_MAX_COLLISION_SUFFIX, 0, 0,
                        &destination->entry.collision_suffix);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->symlink_target,
                        SIDECAR_MAX_SYMLINK_TARGET, 0, 0,
                        &destination->entry.symlink_target);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->hardlink_root_id,
                        SIDECAR_MAX_ROOT_ID, 0, 0,
                        &destination->entry.hardlink_root_id);
    if (status != SIDECAR_STATUS_OK)
        goto fail;
    status = copy_bytes(memory, source->hardlink_logical_path,
                        SIDECAR_MAX_PATH, 0, 0,
                        &destination->entry.hardlink_logical_path);
    if (status != SIDECAR_STATUS_OK)
        goto fail;

    if (source->xattr_count != 0)
    {
        size_t size = (size_t)source->xattr_count * sizeof(*destination->xattrs);
        destination->xattrs = state_alloc(memory, size);
        if (destination->xattrs == NULL)
        {
            status = errno == ENOMEM ? SIDECAR_STATUS_ALLOCATION
                                     : SIDECAR_STATUS_LIMIT;
            goto fail;
        }
        memset(destination->xattrs, 0, size);
    }
    return SIDECAR_STATUS_OK;

fail:
    clear_entry(memory, destination);
    return status;
}

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

#define MAP_INDEX_NONE SIZE_MAX
#define MAP_INITIAL_CAPACITY 16U

static uint64_t map_hash(const StateMap *map, SidecarBytes root_id,
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

static uint64_t mix_hash(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

uint64_t sidecar_process_salt(void)
{
    static uint64_t salt;
    static int initialized;
    if (initialized)
        return salt;

    uint64_t random_value = 0;
    ssize_t result = getrandom(&random_value, sizeof(random_value),
                               GRND_NONBLOCK);
    if (result == (ssize_t)sizeof(random_value))
        salt = random_value;
    else
    {
        struct timespec now;
        memset(&now, 0, sizeof(now));
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t fallback = (uint64_t)now.tv_sec;
        fallback ^= (uint64_t)now.tv_nsec << 32;
        fallback ^= (uint64_t)(unsigned long)getpid();
        fallback ^= (uint64_t)(uintptr_t)&salt;
        salt = mix_hash(fallback);
    }
    initialized = 1;
    return salt;
}

static uint64_t map_hash(const StateMap *map, SidecarBytes root_id,
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
static int map_locate(const StateMap *map, SidecarBytes root_id,
                      SidecarBytes logical_path, uint64_t hash,
                      size_t *out_index)
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

static size_t map_find(const StateMap *map, SidecarBytes root_id,
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

static void map_free(StateMemory *memory, StateMap *map)
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

static SidecarStatus map_prepare_commit(StateMemory *memory, StateMap *map,
                                        const StateEntry *pending,
                                        size_t *existing_index)
{
    if (map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    uint64_t hash = map_hash(map, pending->entry.root_id,
                             pending->entry.logical_path);
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
static SidecarStatus map_prepare_claim(StateMemory *memory, StateMap *map,
                                       SidecarBytes root_id,
                                       SidecarBytes logical_path,
                                       size_t *claim_index)
{
    if (map == NULL || map->value_kind != MAP_VALUE_CLAIM ||
        map->generation == UINT64_MAX)
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    uint64_t hash = map_hash(map, root_id, logical_path);
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

static void map_apply_claim(StateMemory *memory, StateMap *map,
                            StateClaim *claim, size_t claim_index)
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
    slot->hash = map_hash(map, slot->value.claim.claim.root_id,
                          slot->value.claim.claim.logical_path);
    slot->state = MAP_SLOT_LIVE;
    slot->value.claim.generation = map->generation;
    *claim = (StateClaim){0};
}

static SidecarStatus map_apply_remove(StateMemory *memory, StateMap *map,
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

static void map_apply_commit(StateMemory *memory, StateMap *map,
                             PendingEntry *pending, size_t existing_index)
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
    slot->hash = map_hash(map, slot->value.entry.entry.root_id,
                          slot->value.entry.entry.logical_path);
    slot->state = MAP_SLOT_LIVE;
    slot->value.entry.generation = map->generation;
    pending->entry = (StateEntry){0};
    pending->xattrs_seen = 0;
}

static SidecarStatus map_apply_delete(StateMemory *memory, StateMap *map,
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

static SidecarStatus prepare_claim_consumption(const StateMap *claim_map,
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

static int valid_key(SidecarBytes root_id, SidecarBytes logical_path)
{
    return bytes_valid(root_id, SIDECAR_MAX_ROOT_ID, 1) &&
           bytes_valid(logical_path, SIDECAR_MAX_PATH, 0);
}

static int check_size_limit(SidecarLogImplementation *log)
{
    struct stat st;
    if (fstat(log->fd, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > SIDECAR_MAX_TOTAL_BYTES)
    {
        if (errno == 0)
            errno = E2BIG;
        return -1;
    }
    return 0;
}

static void poison(SidecarLogImplementation *log)
{
    if (log != NULL)
        log->poisoned = 1;
}

static int unusable_open_errno(int error)
{
    return error == ELOOP || error == EISDIR || error == ENOTDIR ||
           error == ENXIO || error == ENODEV || error == EOPNOTSUPP;
}

static void unlink_owned_slot(int container_fd, int fd)
{
    struct stat owned;
    struct stat named;
    if (fstat(fd, &owned) == 0 &&
        fstatat(container_fd, SIDECAR_SLOT_NAME, &named,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        owned.st_dev == named.st_dev && owned.st_ino == named.st_ino)
        (void)unlinkat(container_fd, SIDECAR_SLOT_NAME, 0);
}

static void free_log_implementation(SidecarLogImplementation *log)
{
    if (log == NULL)
        return;
    clear_entry(&log->memory, &log->pending.entry);
    map_free(&log->memory, &log->map);
    map_free(&log->memory, &log->claim_map);
    free(log);
}

static SidecarOpenStatus classify_parse_failure(SidecarStatus status,
                                                SidecarStatus callback_error)
{
    if (status == SIDECAR_STATUS_IO_ERROR)
        return SIDECAR_OPEN_IO_ERROR;
    if (status == SIDECAR_STATUS_ALLOCATION ||
        callback_error == SIDECAR_STATUS_ALLOCATION)
        return SIDECAR_OPEN_ALLOCATION;
    if (callback_error == SIDECAR_STATUS_IO_ERROR)
        return SIDECAR_OPEN_IO_ERROR;
    return SIDECAR_OPEN_UNUSABLE;
}

static int load_callback(const SidecarRecord *record, void *context)
{
    LoadContext *load = context;
    SidecarLogImplementation *log = load->log;
    SidecarStatus status = SIDECAR_STATUS_OK;

    if (record->type == SIDECAR_RECORD_ENTRY)
    {
        status = copy_entry(&log->memory, &record->value.entry,
                            &log->pending.entry);
        if (status == SIDECAR_STATUS_OK)
            log->pending.xattrs_seen = 0;
    }
    else if (record->type == SIDECAR_RECORD_XATTR)
    {
        status = copy_xattr(&log->memory, &record->value.xattr,
                            &log->pending.entry.xattrs[
                                log->pending.xattrs_seen]);
        if (status == SIDECAR_STATUS_OK)
            log->pending.xattrs_seen++;
    }
    else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT)
    {
        size_t existing_index = 0;
        size_t claim_index = MAP_INDEX_NONE;
        if ((status = prepare_claim_consumption(
                  &log->claim_map, &log->pending.entry.entry,
                  &claim_index)) == SIDECAR_STATUS_OK)
            status = map_prepare_commit(&log->memory, &log->map,
                                        &log->pending.entry, &existing_index);
        if (status == SIDECAR_STATUS_OK)
        {
            map_apply_commit(&log->memory, &log->map, &log->pending,
                             existing_index);
            if (claim_index != MAP_INDEX_NONE)
                status = map_apply_remove(&log->memory, &log->claim_map,
                                          claim_index);
        }
    }
    else if (record->type == SIDECAR_RECORD_DELETE)
    {
        size_t claim_index = MAP_INDEX_NONE;
        claim_index = map_find(&log->claim_map,
                               record->value.deletion.root_id,
                               record->value.deletion.logical_path);
        if (claim_index != MAP_INDEX_NONE &&
            log->claim_map.generation == UINT64_MAX)
        {
            errno = E2BIG;
            status = SIDECAR_STATUS_LIMIT;
        }
        else
            status = map_apply_delete(&log->memory, &log->map,
                                      record->value.deletion.root_id,
                                      record->value.deletion.logical_path);
        if (status == SIDECAR_STATUS_OK && claim_index != MAP_INDEX_NONE)
            status = map_apply_remove(&log->memory, &log->claim_map,
                                      claim_index);
    }
    else if (record->type == SIDECAR_RECORD_CLAIM)
    {
        size_t claim_index = MAP_INDEX_NONE;
        if (map_find(&log->map, record->value.claim.root_id,
                     record->value.claim.logical_path) != MAP_INDEX_NONE ||
            map_find(&log->claim_map, record->value.claim.root_id,
                     record->value.claim.logical_path) != MAP_INDEX_NONE)
            status = SIDECAR_STATUS_CORRUPT;
        else
        {
            StateClaim claim = {0};
            status = copy_claim(&log->memory, &record->value.claim, &claim);
            if (status == SIDECAR_STATUS_OK)
                status = map_prepare_claim(
                    &log->memory, &log->claim_map, claim.claim.root_id,
                    claim.claim.logical_path, &claim_index);
            if (status == SIDECAR_STATUS_OK)
                map_apply_claim(&log->memory, &log->claim_map, &claim,
                                claim_index);
            else
                clear_claim(&log->memory, &claim);
        }
    }
    else
        status = SIDECAR_STATUS_CORRUPT;

    if (status != SIDECAR_STATUS_OK)
    {
        load->error = status;
        return -1;
    }
    return 0;
}

static SidecarOpenStatus validate_slot_fd(int fd, struct stat *out)
{
    struct stat st;
    if (fstat(fd, &st) != 0)
        return SIDECAR_OPEN_IO_ERROR;
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1)
        return SIDECAR_OPEN_UNUSABLE;
    if (out != NULL)
        *out = st;
    return SIDECAR_OPEN_RESUMABLE;
}

static SidecarLogImplementation *allocate_log(int fd)
{
    SidecarLogImplementation *log = calloc(1, sizeof(*log));
    if (log == NULL)
        return NULL;
    log->fd = fd;
    log->map.hash_salt = sidecar_process_salt();
    log->map.value_kind = MAP_VALUE_ENTRY;
    log->claim_map.hash_salt = log->map.hash_salt;
    log->claim_map.value_kind = MAP_VALUE_CLAIM;
    return log;
}

SidecarOpenStatus sidecar_log_create_at(int container_fd, SidecarLog *out)
{
    if (container_fd < 0 || out == NULL || out->implementation != NULL)
        return SIDECAR_OPEN_INVALID_ARGUMENT;

    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0)
    {
        if (errno == EEXIST)
            return SIDECAR_OPEN_EXISTS;
        return SIDECAR_OPEN_IO_ERROR;
    }

    SidecarLogImplementation *log = NULL;
    SidecarOpenStatus status;

    struct stat st;
    SidecarOpenStatus slot_status = validate_slot_fd(fd, &st);
    if (slot_status != SIDECAR_OPEN_RESUMABLE)
    {
        status = slot_status;
        goto fail;
    }

    log = allocate_log(fd);
    if (log == NULL)
    {
        status = SIDECAR_OPEN_ALLOCATION;
        goto fail;
    }
    if (sidecar_write_header(fd) != 0 || check_size_limit(log) != 0)
    {
        status = errno == ENOMEM ? SIDECAR_OPEN_ALLOCATION
                                 : SIDECAR_OPEN_IO_ERROR;
        goto fail;
    }
    out->implementation = log;
    return SIDECAR_OPEN_FRESH;

fail:
    {
        int saved = errno;
        unlink_owned_slot(container_fd, fd);
        free_log_implementation(log);
        close(fd);
        errno = saved;
    }
    return status;
}

SidecarOpenStatus sidecar_log_adopt_at(int container_fd, SidecarLog *out)
{
    if (container_fd < 0 || out == NULL || out->implementation != NULL)
        return SIDECAR_OPEN_INVALID_ARGUMENT;

    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        if (errno == ENOENT)
            return SIDECAR_OPEN_MISSING;
        return unusable_open_errno(errno) ? SIDECAR_OPEN_UNUSABLE
                                          : SIDECAR_OPEN_IO_ERROR;
    }

    SidecarLogImplementation *log = NULL;
    SidecarOpenStatus status;

    struct stat initial_stat;
    SidecarOpenStatus slot_status = validate_slot_fd(fd, &initial_stat);
    if (slot_status != SIDECAR_OPEN_RESUMABLE)
    {
        status = slot_status;
        goto fail;
    }

    log = allocate_log(fd);
    if (log == NULL)
    {
        status = SIDECAR_OPEN_ALLOCATION;
        goto fail;
    }

    LoadContext load = { .log = log, .error = SIDECAR_STATUS_OK };
    SidecarParseResult result;
    SidecarStatus parse_status = sidecar_parse_fd(fd, load_callback, &load,
                                                  &result);
    struct stat final_stat;
    if (fstat(fd, &final_stat) != 0 || final_stat.st_size != initial_stat.st_size)
    {
        status = SIDECAR_OPEN_IO_ERROR;
        goto fail;
    }
    if (parse_status != SIDECAR_STATUS_OK &&
        parse_status != SIDECAR_STATUS_TRUNCATED_TAIL)
    {
        status = classify_parse_failure(parse_status, load.error);
        goto fail;
    }

    if (parse_status == SIDECAR_STATUS_TRUNCATED_TAIL)
    {
        off_t truncate_offset = (off_t)result.last_valid_boundary;
        if (result.last_valid_boundary > result.bytes_read ||
            result.last_valid_boundary > SIDECAR_MAX_TOTAL_BYTES ||
            truncate_offset < 0 ||
            (uint64_t)truncate_offset != result.last_valid_boundary)
        {
            status = SIDECAR_OPEN_UNUSABLE;
            goto fail;
        }
        clear_entry(&log->memory, &log->pending.entry);
        log->pending.xattrs_seen = 0;
        if (ftruncate(fd, truncate_offset) != 0)
        {
            status = SIDECAR_OPEN_IO_ERROR;
            goto fail;
        }
    }

    if (parse_status == SIDECAR_STATUS_OK && check_size_limit(log) != 0)
    {
        status = SIDECAR_OPEN_IO_ERROR;
        goto fail;
    }
    out->implementation = log;
    return SIDECAR_OPEN_RESUMABLE;

fail:
    {
        int saved = errno;
        free_log_implementation(log);
        close(fd);
        errno = saved;
    }
    return status;
}

SidecarStatus sidecar_log_close(SidecarLog *log)
{
    if (log == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarLogImplementation *implementation = log->implementation;
    if (implementation == NULL)
        return SIDECAR_STATUS_OK;

    int close_result = close(implementation->fd);
    free_log_implementation(implementation);
    log->implementation = NULL;
    return close_result == 0 ? SIDECAR_STATUS_OK : SIDECAR_STATUS_IO_ERROR;
}

static SidecarStatus ready_log(SidecarLog *log,
                               SidecarLogImplementation **out)
{
    if (log == NULL || log->implementation == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarLogImplementation *implementation = log->implementation;
    if (implementation->poisoned)
        return SIDECAR_STATUS_IO_ERROR;
    if (out != NULL)
        *out = implementation;
    return SIDECAR_STATUS_OK;
}

// Shared by all five sidecar_log_append_*() functions: the boundary check
// and poison-or-OK tail that runs once a record's own write and map
// mutation have already succeeded.
static SidecarStatus finish_append(SidecarLogImplementation *implementation)
{
    if (check_size_limit(implementation) != 0)
    {
        poison(implementation);
        return SIDECAR_STATUS_IO_ERROR;
    }
    return SIDECAR_STATUS_OK;
}

SidecarStatus sidecar_log_append_entry(SidecarLog *log,
                                       const SidecarEntry *entry)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK || entry == NULL)
        return status != SIDECAR_STATUS_OK ? status
                                           : SIDECAR_STATUS_INVALID_ARGUMENT;
    if (implementation->pending.entry.entry.root_id.data != NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    StateEntry copy;
    status = copy_entry(&implementation->memory, entry, &copy);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (sidecar_write_entry(implementation->fd, entry) != 0)
    {
        status = status_from_errno();
        clear_entry(&implementation->memory, &copy);
        poison(implementation);
        return status;
    }
    implementation->pending.entry = copy;
    implementation->pending.xattrs_seen = 0;
    return finish_append(implementation);
}

SidecarStatus sidecar_log_append_xattr(SidecarLog *log,
                                       const SidecarXattr *xattr)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (xattr == NULL || implementation->pending.entry.entry.root_id.data == NULL ||
        implementation->pending.xattrs_seen >=
            implementation->pending.entry.entry.xattr_count)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    SidecarXattr copy;
    status = copy_xattr(&implementation->memory, xattr, &copy);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (sidecar_write_xattr(implementation->fd, xattr) != 0)
    {
        status = status_from_errno();
        clear_xattr(&implementation->memory, &copy);
        poison(implementation);
        return status;
    }
    implementation->pending.entry.xattrs[
        implementation->pending.xattrs_seen++] = copy;
    return finish_append(implementation);
}

SidecarStatus sidecar_log_append_entry_commit(SidecarLog *log)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (implementation->pending.entry.entry.root_id.data == NULL ||
        implementation->pending.xattrs_seen !=
            implementation->pending.entry.entry.xattr_count)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    size_t existing_index = 0;
    size_t claim_index = MAP_INDEX_NONE;
    status = prepare_claim_consumption(
        &implementation->claim_map, &implementation->pending.entry.entry,
        &claim_index);
    if (status == SIDECAR_STATUS_OK)
        status = map_prepare_commit(&implementation->memory,
                                    &implementation->map,
                                    &implementation->pending.entry,
                                    &existing_index);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (sidecar_write_entry_commit(implementation->fd) != 0)
    {
        status = status_from_errno();
        poison(implementation);
        return status;
    }
    map_apply_commit(&implementation->memory, &implementation->map,
                     &implementation->pending, existing_index);
    if (claim_index != MAP_INDEX_NONE)
    {
        status = map_apply_remove(&implementation->memory,
                                  &implementation->claim_map, claim_index);
        if (status != SIDECAR_STATUS_OK)
        {
            poison(implementation);
            return status;
        }
    }
    return finish_append(implementation);
}

SidecarStatus sidecar_log_append_delete(SidecarLog *log,
                                        const SidecarDelete *deletion)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (deletion == NULL || implementation->pending.entry.entry.root_id.data != NULL ||
        !valid_key(deletion->root_id, deletion->logical_path))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    size_t claim_index = map_find(&implementation->claim_map,
                                  deletion->root_id,
                                  deletion->logical_path);
    if (implementation->map.generation == UINT64_MAX ||
        (claim_index != MAP_INDEX_NONE &&
         implementation->claim_map.generation == UINT64_MAX))
    {
        errno = E2BIG;
        return SIDECAR_STATUS_LIMIT;
    }
    if (sidecar_write_delete(implementation->fd, deletion) != 0)
    {
        status = status_from_errno();
        poison(implementation);
        return status;
    }
    status = map_apply_delete(&implementation->memory, &implementation->map,
                              deletion->root_id, deletion->logical_path);
    if (status != SIDECAR_STATUS_OK)
    {
        poison(implementation);
        return status;
    }
    if (claim_index != MAP_INDEX_NONE)
    {
        status = map_apply_remove(&implementation->memory,
                                  &implementation->claim_map, claim_index);
        if (status != SIDECAR_STATUS_OK)
        {
            poison(implementation);
            return status;
        }
    }
    return finish_append(implementation);
}

SidecarStatus sidecar_log_append_claim(SidecarLog *log,
                                       const SidecarClaim *claim)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (claim == NULL || implementation->pending.entry.entry.root_id.data != NULL ||
        !valid_key(claim->root_id, claim->logical_path) ||
        !sidecar_claim_kind_valid(claim->kind))
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }
    if (map_find(&implementation->map, claim->root_id,
                 claim->logical_path) != MAP_INDEX_NONE ||
        map_find(&implementation->claim_map, claim->root_id,
                 claim->logical_path) != MAP_INDEX_NONE)
    {
        set_invalid_error();
        return SIDECAR_STATUS_INVALID_ARGUMENT;
    }

    StateClaim copy = {0};
    status = copy_claim(&implementation->memory, claim, &copy);
    if (status != SIDECAR_STATUS_OK)
        return status;
    size_t claim_index = MAP_INDEX_NONE;
    status = map_prepare_claim(&implementation->memory,
                               &implementation->claim_map,
                               copy.claim.root_id, copy.claim.logical_path,
                               &claim_index);
    if (status != SIDECAR_STATUS_OK)
    {
        clear_claim(&implementation->memory, &copy);
        return status;
    }
    if (sidecar_write_claim(implementation->fd, claim) != 0)
    {
        status = status_from_errno();
        clear_claim(&implementation->memory, &copy);
        poison(implementation);
        return status;
    }
    map_apply_claim(&implementation->memory, &implementation->claim_map,
                    &copy, claim_index);
    return finish_append(implementation);
}

size_t sidecar_log_live_count(const SidecarLog *log)
{
    if (log == NULL || log->implementation == NULL)
        return 0;
    const SidecarLogImplementation *implementation = log->implementation;
    return implementation->map.count;
}

size_t sidecar_log_claim_count(const SidecarLog *log)
{
    if (log == NULL || log->implementation == NULL)
        return 0;
    const SidecarLogImplementation *implementation = log->implementation;
    return implementation->claim_map.count;
}

/* Shared by sidecar_log_find()/sidecar_log_find_deleted(): identical guard
 * and SidecarLiveView fill, differing only in whether a live or a
 * tombstoned (deleted) match is accepted. Reading a tombstoned slot's entry
 * is safe -- map_apply_delete() defers freeing its owned bytes until the
 * slot is eventually reused by map_apply_commit(). */
static int find_live_entry(const SidecarLog *log, SidecarBytes root_id,
                           SidecarBytes logical_path, int want_deleted,
                           SidecarLiveView *out)
{
    if (out == NULL)
    {
        set_invalid_error();
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (log == NULL || log->implementation == NULL ||
        !valid_key(root_id, logical_path))
    {
        set_invalid_error();
        return -1;
    }
    const SidecarLogImplementation *implementation = log->implementation;
    size_t index;
    if (want_deleted)
    {
        index = MAP_INDEX_NONE;
        int location = map_locate(&implementation->map, root_id, logical_path,
                                  map_hash(&implementation->map, root_id,
                                           logical_path), &index);
        if (location != 2 || index == MAP_INDEX_NONE)
            return 0;
    }
    else
    {
        index = map_find(&implementation->map, root_id, logical_path);
        if (index == MAP_INDEX_NONE)
            return 0;
    }
    const StateEntry *entry = &implementation->map.slots[index].value.entry;
    out->entry = &entry->entry;
    out->xattrs = entry->xattrs;
    out->xattr_count = entry->entry.xattr_count;
    out->generation = entry->generation;
    return 1;
}

int sidecar_log_find(const SidecarLog *log, SidecarBytes root_id,
                     SidecarBytes logical_path, SidecarLiveView *out)
{
    return find_live_entry(log, root_id, logical_path, 0, out);
}

SidecarStatus sidecar_log_foreach(SidecarLog *log, SidecarLiveCallback callback,
                                  void *context)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (callback == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    for (size_t index = 0; index < implementation->map.capacity; index++)
    {
        MapSlot *slot = &implementation->map.slots[index];
        if (slot->state != MAP_SLOT_LIVE)
            continue;
        SidecarLiveView view = {
            .entry = &slot->value.entry.entry,
            .xattrs = slot->value.entry.xattrs,
            .xattr_count = slot->value.entry.entry.xattr_count,
            .generation = slot->value.entry.generation
        };
        if (callback(&view, context) != 0)
            return SIDECAR_STATUS_CALLBACK;
    }
    return SIDECAR_STATUS_OK;
}

SidecarStatus sidecar_log_claim_foreach(SidecarLog *log,
                                        SidecarClaimCallback callback,
                                        void *context)
{
    SidecarLogImplementation *implementation = NULL;
    SidecarStatus status = ready_log(log, &implementation);
    if (status != SIDECAR_STATUS_OK)
        return status;
    if (callback == NULL)
        return SIDECAR_STATUS_INVALID_ARGUMENT;

    for (size_t index = 0; index < implementation->claim_map.capacity; index++)
    {
        MapSlot *slot = &implementation->claim_map.slots[index];
        if (slot->state != MAP_SLOT_LIVE)
            continue;
        SidecarClaimView view = {
            .claim = &slot->value.claim.claim,
            .generation = slot->value.claim.generation
        };
        if (callback(&view, context) != 0)
            return SIDECAR_STATUS_CALLBACK;
    }
    return SIDECAR_STATUS_OK;
}

int sidecar_log_find_deleted(const SidecarLog *log, SidecarBytes root_id,
                             SidecarBytes logical_path, SidecarLiveView *out)
{
    return find_live_entry(log, root_id, logical_path, 1, out);
}

int sidecar_log_find_claim(const SidecarLog *log, SidecarBytes root_id,
                           SidecarBytes logical_path, SidecarClaimView *out)
{
    if (out == NULL)
    {
        set_invalid_error();
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (log == NULL || log->implementation == NULL ||
        !valid_key(root_id, logical_path))
    {
        set_invalid_error();
        return -1;
    }
    const SidecarLogImplementation *implementation = log->implementation;
    size_t index = map_find(&implementation->claim_map, root_id,
                            logical_path);
    if (index == MAP_INDEX_NONE)
        return 0;
    const StateClaim *claim =
        &implementation->claim_map.slots[index].value.claim;
    out->claim = &claim->claim;
    out->generation = claim->generation;
    return 1;
}
