#ifndef MIGR_SIDECAR_STATE_INTERNAL_H
#define MIGR_SIDECAR_STATE_INTERNAL_H

#include "sidecar.h"

#include <stdint.h>

/* Shared between sidecar_state.c and sidecar_state_map.c only -- nothing
 * outside sidecar_state.c's own translation units references any of
 * this. */

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

#define MAP_INDEX_NONE SIZE_MAX

/* Owned-value layer (sidecar_state.c) -- needed by the map layer. */
void *state_alloc(StateMemory *memory, size_t size);
void state_free(StateMemory *memory, void *pointer, size_t size);
void set_invalid_error(void);
int bytes_valid(SidecarBytes bytes, size_t maximum, int nonempty);
void clear_entry(StateMemory *memory, StateEntry *entry);
void clear_claim(StateMemory *memory, StateClaim *claim);

/* Map layer (sidecar_state_map.c) -- needed by log lifecycle/replay and
 * the public mutation/query API in sidecar_state.c. */
size_t map_find(const StateMap *map, SidecarBytes root_id,
                SidecarBytes logical_path);
uint64_t map_hash(const StateMap *map, SidecarBytes root_id,
                  SidecarBytes logical_path);
int map_locate(const StateMap *map, SidecarBytes root_id,
               SidecarBytes logical_path, uint64_t hash, size_t *out_index);
SidecarStatus map_prepare_commit(StateMemory *memory, StateMap *map,
                                 const StateEntry *pending,
                                 size_t *existing_index, uint64_t *out_hash);
SidecarStatus map_prepare_claim(StateMemory *memory, StateMap *map,
                                SidecarBytes root_id,
                                SidecarBytes logical_path,
                                size_t *claim_index, uint64_t *out_hash);
void map_apply_claim(StateMemory *memory, StateMap *map, StateClaim *claim,
                     size_t claim_index, uint64_t hash);
SidecarStatus map_apply_remove(StateMemory *memory, StateMap *map,
                               size_t index);
void map_apply_commit(StateMemory *memory, StateMap *map,
                      PendingEntry *pending, size_t existing_index,
                      uint64_t hash);
SidecarStatus map_apply_delete(StateMemory *memory, StateMap *map,
                               SidecarBytes root_id, SidecarBytes logical_path);
SidecarStatus prepare_claim_consumption(const StateMap *claim_map,
                                        const SidecarEntry *entry,
                                        size_t *claim_index);
void map_free(StateMemory *memory, StateMap *map);
int valid_key(SidecarBytes root_id, SidecarBytes logical_path);

#endif
