#ifndef MIGR_PORTABLE_RESTORE_INTERNAL_H
#define MIGR_PORTABLE_RESTORE_INTERNAL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "manifest.h"
#include "sidecar.h"

/* Shared by portable_restore_replay.c, portable_restore_preflight.c, and
 * portable_restore_shared.c. */

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
    void *nodes;
    size_t node_count;
    size_t node_capacity;
    size_t node_limit;
    void *identity_slots;
    size_t identity_capacity;
    void *namespace_slots;
    size_t namespace_count;
    size_t namespace_capacity;
    size_t namespace_limit;
    void *topology_slots;
    size_t topology_count;
    size_t topology_capacity;
    PreflightMemory memory;
    uint64_t hash_salt;
    int finalized;
} DestinationIdentityGraph;

typedef enum {
    DESTINATION_IDENTITY_DIRECTORY = 0,
    DESTINATION_IDENTITY_NON_DIRECTORY
} DestinationIdentityClaim;

typedef enum {
    DESTINATION_IDENTITY_PORTABLE_BOUNDS = 0,
    DESTINATION_IDENTITY_NATIVE_BOUNDS
} DestinationIdentityBounds;

typedef enum {
    DESTINATION_IDENTITY_OK = 0,
    DESTINATION_IDENTITY_COLLISION,
    DESTINATION_IDENTITY_PATH_ERROR,
    DESTINATION_IDENTITY_RESOURCE_ERROR,
    DESTINATION_IDENTITY_CYCLE
} DestinationIdentityStatus;

typedef struct {
    size_t node;
    int is_directory;
} DestinationIdentityPlacement;

typedef struct {
    size_t root_index;
    const unsigned char *logical;
    size_t logical_length;
    DestinationIdentityClaim claim;
    DestinationIdentityPlacement *placement;
} DestinationIdentityEntryView;

typedef void (*DestinationIdentityEntryReader)(
    void *context, size_t index, DestinationIdentityEntryView *view);
typedef void (*DestinationIdentityFailureReporter)(void *context,
                                                   size_t index);

typedef enum {
    DESTINATION_IDENTITY_AGGREGATE_COLLISIONS = 0,
    DESTINATION_IDENTITY_STOP_ON_COLLISION
} DestinationIdentityCollisionPolicy;

/* The declarations below are provided by portable_restore_shared.c. */
void *preflight_alloc(PreflightMemory *memory, size_t size);
void *preflight_realloc(PreflightMemory *memory, void *pointer,
                        size_t old_size, size_t new_size);
void preflight_free(PreflightMemory *memory, void *pointer, size_t size);
void *preflight_array_reserve(
    PreflightMemory *memory, void *items, size_t *capacity, size_t count,
    size_t extra, size_t element_size, size_t initial_capacity,
    size_t max_capacity, int clear_new);
int text_component_valid(const char *component, size_t length);
int relative_path_valid(const char *path, int allow_empty);
int manifest_text_valid(const char *text, size_t capacity, int nonempty);
int sidecar_path_valid(SidecarBytes bytes, int allow_empty);
int entry_physical_matches_parent(const ManifestRoot *root,
                                  const ParentMap *parent_map,
                                  const SidecarEntry *entry);
int root_map_build(RootMap *map, const Manifest *manifest);
void root_map_free(RootMap *map);
size_t root_map_find(const RootMap *map, const Manifest *manifest,
                     SidecarBytes id);
void parent_map_free(PreflightMemory *memory, ParentMap *map);
int parent_map_build(ParentMap *map, PreflightMemory *memory,
                     SidecarLog *sidecar);
int xdg_key_index(const char *id);
int xdg_destination_valid(const char * const *xdg_dirs,
                          const ManifestRoot *root);
int destination_path_build(const ManifestRoot *root, const char *logical,
                           const char * const *xdg_dirs,
                           char *out, size_t out_size);
int destination_absolute_path_build(
    const ManifestRoot *root, const char *logical,
    const char * const *xdg_dirs, const char *destination_home,
    char *out, size_t out_size);
int destination_relative_path_build(const char *prefix, const char *logical,
                                    char *out, size_t out_size);
int open_xdg_destination_anchor(const char *path, int *out_fd,
                                char *out_rel, size_t rel_size);
/* Address resolution is common plumbing, but preflight and replay must each
 * build and enforce their own destination graph (docs/DECISIONS.md D34).
 * Preflight aggregates mapped-entry conflicts for a complete report; replay
 * stops at the first conflict before it can mutate the destination. */
int destination_identity_route(
    const Manifest *manifest, size_t root_index, const char *logical,
    int destination_home_fd, const char * const *destination_xdg_dirs,
    int *xdg_anchor_fd, char (*xdg_anchor_prefix)[PATH_MAX], int *anchor_out,
    char *relative, size_t relative_size);
int sidecar_kind_to_type(SidecarObjectKind kind, mode_t *type);
int sidecar_is_complete_readonly(int container_fd);

void destination_identity_graph_init(DestinationIdentityGraph *graph,
                                     DestinationIdentityBounds bounds);
void destination_identity_graph_free(DestinationIdentityGraph *graph);
DestinationIdentityStatus destination_identity_graph_register_anchor(
    DestinationIdentityGraph *graph, int anchor_fd);
DestinationIdentityStatus destination_identity_graph_add(
    DestinationIdentityGraph *graph, int anchor_fd, const char *relative,
    DestinationIdentityClaim claim, size_t owner,
    DestinationIdentityPlacement *placement,
    size_t *conflicting_owner);
DestinationIdentityStatus destination_identity_graph_finalize(
    DestinationIdentityGraph *graph, int *nested_claims_out);
int destination_identity_graph_resume(DestinationIdentityGraph *graph);
int destination_identity_graph_add_entries(
    DestinationIdentityGraph *graph, const Manifest *manifest,
    size_t entry_count, int destination_home_fd,
    const char *destination_home_path,
    const char * const *destination_xdg_dirs, int *xdg_anchor_fd,
    char (*xdg_anchor_prefix)[PATH_MAX], DestinationIdentityEntryReader reader,
    DestinationIdentityFailureReporter report_failure, void *context,
    DestinationIdentityCollisionPolicy collision_policy);
int destination_identity_graph_order(
    const DestinationIdentityGraph *graph,
    const DestinationIdentityPlacement *placement, size_t *order_out);

#endif
