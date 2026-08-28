#ifndef MIGR_PORTABLE_RESTORE_INTERNAL_H
#define MIGR_PORTABLE_RESTORE_INTERNAL_H

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

/* The declarations below are provided by portable_restore_shared.c. */
void *preflight_alloc(PreflightMemory *memory, size_t size);
void *preflight_realloc(PreflightMemory *memory, void *pointer,
                        size_t old_size, size_t new_size);
void preflight_free(PreflightMemory *memory, void *pointer, size_t size);
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
int destination_relative_path_build(const char *prefix, const char *logical,
                                    char *out, size_t out_size);
int open_xdg_destination_anchor(const char *path, int *out_fd,
                                char *out_rel, size_t rel_size);
int sidecar_kind_to_type(SidecarObjectKind kind, mode_t *type);
int sidecar_is_complete_readonly(int container_fd);

#endif
