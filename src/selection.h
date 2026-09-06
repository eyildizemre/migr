#ifndef SELECTION_H
#define SELECTION_H

#include "backup_plan.h"
#include "config.h"
#include <stdint.h>

typedef struct {
    char **paths;
    size_t count;
} SelectionPaths;

typedef struct SelectionRoot {
    BackupPlanRoot root;
    int parent; /* -1 for a top-level owner; otherwise an earlier root index. */
    uint32_t xdg_aliases; /* Bits in xdg_keys order, including the chosen key. */
    SelectionPaths excluded; /* Root-relative user exclusions. */
    SelectionPaths delegated; /* Root-relative immediate child boundaries. */
} SelectionRoot;

/* D34's compiled source ownership forest. This is deliberately distinct from
 * BackupPlan: unfiltered walkers cannot safely consume delegated/excluded roots.
 * No config file lookup, capture or manifest mutation occurs during compilation. */
typedef struct SelectionPlan {
    char home[PATH_MAX];
    ManifestScope scope;
    SelectionRoot *roots;
    size_t root_count;
    SelectionPaths excludes; /* Canonical absolute rules, including missing paths. */
} SelectionPlan;

int selection_plan_build(const char *home, BackupMode mode,
                         const Config *config, SelectionPlan *out);
void selection_plan_free(SelectionPlan *plan);
/* Owns a copied root/policy table. Uses VERSION=1 for unfiltered disjoint plans.
 * Caller supplies source identity and representation/sidecar/optional flags. */
int selection_plan_manifest(const SelectionPlan *plan, Manifest *out);
/* Read-only structural validation of source ownership and payload separation. */
int selection_plan_validate(const SelectionPlan *plan);
/* Pure component matching; rel must be canonical, with "" denoting the root.
 * Return 1 for owned entries, 0 for pruned entries, -1 for invalid input. */
int selection_root_owns(const SelectionRoot *root, const char *rel);
/* Absolute source-address counterpart; no filesystem resolution. */
int selection_source_owns(const SelectionRoot *root, const char *source);
void selection_plan_estimate_size(const SelectionPlan *plan, off_t block_size,
                                  off_t *total, int *had_error);
/* Inventory is read-only; the caller probes the aggregated profiles before
 * setting metadata_preflight_done and capturing an identically adopted policy. */
int backup_selection_inventory(const SelectionPlan *plan, int anchor_fd,
                                int data_fd, MetadataProfiles *profiles);
/* Owns fresh cross-root hardlink/visited maps. Reconciles only after every root
 * succeeds. report, if supplied, must be initialized by the caller; progress
 * and sync settings are retained across roots. data_fd must belong to a fresh or identity-matched native container. */
BackupCaptureStatus backup_selection_capture(const CloneContext *ctx,
                                             const SelectionPlan *plan,
                                             int data_fd, BackupCaptureReport *report);
/* Preserve the conservative destination containment gate, even in exclusions. */
int selection_destination_conflicts(const SelectionPlan *plan, const char *destination);

/* Shared compiler primitives; normalization preserves the final symlink object.
 * Missing ancestors of exclusion rules remain lexical. An excluded include is
 * returned as 1 without inspecting the excluded subtree; failures return -1. */
int selection_normalize(const char *home, const char *raw,
                        const SelectionPaths *excludes, int allow_missing, char out[PATH_MAX]);
int selection_path_covers(const char *parent, const char *path);
int selection_paths_add(SelectionPaths *paths, const char *path);
void selection_paths_free(SelectionPaths *paths);
void selection_paths_reduce(SelectionPaths *paths);

#endif
