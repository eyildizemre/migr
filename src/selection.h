#ifndef SELECTION_H
#define SELECTION_H

#include "backup_plan.h"
#include "config.h"
#include <stdint.h>

typedef struct {
    char **paths;
    size_t count;
} SelectionPaths;

typedef struct {
    BackupPlanRoot root;
    int parent; /* -1 for a top-level owner; otherwise an earlier root index. */
    uint32_t xdg_aliases; /* Bits in xdg_keys order, including the chosen key. */
    SelectionPaths excluded; /* Root-relative user exclusions. */
    SelectionPaths delegated; /* Root-relative immediate child boundaries. */
} SelectionRoot;

/* D34's compiled source ownership forest. This is deliberately distinct from
 * BackupPlan: unfiltered walkers cannot safely consume delegated/excluded roots.
 * No config file lookup, capture or manifest mutation occurs during compilation. */
typedef struct {
    char home[PATH_MAX];
    ManifestScope scope;
    SelectionRoot *roots;
    size_t root_count;
    SelectionPaths excludes; /* Canonical absolute rules, including missing paths. */
} SelectionPlan;

int selection_plan_build(const char *home, BackupMode mode,
                         const Config *config, SelectionPlan *out);
void selection_plan_free(SelectionPlan *plan);
/* Read-only structural validation of source ownership and payload separation. */
int selection_plan_validate(const SelectionPlan *plan);
/* Pure component matching; rel must be canonical, with "" denoting the root.
 * Return 1 for owned entries, 0 for pruned entries, -1 for invalid input. */
int selection_root_owns(const SelectionRoot *root, const char *rel);
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
