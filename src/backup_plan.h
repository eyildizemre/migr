#ifndef BACKUP_PLAN_H
#define BACKUP_PLAN_H

#include <limits.h> /* PATH_MAX */
#include <sys/types.h> /* off_t */

#include "backup.h"   /* BackupMode */
#include "manifest.h" /* ManifestRoot, ManifestScope */

/**
 * @brief Presentation/current-execution grouping for a planned root.
 *
 * Purely about which heading a root is listed under in backup output. It
 * never determines where a root's payload is written -- that address is
 * manifest_root.payload_path alone -- and it is orthogonal to
 * manifest_root.policy, which is the actual restore semantics
 * (docs/DECISIONS.md D16). BACKUP_ROOT_MAIN covers both true XDG roots and
 * the home-relative "Projects" root: both are listed under the same
 * "Main Directories" heading.
 */
typedef enum {
    BACKUP_ROOT_MAIN,
    BACKUP_ROOT_DOTFILE,
    BACKUP_ROOT_BROWSER,
    BACKUP_ROOT_EXPLICIT
} BackupRootGroup;

/**
 * @brief One planned root: where to capture it from, its full manifest
 * identity/addressing, and which output section it belongs to.
 *
 * capture_path is the normalized absolute source address a future capture
 * step should open directly -- its final path component is never resolved
 * through a symlink target (docs/DECISIONS.md D16: the symlink object itself
 * is what gets captured/restored, not whatever it currently points at).
 */
typedef struct {
    char capture_path[PATH_MAX];
    ManifestRoot manifest_root;
    BackupRootGroup group;
} BackupPlanRoot;

/**
 * @brief A full, deterministic backup plan: scope plus the ordered root
 * table backup_plan_build() produced from it.
 *
 * roots is a heap array owned by this struct; backup_plan_free() releases
 * it. A zero-initialized BackupPlan (root_count 0, roots NULL) is always a
 * safe, empty plan.
 */
typedef struct {
    ManifestScope scope;
    int root_count;
    BackupPlanRoot *roots;
} BackupPlan;

/**
 * @brief Builds a deterministic set of backup roots from HOME and the
 * requested mode.
 *
 * This function is read-only over the source side: it never reads the
 * global dry_run flag, never touches a destination, and never calls into
 * fsprobe/container/manifest-writing code -- a plan built during a dry run
 * is byte-for-byte the plan a live run would build, and a rejected plan
 * never creates or mutates anything. It only ever inspects the filesystem
 * (lstat/realpath) to classify candidates, and for explicit paths that
 * inspection is not restricted to HOME -- a path entirely outside HOME is
 * a legitimate MANUAL_NATIVE root, not an error.
 *
 * BACKUP_CRITICAL/BACKUP_COMPREHENSIVE build the fixed built-in catalog
 * (XDG main directories, dotfiles, browser profiles, and -- comprehensive
 * only -- Projects); a built-in that genuinely does not exist is left out of
 * the plan, not treated as an error. BACKUP_EXPLICIT_PATHS instead
 * normalizes and classifies explicit_paths: each is assigned a stable
 * "EXPLICIT_n" id after the whole set is sorted by normalized path (so
 * argument order never changes root identity), and classified
 * ROOT_POLICY_HOME_RELATIVE or ROOT_POLICY_MANUAL_NATIVE by whether it
 * resolves under HOME (docs/DECISIONS.md D16). Two explicit roots that
 * happen to share a basename are distinct roots here and stay distinct
 * downstream: each has its own payload_path, so neither can shadow the
 * other.
 *
 * Any invalid, missing (explicit only), inaccessible, duplicate, overlapping,
 * unsupported-type (socket/device), or resource-exhausting input rejects the
 * whole call: *out is left a safe, empty plan and nothing is partially
 * populated.
 *
 * @param home           The user's home directory; used as a directory
 *                        anchor (resolved canonically) and, for
 *                        BACKUP_CRITICAL/BACKUP_COMPREHENSIVE, as the base
 *                        for the built-in catalog.
 * @param mode           Selects the built-in catalog or explicit-path mode.
 * @param explicit_paths NULL-terminated array of paths; required and used
 *                        only when mode is BACKUP_EXPLICIT_PATHS.
 * @param out            Zeroed and populated on any return; owns its root
 *                        array on success, safe to pass to
 *                        backup_plan_free() in every case.
 * @return 0 on success, -1 on any rejection (a message is printed).
 */
int backup_plan_build(const char *home, BackupMode mode,
                      const char *const *explicit_paths, BackupPlan *out);

/**
 * @brief Estimates the destination allocation represented by a built plan.
 *
 * This is read-only over the source side and never touches a destination.
 * block_size is a caller-supplied destination allocation hint; the estimator
 * never derives it or performs destination I/O itself. Values <= 1 disable
 * regular-file rounding while hardlink deduplication remains active. A root
 * that disappears between planning and measurement is benign and contributes
 * zero. Other measurement failures contribute zero for that root and set
 * *had_error, matching report.c's scoped measurement posture.
 */
void backup_plan_estimate_size(const BackupPlan *plan, off_t block_size,
                               off_t *total, int *had_error);

/**
 * @brief Whether writing a backup to destination would place it inside a tree
 * the plan is going to capture.
 *
 * A destination equal to, or below, any selected root makes the capture feed
 * on its own output: every object written into the destination becomes another
 * object still to be captured. Comparison is on the same normalized
 * capture_path addresses the plan already validated, at component boundaries,
 * so a lexical prefix does not count and a selected symlink (which is captured
 * as itself, never descended into) cannot produce a false positive.
 *
 * Read-only, like the rest of this module: callers must ask before creating or
 * probing the destination, so a refusal costs nothing on disk in a live run or
 * a dry run alike.
 *
 * @param plan        A built plan; NULL reports no conflict.
 * @param destination The backup destination, which need not exist yet.
 * @return 1 if the invocation must be refused (a message is printed), 0 otherwise.
 */
int backup_plan_destination_conflicts(const BackupPlan *plan, const char *destination);

/**
 * @brief Releases the heap-owned root array. Safe on NULL and on an
 * all-zero/never-built BackupPlan.
 */
void backup_plan_free(BackupPlan *plan);

#endif
