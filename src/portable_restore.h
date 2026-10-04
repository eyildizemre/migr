#ifndef PORTABLE_RESTORE_H
#define PORTABLE_RESTORE_H

#include <stddef.h>
#include <limits.h>
#include <sys/types.h>

#include "fileops.h"
#include "manifest.h"
#include "podman_state.h"
#include "metadata.h"
#include "sidecar.h"
#include "xdg.h"

/* Files an open application would overwrite, restored last (D66). */
typedef struct {
    /* Shown to the user, e.g. "Visual Studio Code". */
    const char *label;
    /* Below the destination home, e.g. ".config/Code". */
    const char *home_relative;
} PortableRestoreDeferredPath;

typedef struct {
    int source_container_fd;
    const Manifest *manifest;
    int destination_home_fd;
    /* Borrowed display path for preflight diagnostics; the fd remains the
     * authoritative filesystem target. */
    const char *destination_home_path;
    /* Restore-time XDG destinations, resolved for the current HOME. The
     * request borrows these strings; they are never serialized in a manifest. */
    const char *destination_xdg_dirs[XDG_KEY_COUNT];
    /* Measured policy for the destination filesystem. */
    MetadataTimestampPolicy destination_timestamp_policy;
    /* Who gets the backup user's items (D85); zeroed for as recorded. */
    OwnerMap owner_map;
    /* Borrowed byte/progress/sync state for a live replay; NULL disables it. */
    BackupCaptureReport *capture_report;
    /* Verification is on by default. This opt-out is restore-only CLI policy. */
    int skip_content_verification;
    /* Lets the CLI retire its copy-progress renderer before verification starts. */
    void (*before_content_verification)(void *context);
    void *before_content_verification_context;
    /* Optional; asks in place of the default question before a live
     * (non-dry-run) orchestrated restore changes anything. Returns 1 to
     * restore, 0 to stop with PORTABLE_RESTORE_CANCELLED. */
    int (*confirm)(void *context);
    void *confirm_context;
    /* Optional. Initialize *dconf_database_fd_out to -1; when replay applies
     * the source HOME's .config/dconf/user, it stores a read-only fd of that
     * payload there so the caller can load it into a running session. The
     * caller closes it. NULL disables this. */
    int *dconf_database_fd_out;
    /* Nonzero when the caller loads that payload into a running session
     * (D50). Only then is an existing ~/.config/dconf/user left in place like
     * other live state (D65); otherwise replay writes it (D80). */
    int dconf_loads_into_session;
    /* Nonzero when the target user has a running session, whose services
     * rewrite live desktop state: only then is such state that is already
     * at its destination left in place (D65). Otherwise the backup's copy
     * is restored, as from a text console (D100). */
    int session_running;
    /* Optional. Regular files, symlinks, and hardlinks below these paths of
     * home-relative roots are restored after everything else. Right before
     * that, before_deferred (if set) decides: 1 restores them, 0 leaves them
     * out. Directories are prepared as usual. */
    const PortableRestoreDeferredPath *deferred_paths;
    size_t deferred_path_count;
    int (*before_deferred)(void *context);
    void *before_deferred_context;
    /* Optional. When set, podman's container state in the source HOME's
     * storage folder is left out (D94), and the containers it leaves out
     * are stored here; the caller frees them with podman_containers_free(). */
    PodmanContainers *left_out_containers;
} PortableRestoreRequest;

typedef enum {
    PORTABLE_RESTORE_COMPLETE,
    PORTABLE_RESTORE_DRY_RUN,
    PORTABLE_RESTORE_CANCELLED,
    PORTABLE_RESTORE_ERROR,
    /* Every entry was applied, but read-back verification found items that
     * differ from the backup (report->verification_failed_count). */
    PORTABLE_RESTORE_VERIFICATION_FAILED
} PortableRestoreOutcome;

typedef struct {
    char id[MANIFEST_ID_MAX];
    size_t live_count;
    size_t violation_count;
} PortableRestoreRootReport;

typedef struct {
    size_t live_count;
    size_t mapped_root_count;
    size_t violation_count;
    size_t root_count;
    off_t estimated_bytes;
    PortableRestoreRootReport *roots;
    MetadataProfiles profiles;
} PortableRestorePreflightReport;

typedef enum {
    PORTABLE_RESTORE_REPLAY_FAILURE_NONE = 0,
    PORTABLE_RESTORE_REPLAY_FAILURE_FIND_ROOT,
    PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_SIDECAR_PATH,
    PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY,
    PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ADDRESS_INDEX,
    PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_MANIFEST_OWNERSHIP,
    PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_HOME_REWRITE_TABLE,
    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_PLACEHOLDER,
    PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_ENTRY,
    PORTABLE_RESTORE_REPLAY_FAILURE_FIND_HARDLINK_ROOT,
    PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_HARDLINK_OWNERSHIP,
    PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_HARDLINK_DESTINATION,
    PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_ENTRY_STAT,
    PORTABLE_RESTORE_REPLAY_FAILURE_RESERVE_ENTRY,
    PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_DESTINATION_PATH,
    PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_ADDRESS_INDEX,
    PORTABLE_RESTORE_REPLAY_FAILURE_REGISTER_DESTINATION_ANCHOR,
    PORTABLE_RESTORE_REPLAY_FAILURE_MAP_DESTINATION_IDENTITY,
    PORTABLE_RESTORE_REPLAY_FAILURE_FINALIZE_DESTINATION_IDENTITY,
    PORTABLE_RESTORE_REPLAY_FAILURE_ORDER_DESTINATION_IDENTITY,
    PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_PAYLOAD,
    PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT,
    PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
    PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_DESTINATION,
    PORTABLE_RESTORE_REPLAY_FAILURE_COPY_CONTENT,
    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_PAYLOAD,
    PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_OWNERSHIP_MODE,
    PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_XATTRS,
    PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES,
    PORTABLE_RESTORE_REPLAY_FAILURE_CREATE_SYMLINK,
    PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_REFERENCE,
    PORTABLE_RESTORE_REPLAY_FAILURE_CREATE_HARDLINK,
    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_HARDLINK,
    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
    PORTABLE_RESTORE_REPLAY_FAILURE_READ_DESTINATION_CONTENT,
    PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_DESTINATION_CONTENT,
    PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_BACKUP_CONTENT,
    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK,
    PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR
} PortableRestoreReplayFailureStep;

typedef struct {
    size_t live_count;
    size_t applied_count;
    size_t failed_count;
    size_t preserved_local_state_count;
    /* Live desktop state a running service had already written at the
     * destination, left as it was (D65). */
    size_t live_state_kept_count;
    /* Items restored last because an open application owns them (D66), and
     * how many of those were left out at the user's request. */
    size_t deferred_count;
    size_t deferred_skipped_count;
    size_t skipped_security_xattr_count;
    size_t verification_checked_count;
    size_t verification_failed_count;
    /* Items whose read-back differed because another program changed or
     * removed them after they were restored; not failures (D67). */
    size_t verification_changed_count;
    SidecarObjectKind failed_kind;
    int failed_kind_valid;
    PortableRestoreReplayFailureStep failure_step;
    int failure_errno;
    char failed_root_id[MANIFEST_ID_MAX];
    char failed_logical_path[PATH_MAX];
} PortableRestoreReplayReport;

/* The caller initializes and releases the report around one preflight. */
void portable_restore_preflight_report_init(
    PortableRestorePreflightReport *report);
void portable_restore_preflight_report_free(
    PortableRestorePreflightReport *report);

/* Read-only seam (docs/DECISIONS.md D17); called by production restore()
 * only indirectly, through portable_restore_orchestrate_at(). */
int portable_restore_preflight_at(
    const PortableRestoreRequest *request,
    PortableRestorePreflightReport *report);

#ifdef PORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS
void portable_restore_preflight_test_set_progress_enabled(int enabled);
void portable_restore_preflight_test_reset_profile_root_walk_count(void);
size_t portable_restore_preflight_test_profile_root_walk_count(void);
#endif

void portable_restore_replay_report_init(PortableRestoreReplayReport *report);

/* Applies live sidecar entries with fd-anchored revalidation and metadata. */
int portable_restore_replay_at(
    const PortableRestoreRequest *request,
    PortableRestoreReplayReport *report);

/* Confirmation-gated composition of preflight, probe, and replay. */
int portable_restore_at(const PortableRestoreRequest *request,
                       PortableRestoreReplayReport *report);

/**
 * Composes preflight, confirmation, destination timestamp measurement, probe,
 * and replay while reporting distinct completion outcomes. The destination
 * timestamp policy is measured after confirmation and before replay; the
 * caller-supplied policy is not used. This primitive does not print the final
 * completion summary; its caller owns that output (docs/DECISIONS.md D24).
 */
PortableRestoreOutcome portable_restore_orchestrate_at(
    const PortableRestoreRequest *request,
    PortableRestoreReplayReport *report);

#endif
