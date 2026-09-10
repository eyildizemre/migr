#ifndef PORTABLE_RESTORE_H
#define PORTABLE_RESTORE_H

#include <stddef.h>
#include <limits.h>
#include <sys/types.h>

#include "fileops.h"
#include "manifest.h"
#include "metadata.h"
#include "sidecar.h"
#include "xdg.h"

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
    /* Borrowed byte/progress/sync state for a live replay; NULL disables it. */
    BackupCaptureReport *capture_report;
    /* Verification is on by default. This opt-out is restore-only CLI policy. */
    int skip_content_verification;
    /* Lets the CLI retire its copy-progress renderer before verification starts. */
    void (*before_content_verification)(void *context);
    void *before_content_verification_context;
} PortableRestoreRequest;

typedef enum {
    PORTABLE_RESTORE_COMPLETE,
    PORTABLE_RESTORE_DRY_RUN,
    PORTABLE_RESTORE_CANCELLED,
    PORTABLE_RESTORE_ERROR
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
    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK,
    PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR
} PortableRestoreReplayFailureStep;

typedef struct {
    size_t live_count;
    size_t applied_count;
    size_t failed_count;
    size_t skipped_security_xattr_count;
    size_t verification_checked_count;
    size_t verification_failed_count;
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
void portable_restore_preflight_test_configure_payload_pool(
    size_t worker_count, unsigned int worker_delay_ms,
    const char *delayed_payload_leaf,
    const char *duplicate_payload_leaf);
void portable_restore_preflight_test_reset_payload_pool(void);
size_t portable_restore_preflight_test_payload_peak_workers(void);
size_t portable_restore_preflight_test_payload_checked_count(void);
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
