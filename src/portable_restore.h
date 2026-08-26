#ifndef PORTABLE_RESTORE_H
#define PORTABLE_RESTORE_H

#include <stddef.h>
#include <limits.h>
#include <sys/types.h>

#include "fileops.h"
#include "manifest.h"
#include "metadata.h"
#include "xdg.h"

typedef struct {
    int source_container_fd;
    const Manifest *manifest;
    int destination_home_fd;
    /* Restore-time XDG destinations, resolved for the current HOME. The
     * request borrows these strings; they are never serialized in a manifest. */
    const char *destination_xdg_dirs[XDG_KEY_COUNT];
    /* Measured policy for the destination filesystem. */
    MetadataTimestampPolicy destination_timestamp_policy;
    /* Borrowed byte/progress/sync state for a live replay; NULL disables it. */
    BackupCaptureReport *capture_report;
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
    PortableRestoreRootReport *roots;
    MetadataProfiles profiles;
} PortableRestorePreflightReport;

typedef struct {
    size_t live_count;
    size_t applied_count;
    size_t failed_count;
    size_t skipped_security_xattr_count;
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
