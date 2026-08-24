#ifndef PORTABLE_H
#define PORTABLE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "fileops.h"
#include "manifest.h"
#include "sidecar.h"

typedef struct {
    SidecarXattr *items;
    size_t count;
    size_t capacity;
} PortableXattrs;

void xattrs_free(PortableXattrs *xattrs);
int collect_xattrs(int fd, PortableXattrs *out);
int collect_symlink_xattrs(const char *path, PortableXattrs *out);

/**
 * A source root and its container address for a portable capture.
 *
 * capture_path is opened as an absolute source path. The other fields are
 * copied into the fresh versioned manifest; payload_path is relative to the
 * container's data/ directory.
 */
typedef struct {
    const char *id;
    RootPolicy policy;
    const char *capture_path;
    const char *payload_path;
    const char *source_path;
    const char *restore_path;
    int has_restore_path;
} PortableRootSpec;

/**
 * Inputs for portable_capture_fresh_at(). The caller owns every pointer and
 * keeps it valid for the duration of the call.
 */
typedef struct {
    ManifestScope scope;
    int has_source_identity;
    const char *machine_id;
    uid_t source_uid;
    const PortableRootSpec *roots;
    size_t root_count;
    int nsec_exact;
    int case_sensitive;
} PortableCaptureRequest;

typedef enum {
    PORTABLE_PRESCAN_NAME_TOO_LONG,
    PORTABLE_PRESCAN_PATH_TOO_LONG,
    PORTABLE_PRESCAN_CASE_COLLISION,
    PORTABLE_PRESCAN_UNSUPPORTED_KIND
} PortablePrescanViolationKind;

typedef struct {
    char root_id[MANIFEST_ID_MAX];
    char logical_path[SIDECAR_MAX_PATH + 1U];
    PortablePrescanViolationKind kind;
    size_t limit;
    size_t actual;
    char collides_with_logical_path[SIDECAR_MAX_PATH + 1U];
} PortablePrescanViolation;

#define PORTABLE_PRESCAN_MAX_EXAMPLES 64U

typedef struct {
    char root_id[MANIFEST_ID_MAX];
    char logical_path[SIDECAR_MAX_PATH + 1U];
    char physical_path[SIDECAR_MAX_PATH + 1U];
    char collision_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
} PortableCollisionPlanEntry;

typedef struct {
    PortableCollisionPlanEntry *entries;
    size_t count;
    size_t capacity;
    int sorted;
} PortableCollisionPlan;

typedef struct {
    size_t total_count;
    size_t collision_count;
    size_t unresolved_count;
    PortablePrescanViolation *examples;
    size_t example_count;
    size_t example_capacity;
    PortableCollisionPlan collision_plan;
    size_t skipped_kind_count; /* Sockets/devices are capture warnings, not violations. */
    uint64_t total_size; /* Dense-copy bytes; hardlink groups count once. */
    void *inode_seen;    /* Opaque pre-scan inode set. */
} PortablePrescanReport;

void portable_prescan_report_init(PortablePrescanReport *report);
void portable_prescan_report_free(PortablePrescanReport *report);

void portable_collision_plan_init(PortableCollisionPlan *plan);
void portable_collision_plan_free(PortableCollisionPlan *plan);
const PortableCollisionPlanEntry *portable_collision_plan_find(
    const PortableCollisionPlan *plan, const char *root_id,
    const char *logical_path);

/* Runs the read-only pre-scan and fills the collision plan without applying
 * the capture gate. total_count remains the diagnostic count of every
 * violation; unresolved_count is the fatal subset after planned collisions
 * are accounted for (docs/DECISIONS.md D21, F-4/F-6). */
int portable_collision_plan_build(int container_fd,
                                  const PortableCaptureRequest *request,
                                  PortablePrescanReport *report);

/**
 * The pre-scan and expected manifest for one PortableCaptureRequest,
 * computed once and consumed by the prepared capture entry points and later
 * production container adoption (docs/DECISIONS.md D24).
 */
typedef struct {
    Manifest manifest;
    PortablePrescanReport report;
    int ready;
} PortablePreparedCapture;

/**
 * Runs the mandatory source pre-scan and builds the exact manifest a fresh or
 * resumed capture will use, without creating or reserving a container.
 * scratch_fd anchors the read-only case-collision probe and may be an
 * existing destination parent rather than a claimed container.
 * On a pre-scan or manifest-build refusal, ready remains zero while report
 * retains diagnostics for the caller; both are owned by out until freed.
 */
int portable_capture_prepare(int scratch_fd,
                             const PortableCaptureRequest *request,
                             PortablePreparedCapture *out);

/** Releases a prepared capture and is safe on zeroed or failed objects. */
void portable_prepared_capture_free(PortablePreparedCapture *prepared);

/**
 * State used by the direct portable capture seam. The data and sidecar
 * handles are borrowed; portable_capture_context_close() does not close them.
 */
typedef struct PortableCaptureContext {
    int data_fd;
    SidecarLog *sidecar;
    BackupCaptureReport *progress_report; /* Borrowed; NULL disables counting callbacks. */
    int nsec_exact;
    int case_sensitive;
    int resume_mode;
    const PortableCollisionPlan *collision_plan;
    void *visited;
    void *inode_map;
    void *owned_paths;
    void *claimed_paths;
} PortableCaptureContext;

/**
 * Initializes a capture context over an already-created data directory and
 * fresh or adopted sidecar log.
 */
int portable_capture_context_init(PortableCaptureContext *context,
                                  int data_fd, SidecarLog *sidecar,
                                  int nsec_exact, int case_sensitive);

/** Releases allocations owned by a capture context without closing handles. */
void portable_capture_context_close(PortableCaptureContext *context);

/** Captures one regular-file or directory root into an existing context. */
int portable_capture_root(PortableCaptureContext *context,
                          const PortableRootSpec *root);

/**
 * Runs the mandatory D19 source pre-scan before writing a portable v1 manifest,
 * then creates data/ and sidecar.migr and captures all roots into a fresh
 * container directory. The caller initializes and owns report when non-NULL;
 * NULL requests the same refusal behaviour without diagnostics. This direct
 * API is intentionally separate from production backup() dispatch.
 */
int portable_capture_fresh_at(int container_fd,
                              const PortableCaptureRequest *request,
                              PortablePrescanReport *report);

/**
 * Runs the mandatory D19 source pre-scan, then resumes a portable capture in
 * an existing versioned partial container. The manifest must match request; it
 * is never rewritten by this function. report follows the fresh-entry-point
 * ownership rules above.
 */
int portable_capture_resume_at(int container_fd,
                               const PortableCaptureRequest *request,
                               PortablePrescanReport *report);

/** Captures into a fresh container using a previously prepared plan. */
int portable_capture_fresh_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report);

/** Resumes a container using a previously prepared plan. */
int portable_capture_resume_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report);

typedef enum {
    PORTABLE_TEST_INTERRUPT_NONE = 0,
    PORTABLE_TEST_AFTER_MANIFEST,
    PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
    PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
    PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
    PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
    PORTABLE_TEST_BEFORE_PAYLOAD_WRITE,
    PORTABLE_TEST_AFTER_PAYLOAD_WRITE,
    PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE,
    PORTABLE_TEST_AFTER_PAYLOAD_CLOSE,
    PORTABLE_TEST_AFTER_STALE_DELETE,
    PORTABLE_TEST_BEFORE_STALE_UNLINK,
    PORTABLE_TEST_AFTER_STALE_UNLINK,
    PORTABLE_TEST_BEFORE_FINAL_INVENTORY
} PortableTestInterruptPoint;

/*
 * Unlike SidecarTestInterruptPoint, this enum stays visible in every build:
 * portable.c calls portable_test_interrupt_if() with these constants at
 * unconditional call sites (not wrapped in #ifdef), relying on it compiling
 * down to a real no-op stub when PORTABLE_CAPTURE_TEST_HOOKS is off. Only the
 * setter below is part of the D14 seam.
 */
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
void portable_capture_test_set_interrupt(PortableTestInterruptPoint point);
uint64_t portable_capture_test_case_fs_probe_count(void);
void portable_capture_test_reset_case_fs_probe_count(void);
uint64_t portable_capture_test_inode_map_probe_count(void);
void portable_capture_test_reset_inode_map_probe_count(void);
uint64_t portable_capture_test_prescan_inode_probe_count(void);
void portable_capture_test_reset_prescan_inode_probe_count(void);
uint64_t portable_capture_test_sticky_seed_lstat_count(void);
void portable_capture_test_reset_sticky_seed_lstat_count(void);
uint64_t portable_capture_test_relocation_scan_count(void);
void portable_capture_test_reset_relocation_scan_count(void);
uint64_t portable_capture_test_relocation_remove_count(void);
#endif

#endif
