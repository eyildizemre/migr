#ifndef FILEOPS_H
#define FILEOPS_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

/**
 * @brief How a clone is oriented and represented.
 *
 * `operation` is the direction the tree flows — a backup captures the source, a restore
 * writes it back. `representation` is whether metadata a destination cannot hold natively
 * is instead carried in a sidecar. The native capture/restore entry points
 * implement CLONE_NATIVE_TREE; CLONE_PORTABLE_SIDECAR is served by portable.c.
 */
typedef enum { CLONE_BACKUP, CLONE_RESTORE } CloneOperation;
typedef enum { CLONE_NATIVE_TREE, CLONE_PORTABLE_SIDECAR } CloneRepresentation;

typedef struct CloneContext {
    CloneOperation operation;
    CloneRepresentation representation;
    int timestamp_policy_configured;
    int nsec_exact;
    int metadata_preflight_done;
    void *inode_map; /* NativeInodeMap; backup/restore tracking; NULL disables it. */
    void *visited; /* Native visited-path set, backup-only; NULL disables tracking. */
} CloneContext;

/* Opaque native hardlink map ownership. */
void *native_inode_map_create(void);
void native_inode_map_free(void *map);

/**
 * @brief Seeds native hardlink representatives from existing destination state.
 *
 * The source and destination trees are inspected without mutation. Existing
 * regular payloads whose size and mtime prove completed work seed the map by
 * source inode, so a resumed capture or restore may visit the sibling before
 * the old representative without changing the selected destination inode.
 * destination_rel may be a safe relative path or "" for the destination root.
 */
int native_inode_map_seed_existing(const CloneContext *ctx,
                                   const char *source_path,
                                   int destination_root_fd,
                                   const char *destination_rel);
int native_hardlink_identity_matches(const struct stat *linked,
                                     const struct stat *reference);

/* Opaque native-capture visited-path set ownership (docs/DECISIONS.md D23). */
void *native_visited_create(void);
void native_visited_free(void *visited);
int native_visited_contains(const void *visited, const char *root_key,
                            const char *rel_path);

#ifdef NATIVE_VISITED_TEST_HOOKS
uint64_t native_visited_test_probe_count(void);
void native_visited_test_reset_probe_count(void);
uint64_t native_inode_map_test_probe_count(void);
void native_inode_map_test_reset_probe_count(void);
size_t native_inode_map_test_dir_fd_count(const void *map);
#endif

typedef struct {
    char failed_relative_path[PATH_MAX];
} NativeReconcileReport;

void native_reconcile_report_init(NativeReconcileReport *report);

typedef enum {
    NATIVE_RECONCILE_ERROR = -1,
    NATIVE_RECONCILE_OK = 0
} NativeReconcileStatus;

/**
 * @brief Removes destination entries absent from a completed native capture.
 *
 * The caller must invoke this only after every root in the capture walk has
 * completed successfully. The destination is traversed beneath data_fd with
 * no-follow fd operations; a root object recorded by the capture is never a
 * reconciliation target. A root deliberately skipped as an unsupported
 * special file is unvisited and is therefore stale (docs/DECISIONS.md D23).
 */
NativeReconcileStatus native_reconcile_stale_at(
    const void *visited, const char *root_key, int data_fd,
    NativeReconcileReport *report);

typedef struct MetadataProfiles MetadataProfiles;

/**
 * @brief Native restore byte estimate accumulated during metadata inventory.
 *
 * The estimate counts regular-file content once per source inode across all
 * restore roots, source directory sizes, and symlink target bytes. A failed
 * accounting operation is recorded in had_error so the caller can keep D27's
 * fail-open behaviour for an unmeasurable estimate.
 */
typedef struct {
    off_t estimated_bytes;
    int had_error;
    void *seen_inodes;
} NativeRestoreEstimate;

void native_restore_estimate_init(NativeRestoreEstimate *estimate);
void native_restore_estimate_free(NativeRestoreEstimate *estimate);

/**
 * @brief Result of a native backup capture.
 *
 * BACKUP_CAPTURE_SOURCE_SAFE_READ is distinct from an ordinary I/O failure: the
 * source could not be opened with O_NOATIME and was not retried without it
 * (docs/DECISIONS.md D17).
 */
typedef enum {
    BACKUP_CAPTURE_ERROR = -1,
    BACKUP_CAPTURE_OK = 0,
    BACKUP_CAPTURE_SOURCE_SAFE_READ = -2
} BackupCaptureStatus;

typedef void (*BackupProgressCallback)(off_t bytes_copied,
                                       const char *current_path,
                                       void *userdata);

/**
 * @brief State shared by one native capture or restore across its roots.
 *
 * bytes_copied and the progress fields describe successful regular-file
 * content bytes only. Hardlinked siblings add no new bytes because they are
 * linked to an existing representative, matching the source-size accounting
 * used by backup_plan_estimate_size().
 * bytes_since_sync accumulates the same content bytes until the configured
 * periodic-sync interval is reached; an interval of zero disables syncing.
 */
typedef struct {
    char failed_source_path[PATH_MAX];
    off_t bytes_copied;
    char current_path[PATH_MAX];
    off_t bytes_since_sync;
    off_t sync_interval_bytes;
    BackupProgressCallback progress_cb;
    void *progress_userdata;
    struct timespec progress_last_fired;
    int progress_unthrottled;
} BackupCaptureReport;

void backup_capture_report_init(BackupCaptureReport *report);
int backup_capture_report_tick(BackupCaptureReport *report,
                               off_t chunk_size, int destination_fd);

#ifdef BACKUP_TEST_HOOKS
typedef void (*BackupTestCaptureHook)(const char *source_path,
                                      void *context);

void backup_test_set_capture_hook(BackupTestCaptureHook hook, void *context);
#endif

/**
 * @brief Captures a source tree into an open destination directory.
 *
 * Regular files, directories, symlinks and FIFOs are reproduced; Unix sockets and
 * device nodes are skipped with a warning; permissions and access/modification times
 * are preserved.
 *
 * The source is addressed by pathname, exactly as the caller named it. The
 * destination never is: destination_root_fd is a directory fd the caller opens once
 * and continues to own, and every step below it uses openat/mkdirat/fstatat with
 * O_NOFOLLOW. No intermediate or final symlink inside the destination is ever
 * followed, so payload cannot be redirected outside the container it belongs to
 * (docs/DECISIONS.md D15) -- including when writing into a container a previous,
 * interrupted run already populated.
 *
 * Resuming is address-by-address, and only where the existing object proves the work
 * was already done: a regular file whose size and mtime match is skipped, a symlink
 * with the identical target is accepted, and an existing directory or FIFO is
 * accepted when it is genuinely that type. Every other collision -- a differing
 * symlink target, or any type mismatch -- is an error, never an overwrite.
 *
 * The context is validated, not merely carried: a NULL ctx, a mismatched operation, or
 * an unsupported representation is refused rather than run, so a dispatch mistake
 * fails closed instead of writing a native tree to a destination that needed a
 * sidecar.
 *
 * @param ctx                 Clone orientation and representation; must not be NULL.
 * @param source_path         Path to the source file, directory, or symlink.
 * @param destination_root_fd Open directory fd anchoring destination_leaf; never closed here.
 * @param destination_leaf    Exactly one path component to create beneath it; a name
 *                            containing '/', or "." or "..", is refused.
 * @return BACKUP_CAPTURE_OK on success, BACKUP_CAPTURE_ERROR on an ordinary
 *         failure, or BACKUP_CAPTURE_SOURCE_SAFE_READ when O_NOATIME access
 *         was refused.
 */
BackupCaptureStatus backup_capture_at_report(
    const CloneContext *ctx, const char *source_path,
    int destination_root_fd, const char *destination_leaf,
    BackupCaptureReport *report);

/**
 * @brief Captures one root while preserving an already initialized report.
 *
 * This is used when one backup walks several roots and needs the byte counter
 * and throttle state to remain continuous. The caller owns initialization.
 */
BackupCaptureStatus backup_capture_at_report_continue(
    const CloneContext *ctx, const char *source_path,
    int destination_root_fd, const char *destination_leaf,
    BackupCaptureReport *report);

/**
 * @brief Captures a source object without requiring a refusal report.
 */
BackupCaptureStatus backup_capture_at(const CloneContext *ctx,
                                       const char *source_path,
                                       int destination_root_fd,
                                       const char *destination_leaf);

/**
 * @brief Result of checking a restore source beneath a directory fd.
 */
typedef enum {
    RESTORE_SOURCE_ERROR = -1,
    RESTORE_SOURCE_MISSING = 0,
    RESTORE_SOURCE_PRESENT = 1
} RestoreSourceStatus;

typedef enum {
    RESTORE_NATIVE_ERROR = -1,
    RESTORE_NATIVE_OK = 0,
    RESTORE_NATIVE_SOURCE_SAFE_READ = -2
} RestoreNativeStatus;

typedef struct {
    size_t applied_count;
    size_t failed_count;
    size_t skipped_security_xattr_count;
    char failed_logical_path[PATH_MAX];
} RestoreNativeReport;

/**
 * @brief Checks whether a source object exists without following symlinks.
 *
 * Intermediate components are resolved beneath source_root_fd with O_NOFOLLOW.
 * A dangling symlink at the final component is therefore PRESENT, while a
 * missing component is MISSING. Unsafe relative addresses and operational
 * failures are ERROR.
 */
RestoreSourceStatus restore_native_source_status_at(int source_root_fd,
                                                     const char *source_rel);

/**
 * @brief Validates an FD-anchored native restore without mutating the destination.
 *
 * Uses the same recursive walker and safety rules as restore_native_at(). It
 * checks lexical paths, source traversal, destination traversal and existing
 * destination object types, but does not promise that later writes cannot fail
 * for operational reasons such as permissions or free space. A source regular
 * file or directory that cannot be opened with O_NOATIME returns
 * RESTORE_NATIVE_SOURCE_SAFE_READ; no O_NOATIME-less read is attempted.
 */
RestoreNativeStatus restore_native_preflight_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel);

/**
 * @brief Collects native-restore metadata profiles without probing or mutating.
 *
 * This is the read-only half of the restore ownership preflight. It is useful
 * to aggregate all roots before confirmation, so a single later probe can
 * reject the invocation before any destination payload is changed. It returns
 * RESTORE_NATIVE_SOURCE_SAFE_READ when source inspection would require an
 * atime-changing fallback. Symlink target strings are deliberately not read
 * by this inventory walk: on Linux, readlinkat() itself perturbs a symlink's
 * atime (docs/DECISIONS.md D17 as-built), while the later restore pass still
 * performs ordinary target validation before applying the saved metadata.
 */
RestoreNativeStatus restore_native_metadata_inventory_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    MetadataProfiles *profiles, NativeRestoreEstimate *estimate);

/**
 * @brief FD-anchored native restore core (docs/DECISIONS.md D15 and D16).
 *
 * source_root_fd and destination_root_fd are directory fds the caller opens
 * exactly once (its own trust boundary), and source_rel/destination_rel are
 * relative addresses resolved underneath them component-by-component -- never
 * by string concatenation. Both the backup payload and the destination are
 * treated as untrusted: neither an intermediate symlink nor a symlink at the
 * final address is followed or silently replaced.
 *
 * source_rel must name an existing entry (no intermediate component is ever
 * created reading the source). destination_rel's intermediate components are
 * created as plain directories if missing; an existing intermediate that is
 * not a genuine, non-symlink directory is refused, not silently accepted.
 *
 * An empty string ("") is a valid relative address on either side, meaning
 * "the root object itself" (docs/DECISIONS.md D16: an empty HOME_RELATIVE
 * restore_path legitimately addresses $HOME itself) -- this is the one case
 * with zero path components, distinct from a rejected empty *interior*
 * component. Anything else that is lexically invalid (a leading '/', any
 * ".." component, an empty interior/trailing component, or a bare ".")  is
 * refused before any mutation is attempted; nothing is normalized into some
 * other address.
 *
 * This function never closes source_root_fd or destination_root_fd; the
 * caller owns them for as long as it needs them (e.g. across several calls
 * restoring several top-level items from the same backup into the same
 * destination). Every fd this function itself opens while recursing is
 * closed before returning.
 *
 * Before mutating the destination, this function runs the same recursive
 * checks exposed by restore_native_preflight_at().
 *
 * When ctx->inode_map is supplied, regular payload paths that share a source
 * inode are restored as one destination inode: the first successfully applied
 * member becomes the representative and later members are recreated with
 * linkat(). Validation never mutates that map. A NULL map deliberately keeps
 * the low-level core's tracking disabled; the real native restore() supplies
 * one for the complete apply walk.
 *
 * @param ctx                Clone orientation; must be CLONE_RESTORE +
 *                            CLONE_NATIVE_TREE.
 * @param source_root_fd      Open directory fd anchoring source_rel.
 * @param source_rel          Relative address of the source object, or "".
 * @param destination_root_fd Open directory fd anchoring destination_rel.
 * @param destination_rel     Relative address of the destination object, or "".
 * @param report            Optional per-call replay result; it is reset before
 *                          use and records applied/failed entries.
 * @param capture_report    Optional caller-owned byte/progress/sync state. The
 *                          caller must initialize it with
 *                          backup_capture_report_init() before the first call;
 *                          it is not reset here, so one instance can span
 *                          several sequential restore calls.
 * @return RESTORE_NATIVE_OK on success, RESTORE_NATIVE_ERROR on an ordinary
 *         failure, or RESTORE_NATIVE_SOURCE_SAFE_READ when a source open that
 *         requires O_NOATIME is refused. No O_NOATIME-less retry is attempted.
 */
RestoreNativeStatus restore_native_at_report(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel,
    RestoreNativeReport *report, BackupCaptureReport *capture_report);

RestoreNativeStatus restore_native_at(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel);

#ifdef FILEOPS_TEST_HOOKS
typedef enum {
    RESTORE_TEST_SOURCE_READ_NONE = 0,
    RESTORE_TEST_SOURCE_READ_VALIDATE = 1,
    RESTORE_TEST_SOURCE_READ_APPLY = 2
} RestoreNativeTestSourceReadMode;

typedef void (*RestoreNativeTestApplyHook)(const char *logical_path,
                                           void *context);

void restore_native_test_set_apply_hook(RestoreNativeTestApplyHook hook,
                                        void *context);

void restore_native_test_set_source_read_mode(
    RestoreNativeTestSourceReadMode mode);

void restore_native_test_fail_source_read_after(size_t successful_opens);
#endif

/**
 * @brief Accumulates the total byte size of a file tree into *size.
 *
 * Uses lstat so symlinks are counted by their own size rather than the
 * target's. FIFOs, sockets, and device nodes contribute no payload bytes. The
 * caller must initialize *size before the first call; the function adds to the
 * existing value on each recursive step.
 *
 * @param path Path to the file, directory, or symlink to measure.
 * @param size Pointer to an off_t accumulator; each entry's size is added to it.
 * @return 0 on success, -1 on filesystem errors.
 */
int get_dir_size(const char *path, off_t *size);

/**
 * @brief Executes a command via fork/execvp without invoking a shell.
 *
 * Forks a child process, executes argv[0] with the given argument vector,
 * and blocks until the child exits. Uses _exit in the child to avoid
 * flushing shared stdio buffers.
 *
 * @param argv NULL-terminated argument vector; argv[0] is the program to run.
 * @return The child's exit status on success, -1 if fork or waitpid fails.
 */
int run_command(char *const argv[]);

/**
 * @brief Executes a command and captures its stdout into a caller-supplied buffer.
 *
 * Uses fork/execvp with an anonymous pipe redirecting the child's stdout.
 * The output buffer is always null-terminated. Output is silently truncated
 * if it exceeds output_size - 1 bytes.
 *
 * @param argv        NULL-terminated argument vector; argv[0] is the program to run.
 * @param output      Buffer to receive the captured stdout.
 * @param output_size Total size of the output buffer in bytes.
 * @return The child's exit status on success, -1 if pipe, fork, or waitpid fails.
 */
int run_command_capture(char *const argv[], char *output, size_t output_size);

#endif
