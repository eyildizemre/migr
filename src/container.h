#ifndef CONTAINER_H
#define CONTAINER_H

#include <time.h> /* time_t */

#include "manifest.h" /* Manifest */

/**
 * @brief The atomic backup container lifecycle (docs/DECISIONS.md D15).
 *
 * A container reserves a root directory for migr-owned control artifacts; every
 * user-derived object lives under that root's data/ (out of this module's scope --
 * see container_reserve()'s doc comment). This module owns only naming, claiming,
 * locking, adoption, and atomic publication of the container directory itself:
 *
 *   1. container_reserve()  -- claim a fresh, uniquely-named ".partial" directory.
 *   2. container_adopt()    -- resume a specific interrupted backup's ".partial".
 *   3. container_finalize() -- publish a reserved/adopted container atomically.
 *   4. container_close()    -- release the handle's fds (and thus its lock);
 *                              never deletes anything on disk.
 *
 * Every distinguishable outcome of those four calls.
 */
typedef enum {
    CONTAINER_OK = 0,
    CONTAINER_ERR_IO,           /**< open/stat/mkdir/lock/rename failed for a reason
                                     unrelated to the specific conditions below. */
    CONTAINER_ERR_NO_MATCH,     /**< adopt: nothing under dest_root matches
                                     wanted_identity (including: wanted_identity
                                     itself carries no source identity, which can
                                     never match anything -- docs/DECISIONS.md D15). */
    CONTAINER_ERR_AMBIGUOUS,    /**< adopt: more than one unlocked container matches
                                     wanted_identity exactly; resuming would be a guess. */
    CONTAINER_ERR_FINAL_EXISTS, /**< finalize: the final name is already taken. */
    CONTAINER_ERR_NOREPLACE,    /**< finalize: the destination filesystem/kernel does
                                     not support atomic no-replace rename here. */
    CONTAINER_ERR_INVALID       /**< a NULL out-param, or a handle not in the state
                                     the call requires (e.g. finalize on an empty or
                                     already-finalized handle). Caller programming
                                     error, not a runtime condition. */
} ContainerStatus;

/**
 * @brief Distinguishes an unused handle from a claimed-but-unpublished container
 * from a published one, so the zero-initialized case is safe by construction:
 * CONTAINER_STATE_EMPTY is 0, so a zeroed BackupContainer already reports "nothing
 * to release" without any separate sentinel or "initialized" flag.
 */
typedef enum {
    CONTAINER_STATE_EMPTY = 0, /**< zero-init default; no fd is owned. */
    CONTAINER_STATE_PARTIAL,   /**< reserve()/adopt() succeeded; ".partial" is live. */
    CONTAINER_STATE_FINALIZED  /**< finalize() succeeded; the final name is live. */
} ContainerState;

/**
 * @brief "migr_backup_YYYYMMDD_HHMMSS[-N]", plus the longer of ".partial" or
 * nothing, plus a NUL. Sized generously above the ~47-byte worst case (an N up
 * to INT_MAX) rather than to a specific expected count -- see container_reserve().
 */
#define CONTAINER_NAME_MAX 64

/**
 * @brief A caller-owned handle on one backup container.
 *
 * Fields are populated only by container_reserve()/container_adopt() and are
 * implementation detail: callers should treat this as opaque and go through the
 * API rather than reading or writing fields directly. It is safe to declare a
 * BackupContainer on the stack and zero it (BackupContainer c = {0};); every
 * function here tolerates and expects that as the initial state.
 *
 * partial_fd is retained (not reopened by name) for the handle's entire
 * lifetime, including after a successful finalize(): the rename changes the
 * directory's name, not its identity, so the same fd continues to refer to the
 * same inode. Holding it is also what keeps this handle's flock() held.
 */
typedef struct BackupContainer {
    ContainerState state;
    int  dir_fd;                        /**< dest_root, opened once, O_CLOEXEC. */
    int  partial_fd;                    /**< the container directory itself, O_CLOEXEC;
                                              valid whenever state != CONTAINER_STATE_EMPTY. */
    char partial_name[CONTAINER_NAME_MAX]; /**< leaf name while reserved/adopted. */
    char final_name[CONTAINER_NAME_MAX];   /**< leaf name once finalized. */
    int  suffix;                        /**< the "-N" used, 0 if none; diagnostic only. */
} BackupContainer;

/**
 * @brief Claims a fresh, uniquely-named ".partial" container under dest_root.
 *
 * The base name is derived from timestamp via localtime_r() (production's own
 * clock, passed in rather than read internally so tests can supply a fixed
 * value -- there is deliberately no CLI/environment clock override). Candidate
 * allocation considers both the partial and final forms of each name and
 * atomically claims the first free one; collisions advance to "-1", "-2", ...
 * with no artificial upper bound on N (only int's own range).
 *
 * dest_root is opened exactly once; every subsequent check uses that same
 * directory fd (fstatat/mkdirat/openat), so a path-level swap of dest_root
 * after this call cannot affect which directory is actually claimed.
 *
 * This call only reserves the container directory. Writing manifest.txt or
 * any payload under data/ is the caller's responsibility, done after this
 * returns CONTAINER_OK and before container_finalize().
 *
 * @param dest_root Destination directory the container is created under.
 * @param timestamp Naming clock, interpreted in local time.
 * @param out       Zeroed and populated on any return; CONTAINER_OK leaves it
 *                  holding an owned handle the caller must eventually pass to
 *                  container_finalize() and/or container_close().
 * @return CONTAINER_OK, CONTAINER_ERR_IO, or CONTAINER_ERR_INVALID (NULL out,
 *         or NULL dest_root).
 */
ContainerStatus container_reserve(const char *dest_root, time_t timestamp, BackupContainer *out);

/**
 * @brief Resumes the one existing ".partial" under dest_root whose manifest
 * proves it is the same job as wanted_identity.
 *
 * Scans dest_root's entries, considering only names matching the exact
 * grammar container_reserve() can produce (docs/DECISIONS.md D15). Each
 * candidate is opened by directory fd (never re-resolved by path) and
 * flock(LOCK_EX | LOCK_NB)'d before its manifest is read: a candidate another
 * live process already holds is skipped as "in use", not treated as an error.
 * Only a manifest that reads back MANIFEST_STATUS_VALID and compares equal
 * via manifest_resume_identity_compare() counts as a match; missing, legacy,
 * malformed, or unknown-version manifests are simply not adoptable. A
 * wanted_identity with no source identity can never match anything
 * (docs/DECISIONS.md D15) and is rejected before any scan is attempted.
 *
 * Any operational failure while scanning, opening a candidate, or comparing
 * its identity (including an allocation failure inside
 * manifest_resume_identity_compare() -- MANIFEST_IDENTITY_ERROR, never
 * silently treated as DIFFERENT) -- as opposed to that candidate simply not
 * matching -- makes the whole call fail closed (CONTAINER_ERR_IO) even if
 * exactly one match was already found: an entry this call could not read (or
 * could not finish comparing) might have been a second match it never got to
 * see.
 *
 * On the single-match success path, the same fd already opened, locked, and
 * verified during the scan is transferred into *out; it is never closed and
 * reopened by name.
 *
 * @param dest_root      Destination directory to scan.
 * @param wanted_identity The identity (docs/DECISIONS.md D15) an existing
 *                        container's manifest must match to be resumed.
 * @param out            Zeroed and populated on any return; CONTAINER_OK
 *                        leaves it holding an owned, locked handle.
 * @return CONTAINER_OK, CONTAINER_ERR_NO_MATCH, CONTAINER_ERR_AMBIGUOUS,
 *         CONTAINER_ERR_IO, or CONTAINER_ERR_INVALID (NULL out, dest_root, or
 *         wanted_identity).
 */
ContainerStatus container_adopt(const char *dest_root, const Manifest *wanted_identity, BackupContainer *out);

/**
 * @brief Atomically publishes a reserved/adopted container under its final name.
 *
 * Uses renameat2(..., RENAME_NOREPLACE): finalization can never silently
 * replace an existing final container. On any failure the partial is left
 * exactly as it was and container remains a valid CONTAINER_STATE_PARTIAL
 * handle -- the caller may retry, abandon it for a later adopt(), or close().
 *
 * @param container Must be a handle in CONTAINER_STATE_PARTIAL (as left by a
 *                   successful container_reserve()/container_adopt()).
 * @return CONTAINER_OK, CONTAINER_ERR_FINAL_EXISTS, CONTAINER_ERR_NOREPLACE,
 *         CONTAINER_ERR_IO, or CONTAINER_ERR_INVALID (NULL, or wrong state).
 */
ContainerStatus container_finalize(BackupContainer *container);

/**
 * @brief Releases container's fds (and thus any flock() it holds) and zeroes it.
 *
 * Never deletes anything on disk: an unfinalized partial is left in place for
 * a later container_adopt() to resume, and a finalized container is of course
 * left in place as the completed backup. Safe to call on NULL and on an
 * already-zeroed (CONTAINER_STATE_EMPTY) handle -- neither closes anything.
 */
void container_close(BackupContainer *container);

/**
 * @brief The container directory's own fd, for writing control artifacts and
 * data/ beneath it.
 *
 * Borrowed, not transferred: the handle keeps ownership (and keeps its flock()
 * held through this same fd), so the caller must not close it. Valid for as
 * long as the handle is not closed -- including across container_finalize(),
 * which renames the directory without changing its identity.
 *
 * @return The fd, or -1 for NULL or a handle in CONTAINER_STATE_EMPTY.
 */
int container_root_fd(const BackupContainer *container);

/**
 * @brief The container's live leaf name: the ".partial" name while reserved or
 * adopted, the published name once finalized.
 *
 * Lets a caller report where a container actually is without reaching into the
 * handle or reconstructing the name from the D15 grammar itself.
 *
 * @return A pointer into the handle (valid until it is closed or reused), or
 *         NULL for NULL or a handle in CONTAINER_STATE_EMPTY.
 */
const char *container_current_name(const BackupContainer *container);

/**
 * @brief Whether name matches the exact ".partial" leaf grammar
 * container_reserve() can produce (docs/DECISIONS.md D15) -- i.e. whether it
 * names an in-progress or abandoned container, not a finalized one.
 *
 * Shares parse_partial_name()'s grammar so the naming rule stays defined in
 * one place: a name that merely happens to end in ".partial" without matching
 * the "migr_backup_YYYYMMDD_HHMMSS[-N].partial" shape is not considered ours
 * and is reported as not partial.
 *
 * @param name A single path component (a leaf name, not a full path).
 * @return Non-zero if name matches the partial-container grammar, 0 otherwise
 *         (including a NULL name).
 */
int container_name_is_partial(const char *name);

/**
 * @brief Whether name matches the exact finalized-container leaf grammar
 * container_finalize() can publish.
 *
 * This is the same grammar as container_name_is_partial(), without the
 * ".partial" suffix.
 *
 * @param name A single path component (a leaf name, not a full path).
 * @return Non-zero if name matches the finalized-container grammar, 0
 *         otherwise (including a NULL name).
 */
int container_name_is_final(const char *name);

#endif
