#ifndef MANIFEST_H
#define MANIFEST_H

#include <limits.h>   /* PATH_MAX */
#include <sys/types.h> /* uid_t */

#include "fileops.h" /* CloneRepresentation */

/**
 * @brief Legacy manifest: an unversioned "KEY=value" file recording only XDG
 * directory basenames, so restore can locate source-locale directories when the
 * source and destination locales differ.
 *
 * Superseded by the versioned manifest below (docs/DECISIONS.md D15/D16), but kept
 * verbatim under an explicit "legacy" name: current backup production still writes
 * it, and restore must continue to read existing backups that carry it.
 */

#define LEGACY_MANIFEST_XDG_COUNT 6

extern const char * const legacy_manifest_keys[LEGACY_MANIFEST_XDG_COUNT]; /**< Canonical XDG key names, parallel to the xdg_resolve arrays. */

/**
 * @brief Writes manifest.txt to backup_dir recording the XDG key-to-dirname mapping.
 *
 * Stores one "KEY=basename" line per entry so that restore can locate the
 * correct directories when the source and destination locales differ.
 *
 * @param backup_dir Directory in which manifest.txt is created.
 * @param basenames  Array of n directory basenames parallel to legacy_manifest_keys[].
 * @param n          Number of entries to write.
 * @return 0 on success, 1 if the file cannot be opened for writing.
 */
int legacy_manifest_write(const char *backup_dir, const char * const *basenames, int n);

/**
 * @brief Parses manifest.txt from backup_dir and extracts XDG directory basenames.
 *
 * Each out[i] is set to a strdup'd value matching legacy_manifest_keys[i], or left
 * NULL if the key is absent from the file. The caller must free every
 * non-NULL entry. Returns 1 without modifying out[] if the file does not exist,
 * allowing the caller to fall back to the target system's basename.
 *
 * @param backup_dir Directory from which manifest.txt is read.
 * @param out        Caller-supplied array of n char* pointers; filled with malloc'd values.
 * @param n          Number of entries to look up.
 * @return 0 if manifest.txt was found and parsed, 1 if the file does not exist.
 */
int legacy_manifest_read(const char *backup_dir, char **out, int n);

/* ------------------------------------------------------------------------- */
/* Versioned manifest (docs/DECISIONS.md D15, D16).                          */
/* ------------------------------------------------------------------------- */

#define MANIFEST_CURRENT_VERSION 1
#define MANIFEST_MAX_ROOTS       4096  /**< Resource-exhaustion ceiling, not an expected count. */
#define MANIFEST_ID_MAX          64
#define MANIFEST_MACHINE_ID_MAX  128

/**
 * @brief Every distinguishable outcome of reading manifest.txt.
 *
 * Kept as separate values rather than a bool so a caller can route MISSING and
 * LEGACY to the same fallback behaviour while still telling them apart in tests
 * and diagnostics, and so MALFORMED/UNKNOWN_VERSION are never silently treated
 * as MISSING (that would let a corrupt versioned manifest quietly fall back to
 * "no manifest" behaviour instead of refusing).
 */
typedef enum {
    MANIFEST_STATUS_MISSING,         /**< No manifest.txt in backup_dir at all. */
    MANIFEST_STATUS_LEGACY,          /**< Not the versioned magic, and contains at least one recognized
                                           legacy_manifest_keys[] "KEY=value" line -- genuinely the old
                                           unversioned manifest. An empty file, or content that merely
                                           looks KEY=value-shaped without a recognized key (including a
                                           corrupted/truncated attempt at the versioned magic), is
                                           MALFORMED instead: silently guessing "probably legacy" could
                                           route real corruption through the legacy fallback path. */
    MANIFEST_STATUS_VALID,           /**< Magic + MANIFEST_CURRENT_VERSION, parsed successfully; *out is populated. */
    MANIFEST_STATUS_UNKNOWN_VERSION, /**< Magic present, VERSION is well-formed but not one this build understands. */
    MANIFEST_STATUS_MALFORMED,       /**< Magic present, current version, but the content violates the grammar. */
    MANIFEST_STATUS_IO_ERROR         /**< open/read/allocation failure unrelated to file content. */
} ManifestStatus;

/**
 * @brief How a root's restore destination is determined (docs/DECISIONS.md D16).
 */
typedef enum {
    ROOT_POLICY_XDG,           /**< Restored via the target's own xdg_resolve(), same as today. */
    ROOT_POLICY_HOME_RELATIVE, /**< Restored at the same path relative to the target $HOME. */
    ROOT_POLICY_MANUAL_NATIVE  /**< Captured (native only) but not restored automatically. */
} RootPolicy;

/**
 * @brief Mirrors backup.h's BackupMode by value, defined independently.
 *
 * manifest.h has no other dependency on backup.h's orchestration-level types
 * (its only local-header dependency is the foundational fileops.h, for
 * CloneRepresentation), and a persistence format should not need to reach up
 * into a specific caller's mode enum. The three values are kept in sync with
 * BackupMode by convention and by the tests that exercise both, not by a
 * shared type.
 */
typedef enum {
    MANIFEST_SCOPE_CRITICAL,
    MANIFEST_SCOPE_COMPREHENSIVE,
    MANIFEST_SCOPE_EXPLICIT
} ManifestScope;

/**
 * @brief One captured root: its identity, restore policy, and both its
 * container-relative payload location and its source-side address.
 *
 * restore_path is meaningful only for ROOT_POLICY_HOME_RELATIVE, and
 * has_restore_path (not an empty string) is what marks that — an empty
 * home-relative path is itself a legitimate value (the root is $HOME itself).
 */
typedef struct {
    char id[MANIFEST_ID_MAX];        /**< e.g. "EXPLICIT_0" or an XDG key such as "XDG_DOCUMENTS_DIR". */
    RootPolicy policy;
    char payload_path[PATH_MAX];     /**< Location under the container's data/, relative. */
    char source_path[PATH_MAX];      /**< Source-side identity: a home-relative path for
                                           ROOT_POLICY_HOME_RELATIVE, or a normalized absolute
                                           capture address for ROOT_POLICY_XDG/ROOT_POLICY_MANUAL_NATIVE. */
    char restore_path[PATH_MAX];     /**< Target-side restore address; meaningful only when has_restore_path. */
    int has_restore_path;
} ManifestRoot;

/**
 * @brief The versioned manifest: format identity, representation/scope, optional
 * resume identity, and the full root table.
 *
 * roots is a heap array owned by this struct; manifest_free() releases it.
 * has_source_identity is set only when both machine_id and source_uid are
 * available (docs/DECISIONS.md D15) — one without the other is not adopted as
 * a partial identity.
 */
typedef struct {
    int version;
    CloneRepresentation representation;
    ManifestScope scope;
    int sidecar_version; /**< 0 means no sidecar is present. */
    int has_source_identity;
    char machine_id[MANIFEST_MACHINE_ID_MAX];
    uid_t source_uid;
    int root_count;
    ManifestRoot *roots;
} Manifest;

/**
 * @brief Reads and classifies backup_dir/manifest.txt.
 *
 * Distinguishes every failure class explicitly (see ManifestStatus) rather than
 * collapsing them into a single boolean, so a corrupt or unsupported-version
 * manifest is never treated the same as "no manifest" or silently guessed at.
 * *out is populated only when the return value is MANIFEST_STATUS_VALID; on
 * every other status *out is left zeroed (no partial/inconsistent state).
 *
 * @param backup_dir Directory containing manifest.txt.
 * @param out        Populated on MANIFEST_STATUS_VALID; caller must eventually
 *                   pass it to manifest_free() in that case.
 * @return The classified status.
 */
ManifestStatus manifest_read_v1(const char *backup_dir, Manifest *out);

/**
 * @brief Reads and classifies container_fd's manifest.txt (docs/DECISIONS.md D15).
 *
 * Identical classification to manifest_read_v1() -- both share the same body
 * parser, so a manifest's magic/version/content never reads differently
 * depending on which function opened it. The two differ only in how they
 * reach an open, readable stream:
 *
 * manifest.txt is opened by directory fd (never by re-resolving a path), with
 * O_NONBLOCK so an entry that turns out to be a FIFO can never hang this call
 * even with no writer on the other end, O_NOFOLLOW so a symlink is refused at
 * open() (ELOOP) rather than followed, and an explicit ENXIO check because
 * open() can never succeed on a Unix domain socket at all, regardless of
 * flags. A subsequent fstat()+S_ISREG check catches every other non-regular
 * object that *does* open successfully (FIFO, device, directory). All three
 * -- ELOOP, ENXIO, and a non-regular S_ISREG -- classify as
 * MANIFEST_STATUS_MALFORMED before a single byte is read; a genuine fstat()
 * failure, distinctly, is MANIFEST_STATUS_IO_ERROR. This is deliberately
 * stricter than manifest_read_v1(), which treats manifest.txt-
 * as-a-directory as MANIFEST_STATUS_IO_ERROR: a path this caller was given
 * directly is trusted to be what production wrote, while a directory entry
 * discovered while scanning for adoption (docs/DECISIONS.md D15) may be
 * foreign, so any non-regular object there is simply "not adoptable", full
 * stop.
 *
 * @param container_fd Directory fd of the candidate container.
 * @param out           Populated on MANIFEST_STATUS_VALID; caller must
 *                       eventually pass it to manifest_free() in that case.
 * @return The classified status.
 */
ManifestStatus manifest_read_v1_at(int container_fd, Manifest *out);

/**
 * @brief Outcome of manifest_resume_identity_compare().
 *
 * A three-way result, not a bool: comparing two root tables allocates, and an
 * allocation failure must never be indistinguishable from a genuine mismatch.
 * A caller (container_adopt(), docs/DECISIONS.md D15) that collapsed ERROR
 * into DIFFERENT would silently turn an operational failure into "no match,
 * safe to reserve a brand-new container" -- exactly the wrong conclusion.
 */
typedef enum {
    MANIFEST_IDENTITY_DIFFERENT, /**< Well-formed comparison; not the same job. */
    MANIFEST_IDENTITY_EQUAL,     /**< Well-formed comparison; the same resumable job. */
    MANIFEST_IDENTITY_ERROR      /**< The comparison itself could not be completed
                                       (allocation failure). Callers must treat this
                                       as an operational failure, not as DIFFERENT. */
} ManifestIdentityComparison;

/**
 * @brief Compares two manifests' full resume identity (docs/DECISIONS.md D15).
 *
 * Two manifests are the same resumable job only if version, representation,
 * scope, sidecar_version, and source identity (machine_id + source_uid, both
 * present on both sides) all match exactly, and their root tables carry the
 * same set of roots -- compared by identity fields (id, policy, payload_path,
 * source_path, and restore_path/has_restore_path), independent of on-disk or
 * in-memory order. A timestamp or scope label alone is never sufficient
 * (docs/DECISIONS.md D15); this is the one function that decides the question.
 *
 * @return MANIFEST_IDENTITY_EQUAL or MANIFEST_IDENTITY_DIFFERENT for any
 *         well-formed comparison (including when either side lacks a source
 *         identity, which is always DIFFERENT); MANIFEST_IDENTITY_ERROR only
 *         if the comparison itself could not be completed (allocation
 *         failure while comparing root tables) -- never silently DIFFERENT.
 */
ManifestIdentityComparison manifest_resume_identity_compare(const Manifest *a, const Manifest *b);

/**
 * @brief Writes a versioned manifest to backup_dir/manifest.txt in full.
 *
 * A single fopen/write/fclose sequence: the container's own atomic
 * .partial-to-final rename (docs/DECISIONS.md D15) is what makes an interrupted
 * write harmless, so this function does not need its own temp-file dance. Every
 * write is checked, including fflush/fclose; any failure removes no state but
 * returns non-zero so the caller can refuse rather than finalize a container
 * with a truncated manifest.
 *
 * @param backup_dir Directory in which manifest.txt is created.
 * @param m          The manifest to serialize; must not be NULL.
 * @return 0 on success, 1 on any error.
 */
int manifest_write_v1(const char *backup_dir, const Manifest *m);

/**
 * @brief Releases the heap-owned root array. Safe on NULL and on an all-zero Manifest.
 */
void manifest_free(Manifest *m);

#endif
