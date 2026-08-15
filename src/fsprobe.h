#ifndef FSPROBE_H
#define FSPROBE_H

#include "fileops.h" // CloneRepresentation

// Capabilities migr's native mode depends on. Each is exercised on the destination
// with a create -> read-back -> delete round-trip, so a filesystem that accepts a
// call but silently mangles the value still counts as lacking the capability. The
// set grows per phase (ownership, timestamp precision, ... come later).
typedef enum {
    FS_CAP_MODE,            // permission bits survive a chmod round-trip (file and dir)
    FS_CAP_SYMLINK,         // a symlink is created, typed as a link, target read back exact
    FS_CAP_FIFO,            // a FIFO node is created and typed as a FIFO
    FS_CAP_RAW_NAMES,       // a corpus of Windows-hostile names round-trips byte-for-byte
    FS_CAP_CASE_SENSITIVE,  // "a" and "A" are distinct entries (else foo/FOO collide -> loss)
    FS_CAP_XATTR,           // a user.* xattr is set, read back exact, and removed
    FS_CAP_TIMESTAMPS,      // atime/mtime seconds and ordering round-trip on file and dir
    FS_CAP_HARDLINK,        // link() creates a second name sharing one inode (dev+ino)
    FS_CAP_COUNT
} FsCapability;

typedef enum {
    FS_CAP_UNSET,        // never probed; a forgotten dispatch line must not look supported
    FS_CAP_SUPPORTED,    // exercised and round-tripped faithfully
    FS_CAP_UNAVAILABLE,  // the semantic is not here (ENOTSUP, or a silent round-trip mismatch)
                         // -> a sidecar is needed to carry it: portable
    FS_CAP_ERROR         // an operational failure (ENOSPC/EIO/EROFS/unexpected) -> refuse
} FsCapabilityStatus;

typedef struct {
    FsCapabilityStatus status;
    int errnum; // errno when a syscall failed; 0 for a semantic (round-trip) mismatch
} FsCapabilityResult;

typedef struct {
    FsCapabilityResult capabilities[FS_CAP_COUNT];
    int nsec_exact; // timestamp nanoseconds round-trip exactly; not a verdict input
} FsCapabilityProfile;

/**
 * @brief Empirically probe what the filesystem at existing_root can preserve.
 *
 * Creates a private temporary subdirectory directly under existing_root (never
 * /tmp, so the probe measures the actual destination), exercises each capability
 * with a create -> read-back -> delete round-trip, and removes every artifact.
 * Fills *out with a per-capability result.
 *
 * The probe only measures; it makes no native/portable decision and prints
 * nothing. The verdict is left to select_representation().
 *
 * @return 0 if the probe ran and cleaned up (even if some capabilities are
 *         unavailable or errored — that is recorded in *out). -1 if the probe
 *         could not run reliably: existing_root is unusable, the temp directory,
 *         baseline create/stat/delete, or final cleanup failed. A -1 is fatal and
 *         must never be treated as a "go portable" signal.
 */
int fsprobe(const char *existing_root, FsCapabilityProfile *out);

/**
 * @brief Measures timestamp fidelity under an already-open directory fd.
 *
 * The probe creates and removes a private child directory below root_fd and
 * performs the same regular-file and directory seconds/order round-trip as
 * fsprobe(), without constructing a full pathname.
 */
int fsprobe_timestamps_fd(int root_fd, int *nsec_exact);

/**
 * @brief Reduce a capability profile to a clone representation.
 *
 * Pure: it inspects only the profile, so tests drive it with synthetic profiles
 * and no filesystem is touched. Precedence — an operational error outranks a
 * missing capability, because an error means the measurement is untrustworthy:
 *
 *   - any FS_CAP_ERROR                         -> return -1 (refuse the backup)
 *   - else any FS_CAP_UNAVAILABLE              -> *out = CLONE_PORTABLE_SIDECAR, return 0
 *   - else (all supported)                     -> *out = CLONE_NATIVE_TREE, return 0
 *
 * @return 0 and sets *out on a decidable profile; -1 (refusal) if any capability
 *         errored. *out is untouched on -1.
 */
int select_representation(const FsCapabilityProfile *profile, CloneRepresentation *out);

#endif
