#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/xattr.h>

#include "fsprobe.h"
#include "utils.h" // path_join

// Classify the errno of a *refused capability attempt* (used only via cap_refused, for
// chmod/symlink/mkfifo/setxattr). The taxonomy is a first cut, good enough for A.2/A.3
// (where any non-native verdict is refused anyway); the exact per-filesystem errno
// behaviour is nailed down by the real exFAT/NTFS integration tests before portable mode
// (Phase B) depends on the unavailable/error distinction.
static FsCapabilityStatus classify_errno(int e)
{
    if (e == ENOTSUP
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
        || e == EOPNOTSUPP
#endif
        )
        return FS_CAP_UNAVAILABLE;
    // Every capability this helper serves (chmod, symlink, mkfifo, setxattr) is a
    // filesystem operation on a directory we just created and own, so EPERM/EACCES
    // uniformly means the filesystem itself refuses the operation — the semantic is
    // unavailable, not a privilege problem. This uniform reading is valid only for that
    // set: a future ownership probe's chown EPERM is a privilege signal and must be
    // classified on its own, not routed through here.
    if (e == EPERM || e == EACCES)
        return FS_CAP_UNAVAILABLE;
    return FS_CAP_ERROR; // ENOSPC, EIO, EROFS, or anything unexpected
}

static FsCapabilityResult cap_ok(void)       { FsCapabilityResult r = { FS_CAP_SUPPORTED, 0 };   return r; }
static FsCapabilityResult cap_mismatch(void) { FsCapabilityResult r = { FS_CAP_UNAVAILABLE, 0 }; return r; }
// A capability-attempt the filesystem refused (chmod/symlink/mkfifo/setxattr): an expected
// refusal is unavailable, anything else a real error — classify_errno decides which.
static FsCapabilityResult cap_refused(int e) { FsCapabilityResult r = { classify_errno(e), e };  return r; }
// A supporting operation failed (create, inspect, read a directory): always operational, so
// it never masquerades as a missing capability.
static FsCapabilityResult cap_error(int e)   { FsCapabilityResult r = { FS_CAP_ERROR, e };       return r; }

// Permission bits survive a chmod round-trip, for a file and a directory. A lossy
// mount (e.g. vfat with fmask/dmask) accepts chmod but reports a fixed mode back.
static FsCapabilityResult probe_mode(const char *dir)
{
    char file[PATH_MAX], sub[PATH_MAX];
    if (path_join(file, sizeof(file), dir, "mode_file") != 0 ||
        path_join(sub, sizeof(sub), dir, "mode_dir") != 0)
        return cap_error(ENAMETOOLONG);

    int fd = open(file, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0)
        return cap_error(errno);      // creating the test file failed: operational
    close(fd);

    FsCapabilityResult r = cap_ok();
    struct stat st;
    if (chmod(file, 0642) != 0)
        r = cap_refused(errno);       // the filesystem refused chmod: capability attempt
    else if (lstat(file, &st) != 0)
        r = cap_error(errno);         // inspecting the result failed: operational
    else if ((st.st_mode & 0777) != 0642)
        r = cap_mismatch();
    unlink(file);
    if (r.status != FS_CAP_SUPPORTED)
        return r;

    if (mkdir(sub, 0700) != 0)
        return cap_error(errno);
    if (chmod(sub, 0751) != 0)
        r = cap_refused(errno);
    else if (lstat(sub, &st) != 0)
        r = cap_error(errno);
    else if ((st.st_mode & 0777) != 0751)
        r = cap_mismatch();
    rmdir(sub);
    return r;
}

// A symlink is created, typed as a link, and its target bytes read back exactly.
static FsCapabilityResult probe_symlink(const char *dir)
{
    char link[PATH_MAX];
    if (path_join(link, sizeof(link), dir, "symlink_probe") != 0)
        return cap_error(ENAMETOOLONG);

    const char *target = "target/need/not/exist";
    if (symlink(target, link) != 0)
        return cap_refused(errno);    // the filesystem refused symlink: capability attempt

    FsCapabilityResult r = cap_ok();
    struct stat st;
    char buf[PATH_MAX];
    ssize_t n;
    if (lstat(link, &st) != 0)
        r = cap_error(errno);         // inspecting the result failed: operational
    else if (!S_ISLNK(st.st_mode))
        r = cap_mismatch();           // created, but not a symlink: semantic unavailable
    else if ((n = readlink(link, buf, sizeof(buf) - 1)) < 0)
        r = cap_error(errno);
    else
    {
        buf[n] = '\0';
        if (strcmp(buf, target) != 0)
            r = cap_mismatch();
    }
    unlink(link);
    return r;
}

// A FIFO node is created and typed as a FIFO.
static FsCapabilityResult probe_fifo(const char *dir)
{
    char fifo[PATH_MAX];
    if (path_join(fifo, sizeof(fifo), dir, "fifo_probe") != 0)
        return cap_error(ENAMETOOLONG);

    if (mkfifo(fifo, 0644) != 0)
        return cap_refused(errno);    // the filesystem refused mkfifo: capability attempt

    FsCapabilityResult r = cap_ok();
    struct stat st;
    if (lstat(fifo, &st) != 0)
        r = cap_error(errno);         // inspecting the result failed: operational
    else if (!S_ISFIFO(st.st_mode))
        r = cap_mismatch();           // created, but not a FIFO: semantic unavailable
    unlink(fifo);
    return r;
}

// "a" and "A" are distinct entries. On a case-insensitive filesystem the upper-case
// name resolves to the file we just made, so a native clone of foo/FOO would collide.
static FsCapabilityResult probe_case_sensitive(const char *dir)
{
    char lower[PATH_MAX], upper[PATH_MAX];
    if (path_join(lower, sizeof(lower), dir, "case_probe_a") != 0 ||
        path_join(upper, sizeof(upper), dir, "case_probe_A") != 0)
        return cap_error(ENAMETOOLONG);

    int fda = open(lower, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fda < 0)
        return cap_error(errno);      // creating the base file failed: operational
    close(fda);

    // Creating the upper-case name with O_EXCL proves whether it is a distinct entry.
    // EEXIST means it collided with the lower-case file -> case-insensitive, so a
    // native clone of foo/FOO would lose one of them. Any other error is operational.
    FsCapabilityResult r;
    int fdb = open(upper, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fdb >= 0)
    {
        close(fdb);
        unlink(upper);
        r = cap_ok();
    }
    else if (errno == EEXIST)
        r = cap_mismatch();
    else
        r = cap_error(errno);
    unlink(lower);
    return r;
}

// A user.* xattr is set, read back byte-for-byte, and removed.
static FsCapabilityResult probe_xattr(const char *dir)
{
    char file[PATH_MAX];
    if (path_join(file, sizeof(file), dir, "xattr_probe") != 0)
        return cap_error(ENAMETOOLONG);

    int fd = open(file, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0)
        return cap_error(errno);      // creating the test file failed: operational
    close(fd);

    const char *name = "user.migr_probe";
    const char *value = "migr-probe-value";
    size_t vlen = strlen(value);
    char got[64];
    ssize_t n;

    FsCapabilityResult r = cap_ok();
    if (setxattr(file, name, value, vlen, 0) != 0)
        r = cap_refused(errno);       // the filesystem refused the xattr: capability attempt
    else if ((n = getxattr(file, name, got, sizeof(got))) < 0)
        r = cap_error(errno);         // set succeeded but read-back failed: operational
    else if ((size_t)n != vlen || memcmp(got, value, vlen) != 0)
        r = cap_mismatch();
    else if (removexattr(file, name) != 0)
        r = cap_error(errno);
    unlink(file);
    return r;
}

// A small corpus of names that lossy filesystems (exFAT/NTFS/FAT32) reject outright or
// silently normalise. On a native filesystem every one round-trips byte-for-byte.
static const char *const raw_name_corpus[] = {
    "migr:probe", // colon
    "migr?probe", // question mark
    "trailing.",  // trailing dot (often stripped)
    "trailing ",  // trailing space (often stripped)
};

static FsCapabilityResult probe_raw_names(const char *dir)
{
    int count = (int)(sizeof(raw_name_corpus) / sizeof(raw_name_corpus[0]));
    FsCapabilityResult r = cap_ok();

    for (int i = 0; i < count && r.status == FS_CAP_SUPPORTED; i++)
    {
        char path[PATH_MAX];
        if (path_join(path, sizeof(path), dir, raw_name_corpus[i]) != 0)
        {
            r = cap_error(ENAMETOOLONG);
            break;
        }

        int fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0600);
        if (fd < 0)
        {
            // A name the filesystem cannot represent is unavailable; a genuine
            // operational failure (no space, permission, I/O) is an error.
            if (errno == EINVAL || errno == ENAMETOOLONG || errno == EILSEQ ||
                errno == ENOTSUP)
                r = cap_mismatch();
            else
                r = cap_error(errno);
            break;
        }
        close(fd);

        // The exact byte name must appear in the directory. A filesystem that stored a
        // normalised form (dropped the trailing dot, say) fails this even though the
        // create "succeeded". Reading the directory is a supporting operation: a real
        // readdir failure (errno set once it returns NULL) is an error, not a verdict.
        DIR *d = opendir(dir);
        if (d == NULL)
        {
            r = cap_error(errno);
            unlink(path);
            break;
        }
        int found = 0;
        errno = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL)
        {
            if (strcmp(e->d_name, raw_name_corpus[i]) == 0)
            {
                found = 1;
                break;
            }
        }
        int readdir_errno = found ? 0 : errno;
        closedir(d);

        // On a normalising filesystem the lookup normalises the same way, so unlinking
        // by the original name removes the stored entry; anything it somehow leaves is
        // caught by the caller's final rmdir (-> a fatal, un-masked probe failure).
        unlink(path);
        if (!found)
            r = (readdir_errno != 0) ? cap_error(readdir_errno) : cap_mismatch();
    }
    return r;
}

int fsprobe(const char *existing_root, FsCapabilityProfile *out)
{
    // Private probe directory directly under the destination, so we measure the actual
    // target filesystem rather than whatever backs /tmp.
    char probe_dir[PATH_MAX];
    if (path_join(probe_dir, sizeof(probe_dir), existing_root, ".migr-probe-XXXXXX") != 0)
        return -1;
    if (mkdtemp(probe_dir) == NULL)
        return -1; // cannot create even a directory on the destination

    // Baseline precondition: a plain file must create, stat, and delete. This is not a
    // native-vs-portable capability — a destination that fails it is unusable for any
    // backup, so it is a fatal -1, never a "go portable" signal.
    int baseline_ok = 0;
    char baseline[PATH_MAX];
    if (path_join(baseline, sizeof(baseline), probe_dir, "baseline") == 0)
    {
        int fd = open(baseline, O_CREAT | O_WRONLY | O_EXCL, 0600);
        if (fd >= 0)
        {
            close(fd);
            struct stat st;
            if (lstat(baseline, &st) == 0 && S_ISREG(st.st_mode))
                baseline_ok = 1;
            unlink(baseline);
        }
    }
    if (!baseline_ok)
    {
        rmdir(probe_dir);
        return -1;
    }

    out->capabilities[FS_CAP_MODE]           = probe_mode(probe_dir);
    out->capabilities[FS_CAP_SYMLINK]        = probe_symlink(probe_dir);
    out->capabilities[FS_CAP_FIFO]           = probe_fifo(probe_dir);
    out->capabilities[FS_CAP_RAW_NAMES]      = probe_raw_names(probe_dir);
    out->capabilities[FS_CAP_CASE_SENSITIVE] = probe_case_sensitive(probe_dir);
    out->capabilities[FS_CAP_XATTR]          = probe_xattr(probe_dir);

    // Every probe cleans up after itself; if anything lingered, the directory will not
    // be empty and rmdir fails — treat that as an unreliable probe run.
    if (rmdir(probe_dir) != 0)
        return -1;
    return 0;
}

int select_representation(const FsCapabilityProfile *profile, CloneRepresentation *out)
{
    if (profile == NULL || out == NULL)
        return -1;

    int any_unavailable = 0;
    for (int i = 0; i < FS_CAP_COUNT; i++)
    {
        switch (profile->capabilities[i].status)
        {
            case FS_CAP_SUPPORTED:
                break;
            case FS_CAP_UNAVAILABLE:
                any_unavailable = 1;
                break;
            case FS_CAP_ERROR:
                return -1; // measurement untrustworthy: refuse
            default:
                return -1; // a corrupt/unknown status fails closed, never native
        }
    }
    *out = any_unavailable ? CLONE_PORTABLE_SIDECAR : CLONE_NATIVE_TREE;
    return 0;
}
