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
#include <time.h>

#include "fsprobe.h"

// Classify the errno of a *refused capability attempt* (used only via cap_refused, for
// chmod/symlink/mkfifo/setxattr/link). The taxonomy is a first cut, good enough for A.2/A.3
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

// A small corpus of names that lossy filesystems (exFAT/NTFS/FAT32) reject outright or
// silently normalise. On a native filesystem every one round-trips byte-for-byte.
static const char *const raw_name_corpus[] = {
    "migr:probe", // colon
    "migr?probe", // question mark
    "trailing.",  // trailing dot (often stripped)
    "trailing ",  // trailing space (often stripped)
};

static FsCapabilityResult probe_raw_names_fd(int dir_fd)
{
    int count = (int)(sizeof(raw_name_corpus) / sizeof(raw_name_corpus[0]));
    FsCapabilityResult r = cap_ok();

    for (int i = 0; i < count && r.status == FS_CAP_SUPPORTED; i++)
    {
        int fd = openat(dir_fd, raw_name_corpus[i], O_CREAT | O_WRONLY | O_EXCL, 0600);
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
        int scan_fd = fcntl(dir_fd, F_DUPFD_CLOEXEC, 0);
        if (scan_fd < 0)
        {
            r = cap_error(errno);
            unlinkat(dir_fd, raw_name_corpus[i], 0);
            break;
        }
        DIR *d = fdopendir(scan_fd);
        if (d == NULL)
        {
            r = cap_error(errno);
            close(scan_fd);
            unlinkat(dir_fd, raw_name_corpus[i], 0);
            break;
        }
        rewinddir(d);
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
        unlinkat(dir_fd, raw_name_corpus[i], 0);
        if (!found)
            r = (readdir_errno != 0) ? cap_error(readdir_errno) : cap_mismatch();
    }
    return r;
}

// Permission bits survive a chmod round-trip, for a file and a directory. A lossy
// mount (e.g. vfat with fmask/dmask) accepts chmod but reports a fixed mode back.
static FsCapabilityResult probe_mode_fd(int dir_fd)
{
    int fd = openat(dir_fd, "mode_file", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0)
        return cap_error(errno);
    close(fd);

    FsCapabilityResult r = cap_ok();
    struct stat st;
    if (fchmodat(dir_fd, "mode_file", 0642, 0) != 0)
        r = cap_refused(errno);
    else if (fstatat(dir_fd, "mode_file", &st, AT_SYMLINK_NOFOLLOW) != 0)
        r = cap_error(errno);
    else if ((st.st_mode & 0777) != 0642)
        r = cap_mismatch();
    unlinkat(dir_fd, "mode_file", 0);
    if (r.status != FS_CAP_SUPPORTED)
        return r;

    if (mkdirat(dir_fd, "mode_dir", 0700) != 0)
        return cap_error(errno);
    if (fchmodat(dir_fd, "mode_dir", 0751, 0) != 0)
        r = cap_refused(errno);
    else if (fstatat(dir_fd, "mode_dir", &st, AT_SYMLINK_NOFOLLOW) != 0)
        r = cap_error(errno);
    else if ((st.st_mode & 0777) != 0751)
        r = cap_mismatch();
    unlinkat(dir_fd, "mode_dir", AT_REMOVEDIR);
    return r;
}

// A symlink is created, typed as a link, and its target bytes read back exactly.
static FsCapabilityResult probe_symlink_fd(int dir_fd)
{
    const char *target = "target/need/not/exist";
    if (symlinkat(target, dir_fd, "symlink_probe") != 0)
        return cap_refused(errno);

    FsCapabilityResult r = cap_ok();
    struct stat st;
    char buf[PATH_MAX];
    ssize_t n;
    if (fstatat(dir_fd, "symlink_probe", &st, AT_SYMLINK_NOFOLLOW) != 0)
        r = cap_error(errno);
    else if (!S_ISLNK(st.st_mode))
        r = cap_mismatch();
    else if ((n = readlinkat(dir_fd, "symlink_probe", buf, sizeof(buf) - 1)) < 0)
        r = cap_error(errno);
    else
    {
        buf[n] = '\0';
        if (strcmp(buf, target) != 0)
            r = cap_mismatch();
    }
    unlinkat(dir_fd, "symlink_probe", 0);
    return r;
}

// A FIFO node is created and typed as a FIFO.
static FsCapabilityResult probe_fifo_fd(int dir_fd)
{
    if (mkfifoat(dir_fd, "fifo_probe", 0644) != 0)
        return cap_refused(errno);

    FsCapabilityResult r = cap_ok();
    struct stat st;
    if (fstatat(dir_fd, "fifo_probe", &st, AT_SYMLINK_NOFOLLOW) != 0)
        r = cap_error(errno);
    else if (!S_ISFIFO(st.st_mode))
        r = cap_mismatch();
    unlinkat(dir_fd, "fifo_probe", 0);
    return r;
}

// "a" and "A" are distinct entries. On a case-insensitive filesystem the upper-case
// name resolves to the file we just made, so a native clone of foo/FOO would collide.
static FsCapabilityResult probe_case_sensitive_fd(int dir_fd)
{
    int fda = openat(dir_fd, "case_probe_a", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fda < 0)
        return cap_error(errno);
    close(fda);

    FsCapabilityResult r;
    int fdb = openat(dir_fd, "case_probe_A", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fdb >= 0)
    {
        close(fdb);
        unlinkat(dir_fd, "case_probe_A", 0);
        r = cap_ok();
    }
    else if (errno == EEXIST)
        r = cap_mismatch();
    else
        r = cap_error(errno);
    unlinkat(dir_fd, "case_probe_a", 0);
    return r;
}

// Two names share one inode after link(); a filesystem without hardlinks either
// refuses link() outright (the FAT family) or, in principle, could silently fail to
// share the inode. dev+ino equality is the same identity check backup.c's own native
// hardlink capture already uses -- mirror it here rather than inventing a second
// comparison.
static FsCapabilityResult probe_hardlink_fd(int dir_fd)
{
    int fd = openat(dir_fd, "hardlink_probe_a", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0)
        return cap_error(errno);
    close(fd);

    FsCapabilityResult r = cap_ok();
    if (linkat(dir_fd, "hardlink_probe_a", dir_fd, "hardlink_probe_b", 0) != 0)
        r = cap_refused(errno);
    else
    {
        struct stat st_a, st_b;
        if (fstatat(dir_fd, "hardlink_probe_a", &st_a, AT_SYMLINK_NOFOLLOW) != 0 ||
            fstatat(dir_fd, "hardlink_probe_b", &st_b, AT_SYMLINK_NOFOLLOW) != 0)
            r = cap_error(errno);
        else if (st_a.st_dev != st_b.st_dev || st_a.st_ino != st_b.st_ino)
            r = cap_mismatch();
        unlinkat(dir_fd, "hardlink_probe_b", 0);
    }
    unlinkat(dir_fd, "hardlink_probe_a", 0);
    return r;
}

// A user.* xattr is set, read back byte-for-byte, and removed.
static FsCapabilityResult probe_xattr_fd(int dir_fd)
{
    int fd = openat(dir_fd, "xattr_probe", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0)
        return cap_error(errno);

    const char *name = "user.migr_probe";
    const char *value = "migr-probe-value";
    size_t vlen = strlen(value);
    char got[64];
    ssize_t n;

    FsCapabilityResult r = cap_ok();
    if (fsetxattr(fd, name, value, vlen, 0) != 0)
        r = cap_refused(errno);
    else if ((n = fgetxattr(fd, name, got, sizeof(got))) < 0)
        r = cap_error(errno);
    else if ((size_t)n != vlen || memcmp(got, value, vlen) != 0)
        r = cap_mismatch();
    else if (fremovexattr(fd, name) != 0)
        r = cap_error(errno);
    close(fd);
    unlinkat(dir_fd, "xattr_probe", 0);
    return r;
}

// Writes two known-distinct, known-future (sec, nsec) samples through fd and
// verifies each round-trips: the seconds field exactly, and that the second
// sample's seconds strictly exceed the first's (the ordering half of the
// FS_CAP_TIMESTAMPS contract). Nanosecond exactness is tracked separately in
// *exact (ANDed with its incoming value, so a caller can accumulate it across
// several objects) because it is a measurement, not a verdict input.
//
// Return value distinguishes *why* the probe did not confirm support, which
// the two callers below need for different reasons: fsprobe_timestamps_fd()
// only needs a pass/fail signal, but probe_timestamps_dirfd() must turn a genuine
// syscall failure into FS_CAP_ERROR and a value mismatch into
// FS_CAP_UNAVAILABLE, exactly as its own inline loop did before both probes
// were unified onto this one fd-anchored primitive.
//   0  -- round-trip verified.
//   1  -- a syscall succeeded but the read-back value did not round-trip
//         (capability mismatch, not an error; errno is cleared).
//   -1 -- a syscall itself failed (errno set by the failing call).
static int timestamp_roundtrip_fd(int fd, const struct timespec first[2],
                                  const struct timespec second[2], int *exact)
{
    if (futimens(fd, first) != 0)
        return -1;
    struct stat before;
    if (fstat(fd, &before) != 0)
        return -1;
    if (before.st_atim.tv_sec != first[0].tv_sec ||
        before.st_mtim.tv_sec != first[1].tv_sec)
    {
        errno = 0;
        return 1;
    }
    *exact = *exact && before.st_atim.tv_nsec == first[0].tv_nsec &&
             before.st_mtim.tv_nsec == first[1].tv_nsec;

    if (futimens(fd, second) != 0)
        return -1;
    struct stat after;
    if (fstat(fd, &after) != 0)
        return -1;
    if (after.st_atim.tv_sec != second[0].tv_sec ||
        after.st_mtim.tv_sec != second[1].tv_sec ||
        after.st_atim.tv_sec <= before.st_atim.tv_sec ||
        after.st_mtim.tv_sec <= before.st_mtim.tv_sec)
    {
        errno = 0;
        return 1;
    }
    *exact = *exact && after.st_atim.tv_nsec == second[0].tv_nsec &&
             after.st_mtim.tv_nsec == second[1].tv_nsec;
    return 0;
}

static FsCapabilityResult probe_timestamps_dirfd(int dir_fd, int *nsec_exact)
{
    int file_fd = openat(dir_fd, "timestamp_file",
                         O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0600);
    if (file_fd < 0)
        return cap_error(errno);
    if (mkdirat(dir_fd, "timestamp_dir", 0700) != 0)
    {
        int saved_errno = errno;
        close(file_fd);
        unlinkat(dir_fd, "timestamp_file", 0);
        errno = saved_errno;
        return cap_error(saved_errno);
    }
    int subdir_fd = openat(dir_fd, "timestamp_dir",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (subdir_fd < 0)
    {
        int saved_errno = errno;
        close(file_fd);
        unlinkat(dir_fd, "timestamp_file", 0);
        unlinkat(dir_fd, "timestamp_dir", AT_REMOVEDIR);
        errno = saved_errno;
        return cap_error(saved_errno);
    }

    FsCapabilityResult result;
    int exact = 1;
    time_t now = time(NULL);
    if (now == (time_t)-1)
        result = cap_error(errno);
    else
    {
        struct timespec first[2] = {
            { .tv_sec = now + 31, .tv_nsec = 123456789 },
            { .tv_sec = now + 31, .tv_nsec = 987654321 }
        };
        struct timespec second[2] = {
            { .tv_sec = now + 33, .tv_nsec = 234567890 },
            { .tv_sec = now + 33, .tv_nsec = 876543210 }
        };

        result = cap_ok();
        int fds[] = { file_fd, subdir_fd };
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]) &&
                          result.status == FS_CAP_SUPPORTED; i++)
        {
            int rc = timestamp_roundtrip_fd(fds[i], first, second, &exact);
            if (rc < 0)
                result = cap_error(errno);
            else if (rc > 0)
                result = cap_mismatch();
        }
    }

    int saved_errno = errno;
    if (close(file_fd) != 0 && result.status == FS_CAP_SUPPORTED)
        result = cap_error(errno);
    if (close(subdir_fd) != 0 && result.status == FS_CAP_SUPPORTED)
        result = cap_error(errno);
    if (unlinkat(dir_fd, "timestamp_file", 0) != 0 &&
        result.status == FS_CAP_SUPPORTED)
        result = cap_error(errno);
    if (unlinkat(dir_fd, "timestamp_dir", AT_REMOVEDIR) != 0 &&
        result.status == FS_CAP_SUPPORTED)
        result = cap_error(errno);
    errno = saved_errno;
    if (nsec_exact != NULL)
        *nsec_exact = result.status == FS_CAP_SUPPORTED ? exact : 0;
    return result;
}

int fsprobe_timestamps_fd(int root_fd, int *nsec_exact)
{
    if (root_fd < 0 || nsec_exact == NULL)
        return -1;
    struct stat root_st;
    if (fstat(root_fd, &root_st) != 0 || !S_ISDIR(root_st.st_mode))
        return -1;
    struct timespec root_times[2] = { root_st.st_atim, root_st.st_mtim };

    char probe_name[NAME_MAX + 1];
    int probe_fd = -1;
    int created = 0;
    for (unsigned int suffix = 0; suffix < 1000; suffix++)
    {
        int n = suffix == 0
            ? snprintf(probe_name, sizeof(probe_name), ".migr_ts_%ld",
                       (long)getpid())
            : snprintf(probe_name, sizeof(probe_name), ".migr_ts_%ld_%u",
                       (long)getpid(), suffix);
        if (n < 0 || (size_t)n >= sizeof(probe_name))
            return -1;
        if (mkdirat(root_fd, probe_name, 0700) == 0)
        {
            created = 1;
            probe_fd = openat(root_fd, probe_name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            break;
        }
        if (errno != EEXIST)
            return -1;
    }
    if (!created || probe_fd < 0)
    {
        if (created)
        {
            (void)unlinkat(root_fd, probe_name, AT_REMOVEDIR);
            (void)futimens(root_fd, root_times);
        }
        return -1;
    }

    int file_fd = openat(probe_fd, "file", O_CREAT | O_EXCL | O_RDWR |
                                       O_CLOEXEC, 0600);
    int file_created = file_fd >= 0;
    int failed = file_fd < 0;
    time_t now = time(NULL);
    int exact = 1;
    if (!failed && now == (time_t)-1)
        failed = 1;
    struct timespec first[2] = {
        { .tv_sec = now + 31, .tv_nsec = 123456789 },
        { .tv_sec = now + 31, .tv_nsec = 987654321 }
    };
    struct timespec second[2] = {
        { .tv_sec = now + 33, .tv_nsec = 234567890 },
        { .tv_sec = now + 33, .tv_nsec = 876543210 }
    };
    if (!failed && timestamp_roundtrip_fd(file_fd, first, second, &exact) != 0)
        failed = 1;
    if (!failed && timestamp_roundtrip_fd(probe_fd, first, second, &exact) != 0)
        failed = 1;
    if (file_fd >= 0 && close(file_fd) != 0)
        failed = 1;
    if (file_created && unlinkat(probe_fd, "file", 0) != 0)
        failed = 1;
    if (close(probe_fd) != 0)
        failed = 1;
    if (unlinkat(root_fd, probe_name, AT_REMOVEDIR) != 0)
        failed = 1;
    // mkdirat/rmdir update the anchor directory's timestamps. Restore the
    // observed core times before returning so a rejected probe cannot leave a
    // user destination observably changed merely by being inspected.
    if (futimens(root_fd, root_times) != 0)
        failed = 1;
    if (failed)
        return -1;
    *nsec_exact = exact;
    return 0;
}

int fsprobe_fd(int root_fd, FsCapabilityProfile *out)
{
    if (root_fd < 0 || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    struct stat root_st;
    if (fstat(root_fd, &root_st) != 0 || !S_ISDIR(root_st.st_mode))
        return -1;

    char probe_name[NAME_MAX + 1];
    int probe_fd = -1;
    int created = 0;
    for (unsigned int suffix = 0; suffix < 1000; suffix++)
    {
        int n = suffix == 0
            ? snprintf(probe_name, sizeof(probe_name), ".migr-probe-fd-%ld",
                       (long)getpid())
            : snprintf(probe_name, sizeof(probe_name), ".migr-probe-fd-%ld_%u",
                       (long)getpid(), suffix);
        if (n < 0 || (size_t)n >= sizeof(probe_name))
            return -1;
        if (mkdirat(root_fd, probe_name, 0700) == 0)
        {
            created = 1;
            probe_fd = openat(root_fd, probe_name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            break;
        }
        if (errno != EEXIST)
            return -1;
    }
    if (!created || probe_fd < 0)
    {
        if (created)
            (void)unlinkat(root_fd, probe_name, AT_REMOVEDIR);
        return -1;
    }

    int baseline_ok = 0;
    int baseline_fd = openat(probe_fd, "baseline", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (baseline_fd >= 0)
    {
        close(baseline_fd);
        struct stat st;
        if (fstatat(probe_fd, "baseline", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISREG(st.st_mode))
            baseline_ok = 1;
        unlinkat(probe_fd, "baseline", 0);
    }
    if (!baseline_ok)
    {
        close(probe_fd);
        unlinkat(root_fd, probe_name, AT_REMOVEDIR);
        return -1;
    }

    out->capabilities[FS_CAP_MODE]           = probe_mode_fd(probe_fd);
    out->capabilities[FS_CAP_SYMLINK]        = probe_symlink_fd(probe_fd);
    out->capabilities[FS_CAP_FIFO]           = probe_fifo_fd(probe_fd);
    out->capabilities[FS_CAP_RAW_NAMES]      = probe_raw_names_fd(probe_fd);
    out->capabilities[FS_CAP_CASE_SENSITIVE] = probe_case_sensitive_fd(probe_fd);
    out->capabilities[FS_CAP_XATTR]          = probe_xattr_fd(probe_fd);
    out->capabilities[FS_CAP_TIMESTAMPS]    = probe_timestamps_dirfd(
        probe_fd, &out->nsec_exact);
    out->capabilities[FS_CAP_HARDLINK]      = probe_hardlink_fd(probe_fd);

    int failed = close(probe_fd) != 0;
    if (unlinkat(root_fd, probe_name, AT_REMOVEDIR) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

int fsprobe(const char *existing_root, FsCapabilityProfile *out)
{
    if (existing_root == NULL || out == NULL)
        return -1;
    int root_fd = open(existing_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        return -1;
    int rc = fsprobe_fd(root_fd, out);
    close(root_fd);
    return rc;
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
            case FS_CAP_UNSET:  // never probed: refuse rather than guess
            case FS_CAP_ERROR:
                return -1; // measurement untrustworthy: refuse
            default:
                return -1; // a corrupt/unknown status fails closed, never native
        }
    }
    *out = any_unavailable ? CLONE_PORTABLE_SIDECAR : CLONE_NATIVE_TREE;
    return 0;
}
