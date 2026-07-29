#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h> /* flock */
#include <sys/stat.h>
#include <unistd.h>

#include "container.h"

/* ========================================================================= */
/* Naming (docs/DECISIONS.md D15):                                          */
/*                                                                           */
/*   migr_backup_YYYYMMDD_HHMMSS[-N].partial   (live)                       */
/*   migr_backup_YYYYMMDD_HHMMSS[-N]           (finalized)                  */
/*                                                                           */
/* N, when present, has no leading zero (the writer below never produces    */
/* "-0"); the parser mirrors that exactly so a foreign or hand-crafted name  */
/* can never be misread as one of ours.                                     */
/* ========================================================================= */

#define CONTAINER_PREFIX "migr_backup_"
#define CONTAINER_STAMP_LEN 15 /* "YYYYMMDD_HHMMSS" */
#define CONTAINER_PARTIAL_SUFFIX ".partial"

static int all_digits(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

// Preserve backup.c's existing local-time naming convention. Tests fix the
// timezone, not the clock, to make the expected string computable.
static int format_stamp(time_t when, char *out, size_t out_size)
{
    struct tm tmbuf;
    if (localtime_r(&when, &tmbuf) == NULL)
        return -1;
    int n = snprintf(out, out_size, CONTAINER_PREFIX "%04d%02d%02d_%02d%02d%02d",
                      tmbuf.tm_year + 1900, tmbuf.tm_mon + 1, tmbuf.tm_mday,
                      tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec);
    if (n < 0 || (size_t)n >= out_size)
        return -1;
    return 0;
}

// Builds the final and partial leaf names for a given base+suffix. suffix == 0
// means "no -N at all" (the first candidate), matching what parse_partial_name
// accepts back.
static int build_names(const char *base, int suffix,
                        char *final_out, size_t final_size,
                        char *partial_out, size_t partial_size)
{
    int n = (suffix == 0)
        ? snprintf(final_out, final_size, "%s", base)
        : snprintf(final_out, final_size, "%s-%d", base, suffix);
    if (n < 0 || (size_t)n >= final_size)
        return -1;

    n = snprintf(partial_out, partial_size, "%s" CONTAINER_PARTIAL_SUFFIX, final_out);
    if (n < 0 || (size_t)n >= partial_size)
        return -1;

    return 0;
}

// Recognizes exactly the grammar container_reserve() can produce and writes
// the corresponding final (non-".partial") name to final_out, which must be
// CONTAINER_NAME_MAX bytes (matching every other name buffer in this file).
// Rejects "-0", "-00", "-01", any other leading zero, a bare "-", and any
// suffix that would not fit in int -- none of which the writer ever produces.
static int parse_partial_name(const char *entry, char *final_out, int *suffix_out)
{
    static const char suffix_marker[] = CONTAINER_PARTIAL_SUFFIX;
    const size_t suffix_len = sizeof(suffix_marker) - 1;
    const size_t prefix_len = sizeof(CONTAINER_PREFIX) - 1;

    size_t len = strlen(entry);
    if (len >= CONTAINER_NAME_MAX) // would not fit our own fixed-size storage
        return 0;
    if (len <= suffix_len || strcmp(entry + len - suffix_len, suffix_marker) != 0)
        return 0;

    size_t base_len = len - suffix_len;
    if (base_len < prefix_len + CONTAINER_STAMP_LEN)
        return 0;
    if (strncmp(entry, CONTAINER_PREFIX, prefix_len) != 0)
        return 0;

    const char *stamp = entry + prefix_len;
    if (!all_digits(stamp, 8) || stamp[8] != '_' || !all_digits(stamp + 9, 6))
        return 0;

    size_t rest_len = base_len - (prefix_len + CONTAINER_STAMP_LEN);
    const char *rest = entry + prefix_len + CONTAINER_STAMP_LEN;

    int suffix = 0;
    if (rest_len > 0)
    {
        if (rest[0] != '-' || rest_len < 2 || rest[1] < '1' || rest[1] > '9')
            return 0;
        for (size_t i = 1; i < rest_len; i++)
            if (!isdigit((unsigned char)rest[i]))
                return 0;

        char numbuf[CONTAINER_NAME_MAX]; // rest_len < CONTAINER_NAME_MAX (len already bounded above)
        memcpy(numbuf, rest + 1, rest_len - 1);
        numbuf[rest_len - 1] = '\0';

        char *end;
        errno = 0;
        long v = strtol(numbuf, &end, 10);
        // container_reserve()'s loop condition is "suffix < INT_MAX" (to
        // keep suffix++ itself from overflowing), so INT_MAX is never a
        // suffix the writer can actually produce -- only up to INT_MAX - 1.
        // The parser must reject exactly what the writer cannot produce.
        if (errno != 0 || *end != '\0' || v <= 0 || v >= INT_MAX)
            return 0;
        suffix = (int)v;
    }

    memcpy(final_out, entry, base_len);
    final_out[base_len] = '\0';
    *suffix_out = suffix;
    return 1;
}

// Removes a partial this invocation just created and does not intend to
// keep. When a lock is held, unlinkat() runs before partial_fd is closed, so a
// successful cleanup removes the name before releasing the lock. partial_fd
// may be -1 if no fd was ever opened. unlinkat() failure is returned to the
// caller rather than being mistaken for successful cleanup.
static int abandon_own_claim(int dir_fd, int partial_fd, const char *partial_name)
{
    int rc = unlinkat(dir_fd, partial_name, AT_REMOVEDIR);
    if (partial_fd >= 0)
        close(partial_fd);
    return rc;
}

ContainerStatus container_reserve(const char *dest_root, time_t timestamp, BackupContainer *out)
{
    if (out == NULL)
        return CONTAINER_ERR_INVALID;
    memset(out, 0, sizeof(*out));
    out->dir_fd = -1;
    out->partial_fd = -1;
    if (dest_root == NULL)
        return CONTAINER_ERR_INVALID;

    char base[CONTAINER_NAME_MAX];
    if (format_stamp(timestamp, base, sizeof(base)) != 0)
        return CONTAINER_ERR_IO;

    int dir_fd = open(dest_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0)
        return CONTAINER_ERR_IO;

    // suffix < INT_MAX (not <=) so suffix++ below never overflows a signed
    // int; this is a bound derived from the type, not a policy ceiling.
    for (int suffix = 0; suffix < INT_MAX; suffix++)
    {
        char final_name[CONTAINER_NAME_MAX];
        char partial_name[CONTAINER_NAME_MAX];
        if (build_names(base, suffix, final_name, sizeof(final_name),
                         partial_name, sizeof(partial_name)) != 0)
        {
            close(dir_fd);
            return CONTAINER_ERR_IO;
        }

        struct stat st;
        if (fstatat(dir_fd, final_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
            continue; // final already taken; try next suffix
        if (errno != ENOENT)
        {
            close(dir_fd);
            return CONTAINER_ERR_IO;
        }

        if (mkdirat(dir_fd, partial_name, 0700) != 0)
        {
            if (errno == EEXIST)
                continue; // another process (or a prior run) claimed this suffix
            close(dir_fd);
            return CONTAINER_ERR_IO;
        }

        int partial_fd = openat(dir_fd, partial_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (partial_fd < 0)
        {
            // Nothing was ever locked (openat() itself failed); already
            // failing for this reason regardless of the cleanup's outcome.
            abandon_own_claim(dir_fd, -1, partial_name);
            close(dir_fd);
            return CONTAINER_ERR_IO;
        }

        if (flock(partial_fd, LOCK_EX | LOCK_NB) != 0)
        {
            // Already failing for this reason regardless of the cleanup's
            // outcome (no lock was ever successfully held here either way).
            abandon_own_claim(dir_fd, partial_fd, partial_name);
            close(dir_fd);
            return CONTAINER_ERR_IO;
        }

        // Post-claim recheck: closes the race where a concurrent invocation
        // finalizes a matching final name between our first check above and
        // here. Only our own just-created (still-empty) partial is removed.
        if (fstatat(dir_fd, final_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
        {
            if (abandon_own_claim(dir_fd, partial_fd, partial_name) != 0)
            {
                // Cleanup itself failed: must not silently continue to the
                // next suffix, which would report success while this
                // orphaned, empty, still-locked-by-nobody partial stays
                // behind on disk (docs/DECISIONS.md D15).
                close(dir_fd);
                return CONTAINER_ERR_IO;
            }
            continue;
        }
        if (errno != ENOENT)
        {
            // Already failing for this reason regardless of the cleanup's
            // outcome.
            abandon_own_claim(dir_fd, partial_fd, partial_name);
            close(dir_fd);
            return CONTAINER_ERR_IO;
        }

        out->dir_fd = dir_fd;
        out->partial_fd = partial_fd;
        snprintf(out->partial_name, sizeof(out->partial_name), "%s", partial_name);
        snprintf(out->final_name, sizeof(out->final_name), "%s", final_name);
        out->suffix = suffix;
        out->state = CONTAINER_STATE_PARTIAL;
        return CONTAINER_OK;
    }

    close(dir_fd);
    return CONTAINER_ERR_IO;
}

ContainerStatus container_adopt(const char *dest_root, const Manifest *wanted_identity, BackupContainer *out)
{
    if (out == NULL)
        return CONTAINER_ERR_INVALID;
    memset(out, 0, sizeof(*out));
    out->dir_fd = -1;
    out->partial_fd = -1;
    if (dest_root == NULL || wanted_identity == NULL)
        return CONTAINER_ERR_INVALID;
    // An invocation that cannot establish its own identity can never resume a
    // partial (docs/DECISIONS.md D15) -- rejected before any scan is attempted.
    if (!wanted_identity->has_source_identity)
        return CONTAINER_ERR_NO_MATCH;

    int root_fd = open(dest_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        return CONTAINER_ERR_IO;

    // Scanning needs its own fd (readdir position) without a second open() by
    // path: dup the already-open root_fd instead.
    int scan_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (scan_fd < 0)
    {
        close(root_fd);
        return CONTAINER_ERR_IO;
    }

    DIR *dirp = fdopendir(scan_fd);
    if (dirp == NULL)
    {
        close(scan_fd);
        close(root_fd);
        return CONTAINER_ERR_IO;
    }

    int best_fd = -1;
    char best_partial[CONTAINER_NAME_MAX];
    char best_final[CONTAINER_NAME_MAX];
    int best_suffix = 0;
    int found = 0;
    int scan_error = 0;

    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dirp);
        if (entry == NULL)
        {
            if (errno != 0)
                scan_error = 1; // a genuine readdir() fault, distinct from clean EOF
            break;
        }

        char candidate_final[CONTAINER_NAME_MAX];
        int candidate_suffix;
        if (!parse_partial_name(entry->d_name, candidate_final, &candidate_suffix))
            continue; // not our grammar at all (includes "." and "..")

        int cand_fd = openat(root_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (cand_fd < 0)
        {
            if (errno == ENOENT)
                continue; // removed concurrently between readdir() and here
            scan_error = 1;
            break;
        }

        if (flock(cand_fd, LOCK_EX | LOCK_NB) != 0)
        {
            int lock_errno = errno;
            close(cand_fd);
            if (lock_errno == EWOULDBLOCK)
                continue; // a live process holds this one; not adoptable, not an error
            scan_error = 1;
            break;
        }

        Manifest cand_manifest;
        ManifestStatus mst = manifest_read_v1_at(cand_fd, &cand_manifest);
        if (mst == MANIFEST_STATUS_IO_ERROR)
        {
            scan_error = 1; // an unreadable candidate could be hiding a second match
            close(cand_fd);
            break;
        }
        if (mst != MANIFEST_STATUS_VALID)
        {
            close(cand_fd); // missing/legacy/malformed/unknown-version: not adoptable
            continue;
        }

        ManifestIdentityComparison cmp = manifest_resume_identity_compare(&cand_manifest, wanted_identity);
        manifest_free(&cand_manifest);

        if (cmp == MANIFEST_IDENTITY_ERROR)
        {
            // An allocation failure while comparing is an operational fault,
            // not proof this candidate isn't a match -- must not silently
            // fall through to NO_MATCH (docs/DECISIONS.md D15).
            scan_error = 1;
            close(cand_fd);
            break;
        }
        if (cmp != MANIFEST_IDENTITY_EQUAL)
        {
            close(cand_fd);
            continue;
        }

        // parse_partial_name() already rejects any entry name that would not
        // fit CONTAINER_NAME_MAX, so d_name_len here is provably in range --
        // checked again anyway rather than trusting that invariant blind.
        size_t d_name_len = strlen(entry->d_name);
        if (d_name_len >= sizeof(best_partial))
        {
            scan_error = 1;
            close(cand_fd);
            break;
        }

        found++;
        if (found == 1)
        {
            best_fd = cand_fd;
            memcpy(best_partial, entry->d_name, d_name_len + 1);
            snprintf(best_final, sizeof(best_final), "%s", candidate_final);
            best_suffix = candidate_suffix;
        }
        else
        {
            close(cand_fd); // a second exact match; already ambiguous, keep scanning
        }
    }

    closedir(dirp); // also closes scan_fd

    if (scan_error)
    {
        if (best_fd >= 0)
            close(best_fd);
        close(root_fd);
        return CONTAINER_ERR_IO;
    }
    if (found == 0)
    {
        close(root_fd);
        return CONTAINER_ERR_NO_MATCH;
    }
    if (found > 1)
    {
        close(best_fd);
        close(root_fd);
        return CONTAINER_ERR_AMBIGUOUS;
    }

    out->dir_fd = root_fd;
    out->partial_fd = best_fd; // the same verified fd; never closed and reopened by name
    snprintf(out->partial_name, sizeof(out->partial_name), "%s", best_partial);
    snprintf(out->final_name, sizeof(out->final_name), "%s", best_final);
    out->suffix = best_suffix;
    out->state = CONTAINER_STATE_PARTIAL;
    return CONTAINER_OK;
}

ContainerStatus container_finalize(BackupContainer *container)
{
    if (container == NULL || container->state != CONTAINER_STATE_PARTIAL)
        return CONTAINER_ERR_INVALID;

    if (renameat2(container->dir_fd, container->partial_name,
                  container->dir_fd, container->final_name,
                  RENAME_NOREPLACE) != 0)
    {
        switch (errno)
        {
            case EEXIST:
                return CONTAINER_ERR_FINAL_EXISTS;
            case ENOSYS:
            case EINVAL:
            case EOPNOTSUPP:
                return CONTAINER_ERR_NOREPLACE;
            default:
                return CONTAINER_ERR_IO;
        }
    }

    container->state = CONTAINER_STATE_FINALIZED;
    return CONTAINER_OK;
}

void container_close(BackupContainer *container)
{
    if (container == NULL)
        return;
    if (container->state != CONTAINER_STATE_EMPTY)
    {
        if (container->partial_fd >= 0)
            close(container->partial_fd);
        if (container->dir_fd >= 0)
            close(container->dir_fd);
    }
    memset(container, 0, sizeof(*container));
    container->dir_fd = -1;
    container->partial_fd = -1;
}

int container_root_fd(const BackupContainer *container)
{
    if (container == NULL || container->state == CONTAINER_STATE_EMPTY)
        return -1;
    return container->partial_fd;
}

const char *container_current_name(const BackupContainer *container)
{
    if (container == NULL)
        return NULL;
    if (container->state == CONTAINER_STATE_FINALIZED)
        return container->final_name;
    if (container->state == CONTAINER_STATE_PARTIAL)
        return container->partial_name;
    return NULL;
}

int container_name_is_partial(const char *name)
{
    if (name == NULL)
        return 0;
    char final_out[CONTAINER_NAME_MAX];
    int suffix;
    return parse_partial_name(name, final_out, &suffix) ? 1 : 0;
}

int container_name_is_final(const char *name)
{
    if (name == NULL)
        return 0;

    char partial_name[CONTAINER_NAME_MAX];
    int n = snprintf(partial_name, sizeof(partial_name), "%s%s",
                     name, CONTAINER_PARTIAL_SUFFIX);
    if (n < 0 || (size_t)n >= sizeof(partial_name))
        return 0;

    char final_out[CONTAINER_NAME_MAX];
    int suffix;
    return parse_partial_name(partial_name, final_out, &suffix) ? 1 : 0;
}
