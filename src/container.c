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
/* Naming (docs/DECISIONS.md D71):                                          */
/*                                                                           */
/*   migr-<owner>                     the first backup of a user            */
/*   migr-<owner>-YYYY-MM-DD[-N]      when that name belongs to another     */
/*                                    install; N counts from 2              */
/* followed by ".partial" while the backup is being created.                */
/*                                                                           */
/* <owner> is the user's name, reduced to characters every destination     */
/* filesystem accepts. Which backup belongs to whom is decided by the       */
/* manifest, never by the name.                                             */
/* ========================================================================= */

#define CONTAINER_PREFIX "migr-"
#define CONTAINER_OWNER_MAX 32
#define CONTAINER_DATE_LEN 10 /* "YYYY-MM-DD" */
#define CONTAINER_PARTIAL_SUFFIX ".partial"

#ifdef CONTAINER_TEST_HOOKS
static ContainerTestReserveHook container_test_reserve_hook;
static void *container_test_reserve_hook_context;

void container_test_set_reserve_hook(ContainerTestReserveHook hook,
                                     void *context)
{
    container_test_reserve_hook = hook;
    container_test_reserve_hook_context = context;
}

static void container_test_after_partial_mkdir(int dir_fd,
                                               const char *partial_name)
{
    if (container_test_reserve_hook != NULL)
        container_test_reserve_hook(dir_fd, partial_name,
                                    container_test_reserve_hook_context);
}
#else
static void container_test_after_partial_mkdir(int dir_fd,
                                               const char *partial_name)
{
    (void)dir_fd;
    (void)partial_name;
}
#endif

static int name_char_valid(unsigned char c)
{
    return isalnum(c) || c == '.' || c == '_' || c == '-';
}

static int ends_with(const char *name, const char *suffix)
{
    size_t length = strlen(name), suffix_length = strlen(suffix);
    return length > suffix_length &&
           strcmp(name + length - suffix_length, suffix) == 0;
}

// "migr-<owner>": owner characters outside the portable set become '_'. The
// dot is kept inside a name but not at its start, where it would hide it.
static void build_base(const char *owner, char out[CONTAINER_NAME_MAX])
{
    size_t length = strlen(CONTAINER_PREFIX);
    memcpy(out, CONTAINER_PREFIX, length);
    for (size_t i = 0; owner != NULL && owner[i] != '\0' &&
                       i < CONTAINER_OWNER_MAX; i++)
    {
        unsigned char c = (unsigned char)owner[i];
        out[length++] = name_char_valid(c) && !(i == 0 && c == '.')
            ? (char)c : '_';
    }
    if (length == strlen(CONTAINER_PREFIX))
        out[length++] = '_';
    out[length] = '\0';
}

// The index-th name for base: base itself, then base-YYYY-MM-DD, then
// base-YYYY-MM-DD-2, -3, ... with the local date of when.
static int build_names(const char *base, int index, time_t when,
                       char final_out[CONTAINER_NAME_MAX],
                       char partial_out[CONTAINER_NAME_MAX])
{
    int n;
    if (index == 0)
        n = snprintf(final_out, CONTAINER_NAME_MAX, "%s", base);
    else
    {
        struct tm tmbuf;
        if (localtime_r(&when, &tmbuf) == NULL)
            return -1;
        char date[CONTAINER_DATE_LEN + 1];
        if (strftime(date, sizeof(date), "%Y-%m-%d", &tmbuf) !=
            CONTAINER_DATE_LEN)
            return -1;
        n = index == 1
            ? snprintf(final_out, CONTAINER_NAME_MAX, "%s-%s", base, date)
            : snprintf(final_out, CONTAINER_NAME_MAX, "%s-%s-%d", base, date,
                       index);
    }
    if (n < 0 || n >= CONTAINER_NAME_MAX)
        return -1;
    n = snprintf(partial_out, CONTAINER_NAME_MAX, "%s" CONTAINER_PARTIAL_SUFFIX,
                 final_out);
    return n < 0 || n >= CONTAINER_NAME_MAX ? -1 : 0;
}

// Whether stem (a name without its state suffix) is base, base-YYYY-MM-DD,
// or base-YYYY-MM-DD-N with N >= 2 and no leading zero: exactly what
// build_names() writes. Sets *index_out to the index that wrote it.
static int stem_matches_base(const char *stem, size_t stem_length,
                             const char *base, int *index_out)
{
    size_t base_length = strlen(base);
    if (stem_length < base_length || strncmp(stem, base, base_length) != 0)
        return 0;
    const char *rest = stem + base_length;
    size_t rest_length = stem_length - base_length;
    if (rest_length == 0)
    {
        *index_out = 0;
        return 1;
    }
    if (rest_length < 1 + CONTAINER_DATE_LEN || rest[0] != '-')
        return 0;
    const char *date = rest + 1;
    for (size_t i = 0; i < CONTAINER_DATE_LEN; i++)
        if ((i == 4 || i == 7) ? date[i] != '-'
                               : !isdigit((unsigned char)date[i]))
            return 0;
    const char *number = date + CONTAINER_DATE_LEN;
    size_t number_length = rest_length - 1 - CONTAINER_DATE_LEN;
    if (number_length == 0)
    {
        *index_out = 1;
        return 1;
    }
    if (number_length < 2 || number[0] != '-' || number[1] < '1' ||
        number[1] > '9' || number_length > 10)
        return 0;
    long value = 0;
    for (size_t i = 1; i < number_length; i++)
    {
        if (!isdigit((unsigned char)number[i]))
            return 0;
        value = value * 10 + (number[i] - '0');
    }
    if (value < 2 || value >= INT_MAX)
        return 0;
    *index_out = (int)value;
    return 1;
}

// Whether entry is one of base's in-progress names; writes its finished name.
static int parse_partial_name(const char *entry, const char *base,
                              char final_out[CONTAINER_NAME_MAX],
                              int *index_out)
{
    size_t length = strlen(entry);
    if (length >= CONTAINER_NAME_MAX ||
        !ends_with(entry, CONTAINER_PARTIAL_SUFFIX))
        return 0;
    size_t stem_length = length - strlen(CONTAINER_PARTIAL_SUFFIX);
    if (!stem_matches_base(entry, stem_length, base, index_out))
        return 0;
    memcpy(final_out, entry, stem_length);
    final_out[stem_length] = '\0';
    return 1;
}

// Whether stem looks like any user's container name, for callers that do not
// know the owner (restore and verify refusing an unfinished backup).
static int stem_is_container_name(const char *stem, size_t stem_length)
{
    size_t prefix_length = strlen(CONTAINER_PREFIX);
    if (stem_length <= prefix_length || stem_length >= CONTAINER_NAME_MAX ||
        strncmp(stem, CONTAINER_PREFIX, prefix_length) != 0)
        return 0;
    for (size_t i = prefix_length; i < stem_length; i++)
        if (!name_char_valid((unsigned char)stem[i]))
            return 0;
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

ContainerStatus container_reserve_fd(int dest_root_fd, const char *owner,
                                     time_t timestamp, BackupContainer *out)
{
    if (out == NULL || dest_root_fd < 0 || owner == NULL)
        return CONTAINER_ERR_INVALID;

    int dir_fd = fcntl(dest_root_fd, F_DUPFD_CLOEXEC, 0);
    if (dir_fd < 0)
        return CONTAINER_ERR_IO;

    char base[CONTAINER_NAME_MAX];
    build_base(owner, base);

    // suffix < INT_MAX (not <=) so suffix++ below never overflows a signed
    // int; this is a bound derived from the type, not a policy ceiling.
    for (int suffix = 0; suffix < INT_MAX; suffix++)
    {
        char final_name[CONTAINER_NAME_MAX];
        char partial_name[CONTAINER_NAME_MAX];
        if (build_names(base, suffix, timestamp, final_name,
                        partial_name) != 0)
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

        container_test_after_partial_mkdir(dir_fd, partial_name);

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
            if (errno == EWOULDBLOCK)
            {
                // A concurrent container_adopt_fd() scan can win this exact
                // partial's lock between our mkdirat() above and here -- a
                // legitimate race, not a fault of ours. It, not us, is
                // responsible for what it's holding; leave the directory
                // alone and try the next suffix, the same way an EEXIST
                // from mkdirat() above is handled.
                close(partial_fd);
                continue;
            }
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

ContainerStatus container_reserve(const char *dest_root, const char *owner,
                                  time_t timestamp, BackupContainer *out)
{
    if (out == NULL)
        return CONTAINER_ERR_INVALID;
    memset(out, 0, sizeof(*out));
    out->dir_fd = -1;
    out->partial_fd = -1;
    if (dest_root == NULL)
        return CONTAINER_ERR_INVALID;

    int dest_root_fd = open(dest_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dest_root_fd < 0)
        return CONTAINER_ERR_IO;
    ContainerStatus status = container_reserve_fd(dest_root_fd, owner,
                                                  timestamp, out);
    close(dest_root_fd);
    return status;
}

ContainerStatus container_adopt_fd(int dest_root_fd, const char *owner,
                                   const Manifest *wanted_identity,
                                   BackupContainer *out)
{
    if (out == NULL || dest_root_fd < 0 || owner == NULL)
        return CONTAINER_ERR_INVALID;
    if (wanted_identity == NULL)
        return CONTAINER_ERR_INVALID;
    // An invocation that cannot establish its own identity can never resume a
    // partial (docs/DECISIONS.md D15) -- rejected before any scan is attempted.
    if (!wanted_identity->has_source_identity)
        return CONTAINER_ERR_NO_MATCH;

    int root_fd = fcntl(dest_root_fd, F_DUPFD_CLOEXEC, 0);
    if (root_fd < 0)
        return CONTAINER_ERR_IO;
    char base[CONTAINER_NAME_MAX];
    build_base(owner, base);

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
        if (!parse_partial_name(entry->d_name, base, candidate_final,
                                &candidate_suffix))
            continue; // not this owner's grammar (includes "." and "..")

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

ContainerStatus container_adopt(const char *dest_root, const char *owner,
                                const Manifest *wanted_identity,
                                BackupContainer *out)
{
    if (out == NULL)
        return CONTAINER_ERR_INVALID;
    memset(out, 0, sizeof(*out));
    out->dir_fd = -1;
    out->partial_fd = -1;
    if (dest_root == NULL)
        return CONTAINER_ERR_INVALID;

    int dest_root_fd = open(dest_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dest_root_fd < 0)
        return CONTAINER_ERR_IO;
    ContainerStatus status = container_adopt_fd(dest_root_fd, owner,
                                                wanted_identity, out);
    close(dest_root_fd);
    return status;
}

ContainerStatus container_finalize(BackupContainer *container)
{
    if (container == NULL || container->state != CONTAINER_STATE_PARTIAL)
        return CONTAINER_ERR_INVALID;

    if (syncfs(container->partial_fd) != 0)
        return CONTAINER_ERR_IO;

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

    /*
     * The payload was flushed before publication. A directory-fsync failure
     * leaves only the rename's crash durability uncertain; the rename itself
     * succeeded, so do not misreport the finalized container as a failure.
     */
    (void)fsync(container->dir_fd);

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
    if (name == NULL || !ends_with(name, CONTAINER_PARTIAL_SUFFIX))
        return 0;
    return stem_is_container_name(name, strlen(name) -
                                            strlen(CONTAINER_PARTIAL_SUFFIX));
}

int container_name_is_final(const char *name)
{
    return name != NULL && !container_name_is_partial(name) &&
           stem_is_container_name(name, strlen(name));
}
