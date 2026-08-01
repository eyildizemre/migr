#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <limits.h> // to use PATH_MAX
#include <errno.h>

#include "fileops.h" // CloneContext
#include "metadata.h"
#include "utils.h" // path_join

/* ========================================================================= */
/* Native backup capture: pathname-based source, FD-anchored destination.   */
/*                                                                          */
/* The source side is read through ordinary paths (it is the user's own     */
/* tree, addressed exactly as they named it). The destination side never is:*/
/* every step down uses openat/mkdirat/fstatat under a directory fd the     */
/* caller owns, with O_NOFOLLOW everywhere, so neither an intermediate nor  */
/* a final symlink inside the container can redirect a write outside it --  */
/* which is what makes resuming into an adopted, previously-written         */
/* container safe (docs/DECISIONS.md D15).                                  */
/* ========================================================================= */

// A destination address this walker accepts is exactly one path component.
// Anything with a '/' would be a path to re-resolve, which is precisely what
// the fd anchoring exists to avoid; "." and ".." address the parent rather
// than a new object.
static int destination_leaf_is_safe(const char *leaf)
{
    return leaf != NULL && leaf[0] != '\0' &&
           strchr(leaf, '/') == NULL &&
           strcmp(leaf, ".") != 0 &&
           strcmp(leaf, "..") != 0;
}

static int capture_entry_at(const CloneContext *ctx, const char *src,
                            int dest_dir_fd, const char *leaf);

// An identical symlink already at this address is work a previous run
// finished, so resuming past it succeeds. Any other object there -- a
// symlink to somewhere else included -- is a genuine collision and is
// refused rather than replaced.
static int capture_symlink_at(const char *src, int dest_dir_fd, const char *leaf,
                              const struct stat *st,
                              MetadataTimestampPolicy policy)
{
    char link_target[PATH_MAX];
    ssize_t len = readlink(src, link_target, sizeof(link_target) - 1);
    if (len < 0)
        return -1;
    link_target[len] = '\0';

    if (symlinkat(link_target, dest_dir_fd, leaf) != 0)
    {
        if (errno != EEXIST)
            return -1;

        struct stat dest_st;
        if (fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISLNK(dest_st.st_mode))
            return -1;

        char existing[PATH_MAX];
        ssize_t existing_len = readlinkat(dest_dir_fd, leaf, existing, sizeof(existing) - 1);
        if (existing_len < 0)
            return -1;
        existing[existing_len] = '\0';

        if (strcmp(existing, link_target) != 0)
            return -1;
    }

    struct stat after;
    if (lstat(src, &after) != 0 || !metadata_symlink_unchanged(st, &after))
        return -1;
    return metadata_apply_symlink_at(dest_dir_fd, leaf, st, policy);
}

// A write() that reports zero bytes for a non-zero request has made no
// progress and never will on a retry, so it is treated as the failure it is
// rather than spun on forever.
static int copy_file_contents(int src_fd, int dest_fd)
{
    char buffer[8192];
    ssize_t bytes_read;
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0)
    {
        ssize_t bytes_written = 0;
        while (bytes_written < bytes_read)
        {
            ssize_t res = write(dest_fd, buffer + bytes_written,
                                (size_t)(bytes_read - bytes_written));
            if (res <= 0)
                return -1;
            bytes_written += res;
        }
    }
    return bytes_read < 0 ? -1 : 0;
}

static int capture_regular_at(const CloneContext *ctx, const char *src,
                              int dest_dir_fd, const char *leaf,
                              const struct stat *st)
{
    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
    int src_fd = open(src, O_RDONLY | O_NOATIME | O_CLOEXEC | O_NOFOLLOW);
    if (src_fd < 0)
        return -1;

    struct stat source_snapshot;
    if (fstat(src_fd, &source_snapshot) != 0 ||
        !S_ISREG(source_snapshot.st_mode) ||
        !metadata_source_unchanged(st, &source_snapshot))
    {
        close(src_fd);
        return -1;
    }

    struct stat dest_st;
    if (fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        // A matching size and mtime is the resume signal; a different type at
        // the same address is a collision, never something to truncate.
        if (!S_ISREG(dest_st.st_mode))
        {
            close(src_fd);
            return -1;
        }
        if (dest_st.st_size == source_snapshot.st_size &&
            dest_st.st_mtim.tv_sec == source_snapshot.st_mtim.tv_sec &&
            policy.nsec_exact &&
            dest_st.st_mtim.tv_nsec == source_snapshot.st_mtim.tv_nsec)
        {
            int dest_fd = openat(dest_dir_fd, leaf,
                                 O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            if (dest_fd < 0)
            {
                close(src_fd);
                return -1;
            }
            struct stat opened_dest;
            int failed = fstat(dest_fd, &opened_dest) != 0 ||
                         !S_ISREG(opened_dest.st_mode) ||
                         metadata_apply_fd(dest_fd, &source_snapshot, policy) != 0;
            struct stat after;
            if (!failed && (fstat(src_fd, &after) != 0 ||
                            !metadata_source_unchanged(&source_snapshot, &after)))
                failed = 1;
            if (close(dest_fd) != 0)
                failed = 1;
            if (close(src_fd) != 0)
                failed = 1;
            return failed ? -1 : 0;
        }
    }
    else if (errno != ENOENT)
    {
        close(src_fd);
        return -1;
    }

    // O_NOFOLLOW makes a symlink planted at this address fail the open with
    // ELOOP instead of being written through; O_TRUNC can therefore only ever
    // apply to the regular file the check above already accepted.
    int dest_fd = openat(dest_dir_fd, leaf,
                         O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                         source_snapshot.st_mode & 07777);
    if (dest_fd < 0)
    {
        close(src_fd);
        return -1;
    }

    int failed = copy_file_contents(src_fd, dest_fd) != 0;
    struct stat after;
    if (!failed && (fstat(src_fd, &after) != 0 ||
                    !metadata_source_unchanged(&source_snapshot, &after)))
        failed = 1;
    if (!failed && metadata_apply_fd(dest_fd, &source_snapshot, policy) != 0)
        failed = 1;

    // A write deferred by the kernel (quota, ENOSPC, a network filesystem)
    // can surface only here, so a failed close means the payload is not
    // actually complete and must be reported as such.
    if (close(dest_fd) != 0)
        failed = 1;
    if (close(src_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

// The directory is created with owner-only access and given the source's real
// mode by metadata_apply_fd() only after its whole subtree is written.
// Creating it with the final mode up front would make a read-only source
// directory (e.g. 0555) impossible to descend into and populate, and the
// transient 0700 is never more permissive to group or other than the mode it
// ends up with.
static int capture_directory_at(const CloneContext *ctx, const char *src,
                                int dest_dir_fd, const char *leaf,
                                const struct stat *st)
{
    if (mkdirat(dest_dir_fd, leaf, 0700) != 0 && errno != EEXIST)
        return -1;

    // O_NOFOLLOW rejects a symlink standing where the directory should be
    // (descending through it would write payload outside the container);
    // O_DIRECTORY rejects every other wrong type in the same call.
    int child_fd = openat(dest_dir_fd, leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_fd < 0)
        return -1;

    int source_fd = open(src, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
    if (source_fd < 0)
    {
        close(child_fd);
        return -1;
    }
    struct stat source_snapshot;
    if (fstat(source_fd, &source_snapshot) != 0 ||
        !S_ISDIR(source_snapshot.st_mode) ||
        !metadata_source_unchanged(st, &source_snapshot))
    {
        close(source_fd);
        close(child_fd);
        return -1;
    }

    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        close(source_fd);
        close(child_fd);
        return -1;
    }

    int failed = 0;
    struct dirent *entry;
    for (;;)
    {
        // readdir() reports both "end of directory" and "read failed" as NULL;
        // only errno tells them apart. Without this reset a real read error
        // would look like a complete directory, and the container would be
        // finalized around a silently short subtree.
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
                failed = 1;
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Only the source path grows as we descend; refuse rather than act on
        // a truncated one. The destination never concatenates at all.
        char child_src[PATH_MAX];
        if (path_join(child_src, sizeof(child_src), src, entry->d_name) != 0 ||
            capture_entry_at(ctx, child_src, child_fd, entry->d_name) != 0)
        {
            failed = 1;
            break;
        }
    }

    if (closedir(dir) != 0)
        failed = 1;
    struct stat after;
    if (!failed && (fstat(source_fd, &after) != 0 ||
                    !metadata_source_unchanged(&source_snapshot, &after)))
        failed = 1;
    if (!failed && metadata_apply_fd(child_fd, &source_snapshot,
                                     metadata_policy_from_context(ctx)) != 0)
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    if (close(child_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

// Recreate the node itself, never its contents: reading a FIFO blocks until a
// writer appears, which would hang the whole backup. An existing FIFO at this
// address is accepted so an interrupted backup can resume past it.
static int capture_fifo_at(const CloneContext *ctx, int dest_dir_fd,
                           const char *leaf, const struct stat *st)
{
    if (mkfifoat(dest_dir_fd, leaf, st->st_mode & 07777) != 0)
    {
        struct stat dest_st;
        if (errno != EEXIST ||
            fstatat(dest_dir_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISFIFO(dest_st.st_mode))
            return -1;
    }

    // O_RDONLY | O_NONBLOCK is the one way to open a FIFO that returns
    // immediately with no writer on the other end. The fd is opened purely so
    // the metadata below goes through an fd like every other type here, rather
    // than through a path a swap could redirect.
    int fifo_fd = openat(dest_dir_fd, leaf,
                         O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fifo_fd < 0)
        return -1;

    struct stat opened;
    int failed = fstat(fifo_fd, &opened) != 0 || !S_ISFIFO(opened.st_mode) ||
                 metadata_apply_fd(fifo_fd, st,
                                    metadata_policy_from_context(ctx)) != 0;
    if (close(fifo_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int capture_entry_at(const CloneContext *ctx, const char *src,
                            int dest_dir_fd, const char *leaf)
{
    struct stat st;
    if (lstat(src, &st) != 0)
        return -1;

    MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
    if (S_ISLNK(st.st_mode))
        return capture_symlink_at(src, dest_dir_fd, leaf, &st, policy);
    if (S_ISREG(st.st_mode))
        return capture_regular_at(ctx, src, dest_dir_fd, leaf, &st);
    if (S_ISDIR(st.st_mode))
        return capture_directory_at(ctx, src, dest_dir_fd, leaf, &st);
    if (S_ISFIFO(st.st_mode))
        return capture_fifo_at(ctx, dest_dir_fd, leaf, &st);

    // Sockets and device nodes carry no copyable content: a socket is a runtime
    // IPC endpoint, a device node needs root to recreate. Skip either with a
    // warning rather than failing the enclosing directory over it.
    if (S_ISSOCK(st.st_mode))
    {
        printf("  Warning: skipping socket (runtime-only): %s\n", src);
        return 0;
    }
    if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
    {
        printf("  Warning: skipping %s device node: %s\n",
               S_ISCHR(st.st_mode) ? "character" : "block", src);
        return 0;
    }

    return -1; // unknown file type (unreachable on Linux); refuse defensively
}

int backup_capture_at(const CloneContext *ctx, const char *source_path,
                      int destination_root_fd, const char *destination_leaf)
{
    // Fail closed on a mis-dispatched context rather than running a native clone blindly:
    // a wrong direction or an unimplemented representation must not silently produce a
    // native tree where a sidecar was required.
    if (ctx == NULL || ctx->operation != CLONE_BACKUP ||
        ctx->representation != CLONE_NATIVE_TREE)
        return -1;
    if (source_path == NULL || destination_root_fd < 0 ||
        !destination_leaf_is_safe(destination_leaf))
        return -1;

    return capture_entry_at(ctx, source_path, destination_root_fd, destination_leaf);
}

/* ========================================================================= */
/* FD-anchored native restore core (docs/DECISIONS.md D15 and D16).          */
/*                                                                          */
/* Separate from the capture walker above because the trust boundaries       */
/* differ: restore treats the backup payload as untrusted too, resolving     */
/* both sides component-by-component under directory fds, and refuses a      */
/* symlink at a final destination address rather than writing through it.    */
/* ========================================================================= */

// A path component can never be longer than NAME_MAX; sizing leaf buffers to
// this (rather than PATH_MAX) is what lets the walker below proceed
// component-by-component without ever concatenating a full path string.
#define RESTORE_LEAF_MAX (NAME_MAX + 1)

typedef enum {
    RESTORE_RESOLVE_ERROR = -1,
    RESTORE_RESOLVE_MISSING = 0,
    RESTORE_RESOLVE_OK = 1
} RestoreResolveResult;

typedef enum {
    RESTORE_VALIDATE,
    RESTORE_APPLY
} RestorePass;

// Validates a relative address before any traversal is attempted: a leading
// '/', any ".." component, a bare ".", or an empty interior/trailing
// component (e.g. "a//b" or "a/") are all refused outright -- never
// normalized into some other, unintended address. Does not accept an
// overall empty string; callers special-case "" as "the root object itself"
// before ever reaching this function, since it names zero components, not
// one rejected empty component.
static int relative_path_is_safe(const char *rel)
{
    if (rel[0] == '/')
        return 0;

    size_t start = 0;
    size_t len = strlen(rel);
    for (size_t i = 0; i <= len; i++)
    {
        if (rel[i] == '/' || rel[i] == '\0')
        {
            size_t comp_len = i - start;
            if (comp_len == 0)
                return 0; // "//" or a trailing slash
            if (comp_len == 1 && rel[start] == '.')
                return 0;
            if (comp_len == 2 && rel[start] == '.' && rel[start + 1] == '.')
                return 0;
            start = i + 1;
        }
    }
    return 1;
}

static int fd_is_directory(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
}

static int same_object(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int copy_leaf_name(const char *rel, char *out_leaf, size_t leaf_size)
{
    const char *leaf = strrchr(rel, '/');
    leaf = leaf == NULL ? rel : leaf + 1;
    size_t len = strlen(leaf);
    if (len >= leaf_size)
        return -1;
    memcpy(out_leaf, leaf, len + 1);
    return 0;
}

// Walks every component before rel's leaf from root_fd. An OK result owns
// *out_parent_fd; MISSING means a no-create walk encountered an absent
// intermediate. Existing intermediate symlinks and wrong object types fail.
static RestoreResolveResult resolve_parent(int root_fd, const char *rel,
                                           int create_intermediates,
                                           int *out_parent_fd,
                                           char *out_leaf, size_t leaf_size)
{
    *out_parent_fd = -1;
    if (copy_leaf_name(rel, out_leaf, leaf_size) != 0)
        return RESTORE_RESOLVE_ERROR;

    if (rel[0] == '\0')
    {
        int fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0)
            return RESTORE_RESOLVE_ERROR;
        *out_parent_fd = fd;
        return RESTORE_RESOLVE_OK;
    }

    int cur_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (cur_fd < 0)
        return RESTORE_RESOLVE_ERROR;

    const char *p = rel;
    for (;;)
    {
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);

        char comp[RESTORE_LEAF_MAX];
        if (comp_len >= sizeof(comp))
        {
            close(cur_fd);
            return RESTORE_RESOLVE_ERROR;
        }
        memcpy(comp, p, comp_len);
        comp[comp_len] = '\0';

        if (slash == NULL)
        {
            *out_parent_fd = cur_fd;
            return RESTORE_RESOLVE_OK;
        }

        int next_fd = openat(cur_fd, comp,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0 && errno == ENOENT && create_intermediates)
        {
            if (mkdirat(cur_fd, comp, 0700) != 0 && errno != EEXIST)
            {
                close(cur_fd);
                return RESTORE_RESOLVE_ERROR;
            }
            next_fd = openat(cur_fd, comp,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next_fd < 0)
        {
            int saved_errno = errno;
            close(cur_fd);
            if (!create_intermediates && saved_errno == ENOENT)
                return RESTORE_RESOLVE_MISSING;
            return RESTORE_RESOLVE_ERROR;
        }

        close(cur_fd);
        cur_fd = next_fd;
        p = slash + 1;
    }
}

// Returns a duplicate fd for the directory in which the destination root will
// actually be created or traversed. Existing directory roots use the root
// directory itself; an absent leaf (or an absent intermediate) uses the
// nearest existing parent. This is deliberately separate from resolve_parent:
// a missing intermediate must remain a missing destination during validation,
// not be mistaken for a shorter path under that parent.
static int destination_metadata_anchor(int root_fd, const char *rel)
{
    if (root_fd < 0 || rel == NULL ||
        (rel[0] != '\0' && !relative_path_is_safe(rel)))
        return -1;

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    if (rel[0] == '\0')
        return current;

    const char *p = rel;
    for (;;)
    {
        const char *slash = strchr(p, '/');
        size_t length = slash == NULL ? strlen(p) : (size_t)(slash - p);
        if (length == 0 || length > NAME_MAX)
        {
            close(current);
            return -1;
        }

        if (slash == NULL)
        {
            struct stat final_st;
            if (fstatat(current, p, &final_st, AT_SYMLINK_NOFOLLOW) != 0)
            {
                if (errno == ENOENT)
                    return current;
                close(current);
                return -1;
            }
            if (!S_ISDIR(final_st.st_mode))
                return current;

            int final_fd = openat(current, p,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
            if (final_fd < 0)
            {
                close(current);
                return -1;
            }
            close(current);
            return final_fd;
        }

        char component[NAME_MAX + 1];
        memcpy(component, p, length);
        component[length] = '\0';
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
        {
            if (errno == ENOENT)
                return current;
            close(current);
            return -1;
        }
        close(current);
        current = next;
        p = slash + 1;
    }
}

static int open_source_object(int source_parent_fd, const char *source_leaf,
                              struct stat *st)
{
    int fd = source_leaf[0] == '\0'
        ? fcntl(source_parent_fd, F_DUPFD_CLOEXEC, 0)
        : openat(source_parent_fd, source_leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, st) != 0)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int destination_status(int dest_parent_fd, const char *dest_leaf,
                              struct stat *st, int *exists)
{
    if (dest_parent_fd < 0)
    {
        *exists = 0;
        return 0;
    }

    if (dest_leaf[0] == '\0')
    {
        if (fstat(dest_parent_fd, st) != 0)
            return -1;
        *exists = 1;
        return 0;
    }

    if (fstatat(dest_parent_fd, dest_leaf, st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        *exists = 1;
        return 0;
    }
    if (errno == ENOENT)
    {
        *exists = 0;
        return 0;
    }
    return -1;
}

static int open_source_regular(int source_parent_fd, const char *source_leaf,
                               const struct stat *object_st, struct stat *opened_st)
{
    int fd = openat(source_parent_fd, source_leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, opened_st) != 0 || !S_ISREG(opened_st->st_mode) ||
        !same_object(object_st, opened_st))
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int open_destination_regular(int dest_parent_fd, const char *dest_leaf,
                                    mode_t mode, struct stat *opened_st,
                                    int *created)
{
    *created = 0;
    for (int attempt = 0; attempt < 2; attempt++)
    {
        int fd = openat(dest_parent_fd, dest_leaf,
                        O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0)
        {
            if (fstat(fd, opened_st) == 0 && S_ISREG(opened_st->st_mode))
                return fd;
            close(fd);
            return -1;
        }
        if (errno != ENOENT)
            return -1;

        fd = openat(dest_parent_fd, dest_leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NONBLOCK |
                    O_NOFOLLOW | O_CLOEXEC, mode);
        if (fd >= 0)
        {
            if (fstat(fd, opened_st) == 0 && S_ISREG(opened_st->st_mode))
            {
                *created = 1;
                return fd;
            }
            close(fd);
            return -1;
        }
        if (errno != EEXIST)
            return -1;
    }
    return -1;
}

static int open_source_directory(int source_object_fd,
                                 const struct stat *object_st,
                                 struct stat *opened_st)
{
    int fd = openat(source_object_fd, ".",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, opened_st) != 0 || !S_ISDIR(opened_st->st_mode) ||
        !same_object(object_st, opened_st))
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int open_destination_directory(RestorePass pass,
                                      int dest_parent_fd, const char *dest_leaf)
{
    if (dest_parent_fd < 0)
        return pass == RESTORE_VALIDATE ? -2 : -1;
    if (dest_leaf[0] == '\0')
    {
        int fd = fcntl(dest_parent_fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0 || !fd_is_directory(fd))
        {
            if (fd >= 0)
                close(fd);
            return -1;
        }
        return fd;
    }

    int fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0)
        return fd;
    if (errno != ENOENT)
        return -1;
    if (pass == RESTORE_VALIDATE)
        return -2;

    if (mkdirat(dest_parent_fd, dest_leaf, 0700) != 0 && errno != EEXIST)
        return -1;
    return openat(dest_parent_fd, dest_leaf,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int open_destination_fifo(int dest_parent_fd, const char *dest_leaf,
                                 mode_t mode, struct stat *opened_st)
{
    int fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
    {
        if (mkfifoat(dest_parent_fd, dest_leaf, mode) != 0 && errno != EEXIST)
            return -1;
        fd = openat(dest_parent_fd, dest_leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0)
        return -1;
    if (fstat(fd, opened_st) == 0 && S_ISFIFO(opened_st->st_mode))
        return fd;
    close(fd);
    return -1;
}

/* Keep preflight examples useful without making their display path a new
 * traversal constraint. A deeply nested fd-anchored payload can exceed
 * PATH_MAX as a string; in that case retain its leaf as a bounded hint. */
static void metadata_child_path(const char *parent, const char *leaf,
                                char out[PATH_MAX])
{
    if (parent == NULL || parent[0] == '\0')
    {
        (void)snprintf(out, PATH_MAX, "%s", leaf);
        return;
    }

    int n = snprintf(out, PATH_MAX, "%s/%s", parent, leaf);
    if (n >= 0 && n < PATH_MAX)
        return;
    (void)snprintf(out, PATH_MAX, ".../%s", leaf);
}

// The same recursive dispatcher serves mutation-free validation and the
// actual restore. A negative destination parent means the corresponding
// destination subtree does not exist during validation.
static int restore_entry_at(const CloneContext *ctx, RestorePass pass,
                            int source_parent_fd, const char *source_leaf,
                            int dest_parent_fd, const char *dest_leaf,
                            const char *logical_path,
                            MetadataSnapshots *snapshots,
                            MetadataProfiles *profiles,
                            int metadata_anchor_fd)
{
    int source_is_root = source_leaf[0] == '\0';
    int dest_is_root = dest_leaf[0] == '\0';

    struct stat source_st;
    int source_object_fd = open_source_object(source_parent_fd, source_leaf,
                                               &source_st);
    if (source_object_fd < 0)
        return -1;

    struct stat dest_st;
    int dest_exists;
    if (destination_status(dest_parent_fd, dest_leaf, &dest_st,
                           &dest_exists) != 0)
    {
        close(source_object_fd);
        return -1;
    }
    if (dest_exists && S_ISLNK(dest_st.st_mode))
    {
        close(source_object_fd);
        return -1;
    }

    struct stat desired_st = source_st;
    if (pass == RESTORE_VALIDATE)
    {
        if (metadata_snapshot_record(snapshots, &source_st) != 0)
        {
            close(source_object_fd);
            return -1;
        }
        // One profile anchor governs the whole restore root.  It is the
        // actual destination root when that directory exists, otherwise the
        // nearest existing parent chosen before the walk began.  Descending
        // into payload directories must not turn each child directory into a
        // new probe domain: ACLs and access policy may differ between roots,
        // but the plan deliberately bounds profiles by restore roots.
        int profile_failed = profiles != NULL && metadata_anchor_fd < 0;
        if (!profile_failed && profiles != NULL &&
            !S_ISSOCK(source_st.st_mode) &&
            !S_ISCHR(source_st.st_mode) &&
            !S_ISBLK(source_st.st_mode) &&
            metadata_profiles_add(profiles, metadata_anchor_fd, &source_st,
                                  dest_exists ? &dest_st : NULL,
                                  logical_path) != 0)
            profile_failed = 1;
        if (profile_failed)
        {
            close(source_object_fd);
            return -1;
        }
    }
    else
    {
        const MetadataSnapshot *snapshot = metadata_snapshot_find(snapshots,
                                                                   &source_st);
        if (snapshot == NULL || !metadata_snapshot_matches(snapshot, &source_st) ||
            metadata_snapshot_to_stat(snapshot, &desired_st) != 0)
        {
            close(source_object_fd);
            return -1;
        }
    }

    if (S_ISLNK(source_st.st_mode))
    {
        if (source_is_root || dest_is_root || dest_exists)
        {
            close(source_object_fd);
            return -1;
        }

        char target[PATH_MAX];
        ssize_t len = readlinkat(source_parent_fd, source_leaf,
                                 target, sizeof(target) - 1);
        if (len < 0 || (size_t)len == sizeof(target) - 1)
        {
            close(source_object_fd);
            return -1;
        }
        struct stat after;
        if (fstatat(source_parent_fd, source_leaf, &after,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !metadata_symlink_unchanged(&desired_st, &after))
        {
            close(source_object_fd);
            return -1;
        }
        close(source_object_fd);
        if (pass == RESTORE_VALIDATE)
            return 0;

        target[len] = '\0';
        if (symlinkat(target, dest_parent_fd, dest_leaf) != 0)
        {
            return -1;
        }
        return metadata_apply_symlink_at(dest_parent_fd, dest_leaf, &desired_st,
                                         metadata_policy_from_context(ctx));
    }

    if (S_ISREG(source_st.st_mode))
    {
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISREG(dest_st.st_mode)))
        {
            close(source_object_fd);
            return -1;
        }

        struct stat opened_source_st;
        int src_fd = open_source_regular(source_parent_fd, source_leaf,
                                         &source_st, &opened_source_st);
        close(source_object_fd);
        if (src_fd < 0 || !metadata_source_unchanged(&desired_st,
                                                      &opened_source_st))
        {
            if (src_fd >= 0)
                close(src_fd);
            return -1;
        }
        if (pass == RESTORE_VALIDATE)
        {
            return close(src_fd) == 0 ? 0 : -1;
        }

        struct stat opened_dest_st;
        int dest_created;
        int dst_fd = open_destination_regular(dest_parent_fd, dest_leaf,
                                               desired_st.st_mode & 07777,
                                               &opened_dest_st, &dest_created);
        if (dst_fd < 0)
        {
            close(src_fd);
            return -1;
        }
        MetadataTimestampPolicy policy = metadata_policy_from_context(ctx);
        int content_skip = !dest_created &&
            opened_dest_st.st_size == desired_st.st_size &&
            opened_dest_st.st_mtim.tv_sec == desired_st.st_mtim.tv_sec &&
            policy.nsec_exact &&
            opened_dest_st.st_mtim.tv_nsec == desired_st.st_mtim.tv_nsec;
        if (content_skip)
        {
            int failed = metadata_apply_fd(dst_fd, &desired_st, policy) != 0;
            struct stat after;
            if (!failed && (fstat(src_fd, &after) != 0 ||
                            !metadata_source_unchanged(&desired_st, &after)))
                failed = 1;
            if (close(src_fd) != 0)
                failed = 1;
            if (close(dst_fd) != 0)
                failed = 1;
            return failed ? -1 : 0;
        }
        if (ftruncate(dst_fd, 0) != 0)
        {
            close(src_fd);
            close(dst_fd);
            return -1;
        }

        char buffer[8192];
        int failed = 0;
        for (;;)
        {
            ssize_t bytes_read = read(src_fd, buffer, sizeof(buffer));
            if (bytes_read == 0)
                break;
            if (bytes_read < 0)
            {
                failed = 1;
                break;
            }

            ssize_t written = 0;
            while (written < bytes_read)
            {
                ssize_t res = write(dst_fd, buffer + written, bytes_read - written);
                if (res <= 0)
                {
                    failed = 1;
                    break;
                }
                written += res;
            }
            if (failed)
                break;
        }

        if (!failed)
        {
            struct stat after;
            if (fstat(src_fd, &after) != 0 ||
                !metadata_source_unchanged(&desired_st, &after))
                failed = 1;
        }
        if (!failed && metadata_apply_fd(dst_fd, &desired_st, policy) != 0)
            failed = 1;

        if (close(src_fd) != 0)
            failed = 1;
        if (close(dst_fd) != 0)
            failed = 1;
        return failed ? -1 : 0;
    }

    if (S_ISDIR(source_st.st_mode))
    {
        if (dest_exists && !S_ISDIR(dest_st.st_mode))
        {
            close(source_object_fd);
            return -1;
        }

        struct stat opened_source_st;
        int source_dir_fd = open_source_directory(source_object_fd, &source_st,
                                                  &opened_source_st);
        close(source_object_fd);
        if (source_dir_fd < 0 ||
            !metadata_source_unchanged(&desired_st, &opened_source_st))
        {
            if (source_dir_fd >= 0)
                close(source_dir_fd);
            return -1;
        }

        int dest_dir_fd = open_destination_directory(pass, dest_parent_fd,
                                                     dest_leaf);
        if (dest_dir_fd == -1)
        {
            close(source_dir_fd);
            return -1;
        }
        if (dest_dir_fd == -2)
            dest_dir_fd = -1;

        int scan_fd = fcntl(source_dir_fd, F_DUPFD_CLOEXEC, 0);
        DIR *dirp = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (dirp == NULL)
        {
            if (scan_fd >= 0)
                close(scan_fd);
            close(source_dir_fd);
            if (dest_dir_fd >= 0)
                close(dest_dir_fd);
            return -1;
        }

        int failed = 0;
        for (;;)
        {
            errno = 0;
            struct dirent *entry = readdir(dirp);
            if (entry == NULL)
            {
                if (errno != 0)
                    failed = 1;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            char child_logical_path[PATH_MAX];
            metadata_child_path(logical_path, entry->d_name,
                                child_logical_path);
            if (restore_entry_at(ctx, pass, source_dir_fd, entry->d_name,
                                 dest_dir_fd, entry->d_name,
                                 child_logical_path, snapshots, profiles,
                                 metadata_anchor_fd) != 0)
            {
                failed = 1;
                break;
            }
        }
        if (closedir(dirp) != 0)
            failed = 1;

        if (!failed && pass == RESTORE_APPLY)
        {
            struct stat after;
            if (fstat(source_dir_fd, &after) != 0 ||
                !metadata_source_unchanged(&desired_st, &after))
                failed = 1;
            if (!failed && metadata_apply_fd(dest_dir_fd, &desired_st,
                                             metadata_policy_from_context(ctx)) != 0)
                failed = 1;
        }

        close(source_dir_fd);
        if (dest_dir_fd >= 0)
            close(dest_dir_fd);
        return failed ? -1 : 0;
    }

    if (S_ISFIFO(source_st.st_mode))
    {
        if (source_is_root || dest_is_root ||
            (dest_exists && !S_ISFIFO(dest_st.st_mode)))
        {
            close(source_object_fd);
            return -1;
        }
        close(source_object_fd);

        if (pass == RESTORE_VALIDATE)
            return 0;

        struct stat opened_dest_st;
        int dest_fd = open_destination_fifo(dest_parent_fd, dest_leaf,
                                            desired_st.st_mode & 07777,
                                            &opened_dest_st);
        if (dest_fd < 0)
            return -1;
        int failed = metadata_apply_fd(dest_fd, &desired_st,
                                       metadata_policy_from_context(ctx)) != 0;
        if (close(dest_fd) != 0)
            failed = 1;
        return failed ? -1 : 0;
    }

    if (S_ISSOCK(source_st.st_mode))
    {
        close(source_object_fd);
        if (pass == RESTORE_APPLY)
            printf("  Warning: skipping socket (runtime-only)%s%s\n",
                   source_leaf[0] ? ": " : "", source_leaf);
        return 0;
    }
    if (S_ISCHR(source_st.st_mode) || S_ISBLK(source_st.st_mode))
    {
        close(source_object_fd);
        if (pass == RESTORE_APPLY)
            printf("  Warning: skipping %s device node%s%s\n",
                   S_ISCHR(source_st.st_mode) ? "character" : "block",
                   source_leaf[0] ? ": " : "", source_leaf);
        return 0;
    }

    close(source_object_fd);
    return -1;
}

static int restore_arguments_valid(const CloneContext *ctx,
                                   int source_root_fd, const char *source_rel,
                                   int destination_root_fd, const char *destination_rel)
{
    if (ctx == NULL || ctx->operation != CLONE_RESTORE || ctx->representation != CLONE_NATIVE_TREE)
        return 0;
    if (source_root_fd < 0 || destination_root_fd < 0 ||
        source_rel == NULL || destination_rel == NULL)
        return 0;
    if (!fd_is_directory(source_root_fd) || !fd_is_directory(destination_root_fd))
        return 0;
    if (source_rel[0] != '\0' && !relative_path_is_safe(source_rel))
        return 0;
    if (destination_rel[0] != '\0' && !relative_path_is_safe(destination_rel))
        return 0;
    return 1;
}

RestoreSourceStatus restore_native_source_status_at(int source_root_fd,
                                                     const char *source_rel)
{
    if (source_root_fd < 0 || source_rel == NULL ||
        !fd_is_directory(source_root_fd))
        return RESTORE_SOURCE_ERROR;
    if (source_rel[0] != '\0' && !relative_path_is_safe(source_rel))
        return RESTORE_SOURCE_ERROR;

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult result =
        resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf));
    if (result == RESTORE_RESOLVE_MISSING)
        return RESTORE_SOURCE_MISSING;
    if (result != RESTORE_RESOLVE_OK)
        return RESTORE_SOURCE_ERROR;

    struct stat st;
    int object_fd = open_source_object(source_parent_fd, source_leaf, &st);
    int saved_errno = errno;
    close(source_parent_fd);
    if (object_fd >= 0)
    {
        close(object_fd);
        return RESTORE_SOURCE_PRESENT;
    }
    return saved_errno == ENOENT
        ? RESTORE_SOURCE_MISSING
        : RESTORE_SOURCE_ERROR;
}

int restore_native_preflight_at(const CloneContext *ctx,
                                int source_root_fd, const char *source_rel,
                                int destination_root_fd, const char *destination_rel)
{
    if (!restore_arguments_valid(ctx, source_root_fd, source_rel,
                                 destination_root_fd, destination_rel))
        return -1;

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    if (resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf)) != RESTORE_RESOLVE_OK)
        return -1;

    int dest_parent_fd = -1;
    char dest_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult dest_result =
        resolve_parent(destination_root_fd, destination_rel, 0,
                       &dest_parent_fd, dest_leaf, sizeof(dest_leaf));
    if (dest_result == RESTORE_RESOLVE_ERROR)
    {
        close(source_parent_fd);
        return -1;
    }

    MetadataSnapshots snapshots;
    MetadataProfiles profiles;
    metadata_snapshots_init(&snapshots);
    metadata_profiles_init(&profiles);
    int metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (metadata_anchor_fd < 0)
    {
        close(source_parent_fd);
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        metadata_snapshots_free(&snapshots);
        metadata_profiles_free(&profiles);
        return -1;
    }
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, &profiles,
                              metadata_anchor_fd);
    close(metadata_anchor_fd);
    close(source_parent_fd);
    if (dest_parent_fd >= 0)
        close(dest_parent_fd);
    metadata_snapshots_free(&snapshots);
    metadata_profiles_free(&profiles);
    return rc;
}

int restore_native_metadata_inventory_at(const CloneContext *ctx,
                                          int source_root_fd,
                                          const char *source_rel,
                                          int destination_root_fd,
                                          const char *destination_rel,
                                          MetadataProfiles *profiles)
{
    if (profiles == NULL || !restore_arguments_valid(ctx, source_root_fd,
                                                     source_rel,
                                                     destination_root_fd,
                                                     destination_rel))
        return -1;

    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    if (resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf)) != RESTORE_RESOLVE_OK)
        return -1;

    int dest_parent_fd = -1;
    char dest_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult dest_result =
        resolve_parent(destination_root_fd, destination_rel, 0,
                       &dest_parent_fd, dest_leaf, sizeof(dest_leaf));
    if (dest_result == RESTORE_RESOLVE_ERROR)
    {
        close(source_parent_fd);
        return -1;
    }

    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);
    int metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (metadata_anchor_fd < 0)
    {
        close(source_parent_fd);
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        metadata_snapshots_free(&snapshots);
        return -1;
    }
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, profiles,
                              metadata_anchor_fd);
    close(metadata_anchor_fd);
    close(source_parent_fd);
    if (dest_parent_fd >= 0)
        close(dest_parent_fd);
    metadata_snapshots_free(&snapshots);
    return rc;
}

int restore_native_at(const CloneContext *ctx,
                      int source_root_fd, const char *source_rel,
                      int destination_root_fd, const char *destination_rel)
{
    int source_parent_fd = -1;
    char source_leaf[RESTORE_LEAF_MAX];
    if (!restore_arguments_valid(ctx, source_root_fd, source_rel,
                                 destination_root_fd, destination_rel) ||
        resolve_parent(source_root_fd, source_rel, 0, &source_parent_fd,
                       source_leaf, sizeof(source_leaf)) != RESTORE_RESOLVE_OK)
        return -1;

    int dest_parent_fd = -1;
    char dest_leaf[RESTORE_LEAF_MAX];
    RestoreResolveResult dest_result =
        resolve_parent(destination_root_fd, destination_rel, 0,
                       &dest_parent_fd, dest_leaf,
                       sizeof(dest_leaf));
    if (dest_result == RESTORE_RESOLVE_ERROR)
    {
        close(source_parent_fd);
        return -1;
    }

    MetadataSnapshots snapshots;
    MetadataProfiles profiles;
    metadata_snapshots_init(&snapshots);
    metadata_profiles_init(&profiles);
    int metadata_anchor_fd = destination_metadata_anchor(destination_root_fd,
                                                          destination_rel);
    if (metadata_anchor_fd < 0)
    {
        close(source_parent_fd);
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        metadata_snapshots_free(&snapshots);
        metadata_profiles_free(&profiles);
        return -1;
    }
    int rc = restore_entry_at(ctx, RESTORE_VALIDATE, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, &profiles,
                              metadata_anchor_fd);
    close(metadata_anchor_fd);
    if (rc == 0 && !ctx->metadata_preflight_done &&
        metadata_profiles_probe(&profiles,
                                metadata_policy_from_context(ctx)) != 0)
        rc = -1;

    if (rc == 0)
    {
        if (dest_parent_fd >= 0)
            close(dest_parent_fd);
        dest_parent_fd = -1;
        dest_result = resolve_parent(destination_root_fd, destination_rel, 1,
                                     &dest_parent_fd, dest_leaf,
                                     sizeof(dest_leaf));
        if (dest_result != RESTORE_RESOLVE_OK)
            rc = -1;
    }
    if (rc == 0)
        rc = restore_entry_at(ctx, RESTORE_APPLY, source_parent_fd,
                              source_leaf, dest_parent_fd, dest_leaf,
                              source_rel, &snapshots, NULL,
                              destination_root_fd);
    close(source_parent_fd);
    if (dest_parent_fd >= 0)
        close(dest_parent_fd);
    metadata_snapshots_free(&snapshots);
    metadata_profiles_free(&profiles);
    return rc;
}

int get_dir_size(const char *path, off_t *size)
{
    struct stat st;
    if (lstat(path, &st) != 0)
    {
        return -1;
    }

    // If it's a symlink, we don't follow it, so we just add the size of the link itself
    if (S_ISLNK(st.st_mode))
    {        
        *size += st.st_size;
        return 0;
    }

    // If it's a regular file, add its size to the total
    if (S_ISREG(st.st_mode))
    {
        *size += st.st_size;
        return 0;
    }

    // FIFOs, sockets, and device nodes carry no payload bytes. Contribute nothing
    // and stay silent: measurement feeds the report, which must not be chatty.
    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode) ||
        S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
    {
        return 0;
    }

    // If it's a directory, recursively calculate the size of its contents
    if (S_ISDIR(st.st_mode))
    {
        *size += st.st_size; // add the size of the directory itself

        DIR *dir = opendir(path);
        if (dir == NULL)
        {
            return -1;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            char new_path[PATH_MAX];
            if (path_join(new_path, sizeof(new_path), path, entry->d_name) != 0)
            {
                closedir(dir);
                return -1;
            }

            if (get_dir_size(new_path, size) != 0)
            {
                closedir(dir);
                return -1;
            }
        }

        closedir(dir);
        return 0;
    }

    return -1; // unknown file type (unreachable on Linux); refuse defensively
}

int run_command(char *const argv[])
{
    pid_t pid = fork();

    if (pid == -1)
    {
        return -1; // fork failed
    }
    else if (pid == 0)
    {
        // Child process
        execvp(argv[0], argv);
        
        // If execvp returns, it means it failed
        perror("execvp");
        _exit(1); // _exit() is used to exit immediately since we're in a child process. 
                  // exit() could've caused issues because it might flush stdio buffers that are shared with the parent process.
    }
    else 
    {
        // Parent process
        int status;

        // Wait for the child process to finish so it won't become a zombie process
        if (waitpid(pid, &status, 0) == -1)
        {
            return -1;
        }

        if(WIFEXITED(status))
        {
            return WEXITSTATUS(status); // return the exit status of the child process
        }
    }
    return -1; // should not reach here
}

int run_command_capture(char *const argv[], char *output, size_t output_size)
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        return -1; // pipe creation failed
    }

    pid_t pid = fork();
    if (pid == -1)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1; // fork failed
    }
    else if (pid == 0)
    {
        // Child process
        close(pipefd[0]); // Close the read end of the pipe
        
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to the write end of the pipe
        close(pipefd[1]); // Close the original write end of the pipe
        
        execvp(argv[0], argv); // Execute the command

        // If execvp returns, it means it failed
        perror("execvp");
        _exit(1); // Exit immediately since we're in a child process
    }
    else
    {
        // Parent process
        close(pipefd[1]); // Close the write end of the pipe

        size_t total = 0;
        ssize_t bytes_read;
        while ((bytes_read = read(pipefd[0], output + total, output_size - total - 1)) > 0)
        {
            total += bytes_read;
        }
        output[total] = '\0'; // Null-terminate the output string

        close(pipefd[0]); // Close the read end of the pipe
        int status;
        waitpid(pid, &status, 0); // Wait for the child process to finish
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status); // Return the exit status of the child process
        }
    }
    return -1; // should not reach here
}
