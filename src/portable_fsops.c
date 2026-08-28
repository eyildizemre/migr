#define _GNU_SOURCE

#include "portable_fsops_internal.h"
#include "portable.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int append_logical(char *destination, size_t destination_size,
                          const char *parent, const char *name)
{
    if (destination == NULL || parent == NULL || !safe_component(name))
        return -1;
    size_t parent_length = bounded_strlen(parent, destination_size);
    size_t name_length = strlen(name);
    if (parent_length >= destination_size ||
        name_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0) {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, name, name_length + 1U);
    return 0;
}

int append_physical(char *destination, size_t destination_size,
                    const char *parent, const char *encoded_leaf)
{
    if (destination == NULL || parent == NULL || encoded_leaf == NULL)
        return -1;
    size_t parent_length = bounded_strlen(parent, destination_size);
    size_t leaf_length = strlen(encoded_leaf);
    if (parent_length >= destination_size ||
        leaf_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0) {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, encoded_leaf, leaf_length + 1U);
    return 0;
}

int open_child_directory(int parent_fd, const char *name)
{
    return openat(parent_fd, name,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int remove_leaf(int parent_fd, const char *name);

int remove_directory_tree(int parent_fd, const char *name)
{
    int directory_fd = openat(parent_fd, name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        close(directory_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (remove_leaf(directory_fd, entry->d_name) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    if (failed)
        return -1;
    return unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 ? 0 : -1;
}

int remove_leaf(int parent_fd, const char *name)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (S_ISDIR(st.st_mode))
        return remove_directory_tree(parent_fd, name);
    return unlinkat(parent_fd, name, 0) == 0 ? 0 : -1;
}

int portable_open_relative_parent(int base_fd, const char *relative,
                                  int *parent_out, char *leaf,
                                  size_t leaf_size)
{
    if (base_fd < 0 || relative == NULL || parent_out == NULL ||
        leaf == NULL || leaf_size == 0 ||
        (relative[0] != '\0' && !safe_relative_path(relative)))
    {
        errno = EINVAL;
        return -1;
    }

    int current = dup_cloexec(base_fd);
    if (current < 0)
        return -1;
    if (relative[0] == '\0')
    {
        leaf[0] = '\0';
        *parent_out = current;
        return 0;
    }

    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);

    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL) {
            if (copy_text(leaf, leaf_size, cursor) == 0) {
                *parent_out = current;
                return 0;
            }
            int saved = EINVAL;
            (void)close(current);
            errno = saved;
            return -1;
        }

        struct stat st;
        if (fstatat(current, cursor, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                int saved = ENOTDIR;
                (void)close(current);
                errno = saved;
                return -1;
            }
        } else if (errno == ENOENT) {
            if (mkdirat(current, cursor, 0700) != 0 && errno != EEXIST) {
                int saved = errno;
                (void)close(current);
                errno = saved;
                return -1;
            }
            if (fstatat(current, cursor, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISDIR(st.st_mode)) {
                int saved = ENOTDIR;
                (void)close(current);
                errno = saved;
                return -1;
            }
        } else {
            int saved = errno;
            (void)close(current);
            errno = saved;
            return -1;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0) {
            int saved = errno;
            (void)close(current);
            errno = saved;
            return -1;
        }
        if (close(current) != 0) {
            int saved = errno;
            (void)close(next);
            errno = saved;
            return -1;
        }
        current = next;
        cursor = slash + 1;
    }
}

/* Opens an existing payload parent without creating any component. */
int open_existing_payload_parent(int data_fd, const char *relative,
                                        int *parent_out, char *leaf,
                                        size_t leaf_size)
{
    if (data_fd < 0 || parent_out == NULL || leaf == NULL ||
        !safe_relative_path(relative) || leaf_size == 0)
        return -1;

    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);
    int current = dup_cloexec(data_fd);
    if (current < 0)
        return -1;

    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL) {
            int result = copy_text(leaf, leaf_size, cursor);
            if (result == 0) {
                *parent_out = current;
                return 0;
            }
            close(current);
            return -1;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0) {
            int saved = errno;
            close(current);
            errno = saved;
            return -1;
        }
        close(current);
        current = next;
        cursor = slash + 1;
    }
}

int ensure_directory_leaf(int parent_fd, const char *leaf, int *out_fd)
{
    if (parent_fd < 0 || !safe_component(leaf) || out_fd == NULL)
        return -1;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISDIR(st.st_mode)) {
            *out_fd = open_child_directory(parent_fd, leaf);
            return *out_fd < 0 ? -1 : 0;
        }
        if (remove_leaf(parent_fd, leaf) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    if (mkdirat(parent_fd, leaf, 0700) != 0 && errno != EEXIST)
        return -1;
    *out_fd = open_child_directory(parent_fd, leaf);
    return *out_fd < 0 ? -1 : 0;
}

int ensure_regular_leaf(int parent_fd, const char *leaf, int *out_fd)
{
    if (parent_fd < 0 || !safe_component(leaf) || out_fd == NULL)
        return -1;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (remove_leaf(parent_fd, leaf) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    int fd = openat(parent_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK |
                        O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int saved = errno == 0 ? EIO : errno;
        close(fd);
        unlinkat(parent_fd, leaf, 0);
        errno = saved;
        return -1;
    }
    *out_fd = fd;
    return 0;
}
