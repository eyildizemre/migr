#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <limits.h> // to use PATH_MAX

static int preserve_metadata(const char *path, const struct stat *st)
{
    chmod(path, st->st_mode);

    struct timespec times[2];
    times[0] = st->st_atim; // access time
    times[1] = st->st_mtim; // modification time
    utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW); // preserve times without following symlinks

    return 0;
}

// Recursively clones a file or directory from src to dest, preserving metadata and handling symlinks
int clone_recursive(const char *src, const char *dest) 
{
    struct stat st;
    
    if (lstat(src, &st)!= 0)
    {
        return -1;
    }

    // Check if the reference is a symlink
    if(S_ISLNK(st.st_mode))
    {
        char link_target[PATH_MAX]; // buffer for symlink target path
        ssize_t len = readlink(src, link_target, sizeof(link_target) - 1); // leave space for null terminator
        if (len == -1)
        {
            return -1;
        }
        link_target[len] = '\0'; // null terminator

        if (symlink(link_target, dest) != 0)
        {
            return -1;
        }

        preserve_metadata(dest, &st);
        return 0;
    }

    // Check if the reference is a normal file
    if(S_ISREG(st.st_mode))
    {
        int src_fd = open(src, O_RDONLY);
        if (src_fd == -1)
        {
            return -1;
        }

        int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
        if (dest_fd == -1)
        {
            close(src_fd);
            return -1;
        }

        char buffer[8192];
        ssize_t bytes_read;
        while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0)
        {
            ssize_t bytes_written = 0;
            while (bytes_written < bytes_read)
            {
                ssize_t res = write(dest_fd, buffer + bytes_written, bytes_read - bytes_written);
                if (res == -1)
                {
                    close(src_fd);
                    close(dest_fd);
                    return -1;
                }
                bytes_written += res;
            }
        }

        if (bytes_read == -1)
        {
            close(src_fd);
            close(dest_fd);
            return -1;
        }

        close(src_fd);
        close(dest_fd);
        preserve_metadata(dest, &st);
        return 0;
    }

    // Check if the reference is a directory
    if (S_ISDIR(st.st_mode))
    {

        int dst = mkdir(dest, st.st_mode);
        if (dst == -1)
        {
            return -1;
        }

        DIR *op = opendir(src);
        if (op == NULL)
        {
            return -1;
        }

        struct dirent *entry;
        while ((entry = readdir(op)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            char new_src[PATH_MAX];
            char new_dest[PATH_MAX];
            snprintf(new_src, sizeof(new_src), "%s/%s", src, entry->d_name);
            snprintf(new_dest, sizeof(new_dest), "%s/%s", dest, entry->d_name);

            if (clone_recursive(new_src, new_dest) != 0)
            {
                closedir(op);
                return -1;
            }
        }

        closedir(op);
        preserve_metadata(dest, &st);
        return 0;
    }

    return -1; // unsupported file type
}