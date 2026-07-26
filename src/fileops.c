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

static int preserve_metadata(const char *path, const struct stat *st)
{
    // Never chmod a symlink: chmod() follows the link and would change the target's
    // mode (for an absolute link, the real source file). Symlinks have no meaningful
    // permissions of their own on Linux, so there is nothing to preserve here.
    if (!S_ISLNK(st->st_mode))
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
        struct stat dest_st;
        if (lstat(dest, &dest_st) == 0 &&
            dest_st.st_size == st.st_size &&
            dest_st.st_mtim.tv_sec == st.st_mtim.tv_sec)
        {
            return 0; // already cloned, skip
        }

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
        if (dst == -1 && errno != EEXIST) // If the directory already exists, we can ignore the error
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
            snprintf(new_path, sizeof(new_path), "%s/%s", path, entry->d_name);

            if (get_dir_size(new_path, size) != 0)
            {
                closedir(dir);
                return -1;
            }
        }

        closedir(dir);
    }
    return 0;
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