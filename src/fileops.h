#ifndef FILEOPS_H
#define FILEOPS_H

#include <sys/types.h>

/**
 * @brief Recursively clones a file or directory from src to dest.
 *
 * Handles regular files, directories, symlinks, and FIFOs. Unix sockets and
 * device nodes are skipped with a warning — a socket is a runtime endpoint and
 * a device node needs root to recreate, so neither can be copied meaningfully.
 * Preserves permissions, access time, and modification time via
 * chmod and utimensat. Regular files are skipped if dest already exists with
 * a matching size and modification timestamp, enabling interrupted backups
 * to resume without re-copying.
 *
 * @param src  Path to the source file, directory, or symlink.
 * @param dest Destination path to create.
 * @return 0 on success, -1 on error.
 */
int clone_recursive(const char *src, const char *dest);

/**
 * @brief Accumulates the total byte size of a file tree into *size.
 *
 * Uses lstat so symlinks are counted by their own size rather than the
 * target's. FIFOs, sockets, and device nodes contribute no payload bytes. The
 * caller must initialize *size before the first call; the function adds to the
 * existing value on each recursive step.
 *
 * @param path Path to the file, directory, or symlink to measure.
 * @param size Pointer to an off_t accumulator; each entry's size is added to it.
 * @return 0 on success, -1 on filesystem errors.
 */
int get_dir_size(const char *path, off_t *size);

/**
 * @brief Executes a command via fork/execvp without invoking a shell.
 *
 * Forks a child process, executes argv[0] with the given argument vector,
 * and blocks until the child exits. Uses _exit in the child to avoid
 * flushing shared stdio buffers.
 *
 * @param argv NULL-terminated argument vector; argv[0] is the program to run.
 * @return The child's exit status on success, -1 if fork or waitpid fails.
 */
int run_command(char *const argv[]);

/**
 * @brief Executes a command and captures its stdout into a caller-supplied buffer.
 *
 * Uses fork/execvp with an anonymous pipe redirecting the child's stdout.
 * The output buffer is always null-terminated. Output is silently truncated
 * if it exceeds output_size - 1 bytes.
 *
 * @param argv        NULL-terminated argument vector; argv[0] is the program to run.
 * @param output      Buffer to receive the captured stdout.
 * @param output_size Total size of the output buffer in bytes.
 * @return The child's exit status on success, -1 if pipe, fork, or waitpid fails.
 */
int run_command_capture(char *const argv[], char *output, size_t output_size);

#endif
