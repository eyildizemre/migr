#ifndef FILEOPS_H
#define FILEOPS_H

#include <sys/types.h>

/**
 * @brief How a clone is oriented and represented.
 *
 * `operation` is the direction the tree flows — a backup captures the source, a restore
 * writes it back. `representation` is whether metadata a destination cannot hold natively
 * is instead carried in a sidecar; every clone is a CLONE_NATIVE_TREE for now,
 * CLONE_PORTABLE_SIDECAR is reserved for later phases.
 */
typedef enum { CLONE_BACKUP, CLONE_RESTORE } CloneOperation;
typedef enum { CLONE_NATIVE_TREE, CLONE_PORTABLE_SIDECAR } CloneRepresentation;

typedef struct {
    CloneOperation operation;
    CloneRepresentation representation;
} CloneContext;

/**
 * @brief Public entries to the recursive clone engine.
 *
 * `backup_capture` captures a source tree into a backup; `restore_native` writes a tree
 * back from a backup. Each enforces its half of the orchestration contract and then
 * delegates to one shared native core: regular files, directories, symlinks and FIFOs are
 * reproduced; Unix sockets and device nodes are skipped with a warning; permissions and
 * access/modification times are preserved; an already-matching regular file is skipped so
 * an interrupted run resumes. They are separate names so the two orchestrations can later
 * diverge (e.g. a backup writing a sidecar) without reworking call sites.
 *
 * The context is validated, not merely carried: a NULL ctx, a mismatched operation, or an
 * unimplemented representation is refused rather than run, so a dispatch mistake fails
 * closed instead of writing a native tree to a destination that needed a sidecar. Only
 * CLONE_NATIVE_TREE is implemented currently; CLONE_PORTABLE_SIDECAR is refused.
 *
 * @param ctx  Clone orientation and representation; must not be NULL.
 * @param src  Path to the source file, directory, or symlink.
 * @param dest Destination path to create.
 * @return 0 on success, -1 on error or a rejected context.
 */
int backup_capture(const CloneContext *ctx, const char *src, const char *dest);
int restore_native(const CloneContext *ctx, const char *src, const char *dest);

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
