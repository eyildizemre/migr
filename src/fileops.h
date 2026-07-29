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
 * @brief Captures a source tree into an open destination directory.
 *
 * Regular files, directories, symlinks and FIFOs are reproduced; Unix sockets and
 * device nodes are skipped with a warning; permissions and access/modification times
 * are preserved.
 *
 * The source is addressed by pathname, exactly as the caller named it. The
 * destination never is: destination_root_fd is a directory fd the caller opens once
 * and continues to own, and every step below it uses openat/mkdirat/fstatat with
 * O_NOFOLLOW. No intermediate or final symlink inside the destination is ever
 * followed, so payload cannot be redirected outside the container it belongs to
 * (docs/DECISIONS.md D15) -- including when writing into a container a previous,
 * interrupted run already populated.
 *
 * Resuming is address-by-address, and only where the existing object proves the work
 * was already done: a regular file whose size and mtime match is skipped, a symlink
 * with the identical target is accepted, and an existing directory or FIFO is
 * accepted when it is genuinely that type. Every other collision -- a differing
 * symlink target, or any type mismatch -- is an error, never an overwrite.
 *
 * The context is validated, not merely carried: a NULL ctx, a mismatched operation, or
 * an unimplemented representation is refused rather than run, so a dispatch mistake
 * fails closed instead of writing a native tree to a destination that needed a
 * sidecar. Only CLONE_NATIVE_TREE is implemented currently; CLONE_PORTABLE_SIDECAR is
 * refused.
 *
 * @param ctx                 Clone orientation and representation; must not be NULL.
 * @param source_path         Path to the source file, directory, or symlink.
 * @param destination_root_fd Open directory fd anchoring destination_leaf; never closed here.
 * @param destination_leaf    Exactly one path component to create beneath it; a name
 *                            containing '/', or "." or "..", is refused.
 * @return 0 on success, -1 on error, a rejected context, or an unsafe leaf.
 */
int backup_capture_at(const CloneContext *ctx, const char *source_path,
                      int destination_root_fd, const char *destination_leaf);

/**
 * @brief Result of checking a restore source beneath a directory fd.
 */
typedef enum {
    RESTORE_SOURCE_ERROR = -1,
    RESTORE_SOURCE_MISSING = 0,
    RESTORE_SOURCE_PRESENT = 1
} RestoreSourceStatus;

/**
 * @brief Checks whether a source object exists without following symlinks.
 *
 * Intermediate components are resolved beneath source_root_fd with O_NOFOLLOW.
 * A dangling symlink at the final component is therefore PRESENT, while a
 * missing component is MISSING. Unsafe relative addresses and operational
 * failures are ERROR.
 */
RestoreSourceStatus restore_native_source_status_at(int source_root_fd,
                                                     const char *source_rel);

/**
 * @brief Validates an FD-anchored native restore without mutating the destination.
 *
 * Uses the same recursive walker and safety rules as restore_native_at(). It
 * checks lexical paths, source traversal, destination traversal and existing
 * destination object types, but does not promise that later writes cannot fail
 * for operational reasons such as permissions or free space.
 */
int restore_native_preflight_at(const CloneContext *ctx,
                                int source_root_fd, const char *source_rel,
                                int destination_root_fd, const char *destination_rel);

/**
 * @brief FD-anchored native restore core (docs/DECISIONS.md D15 and D16).
 *
 * source_root_fd and destination_root_fd are directory fds the caller opens
 * exactly once (its own trust boundary), and source_rel/destination_rel are
 * relative addresses resolved underneath them component-by-component -- never
 * by string concatenation. Both the backup payload and the destination are
 * treated as untrusted: neither an intermediate symlink nor a symlink at the
 * final address is followed or silently replaced.
 *
 * source_rel must name an existing entry (no intermediate component is ever
 * created reading the source). destination_rel's intermediate components are
 * created as plain directories if missing; an existing intermediate that is
 * not a genuine, non-symlink directory is refused, not silently accepted.
 *
 * An empty string ("") is a valid relative address on either side, meaning
 * "the root object itself" (docs/DECISIONS.md D16: an empty HOME_RELATIVE
 * restore_path legitimately addresses $HOME itself) -- this is the one case
 * with zero path components, distinct from a rejected empty *interior*
 * component. Anything else that is lexically invalid (a leading '/', any
 * ".." component, an empty interior/trailing component, or a bare ".")  is
 * refused before any mutation is attempted; nothing is normalized into some
 * other address.
 *
 * This function never closes source_root_fd or destination_root_fd; the
 * caller owns them for as long as it needs them (e.g. across several calls
 * restoring several top-level items from the same backup into the same
 * destination). Every fd this function itself opens while recursing is
 * closed before returning.
 *
 * Before mutating the destination, this function runs the same recursive
 * checks exposed by restore_native_preflight_at().
 *
 * @param ctx                Clone orientation; must be CLONE_RESTORE +
 *                            CLONE_NATIVE_TREE.
 * @param source_root_fd      Open directory fd anchoring source_rel.
 * @param source_rel          Relative address of the source object, or "".
 * @param destination_root_fd Open directory fd anchoring destination_rel.
 * @param destination_rel     Relative address of the destination object, or "".
 * @return 0 on success, -1 on error, a rejected context, or a lexically
 *         invalid or unsafe relative address.
 */
int restore_native_at(const CloneContext *ctx,
                       int source_root_fd, const char *source_rel,
                       int destination_root_fd, const char *destination_rel);

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
