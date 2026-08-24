#ifndef UTILS_H
#define UTILS_H

#include <stddef.h> /* size_t */
#include <sys/types.h> /* off_t */

extern int verbose; /**< Non-zero when -v is passed; enables per-file progress output. */
extern int dry_run; /**< Non-zero when -n/--dry-run is passed; suppresses all writes. */

/**
 * @brief Formats a byte count with the same units used by report output.
 */
void format_size(off_t bytes, char *buf, size_t len);

/**
 * @brief Safely join a directory and name into "dir/name".
 *
 * Writes "dir/name" into buf and detects snprintf truncation. Acting on a
 * truncated path is dangerous: it can read from or clobber the wrong file,
 * so callers must treat a -1 return as an error and never touch the
 * filesystem with buf in that case.
 *
 * @return 0 on success, -1 if the result was truncated or on encoding error.
 */
int path_join(char *buf, size_t size, const char *dir, const char *name);

/**
 * @brief Like path_join but uses only the first name_len bytes of name.
 *
 * For joining a path span that is not NUL-terminated at the boundary, such
 * as a parent-directory prefix taken up to (but not including) a '/'.
 */
int path_join_n(char *buf, size_t size, const char *dir,
                const char *name, size_t name_len);

/**
 * @brief Raises the process's open-file soft limit to its hard limit.
 *
 * Best-effort and silent: native hardlink capture holds one fd per unique
 * multiply-linked source inode open for the whole backup (src/fileops.c,
 * native_inode_map_insert()), and a shell's inherited soft nofile limit is
 * commonly far below what the same process's hard limit already permits --
 * 1024 is the classic Linux default, while a modern systemd-managed
 * session's actual ceiling is typically in the hundreds of thousands. This
 * raises the soft limit to whatever the hard limit already allows, without
 * requesting elevated privilege (POSIX permits any process to move its own
 * soft limit anywhere up to its current hard limit). If the hard limit itself
 * is low, or the call fails for any reason, this silently leaves the limit as
 * it was -- never fatal, never printed.
 */
void raise_fd_limit(void);

/**
 * @brief Prints usage information for all commands and options to stdout.
 */
void print_help(void);

/**
 * @brief Prompts the user with a yes/no question and reads their response from stdin.
 *
 * Displays message followed by " [y/N]: " and reads one line from stdin.
 * EOF is treated as a negative response.
 *
 * @param message The prompt string displayed before the [y/N] indicator.
 * @return 1 if the response starts with 'y' or 'Y', 0 otherwise.
 */
int confirm_action(const char *message);

#endif
