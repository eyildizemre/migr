#ifndef UTILS_H
#define UTILS_H

#include <stddef.h> /* size_t */
#include <time.h> /* struct timespec */
#include <sys/types.h> /* off_t */

extern int verbose; /**< Non-zero when -v is passed; enables per-file progress output. */
extern int dry_run; /**< Non-zero when -n/--dry-run is passed; suppresses all writes. */
extern int color_enabled; /**< Non-zero when status colors are enabled for stdout. */

/** @brief Prints a complete error message, optionally in bold red. */
void print_error(const char *fmt, ...);

/**
 * @brief Reports that a source object could not be safely read with O_NOATIME.
 */
void print_source_safe_read_refusal(const char *label);

/** @brief Prints a complete warning message, optionally in bold yellow. */
void print_warning(const char *fmt, ...);

/** @brief Prints a complete success message, optionally in bold green. */
void print_success(const char *fmt, ...);

/**
 * @brief Formats an item count and verb with singular/plural agreement.
 */
void format_item_count_phrase(char *buf, size_t buf_size, size_t count,
                              const char *verb);

/**
 * @brief Formats a byte count with the same units used by report output.
 */
void format_size(off_t bytes, char *buf, size_t len);

/**
 * @brief Formats a non-negative duration as mm:ss or h:mm:ss.
 */
void format_duration(long seconds, char *buf, size_t len);

/**
 * @brief Returns non-negative elapsed seconds between two timestamps.
 *
 * The timestamps are expected to come from the same monotonic clock. A
 * timestamp that precedes start is treated as zero elapsed time.
 */
double timespec_elapsed_seconds(const struct timespec *start,
                                const struct timespec *end);

int dup_cloexec(int fd);
size_t relative_path_depth(const char *path);

/* Live backup progress is sampled at most twice per second in production. */
#define BACKUP_PROGRESS_THROTTLE_MS 500

/* Periodic mid-copy sync interval for live backups. */
#define BACKUP_SYNC_INTERVAL_BYTES (256 * 1024 * 1024)

/**
 * @brief Returns whether a progress callback may fire now.
 *
 * The caller must invoke this only when a callback is installed. An
 * unthrottled caller (the deterministic test seam) fires on every chunk.
 */
int backup_progress_should_fire(struct timespec *last_fired, int unthrottled);

/**
 * @brief Accumulates copied bytes and reports when a sync interval is due.
 *
 * An interval less than or equal to zero disables the check. When the
 * interval is reached, the accumulated counter is reset before returning 1.
 */
int backup_sync_due(off_t *bytes_since_sync, off_t chunk_size,
                    off_t interval);

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
