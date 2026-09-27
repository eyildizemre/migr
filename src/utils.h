#ifndef UTILS_H
#define UTILS_H

#include <limits.h> /* PATH_MAX */
#include <pthread.h> /* pthread_mutex_t, pthread_t */
#include <stddef.h> /* size_t */
#include <time.h> /* struct timespec */
#include <sys/types.h> /* off_t */

extern int verbose; /**< Non-zero when -v is passed; enables per-file progress output. */
extern int dry_run; /**< Non-zero when -n/--dry-run is passed; suppresses all writes. */
extern int color_enabled; /**< Non-zero when status colors are enabled for stderr. */

/**
 * Exit statuses of every command, as in GNU tar (docs/DECISIONS.md D68).
 * backup(), backup_selection(), restore_with_options() and verify_backup()
 * return these directly.
 */
enum {
    MIGR_EXIT_OK = 0,      /**< Completed as asked. */
    MIGR_EXIT_CHANGED = 1, /**< Completed, but something changed or differs; the run says what. */
    MIGR_EXIT_FAILURE = 2  /**< Failed, refused, or was used wrongly. */
};

/**
 * @brief Resolves the HOME of the user whose data this invocation targets.
 *
 * Ordinary runs use HOME. When the process runs as root and SUDO_UID is
 * present, the invoking user's local passwd entry is resolved directly so
 * sudo cannot silently redirect the migration to root's home
 * (docs/DECISIONS.md D38).
 */
int resolve_target_home(char out[PATH_MAX]);

/**
 * @brief The user who ran migr through sudo, whom it acts for (D38).
 *
 * SUDO_UID, its primary gid, and its home come from /etc/passwd directly, so
 * static and dynamic builds use the same NSS-independent account lookup.
 *
 * @return 1 with the invoker's uid, gid, and home (home may be NULL) when
 *         root runs with SUDO_UID set; 0, outputs untouched, otherwise; -1
 *         when SUDO_UID does not resolve to a local account.
 */
int sudo_invoker(uid_t *uid, gid_t *gid, char home[PATH_MAX]);

#define ACCOUNT_NAME_MAX 256

/**
 * @brief Resolves uid's login name from the local passwd file without NSS,
 *        the way sudo_invoker() resolves an account (D38).
 *
 * Returns -1 when no single well-formed entry has that uid.
 */
int local_account_name(uid_t uid, char out[ACCOUNT_NAME_MAX]);

/**
 * @brief The login name of the user a run acts for, for naming only: the
 *        sudo invoker under sudo (SUDO_USER), otherwise USER or LOGNAME.
 *
 * Ownership is never decided by this name (docs/DECISIONS.md D71). Falls
 * back to "user" when no name is set.
 */
const char *invoker_name(void);

/**
 * @brief Prints "Backup taken <local YYYY-MM-DD HH:MM>" and a newline when a
 *        backup's manifest records when it was taken (docs/DECISIONS.md D72);
 *        prints nothing for 0.
 */
void print_backup_time(time_t taken);

/**
 * @brief Starts the run log of a backup or restore (docs/DECISIONS.md D79).
 *
 * From here on everything printed to stdout and stderr also goes to the
 * log, without colors and with a progress line only as last drawn; fds 1
 * and 2 stay the terminal. The log is held in memory until
 * run_log_attach() gives it a place. Its first line names the command.
 *
 * @return 0, or -1 when no log could be started; the run goes on without.
 */
int run_log_start(int argc, char *const argv[]);

/**
 * @brief Writes to the log only, for the full lists the terminal shows
 *        examples of. Does nothing when no log runs.
 */
void run_log_printf(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

/**
 * @brief Gives the log its place: <dir>/<prefix>-YYYY-MM-DD-HHMMSS.log below
 *        base_fd, with what was printed so far.
 *
 * Missing directories of dir are created 0700 and, with the log, owned by
 * uid:gid unless uid is -1. The newest 10 logs with that prefix are kept.
 * Only the first call of a run counts.
 *
 * @return 0, or -1 when it could not be created; the run goes on without.
 */
int run_log_attach(int base_fd, const char *dir, const char *prefix,
                   uid_t uid, gid_t gid);

/**
 * @brief Ends the log and puts the standard streams back.
 *
 * A log that is not kept is removed with the directories created for it,
 * so a run that leaves nothing to say leaves nothing behind.
 *
 * @return The kept log's path, or NULL.
 */
const char *run_log_finish(int keep);

#ifdef USER_CONTEXT_TEST_HOOKS
int resolve_target_home_for_test(const char *home_env,
                                 const char *sudo_uid_env,
                                 const char *passwd_path,
                                 int running_as_root,
                                 char out[PATH_MAX]);
int local_account_name_for_test(uid_t uid, const char *passwd_path,
                                char out[ACCOUNT_NAME_MAX]);
int resolve_sudo_identity_for_test(const char *sudo_uid_env,
                                   const char *passwd_path,
                                   uid_t *uid_out, gid_t *gid_out,
                                   char home_out[PATH_MAX]);
#endif

#define CRYPTO_POLICY_MAX 64
/**
 * @brief Reads the policy name from a crypto-policies config file such as
 *        /etc/crypto-policies/config (first non-comment token, e.g.
 *        "DEFAULT:SHA1"), relative to dir_fd (AT_FDCWD for an absolute
 *        path). Returns -1 when unreadable or not a policy name.
 */
int crypto_policy_read_at(int dir_fd, const char *path,
                          char out[CRYPTO_POLICY_MAX]);

/** @brief Prints a complete error message, optionally in bold red. */
void print_error(const char *fmt, ...);

/**
 * @brief Reports that a source object could not be safely read with O_NOATIME.
 */
void print_source_safe_read_refusal(const char *label);

/**
 * @brief Writes all of data to fd, retrying short writes and EINTR.
 * @return 0, or -1 with errno (EIO for a write that makes no progress).
 */
int write_all(int fd, const void *data, size_t length);

#define EXAMPLE_LIST_KEPT 8
#define EXAMPLE_TEXT_MAX (PATH_MAX + 512)

/* Counts items and keeps the text of the first EXAMPLE_LIST_KEPT, for a
 * summary that names a few and says how many more there were. Zero it to
 * start. */
typedef struct {
    size_t count;
    size_t kept;
    char text[EXAMPLE_LIST_KEPT][EXAMPLE_TEXT_MAX];
} ExampleList;

/* Counts one item and returns where to write its text (EXAMPLE_TEXT_MAX
 * bytes), or NULL once EXAMPLE_LIST_KEPT are kept. */
char *example_list_next(ExampleList *list);

/* Prints each kept text on its own line after indent, then how many more
 * there were. */
void example_list_print(const ExampleList *list, const char *indent);

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
 * @brief Clamps a progress line so carriage-return redraws stay on one row.
 *
 * The current stdout terminal width is used when available; otherwise an
 * 80-column fallback is used. One column is intentionally left unused so a
 * redraw never relies on terminal-specific last-column wrapping behavior.
 */
void progress_line_fit(char *line, size_t line_capacity);

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

/*
 * Grows an array so it can hold at least count + extra elements, doubling
 * from initial_capacity and refusing past max_capacity. Returns the
 * (possibly reallocated) array and updates *capacity, or NULL with errno
 * set on failure -- E2BIG when the request exceeds max_capacity or the
 * size computation would overflow, ENOMEM when the reallocation fails,
 * EINVAL on a bad argument. On failure *capacity and the caller's array
 * are left untouched. Any newly added tail is zeroed.
 */
void *array_reserve(void *items, size_t *capacity, size_t count,
                    size_t extra, size_t element_size,
                    size_t initial_capacity, size_t max_capacity);

/* Live backup progress is sampled at most twice per second in production. */
#define BACKUP_PROGRESS_THROTTLE_MS 500

/* A display-only ticker wakes four times per second, but only redraws after
 * three ordinary progress-throttle windows have passed without real I/O. */
#define PROGRESS_TICK_INTERVAL_MS 250
#define PROGRESS_STALL_MS 1500

typedef struct {
    off_t bytes;
    off_t speed_bytes;
    off_t free_bytes;
    int free_bytes_known;
    char path[PATH_MAX];
    struct timespec at;
} ProgressTickerSnapshot;

typedef void (*ProgressTickerRedraw)(const ProgressTickerSnapshot *snapshot,
                                     const struct timespec *now,
                                     void *context);

typedef struct {
    pthread_mutex_t lock;
    pthread_t thread;
    ProgressTickerSnapshot snapshot;
    ProgressTickerRedraw redraw_cb;
    void *redraw_context;
    int thread_error;
    int stop_requested;
    int has_snapshot;
    int initialized;
    int running;
} ProgressTicker;

/**
 * @brief Starts a display-only stall ticker.
 *
 * The ticker never reads copy-engine state. It redraws only from snapshots
 * supplied by progress_ticker_snapshot().
 */
int progress_ticker_start(ProgressTicker *ticker,
                          ProgressTickerRedraw redraw_cb,
                          void *redraw_context);

/**
 * @brief Replaces the ticker's last synchronized progress snapshot.
 */
int progress_ticker_snapshot(ProgressTicker *ticker, off_t bytes,
                             off_t speed_bytes, off_t free_bytes,
                             int free_bytes_known, const char *current_path,
                             const struct timespec *snapshot_at);

/**
 * @brief Stops and joins the ticker before its owner goes out of scope.
 */
int progress_ticker_stop(ProgressTicker *ticker);

/* Periodic mid-copy sync interval for live backups. */
#define BACKUP_SYNC_INTERVAL_BYTES (512 * 1024 * 1024)

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
 * @brief Writes dir_fd's path, then "/" and rel unless rel is empty, for a
 *        message naming a file the run met; "?" stands for a directory whose
 *        path the kernel cannot give.
 */
void describe_path_at(int dir_fd, const char *rel, char *out, size_t size);

/**
 * @brief Says that restore will not write through the symbolic link at
 *        dir_fd/rel: the user put it there and has to move it aside.
 */
void print_destination_symlink_refusal(int dir_fd, const char *rel);

/**
 * @brief Whether `parent` contains `path` at a path-component boundary,
 * inclusive of equality.
 *
 * A pure string comparison over already-canonical absolute paths: no
 * component is validated and nothing is resolved through the filesystem, so
 * a leaf symlink's own path participates here rather than whatever it
 * points at. "/" is treated as the ancestor of every other absolute path,
 * which a naive prefix comparison gets wrong.
 *
 * Shared by selection matching (backup-time ownership), manifest replay
 * validation, and restore-time destination overlap checks -- all three need
 * exactly this rule and must not drift from each other.
 */
int path_covers(const char *parent, const char *path);

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

/**
 * @brief Prompts with a default-yes choice while still declining on true EOF.
 *
 * Displays message followed by " [Y/n]: ". A successful blank or
 * whitespace-only line accepts the displayed default; EOF means no input was
 * available and is always treated as a negative response.
 *
 * @return 1 for the default or an explicit y/Y response, 0 otherwise.
 */
int confirm_action_default_yes(const char *message);

#endif
