#define _GNU_SOURCE /* fopencookie, memfd_create */
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

int verbose = 0;
int dry_run = 0;
int color_enabled = 0;

static int parse_decimal_value(const char *text, uintmax_t *out)
{
    if (text == NULL || text[0] == '\0')
        return -1;

    uintmax_t value = 0;
    for (const unsigned char *p = (const unsigned char *)text;
         *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
            return -1;
        unsigned int digit = (unsigned int)(*p - '0');
        if (value > (UINTMAX_MAX - digit) / 10U)
            return -1;
        value = value * 10U + digit;
    }

    *out = value;
    return 0;
}

static int parse_uid_decimal(const char *text, uid_t *out)
{
    uintmax_t value;
    if (out == NULL || parse_decimal_value(text, &value) != 0)
        return -1;

    uid_t uid = (uid_t)value;
    if ((uintmax_t)uid != value || uid == (uid_t)-1)
        return -1;
    *out = uid;
    return 0;
}

static int parse_gid_decimal(const char *text, gid_t *out)
{
    uintmax_t value;
    if (out == NULL || parse_decimal_value(text, &value) != 0)
        return -1;

    gid_t gid = (gid_t)value;
    if ((uintmax_t)gid != value || gid == (gid_t)-1)
        return -1;
    *out = gid;
    return 0;
}

typedef enum {
    SUDO_ACCOUNT_OK = 0,
    SUDO_ACCOUNT_READ_ERROR,
    SUDO_ACCOUNT_NOT_FOUND,
    SUDO_ACCOUNT_AMBIGUOUS,
    SUDO_ACCOUNT_MALFORMED,
    SUDO_ACCOUNT_INVALID_HOME
} SudoAccountResult;

static SudoAccountResult resolve_sudo_account(uid_t target_uid,
                                               const char *passwd_path,
                                               char home_out[PATH_MAX],
                                               gid_t *gid_out,
                                               char name_out[ACCOUNT_NAME_MAX])
{
    FILE *passwd = fopen(passwd_path, "r");
    if (passwd == NULL)
        return SUDO_ACCOUNT_READ_ERROR;

    char *line = NULL;
    size_t capacity = 0;
    size_t matches = 0;
    int matching_record_malformed = 0;
    int matching_home_invalid = 0;
    gid_t resolved_gid = 0;
    char resolved[PATH_MAX] = {0};
    char resolved_name[ACCOUNT_NAME_MAX] = {0};
    int read_error = 0;
    int read_errno = 0;

    for (;;)
    {
        errno = 0;
        ssize_t length = getline(&line, &capacity, passwd);
        if (length < 0)
        {
            if (!feof(passwd))
            {
                read_error = 1;
                read_errno = errno != 0 ? errno : EIO;
            }
            break;
        }
        if (length > 0 && line[length - 1] == '\n')
            line[--length] = '\0';

        char *fields[7] = { line, NULL, NULL, NULL, NULL, NULL, NULL };
        size_t colon_count = 0;
        for (char *p = line; *p != '\0'; p++)
        {
            if (*p != ':')
                continue;
            *p = '\0';
            if (colon_count < 6U)
                fields[colon_count + 1U] = p + 1;
            colon_count++;
        }

        if (colon_count < 2U)
            continue;

        uid_t record_uid;
        if (parse_uid_decimal(fields[2], &record_uid) != 0 ||
            record_uid != target_uid)
            continue;

        matches++;
        if (colon_count != 6U)
        {
            matching_record_malformed = 1;
            continue;
        }

        gid_t record_gid = 0;
        if (gid_out != NULL && parse_gid_decimal(fields[3], &record_gid) != 0)
        {
            matching_record_malformed = 1;
            continue;
        }

        const char *home = fields[5];
        if (home == NULL || home[0] != '/' ||
            strnlen(home, PATH_MAX) >= PATH_MAX)
        {
            matching_home_invalid = 1;
            continue;
        }
        size_t name_length = strnlen(fields[0], ACCOUNT_NAME_MAX);
        if (name_out != NULL &&
            (name_length == 0 || name_length >= ACCOUNT_NAME_MAX))
        {
            matching_record_malformed = 1;
            continue;
        }
        memcpy(resolved, home, strlen(home) + 1U);
        memcpy(resolved_name, fields[0], name_length + 1U);
        resolved_gid = record_gid;
    }

    free(line);
    if (fclose(passwd) != 0 && !read_error)
    {
        read_error = 1;
        read_errno = errno != 0 ? errno : EIO;
    }

    if (read_error)
    {
        errno = read_errno;
        return SUDO_ACCOUNT_READ_ERROR;
    }
    if (matches == 0U)
        return SUDO_ACCOUNT_NOT_FOUND;
    if (matches > 1U)
        return SUDO_ACCOUNT_AMBIGUOUS;
    if (matching_record_malformed)
        return SUDO_ACCOUNT_MALFORMED;
    if (matching_home_invalid)
        return SUDO_ACCOUNT_INVALID_HOME;

    if (home_out != NULL)
        memcpy(home_out, resolved, strlen(resolved) + 1U);
    if (gid_out != NULL)
        *gid_out = resolved_gid;
    if (name_out != NULL)
        memcpy(name_out, resolved_name, strlen(resolved_name) + 1U);
    return SUDO_ACCOUNT_OK;
}

static void report_sudo_account_error(SudoAccountResult result)
{
    switch (result)
    {
    case SUDO_ACCOUNT_READ_ERROR:
        print_error("Error: Could not read local passwd database: %s\n",
                    strerror(errno != 0 ? errno : EIO));
        break;
    case SUDO_ACCOUNT_NOT_FOUND:
        print_error("Error: SUDO_UID does not match a local /etc/passwd entry.\n");
        break;
    case SUDO_ACCOUNT_AMBIGUOUS:
        print_error("Error: SUDO_UID matches multiple local /etc/passwd entries.\n");
        break;
    case SUDO_ACCOUNT_MALFORMED:
        print_error("Error: Local passwd entry for SUDO_UID is malformed.\n");
        break;
    case SUDO_ACCOUNT_INVALID_HOME:
        print_error("Error: Local passwd entry for SUDO_UID has an invalid home directory.\n");
        break;
    case SUDO_ACCOUNT_OK:
        break;
    }
}

static int resolve_sudo_home(uid_t target_uid, const char *passwd_path,
                             char out[PATH_MAX])
{
    SudoAccountResult result = resolve_sudo_account(target_uid, passwd_path,
                                                    out, NULL, NULL);
    if (result == SUDO_ACCOUNT_OK)
        return 0;
    report_sudo_account_error(result);
    return -1;
}

static int resolve_sudo_identity_impl(const char *sudo_uid_env,
                                      const char *passwd_path,
                                      uid_t *uid_out, gid_t *gid_out,
                                      char home_out[PATH_MAX])
{
    if (sudo_uid_env == NULL || passwd_path == NULL || passwd_path[0] == '\0' ||
        uid_out == NULL || gid_out == NULL || home_out == NULL)
        return -1;

    uid_t uid;
    if (parse_uid_decimal(sudo_uid_env, &uid) != 0)
        return -1;

    char home[PATH_MAX];
    gid_t gid;
    if (resolve_sudo_account(uid, passwd_path, home, &gid, NULL) !=
        SUDO_ACCOUNT_OK)
        return -1;

    *uid_out = uid;
    *gid_out = gid;
    memcpy(home_out, home, strlen(home) + 1U);
    return 0;
}

int sudo_invoker(uid_t *uid, gid_t *gid, char home[PATH_MAX])
{
    if (geteuid() != 0 || getenv("SUDO_UID") == NULL)
        return 0;
    uid_t found_uid;
    gid_t found_gid;
    char found_home[PATH_MAX];
    if (resolve_sudo_identity_impl(getenv("SUDO_UID"), "/etc/passwd",
                                   &found_uid, &found_gid, found_home) != 0)
        return -1;
    *uid = found_uid;
    *gid = found_gid;
    if (home != NULL)
        memcpy(home, found_home, strlen(found_home) + 1U);
    return 1;
}

static int local_account_name_impl(uid_t uid, const char *passwd_path,
                                   char out[ACCOUNT_NAME_MAX])
{
    return resolve_sudo_account(uid, passwd_path, NULL, NULL, out) ==
           SUDO_ACCOUNT_OK ? 0 : -1;
}

int local_account_name(uid_t uid, char out[ACCOUNT_NAME_MAX])
{
    return local_account_name_impl(uid, "/etc/passwd", out);
}

void print_backup_time(time_t taken)
{
    struct tm local;
    char text[32];
    if (taken > 0 && localtime_r(&taken, &local) != NULL &&
        strftime(text, sizeof(text), "%Y-%m-%d %H:%M", &local) != 0)
        printf("Backup taken %s\n", text);
}

const char *invoker_name(void)
{
    const char *names[] = {
        geteuid() == 0 ? getenv("SUDO_USER") : NULL,
        getenv("USER"),
        getenv("LOGNAME")
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (names[i] != NULL && names[i][0] != '\0')
            return names[i];
    return "user";
}

static int resolve_target_home_impl(const char *home_env,
                                    const char *sudo_uid_env,
                                    const char *passwd_path,
                                    int running_as_root,
                                    char out[PATH_MAX])
{
    if (out == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    out[0] = '\0';

    if (!running_as_root || sudo_uid_env == NULL)
    {
        if (home_env == NULL || home_env[0] == '\0')
        {
            print_error("Error: HOME is not set or is empty for this invocation.\n");
            return -1;
        }
        size_t length = strnlen(home_env, PATH_MAX);
        if (length >= PATH_MAX)
        {
            print_error("Error: HOME path too long to resolve user directories.\n");
            return -1;
        }
        memcpy(out, home_env, length + 1U);
        return 0;
    }

    uid_t target_uid;
    if (parse_uid_decimal(sudo_uid_env, &target_uid) != 0)
    {
        print_error("Error: SUDO_UID is invalid; expected an unsigned local UID.\n");
        return -1;
    }
    if (passwd_path == NULL || passwd_path[0] == '\0')
    {
        print_error("Error: Could not read local passwd database: invalid path.\n");
        return -1;
    }
    return resolve_sudo_home(target_uid, passwd_path, out);
}

int resolve_target_home(char out[PATH_MAX])
{
    return resolve_target_home_impl(getenv("HOME"), getenv("SUDO_UID"),
                                    "/etc/passwd", geteuid() == 0, out);
}

#ifdef USER_CONTEXT_TEST_HOOKS
int resolve_target_home_for_test(const char *home_env,
                                 const char *sudo_uid_env,
                                 const char *passwd_path,
                                 int running_as_root,
                                 char out[PATH_MAX])
{
    return resolve_target_home_impl(home_env, sudo_uid_env, passwd_path,
                                    running_as_root, out);
}

int local_account_name_for_test(uid_t uid, const char *passwd_path,
                                char out[ACCOUNT_NAME_MAX])
{
    return local_account_name_impl(uid, passwd_path, out);
}

int resolve_sudo_identity_for_test(const char *sudo_uid_env,
                                   const char *passwd_path,
                                   uid_t *uid_out, gid_t *gid_out,
                                   char home_out[PATH_MAX])
{
    return resolve_sudo_identity_impl(sudo_uid_env, passwd_path,
                                      uid_out, gid_out, home_out);
}
#endif

static void print_status(const char *color, const char *fmt, va_list args)
{
    if (color_enabled)
        fputs(color, stderr);
    vfprintf(stderr, fmt, args);
    if (color_enabled)
        fputs("\033[0m", stderr);
}

void print_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_status("\033[1;31m", fmt, args);
    va_end(args);
}

void print_source_safe_read_refusal(const char *label)
{
    print_error("Error: Could not safely read source for %s: the kernel "
           "refused the O_NOATIME open; an O_NOATIME-less retry was not "
           "attempted because it could change atime (ownership or "
           "CAP_FOWNER is required).\n", label);
}

void print_warning(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_status("\033[1;33m", fmt, args);
    va_end(args);
}

void print_success(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (color_enabled)
        fputs("\033[1;32m", stderr);
    fputs("  OK: ", stderr);
    vfprintf(stderr, fmt, args);
    if (color_enabled)
        fputs("\033[0m", stderr);
    va_end(args);
}

void format_item_count_phrase(char *buf, size_t buf_size, size_t count,
                              const char *verb)
{
    snprintf(buf, buf_size, "%zu item%s %s", count,
             count == 1 ? "" : "s", verb);
}

void format_size(off_t bytes, char *buf, size_t len)
{
    if (bytes >= 1073741824)
    {
        snprintf(buf, len, "%.1fG", bytes / 1073741824.0);
    }
    else if (bytes >= 1048576)
    {
        snprintf(buf, len, "%.1fM", bytes / 1048576.0);
    }
    else if (bytes >= 1024)
    {
        snprintf(buf, len, "%.1fK", bytes / 1024.0);
    }
    else
    {
        snprintf(buf, len, "%lldB", (long long)bytes);
    }
}

void format_duration(long seconds, char *buf, size_t len)
{
    if (seconds < 0)
        seconds = 0;

    if (seconds >= 3600)
    {
        long hours = seconds / 3600;
        long minutes = (seconds / 60) % 60;
        long remainder = seconds % 60;
        snprintf(buf, len, "%ld:%02ld:%02ld", hours, minutes, remainder);
    }
    else
    {
        long minutes = seconds / 60;
        long remainder = seconds % 60;
        snprintf(buf, len, "%02ld:%02ld", minutes, remainder);
    }
}

void progress_line_fit(char *line, size_t line_capacity)
{
    if (line == NULL || line_capacity == 0U)
        return;

    size_t length = strnlen(line, line_capacity);
    if (length == line_capacity)
    {
        line[line_capacity - 1U] = '\0';
        length = line_capacity - 1U;
    }

    struct winsize ws;
    size_t columns = 80U;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0U)
        columns = (size_t)ws.ws_col;

    size_t max_length = columns > 1U ? columns - 1U : 1U;
    if (max_length < line_capacity && length > max_length)
        line[max_length] = '\0';
}

double timespec_elapsed_seconds(const struct timespec *start,
                                const struct timespec *end)
{
    if (start == NULL || end == NULL)
        return 0.0;

    int64_t seconds = (int64_t)end->tv_sec - (int64_t)start->tv_sec;
    int64_t nanoseconds = (int64_t)end->tv_nsec -
                          (int64_t)start->tv_nsec;
    if (nanoseconds < 0)
    {
        seconds--;
        nanoseconds += INT64_C(1000000000);
    }
    if (seconds < 0)
        return 0.0;
    return (double)seconds + (double)nanoseconds / 1000000000.0;
}

int dup_cloexec(int fd)
{
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

void *array_reserve(void *items, size_t *capacity, size_t count,
                    size_t extra, size_t element_size,
                    size_t initial_capacity, size_t max_capacity)
{
    if (capacity == NULL || extra == 0 || element_size == 0 ||
        initial_capacity == 0 || max_capacity == 0)
    {
        errno = EINVAL;
        return NULL;
    }
    if (count > max_capacity || extra > max_capacity - count)
    {
        errno = E2BIG;
        return NULL;
    }

    size_t needed = count + extra;
    if (needed <= *capacity)
        return items;

    size_t next = *capacity == 0 ? initial_capacity : *capacity * 2U;
    if (next < *capacity)
        next = max_capacity;
    if (next < needed)
        next = needed;
    if (next > max_capacity)
        next = max_capacity;
    if (next < needed || next > SIZE_MAX / element_size)
    {
        errno = E2BIG;
        return NULL;
    }

    void *grown = realloc(items, next * element_size);
    if (grown == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    memset((unsigned char *)grown + *capacity * element_size, 0,
           (next - *capacity) * element_size);
    *capacity = next;
    return grown;
}

size_t relative_path_depth(const char *path)
{
    if (path == NULL || path[0] == '\0')
        return 0;
    size_t depth = 1U;
    for (const char *cursor = path; *cursor != '\0'; cursor++)
        if (*cursor == '/')
            depth++;
    return depth;
}

int backup_progress_should_fire(struct timespec *last_fired, int unthrottled)
{
    if (last_fired == NULL)
        return 0;

    if (unthrottled)
        return 1;
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    if (last_fired->tv_sec == 0 && last_fired->tv_nsec == 0)
    {
        *last_fired = now;
        return 1;
    }

    int64_t seconds = (int64_t)now.tv_sec - (int64_t)last_fired->tv_sec;
    int64_t nanoseconds = (int64_t)now.tv_nsec -
                          (int64_t)last_fired->tv_nsec;
    if (nanoseconds < 0)
    {
        seconds--;
        nanoseconds += INT64_C(1000000000);
    }
    if (seconds < 0 ||
        (seconds == 0 && nanoseconds <
             (int64_t)BACKUP_PROGRESS_THROTTLE_MS * INT64_C(1000000)))
        return 0;

    *last_fired = now;
    return 1;
}

static void *progress_ticker_thread(void *arg)
{
    ProgressTicker *ticker = arg;
    const struct timespec interval = {
        .tv_sec = PROGRESS_TICK_INTERVAL_MS / 1000,
        .tv_nsec = (PROGRESS_TICK_INTERVAL_MS % 1000) * 1000000L
    };

    for (;;)
    {
        struct timespec remaining = interval;
        while (nanosleep(&remaining, &remaining) != 0)
        {
            if (errno == EINTR)
                continue;
            ticker->thread_error = errno;
            return NULL;
        }

        int rc = pthread_mutex_lock(&ticker->lock);
        if (rc != 0)
        {
            ticker->thread_error = rc;
            return NULL;
        }
        if (ticker->stop_requested)
        {
            rc = pthread_mutex_unlock(&ticker->lock);
            if (rc != 0)
                ticker->thread_error = rc;
            return NULL;
        }

        struct timespec now;
        if (ticker->has_snapshot)
        {
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            {
                ticker->thread_error = errno;
                (void)pthread_mutex_unlock(&ticker->lock);
                return NULL;
            }
            if (timespec_elapsed_seconds(&ticker->snapshot.at, &now) * 1000.0 >=
                (double)PROGRESS_STALL_MS)
                ticker->redraw_cb(&ticker->snapshot, &now,
                                  ticker->redraw_context);
        }
        rc = pthread_mutex_unlock(&ticker->lock);
        if (rc != 0)
        {
            ticker->thread_error = rc;
            return NULL;
        }
    }
}

int progress_ticker_start(ProgressTicker *ticker,
                          ProgressTickerRedraw redraw_cb,
                          void *redraw_context)
{
    if (ticker == NULL || redraw_cb == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    memset(ticker, 0, sizeof(*ticker));
    int rc = pthread_mutex_init(&ticker->lock, NULL);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }
    ticker->initialized = 1;
    ticker->redraw_cb = redraw_cb;
    ticker->redraw_context = redraw_context;

    rc = pthread_create(&ticker->thread, NULL, progress_ticker_thread, ticker);
    if (rc != 0)
    {
        (void)pthread_mutex_destroy(&ticker->lock);
        memset(ticker, 0, sizeof(*ticker));
        errno = rc;
        return -1;
    }
    ticker->running = 1;
    return 0;
}

int progress_ticker_snapshot(ProgressTicker *ticker, off_t bytes,
                             off_t speed_bytes, off_t free_bytes,
                             int free_bytes_known, const char *current_path,
                             const struct timespec *snapshot_at)
{
    if (ticker == NULL || snapshot_at == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (!ticker->running)
        return 0;

    size_t path_length = current_path == NULL
        ? 0U : strnlen(current_path, sizeof(ticker->snapshot.path));
    if (path_length >= sizeof(ticker->snapshot.path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int rc = pthread_mutex_lock(&ticker->lock);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }
    ticker->snapshot.bytes = bytes;
    ticker->snapshot.speed_bytes = speed_bytes;
    ticker->snapshot.free_bytes = free_bytes;
    ticker->snapshot.free_bytes_known = free_bytes_known;
    if (path_length != 0)
        memcpy(ticker->snapshot.path, current_path, path_length);
    ticker->snapshot.path[path_length] = '\0';
    ticker->snapshot.at = *snapshot_at;
    ticker->has_snapshot = 1;
    rc = pthread_mutex_unlock(&ticker->lock);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }
    return 0;
}

int progress_ticker_stop(ProgressTicker *ticker)
{
    if (ticker == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (!ticker->initialized)
        return 0;

    int rc = pthread_mutex_lock(&ticker->lock);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }
    ticker->stop_requested = 1;
    rc = pthread_mutex_unlock(&ticker->lock);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }

    if (ticker->running)
    {
        rc = pthread_join(ticker->thread, NULL);
        if (rc != 0)
        {
            errno = rc;
            return -1;
        }
        ticker->running = 0;
    }

    rc = pthread_mutex_destroy(&ticker->lock);
    if (rc != 0)
    {
        errno = rc;
        return -1;
    }
    memset(ticker, 0, sizeof(*ticker));
    return 0;
}

int backup_sync_due(off_t *bytes_since_sync, off_t chunk_size,
                    off_t interval)
{
    if (bytes_since_sync == NULL || interval <= 0)
        return 0;

    *bytes_since_sync += chunk_size;
    if (*bytes_since_sync < interval)
        return 0;

    *bytes_since_sync = 0;
    return 1;
}

int path_join_n(char *buf, size_t size, const char *dir,
                const char *name, size_t name_len)
{
    // The "%.*s" precision is an int; a name_len past INT_MAX would overflow the
    // cast. Production callers stay under PATH_MAX, but reject it rather than
    // rely on that invariant holding forever.
    if (name_len > INT_MAX)
        return -1;
    // Avoid "//name" when dir is exactly "/" -- a cosmetic difference that
    // would otherwise let two identical filesystem objects compare unequal
    // as strings (see backup_plan.c's duplicate/overlap detection).
    int n;
    if (strcmp(dir, "/") == 0)
        n = snprintf(buf, size, "/%.*s", (int)name_len, name);
    else
        n = snprintf(buf, size, "%s/%.*s", dir, (int)name_len, name);
    if (n < 0 || (size_t)n >= size)
        return -1;
    return 0;
}

void describe_path_at(int dir_fd, const char *rel, char *out, size_t size)
{
    char link[64];
    char dir[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", dir_fd);
    ssize_t length = readlink(link, dir, sizeof(dir) - 1U);
    if (length <= 0)
        snprintf(dir, sizeof(dir), "?");
    else
        dir[length] = '\0';
    snprintf(out, size, "%s%s%s", dir, rel[0] != '\0' ? "/" : "", rel);
}

void print_destination_symlink_refusal(int dir_fd, const char *rel)
{
    char path[PATH_MAX * 2];
    describe_path_at(dir_fd, rel, path, sizeof(path));
    print_error("Error: %s is a symbolic link, which restore does not write "
                "through. Move it aside and run the restore again.\n", path);
}

int path_join(char *buf, size_t size, const char *dir, const char *name)
{
    return path_join_n(buf, size, dir, name, strlen(name));
}

int path_trim_trailing_slashes(char *buf, size_t size, const char *path)
{
    int length = snprintf(buf, size, "%s", path);
    if (length < 0 || (size_t)length >= size)
        return -1;
    while (length > 1 && buf[length - 1] == '/')
        buf[--length] = '\0';
    return 0;
}

int path_covers(const char *parent, const char *path)
{
    size_t n = strlen(parent);
    return !strcmp(parent, path) || (n == 1 && parent[0] == '/' && path[0] == '/') ||
           (n && !strncmp(parent, path, n) && path[n] == '/');
}

void raise_fd_limit(void)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        return;
    if (limit.rlim_cur >= limit.rlim_max)
        return;
    limit.rlim_cur = limit.rlim_max;
    (void)setrlimit(RLIMIT_NOFILE, &limit);
}

void print_help(void)
{
    printf("Usage: ./migr <COMMAND> [ARGUMENTS] [OPTIONS]\n");
    printf("\n");
    printf("Commands:\n");
    printf("  report [SCOPE]        Show backup analysis report (default when no command given)\n");
    printf("  backup <PATH>         Create a resumable backup container under PATH\n");
    printf("  restore <SOURCE>      Restore files and packages from a backup at SOURCE\n");
    printf("  verify <SOURCE>       Check a portable backup against its capture record\n");
    printf("  repair <SOURCE> <PATH>\n");
    printf("                        Rebuild a damaged portable backup as a new copy under PATH\n");
    printf("  conf                  Edit persistent critical/comprehensive selection rules\n");
    printf("  help                  Show this help\n");
    printf("\n");
    printf("backup and restore need root: run them with sudo. Their --dry-run\n");
    printf("previews and the other commands do not.\n");
    printf("\n");
    printf("Scope (backup/report, mutually exclusive):\n");
    printf("  --critical            Personal content plus persistent user state (default)\n");
    printf("  --comprehensive       Everything --critical covers, plus Videos and Music\n");
    printf("Backup-only explicit paths:\n");
    printf("  <PATH...>             Paths listed after the destination are backed up\n");
    printf("                        exactly as given, with no assumptions\n");
    printf("\n");
    printf("Scoped report/backup commands automatically read migr.conf from the\n");
    printf("user config directory. Missing or empty config keeps the built-in scope.\n");
    printf("Explicit-path backup and restore do not read the current config.\n");
    printf("\n");
    printf("A destination that cannot hold Linux metadata natively (e.g.\n");
    printf("exFAT/NTFS/FAT32) uses a portable sidecar representation instead\n");
    printf("of being refused; restore reads either representation the same way.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -n, --dry-run         Preview actions without making changes\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
    printf("  -s, --summary         Print only the selected report scope total\n");
    printf("      --max-depth=<N>\n");
    printf("                        Report directory breakdown depth (implies --verbose)\n");
    printf("      --include-self    Include a validated static migr binary in the backup\n");
    printf("                        (requires building migr-static)\n");
    printf("      --include-network-config\n");
    printf("                        Back up NetworkManager, netplan,\n");
    printf("                        systemd-networkd, wpa_supplicant, and\n");
    printf("                        netctl configuration found on this system\n");
    printf("      --no-verify       Skip post-copy content verification (restore only)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  sudo ./migr backup /mnt/drive\n");
    printf("  sudo ./migr backup /mnt/drive --comprehensive\n");
    printf("  sudo ./migr backup /mnt/drive ~/Documents ~/Projects\n");
    printf("  ./migr report --critical --summary\n");
    printf("  ./migr conf\n");
    printf("  ./migr verify /mnt/drive/migr-eyildizemre\n");
    printf("  sudo ./migr restore /mnt/drive/migr-eyildizemre\n");
}

static int confirm_action_with_default(const char *message, int default_yes)
{
    printf("%s %s: ", message, default_yes ? "[Y/n]" : "[y/N]");
    
    char response[16];
    if (fgets(response, sizeof(response), stdin) == NULL)
    {
        return 0;
    }

    int only_whitespace = 1;
    for (size_t i = 0; response[i] != '\0'; i++)
    {
        if (!isspace((unsigned char)response[i]))
        {
            only_whitespace = 0;
            break;
        }
    }
    if (only_whitespace)
        return default_yes;

    return (response[0] == 'y' || response[0] == 'Y');
}

int confirm_action(const char *message)
{
    return confirm_action_with_default(message, 0);
}

int confirm_action_default_yes(const char *message)
{
    return confirm_action_with_default(message, 1);
}

int crypto_policy_read_at(int dir_fd, const char *path,
                          char out[CRYPTO_POLICY_MAX])
{
    out[0] = '\0';
    int fd = openat(dir_fd, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char buffer[4096];
    ssize_t got = read(fd, buffer, sizeof(buffer) - 1U);
    close(fd);
    if (got < 0)
        return -1;
    buffer[got] = '\0';
    for (char *line = buffer; line != NULL && *line != '\0';)
    {
        char *end = strchr(line, '\n');
        if (end != NULL)
            *end = '\0';
        line += strspn(line, " \t");
        size_t length = strcspn(line, " \t\r");
        if (length != 0 && line[0] != '#')
        {
            if (length >= CRYPTO_POLICY_MAX ||
                strspn(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                             "0123456789:_-.") < length)
                return -1;
            memcpy(out, line, length);
            out[length] = '\0';
            return 0;
        }
        line = end != NULL ? end + 1 : NULL;
    }
    return -1;
}

int write_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    while (length > 0)
    {
        ssize_t written = write(fd, bytes, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
        {
            if (written == 0)
                errno = EIO;
            return -1;
        }
        bytes += written;
        length -= (size_t)written;
    }
    return 0;
}

char *example_list_next(ExampleList *list)
{
    if (list->count != SIZE_MAX)
        list->count++;
    if (list->kept == EXAMPLE_LIST_KEPT)
        return NULL;
    char *text = list->text[list->kept++];
    text[0] = '\0';
    return text;
}

void example_list_print(const ExampleList *list, const char *indent)
{
    for (size_t index = 0; index < list->kept; index++)
        printf("%s%s\n", indent, list->text[index]);
    if (list->count > list->kept)
        printf("%s... and %zu more\n", indent, list->count - list->kept);
}

/* ------------------------------------------------------------------------- */
/* Run log (docs/DECISIONS.md D79)                                           */
/* ------------------------------------------------------------------------- */

#define RUN_LOG_KEPT 10
#define RUN_LOG_DEPTH_MAX 4

// One of the standard streams while a log runs: what it prints goes to the
// terminal as before, and to the log without colors and with a line redrawn
// through '\r' only as last drawn.
typedef struct {
    int terminal_fd;
    int escape; /* 1 after ESC, 2 inside a CSI sequence */
    size_t length;
    char line[4096];
} RunLogTee;

static struct {
    pthread_mutex_t lock;
    int active;
    int sink_fd; /* A memfd until attached, then the log file. */
    FILE *saved_stdout;
    FILE *saved_stderr;
    RunLogTee out;
    RunLogTee err;
    int dir_fd; /* The log's directory once attached, else -1. */
    char name[64];
    /* Directories created for the log, outermost first, each by its
     * parent's fd and its name; removed with a log that is not kept. */
    size_t created_count;
    int created_parent_fd[RUN_LOG_DEPTH_MAX];
    char created_name[RUN_LOG_DEPTH_MAX][NAME_MAX + 1];
} run_log = { .lock = PTHREAD_MUTEX_INITIALIZER, .sink_fd = -1,
              .dir_fd = -1 };


// Caller holds run_log.lock. A log that cannot be written stays quiet: the
// run itself goes on, and the terminal still shows everything.
static void run_log_sink(const char *data, size_t length)
{
    if (run_log.sink_fd >= 0)
        (void)write_all(run_log.sink_fd, data, length);
}

static void run_log_tee_consume(RunLogTee *tee, const char *data, size_t size)
{
    pthread_mutex_lock(&run_log.lock);
    for (size_t index = 0; index < size; index++)
    {
        char c = data[index];
        if (tee->escape == 1)
        {
            tee->escape = c == '[' ? 2 : 0;
            continue;
        }
        if (tee->escape == 2)
        {
            if (c >= 0x40 && c <= 0x7e)
                tee->escape = 0;
            continue;
        }
        if (c == '\033')
        {
            tee->escape = 1;
            continue;
        }
        if (c == '\r')
        {
            tee->length = 0;
            continue;
        }
        tee->line[tee->length++] = c;
        if (c == '\n' || tee->length == sizeof(tee->line))
        {
            run_log_sink(tee->line, tee->length);
            tee->length = 0;
        }
    }
    pthread_mutex_unlock(&run_log.lock);
}

static ssize_t run_log_tee_write(void *cookie, const char *data, size_t size)
{
    RunLogTee *tee = cookie;
    if (write_all(tee->terminal_fd, data, size) != 0)
        return -1;
    run_log_tee_consume(tee, data, size);
    return (ssize_t)size;
}

int run_log_start(int argc, char *const argv[])
{
    if (run_log.active)
        return 0;
    int sink = memfd_create("migr-log", MFD_CLOEXEC);
    if (sink < 0)
        return -1;
    cookie_io_functions_t io = { .write = run_log_tee_write };
    FILE *out = fopencookie(&run_log.out, "w", io);
    FILE *err = fopencookie(&run_log.err, "w", io);
    if (out == NULL || err == NULL)
    {
        if (out != NULL)
            fclose(out);
        if (err != NULL)
            fclose(err);
        close(sink);
        return -1;
    }
    // The same buffering the standard streams had on the terminal.
    setvbuf(out, NULL, isatty(STDOUT_FILENO) ? _IOLBF : _IOFBF, BUFSIZ);
    setvbuf(err, NULL, _IONBF, 0);
    fflush(stdout);
    fflush(stderr);

    memset(&run_log.out, 0, sizeof(run_log.out));
    memset(&run_log.err, 0, sizeof(run_log.err));
    run_log.out.terminal_fd = STDOUT_FILENO;
    run_log.err.terminal_fd = STDERR_FILENO;
    run_log.sink_fd = sink;
    run_log.dir_fd = -1;
    run_log.created_count = 0;
    run_log.saved_stdout = stdout;
    run_log.saved_stderr = stderr;
    // glibc lets the standard streams be replaced, so every printf and
    // print_error reaches the log while fds 1 and 2 stay the terminal.
    stdout = out;
    stderr = err;
    run_log.active = 1;

    char started[64] = "";
    time_t now = time(NULL);
    struct tm local;
    if (localtime_r(&now, &local) != NULL)
        strftime(started, sizeof(started), "%Y-%m-%d %H:%M:%S %z", &local);
    run_log_printf("migr run started %s:", started);
    for (int index = 0; index < argc; index++)
        run_log_printf(" %s", argv[index]);
    run_log_printf("\n\n");
    return 0;
}

void run_log_printf(const char *fmt, ...)
{
    if (!run_log.active)
        return;
    char text[PATH_MAX + 256];
    va_list args;
    va_start(args, fmt);
    int length = vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    if (length < 0)
        return;
    // What was printed before comes first, even while stdout is buffered.
    fflush(stdout);
    pthread_mutex_lock(&run_log.lock);
    run_log_sink(text, (size_t)length < sizeof(text) ? (size_t)length
                                                     : sizeof(text) - 1U);
    pthread_mutex_unlock(&run_log.lock);
}

// Opens dir below base_fd, creating what is missing (0700, owned by
// uid:gid unless uid is -1) and recording it, without following symlinks.
static int run_log_open_dir(int base_fd, const char *dir, uid_t uid, gid_t gid)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s", dir) >= (int)sizeof(path))
        return -1;
    int current = dup_cloexec(base_fd);
    char *save = NULL;
    for (char *component = strtok_r(path, "/", &save);
         current >= 0 && component != NULL;
         component = strtok_r(NULL, "/", &save))
    {
        int created = mkdirat(current, component, 0700) == 0;
        if (!created && errno != EEXIST)
        {
            close(current);
            return -1;
        }
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (created && next >= 0 && uid != (uid_t)-1)
            (void)fchown(next, uid, gid);
        if (created && run_log.created_count < RUN_LOG_DEPTH_MAX)
        {
            size_t slot = run_log.created_count++;
            run_log.created_parent_fd[slot] = dup_cloexec(current);
            snprintf(run_log.created_name[slot],
                     sizeof(run_log.created_name[slot]), "%s", component);
        }
        close(current);
        current = next;
    }
    return current;
}

static int run_log_name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

// Removes the oldest of dir_fd's logs named <prefix>-*.log beyond the newest
// RUN_LOG_KEPT; the names carry their time, so they sort by it.
static void run_log_prune(int dir_fd, const char *prefix)
{
    int fd = dup_cloexec(dir_fd);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (dir == NULL)
    {
        if (fd >= 0)
            close(fd);
        return;
    }
    char *names[256];
    size_t count = 0;
    size_t prefix_length = strlen(prefix);
    struct dirent *entry;
    while (count < sizeof(names) / sizeof(names[0]) &&
           (entry = readdir(dir)) != NULL)
    {
        size_t length = strlen(entry->d_name);
        if (strncmp(entry->d_name, prefix, prefix_length) == 0 &&
            entry->d_name[prefix_length] == '-' && length > 4U &&
            strcmp(entry->d_name + length - 4U, ".log") == 0 &&
            (names[count] = strdup(entry->d_name)) != NULL)
            count++;
    }
    closedir(dir);
    qsort(names, count, sizeof(names[0]), run_log_name_cmp);
    for (size_t index = 0; index < count; index++)
    {
        if (index + RUN_LOG_KEPT < count)
            (void)unlinkat(dir_fd, names[index], 0);
        free(names[index]);
    }
}

// Removes a directory created for the log, keeping its parent's times as
// the run left them: a restore has already restored those.
static void run_log_remove_created(size_t slot)
{
    int parent = run_log.created_parent_fd[slot];
    struct stat before;
    int timed = fstat(parent, &before) == 0;
    if (unlinkat(parent, run_log.created_name[slot], AT_REMOVEDIR) == 0 &&
        timed)
    {
        struct timespec times[2] = { before.st_atim, before.st_mtim };
        (void)futimens(parent, times);
    }
}

// Removes the directories made for a log that will not be written.
static void run_log_undo_created(void)
{
    for (size_t slot = run_log.created_count; slot > 0; slot--)
    {
        run_log_remove_created(slot - 1U);
        close(run_log.created_parent_fd[slot - 1U]);
    }
    run_log.created_count = 0;
}

int run_log_attach(int base_fd, const char *dir, const char *prefix,
                   uid_t uid, gid_t gid)
{
    if (!run_log.active || run_log.dir_fd >= 0)
        return 0;
    int dir_fd = run_log_open_dir(base_fd, dir, uid, gid);
    if (dir_fd < 0)
    {
        run_log_undo_created();
        return -1;
    }

    char stamp[32] = "";
    time_t now = time(NULL);
    struct tm local;
    if (localtime_r(&now, &local) != NULL)
        strftime(stamp, sizeof(stamp), "%Y-%m-%d-%H%M%S", &local);
    int fd = -1;
    for (int attempt = 1; fd < 0 && attempt < 10; attempt++)
    {
        if (attempt == 1)
            snprintf(run_log.name, sizeof(run_log.name), "%s-%s.log", prefix,
                     stamp);
        else
            snprintf(run_log.name, sizeof(run_log.name), "%s-%s-%d.log",
                     prefix, stamp, attempt);
        fd = openat(dir_fd, run_log.name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_APPEND |
                    O_CLOEXEC, 0600);
        if (fd < 0 && errno != EEXIST)
            break;
    }
    if (fd < 0)
    {
        close(dir_fd);
        run_log_undo_created();
        return -1;
    }
    if (uid != (uid_t)-1)
        (void)fchown(fd, uid, gid);

    // What was printed before there was a place for it goes in first.
    fflush(stdout);
    fflush(stderr);
    pthread_mutex_lock(&run_log.lock);
    char buffer[65536];
    ssize_t got;
    off_t offset = 0;
    while ((got = pread(run_log.sink_fd, buffer, sizeof(buffer), offset)) > 0)
    {
        (void)write_all(fd, buffer, (size_t)got);
        offset += got;
    }
    close(run_log.sink_fd);
    run_log.sink_fd = fd;
    run_log.dir_fd = dir_fd;
    pthread_mutex_unlock(&run_log.lock);
    run_log_prune(dir_fd, prefix);
    return 0;
}

const char *run_log_finish(int keep)
{
    static char kept[PATH_MAX];
    if (!run_log.active)
        return NULL;
    fflush(stdout);
    fflush(stderr);
    FILE *out = stdout;
    FILE *err = stderr;
    stdout = run_log.saved_stdout;
    stderr = run_log.saved_stderr;
    fclose(out);
    fclose(err);

    pthread_mutex_lock(&run_log.lock);
    RunLogTee *tees[] = { &run_log.out, &run_log.err };
    for (size_t index = 0; index < 2; index++)
        if (tees[index]->length != 0)
        {
            run_log_sink(tees[index]->line, tees[index]->length);
            run_log_sink("\n", 1);
        }
    pthread_mutex_unlock(&run_log.lock);

    kept[0] = '\0';
    if (run_log.dir_fd >= 0 && keep)
    {
        (void)fsync(run_log.sink_fd);
        describe_path_at(run_log.dir_fd, run_log.name, kept, sizeof(kept));
    }
    else if (run_log.dir_fd >= 0)
    {
        (void)unlinkat(run_log.dir_fd, run_log.name, 0);
        run_log_undo_created();
    }

    for (size_t slot = 0; slot < run_log.created_count; slot++)
        close(run_log.created_parent_fd[slot]);
    run_log.created_count = 0;
    if (run_log.dir_fd >= 0)
        close(run_log.dir_fd);
    run_log.dir_fd = -1;
    close(run_log.sink_fd);
    run_log.sink_fd = -1;
    run_log.active = 0;
    return kept[0] != '\0' ? kept : NULL;
}

