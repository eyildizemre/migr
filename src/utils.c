#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

int verbose = 0;
int dry_run = 0;
int color_enabled = 0;

static int parse_uid_decimal(const char *text, uid_t *out)
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

    uid_t uid = (uid_t)value;
    if ((uintmax_t)uid != value || uid == (uid_t)-1)
        return -1;
    *out = uid;
    return 0;
}

static int resolve_sudo_home(uid_t target_uid, const char *passwd_path,
                             char out[PATH_MAX])
{
    FILE *passwd = fopen(passwd_path, "r");
    if (passwd == NULL)
    {
        print_error("Error: Could not read local passwd database: %s\n",
                    strerror(errno));
        return -1;
    }

    char *line = NULL;
    size_t capacity = 0;
    size_t matches = 0;
    int matching_record_malformed = 0;
    int matching_home_invalid = 0;
    char resolved[PATH_MAX] = {0};
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

        const char *home = fields[5];
        if (home == NULL || home[0] != '/' ||
            strnlen(home, PATH_MAX) >= PATH_MAX)
        {
            matching_home_invalid = 1;
            continue;
        }
        memcpy(resolved, home, strlen(home) + 1U);
    }

    free(line);
    if (fclose(passwd) != 0 && !read_error)
    {
        read_error = 1;
        read_errno = errno != 0 ? errno : EIO;
    }

    if (read_error)
    {
        print_error("Error: Could not read local passwd database: %s\n",
                    strerror(read_errno));
        return -1;
    }
    if (matches == 0U)
    {
        print_error("Error: SUDO_UID does not match a local /etc/passwd entry.\n");
        return -1;
    }
    if (matches > 1U)
    {
        print_error("Error: SUDO_UID matches multiple local /etc/passwd entries.\n");
        return -1;
    }
    if (matching_record_malformed)
    {
        print_error("Error: Local passwd entry for SUDO_UID is malformed.\n");
        return -1;
    }
    if (matching_home_invalid)
    {
        print_error("Error: Local passwd entry for SUDO_UID has an invalid home directory.\n");
        return -1;
    }

    memcpy(out, resolved, strlen(resolved) + 1U);
    return 0;
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

int path_join(char *buf, size_t size, const char *dir, const char *name)
{
    return path_join_n(buf, size, dir, name, strlen(name));
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
    printf("  conf                  Edit persistent critical/comprehensive selection rules\n");
    printf("  help                  Show this help\n");
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
    printf("\n");
    printf("Examples:\n");
    printf("  ./migr backup /mnt/drive\n");
    printf("  ./migr backup /mnt/drive --comprehensive\n");
    printf("  ./migr backup /mnt/drive ~/Documents ~/Projects\n");
    printf("  ./migr report --critical --summary\n");
    printf("  ./migr conf\n");
    printf("  ./migr restore /mnt/drive/migr_backup_20260720_143012\n");
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
