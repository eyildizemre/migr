#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/resource.h>
#include <time.h>

#include "utils.h"

int verbose = 0;
int dry_run = 0;
int color_enabled = 0;

static void print_status(const char *color, const char *fmt, va_list args)
{
    if (color_enabled)
        fputs(color, stdout);
    vprintf(fmt, args);
    if (color_enabled)
        fputs("\033[0m", stdout);
}

void print_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    print_status("\033[1;31m", fmt, args);
    va_end(args);
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
    print_status("\033[1;32m", fmt, args);
    va_end(args);
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
    int n = snprintf(buf, size, "%s/%.*s", dir, (int)name_len, name);
    if (n < 0 || (size_t)n >= size)
        return -1;
    return 0;
}

int path_join(char *buf, size_t size, const char *dir, const char *name)
{
    return path_join_n(buf, size, dir, name, strlen(name));
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
    printf("  packages <FILE>       Export the installed package list to FILE\n");
    printf("  restore <SOURCE>      Restore files and packages from a backup at SOURCE\n");
    printf("  help                  Show this help\n");
    printf("\n");
    printf("Scope (backup/report, mutually exclusive):\n");
    printf("  --critical            Documents, Downloads, Pictures, and dotfiles (default)\n");
    printf("  --comprehensive       Everything --critical covers, plus Desktop, Videos, Music\n");
    printf("Backup-only explicit paths:\n");
    printf("  <PATH...>             Paths listed after the destination are backed up\n");
    printf("                        exactly as given, with no assumptions\n");
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
    printf("\n");
    printf("Examples:\n");
    printf("  ./migr backup /mnt/drive\n");
    printf("  ./migr backup /mnt/drive --comprehensive\n");
    printf("  ./migr backup /mnt/drive ~/Documents ~/Projects\n");
    printf("  ./migr report --critical --summary\n");
    printf("  ./migr restore /mnt/drive/migr_backup_20260720_143012\n");
}

int confirm_action(const char *message)
{
    printf("%s [y/N]: ", message);
    
    char response[16];
    if (fgets(response, sizeof(response), stdin) == NULL)
    {
        return 0;
    }
    
    return (response[0] == 'y' || response[0] == 'Y');
}
