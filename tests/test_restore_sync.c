// Native restore progress/sync coverage (D28/D30): restored bytes must span
// several top-level calls, periodic sync must abort a failed restore, and the
// low-level report state is caller-owned rather than reset per item.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fileops.h"
#include "utils.h"

static int failures;
static int sync_calls;
static int sync_should_fail;

extern int __real_syncfs(int fd);

int __wrap_syncfs(int fd)
{
    sync_calls++;
    if (sync_should_fail)
    {
        errno = EIO;
        return -1;
    }
    return __real_syncfs(fd);
}

static void check(int condition, const char *label)
{
    if (condition)
        printf("  v %s\n", label);
    else
    {
        printf("  x %s\n", label);
        failures++;
    }
}

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "restore sync fixture failure: %s\n", message);
    exit(2);
}

static int remove_callback(const char *path, const struct stat *st,
                           int type, struct FTW *state)
{
    (void)st;
    (void)type;
    (void)state;
    if (remove(path) != 0)
        fixture_fatal("could not remove fixture tree");
    return 0;
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_callback, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fixture_fatal("could not walk fixture tree");
}

static void join_path(char *out, size_t size, const char *left,
                      const char *right)
{
    int length = snprintf(out, size, "%s/%s", left, right);
    if (length < 0 || (size_t)length >= size)
        fixture_fatal("fixture path is too long");
}

static void make_base(char *base, size_t size)
{
    const char template[] = "/tmp/migr_restore_sync_XXXXXX";
    if (strlen(template) >= size)
        fixture_fatal("fixture base buffer is too small");
    memcpy(base, template, sizeof(template));
    if (mkdtemp(base) == NULL)
        fixture_fatal("could not create fixture base");
}

static void make_directory(const char *path)
{
    if (mkdir(path, 0700) != 0)
        fixture_fatal("could not create fixture directory");
}

static void write_bytes(const char *path, size_t size)
{
    unsigned char buffer[8192];
    for (size_t index = 0; index < sizeof(buffer); index++)
        buffer[index] = (unsigned char)(index * 17U + 3U);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fixture_fatal("could not create fixture file");

    size_t written_total = 0;
    while (written_total < size)
    {
        size_t request = size - written_total;
        if (request > sizeof(buffer))
            request = sizeof(buffer);
        ssize_t written = write(fd, buffer, request);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            fixture_fatal("could not write fixture file");
        written_total += (size_t)written;
    }
    if (close(fd) != 0)
        fixture_fatal("could not close fixture file");
}

static int open_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        fixture_fatal("could not open fixture directory");
    return fd;
}

static CloneContext native_restore_context(void)
{
    return (CloneContext){
        .operation = CLONE_RESTORE,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1,
        .metadata_preflight_done = 1
    };
}

static RestoreNativeStatus restore_one(const char *source,
                                       const char *destination,
                                       const char *source_leaf,
                                       const char *destination_leaf,
                                       RestoreNativeReport *restore_report,
                                       BackupCaptureReport *capture_report)
{
    int source_fd = open_directory(source);
    int destination_fd = open_directory(destination);
    CloneContext context = native_restore_context();
    RestoreNativeStatus result = restore_native_at_report(
        &context, source_fd, source_leaf, destination_fd, destination_leaf,
        restore_report, capture_report);
    if (close(source_fd) != 0 || close(destination_fd) != 0)
        fixture_fatal("could not close fixture directory");
    return result;
}

static void reset_sync(int should_fail)
{
    sync_calls = 0;
    sync_should_fail = should_fail;
}

static void test_restore_sync_accumulates_across_files(void)
{
    printf(":: native restore report accumulates bytes and syncs across files\n");
    /* Direct/test reports stay at zero; production installs this shared default. */
    check(BACKUP_SYNC_INTERVAL_BYTES == 256 * 1024 * 1024,
          "production periodic sync interval is 256 MiB");

    char base[PATH_MAX], source[PATH_MAX], destination[PATH_MAX];
    char one[PATH_MAX], two[PATH_MAX], three[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(destination, sizeof(destination), base, "destination");
    make_directory(source);
    make_directory(destination);
    join_path(one, sizeof(one), source, "one");
    join_path(two, sizeof(two), source, "two");
    join_path(three, sizeof(three), source, "three");
    write_bytes(one, 80);
    write_bytes(two, 80);
    write_bytes(three, 80);

    BackupCaptureReport capture_report;
    backup_capture_report_init(&capture_report);
    capture_report.sync_interval_bytes = 200;
    RestoreNativeReport restore_report;
    reset_sync(0);

    RestoreNativeStatus first = restore_one(
        source, destination, "one", "one", &restore_report, &capture_report);
    RestoreNativeStatus second = restore_one(
        source, destination, "two", "two", &restore_report, &capture_report);
    RestoreNativeStatus third = restore_one(
        source, destination, "three", "three", &restore_report,
        &capture_report);
    check(first == RESTORE_NATIVE_OK && second == RESTORE_NATIVE_OK &&
              third == RESTORE_NATIVE_OK && capture_report.bytes_copied == 240 &&
              capture_report.bytes_since_sync == 0 && sync_calls == 1,
          "native restore report accumulates across smaller files and syncs once");

    remove_tree(base);
}

static void test_restore_sync_failure_aborts(void)
{
    printf(":: native restore aborts when periodic sync fails\n");

    char base[PATH_MAX], source[PATH_MAX], destination[PATH_MAX];
    char source_file[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(destination, sizeof(destination), base, "destination");
    make_directory(source);
    make_directory(destination);
    join_path(source_file, sizeof(source_file), source, "payload");
    write_bytes(source_file, 80);

    BackupCaptureReport capture_report;
    backup_capture_report_init(&capture_report);
    capture_report.sync_interval_bytes = 1;
    RestoreNativeReport restore_report;
    reset_sync(1);
    RestoreNativeStatus status = restore_one(
        source, destination, "payload", "payload", &restore_report,
        &capture_report);
    check(status == RESTORE_NATIVE_ERROR && sync_calls == 1 &&
              restore_report.failed_count != 0,
          "a failed periodic sync aborts native restore and records failure");

    reset_sync(0);
    remove_tree(base);
}

int main(void)
{
    test_restore_sync_accumulates_across_files();
    test_restore_sync_failure_aborts();
    return failures == 0 ? 0 : 1;
}
