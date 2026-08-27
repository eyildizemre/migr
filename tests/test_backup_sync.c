// Periodic capture-sync coverage (docs/DECISIONS.md D30): the byte counter
// must span files and roots, the zero interval must remain inert, and a
// failed syncfs must abort both native and portable capture.

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
#include "metadata.h"
#include "portable.h"
#include "utils.h"

static int failures;
static int sync_calls;
static int sync_should_fail;
static int short_read_enabled;
static int short_read_triggered;

extern int __real_syncfs(int fd);
extern ssize_t __real_read(int fd, void *buffer, size_t count);

ssize_t __wrap_read(int fd, void *buffer, size_t count)
{
    (void)fd;
    if (short_read_enabled && !short_read_triggered && count > 0)
    {
        short_read_triggered = 1;
        return 0;
    }
    return __real_read(fd, buffer, count);
}

static void arm_short_read_for_source(const char *source_path, void *context)
{
    if (context != NULL && strcmp(source_path, context) == 0)
        short_read_enabled = 1;
}

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
    fprintf(stderr, "backup sync fixture failure: %s\n", message);
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
    const char template[] = "/tmp/migr_backup_sync_XXXXXX";
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

static void close_fixture_fd(int fd)
{
    if (close(fd) != 0)
        fixture_fatal("could not close fixture directory");
}

static void reset_sync(int should_fail)
{
    sync_calls = 0;
    sync_should_fail = should_fail;
}

static CloneContext native_backup_context(void)
{
    return (CloneContext){
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1,
        .metadata_preflight_done = 1
    };
}

static BackupCaptureStatus capture_native(const char *source,
                                          const char *destination,
                                          const char *leaf,
                                          BackupCaptureReport *report)
{
    int destination_fd = open_directory(destination);
    CloneContext context = native_backup_context();
    BackupCaptureStatus result = backup_capture_at_report_continue(
        &context, source, destination_fd, leaf, report);
    close_fixture_fd(destination_fd);
    return result;
}

static PortableCaptureRequest portable_request(PortableRootSpec *root)
{
    return (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .roots = root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
}

static int capture_portable(const char *source, const char *scratch,
                            const char *container,
                            BackupCaptureReport *report)
{
    int scratch_fd = open_directory(scratch);
    int container_fd = open_directory(container);
    PortableRootSpec root = {
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "ROOT",
        .source_path = source,
        .restore_path = "",
        .has_restore_path = 1
    };
    PortableCaptureRequest request = portable_request(&root);
    PortablePreparedCapture prepared = {0};
    int result = -1;

    if (portable_capture_prepare(scratch_fd, &request, &prepared) == 0)
    {
        size_t live_count = 0;
        result = portable_capture_fresh_prepared_at(
            container_fd, &request, &prepared, &live_count, report);
    }
    portable_prepared_capture_free(&prepared);
    close_fixture_fd(scratch_fd);
    close_fixture_fd(container_fd);
    return result;
}

static void test_native_sync(void)
{
    printf(":: native periodic capture sync\n");
    /* Direct/test reports stay at zero; production installs this shared default. */
    check(BACKUP_SYNC_INTERVAL_BYTES == 256 * 1024 * 1024,
          "production periodic sync interval is 256 MiB");
    char base[PATH_MAX];
    char source_dir[PATH_MAX];
    char destination_dir[PATH_MAX];
    char large[PATH_MAX];
    char small_one[PATH_MAX];
    char small_two[PATH_MAX];
    char small_three[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source_dir, sizeof(source_dir), base, "source");
    join_path(destination_dir, sizeof(destination_dir), base, "destination");
    make_directory(source_dir);
    make_directory(destination_dir);
    join_path(large, sizeof(large), source_dir, "large");
    join_path(small_one, sizeof(small_one), source_dir, "small-one");
    join_path(small_two, sizeof(small_two), source_dir, "small-two");
    join_path(small_three, sizeof(small_three), source_dir, "small-three");
    write_bytes(large, 20000);
    write_bytes(small_one, 80);
    write_bytes(small_two, 80);
    write_bytes(small_three, 80);

    BackupCaptureReport report;
    backup_capture_report_init(&report);
    report.sync_interval_bytes = 10000;
    reset_sync(0);
    check(capture_native(large, destination_dir, "large", &report) ==
              BACKUP_CAPTURE_OK &&
              sync_calls == 1,
          "native sync fires once when one file crosses the interval");

    backup_capture_report_init(&report);
    report.sync_interval_bytes = 200;
    reset_sync(0);
    check(capture_native(small_one, destination_dir, "small-one", &report) ==
              BACKUP_CAPTURE_OK &&
              capture_native(small_two, destination_dir, "small-two", &report) ==
                  BACKUP_CAPTURE_OK &&
              capture_native(small_three, destination_dir, "small-three", &report) ==
                  BACKUP_CAPTURE_OK &&
              report.bytes_copied == 240 && report.bytes_since_sync == 0 &&
              sync_calls == 1,
          "native sync counter accumulates across smaller files");

    backup_capture_report_init(&report);
    reset_sync(0);
    check(capture_native(small_one, destination_dir, "disabled", &report) ==
              BACKUP_CAPTURE_OK &&
              report.sync_interval_bytes == 0 && sync_calls == 0,
          "native zero sync interval remains disabled");

    backup_capture_report_init(&report);
    report.sync_interval_bytes = 1;
    reset_sync(1);
    check(capture_native(small_one, destination_dir, "failed", &report) ==
              BACKUP_CAPTURE_ERROR && sync_calls == 1,
          "native capture aborts when periodic sync fails");
    reset_sync(0);
    remove_tree(base);
}

static void test_native_short_copy_refuses(void)
{
    printf(":: native capture rejects a short source read\n");
    char base[PATH_MAX];
    char source_dir[PATH_MAX];
    char destination_dir[PATH_MAX];
    char source[PATH_MAX];
    char destination[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source_dir, sizeof(source_dir), base, "source");
    join_path(destination_dir, sizeof(destination_dir), base, "destination");
    make_directory(source_dir);
    make_directory(destination_dir);
    join_path(source, sizeof(source), source_dir, "payload");
    join_path(destination, sizeof(destination), destination_dir, "payload");
    write_bytes(source, 80);

    BackupCaptureReport report;
    backup_capture_report_init(&report);
    struct stat source_before;
    if (stat(source, &source_before) != 0)
        fixture_fatal("could not inspect the short-copy source");
    short_read_triggered = 0;
    short_read_enabled = 0;
    backup_test_set_capture_hook(arm_short_read_for_source, source);
    BackupCaptureStatus result = capture_native(source, destination_dir,
                                                "payload", &report);
    backup_test_set_capture_hook(NULL, NULL);
    short_read_enabled = 0;

    struct stat source_after;
    struct stat destination_st;
    check(short_read_triggered && result == BACKUP_CAPTURE_ERROR,
          "a short read is rejected instead of reported as a successful capture");
    check(report.bytes_copied == 0 && stat(source, &source_after) == 0 &&
              metadata_source_unchanged(&source_before, &source_after) &&
              lstat(destination, &destination_st) == 0 &&
              destination_st.st_size == 0,
          "the short-copy fixture leaves source metadata unchanged and copies no payload bytes");
    remove_tree(base);
}

static void test_portable_sync(void)
{
    printf(":: portable periodic capture sync\n");
    char base[PATH_MAX];
    char source_large[PATH_MAX];
    char source_small[PATH_MAX];
    char source_disabled[PATH_MAX];
    char source_failed[PATH_MAX];
    char scratch_large[PATH_MAX];
    char scratch_small[PATH_MAX];
    char scratch_disabled[PATH_MAX];
    char scratch_failed[PATH_MAX];
    char container_large[PATH_MAX];
    char container_small[PATH_MAX];
    char container_disabled[PATH_MAX];
    char container_failed[PATH_MAX];
    char path[PATH_MAX];
    make_base(base, sizeof(base));

    join_path(source_large, sizeof(source_large), base, "source-large");
    join_path(source_small, sizeof(source_small), base, "source-small");
    join_path(source_disabled, sizeof(source_disabled), base, "source-disabled");
    join_path(source_failed, sizeof(source_failed), base, "source-failed");
    join_path(scratch_large, sizeof(scratch_large), base, "scratch-large");
    join_path(scratch_small, sizeof(scratch_small), base, "scratch-small");
    join_path(scratch_disabled, sizeof(scratch_disabled), base, "scratch-disabled");
    join_path(scratch_failed, sizeof(scratch_failed), base, "scratch-failed");
    join_path(container_large, sizeof(container_large), base, "container-large");
    join_path(container_small, sizeof(container_small), base, "container-small");
    join_path(container_disabled, sizeof(container_disabled), base, "container-disabled");
    join_path(container_failed, sizeof(container_failed), base, "container-failed");
    make_directory(source_large);
    make_directory(source_small);
    make_directory(source_disabled);
    make_directory(source_failed);
    make_directory(scratch_large);
    make_directory(scratch_small);
    make_directory(scratch_disabled);
    make_directory(scratch_failed);
    make_directory(container_large);
    make_directory(container_small);
    make_directory(container_disabled);
    make_directory(container_failed);

    join_path(path, sizeof(path), source_large, "large");
    write_bytes(path, 20000);
    join_path(path, sizeof(path), source_small, "one");
    write_bytes(path, 80);
    join_path(path, sizeof(path), source_small, "two");
    write_bytes(path, 80);
    join_path(path, sizeof(path), source_small, "three");
    write_bytes(path, 80);
    join_path(path, sizeof(path), source_disabled, "small");
    write_bytes(path, 80);
    join_path(path, sizeof(path), source_failed, "small");
    write_bytes(path, 80);

    BackupCaptureReport report;
    backup_capture_report_init(&report);
    report.sync_interval_bytes = 10000;
    reset_sync(0);
    check(capture_portable(source_large, scratch_large, container_large,
                           &report) == 0 && sync_calls == 1,
          "portable sync fires once when one file crosses the interval");

    backup_capture_report_init(&report);
    report.sync_interval_bytes = 200;
    reset_sync(0);
    check(capture_portable(source_small, scratch_small, container_small,
                           &report) == 0 && report.bytes_copied == 240 &&
              report.bytes_since_sync == 0 && sync_calls == 1,
          "portable sync counter accumulates across smaller files");

    backup_capture_report_init(&report);
    reset_sync(0);
    check(capture_portable(source_disabled, scratch_disabled,
                           container_disabled, &report) == 0 &&
              report.sync_interval_bytes == 0 && sync_calls == 0,
          "portable zero sync interval remains disabled");

    backup_capture_report_init(&report);
    report.sync_interval_bytes = 1;
    reset_sync(1);
    check(capture_portable(source_failed, scratch_failed, container_failed,
                           &report) != 0 && sync_calls == 1,
          "portable capture aborts when periodic sync fails");
    reset_sync(0);
    remove_tree(base);
}

int main(void)
{
    test_native_sync();
    test_native_short_copy_refuses();
    test_portable_sync();
    return failures == 0 ? 0 : 1;
}
