// Portable capture preparation coverage (docs/DECISIONS.md D24): one
// read-only pre-scan produces the manifest and collision plan consumed by
// fresh/resumed capture, while FIFO and skipped special-file policy are
// decided before any container mutation.  The direct entry points remain
// behind the D14 test-only boundary.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "portable.h"
#include "sidecar.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
#define NC    "\033[0m"

static int failures;
static int skips;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void skip_check(const char *label)
{
    printf("  " YELLOW "-" NC " %s\n", label);
    skips++;
}

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "portable prepare fixture failure: %s\n", message);
    exit(2);
}

static int remove_callback_fatal(const char *path, const struct stat *st,
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
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not inspect fixture tree");
    }
    if (nftw(path, remove_callback_fatal, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fixture_fatal("could not walk fixture tree");
}

static void join_path(char *out, size_t size, const char *left,
                      const char *right)
{
    int length = snprintf(out, size, "%s/%s", left, right);
    if (length < 0 || (size_t)length >= size)
        fixture_fatal("fixture path is too long");
}

static void make_directory(const char *path)
{
    if (mkdir(path, 0700) != 0)
        fixture_fatal("could not create fixture directory");
}

static void write_file(const char *path, const char *contents)
{
    size_t length = strlen(contents);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fixture_fatal("could not create fixture file");
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, contents + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            fixture_fatal("could not write fixture file");
        offset += (size_t)written;
    }
    if (close(fd) != 0)
        fixture_fatal("could not close fixture file");
}

static void write_large_file(const char *path, size_t size)
{
    unsigned char buffer[8192];
    for (size_t index = 0; index < sizeof(buffer); index++)
        buffer[index] = (unsigned char)(index * 31U + 7U);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fixture_fatal("could not create large progress fixture");
    size_t written_total = 0;
    while (written_total < size) {
        size_t request = size - written_total;
        if (request > sizeof(buffer))
            request = sizeof(buffer);
        ssize_t written = write(fd, buffer, request);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            fixture_fatal("could not write large progress fixture");
        written_total += (size_t)written;
    }
    if (close(fd) != 0)
        fixture_fatal("could not close large progress fixture");
}

static void make_base(char *base, size_t size)
{
    const char template[] = "/tmp/migr_portable_prepare_XXXXXX";
    if (strlen(template) >= size)
        fixture_fatal("fixture base buffer is too small");
    memcpy(base, template, sizeof(template));
    if (mkdtemp(base) == NULL)
        fixture_fatal("could not create fixture base");
}

static int directory_is_empty(int directory_fd)
{
    if (directory_fd < 0)
        return -1;
    int scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }

    int empty = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                empty = -1;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = 0;
            break;
        }
    }
    if (closedir(directory) != 0)
        return -1;
    return empty;
}

static PortableRootSpec root_spec(const char *id, const char *source,
                                  const char *payload)
{
    return (PortableRootSpec){
        .id = id,
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = payload,
        .source_path = source,
        .restore_path = "",
        .has_restore_path = 1
    };
}

static PortableCaptureRequest request_for(const PortableRootSpec *roots,
                                          size_t root_count,
                                          int case_sensitive)
{
    return (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .roots = roots,
        .root_count = root_count,
        .nsec_exact = 1,
        .case_sensitive = case_sensitive
    };
}

static int open_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        fixture_fatal("could not open fixture directory");
    return fd;
}

static int sidecar_count(const char *container_path, size_t expected)
{
    int container_fd = open_directory(container_path);
    SidecarLog log = {0};
    int result = sidecar_log_adopt_at(container_fd, &log) ==
                     SIDECAR_OPEN_RESUMABLE &&
                 sidecar_log_live_count(&log) == expected;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    if (close(container_fd) != 0)
        fixture_fatal("could not close container directory");
    return result;
}

typedef struct {
    off_t previous;
    size_t count;
    int monotonic;
} ProgressTrace;

static void record_portable_progress(off_t bytes_copied, void *userdata)
{
    ProgressTrace *trace = userdata;
    if (trace == NULL)
        return;
    if (trace->count != 0 && bytes_copied < trace->previous)
        trace->monotonic = 0;
    trace->previous = bytes_copied;
    trace->count++;
}

static void test_prepared_capture_reports_progress(void)
{
    printf(BLUE "::" NC " portable capture reports chunk-level progress\n");
    enum { PROGRESS_SIZE = 131072 };
    char base[PATH_MAX];
    char source[PATH_MAX];
    char scratch[PATH_MAX];
    char container[PATH_MAX];
    char source_file[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(scratch, sizeof(scratch), base, "scratch");
    join_path(container, sizeof(container), base, "container");
    join_path(source_file, sizeof(source_file), source, "large.bin");
    make_directory(source);
    make_directory(scratch);
    make_directory(container);
    write_large_file(source_file, PROGRESS_SIZE);

    PortableRootSpec root = root_spec("ROOT", source, "ROOT");
    PortableCaptureRequest request = request_for(&root, 1, 1);
    int scratch_fd = open_directory(scratch);
    PortablePreparedCapture prepared = {0};
    ProgressTrace trace = { .monotonic = 1 };
    BackupCaptureReport progress_report = {
        .progress_cb = record_portable_progress,
        .progress_userdata = &trace,
        .progress_unthrottled = 1
    };
    int prepare_result = portable_capture_prepare(scratch_fd, &request,
                                                  &prepared);
    int container_fd = open_directory(container);
    size_t live_count = 0;
    int capture_result = prepare_result == 0
        ? portable_capture_fresh_prepared_at(
              container_fd, &request, &prepared, &live_count,
              &progress_report)
        : -1;
    check(capture_result == 0 && live_count != 0,
          "prepared portable capture with a multi-chunk file succeeds");
    check(progress_report.bytes_copied == PROGRESS_SIZE,
          "portable byte accumulation reaches the source size");
    check(trace.count >= 2 && trace.monotonic &&
              trace.previous == PROGRESS_SIZE,
          "portable progress callbacks are monotonic and end at the true total");

    portable_prepared_capture_free(&prepared);
    if (close(scratch_fd) != 0 || close(container_fd) != 0)
        fixture_fatal("could not close portable progress fixture");
    remove_tree(base);
}

static void test_prepare_uses_unclaimed_scratch(void)
{
    printf(BLUE "::" NC " portable capture preparation boundary\n");
    char base[PATH_MAX];
    char source[PATH_MAX];
    char scratch[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(scratch, sizeof(scratch), base, "scratch");
    make_directory(source);
    make_directory(scratch);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source, "file");
    write_file(source_file, "prepared");

    PortableRootSpec root = root_spec("ROOT", source, "ROOT");
    PortableCaptureRequest request = request_for(&root, 1, 1);
    int scratch_fd = open_directory(scratch);
    PortablePreparedCapture prepared = {0};
    int result = portable_capture_prepare(scratch_fd, &request, &prepared);
    check(result == 0 && prepared.ready == 1,
          "prepare succeeds against an unclaimed scratch directory");
    check(directory_is_empty(scratch_fd) == 1,
          "prepare leaves no manifest, data, sidecar, or probe residue");
    portable_prepared_capture_free(&prepared);
    check(prepared.ready == 0 && prepared.manifest.roots == NULL,
          "prepared capture can be freed and reused as a zero object");
    if (close(scratch_fd) != 0)
        fixture_fatal("could not close scratch directory");
    remove_tree(base);
}

static void test_prepared_capture_does_not_prescan_again(void)
{
    printf(BLUE "::" NC " prepared capture reuses its pre-scan\n");
    char base[PATH_MAX];
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char scratch[PATH_MAX];
    char container[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source_a, sizeof(source_a), base, "source-a");
    join_path(source_b, sizeof(source_b), base, "source-b");
    join_path(scratch, sizeof(scratch), base, "scratch");
    join_path(container, sizeof(container), base, "container");
    make_directory(scratch);
    make_directory(container);
    write_file(source_a, "a");
    write_file(source_b, "b");

    PortableRootSpec roots[] = {
        root_spec("A", source_a, "caf\xc3\xa9"),
        root_spec("B", source_b, "CAF\xc3\x89")
    };
    PortableCaptureRequest request = request_for(roots, 2, 0);
    int scratch_fd = open_directory(scratch);
    int container_fd = open_directory(container);
    PortablePreparedCapture prepared = {0};
    portable_capture_test_reset_case_fs_probe_count();
    int prepare_result = portable_capture_prepare(scratch_fd, &request,
                                                  &prepared);
    if (prepare_result != 0) {
        skip_check("host cannot keep the non-ASCII root candidates distinct");
        portable_prepared_capture_free(&prepared);
        close(scratch_fd);
        close(container_fd);
        remove_tree(base);
        return;
    }

    uint64_t probes = portable_capture_test_case_fs_probe_count();
    size_t live_count = 0;
    int capture_result = portable_capture_fresh_prepared_at(
        container_fd, &request, &prepared, &live_count, NULL);
    check(probes != 0 &&
              portable_capture_test_case_fs_probe_count() == probes,
          "prepared capture does not run the pre-scan a second time");
    check(capture_result == 0 && live_count == 2U,
          "prepared fresh capture reports its complete live-entry count");
    check(sidecar_count(container, 2U),
          "the independently adopted sidecar agrees with live_count");

    portable_prepared_capture_free(&prepared);
    if (close(scratch_fd) != 0 || close(container_fd) != 0)
        fixture_fatal("could not close preparation test descriptors");
    remove_tree(base);
}

static void test_resume_live_count(void)
{
    printf(BLUE "::" NC " prepared resume live-entry count\n");
    char base[PATH_MAX];
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char container[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source_a, sizeof(source_a), base, "source-a");
    join_path(source_b, sizeof(source_b), base, "source-b");
    join_path(container, sizeof(container), base, "container");
    make_directory(container);
    write_file(source_a, "a");
    write_file(source_b, "b");

    PortableRootSpec roots[] = {
        root_spec("A", source_a, "A"),
        root_spec("B", source_b, "B")
    };
    PortableCaptureRequest request = request_for(roots, 2, 1);
    int container_fd = open_directory(container);
    PortablePreparedCapture prepared = {0};
    if (portable_capture_prepare(container_fd, &request, &prepared) != 0)
        fixture_fatal("resume fixture preparation failed");

    pid_t child = fork();
    if (child < 0)
        fixture_fatal("could not fork resume fixture");
    if (child == 0) {
        sidecar_test_set_interrupt(SIDECAR_TEST_AFTER_ENTRY_COMMIT);
        int result = portable_capture_fresh_prepared_at(
            container_fd, &request, &prepared, NULL, NULL);
        _exit(result == 0 ? 0 : 3);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        fixture_fatal("could not wait for interrupted capture");
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
          "an interrupted prepared capture leaves a resumable partial");

    portable_prepared_capture_free(&prepared);
    PortablePreparedCapture resumed_plan = {0};
    int prepare_result = portable_capture_prepare(container_fd, &request,
                                                  &resumed_plan);
    size_t live_count = 0;
    int resume_result = prepare_result == 0
        ? portable_capture_resume_prepared_at(container_fd, &request,
                                              &resumed_plan, &live_count, NULL)
        : -1;
    check(resume_result == 0 && live_count == 2U,
          "prepared resume reports adopted plus newly committed entries");
    check(sidecar_count(container, 2U),
          "resumed sidecar live state matches the total count");
    portable_prepared_capture_free(&resumed_plan);
    if (close(container_fd) != 0)
        fixture_fatal("could not close resume container");
    remove_tree(base);
}

static void test_fifo_is_rejected_before_mutation(void)
{
    printf(BLUE "::" NC " FIFO preparation gate\n");
    char base[PATH_MAX];
    char source[PATH_MAX];
    char scratch[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(scratch, sizeof(scratch), base, "scratch");
    make_directory(source);
    make_directory(scratch);
    char fifo[PATH_MAX];
    join_path(fifo, sizeof(fifo), source, "fifo");
    if (mkfifo(fifo, 0600) != 0)
        fixture_fatal("could not create FIFO fixture");

    PortableRootSpec root = root_spec("FIFO", source, "FIFO");
    PortableCaptureRequest request = request_for(&root, 1, 1);
    int scratch_fd = open_directory(scratch);
    PortablePreparedCapture prepared = {0};
    int result = portable_capture_prepare(scratch_fd, &request, &prepared);
    int found_fifo = 0;
    for (size_t index = 0; index < prepared.report.example_count; index++) {
        const PortablePrescanViolation *violation =
            &prepared.report.examples[index];
        if (violation->kind == PORTABLE_PRESCAN_UNSUPPORTED_KIND &&
            strcmp(violation->logical_path, "fifo") == 0)
            found_fifo = 1;
    }
    check(result != 0 && prepared.ready == 0 &&
              prepared.report.unresolved_count >= 1U && found_fifo,
          "FIFO is reported as an unsupported kind before capture");
    check(directory_is_empty(scratch_fd) == 1,
          "FIFO refusal leaves the unclaimed scratch directory untouched");
    portable_prepared_capture_free(&prepared);

    char root_fifo[PATH_MAX];
    join_path(root_fifo, sizeof(root_fifo), base, "root-fifo");
    if (mkfifo(root_fifo, 0600) != 0)
        fixture_fatal("could not create root FIFO fixture");
    PortableRootSpec root_fifo_spec = root_spec("FIFO_ROOT", root_fifo,
                                                "FIFO_ROOT");
    PortableCaptureRequest root_fifo_request = request_for(
        &root_fifo_spec, 1, 1);
    PortablePreparedCapture root_fifo_prepared = {0};
    int root_fifo_result = portable_capture_prepare(
        scratch_fd, &root_fifo_request, &root_fifo_prepared);
    int root_fifo_reported = 0;
    for (size_t index = 0;
         index < root_fifo_prepared.report.example_count; index++) {
        const PortablePrescanViolation *violation =
            &root_fifo_prepared.report.examples[index];
        if (violation->kind == PORTABLE_PRESCAN_UNSUPPORTED_KIND &&
            violation->logical_path[0] == '\0')
            root_fifo_reported = 1;
    }
    check(root_fifo_result != 0 && root_fifo_prepared.ready == 0 &&
              root_fifo_reported,
          "a FIFO selected as the root is rejected before capture");
    check(directory_is_empty(scratch_fd) == 1,
          "root FIFO refusal leaves the scratch directory untouched");
    portable_prepared_capture_free(&root_fifo_prepared);
    if (close(scratch_fd) != 0)
        fixture_fatal("could not close FIFO scratch directory");
    remove_tree(base);
}

static int create_socket_fixture(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return (errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT)
            ? -2 : -1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    strcpy(address.sun_path, path);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved = errno;
        close(fd);
        return (saved == EPERM || saved == EACCES ||
                saved == EAFNOSUPPORT) ? -2 : -1;
    }
    if (close(fd) != 0)
        return -1;
    return 0;
}

static void test_socket_is_informational(void)
{
    printf(BLUE "::" NC " skipped special-file preparation policy\n");
    char base[PATH_MAX];
    char source[PATH_MAX];
    char scratch[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(scratch, sizeof(scratch), base, "scratch");
    make_directory(source);
    make_directory(scratch);
    char socket_path[PATH_MAX];
    join_path(socket_path, sizeof(socket_path), source, "socket");
    int socket_result = create_socket_fixture(socket_path);
    if (socket_result == -2) {
        skip_check("socket fixture unavailable in this sandbox");
        remove_tree(base);
        return;
    }
    if (socket_result != 0) {
        fixture_fatal("could not create socket fixture");
    }

    PortableRootSpec root = root_spec("SOCKET", source, "SOCKET");
    PortableCaptureRequest request = request_for(&root, 1, 1);
    int scratch_fd = open_directory(scratch);
    PortablePreparedCapture prepared = {0};
    int result = portable_capture_prepare(scratch_fd, &request, &prepared);
    check(result == 0 && prepared.ready == 1 &&
              prepared.report.skipped_kind_count >= 1U &&
              prepared.report.unresolved_count == 0,
          "socket is counted as informational and does not refuse prepare");
    check(directory_is_empty(scratch_fd) == 1,
          "socket preparation leaves no scratch residue");
    portable_prepared_capture_free(&prepared);
    if (close(scratch_fd) != 0)
        fixture_fatal("could not close socket scratch directory");
    remove_tree(base);
}

static void test_prepared_at_rejects_invalid_prepared(void)
{
    printf(BLUE "::" NC " prepared capture entry points reject an invalid prepared object\n");
    char base[PATH_MAX];
    char source[PATH_MAX];
    char scratch[PATH_MAX];
    char container[PATH_MAX];
    char resume_container[PATH_MAX];
    make_base(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(scratch, sizeof(scratch), base, "scratch");
    join_path(container, sizeof(container), base, "container");
    join_path(resume_container, sizeof(resume_container), base,
              "resume-container");
    make_directory(source);
    make_directory(scratch);
    make_directory(container);
    make_directory(resume_container);

    PortableRootSpec root = root_spec("ROOT", source, "ROOT");
    PortableCaptureRequest request = request_for(&root, 1, 1);
    int scratch_fd = open_directory(scratch);
    int container_fd = open_directory(container);

    size_t live_count = 0;
    check(portable_capture_fresh_prepared_at(container_fd, &request, NULL,
                                             &live_count, NULL) == -1,
          "fresh_prepared_at with a NULL prepared object is rejected");
    check(portable_capture_resume_prepared_at(container_fd, &request, NULL,
                                              &live_count, NULL) == -1,
          "resume_prepared_at with a NULL prepared object is rejected");

    PortablePreparedCapture not_ready = {0};
    check(portable_capture_fresh_prepared_at(container_fd, &request,
                                             &not_ready, &live_count, NULL) == -1,
          "fresh_prepared_at with a zeroed (never-prepared) object is rejected");
    check(portable_capture_resume_prepared_at(container_fd, &request,
                                              &not_ready, &live_count, NULL) == -1,
          "resume_prepared_at with a zeroed (never-prepared) object is rejected");

    check(directory_is_empty(container_fd) == 1,
          "an invalid prepared object causes no container mutation");

    PortablePreparedCapture prepared = {0};
    int prepare_result = portable_capture_prepare(scratch_fd, &request,
                                                  &prepared);
    check(prepare_result == 0 && prepared.ready == 1,
          "a valid prepared plan is available for the not-ready guard test");
    if (prepare_result == 0 && prepared.ready == 1) {
        prepared.ready = 0;
        check(portable_capture_fresh_prepared_at(container_fd, &request,
                                                 &prepared, &live_count, NULL) == -1,
              "fresh_prepared_at rejects a valid plan marked not-ready");
        check(directory_is_empty(container_fd) == 1,
              "a not-ready fresh plan causes no container mutation");

        int resume_fd = open_directory(resume_container);
        prepared.ready = 1;
        int seed_result = portable_capture_fresh_prepared_at(
            resume_fd, &request, &prepared, NULL, NULL);
        check(seed_result == 0,
              "a valid prepared plan creates a resumable fixture");
        if (seed_result == 0) {
            prepared.ready = 0;
            check(portable_capture_resume_prepared_at(
                      resume_fd, &request, &prepared, &live_count, NULL) == -1,
                  "resume_prepared_at rejects a valid plan marked not-ready");
            check(sidecar_count(resume_container, 1U),
                  "a not-ready resume plan leaves the resumable state intact");
        }
        if (close(resume_fd) != 0)
            fixture_fatal("could not close prepared resume fixture");
    }
    portable_prepared_capture_free(&prepared);

    if (close(scratch_fd) != 0 || close(container_fd) != 0)
        fixture_fatal("could not close guard-test container");
    remove_tree(base);
}

int main(void)
{
    test_prepare_uses_unclaimed_scratch();
    test_prepared_capture_reports_progress();
    test_prepared_capture_does_not_prescan_again();
    test_resume_live_count();
    test_fifo_is_rejected_before_mutation();
    test_socket_is_informational();
    test_prepared_at_rejects_invalid_prepared();
    printf("portable prepare tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
