// Portable restore orchestration tests (docs/DECISIONS.md D17): these fixtures
// exercise the confirmation-gated composition of mutation-free preflight,
// destination metadata probing, and authoritative sidecar replay. They verify
// exact metadata and content on success, prove probe-before-mutation ordering,
// cover probe rejection and dry-run behaviour, and check that no destination
// entry or descriptor is left behind on an aborted restore.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manifest.h"
#include "metadata.h"
#include "portable_restore.h"
#include "sidecar.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void fatal(const char *message)
{
    fprintf(stderr, "portable restore orchestration fixture failure: %s\n",
            message);
    exit(2);
}

static int remove_callback(const char *path, const struct stat *st,
                           int type, struct FTW *state)
{
    (void)st;
    (void)type;
    (void)state;
    return remove(path);
}

static int chmod_directory_callback(const char *path, const struct stat *st,
                                    int type, struct FTW *state)
{
    (void)st;
    (void)state;
    if (type == FTW_D && chmod(path, 0700) != 0)
        return -1;
    return 0;
}

static void remove_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT)
            return;
        fatal("could not inspect fixture tree");
    }
    if (nftw(path, chmod_directory_callback, 16, FTW_PHYS) != 0 ||
        nftw(path, remove_callback, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fatal("could not remove fixture tree");
}

static void path_join_fixture(char *out, size_t out_size, const char *base,
                              const char *suffix)
{
    size_t base_length = strlen(base);
    size_t suffix_length = strlen(suffix);
    if (base_length >= out_size ||
        suffix_length > out_size - base_length - 1U)
        fatal("fixture path is too long");
    memcpy(out, base, base_length);
    memcpy(out + base_length, suffix, suffix_length + 1U);
}

static int open_dir(const char *path)
{
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static void make_dir_at(int parent_fd, const char *name, mode_t mode)
{
    if (mkdirat(parent_fd, name, mode) != 0)
        fatal("could not create fixture directory");
}

static void write_file_at(int parent_fd, const char *name, const char *text)
{
    int fd = openat(parent_fd, name,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(text);
    if (fd < 0 || write(fd, text, length) != (ssize_t)length ||
        close(fd) != 0)
        fatal("could not write fixture file");
}

static int file_equals(const char *path, const char *expected)
{
    int fd = open(path, O_RDONLY | O_NOATIME | O_CLOEXEC);
    if (fd < 0)
        return 0;
    size_t length = strlen(expected);
    char buffer[256];
    ssize_t received = read(fd, buffer, sizeof(buffer));
    int result = received == (ssize_t)length &&
                 memcmp(buffer, expected, length) == 0;
    if (close(fd) != 0)
        result = 0;
    return result;
}

static int metadata_exact(const char *path, mode_t mode, uid_t uid, gid_t gid,
                          int64_t atime_sec, long atime_nsec,
                          int64_t mtime_sec, long mtime_nsec)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (st.st_mode & 07777) == mode && st.st_uid == uid &&
           st.st_gid == gid && st.st_atim.tv_sec == (time_t)atime_sec &&
           st.st_atim.tv_nsec == atime_nsec &&
           st.st_mtim.tv_sec == (time_t)mtime_sec &&
           st.st_mtim.tv_nsec == mtime_nsec;
}

static SidecarBytes text_bytes(const char *text)
{
    return (SidecarBytes){
        .data = (const unsigned char *)text,
        .length = strlen(text)
    };
}

static SidecarEntry entry_for(const char *root, const char *logical,
                              const char *physical, SidecarObjectKind kind,
                              uint64_t size, uint32_t mode, uint32_t uid,
                              uint32_t gid, int64_t atime_sec,
                              uint32_t atime_nsec, int64_t mtime_sec,
                              uint32_t mtime_nsec)
{
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = text_bytes(root);
    entry.logical_path = text_bytes(logical);
    entry.physical_path = text_bytes(physical);
    entry.kind = kind;
    entry.mode = mode;
    entry.uid = uid;
    entry.gid = gid;
    entry.atime_sec = atime_sec;
    entry.atime_nsec = atime_nsec;
    entry.mtime_sec = mtime_sec;
    entry.mtime_nsec = mtime_nsec;
    entry.size = size;
    return entry;
}

static ManifestRoot root_for(void)
{
    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    snprintf(root.id, sizeof(root.id), "ROOT");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    snprintf(root.payload_path, sizeof(root.payload_path), "ROOT");
    snprintf(root.source_path, sizeof(root.source_path), "/source/ROOT");
    root.has_restore_path = 1;
    snprintf(root.restore_path, sizeof(root.restore_path), "restored");
    return root;
}

typedef struct {
    char base[PATH_MAX];
    char container[PATH_MAX];
    char home[PATH_MAX];
    int container_fd;
    int data_fd;
    int home_fd;
} Fixture;

static void fixture_close(Fixture *fixture)
{
    if (fixture == NULL)
        return;
    if (fixture->data_fd >= 0)
        close(fixture->data_fd);
    if (fixture->home_fd >= 0)
        close(fixture->home_fd);
    if (fixture->container_fd >= 0)
        close(fixture->container_fd);
    remove_tree(fixture->base);
}

static int fixture_open(Fixture *fixture, ManifestRoot *root)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->container_fd = -1;
    fixture->data_fd = -1;
    fixture->home_fd = -1;
    if (snprintf(fixture->base, sizeof(fixture->base),
                 "/tmp/migr_portable_orchestrate_XXXXXX") < 0 ||
        mkdtemp(fixture->base) == NULL)
        return -1;
    path_join_fixture(fixture->container, sizeof(fixture->container),
                      fixture->base, "/container");
    path_join_fixture(fixture->home, sizeof(fixture->home), fixture->base,
                      "/home");
    if (mkdir(fixture->container, 0700) != 0 ||
        mkdir(fixture->home, 0700) != 0)
    {
        fixture_close(fixture);
        return -1;
    }
    fixture->container_fd = open_dir(fixture->container);
    fixture->home_fd = open_dir(fixture->home);
    if (fixture->container_fd < 0 || fixture->home_fd < 0)
    {
        fixture_close(fixture);
        return -1;
    }
    if (mkdirat(fixture->container_fd, "data", 0700) != 0)
    {
        fixture_close(fixture);
        return -1;
    }
    fixture->data_fd = openat(fixture->container_fd, "data",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->data_fd < 0)
    {
        fixture_close(fixture);
        return -1;
    }

    Manifest manifest = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = 1,
        .roots = root
    };
    if (manifest_write_v1_at(fixture->container_fd, &manifest) != 0)
    {
        fixture_close(fixture);
        return -1;
    }
    return 0;
}

static int append_entries(SidecarLog *log, const SidecarEntry *entries,
                          size_t count)
{
    for (size_t index = 0; index < count; index++)
    {
        if (sidecar_log_append_entry(log, &entries[index]) !=
                SIDECAR_STATUS_OK ||
            sidecar_log_append_entry_commit(log) != SIDECAR_STATUS_OK)
            return -1;
    }
    return 0;
}

static int write_sidecar(Fixture *fixture, const SidecarEntry *entries,
                         size_t count)
{
    SidecarLog log = {0};
    if (sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH ||
        append_entries(&log, entries, count) != 0 ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return -1;
    return 0;
}

static int open_fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL)
        return -1;
    int count = 0;
    while (readdir(directory) != NULL)
        count++;
    if (closedir(directory) != 0)
        return -1;
    return count - 2;
}

static int directory_entry_count(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR *directory = fdopendir(fd);
    if (directory == NULL)
    {
        close(fd);
        return -1;
    }
    int count = 0;
    while (readdir(directory) != NULL)
        count++;
    if (closedir(directory) != 0)
        return -1;
    return count;
}

typedef struct {
    int saved_stdin;
} ConfirmationInput;

static void confirmation_begin(ConfirmationInput *input, const char *answer)
{
    if (input == NULL || answer == NULL)
        fatal("invalid confirmation fixture");
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0 ||
        write(pipe_fds[1], answer, strlen(answer)) != (ssize_t)strlen(answer) ||
        close(pipe_fds[1]) != 0)
        fatal("could not prepare confirmation input");
    input->saved_stdin = dup(STDIN_FILENO);
    if (input->saved_stdin < 0 || dup2(pipe_fds[0], STDIN_FILENO) < 0 ||
        close(pipe_fds[0]) != 0)
        fatal("could not redirect confirmation input");
}

static void confirmation_end(ConfirmationInput *input)
{
    if (input == NULL || input->saved_stdin < 0)
        fatal("invalid confirmation state");
    if (dup2(input->saved_stdin, STDIN_FILENO) < 0 ||
        close(input->saved_stdin) != 0)
        fatal("could not restore confirmation input");
    input->saved_stdin = -1;
}

typedef struct {
    char sentinel[PATH_MAX];
    char target[PATH_MAX];
    int called;
    int sentinel_untouched;
    int target_absent;
} ProbeObservation;

static void probe_observer(void *context)
{
    ProbeObservation *observation = context;
    if (observation == NULL)
        return;
    observation->called = 1;
    observation->sentinel_untouched = file_equals(observation->sentinel,
                                                  "untouched");
    observation->target_absent = access(observation->target, F_OK) != 0;
}

static PortableRestoreRequest request_for(Fixture *fixture,
                                          Manifest *manifest,
                                          int nsec_exact)
{
    PortableRestoreRequest request = {
        .source_container_fd = fixture->container_fd,
        .manifest = manifest,
        .destination_home_fd = fixture->home_fd,
        .destination_timestamp_policy = {
            .nsec_exact = nsec_exact,
            .configured = 1
        }
    };
    return request;
}

static int run_orchestration(Fixture *fixture, PortableRestoreReplayReport *report,
                             int nsec_exact, const char *answer)
{
    Manifest manifest;
    if (manifest_read_v1_at(fixture->container_fd, &manifest) !=
            MANIFEST_STATUS_VALID)
        return -1;
    PortableRestoreRequest request = request_for(fixture, &manifest,
                                                  nsec_exact);
    ConfirmationInput input = { .saved_stdin = -1 };
    confirmation_begin(&input, answer);
    int result = portable_restore_at(&request, report);
    confirmation_end(&input);
    manifest_free(&manifest);
    return result;
}

static void build_payload(Fixture *fixture, int nested)
{
    make_dir_at(fixture->data_fd, "ROOT", 0700);
    int root_fd = openat(fixture->data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open payload root");
    if (nested)
    {
        make_dir_at(root_fd, "nested", 0700);
        int nested_fd = openat(root_fd, "nested",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (nested_fd < 0)
            fatal("could not open nested payload directory");
        write_file_at(nested_fd, "file", "portable payload");
        close(nested_fd);
    }
    else
        write_file_at(root_fd, "file", "portable payload");
    close(root_fd);
}

static void test_normal_orchestration(void)
{
    printf(BLUE "::" NC " end-to-end portable restore orchestration\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "normal orchestration fixture is created");
    if (opened != 0)
        return;
    build_payload(&fixture, 1);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000000, 123456789, 1700000010, 987654321),
        entry_for("ROOT", "nested", "nested", SIDECAR_KIND_DIRECTORY, 0,
                  0700, uid, gid, 1700000020, 111111111, 1700000030,
                  222222222),
        entry_for("ROOT", "nested/file", "nested/file",
                  SIDECAR_KIND_REGULAR, strlen("portable payload"), 0640,
                  uid, gid, 1700000040, 333333333, 1700000050, 444444444)
    };
    check(write_sidecar(&fixture, entries, 3) == 0,
          "normal orchestration sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");

    char sentinel[PATH_MAX], target[PATH_MAX];
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    ProbeObservation observation = {
        .sentinel_untouched = 0,
        .target_absent = 0
    };
    snprintf(observation.sentinel, sizeof(observation.sentinel), "%s", sentinel);
    snprintf(observation.target, sizeof(observation.target), "%s", target);
    metadata_test_reset_probe_count();
    metadata_test_set_probe_hook(probe_observer, &observation);

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    metadata_test_set_probe_hook(NULL, NULL);
    check(result == 0 && report.live_count == 3 &&
              report.applied_count == 3 && report.failed_count == 0,
          "confirmation, probe, replay, and summary complete successfully");
    check(metadata_test_probe_count() == 1 && observation.called &&
              observation.sentinel_untouched && observation.target_absent,
          "probe runs before the first persistent destination mutation");

    char nested[PATH_MAX], file[PATH_MAX];
    path_join_fixture(nested, sizeof(nested), fixture.home, "/restored/nested");
    path_join_fixture(file, sizeof(file), nested, "/file");
    check(file_equals(file, "portable payload"),
          "portable payload content is restored");
    check(metadata_exact(file, 0640, (uid_t)uid, (gid_t)gid,
                         1700000040, 333333333, 1700000050, 444444444),
          "regular metadata uses the measured exact-nsec policy");
    check(metadata_exact(nested, 0700, (uid_t)uid, (gid_t)gid,
                         1700000020, 111111111, 1700000030, 222222222),
          "nested directory metadata is applied post-order");
    check(file_equals(sentinel, "untouched"),
          "unrelated destination content remains untouched");
    fixture_close(&fixture);
}

static void test_probe_rejection(void)
{
    printf(BLUE "::" NC " confirmation followed by probe rejection\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "probe-rejection fixture is created");
    if (opened != 0)
        return;
    build_payload(&fixture, 0);
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  (uint32_t)geteuid(), gid, 1700000100, 1, 1700000101, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR,
                  strlen("portable payload"), 0600, UINT32_MAX, gid,
                  1700000102, 3, 1700000103, 4)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "probe-rejection sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");

    char sentinel[PATH_MAX], target[PATH_MAX];
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    ProbeObservation observation = {0};
    snprintf(observation.sentinel, sizeof(observation.sentinel), "%s", sentinel);
    snprintf(observation.target, sizeof(observation.target), "%s", target);
    metadata_test_reset_probe_count();
    metadata_test_set_probe_hook(probe_observer, &observation);
    int before_fds = open_fd_count();
    int before_entries = directory_entry_count(fixture.home);

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    metadata_test_set_probe_hook(NULL, NULL);
    int after_fds = open_fd_count();
    int after_entries = directory_entry_count(fixture.home);
    check(result != 0 && metadata_test_probe_count() == 1,
          "confirmation is followed by a rejecting ownership probe");
    check(observation.called && observation.sentinel_untouched &&
              observation.target_absent,
          "probe observes an untouched destination before replay");
    check(access(target, F_OK) != 0 && file_equals(sentinel, "untouched") &&
              before_entries >= 0 && after_entries == before_entries,
          "probe rejection leaves no named destination entry");
    check(before_fds >= 0 && after_fds == before_fds,
          "probe rejection leaves no descriptor residue");
    fixture_close(&fixture);
}

static void test_dry_run(void)
{
    printf(BLUE "::" NC " dry-run orchestration\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "dry-run fixture is created");
    if (opened != 0)
        return;
    build_payload(&fixture, 1);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000200, 1, 1700000201, 2),
        entry_for("ROOT", "nested", "nested", SIDECAR_KIND_DIRECTORY, 0,
                  0700, uid, gid, 1700000202, 3, 1700000203, 4),
        entry_for("ROOT", "nested/file", "nested/file",
                  SIDECAR_KIND_REGULAR, strlen("portable payload"), 0600,
                  uid, gid, 1700000204, 5, 1700000205, 6)
    };
    check(write_sidecar(&fixture, entries, 3) == 0,
          "dry-run sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX], target[PATH_MAX];
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    metadata_test_reset_probe_count();
    metadata_test_set_probe_hook(probe_observer, NULL);
    int previous_dry_run = dry_run;
    dry_run = 1;
    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 0, "y\n");
    dry_run = previous_dry_run;
    metadata_test_set_probe_hook(NULL, NULL);
    check(result == 0 && report.live_count == 3 && report.applied_count == 0 &&
              report.failed_count == 0,
          "dry-run returns the preflight summary without replay");
    check(metadata_test_probe_count() == 0 && access(target, F_OK) != 0 &&
              file_equals(sentinel, "untouched"),
          "dry-run fires no probe and performs no destination mutation");
    fixture_close(&fixture);
}

static void test_coarse_timestamp_policy(void)
{
    printf(BLUE "::" NC " coarse destination timestamp policy\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "coarse-policy fixture is created");
    if (opened != 0)
        return;
    build_payload(&fixture, 0);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000300, 123456789, 1700000301, 987654321),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR,
                  strlen("portable payload"), 0600, uid, gid,
                  1700000302, 333333333, 1700000303, 444444444)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "coarse-policy sidecar is committed");
    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 0, "y\n");
    check(result == 0 && report.applied_count == 2,
          "coarse-policy replay completes");
    char file[PATH_MAX];
    path_join_fixture(file, sizeof(file), fixture.home, "/restored/file");
    check(metadata_exact(file, 0600, (uid_t)uid, (gid_t)gid,
                         1700000302, 0, 1700000303, 0),
          "coarse policy canonicalizes both timestamps to zero nanoseconds");
    fixture_close(&fixture);
}

int main(void)
{
    test_normal_orchestration();
    test_probe_rejection();
    test_dry_run();
    test_coarse_timestamp_policy();
    printf("%s%s%s\n", failures == 0 ? GREEN : RED,
           failures == 0 ? "all portable restore orchestration tests passed" :
           "portable restore orchestration tests failed", NC);
    return failures == 0 ? 0 : 1;
}
