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

#include "backup.h"
#include "manifest.h"
#include "metadata.h"
#include "fsprobe.h"
#include "portable_restore.h"
#include "sidecar.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
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

static void force_no_free_space(off_t needed, off_t *free_bytes,
                                void *context)
{
    (void)needed;
    (void)context;
    if (free_bytes != NULL)
        *free_bytes = 0;
}

static void set_test_block_size(off_t *block_size, void *context)
{
    if (block_size != NULL && context != NULL)
        *block_size = *(const off_t *)context;
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

static int symlink_exact(const char *path, const char *target, mode_t mode,
                         uid_t uid, gid_t gid, int64_t atime_sec,
                         long atime_nsec, int64_t mtime_sec,
                         long mtime_nsec)
{
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISLNK(st.st_mode) ||
        (st.st_mode & 07777) != mode || st.st_uid != uid ||
        st.st_gid != gid || st.st_atim.tv_sec != (time_t)atime_sec ||
        st.st_atim.tv_nsec != atime_nsec ||
        st.st_mtim.tv_sec != (time_t)mtime_sec ||
        st.st_mtim.tv_nsec != mtime_nsec)
        return 0;

    char actual[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    ssize_t length = readlink(path, actual, sizeof(actual) - 1U);
    size_t expected_length = strlen(target);
    if (length < 0 || (size_t)length != expected_length)
        return 0;
    actual[length] = '\0';
    return memcmp(actual, target, expected_length) == 0;
}

typedef struct {
    char base[PATH_MAX];
    char container[PATH_MAX];
    char home[PATH_MAX];
    char xdg_dirs[XDG_KEY_COUNT][PATH_MAX];
    int container_fd;
    int data_fd;
    int home_fd;
} Fixture;

typedef struct {
    char sentinel[PATH_MAX];
    char target[PATH_MAX];
    int called;
    int sentinel_untouched;
    int target_absent;
} ProbeObservation;

static SidecarBytes text_bytes(const char *text);
static SidecarEntry entry_for(const char *root, const char *logical,
                              const char *physical, SidecarObjectKind kind,
                              uint64_t size, uint32_t mode, uint32_t uid,
                              uint32_t gid, int64_t atime_sec,
                              uint32_t atime_nsec, int64_t mtime_sec,
                              uint32_t mtime_nsec);
static ManifestRoot root_for(void);
static void fixture_close(Fixture *fixture);
static int fixture_open(Fixture *fixture, ManifestRoot *root);
static int write_sidecar(Fixture *fixture, const SidecarEntry *entries,
                         size_t count);
static void probe_observer(void *context);
static int run_orchestration(Fixture *fixture,
                             PortableRestoreReplayReport *report,
                             int nsec_exact, const char *answer);
static PortableRestoreOutcome run_direct_orchestration(
    Fixture *fixture, PortableRestoreReplayReport *report, int nsec_exact,
    const char *answer);

static void build_symlink_payload(Fixture *fixture)
{
    make_dir_at(fixture->data_fd, "ROOT", 0700);
    write_file_at(fixture->data_fd, "ROOT/link", "");
    write_file_at(fixture->home_fd, "sentinel_target", "untouched");
}

static void build_hardlink_payload(Fixture *fixture)
{
    make_dir_at(fixture->data_fd, "ROOT", 0700);
    int root_fd = openat(fixture->data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open hardlink payload root");
    write_file_at(root_fd, "alias", "");
    write_file_at(root_fd, "representative", "hardlink payload");
    if (close(root_fd) != 0)
        fatal("could not close hardlink payload root");
}

static void test_symlink_orchestration(void)
{
    printf(BLUE "::" NC " end-to-end portable symlink replay\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "symlink orchestration fixture is created");
    if (opened != 0)
        return;

    build_symlink_payload(&fixture);
    struct stat root_st;
    int root_stat_ok = fstatat(fixture.data_fd, "ROOT", &root_st,
                               AT_SYMLINK_NOFOLLOW) == 0 &&
                       S_ISDIR(root_st.st_mode) && root_st.st_size >= 0;
    check(root_stat_ok, "symlink fixture records its source directory size");
    if (!root_stat_ok)
    {
        fixture_close(&fixture);
        return;
    }
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY,
                  (uint64_t)root_st.st_size, 0700,
                  uid, gid, 1700000400, 123, 1700000401, 456),
        entry_for("ROOT", "link", "link", SIDECAR_KIND_SYMLINK, 0, 0711,
                  uid, gid, 1700000410, 123456789, 1700000420, 987654321)
    };
    entries[1].symlink_target = text_bytes("../sentinel_target");
    check(write_sidecar(&fixture, entries, 2) == 0,
          "symlink orchestration sidecar is committed");

    Manifest manifest;
    int manifest_status = manifest_read_v1_at(fixture.container_fd,
                                               &manifest);
    PortableRestorePreflightReport preflight;
    portable_restore_preflight_report_init(&preflight);
    PortableRestoreRequest preflight_request = {
        .source_container_fd = fixture.container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture.home_fd,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    int preflight_result = manifest_status == MANIFEST_STATUS_VALID
        ? portable_restore_preflight_at(&preflight_request, &preflight) : -1;
    check(preflight_result == 0 && preflight.live_count == 2 &&
              preflight.violation_count == 0 && preflight.root_count == 1 &&
              preflight.estimated_bytes ==
                  root_st.st_size + (off_t)strlen("../sentinel_target") &&
              preflight.roots != NULL && preflight.roots[0].live_count == 2,
          "symlink participates in the full preflight inventory");
    portable_restore_preflight_report_free(&preflight);
    if (manifest_status == MANIFEST_STATUS_VALID)
        manifest_free(&manifest);

    char sentinel[PATH_MAX], target[PATH_MAX], target_link[PATH_MAX];
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home,
                      "/sentinel_target");
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    path_join_fixture(target_link, sizeof(target_link), target, "/link");
    ProbeObservation observation = {0};
    snprintf(observation.sentinel, sizeof(observation.sentinel), "%s",
             sentinel);
    snprintf(observation.target, sizeof(observation.target), "%s",
             target_link);
    metadata_test_reset_probe_count();
    metadata_test_set_probe_hook(probe_observer, &observation);

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    metadata_test_set_probe_hook(NULL, NULL);
    check(result == 0 && report.live_count == 2 &&
              report.applied_count == 2 && report.failed_count == 0,
          "confirmation, probe, and symlink replay complete successfully");
    check(metadata_test_probe_count() == 1 && observation.called &&
              observation.sentinel_untouched && observation.target_absent,
          "symlink probe runs before its destination is created");
    check(symlink_exact(target_link, "../sentinel_target", 0777,
                        (uid_t)uid, (gid_t)gid, 1700000410, 123456789,
                        1700000420, 987654321),
          "destination symlink target and no-follow metadata are exact");
    struct stat target_st;
    check(stat(sentinel, &target_st) == 0 && S_ISREG(target_st.st_mode) &&
              (target_st.st_mode & 07777) == 0600 &&
              file_equals(sentinel, "untouched"),
          "symlink metadata never follows and changes its target");
    struct stat placeholder;
    check(fstatat(fixture.data_fd, "ROOT/link", &placeholder,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(placeholder.st_mode) &&
              placeholder.st_size == 0,
          "empty payload placeholder remains an untouched regular file");
    fixture_close(&fixture);
}

static void test_symlink_ownership_rejection(void)
{
    printf(BLUE "::" NC " symlink ownership probe rejection\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "symlink ownership fixture is created");
    if (opened != 0)
        return;

    build_symlink_payload(&fixture);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000500, 1, 1700000501, 2),
        entry_for("ROOT", "link", "link", SIDECAR_KIND_SYMLINK, 0, 0700,
                  UINT32_MAX, gid, 1700000510, 3, 1700000511, 4)
    };
    entries[1].symlink_target = text_bytes("target");
    check(write_sidecar(&fixture, entries, 2) == 0,
          "symlink ownership sidecar is committed");

    Manifest manifest;
    check(manifest_read_v1_at(fixture.container_fd, &manifest) ==
              MANIFEST_STATUS_VALID, "symlink ownership manifest is readable");
    PortableRestorePreflightReport preflight;
    portable_restore_preflight_report_init(&preflight);
    PortableRestoreRequest request = {
        .source_container_fd = fixture.container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture.home_fd,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    int preflight_result = portable_restore_preflight_at(&request, &preflight);
    check(preflight_result == 0 && preflight.violation_count == 0 &&
              preflight.live_count == 2 && preflight.profiles.count != 0 &&
              preflight.profiles.affected_objects != 0,
          "foreign symlink ownership reaches the metadata profile");
    portable_restore_preflight_report_free(&preflight);
    manifest_free(&manifest);

    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX], target[PATH_MAX];
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    ProbeObservation observation = {0};
    snprintf(observation.sentinel, sizeof(observation.sentinel), "%s",
             sentinel);
    snprintf(observation.target, sizeof(observation.target), "%s", target);
    metadata_test_reset_probe_count();
    metadata_test_set_probe_hook(probe_observer, &observation);
    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    metadata_test_set_probe_hook(NULL, NULL);
    check(result != 0 && metadata_test_probe_count() == 1 &&
              report.live_count == 2 && report.applied_count == 0,
          "foreign symlink ownership is refused by the post-confirmation probe");
    check(observation.called && observation.sentinel_untouched &&
              observation.target_absent && access(target, F_OK) != 0,
          "ownership rejection leaves no destination mutation");
    fixture_close(&fixture);
}

static void test_symlink_destination_conflict(void)
{
    printf(BLUE "::" NC " portable symlink destination conflict\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "symlink conflict fixture is created");
    if (opened != 0)
        return;

    build_symlink_payload(&fixture);
    make_dir_at(fixture.home_fd, "restored", 0700);
    int restored_fd = openat(fixture.home_fd, "restored",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (restored_fd < 0)
        fatal("could not open symlink conflict destination");
    write_file_at(restored_fd, "link", "existing");
    close(restored_fd);

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000600, 1, 1700000601, 2),
        entry_for("ROOT", "link", "link", SIDECAR_KIND_SYMLINK, 0, 0777,
                  uid, gid, 1700000610, 3, 1700000611, 4)
    };
    entries[1].symlink_target = text_bytes("target");
    check(write_sidecar(&fixture, entries, 2) == 0,
          "symlink conflict sidecar is committed");
    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result != 0 && report.live_count == 2 &&
              report.applied_count == 0 && report.failed_count == 1 &&
              strcmp(report.failed_logical_path, "link") == 0,
          "existing destination leaf is rejected as a replay conflict");
    char existing[PATH_MAX];
    path_join_fixture(existing, sizeof(existing), fixture.home,
                      "/restored/link");
    check(file_equals(existing, "existing"),
          "destination conflict leaves the existing regular file intact");
    fixture_close(&fixture);
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
        SidecarClaim claim = {
            .root_id = entries[index].root_id,
            .logical_path = entries[index].logical_path,
            .physical_path = entries[index].physical_path,
            .kind = entries[index].kind
        };
        if (sidecar_log_append_claim(log, &claim) != SIDECAR_STATUS_OK)
            return -1;
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

static int write_sidecar_with_xattr(Fixture *fixture,
                                    const SidecarEntry *entries, size_t count,
                                    size_t xattr_index,
                                    const SidecarXattr *xattr)
{
    SidecarLog log = {0};
    if (fixture == NULL || entries == NULL || xattr == NULL ||
        xattr_index >= count ||
        sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH)
        return -1;

    int failed = 0;
    for (size_t index = 0; index < count; index++)
    {
        SidecarClaim claim = {
            .root_id = entries[index].root_id,
            .logical_path = entries[index].logical_path,
            .physical_path = entries[index].physical_path,
            .kind = entries[index].kind
        };
        if (sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK ||
            sidecar_log_append_entry(&log, &entries[index]) !=
                SIDECAR_STATUS_OK ||
            (index == xattr_index &&
             sidecar_log_append_xattr(&log, xattr) != SIDECAR_STATUS_OK) ||
            sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK)
        {
            failed = 1;
            break;
        }
    }
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        failed = 1;
    return failed ? -1 : 0;
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

typedef struct {
    int saved_stdout;
    int saved_stderr;
    FILE *file;
} OutputCapture;

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

static void output_capture_begin(OutputCapture *capture)
{
    if (capture == NULL)
        fatal("invalid output capture fixture");
    fflush(stdout);
    fflush(stderr);
    capture->file = tmpfile();
    capture->saved_stdout = dup(STDOUT_FILENO);
    capture->saved_stderr = dup(STDERR_FILENO);
    if (capture->file == NULL || capture->saved_stdout < 0 ||
        capture->saved_stderr < 0 ||
        dup2(fileno(capture->file), STDOUT_FILENO) < 0 ||
        dup2(fileno(capture->file), STDERR_FILENO) < 0)
        fatal("could not redirect restore output");
}

static void output_capture_end(OutputCapture *capture, char *output,
                               size_t output_size)
{
    if (capture == NULL || capture->file == NULL ||
        capture->saved_stdout < 0 || capture->saved_stderr < 0 ||
        output == NULL || output_size == 0)
        fatal("invalid output capture state");
    fflush(stdout);
    fflush(stderr);
    if (dup2(capture->saved_stdout, STDOUT_FILENO) < 0 ||
        dup2(capture->saved_stderr, STDERR_FILENO) < 0 ||
        close(capture->saved_stdout) != 0 ||
        close(capture->saved_stderr) != 0)
        fatal("could not restore restore output");
    capture->saved_stdout = -1;
    capture->saved_stderr = -1;
    rewind(capture->file);
    size_t received = fread(output, 1, output_size - 1U, capture->file);
    if (ferror(capture->file))
        fatal("could not read captured restore output");
    output[received] = '\0';
    if (fclose(capture->file) != 0)
        fatal("could not close captured restore output");
    capture->file = NULL;
}

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
        .destination_home_path = fixture->home,
        .destination_timestamp_policy = {
            .nsec_exact = nsec_exact,
            .configured = 1
        }
    };
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        request.destination_xdg_dirs[index] =
            fixture->xdg_dirs[index][0] == '\0'
                ? NULL : fixture->xdg_dirs[index];
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

static int prepare_direct_basic_fixture(Fixture *fixture, uint32_t file_uid)
{
    build_payload(fixture, 0);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700001000, 123456789, 1700001001, 987654321),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR,
                  strlen("portable payload"), 0600, file_uid, gid,
                  1700001002, 333333333, 1700001003, 444444444)
    };
    if (write_sidecar(fixture, entries, 2) != 0)
        return -1;
    write_file_at(fixture->home_fd, "sentinel", "untouched");
    return 0;
}

/* Every other exit path in portable_restore_orchestrate_impl() zero-
 * initializes its out-param report before returning; the parameter-
 * validation early return used to skip it, leaving the caller's report
 * holding whatever was on the stack. Filling it with a non-zero sentinel
 * before the call makes an accidental "still zero from declaration"
 * pass impossible -- the report only reads as zeroed if the function
 * actually wrote it. */
static void test_invalid_request_still_zeroes_report(void)
{
    printf(BLUE "::" NC
           " invalid request still zero-initializes the report\n");

    PortableRestoreReplayReport report;
    memset(&report, 0xAA, sizeof(report));

    PortableRestoreRequest request = {0};
    PortableRestoreOutcome outcome =
        portable_restore_orchestrate_at(&request, &report);

    PortableRestoreReplayReport zeroed = {0};
    check(outcome == PORTABLE_RESTORE_ERROR,
          "a request with a NULL manifest is refused");
    check(memcmp(&report, &zeroed, sizeof(report)) == 0,
          "the report is zero-initialized even on the parameter-validation "
          "early return, not left holding stack garbage");
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
    struct stat root_st, nested_st;
    int directory_stats_ok =
        fstatat(fixture.data_fd, "ROOT", &root_st,
                AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(root_st.st_mode) &&
        root_st.st_size >= 0 &&
        fstatat(fixture.data_fd, "ROOT/nested", &nested_st,
                AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(nested_st.st_mode) &&
        nested_st.st_size >= 0;
    check(directory_stats_ok,
          "nested directory fixture records source directory sizes");
    if (!directory_stats_ok)
    {
        fixture_close(&fixture);
        return;
    }
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY,
                  (uint64_t)root_st.st_size, 0700,
                  uid, gid, 1700000000, 123456789, 1700000010, 987654321),
        entry_for("ROOT", "nested", "nested", SIDECAR_KIND_DIRECTORY,
                  (uint64_t)nested_st.st_size, 0700, uid, gid, 1700000020,
                  111111111, 1700000030, 222222222),
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

static void test_security_xattr_tolerance_orchestration(void)
{
    printf(BLUE "::" NC " portable security.* xattr tolerance orchestration\n");
    if (geteuid() == 0)
    {
        printf("  " YELLOW "-" NC
               " security.* set-refusal orchestration skipped: root can "
               "apply the fixture attribute\n");
        return;
    }

    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "security.* tolerance fixture is created");
    if (opened != 0)
        return;

    build_payload(&fixture, 0);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700001100, 1, 1700001101, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR,
                  strlen("portable payload"), 0600, uid, gid,
                  1700001102, 3, 1700001103, 4)
    };
    static const unsigned char security_name[] = "security.migr_test";
    static const unsigned char security_value[] = "probe";
    SidecarXattr security_xattr = {
        .name = {
            .data = security_name,
            .length = sizeof(security_name) - 1U
        },
        .value = {
            .data = security_value,
            .length = sizeof(security_value) - 1U
        }
    };
    entries[1].xattr_count = 1;
    check(write_sidecar_with_xattr(&fixture, entries, 2, 1,
                                   &security_xattr) == 0,
          "security.* tolerance sidecar is committed");

    Manifest manifest;
    int manifest_status = manifest_read_v1_at(fixture.container_fd,
                                               &manifest);
    PortableRestorePreflightReport preflight;
    portable_restore_preflight_report_init(&preflight);
    PortableRestoreRequest preflight_request = {
        .source_container_fd = fixture.container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture.home_fd,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    int preflight_result = manifest_status == MANIFEST_STATUS_VALID
        ? portable_restore_preflight_at(&preflight_request, &preflight) : -1;
    check(preflight_result == 0 &&
              preflight.profiles.security_xattr_entry_count == 1,
          "preflight counts the entry carrying security.*");
    portable_restore_preflight_report_free(&preflight);
    if (manifest_status == MANIFEST_STATUS_VALID)
        manifest_free(&manifest);

    PortableRestoreReplayReport report;
    char output[4096];
    OutputCapture capture;
    output_capture_begin(&capture);
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    output_capture_end(&capture, output, sizeof(output));
    check(result == 0 && report.live_count == 2 && report.applied_count == 2 &&
              report.failed_count == 0 &&
              report.skipped_security_xattr_count >= 1,
          "security.* set refusal does not abort portable replay");
    check(strstr(output, "carrying security.* attributes") != NULL &&
              strstr(output, "only the attribute will be skipped") != NULL,
          "the existing confirmation prompt includes the security warning");
    char summary_marker[128];
    int summary_length = snprintf(
        summary_marker, sizeof(summary_marker), "Portable restore skipped %zu "
        "security.* attribute", report.skipped_security_xattr_count);
    check(summary_length >= 0 && (size_t)summary_length < sizeof(summary_marker) &&
              strstr(output, summary_marker) != NULL,
          "the final portable summary reports the tolerated attributes");
    char file[PATH_MAX];
    path_join_fixture(file, sizeof(file), fixture.home, "/restored/file");
    check(file_equals(file, "portable payload"),
          "portable replay preserves content when security.* is skipped");
    fixture_close(&fixture);
}

static void test_hardlink_orchestration(void)
{
    printf(BLUE "::" NC " end-to-end portable hardlink replay\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "hardlink orchestration fixture is created");
    if (opened != 0)
        return;

    build_hardlink_payload(&fixture);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000700, 1, 1700000701, 2),
        entry_for("ROOT", "representative", "representative",
                  SIDECAR_KIND_REGULAR, strlen("hardlink payload"), 0640,
                  uid, gid, 1700000710, 3, 1700000711, 4),
        entry_for("ROOT", "alias", "alias", SIDECAR_KIND_HARDLINK, 0,
                  0640, uid, gid, 1700000720, 5, 1700000721, 6)
    };
    entries[2].hardlink_root_id = text_bytes("ROOT");
    entries[2].hardlink_logical_path = text_bytes("representative");
    check(write_sidecar(&fixture, entries, 3) == 0,
          "hardlink orchestration sidecar is committed");

    struct stat placeholder_before;
    check(fstatat(fixture.data_fd, "ROOT/alias", &placeholder_before,
                  AT_SYMLINK_NOFOLLOW) == 0 &&
              S_ISREG(placeholder_before.st_mode) &&
              placeholder_before.st_size == 0,
          "hardlink payload placeholder starts as an empty regular file");

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result == 0 && report.live_count == 3 &&
              report.applied_count == 3 && report.failed_count == 0,
          "hardlink replay succeeds with a complete summary");

    char representative[PATH_MAX], alias[PATH_MAX];
    path_join_fixture(representative, sizeof(representative), fixture.home,
                      "/restored/representative");
    path_join_fixture(alias, sizeof(alias), fixture.home, "/restored/alias");
    struct stat representative_st, alias_st, placeholder_after;
    check(stat(representative, &representative_st) == 0 &&
              stat(alias, &alias_st) == 0 &&
              S_ISREG(representative_st.st_mode) &&
              S_ISREG(alias_st.st_mode) &&
              representative_st.st_dev == alias_st.st_dev &&
              representative_st.st_ino == alias_st.st_ino &&
              file_equals(alias, "hardlink payload"),
          "hardlink destination shares the representative inode and content");
    check(metadata_exact(representative, 0640, (uid_t)uid, (gid_t)gid,
                         1700000710, 3, 1700000711, 4),
          "hardlink uses the representative's metadata without reapplying it");
    check(fstatat(fixture.data_fd, "ROOT/alias", &placeholder_after,
                  AT_SYMLINK_NOFOLLOW) == 0 &&
              placeholder_after.st_dev == placeholder_before.st_dev &&
              placeholder_after.st_ino == placeholder_before.st_ino &&
              placeholder_after.st_size == 0,
          "hardlink payload placeholder remains untouched");
    fixture_close(&fixture);
}

static void test_hardlink_cross_root(void)
{
    printf(BLUE "::" NC " portable hardlink cross-root reference\n");
    ManifestRoot roots[2] = { root_for(), root_for() };
    snprintf(roots[0].id, sizeof(roots[0].id), "ROOT_A");
    snprintf(roots[0].payload_path, sizeof(roots[0].payload_path),
             "ROOT_A");
    snprintf(roots[0].source_path, sizeof(roots[0].source_path),
             "/source/ROOT_A");
    snprintf(roots[0].restore_path, sizeof(roots[0].restore_path),
             "restored-a");
    snprintf(roots[1].id, sizeof(roots[1].id), "ROOT_B");
    snprintf(roots[1].payload_path, sizeof(roots[1].payload_path),
             "ROOT_B");
    snprintf(roots[1].source_path, sizeof(roots[1].source_path),
             "/source/ROOT_B");
    snprintf(roots[1].restore_path, sizeof(roots[1].restore_path),
             "restored-b");

    Fixture fixture;
    int opened = fixture_open(&fixture, &roots[0]);
    check(opened == 0, "cross-root hardlink fixture is created");
    if (opened != 0)
        return;
    Manifest manifest_model = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = 2,
        .roots = roots
    };
    check(manifest_write_v1_at(fixture.container_fd, &manifest_model) == 0,
          "cross-root manifest is committed");

    make_dir_at(fixture.data_fd, "ROOT_A", 0700);
    make_dir_at(fixture.data_fd, "ROOT_B", 0700);
    int root_a_fd = openat(fixture.data_fd, "ROOT_A",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int root_b_fd = openat(fixture.data_fd, "ROOT_B",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_a_fd < 0 || root_b_fd < 0)
        fatal("could not open cross-root payload roots");
    write_file_at(root_a_fd, "representative", "cross-root payload");
    write_file_at(root_b_fd, "alias", "");
    if (close(root_a_fd) != 0 || close(root_b_fd) != 0)
        fatal("could not close cross-root payload roots");

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT_A", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000800, 1, 1700000801, 2),
        entry_for("ROOT_A", "representative", "representative",
                  SIDECAR_KIND_REGULAR, strlen("cross-root payload"), 0640,
                  uid, gid, 1700000810, 3, 1700000811, 4),
        entry_for("ROOT_B", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000820, 5, 1700000821, 6),
        entry_for("ROOT_B", "alias", "alias", SIDECAR_KIND_HARDLINK, 0,
                  0640, uid, gid, 1700000830, 7, 1700000831, 8)
    };
    entries[3].hardlink_root_id = text_bytes("ROOT_A");
    entries[3].hardlink_logical_path = text_bytes("representative");
    check(write_sidecar(&fixture, entries, 4) == 0,
          "cross-root hardlink sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result == 0 && report.live_count == 4 &&
              report.applied_count == 4 && report.failed_count == 0,
          "cross-root hardlink replay succeeds");
    char representative[PATH_MAX], alias[PATH_MAX];
    path_join_fixture(representative, sizeof(representative), fixture.home,
                      "/restored-a/representative");
    path_join_fixture(alias, sizeof(alias), fixture.home,
                      "/restored-b/alias");
    struct stat representative_st, alias_st;
    check(stat(representative, &representative_st) == 0 &&
              stat(alias, &alias_st) == 0 &&
              representative_st.st_dev == alias_st.st_dev &&
              representative_st.st_ino == alias_st.st_ino &&
              file_equals(alias, "cross-root payload"),
          "cross-root hardlink shares the referenced inode");
    fixture_close(&fixture);
}

static void test_hardlink_cross_root_invalid_xdg_reference(void)
{
    printf(BLUE "::" NC
           " portable hardlink rejects an invalid XDG reference root\n");
    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));
    snprintf(roots[0].id, sizeof(roots[0].id), "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    snprintf(roots[0].payload_path, sizeof(roots[0].payload_path),
             "XDG_DOCUMENTS_DIR");
    snprintf(roots[0].source_path, sizeof(roots[0].source_path),
             "/source/XDG_DOCUMENTS_DIR");
    roots[1] = root_for();
    snprintf(roots[1].id, sizeof(roots[1].id), "ROOT_B");
    snprintf(roots[1].payload_path, sizeof(roots[1].payload_path),
             "ROOT_B");
    snprintf(roots[1].source_path, sizeof(roots[1].source_path),
             "/source/ROOT_B");
    snprintf(roots[1].restore_path, sizeof(roots[1].restore_path),
             "restored-b");

    Fixture fixture;
    int opened = fixture_open(&fixture, &roots[0]);
    check(opened == 0, "invalid-XDG hardlink fixture is created");
    if (opened != 0)
        return;

    Manifest manifest_model = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = 2,
        .roots = roots
    };
    check(manifest_write_v1_at(fixture.container_fd, &manifest_model) == 0,
          "invalid-XDG hardlink manifest is committed");

    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    make_dir_at(fixture.data_fd, "ROOT_B", 0700);
    int reference_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int alias_root_fd = openat(fixture.data_fd, "ROOT_B",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (reference_fd < 0 || alias_root_fd < 0)
        fatal("could not open invalid-XDG hardlink payload roots");
    write_file_at(reference_fd, "representative", "cross-root payload");
    write_file_at(alias_root_fd, "alias", "");
    if (close(reference_fd) != 0 || close(alias_root_fd) != 0)
        fatal("could not close invalid-XDG hardlink payload roots");

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0700, uid, gid, 1700000840, 1, 1700000841, 2),
        entry_for("XDG_DOCUMENTS_DIR", "representative", "representative",
                  SIDECAR_KIND_REGULAR, strlen("cross-root payload"), 0640,
                  uid, gid, 1700000850, 3, 1700000851, 4),
        entry_for("ROOT_B", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000860, 5, 1700000861, 6),
        entry_for("ROOT_B", "alias", "alias", SIDECAR_KIND_HARDLINK, 0,
                  0640, uid, gid, 1700000870, 7, 1700000871, 8)
    };
    entries[3].hardlink_root_id = text_bytes("XDG_DOCUMENTS_DIR");
    entries[3].hardlink_logical_path = text_bytes("representative");
    check(write_sidecar(&fixture, entries, 4) == 0,
          "invalid-XDG hardlink sidecar is committed");

    /* This exercises replay_manifest_valid()'s upfront XDG gate, not the
     * hardlink-reference branch in replay_collect_entry(). Every possible
     * hardlink reference root comes from manifest->roots[], so this gate
     * already rejects this manifest before collection starts; no current test
     * can distinguish the old and new replay_collect_entry() behavior here.
     * The invariant covered is that an unresolved XDG root referenced only
     * through a hardlink still gets a complete refusal without mutation. */
    PortableRestoreRequest request = {
        .source_container_fd = fixture.container_fd,
        .manifest = &manifest_model,
        .destination_home_fd = fixture.home_fd,
        .destination_home_path = fixture.home,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    PortableRestoreReplayReport report;
    portable_restore_replay_report_init(&report);
    int result = portable_restore_replay_at(&request, &report);
    char destination_root[PATH_MAX];
    path_join_fixture(destination_root, sizeof(destination_root),
                      fixture.home, "/restored-b");
    check(result != 0 && report.failed_count != 0 &&
              access(destination_root, F_OK) != 0,
          "an unresolved XDG hardlink reference is refused before replay");
    fixture_close(&fixture);
}

static void test_xdg_destination_orchestration(void)
{
    printf(BLUE "::" NC " portable XDG destination orchestration\n");
    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));
    snprintf(roots[0].id, sizeof(roots[0].id), "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    snprintf(roots[0].payload_path, sizeof(roots[0].payload_path),
             "XDG_DOCUMENTS_DIR");
    snprintf(roots[0].source_path, sizeof(roots[0].source_path),
             "/source/XDG_DOCUMENTS_DIR");
    snprintf(roots[1].id, sizeof(roots[1].id), "XDG_DOWNLOAD_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    snprintf(roots[1].payload_path, sizeof(roots[1].payload_path),
             "XDG_DOWNLOAD_DIR");
    snprintf(roots[1].source_path, sizeof(roots[1].source_path),
             "/source/XDG_DOWNLOAD_DIR");

    Fixture fixture;
    int opened = fixture_open(&fixture, &roots[0]);
    check(opened == 0, "XDG destination fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.home_fd, "Documents", 0700);
    make_dir_at(fixture.home_fd, "Downloads", 0700);
    path_join_fixture(fixture.xdg_dirs[0], sizeof(fixture.xdg_dirs[0]),
                      fixture.home, "/Documents");
    path_join_fixture(fixture.xdg_dirs[1], sizeof(fixture.xdg_dirs[1]),
                      fixture.home, "/Downloads");

    Manifest manifest_model = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_CRITICAL,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = 2,
        .roots = roots
    };
    check(manifest_write_v1_at(fixture.container_fd, &manifest_model) == 0,
          "XDG destination manifest is committed");

    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    make_dir_at(fixture.data_fd, "XDG_DOWNLOAD_DIR", 0700);
    int documents_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int downloads_fd = openat(fixture.data_fd, "XDG_DOWNLOAD_DIR",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (documents_fd < 0 || downloads_fd < 0)
        fatal("could not open XDG payload roots");
    write_file_at(documents_fd, "note.txt", "documents payload");
    write_file_at(downloads_fd, "note.txt", "downloads payload");
    if (close(documents_fd) != 0 || close(downloads_fd) != 0)
        fatal("could not close XDG payload roots");

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001100, 1, 1700001101, 2),
        entry_for("XDG_DOCUMENTS_DIR", "note.txt", "note.txt",
                  SIDECAR_KIND_REGULAR, strlen("documents payload"), 0600,
                  uid, gid, 1700001110, 3, 1700001111, 4),
        entry_for("XDG_DOWNLOAD_DIR", "", "", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001120, 5, 1700001121, 6),
        entry_for("XDG_DOWNLOAD_DIR", "note.txt", "note.txt",
                  SIDECAR_KIND_REGULAR, strlen("downloads payload"), 0600,
                  uid, gid, 1700001130, 7, 1700001131, 8)
    };
    check(write_sidecar(&fixture, entries, 4) == 0,
          "XDG destination sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result == 0 && report.live_count == 4 &&
              report.applied_count == 4 && report.failed_count == 0,
          "portable XDG restore completes for both roots");

    char documents_note[PATH_MAX], downloads_note[PATH_MAX], flattened[PATH_MAX];
    path_join_fixture(documents_note, sizeof(documents_note), fixture.home,
                      "/Documents/note.txt");
    path_join_fixture(downloads_note, sizeof(downloads_note), fixture.home,
                      "/Downloads/note.txt");
    path_join_fixture(flattened, sizeof(flattened), fixture.home, "/note.txt");
    check(file_equals(documents_note, "documents payload") &&
              file_equals(downloads_note, "downloads payload") &&
              access(flattened, F_OK) != 0,
          "XDG roots restore under their resolved directories without flattening");
    fixture_close(&fixture);
}

static void test_xdg_missing_destination_anchor_cache(void)
{
    printf(BLUE "::" NC " portable XDG missing-destination anchor cache\n");
    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    snprintf(root.id, sizeof(root.id), "XDG_DOCUMENTS_DIR");
    root.policy = ROOT_POLICY_XDG;
    snprintf(root.payload_path, sizeof(root.payload_path), "XDG_DOCUMENTS_DIR");
    snprintf(root.source_path, sizeof(root.source_path),
             "/source/XDG_DOCUMENTS_DIR");

    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "missing-XDG destination fixture is created");
    if (opened != 0)
        return;
    path_join_fixture(fixture.xdg_dirs[0], sizeof(fixture.xdg_dirs[0]),
                      fixture.home, "/MissingDocuments");

    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    int root_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open missing-XDG payload root");
    write_file_at(root_fd, "first.txt", "first payload");
    write_file_at(root_fd, "second.txt", "second payload");
    if (close(root_fd) != 0)
        fatal("could not close missing-XDG payload root");

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001140, 1, 1700001141, 2),
        entry_for("XDG_DOCUMENTS_DIR", "first.txt", "first.txt",
                  SIDECAR_KIND_REGULAR, strlen("first payload"), 0600,
                  uid, gid, 1700001150, 3, 1700001151, 4),
        entry_for("XDG_DOCUMENTS_DIR", "second.txt", "second.txt",
                  SIDECAR_KIND_REGULAR, strlen("second payload"), 0600,
                  uid, gid, 1700001160, 5, 1700001161, 6)
    };
    check(write_sidecar(&fixture, entries, 3) == 0,
          "missing-XDG destination sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result == 0 && report.live_count == 3 &&
              report.applied_count == 3 && report.failed_count == 0,
          "portable XDG restore creates and reuses a missing destination");

    char first[PATH_MAX], second[PATH_MAX];
    path_join_fixture(first, sizeof(first), fixture.home,
                      "/MissingDocuments/first.txt");
    path_join_fixture(second, sizeof(second), fixture.home,
                      "/MissingDocuments/second.txt");
    check(file_equals(first, "first payload") &&
              file_equals(second, "second payload"),
          "cached parent anchor restores every entry to the new XDG directory");
    fixture_close(&fixture);
}

static void test_parent_cache_distinguishes_destination_bases(void)
{
    printf(BLUE "::" NC " portable parent cache distinguishes destination bases\n");
    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));
    snprintf(roots[0].id, sizeof(roots[0].id), "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    snprintf(roots[0].payload_path, sizeof(roots[0].payload_path),
             "XDG_DOCUMENTS_DIR");
    snprintf(roots[0].source_path, sizeof(roots[0].source_path),
             "/source/XDG_DOCUMENTS_DIR");
    roots[1] = root_for();
    snprintf(roots[1].id, sizeof(roots[1].id), "ROOT_HOME");
    snprintf(roots[1].payload_path, sizeof(roots[1].payload_path),
             "ROOT_HOME");
    snprintf(roots[1].source_path, sizeof(roots[1].source_path),
             "/source/ROOT_HOME");
    snprintf(roots[1].restore_path, sizeof(roots[1].restore_path), "shared");

    Fixture fixture;
    int opened = fixture_open(&fixture, &roots[0]);
    check(opened == 0, "mixed-base parent-cache fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.home_fd, "Documents", 0700);
    path_join_fixture(fixture.xdg_dirs[0], sizeof(fixture.xdg_dirs[0]),
                      fixture.home, "/Documents");

    Manifest manifest_model = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = 2,
        .roots = roots
    };
    check(manifest_write_v1_at(fixture.container_fd, &manifest_model) == 0,
          "mixed-base parent-cache manifest is committed");

    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    make_dir_at(fixture.data_fd, "ROOT_HOME", 0700);
    int xdg_root_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int home_root_fd = openat(fixture.data_fd, "ROOT_HOME",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (xdg_root_fd < 0 || home_root_fd < 0)
        fatal("could not open mixed-base payload roots");
    make_dir_at(xdg_root_fd, "shared", 0700);
    int xdg_shared_fd = openat(xdg_root_fd, "shared",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (xdg_shared_fd < 0)
        fatal("could not open mixed-base XDG payload parent");
    write_file_at(xdg_shared_fd, "xdg-a.txt", "xdg a payload");
    write_file_at(xdg_shared_fd, "xdg-c.txt", "xdg c payload");
    write_file_at(home_root_fd, "home-b.txt", "home b payload");
    write_file_at(home_root_fd, "home-d.txt", "home d payload");
    if (close(xdg_shared_fd) != 0 || close(xdg_root_fd) != 0 ||
        close(home_root_fd) != 0)
        fatal("could not close mixed-base payload roots");

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001170, 1, 1700001171, 2),
        entry_for("XDG_DOCUMENTS_DIR", "shared", "shared",
                  SIDECAR_KIND_DIRECTORY, 0, 0700, uid, gid,
                  1700001180, 3, 1700001181, 4),
        entry_for("XDG_DOCUMENTS_DIR", "shared/xdg-a.txt",
                  "shared/xdg-a.txt", SIDECAR_KIND_REGULAR,
                  strlen("xdg a payload"), 0600, uid, gid,
                  1700001190, 5, 1700001191, 6),
        entry_for("XDG_DOCUMENTS_DIR", "shared/xdg-c.txt",
                  "shared/xdg-c.txt", SIDECAR_KIND_REGULAR,
                  strlen("xdg c payload"), 0600, uid, gid,
                  1700001200, 7, 1700001201, 8),
        entry_for("ROOT_HOME", "", "", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001210, 9, 1700001211, 10),
        entry_for("ROOT_HOME", "home-b.txt", "home-b.txt",
                  SIDECAR_KIND_REGULAR, strlen("home b payload"), 0600,
                  uid, gid, 1700001220, 11, 1700001221, 12),
        entry_for("ROOT_HOME", "home-d.txt", "home-d.txt",
                  SIDECAR_KIND_REGULAR, strlen("home d payload"), 0600,
                  uid, gid, 1700001230, 13, 1700001231, 14)
    };
    check(write_sidecar(&fixture, entries, 7) == 0,
          "mixed-base parent-cache sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result == 0 && report.live_count == 7 &&
              report.applied_count == 7 && report.failed_count == 0,
          "mixed-base restore completes with one bounded parent cache");

    char home_b[PATH_MAX], home_d[PATH_MAX];
    char xdg_a[PATH_MAX], xdg_c[PATH_MAX];
    char wrong_home_xdg_a[PATH_MAX], wrong_xdg_home_b[PATH_MAX];
    path_join_fixture(home_b, sizeof(home_b), fixture.home,
                      "/shared/home-b.txt");
    path_join_fixture(home_d, sizeof(home_d), fixture.home,
                      "/shared/home-d.txt");
    path_join_fixture(xdg_a, sizeof(xdg_a), fixture.home,
                      "/Documents/shared/xdg-a.txt");
    path_join_fixture(xdg_c, sizeof(xdg_c), fixture.home,
                      "/Documents/shared/xdg-c.txt");
    path_join_fixture(wrong_home_xdg_a, sizeof(wrong_home_xdg_a), fixture.home,
                      "/shared/xdg-a.txt");
    path_join_fixture(wrong_xdg_home_b, sizeof(wrong_xdg_home_b), fixture.home,
                      "/Documents/shared/home-b.txt");
    check(file_equals(home_b, "home b payload") &&
              file_equals(home_d, "home d payload") &&
              file_equals(xdg_a, "xdg a payload") &&
              file_equals(xdg_c, "xdg c payload") &&
              access(wrong_home_xdg_a, F_OK) != 0 &&
              access(wrong_xdg_home_b, F_OK) != 0,
          "same parent prefix never crosses the HOME and XDG base descriptors");
    fixture_close(&fixture);
}

static void test_payload_parent_cache_preserves_directory_identity(void)
{
    printf(BLUE "::" NC " portable payload parent cache preserves directory identity\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "payload parent-cache fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    int root_fd = openat(fixture.data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open payload parent-cache root");
    make_dir_at(root_fd, "dir-a", 0700);
    make_dir_at(root_fd, "dir-b", 0700);
    int dir_a_fd = openat(root_fd, "dir-a",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int dir_b_fd = openat(root_fd, "dir-b",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_a_fd < 0 || dir_b_fd < 0)
        fatal("could not open payload parent-cache directories");
    write_file_at(dir_a_fd, "other.txt", "alpha other payload");
    write_file_at(dir_a_fd, "same.txt", "alpha payload");
    write_file_at(dir_b_fd, "other.txt", "bravo other payload");
    write_file_at(dir_b_fd, "same.txt", "bravo payload");
    if (close(dir_a_fd) != 0 || close(dir_b_fd) != 0 || close(root_fd) != 0)
        fatal("could not close payload parent-cache directories");

    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001240, 1, 1700001241, 2),
        entry_for("ROOT", "dir-a", "dir-a", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001250, 3, 1700001251, 4),
        entry_for("ROOT", "dir-b", "dir-b", SIDECAR_KIND_DIRECTORY,
                  0, 0700, uid, gid, 1700001260, 5, 1700001261, 6),
        entry_for("ROOT", "dir-a/other.txt", "dir-a/other.txt",
                  SIDECAR_KIND_REGULAR, strlen("alpha other payload"), 0600,
                  uid, gid, 1700001270, 7, 1700001271, 8),
        entry_for("ROOT", "dir-a/same.txt", "dir-a/same.txt",
                  SIDECAR_KIND_REGULAR, strlen("alpha payload"), 0600,
                  uid, gid, 1700001280, 9, 1700001281, 10),
        entry_for("ROOT", "dir-b/other.txt", "dir-b/other.txt",
                  SIDECAR_KIND_REGULAR, strlen("bravo other payload"), 0600,
                  uid, gid, 1700001290, 11, 1700001291, 12),
        entry_for("ROOT", "dir-b/same.txt", "dir-b/same.txt",
                  SIDECAR_KIND_REGULAR, strlen("bravo payload"), 0600,
                  uid, gid, 1700001300, 13, 1700001301, 14)
    };
    check(write_sidecar(&fixture, entries, 7) == 0,
          "payload parent-cache sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_orchestration(&fixture, &report, 1, "y\n");
    check(result == 0 && report.live_count == 7 &&
              report.applied_count == 7 && report.failed_count == 0,
          "payload parent-cache restore completes");

    char a_other[PATH_MAX], a_same[PATH_MAX];
    char b_other[PATH_MAX], b_same[PATH_MAX];
    path_join_fixture(a_other, sizeof(a_other), fixture.home,
                      "/restored/dir-a/other.txt");
    path_join_fixture(a_same, sizeof(a_same), fixture.home,
                      "/restored/dir-a/same.txt");
    path_join_fixture(b_other, sizeof(b_other), fixture.home,
                      "/restored/dir-b/other.txt");
    path_join_fixture(b_same, sizeof(b_same), fixture.home,
                      "/restored/dir-b/same.txt");
    check(file_equals(a_other, "alpha other payload") &&
              file_equals(a_same, "alpha payload") &&
              file_equals(b_other, "bravo other payload") &&
              file_equals(b_same, "bravo payload"),
          "cached payload parents preserve same-name contents by directory");
    fixture_close(&fixture);
}

static void assert_hardlink_reference_refused(Fixture *fixture,
                                               const SidecarEntry *entries,
                                               size_t count,
                                               const char *label)
{
    check(write_sidecar(fixture, entries, count) == 0,
          "malformed hardlink sidecar is committed");
    PortableRestoreReplayReport report;
    int result = run_orchestration(fixture, &report, 1, "y\n");
    char destination[PATH_MAX];
    path_join_fixture(destination, sizeof(destination), fixture->home,
                      "/restored/alias");
    char root_destination[PATH_MAX];
    path_join_fixture(root_destination, sizeof(root_destination),
                      fixture->home, "/restored");
    check(result != 0 && report.failed_count != 0 &&
              strcmp(report.failed_logical_path, "alias") == 0 &&
              access(destination, F_OK) != 0 &&
              access(root_destination, F_OK) != 0, label);
}

static void test_hardlink_reference_failures(void)
{
    printf(BLUE "::" NC " malformed portable hardlink references\n");
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();

    ManifestRoot missing_root = root_for();
    Fixture missing_fixture;
    int opened = fixture_open(&missing_fixture, &missing_root);
    check(opened == 0, "missing-reference fixture is created");
    if (opened == 0)
    {
        build_hardlink_payload(&missing_fixture);
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                      uid, gid, 1700000900, 1, 1700000901, 2),
            entry_for("ROOT", "representative", "representative",
                      SIDECAR_KIND_REGULAR, strlen("hardlink payload"), 0640,
                      uid, gid, 1700000905, 2, 1700000906, 3),
            entry_for("ROOT", "alias", "alias", SIDECAR_KIND_HARDLINK, 0,
                      0640, uid, gid, 1700000910, 3, 1700000911, 4)
        };
        entries[2].hardlink_root_id = text_bytes("ROOT");
        entries[2].hardlink_logical_path = text_bytes("missing");
        assert_hardlink_reference_refused(
            &missing_fixture, entries, 3,
            "a hardlink with a missing reference is refused before replay");
        fixture_close(&missing_fixture);
    }

    ManifestRoot self_root = root_for();
    Fixture self_fixture;
    opened = fixture_open(&self_fixture, &self_root);
    check(opened == 0, "self-reference fixture is created");
    if (opened == 0)
    {
        build_hardlink_payload(&self_fixture);
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                      uid, gid, 1700000920, 5, 1700000921, 6),
            entry_for("ROOT", "representative", "representative",
                      SIDECAR_KIND_REGULAR, strlen("hardlink payload"), 0640,
                      uid, gid, 1700000925, 6, 1700000926, 7),
            entry_for("ROOT", "alias", "alias", SIDECAR_KIND_HARDLINK, 0,
                      0640, uid, gid, 1700000930, 7, 1700000931, 8)
        };
        entries[2].hardlink_root_id = text_bytes("ROOT");
        entries[2].hardlink_logical_path = text_bytes("alias");
        assert_hardlink_reference_refused(
            &self_fixture, entries, 3,
            "a self-referencing hardlink is refused before replay");
        fixture_close(&self_fixture);
    }

    ManifestRoot nonregular_root = root_for();
    Fixture nonregular_fixture;
    opened = fixture_open(&nonregular_fixture, &nonregular_root);
    check(opened == 0, "non-regular-reference fixture is created");
    if (opened == 0)
    {
        make_dir_at(nonregular_fixture.data_fd, "ROOT", 0700);
        int root_fd = openat(nonregular_fixture.data_fd, "ROOT",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (root_fd < 0)
            fatal("could not open non-regular hardlink payload root");
        make_dir_at(root_fd, "target", 0700);
        write_file_at(root_fd, "alias", "");
        if (close(root_fd) != 0)
            fatal("could not close non-regular hardlink payload root");
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                      uid, gid, 1700000940, 9, 1700000941, 10),
            entry_for("ROOT", "target", "target", SIDECAR_KIND_DIRECTORY,
                      0, 0700, uid, gid, 1700000950, 11, 1700000951, 12),
            entry_for("ROOT", "alias", "alias", SIDECAR_KIND_HARDLINK, 0,
                      0640, uid, gid, 1700000960, 13, 1700000961, 14)
        };
        entries[2].hardlink_root_id = text_bytes("ROOT");
        entries[2].hardlink_logical_path = text_bytes("target");
        assert_hardlink_reference_refused(
            &nonregular_fixture, entries, 3,
            "a hardlink targeting a directory is refused before replay");
        fixture_close(&nonregular_fixture);
    }
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

static void test_destination_space_preflight(void)
{
    printf(BLUE "::" NC " portable restore free-space preflight\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "space-preflight fixture is created");
    if (opened != 0)
        return;

    build_payload(&fixture, 0);
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  uid, gid, 1700000700, 1, 1700000701, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR,
                  strlen("portable payload"), 0600, uid, gid,
                  1700000702, 3, 1700000703, 4)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "space-preflight sidecar is committed");

    off_t block_size = 1;
    backup_test_set_block_size_hook(set_test_block_size, &block_size);
    backup_test_set_free_space_hook(force_no_free_space, NULL);
    int previous_dry_run = dry_run;
    char live_output[4096];
    char dry_output[4096];
    OutputCapture capture;

    dry_run = 0;
    PortableRestoreReplayReport live_report;
    output_capture_begin(&capture);
    int live_result = run_orchestration(&fixture, &live_report, 1, "y\n");
    output_capture_end(&capture, live_output, sizeof(live_output));

    dry_run = 1;
    PortableRestoreReplayReport dry_report;
    output_capture_begin(&capture);
    int dry_result = run_orchestration(&fixture, &dry_report, 1, "y\n");
    output_capture_end(&capture, dry_output, sizeof(dry_output));

    char error_marker[PATH_MAX + 64];
    int marker_length = snprintf(error_marker, sizeof(error_marker),
                                 "Error: not enough free space at %s (need ",
                                 fixture.home);
    int marker_valid = marker_length >= 0 &&
                       (size_t)marker_length < sizeof(error_marker);
    check(marker_valid && live_result != 0 && live_report.live_count == 2 &&
              strstr(live_output, "Estimated restore size: 16B") != NULL &&
              strstr(live_output, "Destination free space: 0B") != NULL &&
              strstr(live_output, error_marker) != NULL &&
              strstr(live_output, "Continue?") == NULL,
          "portable live restore refuses before confirmation when space is insufficient");
    check(marker_valid && dry_result != 0 && dry_report.live_count == 2 &&
              strstr(dry_output, "Estimated restore size: 16B") != NULL &&
              strstr(dry_output, "Destination free space: 0B") != NULL &&
              strstr(dry_output, error_marker) != NULL &&
              strstr(dry_output, "Continue?") == NULL,
          "portable dry-run refuses before preview when space is insufficient");

    char restored[PATH_MAX];
    path_join_fixture(restored, sizeof(restored), fixture.home, "/restored");
    check(access(restored, F_OK) != 0,
          "portable space refusal leaves the destination untouched");

    dry_run = previous_dry_run;
    backup_test_set_block_size_hook(NULL, NULL);
    backup_test_set_free_space_hook(NULL, NULL);
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

static PortableRestoreOutcome run_direct_orchestration(
    Fixture *fixture, PortableRestoreReplayReport *report, int nsec_exact,
    const char *answer)
{
    Manifest manifest;
    if (manifest_read_v1_at(fixture->container_fd, &manifest) !=
            MANIFEST_STATUS_VALID)
        return PORTABLE_RESTORE_ERROR;
    PortableRestoreRequest request = request_for(fixture, &manifest,
                                                  nsec_exact);
    ConfirmationInput input = { .saved_stdin = -1 };
    confirmation_begin(&input, answer);
    PortableRestoreOutcome outcome =
        portable_restore_orchestrate_at(&request, report);
    confirmation_end(&input);
    manifest_free(&manifest);
    return outcome;
}

static void test_direct_complete_outcome(void)
{
    printf(BLUE "::" NC " direct portable restore complete outcome\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "direct-complete fixture is created");
    if (opened != 0)
        return;
    check(prepare_direct_basic_fixture(&fixture, (uint32_t)geteuid()) == 0,
          "direct-complete sidecar is committed");
    PortableRestoreReplayReport report;
    PortableRestoreOutcome outcome = run_direct_orchestration(
        &fixture, &report, 0, "y\n");
    check(outcome == PORTABLE_RESTORE_COMPLETE && report.live_count == 2 &&
              report.applied_count == 2 && report.failed_count == 0,
          "direct orchestration reports a complete restore distinctly");
    char file[PATH_MAX];
    path_join_fixture(file, sizeof(file), fixture.home, "/restored/file");
    check(file_equals(file, "portable payload"),
          "direct complete outcome leaves restored content");
    fixture_close(&fixture);
}

static void test_direct_dry_run_outcome(void)
{
    printf(BLUE "::" NC " direct portable restore dry-run outcome\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "direct-dry-run fixture is created");
    if (opened != 0)
        return;
    check(prepare_direct_basic_fixture(&fixture, (uint32_t)geteuid()) == 0,
          "direct-dry-run sidecar is committed");
    int previous_dry_run = dry_run;
    dry_run = 1;
    PortableRestoreReplayReport report;
    PortableRestoreOutcome outcome = run_direct_orchestration(
        &fixture, &report, 1, "y\n");
    dry_run = previous_dry_run;
    char target[PATH_MAX], sentinel[PATH_MAX];
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(outcome == PORTABLE_RESTORE_DRY_RUN && report.live_count == 2 &&
              report.applied_count == 0 && report.failed_count == 0,
          "direct orchestration reports a dry-run distinctly");
    check(access(target, F_OK) != 0 && file_equals(sentinel, "untouched"),
          "direct dry-run performs no destination mutation");
    fixture_close(&fixture);
}

static void test_direct_cancelled_outcome(void)
{
    printf(BLUE "::" NC " direct portable restore cancelled outcome\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "direct-cancelled fixture is created");
    if (opened != 0)
        return;
    check(prepare_direct_basic_fixture(&fixture, (uint32_t)geteuid()) == 0,
          "direct-cancelled sidecar is committed");
    PortableRestoreReplayReport report;
    PortableRestoreOutcome outcome = run_direct_orchestration(
        &fixture, &report, 1, "n\n");
    char target[PATH_MAX], sentinel[PATH_MAX];
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(outcome == PORTABLE_RESTORE_CANCELLED && report.live_count == 0 &&
              report.applied_count == 0 && report.failed_count == 0,
          "direct orchestration reports cancellation distinctly");
    check(access(target, F_OK) != 0 && file_equals(sentinel, "untouched"),
          "cancelled direct restore performs no destination mutation");
    fixture_close(&fixture);
}

static void test_direct_error_outcome(void)
{
    printf(BLUE "::" NC " direct portable restore error outcome\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "direct-error fixture is created");
    if (opened != 0)
        return;
    check(prepare_direct_basic_fixture(&fixture, UINT32_MAX) == 0,
          "direct-error sidecar is committed");
    PortableRestoreReplayReport report;
    PortableRestoreOutcome outcome = run_direct_orchestration(
        &fixture, &report, 1, "y\n");
    char target[PATH_MAX], sentinel[PATH_MAX];
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(outcome == PORTABLE_RESTORE_ERROR && report.live_count == 2 &&
              report.applied_count == 0 && report.failed_count == 0,
          "direct orchestration reports probe failure distinctly");
    check(access(target, F_OK) != 0 && file_equals(sentinel, "untouched"),
          "direct probe failure performs no destination mutation");
    fixture_close(&fixture);
}

/* fsprobe_timestamps_fd() needs to create a scratch probe directory under
 * the destination to measure timestamp-write support; removing write
 * permission on the destination makes that probe fail cleanly without
 * affecting the earlier preflight/space-preflight stages, which only need
 * to read. This isolates the fsprobe_timestamps_fd() failure branch
 * specifically (root_probe timestamp measurement), distinct from
 * test_direct_error_outcome's metadata-probe failure (a bad file owner
 * uid) a few lines later in the same function. */
static void test_direct_timestamp_probe_failure(void)
{
    printf(BLUE "::" NC " direct portable restore timestamp probe failure\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "direct-timestamp-probe-failure fixture is created");
    if (opened != 0)
        return;
    check(prepare_direct_basic_fixture(&fixture, (uint32_t)geteuid()) == 0,
          "direct-timestamp-probe-failure sidecar is committed");
    check(fchmod(fixture.home_fd, 0500) == 0,
          "destination home is made read-only");
    PortableRestoreReplayReport report;
    PortableRestoreOutcome outcome = run_direct_orchestration(
        &fixture, &report, 1, "y\n");
    fchmod(fixture.home_fd, 0700);
    char target[PATH_MAX], sentinel[PATH_MAX];
    path_join_fixture(target, sizeof(target), fixture.home, "/restored");
    path_join_fixture(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(outcome == PORTABLE_RESTORE_ERROR && report.live_count == 2 &&
              report.applied_count == 0 && report.failed_count == 0,
          "direct orchestration reports the timestamp probe failure with "
          "the live count already discovered by preflight, not zero");
    check(access(target, F_OK) != 0 && file_equals(sentinel, "untouched"),
          "direct timestamp probe failure performs no destination mutation");
    fixture_close(&fixture);
}

static void test_direct_measures_timestamp_policy(void)
{
    printf(BLUE "::" NC " direct portable restore timestamp measurement\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "direct-timestamp fixture is created");
    if (opened != 0)
        return;
    check(prepare_direct_basic_fixture(&fixture, (uint32_t)geteuid()) == 0,
          "direct-timestamp sidecar is committed");
    int measured = 0;
    check(fsprobe_timestamps_fd(fixture.home_fd, &measured) == 0 &&
              measured == 1,
          "host destination reports exact timestamp support");
    if (measured != 1)
    {
        fixture_close(&fixture);
        return;
    }
    PortableRestoreReplayReport report;
    PortableRestoreOutcome outcome = run_direct_orchestration(
        &fixture, &report, 0, "y\n");
    char file[PATH_MAX];
    path_join_fixture(file, sizeof(file), fixture.home, "/restored/file");
    uint32_t uid = (uint32_t)geteuid();
    uint32_t gid = (uint32_t)getegid();
    check(outcome == PORTABLE_RESTORE_COMPLETE &&
              metadata_exact(file, 0600, (uid_t)uid, (gid_t)gid,
                             1700001002, 333333333,
                             1700001003, 444444444),
          "direct orchestration ignores an injected timestamp policy and uses its measurement");
    fixture_close(&fixture);
}

int main(void)
{
    test_invalid_request_still_zeroes_report();
    test_normal_orchestration();
    test_security_xattr_tolerance_orchestration();
    test_hardlink_orchestration();
    test_hardlink_cross_root();
    test_hardlink_cross_root_invalid_xdg_reference();
    test_xdg_destination_orchestration();
    test_xdg_missing_destination_anchor_cache();
    test_parent_cache_distinguishes_destination_bases();
    test_payload_parent_cache_preserves_directory_identity();
    test_hardlink_reference_failures();
    test_symlink_orchestration();
    test_symlink_ownership_rejection();
    test_symlink_destination_conflict();
    test_probe_rejection();
    test_dry_run();
    test_destination_space_preflight();
    test_coarse_timestamp_policy();
    test_direct_complete_outcome();
    test_direct_dry_run_outcome();
    test_direct_cancelled_outcome();
    test_direct_error_outcome();
    test_direct_timestamp_probe_failure();
    test_direct_measures_timestamp_policy();
    printf("%s%s%s\n", failures == 0 ? GREEN : RED,
           failures == 0 ? "all portable restore orchestration tests passed" :
           "portable restore orchestration tests failed", NC);
    return failures == 0 ? 0 : 1;
}
