// Portable restore replay tests (docs/DECISIONS.md D17/D21): this fixture drives
// the mutation layer only after the read-only preflight, then checks exact core
// metadata, fd-anchored payload revalidation, parent-first directory creation,
// post-order directory metadata, and last-committed tombstone semantics.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "manifest.h"
#include "portable.h"
#include "portable_restore.h"
#include "portable_restore_replay_internal.h"
#include "sidecar.h"

extern int replay_entry_valid(const SidecarEntry *entry);
extern int replay_stat_from_entry(const SidecarEntry *entry,
                                  struct stat *desired);
extern int replay_hardlink_identity_matches(const struct stat *linked,
                                            const struct stat *reference);
extern void replay_copy_bytes(char *destination, size_t destination_size,
                              SidecarBytes source);

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define YELLOW "\033[0;33m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

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
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void fatal(const char *message)
{
    fprintf(stderr, "portable restore replay fixture failure: %s\n", message);
    exit(2);
}

static void test_payload_path_fits_boundary(void)
{
    check(portable_payload_path_fits(5U, 0U, 6U),
          "payload root plus NUL exactly fits");
    check(!portable_payload_path_fits(5U, 0U, 5U),
          "payload root cannot consume the full capacity");
    check(!portable_payload_path_fits(5U, 4U, 10U),
          "payload path rejects the former off-by-one boundary");
    check(portable_payload_path_fits(5U, 3U, 10U),
          "payload path accepts an exact root slash physical NUL fit");
    check(!portable_payload_path_fits(0U, 1U, 10U),
          "payload path rejects an empty root");
    check(!portable_payload_path_fits(10U, 0U, 10U),
          "payload path rejects a root at capacity");
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

static void path_join(char *out, size_t out_size, const char *base,
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

static void make_dir_at(int parent_fd, const char *name, mode_t mode)
{
    if (mkdirat(parent_fd, name, mode) != 0)
        fatal("could not create fixture directory");
}

static int open_dir(const char *path)
{
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
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

static int file_equals_noatime(const char *path, const char *expected)
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

static SidecarBytes text_bytes(const char *text)
{
    return (SidecarBytes){
        .data = (const unsigned char *)text,
        .length = strlen(text)
    };
}

static SidecarEntry entry_for(const char *root, const char *logical,
                              const char *physical, SidecarObjectKind kind,
                              uint64_t size, uint32_t mode,
                              int64_t atime_sec, uint32_t atime_nsec,
                              int64_t mtime_sec, uint32_t mtime_nsec)
{
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = text_bytes(root);
    entry.logical_path = text_bytes(logical);
    entry.physical_path = text_bytes(physical);
    entry.kind = kind;
    entry.mode = mode;
    entry.uid = (uint32_t)geteuid();
    entry.gid = (uint32_t)getegid();
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
                 "/tmp/migr_portable_replay_XXXXXX") < 0 ||
        mkdtemp(fixture->base) == NULL)
        return -1;
    path_join(fixture->container, sizeof(fixture->container),
              fixture->base, "/container");
    path_join(fixture->home, sizeof(fixture->home), fixture->base, "/home");
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
                          size_t count, const char *xattr_name)
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
            (entries[index].xattr_count != 0 &&
             sidecar_log_append_xattr(log, &(SidecarXattr){
                 .name = text_bytes(xattr_name != NULL
                                        ? xattr_name : "user.migr_test"),
                 .value = text_bytes("value")
             }) != SIDECAR_STATUS_OK) ||
            sidecar_log_append_entry_commit(log) != SIDECAR_STATUS_OK)
            return -1;
    }
    return 0;
}

static int write_sidecar(Fixture *fixture, const SidecarEntry *entries,
                         size_t count, const SidecarDelete *deletion,
                         const char *xattr_name)
{
    SidecarLog log = {0};
    if (sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH ||
        append_entries(&log, entries, count, xattr_name) != 0 ||
        (deletion != NULL && sidecar_log_append_delete(&log, deletion) !=
             SIDECAR_STATUS_OK) ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return -1;
    return 0;
}

static int append_raw_sidecar(Fixture *fixture, const unsigned char *data,
                               size_t length)
{
    int fd = openat(fixture->container_fd, SIDECAR_SLOT_NAME,
                    O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int result = write(fd, data, length) == (ssize_t)length ? 0 : -1;
    if (close(fd) != 0)
        result = -1;
    return result;
}

static int raw_field(unsigned char *buffer, size_t capacity, size_t *length,
                     const unsigned char *data, size_t data_length)
{
    if (buffer == NULL || length == NULL || *length >= capacity ||
        data_length >= capacity - *length)
        return -1;
    if (data_length != 0)
        memcpy(buffer + *length, data, data_length);
    *length += data_length;
    buffer[(*length)++] = '\0';
    return 0;
}

static int raw_text_field(unsigned char *buffer, size_t capacity,
                          size_t *length, const char *text)
{
    return raw_field(buffer, capacity, length,
                     (const unsigned char *)text, strlen(text));
}

static int append_raw_suffix_entry(Fixture *fixture,
                                   const unsigned char *suffix,
                                   size_t suffix_length)
{
    unsigned char raw[512];
    size_t length = 0;
    if (raw_text_field(raw, sizeof(raw), &length, "ENTRY") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "ROOT") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "file") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "file") != 0 ||
        raw_field(raw, sizeof(raw), &length, suffix, suffix_length) != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "regular") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "600") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "0") != 0)
        return -1;

    static const unsigned char commit[] = {
        'E', 'N', 'T', 'R', 'Y', '_', 'C', 'O', 'M', 'M', 'I', 'T', '\0'
    };
    SidecarLog log = {0};
    if (sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK ||
        append_raw_sidecar(fixture, raw, length) != 0 ||
        append_raw_sidecar(fixture, commit, sizeof(commit)) != 0)
        return -1;
    return 0;
}

static int run_preflight(Fixture *fixture)
{
    Manifest manifest;
    if (manifest_read_v1_at(fixture->container_fd, &manifest) !=
            MANIFEST_STATUS_VALID)
        return -1;
    PortableRestorePreflightReport report;
    portable_restore_preflight_report_init(&report);
    PortableRestoreRequest request = {
        .source_container_fd = fixture->container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture->home_fd,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    int result = portable_restore_preflight_at(&request, &report);
    portable_restore_preflight_report_free(&report);
    manifest_free(&manifest);
    return result;
}

static int run_replay_with_capture(
    Fixture *fixture, PortableRestoreReplayReport *report,
    BackupCaptureReport *capture_report);

static int run_replay(Fixture *fixture, PortableRestoreReplayReport *report)
{
    return run_replay_with_capture(fixture, report, NULL);
}

static int run_replay_with_capture(
    Fixture *fixture, PortableRestoreReplayReport *report,
    BackupCaptureReport *capture_report)
{
    Manifest manifest;
    if (manifest_read_v1_at(fixture->container_fd, &manifest) !=
            MANIFEST_STATUS_VALID)
        return -1;
    PortableRestoreRequest request = {
        .source_container_fd = fixture->container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture->home_fd,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        },
        .capture_report = capture_report
    };
    portable_restore_replay_report_init(report);
    int result = portable_restore_replay_at(&request, report);
    manifest_free(&manifest);
    return result;
}

static void test_symlink_collection_validation(void)
{
    printf(BLUE "::" NC " portable symlink replay collection validation\n");
    SidecarEntry entry = entry_for("ROOT", "link", "link",
                                   SIDECAR_KIND_SYMLINK, 0, 0777,
                                   1700000300, 11, 1700000301, 22);
    entry.symlink_target = text_bytes("target");

    struct stat desired;
    check(replay_entry_valid(&entry),
          "well-formed symlink entry is accepted by collection validation");
    check(replay_stat_from_entry(&entry, &desired) == 0 &&
              S_ISLNK(desired.st_mode) &&
              (desired.st_mode & 07777) == 0777 &&
              desired.st_uid == (uid_t)geteuid() &&
              desired.st_gid == (gid_t)getegid() &&
              desired.st_atim.tv_sec == 1700000300 &&
              desired.st_atim.tv_nsec == 11 &&
              desired.st_mtim.tv_sec == 1700000301 &&
              desired.st_mtim.tv_nsec == 22,
          "symlink desired stat carries type, ownership, and timestamps");

    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "symlink collection fixture is created");
    if (opened == 0)
    {
        make_dir_at(fixture.data_fd, "ROOT", 0700);
        write_file_at(fixture.data_fd, "ROOT/link", "");
        write_file_at(fixture.home_fd, "restored", "sentinel");
        check(write_sidecar(&fixture, &entry, 1, NULL, NULL) == 0,
              "well-formed symlink sidecar is committed");
        PortableRestoreReplayReport report;
        int result = run_replay(&fixture, &report);
        char restored[PATH_MAX];
        path_join(restored, sizeof(restored), fixture.home, "/restored");
        check(result != 0 && report.live_count == 1 &&
                  report.failed_count == 1 &&
                  strcmp(report.failed_logical_path, "link") == 0,
              "collection accepts the symlink before destination validation fails");
        check(file_equals_noatime(restored, "sentinel"),
              "collection failure leaves the destination untouched");
        fixture_close(&fixture);
    }

    Fixture missing;
    opened = fixture_open(&missing, &root);
    check(opened == 0, "missing-placeholder fixture is created");
    if (opened == 0)
    {
        make_dir_at(missing.data_fd, "ROOT", 0700);
        check(write_sidecar(&missing, &entry, 1, NULL, NULL) == 0,
              "missing-placeholder sidecar is committed");
        PortableRestoreReplayReport report;
        int result = run_replay(&missing, &report);
        check(result != 0 && report.live_count == 0 &&
                  report.failed_count == 1,
              "missing symlink placeholder is rejected during collection");
        fixture_close(&missing);
    }

    Fixture redirected;
    opened = fixture_open(&redirected, &root);
    check(opened == 0, "payload-redirect fixture is created");
    if (opened == 0)
    {
        make_dir_at(redirected.data_fd, "ROOT", 0700);
        char outside[PATH_MAX], payload_link[PATH_MAX];
        path_join(outside, sizeof(outside), redirected.base, "/outside");
        if (mkdir(outside, 0700) != 0)
            fatal("could not create payload redirect target");
        path_join(payload_link, sizeof(payload_link), redirected.base,
                  "/container/data/ROOT/link");
        check(symlink(outside, payload_link) == 0,
              "payload placeholder symlink is planted");
        check(write_sidecar(&redirected, &entry, 1, NULL, NULL) == 0,
              "payload-redirect sidecar is committed");
        PortableRestoreReplayReport report;
        int result = run_replay(&redirected, &report);
        check(result != 0 && report.live_count == 0 &&
                  report.failed_count == 1,
              "payload placeholder redirect is rejected during collection");
        fixture_close(&redirected);
    }

    SidecarEntry empty_target = entry;
    empty_target.symlink_target = (SidecarBytes){0};
    check(!replay_entry_valid(&empty_target),
          "empty symlink target is rejected");

    SidecarEntry xattr = entry;
    xattr.xattr_count = 1;
    check(replay_entry_valid(&xattr),
          "xattr-bearing symlink entries are valid (replay now applies them)");

    SidecarEntry sized = entry;
    sized.size = 1;
    check(!replay_entry_valid(&sized),
          "nonzero symlink size is rejected");

    unsigned char oversized_target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    memset(oversized_target, 'x', sizeof(oversized_target));
    SidecarEntry oversized = entry;
    oversized.symlink_target = (SidecarBytes){
        .data = oversized_target,
        .length = sizeof(oversized_target)
    };
    check(!replay_entry_valid(&oversized),
          "oversized symlink target is rejected");

    SidecarEntry fifo = entry_for("ROOT", "fifo", "fifo",
                                  SIDECAR_KIND_FIFO, 0, 0644,
                                  1700000300, 11, 1700000301, 22);
    struct stat fifo_desired;
    errno = 0;
    check(replay_stat_from_entry(&fifo, &fifo_desired) == -1 &&
              errno == EINVAL,
          "a FIFO entry is rejected, not silently treated as regular");
}

static void test_hardlink_identity_validation(void)
{
    printf(BLUE "::" NC " hardlink identity readback validation\n");
    struct stat linked = {0};
    struct stat reference = {0};
    linked.st_dev = 1;
    linked.st_ino = 42;
    reference.st_dev = 1;
    reference.st_ino = 42;
    check(replay_hardlink_identity_matches(&linked, &reference),
          "matching dev/ino is accepted");

    reference.st_ino = 43;
    check(!replay_hardlink_identity_matches(&linked, &reference),
          "mismatched ino is rejected");

    reference.st_ino = 42;
    reference.st_dev = 2;
    check(!replay_hardlink_identity_matches(&linked, &reference),
          "mismatched dev is rejected");
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

static void test_physical_logical_mismatch(void)
{
    printf(BLUE "::" NC " physical/logical invariant during replay\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "physical-mismatch fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/something-else.txt", "payload");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    SidecarEntry mismatch = entry_for(
        "ROOT", "innocuous.txt", "something-else.txt",
        SIDECAR_KIND_REGULAR, 7, 0644, 1700000000, 0, 1700000000, 0);
    check(write_sidecar(&fixture, &mismatch, 1, NULL, NULL) == 0,
          "physical-mismatch sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result != 0 && report.failed_count == 1 &&
              strcmp(report.failed_logical_path, "innocuous.txt") == 0,
          "replay refuses a mismatched physical path");
    char sentinel[PATH_MAX];
    path_join(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(file_equals_noatime(sentinel, "untouched"),
          "physical-mismatch refusal leaves the destination untouched");
    fixture_close(&fixture);
}

static void run_replay_suffix_refusal(const char *label, const char *suffix,
                                      const char *physical,
                                      ManifestRoot *root)
{
    Fixture fixture;
    int opened = fixture_open(&fixture, root);
    check(opened == 0, "suffix-refusal replay fixture is created");
    if (opened != 0)
        return;
    make_dir_at(fixture.data_fd, "ROOT", 0700);
    char payload_path[PATH_MAX];
    int payload_length = snprintf(payload_path, sizeof(payload_path),
                                  "ROOT/%s", physical);
    if (payload_length < 0 || (size_t)payload_length >= sizeof(payload_path))
        fatal("suffix fixture payload path is too long");
    write_file_at(fixture.data_fd, payload_path, "payload");
    SidecarEntry entry = entry_for("ROOT", "file", physical,
                                   SIDECAR_KIND_REGULAR, 0, 0600,
                                   1700000000, 0, 1700000001, 0);
    entry.collision_suffix = text_bytes(suffix);
    check(write_sidecar(&fixture, &entry, 1, NULL, NULL) == 0,
          "suffix-refusal replay sidecar is committed");
    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result != 0 && report.failed_count == 1 &&
              strcmp(report.failed_logical_path, "file") == 0,
          label);
    fixture_close(&fixture);
}

static void run_raw_replay_suffix_refusal(const char *label,
                                          const unsigned char *suffix,
                                          size_t suffix_length,
                                          ManifestRoot *root)
{
    Fixture fixture;
    int opened = fixture_open(&fixture, root);
    check(opened == 0, "raw suffix-refusal replay fixture is created");
    if (opened != 0)
        return;
    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    check(append_raw_suffix_entry(&fixture, suffix, suffix_length) == 0,
          "raw malformed suffix replay record is committed");
    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result != 0 && report.failed_count == 1,
          label);
    fixture_close(&fixture);
}

static void test_collision_suffix_validation(void)
{
    printf(BLUE "::" NC " parent-prefix and collision-suffix replay\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "suffixed replay fixture is created");
    if (opened == 0)
    {
        make_dir_at(fixture.data_fd, "ROOT", 0700);
        int payload_root = openat(fixture.data_fd, "ROOT",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not open suffixed replay payload root");
        make_dir_at(payload_root, "dir%7E1", 0700);
        int suffixed_dir = openat(payload_root, "dir%7E1",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (suffixed_dir < 0)
            fatal("could not open suffixed replay directory");
        write_file_at(suffixed_dir, "file", "nested");
        close(suffixed_dir);
        write_file_at(payload_root, "Foo%7E1", "leaf");
        close(payload_root);

        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                      1700000000, 0, 1700000001, 0),
            entry_for("ROOT", "dir", "dir%7E1",
                      SIDECAR_KIND_DIRECTORY, 0, 0700,
                      1700000002, 0, 1700000003, 0),
            entry_for("ROOT", "dir/file", "dir%7E1/file",
                      SIDECAR_KIND_REGULAR, 6, 0600,
                      1700000004, 0, 1700000005, 0),
            entry_for("ROOT", "Foo", "Foo%7E1", SIDECAR_KIND_REGULAR, 4,
                      0600, 1700000006, 0, 1700000007, 0)
        };
        entries[1].collision_suffix = text_bytes("%7E1");
        entries[3].collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&fixture, entries, 4, NULL, NULL) == 0,
              "suffixed replay sidecar is committed");
        check(run_preflight(&fixture) == 0,
              "suffixed ancestor state passes preflight");
        PortableRestoreReplayReport report;
        int result = run_replay(&fixture, &report);
        check(result == 0 && report.live_count == 4 &&
                  report.applied_count == 4 && report.failed_count == 0,
              "suffixed ancestor and suffixed leaf replay successfully");
        char nested[PATH_MAX], leaf[PATH_MAX];
        path_join(nested, sizeof(nested), fixture.home,
                  "/restored/dir/file");
        path_join(leaf, sizeof(leaf), fixture.home, "/restored/Foo");
        check(file_equals_noatime(nested, "nested"),
              "child beneath a suffixed directory is restored by logical name");
        check(file_equals_noatime(leaf, "leaf"),
              "suffixed physical leaf is not exposed at the destination");
        fixture_close(&fixture);
    }

    run_replay_suffix_refusal("suffix-lower-e", "%7e1", "file%7e1", &root);
    run_replay_suffix_refusal("suffix-zero", "%7E0", "file%7E0", &root);
    run_replay_suffix_refusal("suffix-leading-zero", "%7E01",
                              "file%7E01", &root);
    run_replay_suffix_refusal("suffix-no-digits", "%7E", "file%7E", &root);
    run_replay_suffix_refusal("suffix-overflow",
                              "%7E18446744073709551616",
                              "file%7E18446744073709551616", &root);
    static const unsigned char embedded_nul[] = { '%', '7', 'E', '\0', '1' };
    run_raw_replay_suffix_refusal("suffix-embedded-nul", embedded_nul,
                                  sizeof(embedded_nul), &root);
    unsigned char overlong[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    memset(overlong, '1', sizeof(overlong));
    overlong[0] = '%';
    overlong[1] = '7';
    overlong[2] = 'E';
    run_raw_replay_suffix_refusal("suffix-over-ceiling", overlong,
                                  sizeof(overlong), &root);

    Fixture missing;
    opened = fixture_open(&missing, &root);
    check(opened == 0, "missing-parent replay fixture is created");
    if (opened == 0)
    {
        make_dir_at(missing.data_fd, "ROOT", 0700);
        SidecarEntry child = entry_for("ROOT", "dir/file", "dir/file",
                                       SIDECAR_KIND_REGULAR, 0, 0600,
                                       1700000010, 0, 1700000011, 0);
        check(write_sidecar(&missing, &child, 1, NULL, NULL) == 0,
              "missing-parent replay sidecar is committed");
        PortableRestoreReplayReport report;
        check(run_replay(&missing, &report) != 0 &&
                  report.failed_count == 1,
              "missing parent entry is refused during replay");
        fixture_close(&missing);
    }

    Fixture mismatch;
    opened = fixture_open(&mismatch, &root);
    check(opened == 0, "parent-mismatch replay fixture is created");
    if (opened == 0)
    {
        make_dir_at(mismatch.data_fd, "ROOT", 0700);
        int payload_root = openat(mismatch.data_fd, "ROOT",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not open parent-mismatch replay root");
        make_dir_at(payload_root, "dir%7E1", 0700);
        close(payload_root);
        SidecarEntry entries[] = {
            entry_for("ROOT", "dir", "dir%7E1",
                      SIDECAR_KIND_DIRECTORY, 0, 0700,
                      1700000012, 0, 1700000013, 0),
            entry_for("ROOT", "dir/file", "other/file",
                      SIDECAR_KIND_REGULAR, 0, 0600,
                      1700000014, 0, 1700000015, 0)
        };
        entries[0].collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&mismatch, entries, 2, NULL, NULL) == 0,
              "parent-mismatch replay sidecar is committed");
        PortableRestoreReplayReport report;
        check(run_replay(&mismatch, &report) != 0 &&
                  report.failed_count == 1,
              "parent physical-prefix mismatch is refused during replay");
        fixture_close(&mismatch);
    }

    Fixture root_suffix;
    opened = fixture_open(&root_suffix, &root);
    check(opened == 0, "root-suffix replay fixture is created");
    if (opened == 0)
    {
        make_dir_at(root_suffix.data_fd, "ROOT", 0700);
        SidecarEntry entry = entry_for("ROOT", "", "",
                                       SIDECAR_KIND_DIRECTORY, 0, 0700,
                                       1700000016, 0, 1700000017, 0);
        entry.collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&root_suffix, &entry, 1, NULL, NULL) == 0,
              "root-suffix replay sidecar is committed");
        PortableRestoreReplayReport report;
        check(run_replay(&root_suffix, &report) != 0 &&
                  report.failed_count == 1,
              "root payload entry cannot carry a collision suffix");
        fixture_close(&root_suffix);
    }
}

static void test_normal_replay(void)
{
    printf(BLUE "::" NC " normal replay and exact metadata\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "normal replay fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    int root_fd = openat(fixture.data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open payload root");
    make_dir_at(root_fd, "nested", 0700);
    int nested_fd = openat(root_fd, "nested",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (nested_fd < 0)
        fatal("could not open nested payload directory");
    write_file_at(nested_fd, "file", "portable payload");
    close(nested_fd);
    close(root_fd);

    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0500,
                  1700000000, 123456789, 1700000010, 987654321),
        entry_for("ROOT", "nested", "nested", SIDECAR_KIND_DIRECTORY, 0,
                  0500, 1700000020, 111111111, 1700000030, 222222222),
        entry_for("ROOT", "nested/file", "nested/file",
                  SIDECAR_KIND_REGULAR, strlen("portable payload"), 0640,
                  1700000040, 333333333, 1700000050, 444444444)
    };
    check(write_sidecar(&fixture, entries, 3, NULL, NULL) == 0,
          "normal replay sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    check(run_preflight(&fixture) == 0, "normal state passes preflight");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result == 0 && report.live_count == 3 &&
              report.applied_count == 3 && report.failed_count == 0,
          "all live entries replay successfully");

    char restored_root[PATH_MAX], restored_nested[PATH_MAX],
        restored_file[PATH_MAX], sentinel[PATH_MAX];
    path_join(restored_root, sizeof(restored_root), fixture.home, "/restored");
    path_join(restored_nested, sizeof(restored_nested), restored_root, "/nested");
    path_join(restored_file, sizeof(restored_file), restored_nested, "/file");
    path_join(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(file_equals_noatime(restored_file, "portable payload"),
          "regular payload content is restored");
    check(metadata_exact(restored_root, 0500, (uid_t)geteuid(),
                         (gid_t)getegid(), 1700000000, 123456789,
                         1700000010, 987654321),
          "root directory metadata is applied post-order");
    check(metadata_exact(restored_nested, 0500, (uid_t)geteuid(),
                         (gid_t)getegid(), 1700000020, 111111111,
                         1700000030, 222222222),
          "nested directory metadata is applied post-order");
    check(metadata_exact(restored_file, 0640, (uid_t)geteuid(),
                         (gid_t)getegid(), 1700000040, 333333333,
                         1700000050, 444444444),
          "regular metadata is applied exactly");
    check(file_equals_noatime(sentinel, "untouched"),
          "unrelated destination content remains untouched");
    fixture_close(&fixture);
}

static void test_destination_truncation(void)
{
    printf(BLUE "::" NC " restore truncates a longer existing regular file\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "destination-truncation fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "short");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000600, 1, 1700000601, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 5, 0600,
                  1700000602, 3, 1700000603, 4)
    };
    check(write_sidecar(&fixture, entries, 2, NULL, NULL) == 0,
          "destination-truncation sidecar is committed");

    make_dir_at(fixture.home_fd, "restored", 0700);
    write_file_at(fixture.home_fd, "restored/file",
                  "stale destination content");
    check(run_preflight(&fixture) == 0,
          "destination-truncation state passes preflight");

    PortableRestoreReplayReport report;
    check(run_replay(&fixture, &report) == 0 && report.failed_count == 0,
          "restore overwrites the existing regular file");

    char restored_file[PATH_MAX];
    path_join(restored_file, sizeof(restored_file), fixture.home,
              "/restored/file");
    struct stat restored_stat;
    check(fstatat(fixture.home_fd, "restored/file", &restored_stat,
                  AT_SYMLINK_NOFOLLOW) == 0 && restored_stat.st_size == 5 &&
              file_equals_noatime(restored_file, "short"),
          "restored regular file has no stale trailing bytes");
    fixture_close(&fixture);
}

static void reset_sync(int should_fail)
{
    sync_calls = 0;
    sync_should_fail = should_fail;
}

static void test_capture_report_sync_accumulates(void)
{
    printf(BLUE "::" NC " portable restore report accumulates bytes and syncs across files\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "portable sync fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    char payload[81];
    memset(payload, 'p', sizeof(payload) - 1U);
    payload[sizeof(payload) - 1U] = '\0';
    write_file_at(fixture.data_fd, "ROOT/one", payload);
    write_file_at(fixture.data_fd, "ROOT/two", payload);
    write_file_at(fixture.data_fd, "ROOT/three", payload);
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000500, 1, 1700000501, 2),
        entry_for("ROOT", "one", "one", SIDECAR_KIND_REGULAR, 80, 0600,
                  1700000502, 3, 1700000503, 4),
        entry_for("ROOT", "two", "two", SIDECAR_KIND_REGULAR, 80, 0600,
                  1700000504, 5, 1700000505, 6),
        entry_for("ROOT", "three", "three", SIDECAR_KIND_REGULAR, 80, 0600,
                  1700000506, 7, 1700000507, 8)
    };
    check(write_sidecar(&fixture, entries, 4, NULL, NULL) == 0,
          "portable sync sidecar is committed");

    BackupCaptureReport capture_report = {0};
    capture_report.sync_interval_bytes = 200;
    PortableRestoreReplayReport report;
    reset_sync(0);
    int result = run_replay_with_capture(&fixture, &report, &capture_report);
    check(result == 0 && report.live_count == 4 &&
              report.applied_count == 4 && report.failed_count == 0 &&
              capture_report.bytes_copied == 240 &&
              capture_report.bytes_since_sync == 0 && sync_calls == 1,
          "portable restore report accumulates across smaller files and syncs once");
    fixture_close(&fixture);
}

static void test_capture_report_sync_failure(void)
{
    printf(BLUE "::" NC " portable restore aborts when periodic sync fails\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "portable sync-failure fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    char payload[81];
    memset(payload, 'f', sizeof(payload) - 1U);
    payload[sizeof(payload) - 1U] = '\0';
    write_file_at(fixture.data_fd, "ROOT/file", payload);
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000510, 1, 1700000511, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 80, 0600,
                  1700000512, 3, 1700000513, 4)
    };
    check(write_sidecar(&fixture, entries, 2, NULL, NULL) == 0,
          "portable sync-failure sidecar is committed");

    BackupCaptureReport capture_report = {0};
    capture_report.sync_interval_bytes = 1;
    PortableRestoreReplayReport report;
    reset_sync(1);
    int result = run_replay_with_capture(&fixture, &report, &capture_report);
    check(result != 0 && sync_calls == 1 &&
              capture_report.bytes_copied == 80 && report.failed_count != 0,
          "a failed periodic sync aborts portable restore and records failure");
    reset_sync(0);
    fixture_close(&fixture);
}

static void test_outstanding_claim_gate(void)
{
    printf(BLUE "::" NC " outstanding claims are rejected before replay\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "claim-gate replay fixture is created");
    if (opened != 0)
        return;
    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000200, 1, 1700000201, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 7, 0600,
                  1700000202, 3, 1700000203, 4)
    };
    check(write_sidecar(&fixture, entries, 2, NULL, NULL) == 0,
          "claim-gate replay sidecar has valid live entries");
    SidecarClaim outstanding = {
        .root_id = text_bytes("ROOT"),
        .logical_path = text_bytes("blocked"),
        .physical_path = text_bytes("blocked"),
        .kind = SIDECAR_KIND_REGULAR
    };
    SidecarLog log = {0};
    check(sidecar_log_adopt_at(fixture.container_fd, &log) ==
              SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_append_claim(&log, &outstanding) ==
                  SIDECAR_STATUS_OK &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "an outstanding claim is planted in the valid sidecar");

    write_file_at(fixture.home_fd, "sentinel", "untouched");
    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result != 0 && report.live_count == 0 &&
              report.failed_count == 1,
          "replay rejects the claim before collecting or mutating entries");
    char sentinel[PATH_MAX];
    path_join(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(file_equals_noatime(sentinel, "untouched"),
          "claim-gate replay leaves the destination untouched");
    fixture_close(&fixture);
}

static void test_xattr_replay(void)
{
    printf(BLUE "::" NC " replay applies the payload's exact xattr set\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "xattr replay fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000100, 1, 1700000101, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 7, 0600,
                  1700000102, 3, 1700000103, 4)
    };
    entries[1].xattr_count = 1;
    check(write_sidecar(&fixture, entries, 2, NULL, NULL) == 0,
          "xattr-bearing sidecar is committed");
    check(run_preflight(&fixture) == 0, "xattr state passes preflight");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result == 0 && report.applied_count == 2 &&
              report.failed_count == 0,
          "xattr-bearing entries replay successfully");

    char restored_file[PATH_MAX];
    path_join(restored_file, sizeof(restored_file), fixture.home,
              "/restored/file");
    char value[64];
    ssize_t length = getxattr(restored_file, "user.migr_test", value,
                              sizeof(value));
    check(length == (ssize_t)strlen("value") &&
              memcmp(value, "value", (size_t)length) == 0,
          "payload xattr is applied to the destination");

    fixture_close(&fixture);
}

static void test_xattr_reconciliation(void)
{
    printf(BLUE "::" NC " replay reconciles stale and changed destination xattrs\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "xattr reconciliation fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000100, 1, 1700000101, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 7, 0600,
                  1700000102, 3, 1700000103, 4)
    };
    entries[1].xattr_count = 1;
    check(write_sidecar(&fixture, entries, 2, NULL, NULL) == 0,
          "xattr reconciliation sidecar is committed");
    check(run_preflight(&fixture) == 0, "xattr reconciliation passes preflight");

    PortableRestoreReplayReport report;
    check(run_replay(&fixture, &report) == 0 && report.failed_count == 0,
          "first replay applies the payload xattr set");

    /* Plant a stale xattr and a changed value directly on the destination,
     * then restore again over the same destination: exact-set reconciliation
     * must remove the stale one and overwrite the changed one. */
    char restored_file[PATH_MAX];
    path_join(restored_file, sizeof(restored_file), fixture.home,
              "/restored/file");
    check(setxattr(restored_file, "user.migr_stale", "stale", 5, 0) == 0,
          "fixture: a stale destination xattr is planted");
    check(setxattr(restored_file, "user.migr_test", "old-value", 9, 0) == 0,
          "fixture: the payload xattr name is set to a different value");

    PortableRestoreReplayReport second_report;
    check(run_replay(&fixture, &second_report) == 0 &&
              second_report.failed_count == 0,
          "second replay succeeds over the same destination");

    char value[64];
    ssize_t length = getxattr(restored_file, "user.migr_test", value,
                              sizeof(value));
    check(length == (ssize_t)strlen("value") &&
              memcmp(value, "value", (size_t)length) == 0,
          "changed destination xattr is overwritten to the payload value");
    check(getxattr(restored_file, "user.migr_stale", value, sizeof(value)) < 0 &&
              errno == ENODATA,
          "stale destination xattr is removed by exact-set reconciliation");

    fixture_close(&fixture);
}

static void test_gate_refuses_trusted_before_mutation(void)
{
    printf(BLUE "::" NC " pre-mutation gate refuses a trusted.* payload\n");
    if (geteuid() == 0)
    {
        printf(YELLOW "- " NC " trusted.* gate refusal skipped: running as root\n");
        return;
    }

    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "gate-refusal fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000100, 1, 1700000101, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 7, 0600,
                  1700000102, 3, 1700000103, 4)
    };
    entries[1].xattr_count = 1;
    check(write_sidecar(&fixture, entries, 2, NULL, "trusted.migr_test") == 0,
          "trusted.* sidecar is committed");

    char sentinel[PATH_MAX];
    path_join(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    write_file_at(fixture.home_fd, "sentinel", "untouched");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result != 0, "gate refuses a trusted.* payload");
    check(report.applied_count == 0 && report.failed_count == 1,
          "gate refusal applies nothing and reports one failure");
    check(file_equals_noatime(sentinel, "untouched"),
          "gate refusal leaves the destination sentinel untouched");

    char restored_file[PATH_MAX];
    path_join(restored_file, sizeof(restored_file), fixture.home,
              "/restored/file");
    check(access(restored_file, F_OK) != 0,
          "gate refusal never creates the entry's destination path");
    fixture_close(&fixture);
}

static void test_gate_allows_security_only(void)
{
    printf(BLUE "::" NC " pre-mutation gate does not refuse a security.*-only payload\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "security-only fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000100, 1, 1700000101, 2),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 7, 0600,
                  1700000102, 3, 1700000103, 4)
    };
    entries[1].xattr_count = 1;
    check(write_sidecar(&fixture, entries, 2, NULL, "security.selinux") == 0,
          "security.*-only sidecar is committed");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);

    char restored_file[PATH_MAX];
    path_join(restored_file, sizeof(restored_file), fixture.home,
              "/restored/file");
    /*
     * The gate must not refuse a security.*-only payload (the probe masks
     * that namespace out). The apply itself may still fail on hosts where
     * writing an arbitrary security.* value is policy-refused -- so assert
     * specifically that replay got past the gate and into replay_run: the
     * destination tree was created. Do not assert overall success.
     */
    check(access(restored_file, F_OK) == 0,
          "security.*-only payload passes the gate and reaches replay");
    (void)result;
    fixture_close(&fixture);
}

static void test_payload_swap(void)
{
    printf(BLUE "::" NC " per-entry payload revalidation\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "payload-swap fixture is created");
    if (opened != 0)
        return;
    make_dir_at(fixture.data_fd, "ROOT", 0700);
    write_file_at(fixture.data_fd, "ROOT/file", "original");
    write_file_at(fixture.data_fd, "ROOT/a", "applied");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000100, 1, 1700000101, 2),
        entry_for("ROOT", "a", "a", SIDECAR_KIND_REGULAR, 7,
                  0600, 1700000104, 5, 1700000105, 6),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 8, 0600,
                  1700000102, 3, 1700000103, 4)
    };
    check(write_sidecar(&fixture, entries, 3, NULL, NULL) == 0,
          "payload-swap sidecar is committed");
    check(run_preflight(&fixture) == 0, "payload-swap state passes preflight");

    int root_fd = openat(fixture.data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open payload root for swap");
    write_file_at(root_fd, "replacement", "different-size");
    if (renameat(root_fd, "replacement", root_fd, "file") != 0)
        fatal("could not swap payload file");
    close(root_fd);
    write_file_at(fixture.home_fd, "sentinel", "untouched");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    check(result != 0 && report.live_count == 3 &&
              report.applied_count == 1 && report.failed_count == 1 &&
              strcmp(report.failed_logical_path, "file") == 0,
          "payload replacement is caught after reporting prior progress");
    char restored_first[PATH_MAX], restored_file[PATH_MAX], sentinel[PATH_MAX];
    path_join(restored_first, sizeof(restored_first), fixture.home,
              "/restored/a");
    path_join(restored_file, sizeof(restored_file), fixture.home,
              "/restored/file");
    path_join(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(file_equals_noatime(restored_first, "applied"),
          "entries before the swapped payload remain applied");
    check(access(restored_file, F_OK) != 0,
          "rejected payload has no destination file");
    check(file_equals_noatime(sentinel, "untouched"),
          "payload-swap refusal leaves the sentinel untouched");
    fixture_close(&fixture);
}

static void test_tombstone_skipped(void)
{
    printf(BLUE "::" NC " tombstoned state is not replayed\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "tombstone fixture is created");
    if (opened != 0)
        return;
    make_dir_at(fixture.data_fd, "ROOT", 0700);
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000200, 1, 1700000201, 2),
        entry_for("ROOT", "deleted", "deleted", SIDECAR_KIND_REGULAR, 7,
                  0600, 1700000202, 3, 1700000203, 4)
    };
    SidecarDelete deletion = {
        .root_id = text_bytes("ROOT"),
        .logical_path = text_bytes("deleted")
    };
    check(write_sidecar(&fixture, entries, 2, &deletion, NULL) == 0,
          "tombstone sidecar is committed");
    check(run_preflight(&fixture) == 0,
          "tombstoned state passes preflight without payload");
    PortableRestoreReplayReport report;
    check(run_replay(&fixture, &report) == 0 && report.live_count == 1 &&
              report.applied_count == 1 && report.failed_count == 0,
          "only the live root is replayed");
    char deleted[PATH_MAX];
    path_join(deleted, sizeof(deleted), fixture.home, "/restored/deleted");
    check(access(deleted, F_OK) != 0,
          "tombstoned entry is not resurrected");
    fixture_close(&fixture);
}

static Fixture *hardlink_race_fixture;

static void swap_representative_hook(void)
{
    if (hardlink_race_fixture == NULL)
        return;
    int root_fd = openat(hardlink_race_fixture->home_fd, "restored",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open restored root during hardlink race hook");
    if (unlinkat(root_fd, "representative", 0) != 0)
        fatal("could not remove representative during hardlink race hook");
    write_file_at(root_fd, "representative", "swapped payload");
    if (close(root_fd) != 0)
        fatal("could not close restored root during hardlink race hook");
}

static void test_hardlink_toctou_race(void)
{
    printf(BLUE "::" NC " hardlink post-link identity check catches a "
                 "reference swapped after the pre-link validation\n");
    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "hardlink race fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    int root_fd = openat(fixture.data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open hardlink race payload root");
    write_file_at(root_fd, "representative", "hardlink payload");
    write_file_at(root_fd, "alias", "");
    if (close(root_fd) != 0)
        fatal("could not close hardlink race payload root");

    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0, 0700,
                  1700000700, 1, 1700000701, 2),
        entry_for("ROOT", "representative", "representative",
                  SIDECAR_KIND_REGULAR, strlen("hardlink payload"), 0640,
                  1700000710, 3, 1700000711, 4),
        entry_for("ROOT", "alias", "alias", SIDECAR_KIND_HARDLINK, 0, 0640,
                  1700000720, 5, 1700000721, 6)
    };
    entries[2].hardlink_root_id = text_bytes("ROOT");
    entries[2].hardlink_logical_path = text_bytes("representative");
    check(write_sidecar(&fixture, entries, 3, NULL, NULL) == 0,
          "hardlink race sidecar is committed");
    check(run_preflight(&fixture) == 0,
          "hardlink race state passes preflight");

    hardlink_race_fixture = &fixture;
    portable_restore_replay_test_set_hardlink_race_hook(
        swap_representative_hook);
    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    portable_restore_replay_test_set_hardlink_race_hook(NULL);
    hardlink_race_fixture = NULL;

    check(result != 0 && report.applied_count == 1 &&
              report.failed_count == 1,
          "the reference swapped between validation and linkat is "
          "detected instead of silently accepted");

    char representative[PATH_MAX];
    path_join(representative, sizeof(representative), fixture.home,
              "/restored/representative");
    check(file_equals_noatime(representative, "swapped payload"),
          "the swap actually took effect between validation and linkat");
    fixture_close(&fixture);
}

static void test_copy_bytes_rejects_corruption(void)
{
    printf(BLUE "::" NC " replay_copy_bytes rejects what it cannot "
                 "faithfully represent\n");
    char destination[8];

    replay_copy_bytes(destination, sizeof(destination), text_bytes("short"));
    check(strcmp(destination, "short") == 0,
          "a source that fits is copied exactly");

    replay_copy_bytes(destination, sizeof(destination),
                      text_bytes("1234567"));
    check(strcmp(destination, "1234567") == 0,
          "a source that fits exactly at the boundary is copied exactly");

    replay_copy_bytes(destination, sizeof(destination),
                      text_bytes("exactly8"));
    check(strcmp(destination, "") == 0,
          "a source that doesn't fit is rejected, not truncated");

    unsigned char embedded_nul[] = { 'a', 'b', '\0', 'c' };
    SidecarBytes with_nul = { .data = embedded_nul,
                              .length = sizeof(embedded_nul) };
    strcpy(destination, "sentinl");
    replay_copy_bytes(destination, sizeof(destination), with_nul);
    check(strcmp(destination, "") == 0,
          "a source with an embedded NUL is rejected, not silently "
          "misrepresented as a shorter string");
}

int main(void)
{
    test_payload_path_fits_boundary();
    test_symlink_collection_validation();
    test_hardlink_identity_validation();
    test_physical_logical_mismatch();
    test_collision_suffix_validation();
    test_normal_replay();
    test_destination_truncation();
    test_capture_report_sync_accumulates();
    test_capture_report_sync_failure();
    test_outstanding_claim_gate();
    test_xattr_replay();
    test_xattr_reconciliation();
    test_gate_refuses_trusted_before_mutation();
    test_gate_allows_security_only();
    test_payload_swap();
    test_tombstone_skipped();
    test_hardlink_toctou_race();
    test_copy_bytes_rejects_corruption();
    printf("%s%s%s\n", failures == 0 ? GREEN : RED,
           failures == 0 ? "all portable restore replay tests passed" :
           "portable restore replay tests failed", NC);
    return failures == 0 ? 0 : 1;
}
