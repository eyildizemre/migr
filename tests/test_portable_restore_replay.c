// Portable restore replay tests (docs/DECISIONS.md D17): this fixture drives
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
#include <unistd.h>

#include "manifest.h"
#include "portable_restore.h"
#include "sidecar.h"

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
    fprintf(stderr, "portable restore replay fixture failure: %s\n", message);
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
                         size_t count, const SidecarDelete *deletion)
{
    SidecarLog log = {0};
    if (sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH ||
        append_entries(&log, entries, count) != 0 ||
        (deletion != NULL && sidecar_log_append_delete(&log, deletion) !=
             SIDECAR_STATUS_OK) ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
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
        .destination_home_fd = fixture->home_fd
    };
    int result = portable_restore_preflight_at(&request, &report);
    portable_restore_preflight_report_free(&report);
    manifest_free(&manifest);
    return result;
}

static int run_replay(Fixture *fixture, PortableRestoreReplayReport *report)
{
    Manifest manifest;
    if (manifest_read_v1_at(fixture->container_fd, &manifest) !=
            MANIFEST_STATUS_VALID)
        return -1;
    PortableRestoreRequest request = {
        .source_container_fd = fixture->container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture->home_fd
    };
    portable_restore_replay_report_init(report);
    int result = portable_restore_replay_at(&request, report);
    manifest_free(&manifest);
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
    check(write_sidecar(&fixture, entries, 3, NULL) == 0,
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
    check(write_sidecar(&fixture, entries, 3, NULL) == 0,
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
    check(write_sidecar(&fixture, entries, 2, &deletion) == 0,
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

int main(void)
{
    test_normal_replay();
    test_payload_swap();
    test_tombstone_skipped();
    printf("%s%s%s\n", failures == 0 ? GREEN : RED,
           failures == 0 ? "all portable restore replay tests passed" :
           "portable restore replay tests failed", NC);
    return failures == 0 ? 0 : 1;
}
