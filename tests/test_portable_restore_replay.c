// Portable restore replay tests (docs/DECISIONS.md D17/D21): this fixture drives
// the mutation layer only after the read-only preflight, then checks exact core
// metadata, fd-anchored payload revalidation, parent-first directory creation,
// post-order directory metadata, and last-committed tombstone semantics.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "manifest.h"
#include "portable.h"
#include "portable_restore_internal.h"
#include "portable_restore.h"
#include "portable_restore_replay_internal.h"
#include "sidecar.h"

extern void replay_copy_bytes(char *destination, size_t destination_size,
                              SidecarBytes source);

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define YELLOW "\033[0;33m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;
static int skips;
static int sync_calls;
static int sync_should_fail;

enum { CHILD_SKIP = 77 };

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

static void skip_case(const char *label, const char *reason)
{
    printf("  " YELLOW "-" NC " %s skipped: %s\n", label, reason);
    skips++;
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

static int write_proc_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t length = strlen(content);
    ssize_t written = write(fd, content, length);
    int saved_errno = errno;
    int close_rc = close(fd);
    if (written < 0)
        errno = saved_errno;
    return written == (ssize_t)length && close_rc == 0 ? 0 : -1;
}

static int setup_bind_mount_namespace(void)
{
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
        return -1;

    char mapping[64];
    int length = snprintf(mapping, sizeof(mapping), "0 %lu 1\n",
                          (unsigned long)host_uid);
    if (length < 0 || (size_t)length >= sizeof(mapping) ||
        write_proc_file("/proc/self/uid_map", mapping) != 0 ||
        write_proc_file("/proc/self/setgroups", "deny\n") != 0)
        return -1;

    length = snprintf(mapping, sizeof(mapping), "0 %lu 1\n",
                      (unsigned long)host_gid);
    if (length < 0 || (size_t)length >= sizeof(mapping) ||
        write_proc_file("/proc/self/gid_map", mapping) != 0)
        return -1;

    return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
}

static int path_mount_id(const char *path, unsigned int *mount_id)
{
    if (path == NULL || mount_id == NULL)
        return -1;
    struct statx state;
    memset(&state, 0, sizeof(state));
    if (statx(AT_FDCWD, path, AT_STATX_DONT_SYNC, STATX_MNT_ID, &state) != 0 ||
        (state.stx_mask & STATX_MNT_ID) == 0)
        return -1;
    *mount_id = state.stx_mnt_id;
    return 0;
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

static int write_v2_nested_manifest(Fixture *fixture, ManifestRoot roots[2])
{
    memset(roots, 0, 2U * sizeof(*roots));
    strcpy(roots[0].id, "HOME");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "HOME");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "CHILD");
    roots[1].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[1].payload_path, "CHILD");
    strcpy(roots[1].source_path, "/source/home/Child");
    roots[1].has_restore_path = 1;
    strcpy(roots[1].restore_path, "Documents");

    Manifest manifest = {
        .version = MANIFEST_SELECTION_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_CRITICAL,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = 2,
        .roots = roots
    };
    strcpy(manifest.source_home, "/source/home");
    return manifest_write_v1_at(fixture->container_fd, &manifest);
}

static int write_v1_identity_manifest(Fixture *fixture, ManifestRoot *roots,
                                      int root_count)
{
    Manifest manifest = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .root_count = root_count,
        .roots = roots
    };
    return manifest_write_v1_at(fixture->container_fd, &manifest);
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

static int run_preflight_with_xdg(
    Fixture *fixture, const char * const *destination_xdg_dirs)
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
        .destination_home_path = fixture->home,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        request.destination_xdg_dirs[index] =
            destination_xdg_dirs == NULL ? NULL : destination_xdg_dirs[index];
    int result = portable_restore_preflight_at(&request, &report);
    portable_restore_preflight_report_free(&report);
    manifest_free(&manifest);
    return result;
}

static int run_preflight(Fixture *fixture)
{
    return run_preflight_with_xdg(fixture, NULL);
}

static int run_replay_with_capture(
    Fixture *fixture, PortableRestoreReplayReport *report,
    BackupCaptureReport *capture_report);

static int run_replay_with_xdg(
    Fixture *fixture, PortableRestoreReplayReport *report,
    const char * const *destination_xdg_dirs);

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
        .destination_home_path = fixture->home,
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

static int run_replay_with_xdg(
    Fixture *fixture, PortableRestoreReplayReport *report,
    const char * const *destination_xdg_dirs)
{
    Manifest manifest;
    if (manifest_read_v1_at(fixture->container_fd, &manifest) !=
            MANIFEST_STATUS_VALID)
        return -1;
    PortableRestoreRequest request = {
        .source_container_fd = fixture->container_fd,
        .manifest = &manifest,
        .destination_home_fd = fixture->home_fd,
        .destination_home_path = fixture->home,
        .destination_timestamp_policy = {
            .nsec_exact = 1,
            .configured = 1
        }
    };
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        request.destination_xdg_dirs[index] =
            destination_xdg_dirs == NULL ? NULL : destination_xdg_dirs[index];
    portable_restore_replay_report_init(report);
    int result = portable_restore_replay_at(&request, report);
    manifest_free(&manifest);
    return result;
}

static int run_portable_mount_case(
    Fixture *fixture, const char *documents_root, const char *downloads_root,
    const char *documents_shared, const char *downloads_shared,
    const char *sentinel)
{
    pid_t pid = fork();
    if (pid < 0)
        fatal("could not fork portable mount-view fixture");
    if (pid == 0)
    {
        if (setup_bind_mount_namespace() != 0 ||
            mount(downloads_shared, documents_shared, NULL, MS_BIND, NULL) != 0)
            _exit(CHILD_SKIP);

        struct stat documents_st, downloads_st;
        unsigned int documents_mount_id, downloads_mount_id;
        if (stat(documents_shared, &documents_st) != 0 ||
            stat(downloads_shared, &downloads_st) != 0 ||
            documents_st.st_dev != downloads_st.st_dev ||
            documents_st.st_ino != downloads_st.st_ino ||
            path_mount_id(documents_shared, &documents_mount_id) != 0 ||
            path_mount_id(downloads_shared, &downloads_mount_id) != 0 ||
            documents_mount_id == downloads_mount_id)
            _exit(CHILD_SKIP);

        const char *xdg_dirs[XDG_KEY_COUNT] = {0};
        xdg_dirs[0] = documents_root;
        xdg_dirs[1] = downloads_root;
        int result = run_preflight_with_xdg(
            fixture, (const char * const *)xdg_dirs);
        _exit(result != 0 && file_equals_noatime(sentinel, "ORIGINAL")
                  ? 0 : 1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        fatal("could not wait for portable mount-view fixture");
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Keep this at the identity-graph boundary: a full restore with two directory
 * metadata owners would correctly stop earlier on R2a's alias collision. */
static int run_nested_mount_view_graph_case(
    const char *documents_root, const char *downloads_root,
    const char *documents_shared, const char *downloads_shared,
    const char *alternate)
{
    pid_t pid = fork();
    if (pid < 0)
        fatal("could not fork portable nested mount-view fixture");
    if (pid == 0)
    {
        if (setup_bind_mount_namespace() != 0 ||
            mount(downloads_shared, documents_shared, NULL, MS_BIND, NULL) != 0)
            _exit(CHILD_SKIP);

        struct stat documents_st, downloads_st;
        unsigned int documents_mount_id, downloads_mount_id;
        if (stat(documents_shared, &documents_st) != 0 ||
            stat(downloads_shared, &downloads_st) != 0 ||
            documents_st.st_dev != downloads_st.st_dev ||
            documents_st.st_ino != downloads_st.st_ino ||
            path_mount_id(documents_shared, &documents_mount_id) != 0 ||
            path_mount_id(downloads_shared, &downloads_mount_id) != 0 ||
            documents_mount_id == downloads_mount_id)
            _exit(CHILD_SKIP);

        char documents_desc[PATH_MAX];
        path_join(documents_desc, sizeof(documents_desc),
                  documents_shared, "/desc");
        if (mount(alternate, documents_desc, NULL, MS_BIND, NULL) != 0)
            _exit(CHILD_SKIP);

        int documents_fd = open_dir(documents_root);
        int downloads_fd = open_dir(downloads_root);
        if (documents_fd < 0 || downloads_fd < 0)
            _exit(1);

        DestinationIdentityGraph graph;
        destination_identity_graph_init(
            &graph, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
        DestinationIdentityPlacement placement;
        size_t conflicting_owner;
        DestinationIdentityNameConflict name_conflict;
        errno = 0;
        DestinationIdentityStatus first = destination_identity_graph_add(
            &graph, downloads_fd, "shared/desc/docs-file",
            DESTINATION_IDENTITY_NON_DIRECTORY, 1, &placement,
            &conflicting_owner, &name_conflict);
        errno = 0;
        DestinationIdentityStatus second = destination_identity_graph_add(
            &graph, documents_fd, "shared/desc/downloads-file",
            DESTINATION_IDENTITY_NON_DIRECTORY, 2, &placement,
            &conflicting_owner, &name_conflict);
        int second_errno = errno;
        destination_identity_graph_free(&graph);
        close(documents_fd);
        close(downloads_fd);
        _exit(first == DESTINATION_IDENTITY_OK &&
              second == DESTINATION_IDENTITY_COLLISION &&
              second_errno == EISDIR ? 0 : 1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        fatal("could not wait for portable nested mount-view fixture");
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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

static void test_resolved_destination_identity_replay(void)
{
    printf(BLUE "::" NC " portable replay enforces resolved destination identity\n");

    ManifestRoot bootstrap = root_for();
    ManifestRoot roots[3];
    Fixture fixture;
    const char *xdg_dirs[XDG_KEY_COUNT] = {0};

    int opened = fixture_open(&fixture, &bootstrap);
    check(opened == 0, "direct replay alias-collision fixture is created");
    if (opened != 0)
        return;

    memset(roots, 0, 2U * sizeof(*roots));
    strcpy(roots[0].id, "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    strcpy(roots[0].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[0].source_path, "/source/Documents");
    strcpy(roots[1].id, "XDG_DOWNLOAD_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOWNLOAD_DIR");
    strcpy(roots[1].source_path, "/source/Downloads");
    check(write_v1_identity_manifest(&fixture, roots, 2) == 0,
          "direct replay VERSION=1 alias manifest is written");

    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    make_dir_at(fixture.data_fd, "XDG_DOWNLOAD_DIR", 0700);
    int docs_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int downloads_fd = openat(fixture.data_fd, "XDG_DOWNLOAD_DIR",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (docs_fd < 0 || downloads_fd < 0)
        fatal("could not open direct replay alias payload roots");
    write_file_at(docs_fd, "file", "DOCS");
    write_file_at(downloads_fd, "file", "DOWNLOADS");
    if (close(docs_fd) != 0 || close(downloads_fd) != 0)
        fatal("could not close direct replay alias payload roots");

    SidecarEntry collision_entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0750, 1700001100, 1, 1700001101, 2),
        entry_for("XDG_DOCUMENTS_DIR", "file", "file",
                  SIDECAR_KIND_REGULAR, 4, 0640,
                  1700001102, 3, 1700001103, 4),
        entry_for("XDG_DOWNLOAD_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0755, 1700001110, 5, 1700001111, 6),
        entry_for("XDG_DOWNLOAD_DIR", "file", "file",
                  SIDECAR_KIND_REGULAR, 9, 0600,
                  1700001112, 7, 1700001113, 8)
    };
    check(write_sidecar(&fixture, collision_entries, 4, NULL, NULL) == 0,
          "direct replay alias sidecar is committed");
    make_dir_at(fixture.home_fd, "Shared", 0700);
    if (symlinkat("Shared", fixture.home_fd, "Alias") != 0)
        fatal("could not create direct replay alias");
    int shared_fd = openat(fixture.home_fd, "Shared",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (shared_fd < 0)
        fatal("could not open direct replay Shared target");
    write_file_at(shared_fd, "file", "ORIGINAL");
    if (close(shared_fd) != 0)
        fatal("could not close direct replay Shared target");

    char shared[PATH_MAX], alias[PATH_MAX], sentinel[PATH_MAX];
    path_join(shared, sizeof(shared), fixture.home, "/Shared");
    path_join(alias, sizeof(alias), fixture.home, "/Alias");
    path_join(sentinel, sizeof(sentinel), shared, "/file");
    xdg_dirs[0] = shared;
    xdg_dirs[1] = alias;
    PortableRestoreReplayReport report;
    int result = run_replay_with_xdg(&fixture, &report, xdg_dirs);
    check(result != 0 && report.applied_count == 0 &&
              file_equals_noatime(sentinel, "ORIGINAL"),
          "direct replay refuses aliased duplicate files before any target content changes");
    fixture_close(&fixture);

    memset(xdg_dirs, 0, sizeof(xdg_dirs));
    opened = fixture_open(&fixture, &bootstrap);
    check(opened == 0, "nested alias replay fixture is created");
    if (opened != 0)
        return;

    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "HOME");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "HOME");
    strcpy(roots[0].source_path, "/source/Outer");
    strcpy(roots[0].restore_path, "Outer");
    roots[0].has_restore_path = 1;
    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "/source/Documents");
    strcpy(roots[2].id, "XDG_DOWNLOAD_DIR");
    roots[2].policy = ROOT_POLICY_XDG;
    strcpy(roots[2].payload_path, "XDG_DOWNLOAD_DIR");
    strcpy(roots[2].source_path, "/source/Downloads");
    check(write_v1_identity_manifest(&fixture, roots, 3) == 0,
          "nested alias VERSION=1 manifest is written");

    make_dir_at(fixture.data_fd, "HOME", 0700);
    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    make_dir_at(fixture.data_fd, "XDG_DOWNLOAD_DIR", 0700);
    int home_payload_fd = openat(fixture.data_fd, "HOME",
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    docs_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    downloads_fd = openat(fixture.data_fd, "XDG_DOWNLOAD_DIR",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_payload_fd < 0 || docs_fd < 0 || downloads_fd < 0)
        fatal("could not open nested alias payload roots");
    write_file_at(home_payload_fd, "outer.txt", "LINKED");
    write_file_at(docs_fd, "middle.txt", "MIDDLE");
    write_file_at(downloads_fd, "leaf-link.txt", "");
    if (close(home_payload_fd) != 0 || close(docs_fd) != 0 ||
        close(downloads_fd) != 0)
        fatal("could not close nested alias payload roots");

    SidecarEntry success_entries[] = {
        entry_for("HOME", "", "", SIDECAR_KIND_DIRECTORY, 0, 0711,
                  1700001200, 1, 1700001201, 2),
        entry_for("HOME", "outer.txt", "outer.txt", SIDECAR_KIND_REGULAR,
                  6, 0640, 1700001202, 3, 1700001203, 4),
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0722, 1700001210, 5, 1700001211, 6),
        entry_for("XDG_DOCUMENTS_DIR", "middle.txt", "middle.txt",
                  SIDECAR_KIND_REGULAR, 6, 0600,
                  1700001212, 7, 1700001213, 8),
        entry_for("XDG_DOWNLOAD_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0733, 1700001220, 9, 1700001221, 10),
        entry_for("XDG_DOWNLOAD_DIR", "leaf-link.txt", "leaf-link.txt",
                  SIDECAR_KIND_HARDLINK, 0, 0640,
                  1700001222, 11, 1700001223, 12)
    };
    success_entries[5].hardlink_root_id = text_bytes("HOME");
    success_entries[5].hardlink_logical_path = text_bytes("outer.txt");
    check(write_sidecar(&fixture, success_entries, 6, NULL, NULL) == 0,
          "nested alias sidecar with a cross-root hardlink is committed");

    make_dir_at(fixture.home_fd, "Outer", 0700);
    int outer_fd = openat(fixture.home_fd, "Outer",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (outer_fd < 0)
        fatal("could not open nested alias Outer target");
    make_dir_at(outer_fd, "Middle", 0700);
    int middle_fd = openat(outer_fd, "Middle",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (middle_fd < 0)
        fatal("could not open nested alias Middle target");
    make_dir_at(middle_fd, "Leaf", 0700);
    if (close(middle_fd) != 0 || close(outer_fd) != 0)
        fatal("could not close nested alias target directories");
    if (symlinkat("Outer/Middle", fixture.home_fd, "d") != 0 ||
        symlinkat("Outer/Middle/Leaf", fixture.home_fd,
                  "a-very-long-download-alias") != 0)
        fatal("could not create nested alias trust roots");

    char outer[PATH_MAX], middle[PATH_MAX], leaf[PATH_MAX];
    char documents_alias[PATH_MAX], downloads_alias[PATH_MAX];
    char outer_file[PATH_MAX], leaf_file[PATH_MAX];
    path_join(outer, sizeof(outer), fixture.home, "/Outer");
    path_join(middle, sizeof(middle), outer, "/Middle");
    path_join(leaf, sizeof(leaf), middle, "/Leaf");
    path_join(documents_alias, sizeof(documents_alias), fixture.home, "/d");
    path_join(downloads_alias, sizeof(downloads_alias), fixture.home,
              "/a-very-long-download-alias");
    path_join(outer_file, sizeof(outer_file), outer, "/outer.txt");
    path_join(leaf_file, sizeof(leaf_file), leaf, "/leaf-link.txt");
    xdg_dirs[0] = documents_alias;
    xdg_dirs[1] = downloads_alias;

    check(run_preflight_with_xdg(&fixture, xdg_dirs) == 0,
          "non-conflicting nested aliases pass portable preflight");
    result = run_replay_with_xdg(&fixture, &report, xdg_dirs);
    struct stat outer_st, middle_st, leaf_st, first_st, second_st;
    int metadata_ok = stat(outer, &outer_st) == 0 &&
                      stat(middle, &middle_st) == 0 &&
                      stat(leaf, &leaf_st) == 0;
    int hardlink_ok = stat(outer_file, &first_st) == 0 &&
                      stat(leaf_file, &second_st) == 0 &&
                      first_st.st_dev == second_st.st_dev &&
                      first_st.st_ino == second_st.st_ino;
    check(result == 0 && report.failed_count == 0 && hardlink_ok &&
              file_equals_noatime(outer_file, "LINKED") &&
              file_equals_noatime(leaf_file, "LINKED"),
          "nested alias replay preserves cross-root hardlink identity");
    check(metadata_ok && (outer_st.st_mode & 07777) == 0711 &&
              (middle_st.st_mode & 07777) == 0722 &&
              (leaf_st.st_mode & 07777) == 0733 &&
              outer_st.st_mtim.tv_sec == 1700001201 &&
              middle_st.st_mtim.tv_sec == 1700001211 &&
              leaf_st.st_mtim.tv_sec == 1700001221,
          "nested alias replay finalizes directory metadata by resolved namespace depth");
    fixture_close(&fixture);
}

static void test_ascii_case_distinct_names(void)
{
    printf(BLUE "::" NC " portable replay: byte-sensitive directories keep ASCII-case-distinct names\n");

    ManifestRoot root = root_for();
    Fixture fixture;
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "ASCII-case fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.data_fd, "ROOT", 0700);
    int root_fd = openat(fixture.data_fd, "ROOT",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        fatal("could not open ASCII-case payload root");
    write_file_at(root_fd, "Documents", "UPPER");
    write_file_at(root_fd, "documents", "LOWER");
    if (close(root_fd) != 0)
        fatal("could not close ASCII-case payload root");

    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0755, 10, 1, 20, 2),
        entry_for("ROOT", "Documents", "Documents", SIDECAR_KIND_REGULAR, 5,
                  0600, 11, 1, 21, 2),
        entry_for("ROOT", "documents", "documents", SIDECAR_KIND_REGULAR, 5,
                  0600, 12, 1, 22, 2)
    };
    check(write_sidecar(&fixture, entries, 3, NULL, NULL) == 0,
          "ASCII-case sidecar is committed");

    check(run_preflight(&fixture) == 0,
          "ordinary byte-sensitive directory passes portable preflight");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    char upper[PATH_MAX], lower[PATH_MAX];
    path_join(upper, sizeof(upper), fixture.home, "/restored/Documents");
    path_join(lower, sizeof(lower), fixture.home, "/restored/documents");
    check(result == 0 && report.failed_count == 0 &&
              file_equals_noatime(upper, "UPPER") &&
              file_equals_noatime(lower, "LOWER"),
          "ordinary byte-sensitive directory restores both ASCII-case-distinct entries");
    fixture_close(&fixture);
}

static void test_portable_identity_graph_keeps_nested_mount_views_route_specific(void)
{
    printf(BLUE "::" NC " portable restore identity graph: nested bind-mounted descendants keep route-specific views\n");

    Fixture fixture;
    ManifestRoot root = root_for();
    int opened = fixture_open(&fixture, &root);
    check(opened == 0, "nested mount-view fixture is created");
    if (opened != 0)
        return;

    make_dir_at(fixture.home_fd, "Documents", 0700);
    make_dir_at(fixture.home_fd, "Downloads", 0700);
    make_dir_at(fixture.home_fd, "alternate", 0700);
    char documents_root[PATH_MAX], downloads_root[PATH_MAX];
    char documents_shared[PATH_MAX], downloads_shared[PATH_MAX];
    char documents_desc[PATH_MAX], downloads_desc[PATH_MAX], alternate[PATH_MAX];
    path_join(documents_root, sizeof(documents_root), fixture.home,
              "/Documents");
    path_join(downloads_root, sizeof(downloads_root), fixture.home,
              "/Downloads");
    path_join(documents_shared, sizeof(documents_shared), fixture.home,
              "/Documents/shared");
    path_join(downloads_shared, sizeof(downloads_shared), fixture.home,
              "/Downloads/shared");
    path_join(documents_desc, sizeof(documents_desc), documents_shared, "/desc");
    path_join(downloads_desc, sizeof(downloads_desc), downloads_shared, "/desc");
    path_join(alternate, sizeof(alternate), fixture.home, "/alternate");
    if (mkdir(documents_shared, 0700) != 0 || mkdir(downloads_shared, 0700) != 0 ||
        mkdir(documents_desc, 0700) != 0 || mkdir(downloads_desc, 0700) != 0)
        fatal("could not create nested mount-view destinations");

    char alternate_file[PATH_MAX];
    path_join(alternate_file, sizeof(alternate_file), alternate,
              "/downloads-file");
    if (mkdir(alternate_file, 0700) != 0)
        fatal("could not create alternate nested mount-view descendant");

    int result = run_nested_mount_view_graph_case(
        documents_root, downloads_root, documents_shared, downloads_shared,
        alternate);
    if (result == CHILD_SKIP)
        skip_case("portable nested bind-mounted descendant views",
                  "user namespace, bind mounts, or distinct mount ids are unavailable");
    else
        check(result == 0,
              "portable replay resolves descendants through the current route");
    fixture_close(&fixture);
}

static void test_differing_mount_ids_do_not_hide_portable_collisions(void)
{
    printf(BLUE "::" NC " portable replay: differing mount ids do not make aliases disjoint\n");

    ManifestRoot bootstrap = root_for();
    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    strcpy(roots[0].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[0].source_path, "/source/Documents");
    strcpy(roots[1].id, "XDG_DOWNLOAD_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOWNLOAD_DIR");
    strcpy(roots[1].source_path, "/source/Downloads");

    Fixture fixture;
    int opened = fixture_open(&fixture, &bootstrap);
    check(opened == 0, "differing-mount-id fixture is created");
    if (opened != 0)
        return;
    check(write_v1_identity_manifest(&fixture, roots, 2) == 0,
          "differing-mount-id manifest is written");
    make_dir_at(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700);
    make_dir_at(fixture.data_fd, "XDG_DOWNLOAD_DIR", 0700);
    int documents_payload = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                                   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int downloads_payload = openat(fixture.data_fd, "XDG_DOWNLOAD_DIR",
                                   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (documents_payload < 0 || downloads_payload < 0)
        fatal("could not open differing-mount-id payload roots");
    make_dir_at(documents_payload, "shared", 0700);
    make_dir_at(downloads_payload, "shared", 0700);
    int documents_shared_payload = openat(
        documents_payload, "shared", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int downloads_shared_payload = openat(
        downloads_payload, "shared", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (documents_shared_payload < 0 || downloads_shared_payload < 0)
        fatal("could not open differing-mount-id shared payloads");
    write_file_at(documents_shared_payload, "file", "DOCS");
    write_file_at(downloads_shared_payload, "file", "DOWNLOADS");
    if (close(documents_shared_payload) != 0 ||
        close(downloads_shared_payload) != 0 || close(documents_payload) != 0 ||
        close(downloads_payload) != 0)
        fatal("could not close differing-mount-id payloads");

    make_dir_at(fixture.home_fd, "Documents", 0700);
    make_dir_at(fixture.home_fd, "Downloads", 0700);
    char documents_root[PATH_MAX], downloads_root[PATH_MAX];
    char documents_shared[PATH_MAX], downloads_shared[PATH_MAX];
    char sentinel[PATH_MAX];
    path_join(documents_root, sizeof(documents_root), fixture.home,
              "/Documents");
    path_join(downloads_root, sizeof(downloads_root), fixture.home,
              "/Downloads");
    path_join(documents_shared, sizeof(documents_shared), fixture.home,
              "/Documents/shared");
    path_join(downloads_shared, sizeof(downloads_shared), fixture.home,
              "/Downloads/shared");
    if (mkdir(documents_shared, 0700) != 0 || mkdir(downloads_shared, 0700) != 0)
        fatal("could not create differing-mount-id destinations");
    path_join(sentinel, sizeof(sentinel), downloads_shared, "/file");
    int sentinel_fd = open(sentinel, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                           0600);
    if (sentinel_fd < 0 || write(sentinel_fd, "ORIGINAL", 8) != 8 ||
        close(sentinel_fd) != 0)
        fatal("could not create differing-mount-id sentinel");

    SidecarEntry entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0755, 10, 1, 20, 2),
        entry_for("XDG_DOCUMENTS_DIR", "shared", "shared",
                  SIDECAR_KIND_DIRECTORY, 0, 0755, 11, 1, 21, 2),
        entry_for("XDG_DOCUMENTS_DIR", "shared/file", "shared/file",
                  SIDECAR_KIND_REGULAR, 4, 0600, 12, 1, 22, 2),
        entry_for("XDG_DOWNLOAD_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0,
                  0755, 13, 1, 23, 2),
        entry_for("XDG_DOWNLOAD_DIR", "shared", "shared",
                  SIDECAR_KIND_DIRECTORY, 0, 0755, 14, 1, 24, 2),
        entry_for("XDG_DOWNLOAD_DIR", "shared/file", "shared/file",
                  SIDECAR_KIND_REGULAR, 8, 0600, 15, 1, 25, 2)
    };
    check(write_sidecar(&fixture, entries, 6, NULL, NULL) == 0,
          "differing-mount-id sidecar is committed");

    int result = run_portable_mount_case(
        &fixture, documents_root, downloads_root, documents_shared,
        downloads_shared, sentinel);
    if (result == CHILD_SKIP)
        skip_case("portable differing-mount-id alias collision",
                  "user namespace, bind mounts, or distinct mount ids are unavailable");
    else
        check(result == 0 && file_equals_noatime(sentinel, "ORIGINAL"),
              "portable preflight refuses the collision before mutation");
    fixture_close(&fixture);
}

static void test_v2_nested_root_replay_order(void)
{
    printf(BLUE "::" NC " VERSION=2 replay uses combined destination order across roots\n");

    ManifestRoot bootstrap = root_for();
    ManifestRoot roots[2];
    Fixture fixture;
    int opened = fixture_open(&fixture, &bootstrap);
    check(opened == 0, "VERSION=2 replay fixture is created");
    if (opened != 0)
        return;
    check(write_v2_nested_manifest(&fixture, roots) == 0,
          "VERSION=2 replay manifest is written");

    make_dir_at(fixture.data_fd, "HOME", 0700);
    make_dir_at(fixture.data_fd, "CHILD", 0700);
    int home_payload_fd = openat(fixture.data_fd, "HOME",
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int child_payload_fd = openat(fixture.data_fd, "CHILD",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_payload_fd < 0 || child_payload_fd < 0)
        fatal("could not open VERSION=2 replay payload roots");
    write_file_at(home_payload_fd, "home.txt", "home");
    write_file_at(child_payload_fd, "child.txt", "child");
    if (close(home_payload_fd) != 0 || close(child_payload_fd) != 0)
        fatal("could not close VERSION=2 replay payload roots");

    SidecarEntry entries[] = {
        entry_for("HOME", "", "", SIDECAR_KIND_DIRECTORY, 0, 0711,
                  1700000900, 1, 1700000901, 2),
        entry_for("HOME", "home.txt", "home.txt", SIDECAR_KIND_REGULAR, 4, 0640,
                  1700000902, 3, 1700000903, 4),
        entry_for("CHILD", "", "", SIDECAR_KIND_DIRECTORY, 0, 0750,
                  1700000910, 5, 1700000911, 6),
        entry_for("CHILD", "child.txt", "child.txt", SIDECAR_KIND_REGULAR, 5, 0600,
                  1700000912, 7, 1700000913, 8)
    };
    check(write_sidecar(&fixture, entries, 4, NULL, NULL) == 0,
          "VERSION=2 replay sidecar is committed");
    check(run_preflight(&fixture) == 0,
          "VERSION=2 nested roots pass portable preflight");

    PortableRestoreReplayReport report;
    int result = run_replay(&fixture, &report);
    char home_file[PATH_MAX], child_file[PATH_MAX], documents[PATH_MAX];
    path_join(home_file, sizeof(home_file), fixture.home, "/home.txt");
    path_join(child_file, sizeof(child_file), fixture.home, "/Documents/child.txt");
    path_join(documents, sizeof(documents), fixture.home, "/Documents");
    struct stat home_st, documents_st;
    int metadata_ok = stat(fixture.home, &home_st) == 0 &&
                      stat(documents, &documents_st) == 0;
    check(result == 0 && report.failed_count == 0 &&
              file_equals_noatime(home_file, "home") &&
              file_equals_noatime(child_file, "child"),
          "VERSION=2 replay maps both roots to their recorded target destinations");
    check(metadata_ok && (home_st.st_mode & 07777) == 0711 &&
              (documents_st.st_mode & 07777) == 0750 &&
              home_st.st_mtim.tv_sec == 1700000901 &&
              documents_st.st_mtim.tv_sec == 1700000911,
          "directory metadata is finalized deepest-first across VERSION=2 roots");
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
    test_resolved_destination_identity_replay();
    test_ascii_case_distinct_names();
    test_portable_identity_graph_keeps_nested_mount_views_route_specific();
    test_differing_mount_ids_do_not_hide_portable_collisions();
    test_v2_nested_root_replay_order();
    test_copy_bytes_rejects_corruption();
    if (skips != 0)
        printf(YELLOW "%d portable restore replay test(s) skipped" NC "\n",
               skips);
    printf("%s%s%s\n", failures == 0 ? GREEN : RED,
           failures == 0 ? "all portable restore replay tests passed" :
           "portable restore replay tests failed", NC);
    return failures == 0 ? 0 : 1;
}
