// Unit tests for the portable restore preflight gate (docs/DECISIONS.md
// D17/D21): portable_restore_preflight_at() is the read-only validation layer of
// the portable restore path — it checks an untrusted portable container
// without mutating anything: no destination write, no container write, no
// O_TMPFILE probe. Ownership profiles are only *collected* here; the probe
// itself is deferred until after user confirmation, before the first
// persistent destination mutation.
//
// Every fixture is built from raw pieces (manifest written via
// manifest_write_v1_at, payload files planted under data/, sidecar records
// committed through the real sidecar_log_* API or raw bytes appended for
// malformed-input cases), so a reader bug can never be masked by the writer
// refusing to produce the input under test — same split as
// tests/test_manifest.c and tests/test_sidecar.c.
//
// The adversarial set covers lexical path refusals (absolute, `..`, empty
// component), duplicate logical→physical mapping, file-as-ancestor,
// manifest-external and unrepresented roots, unsupported kinds, nonzero
// xattr count, intermediate and final payload symlink redirects, interior
// malformed / truncated / oversized sidecar records, and decoded-NUL
// attempts. The gate assertion on every rejection path — and on the
// success path — is that the destination sentinel file is untouched; the
// metadata_test_probe_count() seam additionally proves the ownership probe
// is never fired by this step.

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
#include "metadata.h"
#include "portable_name.h"
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
    fprintf(stderr, "portable restore preflight fixture failure: %s\n",
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

static void remove_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT)
            return;
        fatal("could not inspect fixture tree");
    }
    if (nftw(path, remove_callback, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fatal("could not remove fixture tree");
}

static void make_dir(const char *path)
{
    if (mkdir(path, 0700) != 0)
        fatal("could not create fixture directory");
}

static void fixture_path(char *out, size_t out_size, const char *base,
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

static void write_file_at(int parent_fd, const char *name, const char *text)
{
    int fd = openat(parent_fd, name,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, text, strlen(text)) != (ssize_t)strlen(text) ||
        close(fd) != 0)
        fatal("could not write fixture file");
}

static int file_equals(const char *path, const char *expected)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    char buffer[256];
    size_t expected_length = strlen(expected);
    ssize_t received = read(fd, buffer, sizeof(buffer));
    int result = received == (ssize_t)expected_length &&
                 memcmp(buffer, expected, expected_length) == 0;
    if (close(fd) != 0)
        result = 0;
    return result;
}

static off_t descriptor_size(int fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0)
        fatal("could not inspect fixture descriptor");
    return st.st_size;
}

static SidecarBytes text_bytes(const char *text)
{
    return (SidecarBytes){ (const unsigned char *)text, strlen(text) };
}

static SidecarEntry entry_for(const char *root, const char *logical,
                              const char *physical, SidecarObjectKind kind,
                              uint64_t size)
{
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = text_bytes(root);
    entry.logical_path = text_bytes(logical);
    const char *slash = strrchr(physical, '/');
    const char *leaf = logical[0] == '\0' ? "" :
                       (slash == NULL ? physical : slash + 1);
    entry.physical_leaf = text_bytes(leaf);
    entry.kind = kind;
    entry.mode = kind == SIDECAR_KIND_DIRECTORY ? 0755U : 04755U;
    entry.uid = (uint32_t)(geteuid() == 0 ? 65534U : 0U);
    entry.gid = (uint32_t)(getegid() == 0 ? 65534U : 0U);
    entry.atime_sec = 10;
    entry.mtime_sec = 20;
    entry.atime_nsec = 1;
    entry.mtime_nsec = 2;
    entry.size = size;
    return entry;
}

static ManifestRoot root_for(const char *id, const char *payload,
                             const char *restore)
{
    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    snprintf(root.id, sizeof(root.id), "%s", id);
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    snprintf(root.payload_path, sizeof(root.payload_path), "%s", payload);
    snprintf(root.source_path, sizeof(root.source_path), "/source/%s", id);
    root.has_restore_path = 1;
    snprintf(root.restore_path, sizeof(root.restore_path), "%s", restore);
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

static void fixture_close(Fixture *fixture);

static int fixture_open(Fixture *fixture, const char *label,
                        ManifestRoot *roots, int root_count)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->container_fd = -1;
    fixture->data_fd = -1;
    fixture->home_fd = -1;
    snprintf(fixture->base, sizeof(fixture->base),
             "/tmp/migr_portable_restore_%s_XXXXXX", label);
    if (mkdtemp(fixture->base) == NULL)
        return -1;
    if (snprintf(fixture->container, sizeof(fixture->container), "%s/container",
                 fixture->base) < 0 ||
        snprintf(fixture->home, sizeof(fixture->home), "%s/home",
                 fixture->base) < 0)
        fatal("fixture path is too long");
    make_dir(fixture->container);
    make_dir(fixture->home);
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
        .root_count = root_count,
        .roots = roots
    };
    if (manifest_write_v1_at(fixture->container_fd, &manifest) != 0)
    {
        fixture_close(fixture);
        return -1;
    }
    return 0;
}

static void fixture_close(Fixture *fixture)
{
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

static int append_entries(SidecarLog *log, const SidecarEntry *entries,
                          size_t count)
{
    for (size_t index = 0; index < count; index++)
    {
        SidecarClaim claim = {
            .root_id = entries[index].root_id,
            .logical_path = entries[index].logical_path,
            .physical_leaf = entries[index].physical_leaf,
            .kind = entries[index].kind
        };
        if (entries[index].kind != SIDECAR_KIND_FIFO &&
            sidecar_log_append_claim(log, &claim) != SIDECAR_STATUS_OK)
            return -1;
        if (sidecar_log_append_entry(log, &entries[index]) != SIDECAR_STATUS_OK)
            return -1;
        if (entries[index].xattr_count != 0)
        {
            SidecarXattr xattr = {
                .name = text_bytes("user.migr_test"),
                .value = text_bytes("value")
            };
            if (sidecar_log_append_xattr(log, &xattr) != SIDECAR_STATUS_OK)
                return -1;
        }
        if (sidecar_log_append_entry_commit(log) != SIDECAR_STATUS_OK)
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

static int write_raw_entries_sidecar(Fixture *fixture,
                                     const SidecarEntry *entries,
                                     size_t count)
{
    SidecarLog log = {0};
    if ((entries == NULL && count != 0) ||
        sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH || sidecar_log_close(&log) !=
            SIDECAR_STATUS_OK)
        return -1;
    int fd = openat(fixture->container_fd, SIDECAR_SLOT_NAME,
                    O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int result = 1;
    for (size_t index = 0; index < count && result; index++)
        result = sidecar_write_entry(fd, &entries[index]) == 0 &&
                 sidecar_write_entry_commit(fd) == 0;
    if (close(fd) != 0)
        result = 0;
    return result ? 0 : -1;
}

static int write_raw_entry_sidecar(Fixture *fixture,
                                   const SidecarEntry *entry)
{
    return write_raw_entries_sidecar(fixture, entry, entry == NULL ? 0U : 1U);
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

static int append_raw_suffix_entry_fields(Fixture *fixture,
                                          const char *logical,
                                          const char *physical_leaf,
                                          const unsigned char *suffix,
                                          size_t suffix_length,
                                          const char *kind,
                                          const char *mode)
{
    unsigned char raw[512];
    size_t length = 0;
    if (raw_text_field(raw, sizeof(raw), &length, "ENTRY") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, "ROOT") != 0 ||
        raw_text_field(raw, sizeof(raw), &length, logical) != 0 ||
        raw_text_field(raw, sizeof(raw), &length, physical_leaf) != 0 ||
        raw_field(raw, sizeof(raw), &length, suffix, suffix_length) != 0 ||
        raw_text_field(raw, sizeof(raw), &length, kind) != 0 ||
        raw_text_field(raw, sizeof(raw), &length, mode) != 0 ||
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

static int append_raw_suffix_entry(Fixture *fixture,
                                   const unsigned char *suffix,
                                   size_t suffix_length)
{
    return append_raw_suffix_entry_fields(fixture, "file", "file", suffix,
                                          suffix_length, "regular", "600");
}

static int run_preflight_with_xdg(
    Fixture *fixture, PortableRestorePreflightReport *report,
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
        .destination_home_path = fixture->home
    };
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        request.destination_xdg_dirs[index] =
            destination_xdg_dirs == NULL ? NULL : destination_xdg_dirs[index];
    portable_restore_preflight_report_init(report);
    int result = portable_restore_preflight_at(&request, report);
    manifest_free(&manifest);
    return result;
}

static int run_preflight(Fixture *fixture,
                         PortableRestorePreflightReport *report)
{
    return run_preflight_with_xdg(fixture, report, NULL);
}

static int run_preflight_capturing(Fixture *fixture,
                                   PortableRestorePreflightReport *report,
                                   char *output, size_t output_size)
{
    if (fixture == NULL || report == NULL || output == NULL ||
        output_size == 0)
        fatal("invalid preflight output capture fixture");

    fflush(stdout);
    FILE *file = tmpfile();
    int saved_stdout = dup(STDOUT_FILENO);
    if (file == NULL || saved_stdout < 0 ||
        dup2(fileno(file), STDOUT_FILENO) < 0)
        fatal("could not redirect preflight output");

    int result = run_preflight(fixture, report);
    fflush(stdout);
    if (dup2(saved_stdout, STDOUT_FILENO) < 0 || close(saved_stdout) != 0)
        fatal("could not restore preflight output");
    rewind(file);
    size_t received = fread(output, 1, output_size - 1U, file);
    if (ferror(file))
        fatal("could not read captured preflight output");
    output[received] = '\0';
    if (fclose(file) != 0)
        fatal("could not close captured preflight output");
    return result;
}

static void make_root_payload(Fixture *fixture)
{
    if (mkdirat(fixture->data_fd, "ROOT", 0700) != 0)
        fatal("could not create root payload");
}

static void test_valid_and_profiles(void)
{
    printf(BLUE "::" NC " valid preflight and ownership collection\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "valid", &root, 1);
    check(opened == 0, "valid fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/file", "hello");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 5)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "valid sidecar is committed");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    metadata_test_reset_probe_count();
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result == 0, "valid portable state passes preflight");
    check(report.live_count == 2 && report.mapped_root_count == 1,
          "live count and manifest root mapping are reported");
    check(report.profiles.count > 0 && metadata_test_probe_count() == 0,
          "profiles are collected without firing the ownership probe");
    check(file_equals(sentinel, "untouched"),
          "successful preflight leaves the destination untouched");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_destination_profile_ancestor_cache(void)
{
    printf(BLUE "::" NC " destination profile walks reuse resolved ancestors\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "profile-cache", &root, 1);
    check(opened == 0, "profile-cache fixture is created");
    if (opened != 0)
        return;

    make_root_payload(&fixture);
    if (mkdirat(fixture.data_fd, "ROOT/deep", 0700) != 0 ||
        mkdirat(fixture.data_fd, "ROOT/deep/a", 0700) != 0 ||
        mkdirat(fixture.data_fd, "ROOT/deep/a/share", 0700) != 0 ||
        mkdirat(fixture.data_fd, "ROOT/deep/a/share2", 0700) != 0)
        fatal("could not create profile-cache payload directories");
    write_file_at(fixture.data_fd, "ROOT/deep/a/share/alpha", "x");
    write_file_at(fixture.data_fd, "ROOT/deep/a/share/beta", "x");
    write_file_at(fixture.data_fd, "ROOT/deep/a/share/missing", "x");
    write_file_at(fixture.data_fd, "ROOT/deep/a/share2/gamma", "x");

    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "deep", "deep", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "deep/a", "deep/a", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "deep/a/share", "deep/a/share",
                  SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "deep/a/share/alpha", "deep/a/share/alpha",
                  SIDECAR_KIND_REGULAR, 1),
        entry_for("ROOT", "deep/a/share/beta", "deep/a/share/beta",
                  SIDECAR_KIND_REGULAR, 1),
        entry_for("ROOT", "deep/a/share/missing", "deep/a/share/missing",
                  SIDECAR_KIND_REGULAR, 1),
        entry_for("ROOT", "deep/a/share2", "deep/a/share2",
                  SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "deep/a/share2/gamma", "deep/a/share2/gamma",
                  SIDECAR_KIND_REGULAR, 1)
    };
    check(write_sidecar(&fixture, entries,
                        sizeof(entries) / sizeof(entries[0])) == 0,
          "profile-cache sidecar is committed");

    char restored[PATH_MAX], deep[PATH_MAX], branch[PATH_MAX];
    char share[PATH_MAX], share2[PATH_MAX];
    fixture_path(restored, sizeof(restored), fixture.home, "/restored");
    fixture_path(deep, sizeof(deep), restored, "/deep");
    fixture_path(branch, sizeof(branch), deep, "/a");
    fixture_path(share, sizeof(share), branch, "/share");
    fixture_path(share2, sizeof(share2), branch, "/share2");
    make_dir(restored);
    make_dir(deep);
    make_dir(branch);
    make_dir(share);
    make_dir(share2);
    write_file_at(fixture.home_fd, "restored/deep/a/share/alpha", "old");
    write_file_at(fixture.home_fd, "restored/deep/a/share/beta", "old");
    write_file_at(fixture.home_fd, "restored/deep/a/share2/gamma", "old");

    struct stat share_st, share2_st;
    if (stat(share, &share_st) != 0 || stat(share2, &share2_st) != 0)
        fatal("could not inspect profile-cache destination directories");

    portable_restore_preflight_test_reset_profile_root_walk_count();
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    size_t root_walks =
        portable_restore_preflight_test_profile_root_walk_count();

    int saw_existing_share = 0;
    int saw_missing_share = 0;
    int saw_existing_share2 = 0;
    for (size_t index = 0; index < report.profiles.count; index++)
    {
        const MetadataProfile *profile = &report.profiles.items[index];
        if (profile->desired_mode != 04755U)
            continue;
        if (profile->anchor_device == share_st.st_dev &&
            profile->anchor_inode == share_st.st_ino)
        {
            if (profile->has_initial_owner &&
                profile->initial_uid == geteuid() &&
                profile->initial_gid == getegid())
                saw_existing_share = 1;
            if (!profile->has_initial_owner)
                saw_missing_share = 1;
        }
        if (profile->anchor_device == share2_st.st_dev &&
            profile->anchor_inode == share2_st.st_ino &&
            profile->has_initial_owner &&
            profile->initial_uid == geteuid() &&
            profile->initial_gid == getegid())
            saw_existing_share2 = 1;
    }

    check(result == 0 && report.live_count ==
              sizeof(entries) / sizeof(entries[0]),
          "deep sibling profile fixture passes preflight");
    check(saw_existing_share && saw_missing_share && saw_existing_share2,
          "cached walks preserve existing and missing destination profile state");
    check(root_walks == 2,
          "deep sibling groups need only two profile walks from the HOME anchor");

    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_payload_inventory_progress(void)
{
    printf(BLUE "::" NC " payload inventory reports live verification progress\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "payload-progress", &root, 1);
    check(opened == 0, "payload-progress fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/file", "hello");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 5)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "payload-progress sidecar is committed");

    PortableRestorePreflightReport report;
    char output[1024];
    portable_restore_preflight_test_set_progress_enabled(1);
    int result = run_preflight_capturing(&fixture, &report, output,
                                         sizeof(output));
    portable_restore_preflight_test_set_progress_enabled(0);
    const char *collection_start = strstr(
        output, "Verifying backup contents: entries 0/2 checked");
    const char *collection_done = strstr(
        output, "Verifying backup contents: entries 2/2 checked");
    const char *identity_start = strstr(
        output, "Verifying backup contents: identity 0/2 checked");
    const char *identity_done = strstr(
        output, "Verifying backup contents: identity 2/2 checked");
    const char *payload_start = strstr(
        output, "Verifying backup contents: payload 0/2 checked");
    const char *payload_done = strstr(
        output, "Verifying backup contents: payload 2/2 checked");
    check(result == 0 && collection_start != NULL && collection_done != NULL &&
              identity_start != NULL && identity_done != NULL &&
              payload_start != NULL && payload_done != NULL &&
              collection_start < collection_done &&
              collection_done < identity_start && identity_start < identity_done &&
              identity_done < payload_start && payload_start < payload_done,
          "preflight progress covers collection, identity validation, and payload scanning in order");

    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_outstanding_claim_gate(void)
{
    printf(BLUE "::" NC " outstanding claims are rejected before preflight probing\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "claim-gate", &root, 1);
    check(opened == 0, "claim-gate preflight fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/file", "hello");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 5)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "claim-gate preflight sidecar has valid live entries");
    SidecarClaim outstanding = {
        .root_id = text_bytes("ROOT"),
        .logical_path = text_bytes("blocked"),
        .physical_leaf = text_bytes("blocked"),
        .kind = SIDECAR_KIND_REGULAR
    };
    SidecarLog log = {0};
    check(sidecar_log_adopt_at(fixture.container_fd, &log) ==
              SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_append_claim(&log, &outstanding) ==
                  SIDECAR_STATUS_OK &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "an outstanding claim is planted in the valid sidecar");

    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    metadata_test_reset_probe_count();
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result != 0 && report.violation_count != 0 &&
              metadata_test_probe_count() == 0 &&
              file_equals(sentinel, "untouched"),
          "preflight rejects the claim before destination probing or mutation");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_missing_payload(void)
{
    printf(BLUE "::" NC " committed key without payload\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "missing", &root, 1);
    check(opened == 0, "missing-payload fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "missing", "missing", SIDECAR_KIND_REGULAR, 3)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "missing-payload state is committed");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    PortableRestorePreflightReport report;
    check(run_preflight(&fixture, &report) != 0 &&
          file_equals(sentinel, "untouched"),
          "missing payload is refused");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_shortened_leaf_preflight(void)
{
    printf(BLUE "::" NC " canonical shortened physical leaf preflight\n");
    char logical[NAME_MAX + 1U];
    memset(logical, '!', NAME_MAX);
    logical[NAME_MAX] = '\0';
    PortablePhysicalName mapped;
    check(portable_physical_name_map(logical, 0, &mapped) == 0 &&
              mapped.shortened,
          "overlong encoded component maps to a shortened physical leaf");

    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "shortened", &root, 1);
    check(opened == 0, "shortened-leaf fixture is created");
    if (opened == 0)
    {
        make_root_payload(&fixture);
        int payload_root = openat(fixture.data_fd, "ROOT",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not open shortened payload root");
        write_file_at(payload_root, mapped.physical_leaf, "shortened");
        if (close(payload_root) != 0)
            fatal("could not close shortened payload root");
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", logical, mapped.physical_leaf,
                      SIDECAR_KIND_REGULAR, 9)
        };
        check(write_sidecar(&fixture, entries, 2) == 0,
              "shortened-leaf sidecar is committed");
        write_file_at(fixture.home_fd, "sentinel", "untouched");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
        PortableRestorePreflightReport report;
        int result = run_preflight(&fixture, &report);
        check(result == 0 && report.live_count == 2 &&
                  report.mapped_root_count == 1 &&
                  report.violation_count == 0 &&
                  file_equals(sentinel, "untouched"),
              "canonical shortened leaf is inventoried without destination mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&fixture);
    }

    char tampered[NAME_MAX + 1U];
    snprintf(tampered, sizeof(tampered), "%s", mapped.physical_leaf);
    tampered[0] = tampered[0] == 'X' ? 'Y' : 'X';
    Fixture corrupt;
    opened = fixture_open(&corrupt, "shortened-tampered", &root, 1);
    check(opened == 0, "tampered-shortened fixture is created");
    if (opened == 0)
    {
        make_root_payload(&corrupt);
        int payload_root = openat(corrupt.data_fd, "ROOT",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not open tampered-shortened payload root");
        write_file_at(payload_root, tampered, "shortened");
        if (close(payload_root) != 0)
            fatal("could not close tampered-shortened payload root");
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", logical, tampered, SIDECAR_KIND_REGULAR, 9)
        };
        check(write_sidecar(&corrupt, entries, 2) == 0,
              "tampered-shortened sidecar is committed");
        write_file_at(corrupt.home_fd, "sentinel", "untouched");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), corrupt.home, "/sentinel");
        PortableRestorePreflightReport report;
        check(run_preflight(&corrupt, &report) != 0 &&
                  file_equals(sentinel, "untouched"),
              "non-canonical shortened leaf is refused before payload acceptance");
        portable_restore_preflight_report_free(&report);
        fixture_close(&corrupt);
    }
}

static void test_deep_physical_path_preflight(void)
{
    printf(BLUE "::" NC " fd-relative payload depth beyond physical PATH_MAX\n");
    enum { DEPTH = 17, COMPONENT_LENGTH = 100 };
    char component[COMPONENT_LENGTH + 1U];
    memset(component, '!', COMPONENT_LENGTH);
    component[COMPONENT_LENGTH] = '\0';
    PortablePhysicalName mapped;
    check(portable_physical_name_map(component, 0, &mapped) == 0 &&
              mapped.shortened &&
              DEPTH * strlen(mapped.physical_leaf) + (DEPTH - 1U) >
                  SIDECAR_MAX_PATH,
          "deep fixture exceeds the old cumulative physical path envelope");

    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "deep-physical", &root, 1);
    check(opened == 0, "deep physical-path fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    int directory_fds[DEPTH + 1U];
    for (size_t index = 0; index < DEPTH + 1U; index++)
        directory_fds[index] = -1;
    directory_fds[0] = openat(fixture.data_fd, "ROOT",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fds[0] < 0)
        fatal("could not open deep payload root");

    SidecarEntry entries[DEPTH + 1U];
    entries[0] = entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0);
    char logical[DEPTH][SIDECAR_MAX_PATH + 1U];
    size_t logical_length = 0;
    for (size_t index = 0; index < DEPTH; index++)
    {
        size_t parent_length = logical_length;
        if (index != 0)
        {
            memcpy(logical[index], logical[index - 1], parent_length);
            logical[index][parent_length++] = '/';
        }
        memcpy(logical[index] + parent_length, component, COMPONENT_LENGTH);
        logical_length = parent_length + COMPONENT_LENGTH;
        logical[index][logical_length] = '\0';
        entries[index + 1U] = entry_for(
            "ROOT", logical[index], mapped.physical_leaf,
            SIDECAR_KIND_DIRECTORY, 0);

        if (mkdirat(directory_fds[index], mapped.physical_leaf, 0700) != 0)
            fatal("could not create deep physical payload component");
        directory_fds[index + 1U] = openat(
            directory_fds[index], mapped.physical_leaf,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory_fds[index + 1U] < 0)
            fatal("could not descend through deep physical payload");
    }
    check(logical_length < SIDECAR_MAX_PATH,
          "deep fixture remains within the logical path ceiling");
    check(write_sidecar(&fixture, entries, DEPTH + 1U) == 0,
          "deep physical-path sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result == 0 && report.live_count == DEPTH + 1U &&
              report.violation_count == 0 &&
              file_equals(sentinel, "untouched"),
          "preflight inventories a valid over-PATH_MAX physical chain fd-relatively");
    portable_restore_preflight_report_free(&report);
    for (size_t index = DEPTH; index != 0; index--)
    {
        if (close(directory_fds[index]) != 0 ||
            unlinkat(directory_fds[index - 1U], mapped.physical_leaf,
                     AT_REMOVEDIR) != 0)
            fatal("could not remove deep physical payload component");
        directory_fds[index] = -1;
    }
    if (close(directory_fds[0]) != 0)
        fatal("could not close deep payload root");
    fixture_close(&fixture);
}

static void test_destination_profile_refusal_is_named(void)
{
    printf(BLUE "::" NC " destination profile refusal is named\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "destination-symlink", &root, 1);
    check(opened == 0, "destination-symlink fixture is created");
    if (opened != 0)
        return;

    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 7)
    };
    entries[0].uid = (uint32_t)geteuid();
    entries[0].gid = (uint32_t)getegid();
    check(write_sidecar(&fixture, entries, 2) == 0,
          "destination-symlink sidecar is committed");

    char restored[PATH_MAX], target[PATH_MAX];
    fixture_path(restored, sizeof(restored), fixture.home, "/restored");
    fixture_path(target, sizeof(target), restored, "/file");
    make_dir(restored);
    check(symlink("outside", target) == 0,
          "destination symlink is planted at the incoming target");

    PortableRestorePreflightReport report;
    char output[4096];
    int result = run_preflight_capturing(&fixture, &report, output,
                                         sizeof(output));
    check(result != 0 && report.violation_count == 1 &&
              report.root_count == 1 && report.roots != NULL &&
              report.roots[0].violation_count == 1 &&
              report.profiles.example_count == 1 &&
              strcmp(report.profiles.examples[0], "file") == 0,
          "destination anchor refusal names the offending entry and root");
    check(strstr(output, "preflight example: file") != NULL,
          "preflight output includes the offending logical path");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_destination_profile_refusal_keeps_scanning(void)
{
    printf(BLUE "::" NC " destination anchor refusal keeps scanning past "
                 "the first conflict\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "destination-symlink-two", &root, 1);
    check(opened == 0, "destination-symlink-two fixture is created");
    if (opened != 0)
        return;

    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/one", "payload");
    write_file_at(fixture.data_fd, "ROOT/two", "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "one", "one", SIDECAR_KIND_REGULAR, 7),
        entry_for("ROOT", "two", "two", SIDECAR_KIND_REGULAR, 7)
    };
    entries[0].uid = (uint32_t)geteuid();
    entries[0].gid = (uint32_t)getegid();
    check(write_sidecar(&fixture, entries, 3) == 0,
          "destination-symlink-two sidecar is committed");

    char restored[PATH_MAX], target_one[PATH_MAX], target_two[PATH_MAX];
    fixture_path(restored, sizeof(restored), fixture.home, "/restored");
    fixture_path(target_one, sizeof(target_one), restored, "/one");
    fixture_path(target_two, sizeof(target_two), restored, "/two");
    make_dir(restored);
    check(symlink("outside", target_one) == 0 &&
              symlink("outside", target_two) == 0,
          "destination symlinks are planted at both incoming targets");

    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result != 0 && report.violation_count == 2 &&
              report.root_count == 1 && report.roots != NULL &&
              report.roots[0].violation_count == 2 &&
              report.profiles.example_count == 2,
          "both destination anchor conflicts are recorded in one pass, "
          "not just the first");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void run_refusal_case(const char *label, ManifestRoot *root,
                             SidecarEntry *entries, size_t entry_count,
                             void (*prepare)(Fixture *fixture),
                             int raw_state)
{
    Fixture fixture;
    int opened = fixture_open(&fixture, label, root, 1);
    check(opened == 0, "refusal fixture is created");
    if (opened != 0)
        return;
    if (prepare != NULL)
        prepare(&fixture);
    int fifo_fixture = entries != NULL && entry_count == 1 &&
                       entries[0].kind == SIDECAR_KIND_FIFO;
    /* D25 excludes FIFO from claim kinds, and the wire parser rejects a raw
     * FIFO CLAIM as corruption.  No valid v4 wire sequence can therefore
     * reach collect_entry with FIFO; this raw entry must be rejected by the
     * strict claimless adoption gate before "unsupported-kind". */
    int sidecar_result = fifo_fixture || raw_state
        ? write_raw_entries_sidecar(&fixture, entries, entry_count)
        : write_sidecar(&fixture, entries, entry_count);
    check(sidecar_result == 0, "refusal sidecar is committed");
    if (fifo_fixture)
    {
        SidecarLog adopted = {0};
        SidecarOpenStatus status = sidecar_log_adopt_at(
            fixture.container_fd, &adopted);
        if (status == SIDECAR_OPEN_RESUMABLE)
            (void)sidecar_log_close(&adopted);
        check(status == SIDECAR_OPEN_UNUSABLE,
              "FIFO entry is rejected at the strict claim adoption gate");
    }
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    int preflight_result = run_preflight(&fixture, &report);
    if (fifo_fixture)
        check(preflight_result != 0 && report.violation_count == 1 &&
                  report.profiles.example_count == 1 &&
                  strcmp(report.profiles.examples[0], "preflight") == 0,
              "FIFO unsupported-kind is documented as unreachable after D25");
    else
        check(preflight_result != 0, label);
    check(file_equals(sentinel, "untouched"),
          "refusal leaves the destination sentinel untouched");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void prepare_root_dir(Fixture *fixture)
{
    make_root_payload(fixture);
}

static void prepare_root_file(Fixture *fixture)
{
    write_file_at(fixture->data_fd, "ROOT", "payload");
}

static void test_path_and_mapping_refusals(void)
{
    printf(BLUE "::" NC " lexical, mapping, and type refusals\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    SidecarEntry absolute[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "/absolute", "x", SIDECAR_KIND_REGULAR, 0)
    };
    run_refusal_case("absolute", &root, absolute, 2, prepare_root_dir, 0);
    SidecarEntry parent[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a", "a", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a/..", "a/dotdot", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a/../b", "a/dotdot/b", SIDECAR_KIND_REGULAR, 0)
    };
    run_refusal_case("dotdot", &root, parent, 4, prepare_root_dir, 0);
    SidecarEntry empty[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a", "a", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a/", "a/gap", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a//b", "a/gap/b", SIDECAR_KIND_REGULAR, 0)
    };
    run_refusal_case("empty-component", &root, empty, 4,
                     prepare_root_dir, 0);

    /* Both aliases are now rejected by the physical/logical invariant before
     * duplicate-path analysis; retain the two-entry shape as an early refusal. */
    SidecarEntry duplicate[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "a", "shared", SIDECAR_KIND_REGULAR, 3),
        entry_for("ROOT", "b", "shared", SIDECAR_KIND_REGULAR, 3)
    };
    run_refusal_case("physical-mismatch-before-duplicate", &root, duplicate, 3,
                     prepare_root_dir, 0);

    SidecarEntry ancestor[] = {
        entry_for("ROOT", "dir", "dir", SIDECAR_KIND_REGULAR, 7),
        entry_for("ROOT", "dir/child", "dir/child", SIDECAR_KIND_REGULAR, 1)
    };
    run_refusal_case("file-ancestor", &root, ancestor, 2,
                     prepare_root_file, 1);

    SidecarEntry external[] = {
        entry_for("OTHER", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("OTHER", "file", "file", SIDECAR_KIND_REGULAR, 0)
    };
    run_refusal_case("external-root", &root, external, 2,
                     prepare_root_dir, 0);

    SidecarEntry fifo = entry_for("ROOT", "fifo", "fifo", SIDECAR_KIND_FIFO, 0);
    run_refusal_case("unsupported-kind", &root, &fifo, 1,
                     prepare_root_dir, 1);

    SidecarEntry mismatch[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "innocuous.txt", "something-else.txt",
                  SIDECAR_KIND_REGULAR, 7)
    };
    run_refusal_case("physical-mismatch", &root, mismatch, 2,
                     prepare_root_dir, 0);
}

static void run_suffix_refusal_case(const char *label, const char *suffix,
                                    const char *physical,
                                    ManifestRoot *root)
{
    Fixture fixture;
    int opened = fixture_open(&fixture, label, root, 1);
    check(opened == 0, "suffix-refusal fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    char payload_path[PATH_MAX];
    int payload_length = snprintf(payload_path, sizeof(payload_path),
                                  "ROOT/%s", physical);
    if (payload_length < 0 || (size_t)payload_length >= sizeof(payload_path))
        fatal("suffix fixture payload path is too long");
    write_file_at(fixture.data_fd, payload_path, "payload");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "file", physical, SIDECAR_KIND_REGULAR, 0)
    };
    entries[1].collision_suffix = text_bytes(suffix);
    check(write_sidecar(&fixture, entries, 2) == 0,
          "suffix-refusal sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    check(run_preflight(&fixture, &report) != 0 &&
              file_equals(sentinel, "untouched"),
          label);
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void run_raw_suffix_refusal_case(const char *label,
                                        const unsigned char *suffix,
                                        size_t suffix_length,
                                        ManifestRoot *root)
{
    Fixture fixture;
    int opened = fixture_open(&fixture, label, root, 1);
    check(opened == 0, "raw suffix-refusal fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/file", "payload");
    check(append_raw_suffix_entry(&fixture, suffix, suffix_length) == 0,
          "raw malformed suffix record is committed");
    PortableRestorePreflightReport report;
    check(run_preflight(&fixture, &report) != 0 &&
              report.violation_count != 0,
          label);
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_collision_suffix_validation(void)
{
    printf(BLUE "::" NC " parent-prefix and collision-suffix validation\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "suffix-valid", &root, 1);
    check(opened == 0, "suffixed-tree fixture is created");
    if (opened == 0)
    {
        make_root_payload(&fixture);
        int payload_root = openat(fixture.data_fd, "ROOT",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not open suffixed payload root");
        if (mkdirat(payload_root, "dir%7E1", 0700) != 0)
            fatal("could not create suffixed payload directory");
        int suffixed_dir = openat(payload_root, "dir%7E1",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (suffixed_dir < 0)
            fatal("could not open suffixed payload directory");
        write_file_at(suffixed_dir, "file", "nested");
        close(suffixed_dir);
        write_file_at(payload_root, "Foo%7E1", "leaf");
        close(payload_root);

        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", "dir", "dir%7E1",
                      SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", "dir/file", "dir%7E1/file",
                      SIDECAR_KIND_REGULAR, 6),
            entry_for("ROOT", "Foo", "Foo%7E1", SIDECAR_KIND_REGULAR, 4)
        };
        entries[1].collision_suffix = text_bytes("%7E1");
        entries[3].collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&fixture, entries, 4) == 0,
              "suffixed-tree sidecar is committed");
        PortableRestorePreflightReport report;
        int result = run_preflight(&fixture, &report);
        check(result == 0 && report.live_count == 4 &&
                  report.violation_count == 0,
              "suffixed ancestor and suffixed leaf pass preflight");
        portable_restore_preflight_report_free(&report);

        payload_root = openat(fixture.data_fd, "ROOT",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not reopen suffixed payload root");
        suffixed_dir = openat(payload_root, "dir%7E1",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (suffixed_dir < 0)
            fatal("could not reopen suffixed payload directory");
        write_file_at(suffixed_dir, "foreign", "unknown");
        if (close(suffixed_dir) != 0 || close(payload_root) != 0)
            fatal("could not close suffixed payload directories");
        result = run_preflight(&fixture, &report);
        check(result != 0,
              "unknown sibling beneath a suffixed parent is refused locally");
        portable_restore_preflight_report_free(&report);
        fixture_close(&fixture);
    }

    run_suffix_refusal_case("suffix-lower-e", "%7e1", "file%7e1", &root);
    run_suffix_refusal_case("suffix-zero", "%7E0", "file%7E0", &root);
    run_suffix_refusal_case("suffix-leading-zero", "%7E01",
                            "file%7E01", &root);
    run_suffix_refusal_case("suffix-no-digits", "%7E", "file%7E", &root);
    run_suffix_refusal_case("suffix-overflow",
                            "%7E18446744073709551616",
                            "file%7E18446744073709551616", &root);
    static const unsigned char embedded_nul[] = { '%', '7', 'E', '\0', '1' };
    run_raw_suffix_refusal_case("suffix-embedded-nul", embedded_nul,
                                sizeof(embedded_nul), &root);
    unsigned char overlong[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    memset(overlong, '1', sizeof(overlong));
    overlong[0] = '%';
    overlong[1] = '7';
    overlong[2] = 'E';
    run_raw_suffix_refusal_case("suffix-over-ceiling", overlong,
                                sizeof(overlong), &root);

    Fixture missing;
    opened = fixture_open(&missing, "missing-parent", &root, 1);
    check(opened == 0, "missing-parent fixture is created");
    if (opened == 0)
    {
        make_root_payload(&missing);
        SidecarEntry child = entry_for("ROOT", "dir/file", "dir/file",
                                       SIDECAR_KIND_REGULAR, 0);
        check(write_raw_entry_sidecar(&missing, &child) == 0,
              "missing-parent sidecar is committed");
        PortableRestorePreflightReport report;
        check(run_preflight(&missing, &report) != 0,
              "missing parent entry is refused");
        portable_restore_preflight_report_free(&report);
        fixture_close(&missing);
    }

    Fixture mismatch;
    opened = fixture_open(&mismatch, "parent-mismatch", &root, 1);
    check(opened == 0, "parent-mismatch fixture is created");
    if (opened == 0)
    {
        make_root_payload(&mismatch);
        int payload_root = openat(mismatch.data_fd, "ROOT",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (payload_root < 0)
            fatal("could not open parent-mismatch payload root");
        if (mkdirat(payload_root, "dir%7E1", 0700) != 0)
            fatal("could not create parent-mismatch payload directory");
        close(payload_root);
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", "dir", "dir%7E1",
                      SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", "dir/file", "dir%7E1/other",
                      SIDECAR_KIND_REGULAR, 0)
        };
        entries[1].collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&mismatch, entries, 3) == 0,
              "parent-mismatch sidecar is committed");
        PortableRestorePreflightReport report;
        check(run_preflight(&mismatch, &report) != 0,
              "child physical mismatch beneath a suffixed parent is refused");
        portable_restore_preflight_report_free(&report);
        fixture_close(&mismatch);
    }

    Fixture root_suffix;
    opened = fixture_open(&root_suffix, "root-suffix", &root, 1);
    check(opened == 0, "root-suffix fixture is created");
    if (opened == 0)
    {
        make_root_payload(&root_suffix);
        static const unsigned char root_suffix_bytes[] = "%7E1";
        check(append_raw_suffix_entry_fields(
                  &root_suffix, "", "", root_suffix_bytes,
                  sizeof(root_suffix_bytes) - 1U, "directory", "755") == 0,
              "root-suffix sidecar is committed");
        PortableRestorePreflightReport report;
        check(run_preflight(&root_suffix, &report) != 0,
              "root payload entry cannot carry a collision suffix");
        portable_restore_preflight_report_free(&report);
        fixture_close(&root_suffix);
    }
}

static void test_xattr_entry_acceptance(void)
{
    printf(BLUE "::" NC " xattr-bearing entries pass preflight\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "xattr-accept", &root, 1);
    check(opened == 0, "xattr fixture is created");
    if (opened != 0)
        return;
    make_root_payload(&fixture);
    write_file_at(fixture.data_fd, "ROOT/file", "hello");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "file", "file", SIDECAR_KIND_REGULAR, 5)
    };
    entries[1].xattr_count = 1;
    check(write_sidecar(&fixture, entries, 2) == 0,
          "xattr-bearing sidecar is committed");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result == 0,
          "xattr-bearing entries pass preflight (replay can now apply them)");
    check(file_equals(sentinel, "untouched"),
          "xattr acceptance preflight leaves the destination untouched");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_symlink_refusals(void)
{
    printf(BLUE "::" NC " payload symlink refusals\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    SidecarEntry root_entry = entry_for("ROOT", "", "",
                                        SIDECAR_KIND_DIRECTORY, 0);
    Fixture fixture;
    int opened = fixture_open(&fixture, "root-symlink", &root, 1);
    check(opened == 0, "root-symlink fixture is created");
    if (opened == 0)
    {
        char outside[PATH_MAX], link_path[PATH_MAX];
        fixture_path(outside, sizeof(outside), fixture.base, "/outside");
        make_dir(outside);
        fixture_path(link_path, sizeof(link_path), fixture.container,
                     "/data/ROOT");
        check(symlink(outside, link_path) == 0,
              "intermediate payload symlink is planted");
        check(write_sidecar(&fixture, &root_entry, 1) == 0,
              "root-symlink sidecar is committed");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
        write_file_at(fixture.home_fd, "sentinel", "untouched");
        PortableRestorePreflightReport report;
        check(run_preflight(&fixture, &report) != 0 &&
              file_equals(sentinel, "untouched"),
              "intermediate payload symlink is refused without mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&fixture);
    }

    root_entry = entry_for("ROOT", "link", "link", SIDECAR_KIND_REGULAR, 4);
    Fixture final_fixture;
    opened = fixture_open(&final_fixture, "final-symlink", &root, 1);
    check(opened == 0, "final-symlink fixture is created");
    if (opened == 0)
    {
        make_root_payload(&final_fixture);
        char outside[PATH_MAX], link_path[PATH_MAX];
        fixture_path(outside, sizeof(outside), final_fixture.base, "/outside");
        write_file_at(final_fixture.home_fd, "outside", "outside");
        fixture_path(link_path, sizeof(link_path), final_fixture.container,
                     "/data/ROOT/link");
        check(symlink(outside, link_path) == 0,
              "final payload symlink is planted");
        SidecarEntry entries[] = {
            entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
            root_entry
        };
        check(write_sidecar(&final_fixture, entries, 2) == 0,
              "final-symlink sidecar is committed");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), final_fixture.home,
                     "/sentinel");
        write_file_at(final_fixture.home_fd, "sentinel", "untouched");
        PortableRestorePreflightReport report;
        check(run_preflight(&final_fixture, &report) != 0 &&
              file_equals(sentinel, "untouched"),
              "final payload symlink is refused without mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&final_fixture);
    }
}

static void test_malformed_sidecars(void)
{
    printf(BLUE "::" NC " malformed and truncated sidecars\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    const unsigned char malformed[] = { 'g','a','r','b','a','g','e' };
    Fixture fixture;
    int opened = fixture_open(&fixture, "malformed", &root, 1);
    check(opened == 0, "malformed fixture is created");
    if (opened == 0)
    {
        SidecarLog log = {0};
        check(sidecar_log_create_at(fixture.container_fd, &log) ==
                  SIDECAR_OPEN_FRESH && sidecar_log_close(&log) ==
                  SIDECAR_STATUS_OK &&
              append_raw_sidecar(&fixture, malformed, sizeof(malformed)) == 0,
              "interior malformed bytes are planted");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
        write_file_at(fixture.home_fd, "sentinel", "untouched");
        off_t sidecar_size = descriptor_size(fixture.container_fd);
        PortableRestorePreflightReport report;
        check(run_preflight(&fixture, &report) != 0 &&
              file_equals(sentinel, "untouched") &&
              descriptor_size(fixture.container_fd) == sidecar_size,
              "interior malformed sidecar is refused before mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&fixture);
    }

    Fixture truncated;
    opened = fixture_open(&truncated, "truncated", &root, 1);
    check(opened == 0, "truncated fixture is created");
    if (opened == 0)
    {
        SidecarLog log = {0};
        check(sidecar_log_create_at(truncated.container_fd, &log) ==
                  SIDECAR_OPEN_FRESH && sidecar_log_close(&log) ==
                  SIDECAR_STATUS_OK &&
              append_raw_sidecar(&truncated,
                                 (const unsigned char *)"ENTRY\0ROOT\0",
                                 sizeof("ENTRY\0ROOT\0") - 1U) == 0,
              "truncated record is planted");
        write_file_at(truncated.home_fd, "sentinel", "untouched");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), truncated.home, "/sentinel");
        off_t sidecar_size = descriptor_size(truncated.container_fd);
        PortableRestorePreflightReport report;
        check(run_preflight(&truncated, &report) != 0 &&
              file_equals(sentinel, "untouched") &&
              descriptor_size(truncated.container_fd) == sidecar_size,
              "truncated sidecar is refused without destination mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&truncated);
    }

    Fixture oversized;
    opened = fixture_open(&oversized, "oversized", &root, 1);
    check(opened == 0, "oversized fixture is created");
    if (opened == 0)
    {
        SidecarLog log = {0};
        check(sidecar_log_create_at(oversized.container_fd, &log) ==
                  SIDECAR_OPEN_FRESH &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
              "oversized sidecar header is created");

        size_t oversized_path_length = SIDECAR_MAX_PATH + 1U;
        size_t raw_length = 6U + 5U + oversized_path_length + 1U;
        unsigned char *raw = malloc(raw_length);
        if (raw == NULL)
            fatal("could not allocate oversized fixture record");
        size_t offset = 0;
        memcpy(raw + offset, "ENTRY\0", 6U);
        offset += 6U;
        memcpy(raw + offset, "ROOT\0", 5U);
        offset += 5U;
        memset(raw + offset, 'x', oversized_path_length);
        offset += oversized_path_length;
        raw[offset] = '\0';
        check(append_raw_sidecar(&oversized, raw, raw_length) == 0,
              "oversized path field is planted");
        free(raw);

        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), oversized.home,
                     "/sentinel");
        write_file_at(oversized.home_fd, "sentinel", "untouched");
        off_t sidecar_size = descriptor_size(oversized.container_fd);
        PortableRestorePreflightReport report;
        check(run_preflight(&oversized, &report) != 0 &&
              file_equals(sentinel, "untouched") &&
              descriptor_size(oversized.container_fd) == sidecar_size,
              "oversized sidecar is refused without mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&oversized);
    }
}

static void test_raw_nul_and_root_gap(void)
{
    printf(BLUE "::" NC " decoded NUL and unrepresented manifest roots\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    Fixture fixture;
    int opened = fixture_open(&fixture, "nul", &root, 1);
    check(opened == 0, "NUL fixture is created");
    if (opened == 0)
    {
        SidecarLog log = {0};
        check(sidecar_log_create_at(fixture.container_fd, &log) ==
                  SIDECAR_OPEN_FRESH && sidecar_log_close(&log) ==
                  SIDECAR_STATUS_OK,
              "NUL sidecar header is created");
        static const unsigned char nul_record[] = {
            'E','N','T','R','Y',0,'R','O','O','T',0,'a',0,'b',0,
            'r','e','g','u','l','a','r',0,'6','4','4',0,'0',0,'0',0,
            '0',0,'0',0,'0',0,'0',0,'0',0,'0',0
        };
        check(append_raw_sidecar(&fixture, nul_record,
                                 sizeof(nul_record)) == 0,
              "decoded NUL bytes are planted in the record stream");
        write_file_at(fixture.home_fd, "sentinel", "untouched");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
        off_t sidecar_size = descriptor_size(fixture.container_fd);
        PortableRestorePreflightReport report;
        check(run_preflight(&fixture, &report) != 0 &&
              file_equals(sentinel, "untouched") &&
              descriptor_size(fixture.container_fd) == sidecar_size,
              "decoded NUL attempt is refused without mutation");
        portable_restore_preflight_report_free(&report);
        fixture_close(&fixture);
    }

    ManifestRoot roots[2] = {
        root_for("ROOT", "ROOT", "restored"),
        root_for("EMPTY", "EMPTY", "empty")
    };
    Fixture gap;
    opened = fixture_open(&gap, "root-gap", roots, 2);
    check(opened == 0, "root-gap fixture is created");
    if (opened == 0)
    {
        make_root_payload(&gap);
        SidecarEntry entry = entry_for("ROOT", "", "",
                                       SIDECAR_KIND_DIRECTORY, 0);
        check(write_sidecar(&gap, &entry, 1) == 0,
              "root-gap sidecar is committed");
        write_file_at(gap.home_fd, "sentinel", "untouched");
        char sentinel[PATH_MAX];
        fixture_path(sentinel, sizeof(sentinel), gap.home, "/sentinel");
        PortableRestorePreflightReport report;
        check(run_preflight(&gap, &report) != 0 &&
              file_equals(sentinel, "untouched"),
              "manifest root with no live entries is refused");
        portable_restore_preflight_report_free(&report);
        fixture_close(&gap);
    }
}

static void test_file_ancestor_conflict_wedge(void)
{
    printf(BLUE "::" NC " lexical wedge ancestor conflict\n");
    ManifestRoot root = root_for("ROOT", "ROOT", "restored");
    SidecarEntry entries[] = {
        entry_for("ROOT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("ROOT", "dir", "dir", SIDECAR_KIND_REGULAR, 7),
        entry_for("ROOT", "parent", "parent", SIDECAR_KIND_REGULAR, 7),
        entry_for("ROOT", "dir-x", "dir-x", SIDECAR_KIND_REGULAR, 7),
        entry_for("ROOT", "parent/child", "parent/child",
                  SIDECAR_KIND_REGULAR, 1)
    };
    Fixture fixture;
    int opened = fixture_open(&fixture, "file-ancestor-wedge", &root, 1);
    check(opened == 0, "file-ancestor-wedge fixture is created");
    if (opened != 0)
        return;
    check(write_raw_entries_sidecar(&fixture, entries, 5) == 0,
          "file-ancestor-wedge sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result != 0 && report.violation_count == 1 &&
              file_equals(sentinel, "untouched"),
          "lexical wedge does not hide a non-directory logical parent");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_overlapping_manifest_roots(void)
{
    printf(BLUE "::" NC " overlapping manifest root payloads\n");
    ManifestRoot roots[2] = {
        root_for("PARENT", "shared", "restored-parent"),
        root_for("CHILD", "shared/nested", "restored-child")
    };
    Fixture fixture;
    int opened = fixture_open(&fixture, "root-overlap", roots, 2);
    check(opened == 0, "root-overlap fixture is created");
    if (opened != 0)
        return;

    if (mkdirat(fixture.data_fd, "shared", 0700) != 0)
        fatal("could not create overlapping root payload");
    int shared_fd = openat(fixture.data_fd, "shared",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (shared_fd < 0 || mkdirat(shared_fd, "nested", 0700) != 0)
    {
        if (shared_fd >= 0)
            close(shared_fd);
        fatal("could not create nested overlapping root payload");
    }
    if (close(shared_fd) != 0)
        fatal("could not close overlapping root payload");

    SidecarEntry entries[] = {
        entry_for("PARENT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("CHILD", "", "", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, entries, 2) == 0,
          "root-overlap sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result != 0 && report.violation_count == 1 &&
              report.roots != NULL && report.roots[1].violation_count == 1 &&
              file_equals(sentinel, "untouched"),
          "overlapping manifest roots are refused before payload validation");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_overlapping_manifest_roots_wedge(void)
{
    printf(BLUE "::" NC " overlapping roots with lexical wedge\n");
    ManifestRoot roots[3] = {
        root_for("PARENT", "shared", "restored-parent"),
        root_for("SIBLING", "shared!", "restored-sibling"),
        root_for("CHILD", "shared/nested", "restored-child")
    };
    Fixture fixture;
    int opened = fixture_open(&fixture, "root-overlap-wedge", roots, 3);
    check(opened == 0, "root-overlap-wedge fixture is created");
    if (opened != 0)
        return;
    if (mkdirat(fixture.data_fd, "shared", 0700) != 0)
        fatal("could not create overlapping root payload");
    int shared_fd = openat(fixture.data_fd, "shared",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (shared_fd < 0 || mkdirat(shared_fd, "nested", 0700) != 0)
        fatal("could not create nested overlapping root payload");
    if (close(shared_fd) != 0)
        fatal("could not close overlapping root payload");
    if (mkdirat(fixture.data_fd, "shared!", 0700) != 0)
        fatal("could not create wedge sibling root payload");
    SidecarEntry entries[] = {
        entry_for("PARENT", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("SIBLING", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("CHILD", "", "", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, entries, 3) == 0,
          "root-overlap-wedge sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result != 0 && report.violation_count == 1 &&
              report.roots != NULL && report.roots[2].violation_count == 1 &&
              file_equals(sentinel, "untouched"),
          "lexical wedge does not hide overlapping manifest roots");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_root_lookup_wedge(void)
{
    printf(BLUE "::" NC " root lookup with lexical wedge\n");
    ManifestRoot roots[2] = {
        root_for("NESTED", "config/nested", "restored-nested"),
        root_for("SIBLING", "config/nested!", "restored-sibling")
    };
    Fixture fixture;
    int opened = fixture_open(&fixture, "root-lookup-wedge", roots, 2);
    check(opened == 0, "root-lookup-wedge fixture is created");
    if (opened != 0)
        return;
    if (mkdirat(fixture.data_fd, "config", 0700) != 0)
        fatal("could not create wedge fixture parent directory");
    int config_fd = openat(fixture.data_fd, "config",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (config_fd < 0 || mkdirat(config_fd, "nested", 0700) != 0 ||
        mkdirat(config_fd, "nested!", 0700) != 0)
        fatal("could not create wedge fixture root payloads");
    write_file_at(config_fd, "nested/x", "payload");
    if (close(config_fd) != 0)
        fatal("could not close wedge fixture parent directory");
    SidecarEntry entries[] = {
        entry_for("NESTED", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("NESTED", "x", "x", SIDECAR_KIND_REGULAR, 7),
        entry_for("SIBLING", "", "", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, entries, 3) == 0,
          "root-lookup-wedge sidecar is committed");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result == 0 && report.violation_count == 0,
          "root lookup succeeds");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_v2_selection_ownership_and_destination_collisions(void)
{
    printf(BLUE "::" NC " VERSION=2 ownership and combined destination mapping\n");

    ManifestRoot bootstrap = root_for("ROOT", "ROOT", "restored");
    ManifestRoot roots[2];
    Fixture fixture;
    int opened = fixture_open(&fixture, "v2-ownership", &bootstrap, 1);
    check(opened == 0, "VERSION=2 ownership fixture is created");
    if (opened != 0)
        return;
    check(write_v2_nested_manifest(&fixture, roots) == 0,
          "VERSION=2 ownership manifest is written");
    if (mkdirat(fixture.data_fd, "HOME", 0700) != 0 ||
        mkdirat(fixture.data_fd, "CHILD", 0700) != 0)
        fatal("could not create VERSION=2 payload roots");
    int home_payload_fd = openat(fixture.data_fd, "HOME",
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_payload_fd < 0 || mkdirat(home_payload_fd, "Child", 0700) != 0)
        fatal("could not create delegated wrong-root payload");
    if (close(home_payload_fd) != 0)
        fatal("could not close VERSION=2 HOME payload");
    SidecarEntry ownership_entries[] = {
        entry_for("HOME", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("HOME", "Child", "Child", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("CHILD", "", "", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, ownership_entries, 3) == 0,
          "VERSION=2 ownership sidecar is committed");
    PortableRestorePreflightReport report;
    int result = run_preflight(&fixture, &report);
    check(result != 0 && report.violation_count > 0,
          "a delegated source entry in the parent root is refused");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);

    opened = fixture_open(&fixture, "v2-destination", &bootstrap, 1);
    check(opened == 0, "VERSION=2 destination-collision fixture is created");
    if (opened != 0)
        return;
    check(write_v2_nested_manifest(&fixture, roots) == 0,
          "VERSION=2 destination-collision manifest is written");
    if (mkdirat(fixture.data_fd, "HOME", 0700) != 0 ||
        mkdirat(fixture.data_fd, "CHILD", 0700) != 0)
        fatal("could not create VERSION=2 collision roots");
    home_payload_fd = openat(fixture.data_fd, "HOME",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_payload_fd < 0 || mkdirat(home_payload_fd, "Documents", 0700) != 0)
        fatal("could not create VERSION=2 collision payload");
    if (close(home_payload_fd) != 0)
        fatal("could not close VERSION=2 collision payload");
    SidecarEntry collision_entries[] = {
        entry_for("HOME", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("HOME", "Documents", "Documents", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("CHILD", "", "", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, collision_entries, 3) == 0,
          "VERSION=2 destination-collision sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    result = run_preflight(&fixture, &report);
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    check(result != 0 && report.violation_count > 0 &&
              file_equals(sentinel, "untouched"),
          "two selected entries mapping to one destination are refused without mutation");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

static void test_resolved_destination_identity_collisions(void)
{
    printf(BLUE "::" NC " resolved destination identity collisions\n");

    ManifestRoot bootstrap = root_for("ROOT", "ROOT", "restored");
    ManifestRoot roots[2];
    Fixture fixture;
    PortableRestorePreflightReport report;
    const char *xdg_dirs[XDG_KEY_COUNT] = {0};

    int opened = fixture_open(&fixture, "identity-alias-files", &bootstrap, 1);
    check(opened == 0, "identity alias-file fixture is created");
    if (opened != 0)
        return;
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    strcpy(roots[0].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[0].source_path, "/source/Documents");
    strcpy(roots[1].id, "XDG_DOWNLOAD_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOWNLOAD_DIR");
    strcpy(roots[1].source_path, "/source/Downloads");
    check(write_v1_identity_manifest(&fixture, roots, 2) == 0,
          "VERSION=1 portable alias-file manifest is written");
    if (mkdirat(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700) != 0 ||
        mkdirat(fixture.data_fd, "XDG_DOWNLOAD_DIR", 0700) != 0)
        fatal("could not create alias-file payload roots");
    int docs_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int downloads_fd = openat(fixture.data_fd, "XDG_DOWNLOAD_DIR",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (docs_fd < 0 || downloads_fd < 0)
        fatal("could not open alias-file payload roots");
    write_file_at(docs_fd, "file", "DOCS");
    write_file_at(downloads_fd, "file", "DOWNLOADS");
    if (close(docs_fd) != 0 || close(downloads_fd) != 0)
        fatal("could not close alias-file payload roots");
    SidecarEntry alias_entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOCUMENTS_DIR", "file", "file", SIDECAR_KIND_REGULAR, 4),
        entry_for("XDG_DOWNLOAD_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOWNLOAD_DIR", "file", "file", SIDECAR_KIND_REGULAR, 9)
    };
    check(write_sidecar(&fixture, alias_entries, 4) == 0,
          "VERSION=1 portable alias-file sidecar is committed");
    if (mkdirat(fixture.home_fd, "Shared", 0700) != 0 ||
        symlinkat("Shared", fixture.home_fd, "Alias") != 0)
        fatal("could not create Shared/Alias destination");
    int shared_fd = openat(fixture.home_fd, "Shared",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (shared_fd < 0)
        fatal("could not open Shared destination");
    write_file_at(shared_fd, "file", "ORIGINAL");
    if (close(shared_fd) != 0)
        fatal("could not close Shared destination");
    char shared[PATH_MAX], alias[PATH_MAX], sentinel[PATH_MAX];
    fixture_path(shared, sizeof(shared), fixture.home, "/Shared");
    fixture_path(alias, sizeof(alias), fixture.home, "/Alias");
    fixture_path(sentinel, sizeof(sentinel), shared, "/file");
    xdg_dirs[0] = shared;
    xdg_dirs[1] = alias;
    int result = run_preflight_with_xdg(&fixture, &report, xdg_dirs);
    check(result != 0 && report.violation_count > 0 &&
              file_equals(sentinel, "ORIGINAL"),
          "Shared/Alias duplicate files refuse while the existing sentinel remains intact");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);

    memset(xdg_dirs, 0, sizeof(xdg_dirs));
    opened = fixture_open(&fixture, "identity-alias-dirs", &bootstrap, 1);
    check(opened == 0, "identity empty-directory fixture is created");
    if (opened != 0)
        return;
    check(write_v1_identity_manifest(&fixture, roots, 2) == 0,
          "VERSION=1 portable empty-directory alias manifest is written");
    if (mkdirat(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700) != 0 ||
        mkdirat(fixture.data_fd, "XDG_DOWNLOAD_DIR", 0700) != 0 ||
        mkdirat(fixture.home_fd, "Shared", 0700) != 0 ||
        symlinkat("Shared", fixture.home_fd, "Alias") != 0)
        fatal("could not create empty-directory alias fixture");
    SidecarEntry directory_entries[] = {
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOWNLOAD_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, directory_entries, 2) == 0,
          "empty-directory alias sidecar is committed");
    shared_fd = openat(fixture.home_fd, "Shared",
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (shared_fd < 0)
        fatal("could not open empty-directory Shared target");
    write_file_at(shared_fd, "sentinel", "ORIGINAL");
    if (close(shared_fd) != 0)
        fatal("could not close empty-directory Shared target");
    fixture_path(shared, sizeof(shared), fixture.home, "/Shared");
    fixture_path(alias, sizeof(alias), fixture.home, "/Alias");
    fixture_path(sentinel, sizeof(sentinel), shared, "/sentinel");
    xdg_dirs[0] = shared;
    xdg_dirs[1] = alias;
    result = run_preflight_with_xdg(&fixture, &report, xdg_dirs);
    check(result != 0 && report.violation_count > 0 &&
              file_equals(sentinel, "ORIGINAL"),
          "distinct empty source directories cannot own one aliased destination directory");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);

    memset(xdg_dirs, 0, sizeof(xdg_dirs));
    opened = fixture_open(&fixture, "identity-missing-suffix", &bootstrap, 1);
    check(opened == 0, "identity missing-suffix fixture is created");
    if (opened != 0)
        return;
    roots[0] = root_for("HOME", "HOME", "a/new");
    memset(&roots[1], 0, sizeof(roots[1]));
    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "/source/Documents");
    check(write_v1_identity_manifest(&fixture, roots, 2) == 0,
          "converging missing-suffix manifest is written");
    if (mkdirat(fixture.data_fd, "HOME", 0700) != 0 ||
        mkdirat(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700) != 0 ||
        mkdirat(fixture.home_fd, "a", 0700) != 0)
        fatal("could not create missing-suffix roots");
    docs_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (docs_fd < 0 || mkdirat(docs_fd, "new", 0700) != 0)
        fatal("could not create missing-suffix child");
    if (close(docs_fd) != 0)
        fatal("could not close missing-suffix payload root");
    SidecarEntry suffix_entries[] = {
        entry_for("HOME", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOCUMENTS_DIR", "new", "new", SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, suffix_entries, 3) == 0,
          "converging missing-suffix sidecar is committed");
    char a_path[PATH_MAX], missing[PATH_MAX];
    fixture_path(a_path, sizeof(a_path), fixture.home, "/a");
    fixture_path(missing, sizeof(missing), a_path, "/new");
    write_file_at(fixture.home_fd, "sentinel", "ORIGINAL");
    char home_sentinel[PATH_MAX];
    fixture_path(home_sentinel, sizeof(home_sentinel), fixture.home,
                 "/sentinel");
    xdg_dirs[0] = a_path;
    result = run_preflight_with_xdg(&fixture, &report, xdg_dirs);
    check(result != 0 && report.violation_count > 0 &&
              access(missing, F_OK) != 0 &&
              file_equals(home_sentinel, "ORIGINAL"),
          "different existing ancestors converge on one planned node without creating it");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);

    memset(xdg_dirs, 0, sizeof(xdg_dirs));
    opened = fixture_open(&fixture, "identity-home-xdg", &bootstrap, 1);
    check(opened == 0, "identity HOME/XDG alias fixture is created");
    if (opened != 0)
        return;
    roots[0] = root_for("HOME", "HOME", "Shared/home-child");
    memset(&roots[1], 0, sizeof(roots[1]));
    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "/source/Documents");
    check(write_v1_identity_manifest(&fixture, roots, 2) == 0,
          "HOME/XDG alias convergence manifest is written");
    if (mkdirat(fixture.data_fd, "HOME", 0700) != 0 ||
        mkdirat(fixture.data_fd, "XDG_DOCUMENTS_DIR", 0700) != 0 ||
        mkdirat(fixture.home_fd, "Shared", 0700) != 0 ||
        symlinkat("Shared", fixture.home_fd, "Alias") != 0)
        fatal("could not create HOME/XDG alias roots");
    docs_fd = openat(fixture.data_fd, "XDG_DOCUMENTS_DIR",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (docs_fd < 0 || mkdirat(docs_fd, "home-child", 0700) != 0)
        fatal("could not create HOME/XDG alias child");
    if (close(docs_fd) != 0)
        fatal("could not close HOME/XDG alias payload root");
    SidecarEntry home_xdg_entries[] = {
        entry_for("HOME", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOCUMENTS_DIR", "", "", SIDECAR_KIND_DIRECTORY, 0),
        entry_for("XDG_DOCUMENTS_DIR", "home-child", "home-child",
                  SIDECAR_KIND_DIRECTORY, 0)
    };
    check(write_sidecar(&fixture, home_xdg_entries, 3) == 0,
          "HOME/XDG alias convergence sidecar is committed");
    fixture_path(shared, sizeof(shared), fixture.home, "/Shared");
    fixture_path(alias, sizeof(alias), fixture.home, "/Alias");
    fixture_path(missing, sizeof(missing), shared, "/home-child");
    write_file_at(fixture.home_fd, "sentinel", "ORIGINAL");
    fixture_path(home_sentinel, sizeof(home_sentinel), fixture.home,
                 "/sentinel");
    xdg_dirs[0] = alias;
    result = run_preflight_with_xdg(&fixture, &report, xdg_dirs);
    check(result != 0 && report.violation_count > 0 &&
              access(missing, F_OK) != 0 &&
              file_equals(home_sentinel, "ORIGINAL"),
          "HOME-relative and XDG entries converging through an alias refuse before mutation");
    portable_restore_preflight_report_free(&report);
    fixture_close(&fixture);
}

int main(void)
{
    test_valid_and_profiles();
    test_destination_profile_ancestor_cache();
    test_payload_inventory_progress();
    test_outstanding_claim_gate();
    test_missing_payload();
    test_shortened_leaf_preflight();
    test_deep_physical_path_preflight();
    test_destination_profile_refusal_is_named();
    test_destination_profile_refusal_keeps_scanning();
    test_xattr_entry_acceptance();
    test_path_and_mapping_refusals();
    test_collision_suffix_validation();
    test_symlink_refusals();
    test_malformed_sidecars();
    test_raw_nul_and_root_gap();
    test_file_ancestor_conflict_wedge();
    test_overlapping_manifest_roots();
    test_overlapping_manifest_roots_wedge();
    test_root_lookup_wedge();
    test_v2_selection_ownership_and_destination_collisions();
    test_resolved_destination_identity_collisions();
    if (failures != 0)
    {
        printf(RED "%d portable restore preflight test(s) failed" NC "\n",
               failures);
        return 1;
    }
    printf(GREEN "portable restore preflight tests passed" NC "\n");
    return 0;
}
