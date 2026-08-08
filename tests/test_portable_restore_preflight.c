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
    entry.physical_path = text_bytes(physical);
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

static int append_entries(SidecarLog *log, const SidecarEntry *entries,
                          size_t count)
{
    for (size_t index = 0; index < count; index++)
    {
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

static int run_preflight(Fixture *fixture, PortableRestorePreflightReport *report)
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
    portable_restore_preflight_report_init(report);
    int result = portable_restore_preflight_at(&request, report);
    manifest_free(&manifest);
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
    SidecarEntry entry = entry_for("ROOT", "missing", "missing",
                                   SIDECAR_KIND_REGULAR, 3);
    check(write_sidecar(&fixture, &entry, 1) == 0,
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

static void run_refusal_case(const char *label, ManifestRoot *root,
                             SidecarEntry *entries, size_t entry_count,
                             void (*prepare)(Fixture *fixture))
{
    Fixture fixture;
    int opened = fixture_open(&fixture, label, root, 1);
    check(opened == 0, "refusal fixture is created");
    if (opened != 0)
        return;
    if (prepare != NULL)
        prepare(&fixture);
    int sidecar_result = write_sidecar(&fixture, entries, entry_count);
    check(sidecar_result == 0, "refusal sidecar is committed");
    write_file_at(fixture.home_fd, "sentinel", "untouched");
    char sentinel[PATH_MAX];
    fixture_path(sentinel, sizeof(sentinel), fixture.home, "/sentinel");
    PortableRestorePreflightReport report;
    check(run_preflight(&fixture, &report) != 0,
          label);
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
    SidecarEntry absolute = entry_for("ROOT", "/absolute", "x",
                                      SIDECAR_KIND_REGULAR, 0);
    run_refusal_case("absolute", &root, &absolute, 1, prepare_root_dir);
    SidecarEntry parent = entry_for("ROOT", "a/../b", "x",
                                    SIDECAR_KIND_REGULAR, 0);
    run_refusal_case("dotdot", &root, &parent, 1, prepare_root_dir);
    SidecarEntry empty = entry_for("ROOT", "a//b", "x",
                                   SIDECAR_KIND_REGULAR, 0);
    run_refusal_case("empty-component", &root, &empty, 1, prepare_root_dir);

    /* Both aliases are now rejected by the physical/logical invariant before
     * duplicate-path analysis; retain the two-entry shape as an early refusal. */
    SidecarEntry duplicate[] = {
        entry_for("ROOT", "a", "shared", SIDECAR_KIND_REGULAR, 3),
        entry_for("ROOT", "b", "shared", SIDECAR_KIND_REGULAR, 3)
    };
    run_refusal_case("physical-mismatch-before-duplicate", &root, duplicate, 2,
                     prepare_root_dir);

    SidecarEntry ancestor[] = {
        entry_for("ROOT", "dir", "dir", SIDECAR_KIND_REGULAR, 7),
        entry_for("ROOT", "dir/child", "dir/child", SIDECAR_KIND_REGULAR, 1)
    };
    run_refusal_case("file-ancestor", &root, ancestor, 2,
                     prepare_root_file);

    SidecarEntry external = entry_for("OTHER", "file", "file",
                                      SIDECAR_KIND_REGULAR, 0);
    run_refusal_case("external-root", &root, &external, 1,
                     prepare_root_dir);

    SidecarEntry fifo = entry_for("ROOT", "fifo", "fifo", SIDECAR_KIND_FIFO, 0);
    run_refusal_case("unsupported-kind", &root, &fifo, 1,
                     prepare_root_dir);

    SidecarEntry mismatch = entry_for("ROOT", "innocuous.txt",
                                      "something-else.txt",
                                      SIDECAR_KIND_REGULAR, 7);
    run_refusal_case("physical-mismatch", &root, &mismatch, 1,
                     prepare_root_dir);
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
    SidecarEntry entry = entry_for("ROOT", "file", physical,
                                   SIDECAR_KIND_REGULAR, 0);
    entry.collision_suffix = text_bytes(suffix);
    check(write_sidecar(&fixture, &entry, 1) == 0,
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
        check(write_sidecar(&missing, &child, 1) == 0,
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
            entry_for("ROOT", "dir", "dir%7E1",
                      SIDECAR_KIND_DIRECTORY, 0),
            entry_for("ROOT", "dir/file", "other/file",
                      SIDECAR_KIND_REGULAR, 0)
        };
        entries[0].collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&mismatch, entries, 2) == 0,
              "parent-mismatch sidecar is committed");
        PortableRestorePreflightReport report;
        check(run_preflight(&mismatch, &report) != 0,
              "parent physical-prefix mismatch is refused");
        portable_restore_preflight_report_free(&report);
        fixture_close(&mismatch);
    }

    Fixture root_suffix;
    opened = fixture_open(&root_suffix, "root-suffix", &root, 1);
    check(opened == 0, "root-suffix fixture is created");
    if (opened == 0)
    {
        make_root_payload(&root_suffix);
        SidecarEntry entry = entry_for("ROOT", "", "",
                                       SIDECAR_KIND_DIRECTORY, 0);
        entry.collision_suffix = text_bytes("%7E1");
        check(write_sidecar(&root_suffix, &entry, 1) == 0,
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
        check(write_sidecar(&final_fixture, &root_entry, 1) == 0,
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

int main(void)
{
    test_valid_and_profiles();
    test_missing_payload();
    test_xattr_entry_acceptance();
    test_path_and_mapping_refusals();
    test_collision_suffix_validation();
    test_symlink_refusals();
    test_malformed_sidecars();
    test_raw_nul_and_root_gap();
    if (failures != 0)
    {
        printf(RED "%d portable restore preflight test(s) failed" NC "\n",
               failures);
        return 1;
    }
    printf(GREEN "portable restore preflight tests passed" NC "\n");
    return 0;
}
