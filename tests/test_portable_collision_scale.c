// Host-only scale tests for portable case-collision planning and resume
// relocation (docs/DECISIONS.md D21).  The first fixture measures the
// destination filesystem probe budget for a large sibling collision set; the
// second reports how much owned-path work one newly introduced sibling causes
// during resume.  Both measurements use the D14 test-only counters rather
// than wall-clock timing.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manifest.h"
#include "portable.h"
#include "sidecar.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define COLLISION_PAIR_COUNT 2000U
#define COLLISION_ENTRY_COUNT (COLLISION_PAIR_COUNT * 2U)
#define RELOCATION_UNRELATED_COUNT 5000U
#define RELOCATION_NESTED_DESCENDANT_COUNT 2000U
#define RELOCATION_NESTED_UNRELATED_COUNT 1000U
#define STALE_CLAIM_DESCENDANT_COUNT 4000U
#define TOMBSTONE_LOOKUP_COUNT 3000U

extern int entry_from_stat(const char *root_id, const char *logical,
                           const char *physical,
                           const char *collision_suffix,
                           const struct stat *st, int nsec_exact,
                           PortableXattrs *xattrs, SidecarEntry *out,
                           const SidecarBytes *symlink_target,
                           const SidecarBytes *hardlink_root_id,
                           const SidecarBytes *hardlink_logical_path);
extern uint64_t portable_capture_test_probe_count(void);
extern void portable_capture_test_reset_probe_count(void);

static int failures;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "portable collision scale fixture failure: %s\n",
            message);
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

static void make_path(char *destination, size_t destination_size,
                      const char *base, const char *leaf)
{
    int length = snprintf(destination, destination_size, "%s/%s", base,
                          leaf);
    if (length < 0 || (size_t)length >= destination_size)
        fixture_fatal("fixture path is too long");
}

static int write_file_at(int parent_fd, const char *name,
                         const char *contents, size_t length)
{
    if (parent_fd < 0 || name == NULL || contents == NULL)
        return -1;
    int fd = openat(parent_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    size_t written = 0;
    while (written < length) {
        ssize_t result = write(fd, contents + written, length - written);
        if (result <= 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        written += (size_t)result;
    }
    return close(fd);
}

static int file_equals_at(int parent_fd, const char *name,
                          const char *expected, size_t expected_length)
{
    if (parent_fd < 0 || name == NULL || expected == NULL)
        return 0;
    int fd = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 0;
    char buffer[64];
    size_t offset = 0;
    while (offset < sizeof(buffer) && offset < expected_length) {
        ssize_t result = read(fd, buffer + offset,
                              sizeof(buffer) - offset);
        if (result <= 0) {
            close(fd);
            return 0;
        }
        offset += (size_t)result;
    }
    char extra;
    int has_extra = read(fd, &extra, 1) > 0;
    int result = close(fd) == 0 && !has_extra && offset == expected_length &&
                 memcmp(buffer, expected, expected_length) == 0;
    return result;
}

static PortableRootSpec root_spec(const char *source)
{
    return (PortableRootSpec){
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "ROOT",
        .source_path = source,
        .restore_path = "fixture",
        .has_restore_path = 1
    };
}

static PortableCaptureRequest capture_request(const PortableRootSpec *root)
{
    return (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "c0111de5",
        .source_uid = getuid(),
        .roots = root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
}

static void collision_names(unsigned int index, char *upper,
                            size_t upper_size, char *lower,
                            size_t lower_size)
{
    int upper_length = snprintf(upper, upper_size, "A%04u", index);
    int lower_length = snprintf(lower, lower_size, "a%04u", index);
    if (upper_length < 0 || lower_length < 0 ||
        (size_t)upper_length >= upper_size ||
        (size_t)lower_length >= lower_size)
        fixture_fatal("could not build collision fixture name");
}

static void test_collision_plan_scale(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture, "collision-source");
    make_path(container_path, sizeof(container_path), fixture,
              "collision-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create collision fixtures");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open collision fixtures");

    for (unsigned int index = 0; index < COLLISION_PAIR_COUNT; index++) {
        char upper[32];
        char lower[32];
        collision_names(index, upper, sizeof(upper), lower, sizeof(lower));
        if (write_file_at(source_fd, upper, "u", 1) != 0 ||
            write_file_at(source_fd, lower, "l", 1) != 0)
            fixture_fatal("could not create collision pair");
    }

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    portable_capture_test_reset_case_fs_probe_count();
    int result = portable_capture_fresh_at(container_fd, &request, &report);
    uint64_t probes = portable_capture_test_case_fs_probe_count();
    uint64_t entries = COLLISION_ENTRY_COUNT;

    printf("  collision_entries=%" PRIu64 " fs_probes=%" PRIu64 "\n",
           entries, probes);
    check(result == 0 && report.collision_plan.count == entries,
          "large ASCII collision set receives a complete assignment plan");
    check(probes >= entries,
          "collision-plan probe counter observes every candidate");
    check(probes <= entries * UINT64_C(32),
          "collision-plan filesystem probes remain bounded linearly");
    check(probes < (entries * entries) / UINT64_C(1000),
          "collision-plan filesystem probes remain far below quadratic work");

    portable_prescan_report_free(&report);
    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void rewrite_owned_predecessor(int container_fd, int source_fd)
{
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0 || payload_fd < 0 ||
        renameat(payload_fd, "foo", payload_fd, "Foo") != 0) {
        if (payload_fd >= 0)
            close(payload_fd);
        if (data_fd >= 0)
            close(data_fd);
        fixture_fatal("could not prepare the occupied collision slot");
    }
    if (close(payload_fd) != 0 || close(data_fd) != 0)
        fixture_fatal("could not close the collision payload namespace");

    struct stat source_stat;
    if (fstatat(source_fd, "foo", &source_stat, AT_SYMLINK_NOFOLLOW) != 0)
        fixture_fatal("could not stat the collision predecessor");
    PortableXattrs empty_xattrs = {0};
    SidecarEntry predecessor = {0};
    if (entry_from_stat("ROOT", "foo", "Foo", "", &source_stat, 1,
                        &empty_xattrs, &predecessor, NULL, NULL, NULL) != 0)
        fixture_fatal("could not prepare the collision predecessor record");

    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        fixture_fatal("could not adopt the fresh sidecar");
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"foo", 3 }
    };
    SidecarClaim claim = {
        .root_id = predecessor.root_id,
        .logical_path = predecessor.logical_path,
        .physical_path = predecessor.physical_path,
        .kind = predecessor.kind
    };
    if (sidecar_log_append_delete(&log, &deletion) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &predecessor) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not rewrite the collision predecessor record");
}

static void rewrite_claimed_predecessor(int container_fd)
{
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0 || payload_fd < 0 ||
        renameat(payload_fd, "foo", payload_fd, "Foo") != 0) {
        if (payload_fd >= 0)
            close(payload_fd);
        if (data_fd >= 0)
            close(data_fd);
        fixture_fatal("could not prepare the claimed collision slot");
    }
    if (close(payload_fd) != 0 || close(data_fd) != 0)
        fixture_fatal("could not close the claimed collision namespace");

    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        fixture_fatal("could not adopt the sidecar for the claimed predecessor");
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"foo", 3 }
    };
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"foo", 3 },
        .physical_path = { (const unsigned char *)"Foo", 3 },
        .kind = SIDECAR_KIND_REGULAR
    };
    if (sidecar_log_append_delete(&log, &deletion) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not record the claimed collision predecessor");
}

static void rewrite_live_predecessor(int container_fd, int source_fd,
                                     const char *logical,
                                     const char *physical)
{
    struct stat source_stat;
    if (fstatat(source_fd, logical, &source_stat, AT_SYMLINK_NOFOLLOW) != 0)
        fixture_fatal("could not stat the live collision predecessor");
    PortableXattrs empty_xattrs = {0};
    SidecarEntry predecessor = {0};
    if (entry_from_stat("ROOT", logical, physical, "", &source_stat, 1,
                        &empty_xattrs, &predecessor, NULL, NULL, NULL) != 0)
        fixture_fatal("could not prepare the live collision predecessor");

    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        fixture_fatal("could not adopt the sidecar for the live predecessor");
    SidecarDelete deletion = {
        .root_id = predecessor.root_id,
        .logical_path = predecessor.logical_path
    };
    SidecarClaim claim = {
        .root_id = predecessor.root_id,
        .logical_path = predecessor.logical_path,
        .physical_path = predecessor.physical_path,
        .kind = predecessor.kind
    };
    SidecarStatus delete_status = sidecar_log_append_delete(&log, &deletion);
    SidecarStatus claim_status = delete_status == SIDECAR_STATUS_OK
        ? sidecar_log_append_claim(&log, &claim)
        : SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarStatus entry_status = claim_status == SIDECAR_STATUS_OK
        ? sidecar_log_append_entry(&log, &predecessor)
        : SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarStatus commit_status = entry_status == SIDECAR_STATUS_OK
        ? sidecar_log_append_entry_commit(&log)
        : SIDECAR_STATUS_INVALID_ARGUMENT;
    SidecarStatus close_status = sidecar_log_close(&log);
    if (delete_status != SIDECAR_STATUS_OK ||
        claim_status != SIDECAR_STATUS_OK ||
        entry_status != SIDECAR_STATUS_OK ||
        commit_status != SIDECAR_STATUS_OK || close_status != SIDECAR_STATUS_OK)
        fixture_fatal("could not record the live collision predecessor");
}

static void test_relocation_scale(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture,
              "relocation-source");
    make_path(container_path, sizeof(container_path), fixture,
              "relocation-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create relocation fixtures");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open relocation fixtures");
    for (unsigned int index = 0; index < RELOCATION_UNRELATED_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            write_file_at(source_fd, name, "x", 1) != 0)
            fixture_fatal("could not create unrelated relocation entry");
    }
    if (write_file_at(source_fd, "foo", "original", 8) != 0)
        fixture_fatal("could not create the collision predecessor");

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    if (portable_capture_fresh_at(container_fd, &request, &report) != 0)
        fixture_fatal("could not create the relocation baseline");
    portable_prescan_report_free(&report);

    rewrite_owned_predecessor(container_fd, source_fd);
    if (write_file_at(source_fd, "Foo", "new", 3) != 0)
        fixture_fatal("could not add the lexical winner");

    portable_prescan_report_init(&report);
    portable_capture_test_reset_relocation_scan_count();
    int result = portable_capture_resume_at(container_fd, &request, &report);
    uint64_t scans = portable_capture_test_relocation_scan_count();
    uint64_t removals = portable_capture_test_relocation_remove_count();
    uint64_t owned_entries = RELOCATION_UNRELATED_COUNT + 2U;
    printf("  owned_entries=%" PRIu64 " relocation_scans=%" PRIu64
           " removals=%" PRIu64 "\n",
           owned_entries, scans, removals);
    check(result == 0,
          "resume succeeds after one new sibling changes the collision plan");
    check(removals == 1,
          "one new sibling causes exactly one owned-payload removal");
    check(scans >= owned_entries,
          "resume reports the owned-path scan cost");

    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int payloads_ok = payload_fd >= 0 &&
        fstatat(payload_fd, "Foo", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        fstatat(payload_fd, "foo%7E1", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        fstatat(payload_fd, "foo", &st, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT && file_equals_at(payload_fd, "Foo", "new", 3) &&
        file_equals_at(payload_fd, "foo%7E1", "original", 8);
    check(payloads_ok, "resume leaves the relocated predecessor and winner");
    if (payload_fd >= 0)
        close(payload_fd);
    if (data_fd >= 0)
        close(data_fd);

    portable_prescan_report_free(&report);
    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_claim_relocation_scale(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture,
              "claim-relocation-source");
    make_path(container_path, sizeof(container_path), fixture,
              "claim-relocation-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create claimed relocation fixtures");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open claimed relocation fixtures");
    for (unsigned int index = 0; index < RELOCATION_UNRELATED_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            write_file_at(source_fd, name, "x", 1) != 0)
            fixture_fatal("could not create unrelated claimed relocation entry");
    }
    if (write_file_at(source_fd, "foo", "original", 8) != 0 ||
        write_file_at(source_fd, "bar", "original", 8) != 0)
        fixture_fatal("could not create the claimed collision predecessor");

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    request.case_sensitive = 1;
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    if (portable_capture_fresh_at(container_fd, &request, &report) != 0)
        fixture_fatal("could not create the claimed relocation baseline");
    portable_prescan_report_free(&report);

    rewrite_claimed_predecessor(container_fd);
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0 || payload_fd < 0 ||
        renameat(payload_fd, "bar", payload_fd, "Bar") != 0) {
        if (payload_fd >= 0)
            close(payload_fd);
        if (data_fd >= 0)
            close(data_fd);
        fixture_fatal("could not prepare the live collision slot");
    }
    if (close(payload_fd) != 0 || close(data_fd) != 0)
        fixture_fatal("could not close the live collision namespace");
    rewrite_live_predecessor(container_fd, source_fd, "bar", "Bar");
    if (write_file_at(source_fd, "Foo", "new", 3) != 0 ||
        write_file_at(source_fd, "Bar", "new", 3) != 0)
        fixture_fatal("could not add the claimed relocation winner");
    request.case_sensitive = 0;

    portable_prescan_report_init(&report);
    portable_capture_test_reset_relocation_scan_count();
    int result = portable_capture_resume_at(container_fd, &request, &report);
    uint64_t scans = portable_capture_test_relocation_scan_count();
    uint64_t removals = portable_capture_test_relocation_remove_count();
    uint64_t owned_entries = RELOCATION_UNRELATED_COUNT + 3U;
    printf("  claimed_owned_entries=%" PRIu64 " relocation_scans=%" PRIu64
           " removals=%" PRIu64 "\n", owned_entries, scans, removals);
    check(result == 0,
          "resume succeeds when the renumbered predecessor is only CLAIMED");
    check(removals == 2,
          "live and claimed collision predecessors are each removed once");
    check(scans >= owned_entries && scans <= (owned_entries + 1U) * UINT64_C(8),
          "live plus CLAIM relocation scans remain bounded linearly");

    data_fd = openat(container_fd, "data",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int payloads_ok = payload_fd >= 0 &&
        fstatat(payload_fd, "Foo", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        fstatat(payload_fd, "Bar", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        fstatat(payload_fd, "foo%7E1", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        fstatat(payload_fd, "bar%7E1", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        fstatat(payload_fd, "foo", &st, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT && file_equals_at(payload_fd, "Foo", "new", 3) &&
        file_equals_at(payload_fd, "Bar", "new", 3) &&
        file_equals_at(payload_fd, "foo%7E1", "original", 8) &&
        file_equals_at(payload_fd, "bar%7E1", "original", 8);
    check(payloads_ok,
          "live and claimed relocation leave the new and suffixed payloads");

    SidecarLog log = {0};
    int sidecar_ok = sidecar_log_adopt_at(container_fd, &log) ==
                         SIDECAR_OPEN_RESUMABLE &&
                     sidecar_log_claim_count(&log) == 0;
    if (log.implementation != NULL &&
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        sidecar_ok = 0;
    check(sidecar_ok, "claimed relocation consumes the old CLAIM");
    if (payload_fd >= 0)
        close(payload_fd);
    if (data_fd >= 0)
        close(data_fd);

    portable_prescan_report_free(&report);
    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_claim_directory_collision(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture,
              "mixed-claim-source");
    make_path(container_path, sizeof(container_path), fixture,
              "mixed-claim-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create mixed CLAIM fixtures");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open mixed CLAIM fixtures");
    if (mkdirat(source_fd, "dir", 0700) != 0)
        fixture_fatal("could not create the mixed CLAIM directory");
    int directory_fd = openat(source_fd, "dir",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || write_file_at(directory_fd, "child", "old", 3) != 0)
        fixture_fatal("could not create the mixed CLAIM live child");
    if (close(directory_fd) != 0)
        fixture_fatal("could not close the mixed CLAIM source directory");

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    request.case_sensitive = 1;
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    if (portable_capture_fresh_at(container_fd, &request, &report) != 0)
        fixture_fatal("could not create the mixed CLAIM baseline");
    portable_prescan_report_free(&report);

    SidecarLog log = {0};
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"dir", 3 }
    };
    SidecarClaim claim = {
        .root_id = deletion.root_id,
        .logical_path = deletion.logical_path,
        .physical_path = { (const unsigned char *)"dir", 3 },
        .kind = SIDECAR_KIND_DIRECTORY
    };
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE ||
        sidecar_log_append_delete(&log, &deletion) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not plant the mixed CLAIM state");
    if (mkdirat(source_fd, "Dir", 0700) != 0)
        fixture_fatal("could not add the mixed CLAIM collision sibling");

    request.case_sensitive = 0;
    int result = portable_capture_resume_at(container_fd, &request, NULL);
    check(result == 0,
          "directory CLAIM relocation handles a committed live descendant");

    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int payloads_ok = payload_fd >= 0 &&
        fstatat(payload_fd, "Dir", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(st.st_mode) &&
        fstatat(payload_fd, "dir%7E1", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(st.st_mode);
    int relocated_child_fd = payload_fd < 0
        ? -1
        : openat(payload_fd, "dir%7E1",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    payloads_ok = payloads_ok && relocated_child_fd >= 0 &&
        file_equals_at(relocated_child_fd, "child", "old", 3);
    check(payloads_ok,
          "mixed CLAIM relocation preserves the live descendant under the suffix");

    int sidecar_ok = 0;
    if (sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE) {
        sidecar_ok = sidecar_log_claim_count(&log) == 0;
        if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
            sidecar_ok = 0;
    }
    check(sidecar_ok, "mixed CLAIM relocation consumes the parent CLAIM");
    if (relocated_child_fd >= 0)
        close(relocated_child_fd);
    if (payload_fd >= 0)
        close(payload_fd);
    if (data_fd >= 0)
        close(data_fd);
    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_nested_relocation_scale(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture,
              "nested-relocation-source");
    make_path(container_path, sizeof(container_path), fixture,
              "nested-relocation-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create nested relocation fixtures");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open nested relocation fixtures");
    if (mkdirat(source_fd, "foo", 0700) != 0)
        fixture_fatal("could not create the nested collision predecessor");
    int nested_source_fd = openat(source_fd, "foo",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (nested_source_fd < 0)
        fixture_fatal("could not open the nested collision predecessor");

    for (unsigned int index = 0;
         index < RELOCATION_NESTED_DESCENDANT_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            write_file_at(nested_source_fd, name, "nested", 6) != 0)
            fixture_fatal("could not create a nested relocation entry");
    }
    for (unsigned int index = 0;
         index < RELOCATION_NESTED_UNRELATED_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "unrelated-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            write_file_at(source_fd, name, "root", 4) != 0)
            fixture_fatal("could not create an unrelated relocation entry");
    }
    if (close(nested_source_fd) != 0)
        fixture_fatal("could not close the nested source directory");

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    request.case_sensitive = 1;
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    if (portable_capture_fresh_at(container_fd, &request, &report) != 0)
        fixture_fatal("could not create the nested relocation baseline");
    portable_prescan_report_free(&report);

    if (write_file_at(source_fd, "Foo", "new", 3) != 0)
        fixture_fatal("could not add the nested lexical winner");
    request.case_sensitive = 0;

    portable_prescan_report_init(&report);
    portable_capture_test_reset_relocation_scan_count();
    int result = portable_capture_resume_at(container_fd, &request, &report);
    uint64_t scans = portable_capture_test_relocation_scan_count();
    uint64_t removals = portable_capture_test_relocation_remove_count();
    uint64_t owned_entries =
        (uint64_t)RELOCATION_NESTED_DESCENDANT_COUNT +
        (uint64_t)RELOCATION_NESTED_UNRELATED_COUNT + 2U;
    printf("  owned_entries=%" PRIu64 " descendants=%u relocation_scans=%" PRIu64
           " removals=%" PRIu64 "\n",
           owned_entries, RELOCATION_NESTED_DESCENDANT_COUNT, scans,
           removals);
    check(result == 0,
          "nested resume succeeds after one new sibling changes the plan");
    check(removals == RELOCATION_NESTED_DESCENDANT_COUNT + 1U,
          "nested resume removes the directory and every owned descendant");

    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ROOT",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    char first_entry[32] = {0};
    char last_entry[32] = {0};
    int first_length = snprintf(first_entry, sizeof(first_entry),
                                "entry-%05u", 0U);
    int last_length = snprintf(
        last_entry, sizeof(last_entry), "entry-%05u",
        RELOCATION_NESTED_DESCENDANT_COUNT - 1U);
    char first_payload[PATH_MAX];
    char last_payload[PATH_MAX];
    int first_path_length = snprintf(first_payload, sizeof(first_payload),
                                     "foo%%7E1/%s", first_entry);
    int last_path_length = snprintf(last_payload, sizeof(last_payload),
                                    "foo%%7E1/%s", last_entry);
    int payloads_ok = first_length >= 0 && last_length >= 0 &&
        (size_t)first_length < sizeof(first_entry) &&
        (size_t)last_length < sizeof(last_entry) &&
        first_path_length >= 0 && last_path_length >= 0 &&
        (size_t)first_path_length < sizeof(first_payload) &&
        (size_t)last_path_length < sizeof(last_payload) &&
        payload_fd >= 0 &&
        fstatat(payload_fd, "Foo", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) &&
        file_equals_at(payload_fd, "Foo", "new", 3) &&
        fstatat(payload_fd, "foo", &st, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT &&
        fstatat(payload_fd, "foo%7E1", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(st.st_mode) &&
        file_equals_at(payload_fd, first_payload, "nested", 6) &&
        file_equals_at(payload_fd, last_payload, "nested", 6);
    check(payloads_ok,
          "nested resume leaves the suffixed subtree and removes the old one");
    if (payload_fd >= 0)
        close(payload_fd);
    if (data_fd >= 0)
        close(data_fd);

    portable_prescan_report_free(&report);
    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void convert_deep_directory_to_claim(int container_fd,
                                            unsigned int descendant_count)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        fixture_fatal("could not adopt the deep CLAIM fixture");
    SidecarDelete directory_delete = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"claimed", 7 }
    };
    SidecarClaim directory_claim = {
        .root_id = directory_delete.root_id,
        .logical_path = directory_delete.logical_path,
        .physical_path = { (const unsigned char *)"claimed", 7 },
        .kind = SIDECAR_KIND_DIRECTORY
    };
    if (sidecar_log_append_delete(&log, &directory_delete) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &directory_claim) != SIDECAR_STATUS_OK)
        fixture_fatal("could not claim the deep directory");

    for (unsigned int index = 0; index < descendant_count; index++) {
        char logical[64];
        int length = snprintf(logical, sizeof(logical),
                              "claimed/entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(logical))
            fixture_fatal("could not build a deep CLAIM logical path");
        SidecarDelete deletion = {
            .root_id = { (const unsigned char *)"ROOT", 4 },
            .logical_path = { (const unsigned char *)logical,
                              (size_t)length }
        };
        SidecarClaim claim = {
            .root_id = deletion.root_id,
            .logical_path = deletion.logical_path,
            .physical_path = deletion.logical_path,
            .kind = SIDECAR_KIND_REGULAR
        };
        if (sidecar_log_append_delete(&log, &deletion) != SIDECAR_STATUS_OK ||
            sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK)
            fixture_fatal("could not claim a deep directory descendant");
    }
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close the deep CLAIM fixture");
}

static void test_deep_stale_claim_scale(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture,
              "deep-claim-source");
    make_path(container_path, sizeof(container_path), fixture,
              "deep-claim-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create deep CLAIM fixtures");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0)
        fixture_fatal("could not open the deep CLAIM source");
    if (write_file_at(source_fd, "keep", "keep", 4) != 0 ||
        mkdirat(source_fd, "claimed", 0700) != 0)
        fixture_fatal("could not create the deep CLAIM source tree");
    int claimed_fd = openat(source_fd, "claimed",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (claimed_fd < 0)
        fixture_fatal("could not open the deep CLAIM source directory");
    for (unsigned int index = 0;
         index < STALE_CLAIM_DESCENDANT_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            write_file_at(claimed_fd, name, "stale", 5) != 0)
            fixture_fatal("could not create a deep CLAIM descendant");
    }
    if (close(claimed_fd) != 0)
        fixture_fatal("could not close the deep CLAIM source directory");

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open the deep CLAIM container");
    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    request.case_sensitive = 1;
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    if (portable_capture_fresh_at(container_fd, &request, &report) != 0)
        fixture_fatal("could not create the deep CLAIM baseline");
    portable_prescan_report_free(&report);

    convert_deep_directory_to_claim(container_fd,
                                    STALE_CLAIM_DESCENDANT_COUNT);
    int stale_fd = openat(source_fd, "claimed",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (stale_fd < 0)
        fixture_fatal("could not reopen the deep CLAIM source directory");
    for (unsigned int index = 0;
         index < STALE_CLAIM_DESCENDANT_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            unlinkat(stale_fd, name, 0) != 0)
            fixture_fatal("could not remove a deep CLAIM source descendant");
    }
    if (close(stale_fd) != 0 ||
        unlinkat(source_fd, "claimed", AT_REMOVEDIR) != 0)
        fixture_fatal("could not remove the deep CLAIM source directory");

    portable_capture_test_reset_probe_count();
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume cleans a deep all-CLAIM directory");
    uint64_t probes = portable_capture_test_probe_count();
    uint64_t entries = STALE_CLAIM_DESCENDANT_COUNT + 3U;
    printf("  stale_claim_entries=%" PRIu64 " visited_probes=%" PRIu64 "\n",
           entries, probes);
    check(probes <= entries * UINT64_C(64),
          "deep CLAIM validation and mutation remain bounded linearly");
    check(probes < (entries * entries) / UINT64_C(1000),
          "deep CLAIM work remains far below quadratic traversal");

    char payload_claimed[PATH_MAX];
    make_path(payload_claimed, sizeof(payload_claimed), container_path,
              "data/ROOT/claimed");
    check(access(payload_claimed, F_OK) != 0 && errno == ENOENT,
          "deep stale CLAIM cleanup removes the entire payload subtree");
    SidecarLog log = {0};
    int sidecar_ok = sidecar_log_adopt_at(container_fd, &log) ==
                         SIDECAR_OPEN_RESUMABLE &&
                     sidecar_log_claim_count(&log) == 0;
    if (log.implementation != NULL &&
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        sidecar_ok = 0;
    check(sidecar_ok, "deep stale CLAIM cleanup leaves no outstanding claims");

    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_tombstone_lookup_scale(const char *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    make_path(source_path, sizeof(source_path), fixture,
              "tombstone-lookup-source");
    make_path(container_path, sizeof(container_path), fixture,
              "tombstone-lookup-container");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create tombstone lookup fixtures");
    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open tombstone lookup fixtures");
    for (unsigned int index = 0; index < TOMBSTONE_LOOKUP_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            write_file_at(source_fd, name, "x", 1) != 0)
            fixture_fatal("could not create a tombstone lookup entry");
    }

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = capture_request(&root);
    request.case_sensitive = 1;
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    if (portable_capture_fresh_at(container_fd, &request, &report) != 0)
        fixture_fatal("could not create the tombstone lookup baseline");
    portable_prescan_report_free(&report);
    for (unsigned int index = 0; index < TOMBSTONE_LOOKUP_COUNT; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            unlinkat(source_fd, name, 0) != 0)
            fixture_fatal("could not remove a tombstone lookup source entry");
    }

    portable_capture_test_reset_probe_count();
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "portable resume records a large tombstone set");
    uint64_t visited_probes = portable_capture_test_probe_count();
    uint64_t entries = TOMBSTONE_LOOKUP_COUNT + 1U;
    printf("  tombstone_entries=%" PRIu64 " visited_probes=%" PRIu64 "\n",
           entries, visited_probes);
    check(visited_probes <= entries * UINT64_C(64),
          "tombstone reconciliation remains bounded linearly");

    SidecarLog log = {0};
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE,
          "tombstone lookup scale reopens the adopted sidecar");
    int lookups_ok = log.implementation != NULL;
    size_t lookup_count = 0;
    for (unsigned int index = 0; index < TOMBSTONE_LOOKUP_COUNT; index++) {
        char logical[32];
        int length = snprintf(logical, sizeof(logical), "entry-%05u", index);
        SidecarBytes root_key = {
            (const unsigned char *)"ROOT", 4
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, (size_t)length
        };
        SidecarLiveView live = {0};
        SidecarClaimView claim = {0};
        lookups_ok = lookups_ok && length >= 0 &&
            sidecar_log_find(&log, root_key, logical_key, &live) == 0 &&
            sidecar_log_find_deleted(&log, root_key, logical_key, &live) == 1 &&
            sidecar_log_find_claim(&log, root_key, logical_key, &claim) == 0;
        lookup_count += 3U;
    }
    for (unsigned int index = 0; index < TOMBSTONE_LOOKUP_COUNT; index++) {
        char logical[32];
        int length = snprintf(logical, sizeof(logical), "absent-%05u", index);
        SidecarBytes root_key = {
            (const unsigned char *)"ROOT", 4
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, (size_t)length
        };
        SidecarLiveView live = {0};
        SidecarClaimView claim = {0};
        lookups_ok = lookups_ok && length >= 0 &&
            sidecar_log_find(&log, root_key, logical_key, &live) == 0 &&
            sidecar_log_find_deleted(&log, root_key, logical_key, &live) == 0 &&
            sidecar_log_find_claim(&log, root_key, logical_key, &claim) == 0;
        lookup_count += 3U;
    }
    if (log.implementation != NULL &&
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        lookups_ok = 0;
    check(lookups_ok && lookup_count == TOMBSTONE_LOOKUP_COUNT * 6U,
          "present and absent live/deleted/CLAIM lookups stay correct at scale");

    close(source_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

int main(void)
{
    printf(BLUE "::" NC " portable collision-resolution scale\n");
    char fixture[] = "/tmp/migr_portable_collision_scale_XXXXXX";
    if (mkdtemp(fixture) == NULL)
        fixture_fatal("could not create fixture root");

    test_collision_plan_scale(fixture);
    test_relocation_scale(fixture);
    test_claim_relocation_scale(fixture);
    test_claim_directory_collision(fixture);
    test_nested_relocation_scale(fixture);
    test_deep_stale_claim_scale(fixture);
    test_tombstone_lookup_scale(fixture);
    remove_tree(fixture);
    printf("portable collision scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
