// Resume, adopt, and interruption-safety coverage for the portable capture
// seam (docs/DECISIONS.md D17/D21): committed-entry skip on unchanged regular and
// symlink sources (inode + metadata/xattr equality; symlink source atime is
// excluded per D18 because target reads may update it + on-disk payload shape),
// forced recapture on a missing or changed payload, and pristine-namespace
// gating before a fresh sidecar is ever recovered onto a partial (manifest written,
// data/
// absent or empty, sidecar absent), refusal (not silent freshening) of a
// non-empty data/ without a sidecar and of a corrupt or symlinked sidecar
// slot, truncated-tail adoption, a manifest-identity mismatch refusing to
// adopt someone else's partial, and real SIGKILL fixtures (child processes,
// not synthetic stand-ins) at every interruption boundary listed for B.3b:
// the replacement tombstone, payload replace/write/close, and the sidecar's
// own mid-ENTRY/mid-XATTR/ENTRY_COMMIT boundaries via the SIDECAR_TEST_HOOKS
// seam shared with tests/test_sidecar_state.c and friends.
//
// The xattr-middle interruption case is skipped (not failed) when the
// fixture filesystem rejects user xattrs -- the same ENOTSUP/EOPNOTSUPP/EPERM
// fallback tests/test_portable_capture.c already uses for its own xattr
// fixture, not a new asymmetry introduced here.

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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "manifest.h"
#include "portable.h"
#include "sidecar.h"

extern int entries_equal(const SidecarEntry *current,
                         const SidecarLiveView *previous,
                         const PortableXattrs *xattrs);
extern int entry_from_stat(const char *root_id, const char *logical,
                           const char *physical,
                           const char *collision_suffix,
                           const struct stat *st, int nsec_exact,
                           PortableXattrs *xattrs, SidecarEntry *out,
                           const SidecarBytes *symlink_target,
                           const SidecarBytes *hardlink_root_id,
                           const SidecarBytes *hardlink_logical_path);

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
    fprintf(stderr, "portable resume fixture failure: %s\n", message);
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

static void write_file(const char *path, const char *text)
{
    size_t length = strlen(text);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fixture_fatal("could not create fixture file");
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, text + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            fixture_fatal("could not write fixture file");
        offset += (size_t)written;
    }
    if (close(fd) != 0)
        fixture_fatal("could not close fixture file");
}

static int file_equals(const char *path, const char *expected)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    size_t expected_length = strlen(expected);
    unsigned char buffer[256];
    size_t received = 0;
    while (received < sizeof(buffer)) {
        ssize_t count = read(fd, buffer + received, sizeof(buffer) - received);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            close(fd);
            return 0;
        }
        if (count == 0)
            break;
        received += (size_t)count;
    }
    int result = close(fd) == 0 && received == expected_length &&
                 memcmp(buffer, expected, expected_length) == 0;
    return result;
}

static int symlink_equals(const char *path, const char *expected)
{
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    ssize_t length = readlink(path, target, sizeof(target));
    if (length < 0 || (size_t)length >= sizeof(target))
        return 0;
    size_t expected_length = strlen(expected);
    return (size_t)length == expected_length &&
           memcmp(target, expected, expected_length) == 0;
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

static PortableCaptureRequest request_for(const PortableRootSpec *root,
                                          const char *machine_id)
{
    return (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = machine_id,
        .source_uid = getuid(),
        .roots = root,
        .root_count = 1,
        .nsec_exact = 1
    };
}

static int create_container(const char *path)
{
    if (mkdir(path, 0700) != 0)
        return -1;
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int missing_at(int directory_fd, const char *name)
{
    struct stat st;
    return fstatat(directory_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
           errno == ENOENT;
}

static int child_killed_by(int status)
{
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static SidecarBytes resume_bytes(const char *text)
{
    return (SidecarBytes){ (const unsigned char *)text, strlen(text) };
}

static int run_fresh_sidecar_interrupt(
    int container_fd, const PortableCaptureRequest *request,
    PortableTestInterruptPoint portable_point,
    SidecarTestInterruptPoint sidecar_point);
static int fresh_capture(const char *container_path,
                         const PortableCaptureRequest *request,
                         int *container_fd);

static void test_collision_suffix_resume_key(void)
{
    printf(BLUE "::" NC " collision suffix resume identity\n");
    SidecarEntry current = {0};
    SidecarEntry previous = {0};
    current.root_id = previous.root_id = resume_bytes("ROOT");
    current.logical_path = previous.logical_path = resume_bytes("file");
    current.physical_path = previous.physical_path = resume_bytes("file");
    SidecarLiveView view = {
        .entry = &previous,
        .xattrs = NULL,
        .xattr_count = 0,
        .generation = 0
    };
    PortableXattrs no_xattrs = {0};

    current.collision_suffix = resume_bytes("%7E1");
    check(entries_equal(&current, &view, &no_xattrs) == 0,
          "a changed collision suffix forces resume replacement");

    current.collision_suffix = (SidecarBytes){0};
    check(entries_equal(&current, &view, &no_xattrs) != 0,
          "identical empty collision suffixes preserve resume equality");
}

static int run_case_alias_claim_fixture(const char *base, const char *label,
                                        char *foo_physical,
                                        size_t foo_physical_size)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, label);
    char container_label[NAME_MAX + 1U];
    int length = snprintf(container_label, sizeof(container_label),
                          "%s-container", label);
    if (length < 0 || (size_t)length >= sizeof(container_label))
        return -1;
    join_path(container_path, sizeof(container_path), base, container_label);
    make_directory(source_path);
    char source_foo[PATH_MAX];
    join_path(source_foo, sizeof(source_foo), source_path, "foo");
    write_file(source_foo, "original");

    PortableRootSpec root = root_spec("ALIAS", source_path, "ALIAS");
    PortableCaptureRequest request = request_for(&root, "d8a1");
    request.case_sensitive = 1;
    int container_fd = -1;
    int initial_result = fresh_capture(container_path, &request, &container_fd);
    if (initial_result != 0)
        return -1;

    char source_Foo[PATH_MAX];
    join_path(source_Foo, sizeof(source_Foo), source_path, "Foo");
    write_file(source_Foo, "new");

    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int payload_fd = data_fd < 0
        ? -1
        : openat(data_fd, "ALIAS",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0 || payload_fd < 0 ||
        renameat(payload_fd, "foo", payload_fd, "Foo") != 0) {
        if (payload_fd >= 0)
            close(payload_fd);
        if (data_fd >= 0)
            close(data_fd);
        close(container_fd);
        return -1;
    }
    if (close(payload_fd) != 0 || close(data_fd) != 0) {
        close(container_fd);
        return -1;
    }

    SidecarLog log = {0};
    SidecarDelete deletion = {
        .root_id = resume_bytes("ALIAS"),
        .logical_path = resume_bytes("foo")
    };
    SidecarClaim claim = {
        .root_id = deletion.root_id,
        .logical_path = deletion.logical_path,
        .physical_path = resume_bytes("Foo"),
        .kind = SIDECAR_KIND_REGULAR
    };
    int planted = sidecar_log_adopt_at(container_fd, &log) ==
                      SIDECAR_OPEN_RESUMABLE &&
                  sidecar_log_append_delete(&log, &deletion) ==
                      SIDECAR_STATUS_OK &&
                  sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK;
    if (log.implementation != NULL &&
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        planted = 0;
    request.case_sensitive = 0;
    int result = planted &&
                 portable_capture_resume_at(container_fd, &request, NULL) == 0;
    if (result) {
        result = sidecar_log_adopt_at(container_fd, &log) ==
                     SIDECAR_OPEN_RESUMABLE;
        SidecarLiveView foo = {0};
        SidecarLiveView Foo = {0};
        if (result)
            result = sidecar_log_find(&log, resume_bytes("ALIAS"),
                                      resume_bytes("foo"), &foo) == 1 &&
                     sidecar_log_find(&log, resume_bytes("ALIAS"),
                                      resume_bytes("Foo"), &Foo) == 1 &&
                     sidecar_log_claim_count(&log) == 0 &&
                     foo.entry->kind == SIDECAR_KIND_REGULAR &&
                     Foo.entry->kind == SIDECAR_KIND_REGULAR;
        if (result && foo.entry->physical_path.length >= foo_physical_size)
            result = 0;
        if (result) {
            memcpy(foo_physical, foo.entry->physical_path.data,
                   foo.entry->physical_path.length);
            foo_physical[foo.entry->physical_path.length] = '\0';
        }
        if (log.implementation != NULL &&
            sidecar_log_close(&log) != SIDECAR_STATUS_OK)
            result = 0;
    }
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
    return result ? 0 : -1;
}

static void test_case_alias_claim_determinism(const char *base)
{
    printf(BLUE "::" NC " case-fold collision with an outstanding CLAIM\n");
    char first[SIDECAR_MAX_PATH + 1U] = {0};
    char second[SIDECAR_MAX_PATH + 1U] = {0};
    check(run_case_alias_claim_fixture(base, "alias-claim-one", first,
                                       sizeof(first)) == 0 &&
              run_case_alias_claim_fixture(base, "alias-claim-two", second,
                                           sizeof(second)) == 0,
          "case-fold renumbering resumes from the claimed predecessor");
    check(strcmp(first, second) == 0 && strcmp(first, "foo%7E1") == 0,
          "case-fold renumbering assigns the same suffix on repeated fixtures");
}

static int copy_resume_bytes(SidecarBytes value, char *destination,
                             size_t destination_size)
{
    if (destination == NULL || destination_size == 0 ||
        value.length >= destination_size ||
        (value.length != 0 && value.data == NULL))
        return -1;
    if (value.length != 0)
        memcpy(destination, value.data, value.length);
    destination[value.length] = '\0';
    return 0;
}

static int run_hardlink_representative_transition(
    const char *base, const char *label, char *member_name,
    size_t member_name_size, char *member_physical, size_t member_physical_size)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, label);
    char container_label[NAME_MAX + 1U];
    int length = snprintf(container_label, sizeof(container_label),
                          "%s-container", label);
    if (length < 0 || (size_t)length >= sizeof(container_label))
        return -1;
    join_path(container_path, sizeof(container_path), base, container_label);
    make_directory(source_path);
    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    join_path(first_path, sizeof(first_path), source_path, "first");
    join_path(second_path, sizeof(second_path), source_path, "second");
    write_file(first_path, "before");
    if (link(first_path, second_path) != 0)
        return -1;

    PortableRootSpec root = root_spec("HLTRANS", source_path, "HLTRANS");
    PortableCaptureRequest request = request_for(&root, "d8a2");
    request.case_sensitive = 1;
    int container_fd = -1;
    if (fresh_capture(container_path, &request, &container_fd) != 0)
        return -1;

    SidecarLog log = {0};
    int prepared = sidecar_log_adopt_at(container_fd, &log) ==
                       SIDECAR_OPEN_RESUMABLE;
    SidecarLiveView first = {0};
    SidecarLiveView second = {0};
    if (prepared)
        prepared = sidecar_log_find(&log, resume_bytes("HLTRANS"),
                                    resume_bytes("first"), &first) == 1 &&
                   sidecar_log_find(&log, resume_bytes("HLTRANS"),
                                    resume_bytes("second"), &second) == 1;
    const char *representative = NULL;
    const char *member = NULL;
    if (prepared && first.entry->kind == SIDECAR_KIND_REGULAR &&
        second.entry->kind == SIDECAR_KIND_HARDLINK) {
        representative = "first";
        member = "second";
    } else if (prepared && second.entry->kind == SIDECAR_KIND_REGULAR &&
               first.entry->kind == SIDECAR_KIND_HARDLINK) {
        representative = "second";
        member = "first";
    } else {
        prepared = 0;
    }
    if (prepared &&
        copy_resume_bytes(resume_bytes(member), member_name,
                          member_name_size) != 0)
        prepared = 0;
    if (prepared) {
        SidecarDelete deletion = {
            .root_id = resume_bytes("HLTRANS"),
            .logical_path = resume_bytes(representative)
        };
        SidecarClaim claim = {
            .root_id = deletion.root_id,
            .logical_path = deletion.logical_path,
            .physical_path = resume_bytes(representative),
            .kind = SIDECAR_KIND_REGULAR
        };
        prepared = sidecar_log_append_delete(&log, &deletion) ==
                       SIDECAR_STATUS_OK &&
                   sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK;
    }
    if (log.implementation != NULL &&
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        prepared = 0;
    if (!prepared) {
        close(container_fd);
        remove_tree(source_path);
        remove_tree(container_path);
        return -1;
    }

    char representative_path[PATH_MAX];
    join_path(representative_path, sizeof(representative_path), source_path,
              representative);
    if (unlink(representative_path) != 0) {
        close(container_fd);
        remove_tree(source_path);
        remove_tree(container_path);
        return -1;
    }
    char alias[NAME_MAX + 1U];
    length = snprintf(alias, sizeof(alias), "%c%s", member[0] -
                      ('a' - 'A'), member + 1);
    if (length < 0 || (size_t)length >= sizeof(alias)) {
        close(container_fd);
        remove_tree(source_path);
        remove_tree(container_path);
        return -1;
    }
    char alias_path[PATH_MAX];
    join_path(alias_path, sizeof(alias_path), source_path, alias);
    write_file(alias_path, "alias");

    request.case_sensitive = 0;
    int result = portable_capture_resume_at(container_fd, &request, NULL) == 0;
    if (result) {
        result = sidecar_log_adopt_at(container_fd, &log) ==
                 SIDECAR_OPEN_RESUMABLE;
        SidecarLiveView member_view = {0};
        SidecarLiveView alias_view = {0};
        if (result)
            result = sidecar_log_find(&log, resume_bytes("HLTRANS"),
                                      resume_bytes(member), &member_view) == 1 &&
                     sidecar_log_find(&log, resume_bytes("HLTRANS"),
                                      resume_bytes(alias), &alias_view) == 1 &&
                     sidecar_log_claim_count(&log) == 0 &&
                     member_view.entry->kind == SIDECAR_KIND_REGULAR &&
                     alias_view.entry->kind == SIDECAR_KIND_REGULAR &&
                     copy_resume_bytes(member_view.entry->physical_path,
                                       member_physical,
                                       member_physical_size) == 0;
        if (log.implementation != NULL &&
            sidecar_log_close(&log) != SIDECAR_STATUS_OK)
            result = 0;
        char expected_physical[SIDECAR_MAX_PATH + 1U];
        int expected_length = snprintf(expected_physical,
                                       sizeof(expected_physical),
                                       "%s%%7E1", member);
        char member_payload[PATH_MAX];
        char alias_payload[PATH_MAX];
        join_path(member_payload, sizeof(member_payload), container_path,
                  "data/HLTRANS");
        size_t member_payload_length = strlen(member_payload);
        if (result && expected_length >= 0 &&
            (size_t)expected_length < sizeof(expected_physical) &&
            member_payload_length + 1U + (size_t)expected_length <
                sizeof(member_payload)) {
            member_payload[member_payload_length] = '/';
            memcpy(member_payload + member_payload_length + 1U,
                   expected_physical, (size_t)expected_length + 1U);
            join_path(alias_payload, sizeof(alias_payload), container_path,
                      "data/HLTRANS");
            size_t alias_payload_length = strlen(alias_payload);
            if (alias_payload_length + 1U + strlen(alias) >=
                sizeof(alias_payload))
                result = 0;
            else {
                alias_payload[alias_payload_length] = '/';
                memcpy(alias_payload + alias_payload_length + 1U, alias,
                       strlen(alias) + 1U);
                result = result && strcmp(member_physical,
                                          expected_physical) == 0 &&
                         file_equals(member_payload, "before") &&
                         file_equals(alias_payload, "alias");
            }
        } else {
            result = 0;
        }
    }
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
    return result ? 0 : -1;
}

static void test_hardlink_representative_transition_determinism(
    const char *base)
{
    printf(BLUE "::" NC
           " hardlink representative transition with an outstanding CLAIM\n");
    char first_member[NAME_MAX + 1U] = {0};
    char second_member[NAME_MAX + 1U] = {0};
    char first_physical[SIDECAR_MAX_PATH + 1U] = {0};
    char second_physical[SIDECAR_MAX_PATH + 1U] = {0};
    check(run_hardlink_representative_transition(
              base, "hardlink-transition-one", first_member,
              sizeof(first_member), first_physical, sizeof(first_physical)) == 0 &&
              run_hardlink_representative_transition(
                  base, "hardlink-transition-two", second_member,
                  sizeof(second_member), second_physical,
                  sizeof(second_physical)) == 0,
          "a vanished claimed representative is reconciled to its member");
    char expected_physical[SIDECAR_MAX_PATH + 1U];
    int expected_length = snprintf(expected_physical,
                                   sizeof(expected_physical), "%s%%7E1",
                                   first_member);
    check(strcmp(first_member, second_member) == 0 &&
              strcmp(first_physical, second_physical) == 0 &&
              (strcmp(first_member, "first") == 0 ||
               strcmp(first_member, "second") == 0) &&
              expected_length >= 0 &&
              (size_t)expected_length < sizeof(expected_physical) &&
              strcmp(first_physical, expected_physical) == 0,
          "hardlink transition keeps the same member assignment on repeat");
}

static int run_fresh_interrupt(int container_fd,
                               const PortableCaptureRequest *request,
                               PortableTestInterruptPoint point)
{
    return run_fresh_sidecar_interrupt(container_fd, request, point,
                                        SIDECAR_TEST_INTERRUPT_NONE);
}

static int run_fresh_sidecar_interrupt(
    int container_fd, const PortableCaptureRequest *request,
    PortableTestInterruptPoint portable_point,
    SidecarTestInterruptPoint sidecar_point)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        portable_capture_test_set_interrupt(portable_point);
        sidecar_test_set_interrupt(sidecar_point);
        int result = portable_capture_fresh_at(container_fd, request, NULL);
        _exit(result == 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return child_killed_by(status) ? 0 : -1;
}

typedef struct {
    size_t claims;
} ClaimRecordCount;

static int count_claim_records(const SidecarRecord *record, void *opaque)
{
    ClaimRecordCount *count = opaque;
    if (record->type == SIDECAR_RECORD_CLAIM)
        count->claims++;
    return 0;
}

static int sidecar_claim_record_count(int container_fd, size_t *count)
{
    int slot_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                         O_RDONLY | O_CLOEXEC);
    if (slot_fd < 0)
        return -1;
    ClaimRecordCount records = {0};
    SidecarParseResult parse = {0};
    SidecarStatus status = sidecar_parse_fd(slot_fd, count_claim_records,
                                             &records, &parse);
    int close_result = close(slot_fd);
    if (status != SIDECAR_STATUS_OK || close_result != 0)
        return -1;
    *count = records.claims;
    return 0;
}

static int resume_claim_state(int container_fd, size_t expected_live,
                              size_t expected_outstanding,
                              size_t expected_claim_records)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        return 0;
    int result = sidecar_log_live_count(&log) == expected_live &&
                 sidecar_log_claim_count(&log) == expected_outstanding;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    size_t claim_records = 0;
    return result && sidecar_claim_record_count(container_fd,
                                                &claim_records) == 0 &&
           claim_records == expected_claim_records;
}

static int run_resume_interrupt(int container_fd,
                                const PortableCaptureRequest *request,
                                PortableTestInterruptPoint portable_point,
                                SidecarTestInterruptPoint sidecar_point)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        portable_capture_test_set_interrupt(portable_point);
        sidecar_test_set_interrupt(sidecar_point);
        int result = portable_capture_resume_at(container_fd, request, NULL);
        _exit(result == 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return child_killed_by(status) ? 0 : -1;
}

static int fresh_capture(const char *container_path,
                         const PortableCaptureRequest *request,
                         int *container_fd)
{
    *container_fd = create_container(container_path);
    if (*container_fd < 0)
        return -1;
    return portable_capture_fresh_at(*container_fd, request, NULL);
}

static void test_resume_skips_and_replaces(const char *base)
{
    printf(BLUE "::" NC " resume live-state skip and replacement\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    char payload_a[PATH_MAX];
    char payload_b[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "skip-source");
    join_path(container_path, sizeof(container_path), base, "skip-container");
    join_path(payload_a, sizeof(payload_a), container_path, "data/A");
    join_path(payload_b, sizeof(payload_b), container_path, "data/B");
    make_directory(source_path);
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    join_path(source_a, sizeof(source_a), source_path, "a");
    join_path(source_b, sizeof(source_b), source_path, "b");
    write_file(source_a, "unchanged");
    write_file(source_b, "before");

    PortableRootSpec roots[2] = {
        root_spec("A", source_a, "A"),
        root_spec("B", source_b, "B")
    };
    PortableCaptureRequest request = request_for(&roots[0], "a1");
    request.roots = roots;
    request.root_count = 2;
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "fresh partial is available for resume");
    if (container_fd < 0)
        return;

    struct stat before_a;
    check(stat(payload_a, &before_a) == 0 && file_equals(payload_a, "unchanged"),
          "the committed payload exists before resume");
    if (unlink(payload_b) != 0)
        fixture_fatal("could not remove incomplete payload");
    write_file(source_b, "after");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume adopts the existing sidecar");

    struct stat after_a;
    check(stat(payload_a, &after_a) == 0 && after_a.st_ino == before_a.st_ino,
          "an unchanged committed regular file is skipped in place");
    check(file_equals(payload_b, "after"),
          "a missing or changed committed payload is recaptured");
    close(container_fd);
}

static int regular_xattr_fixture_available(void)
{
    char base[] = "/tmp/migr_portable_resume_xattr_XXXXXX";
    int fd = mkstemp(base);
    if (fd < 0)
        return 0;
    close(fd);
    int available = 1;
    if (setxattr(base, "user.migr_resume", "x", 1, 0) != 0 &&
        (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM))
        available = 0;
    unlink(base);
    return available;
}

/*
 * Answers "does this entry's live xattr set consist of exactly these
 * name/value pairs?" for a single-entry root. Returns 1 on exact match
 * (count included), 0 otherwise. view.xattrs is borrowed from the open
 * log, so the check happens before sidecar_log_close.
 */
static int live_xattr_set_exact(int container_fd, const char *root_id,
                                const char *logical,
                                const char *const *names,
                                const char *const *values, size_t count)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        return 0;
    SidecarLiveView view;
    int found = sidecar_log_find(
        &log,
        (SidecarBytes){ (const unsigned char *)root_id, strlen(root_id) },
        (SidecarBytes){ (const unsigned char *)logical, strlen(logical) },
        &view);
    if (found != 1 || view.entry == NULL)
    {
        (void)sidecar_log_close(&log);
        return 0;
    }
    /* Count only user.* xattrs: an SELinux-enabled host auto-assigns
     * security.selinux on every object, which capture faithfully records
     * (D20 E-1) but which is not part of what this test asserts. */
    size_t user_count = 0;
    for (size_t index = 0; index < view.xattr_count; index++)
        if (view.xattrs[index].name.length >= 5 &&
            memcmp(view.xattrs[index].name.data, "user.", 5) == 0)
            user_count++;
    if (user_count != count)
    {
        (void)sidecar_log_close(&log);
        return 0;
    }
    int exact = 1;
    for (size_t index = 0; index < count; index++)
    {
        int matched = 0;
        for (size_t candidate = 0; candidate < view.xattr_count; candidate++)
        {
            const SidecarXattr *xattr = &view.xattrs[candidate];
            if (xattr->name.length < 5 ||
                memcmp(xattr->name.data, "user.", 5) != 0)
                continue;
            size_t name_length = strlen(names[index]);
            size_t value_length = strlen(values[index]);
            if (xattr->name.length == name_length &&
                memcmp(xattr->name.data, names[index], name_length) == 0 &&
                xattr->value.length == value_length &&
                memcmp(xattr->value.data, values[index], value_length) == 0)
            {
                matched = 1;
                break;
            }
        }
        if (!matched)
            exact = 0;
    }
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return 0;
    return exact;
}

static void test_resume_xattr_equivalence(const char *base)
{
    printf(BLUE "::" NC " resume xattr equivalence (added/changed/removed)\n");

    if (!regular_xattr_fixture_available())
    {
        skip_check("xattr resume fixture unavailable on this filesystem");
        return;
    }

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "xattr-source");
    join_path(container_path, sizeof(container_path), base, "xattr-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "entry");
    write_file(source_file, "unchanged-content");

    PortableRootSpec roots[1] = { root_spec("X", source_file, "X") };
    PortableCaptureRequest request = request_for(&roots[0], "c1");
    request.roots = roots;
    request.root_count = 1;
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "xattr resume fixture is captured");
    if (container_fd < 0)
        return;

    static const char *const no_names[1] = { NULL };
    static const char *const no_values[1] = { NULL };

    /* Direction 1: added -- source gains an xattr it did not have. */
    check(setxattr(source_file, "user.migr_resume", "added", 5, 0) == 0,
          "fixture: an xattr is added to the source");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume after adding an xattr succeeds");
    const char *const added_names[1] = { "user.migr_resume" };
    const char *const added_values[1] = { "added" };
    check(live_xattr_set_exact(container_fd, "X", "",
                               added_names, added_values, 1),
          "live sidecar entry carries the added xattr exactly");

    /* Direction 2: changed -- same name, different value. */
    check(setxattr(source_file, "user.migr_resume", "changed", 7, 0) == 0,
          "fixture: the xattr value is changed on the source");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume after changing an xattr value succeeds");
    const char *const changed_names[1] = { "user.migr_resume" };
    const char *const changed_values[1] = { "changed" };
    check(live_xattr_set_exact(container_fd, "X", "",
                               changed_names, changed_values, 1),
          "live sidecar entry carries the changed xattr value exactly");

    /* Direction 3: removed -- source loses the xattr it had. Content and
     * size are identical across all three mutations, so only the sidecar's
     * recorded set (count included) proves the removal was re-captured. */
    check(removexattr(source_file, "user.migr_resume") == 0,
          "fixture: the xattr is removed from the source");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume after removing an xattr succeeds");
    check(live_xattr_set_exact(container_fd, "X", "",
                               no_names, no_values, 0),
          "live sidecar entry carries no xattrs after removal");

    close(container_fd);
}

static void test_encoded_resume(const char *base)
{
    printf(BLUE "::" NC " resume skip for an encoded payload leaf\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "encoded-resume-source");
    join_path(container_path, sizeof(container_path), base,
              "encoded-resume-container");
    make_directory(source_path);

    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "question?name");
    write_file(source_file, "encoded");

    PortableRootSpec root = root_spec("ENCODED", source_path, "ENCODED");
    PortableCaptureRequest request = request_for(&root, "a1e");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "encoded-name fixture is captured before resume");
    if (container_fd < 0)
        return;

    char payload_path[PATH_MAX];
    join_path(payload_path, sizeof(payload_path), container_path,
              "data/ENCODED/question%3Fname");
    char slot_path[PATH_MAX];
    join_path(slot_path, sizeof(slot_path), container_path,
              SIDECAR_SLOT_NAME);
    struct stat payload_before;
    struct stat sidecar_before;
    check(lstat(payload_path, &payload_before) == 0 &&
              file_equals(payload_path, "encoded") &&
              stat(slot_path, &sidecar_before) == 0,
          "encoded payload and sidecar exist before resume");

    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume accepts an unchanged encoded source");
    struct stat payload_after;
    check(lstat(payload_path, &payload_after) == 0 &&
              payload_after.st_ino == payload_before.st_ino,
          "unchanged encoded payload is skipped in place");
    close(container_fd);
}

static int prepare_symlink_replacement(const char *base, const char *label,
                                       PortableRootSpec *root,
                                       PortableCaptureRequest *request,
                                       int *container_fd)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, label);
    char container_name[PATH_MAX];
    int written = snprintf(container_name, sizeof(container_name),
                           "%s-container", label);
    if (written < 0 || (size_t)written >= sizeof(container_name))
        return -1;
    join_path(container_path, sizeof(container_path), base, container_name);
    make_directory(source_path);

    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source_path, "link");
    if (symlink("before-target", link_path) != 0)
        return -1;
    char *stable_link = strdup(link_path);
    if (stable_link == NULL)
        fixture_fatal("could not retain symlink source path");

    *root = root_spec("LINK", stable_link, "LINK");
    *request = request_for(root, "c3c0");
    if (fresh_capture(container_path, request, container_fd) != 0) {
        free(stable_link);
        return -1;
    }
    return 0;
}

static void replace_symlink_target(const char *path, const char *target)
{
    if (unlink(path) != 0 || symlink(target, path) != 0)
        fixture_fatal("could not replace symlink fixture target");
}

static int symlink_live_target(int container_fd, const char *expected)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        return 0;
    SidecarLiveView view;
    int found = sidecar_log_find(
        &log,
        (SidecarBytes){ (const unsigned char *)"LINK", 4 },
        (SidecarBytes){ (const unsigned char *)"", 0 }, &view);
    size_t expected_length = strlen(expected);
    int result = found == 1 && view.entry->kind == SIDECAR_KIND_SYMLINK &&
                 view.entry->symlink_target.length == expected_length &&
                 memcmp(view.entry->symlink_target.data, expected,
                        expected_length) == 0;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return 0;
    return result;
}

static int symlink_placeholder(int container_fd)
{
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0)
        return 0;
    struct stat st;
    int result = fstatat(data_fd, "LINK", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                 S_ISREG(st.st_mode) && st.st_size == 0;
    if (close(data_fd) != 0)
        result = 0;
    return result;
}

static void test_symlink_resume(const char *base)
{
    printf(BLUE "::" NC " symlink resume skip and target replacement\n");
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd = -1;
    char container_path[PATH_MAX];
    join_path(container_path, sizeof(container_path), base,
              "symlink-resume-container");
    check(prepare_symlink_replacement(base, "symlink-resume", &root,
                                      &request, &container_fd) == 0,
          "symlink resume fixture has a committed predecessor");
    if (container_fd < 0)
        return;

    char slot_path[PATH_MAX];
    join_path(slot_path, sizeof(slot_path), container_path,
              SIDECAR_SLOT_NAME);
    char payload_path[PATH_MAX];
    join_path(payload_path, sizeof(payload_path), container_path,
              "data/LINK");
    struct stat payload_before;
    struct stat sidecar_before;
    check(lstat(payload_path, &payload_before) == 0 &&
              S_ISREG(payload_before.st_mode) && payload_before.st_size == 0 &&
              stat(slot_path, &sidecar_before) == 0,
          "symlink placeholder and sidecar exist before resume");
    check(symlink_live_target(container_fd, "before-target"),
          "initial symlink entry records its target");

    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume accepts an unchanged symlink");
    struct stat payload_after;
    struct stat sidecar_after;
    check(lstat(payload_path, &payload_after) == 0 &&
              payload_after.st_ino == payload_before.st_ino &&
              stat(slot_path, &sidecar_after) == 0 &&
              sidecar_after.st_size == sidecar_before.st_size &&
              symlink_placeholder(container_fd) &&
              symlink_live_target(container_fd, "before-target"),
          "unchanged symlink resume leaves payload and sidecar untouched");

    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "a second unchanged symlink resume remains idempotent");
    check(stat(slot_path, &sidecar_after) == 0 &&
              sidecar_after.st_size == sidecar_before.st_size,
          "repeated unchanged resume appends no sidecar group");

    replace_symlink_target(root.capture_path, "after-target");
    check(symlink_equals(root.capture_path, "after-target"),
          "fixture exposes the changed symlink target");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume recaptures a changed symlink target");
    check(symlink_placeholder(container_fd) &&
              symlink_live_target(container_fd, "after-target") &&
              stat(slot_path, &sidecar_after) == 0 &&
              sidecar_after.st_size > sidecar_before.st_size,
          "changed symlink gets a fresh group and intact placeholder");

    close(container_fd);
    free((void *)root.capture_path);
}

static void test_missing_sidecar(const char *base)
{
    printf(BLUE "::" NC " pristine sidecar recovery\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "missing-source");
    join_path(container_path, sizeof(container_path), base,
              "missing-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "recoverable");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a2");
    int container_fd = create_container(container_path);
    if (container_fd < 0)
        fixture_fatal("could not create missing-sidecar container");

    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_MANIFEST) == 0,
          "SIGKILL after manifest leaves an adoptable boundary");
    check(!missing_at(container_fd, "manifest.txt") &&
          missing_at(container_fd, SIDECAR_SLOT_NAME),
          "manifest exists while sidecar is still absent");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume creates a sidecar only for the pristine namespace");
    check(!missing_at(container_fd, SIDECAR_SLOT_NAME),
          "recovery creates the sidecar slot");
    close(container_fd);
}

static void test_nonempty_without_sidecar(const char *base)
{
    printf(BLUE "::" NC " non-pristine sidecar refusal\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "orphan-source");
    join_path(container_path, sizeof(container_path), base,
              "orphan-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "orphan");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a3");
    int container_fd = create_container(container_path);
    if (container_fd < 0)
        fixture_fatal("could not create orphan container");
    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_MANIFEST) == 0,
          "orphan fixture starts at the manifest boundary");
    if (mkdirat(container_fd, "data", 0700) != 0)
        fixture_fatal("could not create orphan data directory");
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (data_fd < 0)
        fixture_fatal("could not open orphan data directory");
    int orphan_fd = openat(data_fd, "orphan", O_WRONLY | O_CREAT | O_EXCL |
                            O_CLOEXEC, 0600);
    if (orphan_fd < 0 || close(orphan_fd) != 0 || close(data_fd) != 0)
        fixture_fatal("could not create orphan payload");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "resume refuses a nonempty data namespace without a sidecar");
    check(missing_at(container_fd, SIDECAR_SLOT_NAME),
          "refusal does not silently create a fresh sidecar");
    struct stat st;
    check(fstatat(container_fd, "data/orphan", &st, AT_SYMLINK_NOFOLLOW) == 0,
          "refusal leaves the unclaimed payload untouched");
    close(container_fd);
}

static void test_unsafe_sidecar(const char *base)
{
    printf(BLUE "::" NC " corrupt and unsafe sidecar refusal\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    char target_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "unsafe-source");
    join_path(container_path, sizeof(container_path), base,
              "unsafe-container");
    join_path(target_path, sizeof(target_path), base, "sidecar-target");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "unsafe");
    write_file(target_path, "not a sidecar");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a4");
    int container_fd = create_container(container_path);
    if (container_fd < 0)
        fixture_fatal("could not create unsafe container");
    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_MANIFEST) == 0,
          "unsafe fixture starts at the manifest boundary");
    char slot_path[PATH_MAX];
    join_path(slot_path, sizeof(slot_path), container_path, SIDECAR_SLOT_NAME);
    if (symlink(target_path, slot_path) != 0)
        fixture_fatal("could not create unsafe sidecar symlink");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "a symlink sidecar is unusable rather than followed");
    check(missing_at(container_fd, "data"),
          "unsafe sidecar refusal leaves the missing data namespace absent");

    if (unlink(slot_path) != 0 || mkdirat(container_fd, "data", 0700) != 0)
        fixture_fatal("could not prepare malformed sidecar fixture");
    int malformed_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (malformed_fd < 0 || write(malformed_fd, "garbage", 7) != 7 ||
        close(malformed_fd) != 0)
        fixture_fatal("could not write malformed sidecar fixture");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "an interior-corrupt sidecar is unusable rather than freshened");
    check(file_equals(target_path, "not a sidecar"),
          "malformed-sidecar refusal leaves the unrelated target untouched");
    close(container_fd);
}

static void test_truncated_tail(const char *base)
{
    printf(BLUE "::" NC " truncated sidecar tail recovery\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    char slot_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "tail-source");
    join_path(container_path, sizeof(container_path), base, "tail-container");
    join_path(slot_path, sizeof(slot_path), container_path, SIDECAR_SLOT_NAME);
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "tail");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a5");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "fresh capture creates a complete sidecar");
    if (container_fd < 0)
        return;
    int slot_fd = open(slot_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (slot_fd < 0)
        fixture_fatal("could not open sidecar for tail fixture");
    static const char tail[] = "ENTRY\0partial";
    if (write(slot_fd, tail, sizeof(tail) - 1U) !=
            (ssize_t)(sizeof(tail) - 1U) || close(slot_fd) != 0)
        fixture_fatal("could not append sidecar tail");
    struct stat before;
    if (stat(slot_path, &before) != 0)
        fixture_fatal("could not stat tailed sidecar");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume truncates an incomplete final sidecar record");
    struct stat after;
    check(stat(slot_path, &after) == 0 && after.st_size < before.st_size,
          "tail recovery truncates only the incomplete suffix");
    close(container_fd);
}

static void test_zero_claim_gate(const char *base)
{
    printf(BLUE "::" NC " resume rejects outstanding ownership claims\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "claim-gate-source");
    join_path(container_path, sizeof(container_path), base,
              "claim-gate-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "unchanged");

    PortableRootSpec root = root_spec("ROOT", source_path, "ROOT");
    PortableCaptureRequest request = request_for(&root, "ca1e");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "claim-gate fixture has an otherwise complete capture");
    if (container_fd < 0)
        return;

    SidecarClaim outstanding = {
        /* A claim belonging to a root outside this request is not a stale
         * candidate for this walk; the global zero-claim gate must still
         * reject the otherwise resumable container. */
        .root_id = resume_bytes("OTHER"),
        .logical_path = resume_bytes("blocked"),
        .physical_path = resume_bytes("blocked"),
        .kind = SIDECAR_KIND_REGULAR
    };
    SidecarLog log = {0};
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_append_claim(&log, &outstanding) ==
                  SIDECAR_STATUS_OK &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "an outstanding claim is planted after the valid capture");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "resume fails at the global zero-claim gate");

    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_claim_count(&log) == 1 &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK &&
              file_equals(source_file, "unchanged"),
          "the failed resume leaves the claim and source unchanged");
    close(container_fd);
}

typedef struct {
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd;
    char *capture_path;
    char *container_path;
    const char *hardlink_representative;
} SigkillFixture;

typedef struct {
    const char *label;
    PortableTestInterruptPoint portable_point;
    SidecarTestInterruptPoint sidecar_point;
    int requires_xattr;
} SigkillCase;

typedef int (*SigkillPrepare)(const char *base, const char *label,
                             SigkillFixture *fixture);
typedef int (*SigkillMutate)(SigkillFixture *fixture);
typedef int (*SigkillValidate)(const SigkillFixture *fixture);
typedef int (*SigkillXattrAvailable)(void);

typedef enum {
    SIGKILL_XATTR_NONE,
    SIGKILL_XATTR_FOLLOW,
    SIGKILL_XATTR_NOFOLLOW
} SigkillXattrMode;

typedef struct {
    const char *heading;
    const char *label_prefix;
    const char *predecessor_label;
    const char *resumable_label;
    const char *recovery_label;
    const char *xattr_skip_label;
    const char *xattr_check_label;
    const char *xattr_root_id;
    const char *xattr_name;
    const char *xattr_value;
    SigkillXattrMode xattr_mode;
    SigkillPrepare prepare;
    SigkillMutate mutate;
    SigkillValidate validate;
    SigkillXattrAvailable xattr_available;
    const SigkillCase *cases;
    size_t case_count;
} SigkillKind;

static int symlink_xattr_fixture_available(void);

static void sigkill_fixture_retain_paths(SigkillFixture *fixture,
                                         const char *capture_path,
                                         const char *container_path)
{
    fixture->capture_path = strdup(capture_path);
    fixture->container_path = strdup(container_path);
    if (fixture->capture_path == NULL || fixture->container_path == NULL)
        fixture_fatal("could not retain interruption fixture paths");
}

static void sigkill_fixture_close(SigkillFixture *fixture)
{
    if (fixture->container_fd >= 0)
        close(fixture->container_fd);
    free(fixture->capture_path);
    free(fixture->container_path);
    fixture->container_fd = -1;
    fixture->capture_path = NULL;
    fixture->container_path = NULL;
    fixture->hardlink_representative = NULL;
}

static int sigkill_fixture_paths(const char *base, const char *label,
                                 char *source_path, size_t source_size,
                                 char *container_path, size_t container_size)
{
    join_path(source_path, source_size, base, label);
    char container_name[PATH_MAX];
    int written = snprintf(container_name, sizeof(container_name),
                           "%s-container", label);
    if (written < 0 || (size_t)written >= sizeof(container_name))
        return -1;
    join_path(container_path, container_size, base, container_name);
    return 0;
}

static int prepare_regular_sigkill(const char *base, const char *label,
                                   SigkillFixture *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    if (sigkill_fixture_paths(base, label, source_path, sizeof(source_path),
                              container_path, sizeof(container_path)) != 0)
        return -1;
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "before");
    sigkill_fixture_retain_paths(fixture, source_file, container_path);
    fixture->root = root_spec("ROOT", fixture->capture_path, "ROOT");
    fixture->request = request_for(&fixture->root, "b1");
    fixture->container_fd = -1;
    if (fresh_capture(fixture->container_path, &fixture->request,
                      &fixture->container_fd) != 0)
        return -1;
    return 0;
}

static int mutate_regular_sigkill(SigkillFixture *fixture)
{
    write_file(fixture->capture_path, "after");
    return 0;
}

static int prepare_symlink_sigkill(const char *base, const char *label,
                                   SigkillFixture *fixture)
{
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd = -1;
    if (prepare_symlink_replacement(base, label, &root, &request,
                                     &container_fd) != 0)
        return -1;
    char source_unused[PATH_MAX];
    char container_path[PATH_MAX];
    if (sigkill_fixture_paths(base, label, source_unused, sizeof(source_unused),
                              container_path, sizeof(container_path)) != 0) {
        close(container_fd);
        free((void *)root.capture_path);
        return -1;
    }
    fixture->root = root;
    fixture->request = request;
    fixture->container_fd = container_fd;
    sigkill_fixture_retain_paths(fixture, root.capture_path, container_path);
    free((void *)root.capture_path);
    fixture->root.capture_path = fixture->capture_path;
    fixture->root.source_path = fixture->capture_path;
    fixture->request.roots = &fixture->root;
    return 0;
}

static int mutate_symlink_sigkill(SigkillFixture *fixture)
{
    replace_symlink_target(fixture->capture_path, "after-target");
    return 0;
}

static int directory_xattr_fixture_available(void)
{
    char base[] = "/tmp/migr_portable_resume_directory_xattr_XXXXXX";
    if (mkdtemp(base) == NULL)
        return 0;
    int available = setxattr(base, "user.migr_directory_resume", "x", 1, 0) == 0;
    if (!available && errno != ENOTSUP && errno != EOPNOTSUPP && errno != EPERM)
        fixture_fatal("could not probe directory xattr support");
    if (rmdir(base) != 0)
        fixture_fatal("could not remove directory xattr probe");
    return available;
}

static int first_hardlink_entry(const char *source, char *first_seen,
                                size_t first_seen_size)
{
    DIR *directory = opendir(source);
    if (directory == NULL)
        return -1;
    struct dirent *entry = NULL;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL)
            break;
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            break;
    }
    int valid = entry != NULL &&
                (strcmp(entry->d_name, "first") == 0 ||
                 strcmp(entry->d_name, "second") == 0) &&
                snprintf(first_seen, first_seen_size, "%s", entry->d_name) >= 0 &&
                strlen(entry->d_name) < first_seen_size;
    if (closedir(directory) != 0)
        return -1;
    return valid ? 0 : -1;
}

static int prepare_directory_sigkill(const char *base, const char *label,
                                     SigkillFixture *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    if (sigkill_fixture_paths(base, label, source_path, sizeof(source_path),
                              container_path, sizeof(container_path)) != 0)
        return -1;
    make_directory(source_path);
    sigkill_fixture_retain_paths(fixture, source_path, container_path);
    fixture->root = root_spec("DIR", fixture->capture_path, "DIR");
    fixture->request = request_for(&fixture->root, "d1");
    fixture->container_fd = -1;
    if (fresh_capture(fixture->container_path, &fixture->request,
                      &fixture->container_fd) != 0)
        return -1;
    return 0;
}

static int mutate_directory_sigkill(SigkillFixture *fixture)
{
    if (chmod(fixture->capture_path, 0755) != 0)
        fixture_fatal("could not mutate directory interruption fixture");
    return 0;
}

static int prepare_hardlink_sigkill(const char *base, const char *label,
                                    SigkillFixture *fixture)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    if (sigkill_fixture_paths(base, label, source_path, sizeof(source_path),
                              container_path, sizeof(container_path)) != 0)
        return -1;
    make_directory(source_path);
    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    join_path(first_path, sizeof(first_path), source_path, "first");
    join_path(second_path, sizeof(second_path), source_path, "second");
    write_file(first_path, "before");
    if (link(first_path, second_path) != 0)
        return -1;

    char first_seen[NAME_MAX + 1U];
    if (first_hardlink_entry(source_path, first_seen, sizeof(first_seen)) != 0)
        return -1;
    const char *old_representative = strcmp(first_seen, "first") == 0
        ? "second" : "first";
    const char *old_member = strcmp(old_representative, "first") == 0
        ? "second" : "first";

    sigkill_fixture_retain_paths(fixture, source_path, container_path);
    fixture->hardlink_representative = old_representative;
    fixture->root = root_spec("HL", fixture->capture_path, "HL");
    fixture->root.source_path = "";
    fixture->request = request_for(&fixture->root, "c1");
    fixture->request.case_sensitive = 1;
    fixture->container_fd = create_container(fixture->container_path);
    if (fixture->container_fd < 0)
        return -1;
    if (mkdirat(fixture->container_fd, "data", 0700) != 0 ||
        mkdirat(fixture->container_fd, "data/HL", 0700) != 0)
        return -1;

    char data_root[PATH_MAX];
    char representative_payload[PATH_MAX];
    char member_payload[PATH_MAX];
    join_path(data_root, sizeof(data_root), fixture->container_path,
              "data/HL");
    join_path(representative_payload, sizeof(representative_payload),
              data_root, old_representative);
    join_path(member_payload, sizeof(member_payload), data_root, old_member);
    write_file(representative_payload, "before");
    write_file(member_payload, "");

    struct stat source_root_stat;
    struct stat representative_stat;
    struct stat member_stat;
    const char *representative_path = strcmp(old_representative, "first") == 0
        ? first_path : second_path;
    const char *member_path = strcmp(old_member, "first") == 0
        ? first_path : second_path;
    if (stat(fixture->capture_path, &source_root_stat) != 0 ||
        stat(representative_path, &representative_stat) != 0 ||
        stat(member_path, &member_stat) != 0)
        return -1;

    int source_fd = open(representative_path, O_RDONLY | O_CLOEXEC);
    PortableXattrs representative_xattrs = {0};
    if (source_fd < 0 || collect_xattrs(source_fd, &representative_xattrs) != 0) {
        if (source_fd >= 0)
            close(source_fd);
        return -1;
    }
    if (close(source_fd) != 0)
        return -1;

    ManifestRoot manifest_root = {
        .id = "HL",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .payload_path = "HL",
        .source_path = "",
        .restore_path = "",
        .has_restore_path = 1
    };
    Manifest manifest = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .has_source_identity = 1,
        .source_uid = getuid(),
        .root_count = 1,
        .roots = &manifest_root
    };
    if (snprintf(manifest.machine_id, sizeof(manifest.machine_id), "%s", "c1") < 0 ||
        manifest_write_v1_at(fixture->container_fd, &manifest) != 0)
        return -1;

    PortableXattrs empty_xattrs = {0};
    SidecarEntry root_entry = {0};
    SidecarEntry representative_entry = {0};
    SidecarEntry member_entry = {0};
    SidecarBytes hardlink_root_id = resume_bytes("HL");
    SidecarBytes hardlink_logical_path = resume_bytes(old_representative);
    if (entry_from_stat("HL", "", "", "", &source_root_stat, 1,
                        &empty_xattrs, &root_entry, NULL, NULL, NULL) != 0 ||
        entry_from_stat("HL", old_representative, old_representative, "",
                        &representative_stat, 1, &representative_xattrs,
                        &representative_entry, NULL, NULL, NULL) != 0 ||
        entry_from_stat("HL", old_member, old_member, "", &member_stat, 1,
                        &empty_xattrs, &member_entry, NULL,
                        &hardlink_root_id, &hardlink_logical_path) != 0)
        return -1;
    SidecarClaim root_claim = {
        .root_id = root_entry.root_id,
        .logical_path = root_entry.logical_path,
        .physical_path = root_entry.physical_path,
        .kind = root_entry.kind
    };
    SidecarClaim representative_claim = {
        .root_id = representative_entry.root_id,
        .logical_path = representative_entry.logical_path,
        .physical_path = representative_entry.physical_path,
        .kind = representative_entry.kind
    };
    SidecarClaim member_claim = {
        .root_id = member_entry.root_id,
        .logical_path = member_entry.logical_path,
        .physical_path = member_entry.physical_path,
        .kind = member_entry.kind
    };

    SidecarLog log = {0};
    if (sidecar_log_create_at(fixture->container_fd, &log) !=
            SIDECAR_OPEN_FRESH ||
        sidecar_log_append_claim(&log, &root_claim) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &root_entry) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &representative_claim) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &representative_entry) !=
            SIDECAR_STATUS_OK)
        return -1;
    for (size_t index = 0; index < representative_xattrs.count; index++)
        if (sidecar_log_append_xattr(&log,
                                     &representative_xattrs.items[index]) !=
            SIDECAR_STATUS_OK)
            return -1;
    if (sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &member_claim) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &member_entry) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return -1;
    xattrs_free(&representative_xattrs);
    return 0;
}

static int mutate_hardlink_sigkill(SigkillFixture *fixture)
{
    char first_path[PATH_MAX];
    join_path(first_path, sizeof(first_path), fixture->capture_path, "first");
    write_file(first_path, "after");
    return 0;
}

static int regular_sigkill_recovered(const SigkillFixture *fixture)
{
    return file_equals(fixture->capture_path, "after");
}

static int symlink_sigkill_recovered(const SigkillFixture *fixture)
{
    return symlink_placeholder(fixture->container_fd) &&
           symlink_live_target(fixture->container_fd, "after-target");
}

static int directory_sigkill_recovered(const SigkillFixture *fixture)
{
    struct stat source;
    struct stat payload;
    char payload_path[PATH_MAX];
    join_path(payload_path, sizeof(payload_path), fixture->container_path,
              "data/DIR");
    if (stat(fixture->capture_path, &source) != 0 ||
        stat(payload_path, &payload) != 0 || !S_ISDIR(source.st_mode) ||
        !S_ISDIR(payload.st_mode) || (source.st_mode & 07777U) != 0755U)
        return 0;

    SidecarLog log = {0};
    if (sidecar_log_adopt_at(fixture->container_fd, &log) !=
        SIDECAR_OPEN_RESUMABLE)
        return 0;
    SidecarLiveView view = {0};
    int found = sidecar_log_find(&log, resume_bytes("DIR"),
                                 resume_bytes(""), &view);
    int result = found == 1 && view.entry->kind == SIDECAR_KIND_DIRECTORY &&
                 (view.entry->mode & 07777U) == 0755U;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    return result;
}

static int resume_bytes_equal(SidecarBytes left, SidecarBytes right)
{
    if (left.length != right.length)
        return 0;
    if (left.length == 0)
        return 1;
    return left.data != NULL && right.data != NULL &&
           memcmp(left.data, right.data, left.length) == 0;
}

static int resume_bytes_match_text(SidecarBytes value, const char *text)
{
    return resume_bytes_equal(value, resume_bytes(text));
}

static int hardlink_sigkill_recovered(const SigkillFixture *fixture)
{
    char source_first[PATH_MAX];
    char source_second[PATH_MAX];
    char payload_first[PATH_MAX];
    char payload_second[PATH_MAX];
    join_path(source_first, sizeof(source_first), fixture->capture_path,
              "first");
    join_path(source_second, sizeof(source_second), fixture->capture_path,
              "second");
    join_path(payload_first, sizeof(payload_first), fixture->container_path,
              "data/HL/first");
    join_path(payload_second, sizeof(payload_second), fixture->container_path,
              "data/HL/second");

    struct stat source_first_stat;
    struct stat source_second_stat;
    struct stat payload_first_stat;
    struct stat payload_second_stat;
    if (stat(source_first, &source_first_stat) != 0 ||
        stat(source_second, &source_second_stat) != 0 ||
        stat(payload_first, &payload_first_stat) != 0 ||
        stat(payload_second, &payload_second_stat) != 0 ||
        !file_equals(source_first, "after") ||
        !file_equals(source_second, "after") ||
        source_first_stat.st_dev != source_second_stat.st_dev ||
        source_first_stat.st_ino != source_second_stat.st_ino ||
        !S_ISREG(payload_first_stat.st_mode) ||
        !S_ISREG(payload_second_stat.st_mode))
        return 0;

    SidecarLog log = {0};
    if (sidecar_log_adopt_at(fixture->container_fd, &log) !=
        SIDECAR_OPEN_RESUMABLE)
        return 0;
    const char *representative_name = fixture->hardlink_representative;
    if (representative_name == NULL ||
        (strcmp(representative_name, "first") != 0 &&
         strcmp(representative_name, "second") != 0)) {
        sidecar_log_close(&log);
        return 0;
    }
    const char *member_name = strcmp(representative_name, "first") == 0
        ? "second" : "first";
    SidecarLiveView representative = {0};
    SidecarLiveView member = {0};
    int pair_found = sidecar_log_find(&log, resume_bytes("HL"),
                                      resume_bytes(representative_name),
                                      &representative) == 1 &&
                     sidecar_log_find(&log, resume_bytes("HL"),
                                      resume_bytes(member_name), &member) == 1;
    int result = pair_found &&
                 strcmp(representative_name,
                        fixture->hardlink_representative) == 0 &&
                 representative.entry->kind == SIDECAR_KIND_REGULAR &&
                 member.entry->kind == SIDECAR_KIND_HARDLINK &&
                 resume_bytes_match_text(member.entry->hardlink_root_id, "HL") &&
                 resume_bytes_equal(member.entry->hardlink_logical_path,
                                    representative.entry->logical_path) &&
                 ((strcmp(representative_name, "first") == 0
                       ? file_equals(payload_first, "after")
                       : file_equals(payload_second, "after"))) &&
                 ((strcmp(member_name, "first") == 0
                       ? payload_first_stat.st_size == 0
                       : payload_second_stat.st_size == 0));
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    return result;
}

static int payload_regular_size(const char *container_path,
                                const char *relative, off_t expected_size)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), container_path, relative);
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_size == expected_size;
}

static int payload_directory(const char *container_path, const char *relative)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), container_path, relative);
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

typedef struct {
    char source[PATH_MAX];
    char container[PATH_MAX];
    char node[PATH_MAX];
    char first[PATH_MAX];
    char second[PATH_MAX];
    char logical[NAME_MAX + 1U];
    const char *root_id;
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd;
} ClaimKindChangeFixture;

static int prepare_claim_kind_change_fixture(const char *base,
                                             const char *label, int hardlink,
                                             int old_directory,
                                             ClaimKindChangeFixture *fixture)
{
    if (base == NULL || label == NULL || fixture == NULL)
        return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->container_fd = -1;
    join_path(fixture->source, sizeof(fixture->source), base, label);
    char container_label[NAME_MAX + 1U];
    int length = snprintf(container_label, sizeof(container_label),
                          "%s-container", label);
    if (length < 0 || (size_t)length >= sizeof(container_label))
        return -1;
    join_path(fixture->container, sizeof(fixture->container), base,
              container_label);
    make_directory(fixture->source);

    if (hardlink) {
        join_path(fixture->first, sizeof(fixture->first), fixture->source,
                  "first");
        join_path(fixture->second, sizeof(fixture->second), fixture->source,
                  "second");
        write_file(fixture->first, "hardlink-before");
        if (link(fixture->first, fixture->second) != 0)
            return -1;
        memcpy(fixture->logical, "second", sizeof("second"));
        fixture->root_id = "TYPEHL";
    } else {
        join_path(fixture->node, sizeof(fixture->node), fixture->source,
                  "node");
        if (old_directory)
            make_directory(fixture->node);
        else
            write_file(fixture->node, "regular-before");
        memcpy(fixture->logical, "node", sizeof("node"));
        fixture->root_id = "TYPE";
    }

    fixture->root = root_spec(fixture->root_id, fixture->source,
                              fixture->root_id);
    fixture->request = request_for(&fixture->root, "c7a1");
    if (fresh_capture(fixture->container, &fixture->request,
                      &fixture->container_fd) != 0)
        return -1;
    return 0;
}

static int plant_type_change_claim(const ClaimKindChangeFixture *fixture,
                                   SidecarObjectKind old_kind)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(fixture->container_fd, &log) !=
        SIDECAR_OPEN_RESUMABLE)
        return -1;
    SidecarBytes root = resume_bytes(fixture->root_id);
    SidecarBytes logical = resume_bytes(fixture->logical);
    SidecarDelete deletion = {
        .root_id = root,
        .logical_path = logical
    };
    SidecarClaim claim = {
        .root_id = root,
        .logical_path = logical,
        .physical_path = logical,
        .kind = old_kind
    };
    int result = sidecar_log_append_delete(&log, &deletion) ==
                     SIDECAR_STATUS_OK &&
                 sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    return result ? 0 : -1;
}

static int mutate_claim_kind_source(ClaimKindChangeFixture *fixture,
                                    int hardlink, int old_directory)
{
    if (hardlink) {
        if (unlink(fixture->second) != 0)
            return -1;
        write_file(fixture->second, "hardlink-now-regular");
        return 0;
    }
    if (old_directory) {
        if (rmdir(fixture->node) != 0)
            return -1;
        write_file(fixture->node, "directory-now-regular");
    } else {
        if (unlink(fixture->node) != 0)
            return -1;
        if (mkdir(fixture->node, 0700) != 0)
            return -1;
    }
    return 0;
}

static int live_kind_and_no_claim(const ClaimKindChangeFixture *fixture,
                                  SidecarObjectKind expected_kind)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(fixture->container_fd, &log) !=
        SIDECAR_OPEN_RESUMABLE)
        return 0;
    SidecarLiveView view = {0};
    int result = sidecar_log_find(&log, resume_bytes(fixture->root_id),
                                  resume_bytes(fixture->logical), &view) == 1 &&
                 view.entry->kind == expected_kind &&
                 sidecar_log_claim_count(&log) == 0;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    return result;
}

static void test_claim_kind_changes(const char *base)
{
    printf(BLUE "::" NC " stale CLAIM kind changes\n");
    ClaimKindChangeFixture fixture;
    check(prepare_claim_kind_change_fixture(base, "claim-dir-regular", 0, 1,
                                            &fixture) == 0 &&
              plant_type_change_claim(&fixture, SIDECAR_KIND_DIRECTORY) == 0 &&
              mutate_claim_kind_source(&fixture, 0, 1) == 0 &&
              portable_capture_resume_at(fixture.container_fd,
                                          &fixture.request, NULL) == 0 &&
              live_kind_and_no_claim(&fixture, SIDECAR_KIND_REGULAR) &&
              file_equals(fixture.node, "directory-now-regular"),
          "claimed directory changes to regular with cleanup and DELETE");
    if (fixture.container_fd >= 0)
        close(fixture.container_fd);

    check(prepare_claim_kind_change_fixture(base, "claim-regular-dir", 0, 0,
                                            &fixture) == 0 &&
              plant_type_change_claim(&fixture, SIDECAR_KIND_REGULAR) == 0 &&
              mutate_claim_kind_source(&fixture, 0, 0) == 0 &&
              portable_capture_resume_at(fixture.container_fd,
                                          &fixture.request, NULL) == 0 &&
              live_kind_and_no_claim(&fixture, SIDECAR_KIND_DIRECTORY) &&
              payload_directory(fixture.container, "data/TYPE/node"),
          "claimed regular changes to directory with cleanup and DELETE");
    if (fixture.container_fd >= 0)
        close(fixture.container_fd);

    check(prepare_claim_kind_change_fixture(base, "claim-hardlink-regular", 1,
                                            0, &fixture) == 0 &&
              plant_type_change_claim(&fixture, SIDECAR_KIND_HARDLINK) == 0 &&
              mutate_claim_kind_source(&fixture, 1, 0) == 0 &&
              portable_capture_resume_at(fixture.container_fd,
                                          &fixture.request, NULL) == 0 &&
              live_kind_and_no_claim(&fixture, SIDECAR_KIND_REGULAR) &&
              file_equals(fixture.second, "hardlink-now-regular"),
          "claimed hardlink changes to regular without retaining the old relation");
    if (fixture.container_fd >= 0)
        close(fixture.container_fd);
}

static void test_repeated_claim_kind_change_interrupt(const char *base)
{
    printf(BLUE "::" NC " repeated stale CLAIM kind-change interruption\n");
    ClaimKindChangeFixture fixture;
    check(prepare_claim_kind_change_fixture(base, "claim-kind-repeat", 0, 1,
                                            &fixture) == 0 &&
              plant_type_change_claim(&fixture, SIDECAR_KIND_DIRECTORY) == 0 &&
              mutate_claim_kind_source(&fixture, 0, 1) == 0,
          "repeated kind-change fixture is prepared");
    if (fixture.container_fd < 0)
        return;

    check(run_resume_interrupt(fixture.container_fd, &fixture.request,
                               PORTABLE_TEST_AFTER_STALE_UNLINK,
                               SIDECAR_TEST_INTERRUPT_NONE) == 0 &&
              !payload_directory(fixture.container, "data/TYPE/node") &&
              live_kind_and_no_claim(&fixture, SIDECAR_KIND_REGULAR) == 0,
          "SIGKILL after old CLAIM payload removal leaves the CLAIM resumable");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) == 0 &&
              live_kind_and_no_claim(&fixture, SIDECAR_KIND_REGULAR) &&
              file_equals(fixture.node, "directory-now-regular"),
          "the next resume idempotently completes the kind change");
    close(fixture.container_fd);
}

static void test_fresh_regular_claim_resume(const char *base)
{
    printf(BLUE "::" NC " fresh regular CLAIM resume proof\n");
    char source_dir[PATH_MAX];
    char source_file[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_dir, sizeof(source_dir), base,
              "fresh-regular-source");
    join_path(container_path, sizeof(container_path), base,
              "fresh-regular-container");
    make_directory(source_dir);
    join_path(source_file, sizeof(source_file), source_dir, "file");
    write_file(source_file, "fresh-regular");

    PortableRootSpec root = root_spec("FRESH_REG", source_file, "FRESH_REG");
    PortableCaptureRequest request = request_for(&root, "f123");
    int container_fd = create_container(container_path);
    check(container_fd >= 0, "fresh regular fixture has an empty container");
    if (container_fd < 0)
        return;

    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_PAYLOAD_REPLACE) == 0,
          "fresh regular capture is killed after payload creation");
    check(payload_regular_size(container_path, "data/FRESH_REG", 0) &&
              resume_claim_state(container_fd, 0, 1, 1),
          "fresh regular interruption leaves one exact outstanding CLAIM");

    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "fresh regular capture resumes from its CLAIM");
    check(file_equals(source_file, "fresh-regular") &&
              payload_regular_size(container_path, "data/FRESH_REG", 13) &&
              resume_claim_state(container_fd, 1, 0, 1),
          "fresh regular payload commits without duplicating its CLAIM");
    close(container_fd);
}

static void test_fresh_symlink_claim_resume(const char *base)
{
    printf(BLUE "::" NC " fresh symlink CLAIM resume proof\n");
    char source_dir[PATH_MAX];
    char source_link[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_dir, sizeof(source_dir), base,
              "fresh-symlink-source");
    join_path(container_path, sizeof(container_path), base,
              "fresh-symlink-container");
    make_directory(source_dir);
    join_path(source_link, sizeof(source_link), source_dir, "link");
    if (symlink("fresh-target", source_link) != 0)
        fixture_fatal("could not create fresh symlink fixture");

    PortableRootSpec root = root_spec("LINK", source_link, "LINK");
    PortableCaptureRequest request = request_for(&root, "f124");
    int container_fd = create_container(container_path);
    check(container_fd >= 0, "fresh symlink fixture has an empty container");
    if (container_fd < 0)
        return;

    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_PAYLOAD_REPLACE) == 0,
          "fresh symlink capture is killed after placeholder creation");
    check(payload_regular_size(container_path, "data/LINK", 0) &&
              resume_claim_state(container_fd, 0, 1, 1),
          "fresh symlink interruption leaves one exact outstanding CLAIM");

    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "fresh symlink capture resumes from its CLAIM");
    check(symlink_placeholder(container_fd) &&
              symlink_live_target(container_fd, "fresh-target") &&
              resume_claim_state(container_fd, 1, 0, 1),
          "fresh symlink payload commits without duplicating its CLAIM");
    close(container_fd);
}

static void test_fresh_hardlink_claim_resume(const char *base)
{
    printf(BLUE "::" NC " fresh hardlink CLAIM resume proof\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    if (sigkill_fixture_paths(base, "fresh-hardlink", source_path,
                              sizeof(source_path), container_path,
                              sizeof(container_path)) != 0)
        fixture_fatal("fresh hardlink fixture path is too long");
    make_directory(source_path);

    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    join_path(first_path, sizeof(first_path), source_path, "first");
    join_path(second_path, sizeof(second_path), source_path, "second");
    write_file(first_path, "fresh-hardlink");
    if (link(first_path, second_path) != 0)
        fixture_fatal("could not create fresh hardlink fixture");

    char representative_name[NAME_MAX + 1U];
    if (first_hardlink_entry(source_path, representative_name,
                             sizeof(representative_name)) != 0)
        fixture_fatal("could not identify fresh hardlink representative");
    const char *member_name = strcmp(representative_name, "first") == 0
        ? "second" : "first";

    PortableRootSpec root = root_spec("HL", source_path, "HL");
    PortableCaptureRequest request = request_for(&root, "f125");
    request.case_sensitive = 1;
    int container_fd = create_container(container_path);
    check(container_fd >= 0, "fresh hardlink fixture has an empty container");
    if (container_fd < 0)
        return;

    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_PAYLOAD_REPLACE) == 0,
          "fresh hardlink capture is killed after representative creation");
    check(payload_directory(container_path, "data/HL") &&
              resume_claim_state(container_fd, 0, 2, 2),
          "fresh hardlink interruption leaves directory and representative CLAIMs");

    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "fresh hardlink capture resumes from its CLAIMs");

    char representative_payload[PATH_MAX];
    join_path(representative_payload, sizeof(representative_payload),
              container_path, "data/HL");
    char member_payload_root[PATH_MAX];
    join_path(member_payload_root, sizeof(member_payload_root),
              representative_payload, member_name);
    char representative_payload_path[PATH_MAX];
    join_path(representative_payload_path, sizeof(representative_payload_path),
              representative_payload, representative_name);

    struct stat source_first_stat;
    struct stat source_second_stat;
    struct stat representative_stat;
    struct stat member_stat;
    int payloads_ok = stat(first_path, &source_first_stat) == 0 &&
                      stat(second_path, &source_second_stat) == 0 &&
                      stat(representative_payload_path, &representative_stat) == 0 &&
                      stat(member_payload_root, &member_stat) == 0 &&
                      file_equals(first_path, "fresh-hardlink") &&
                      file_equals(second_path, "fresh-hardlink") &&
                      source_first_stat.st_ino == source_second_stat.st_ino &&
                      S_ISREG(representative_stat.st_mode) &&
                      S_ISREG(member_stat.st_mode) && member_stat.st_size == 0;

    SidecarLog log = {0};
    int sidecar_open = sidecar_log_adopt_at(container_fd, &log) ==
                       SIDECAR_OPEN_RESUMABLE;
    int sidecar_ok = sidecar_open;
    SidecarLiveView root_view = {0};
    SidecarLiveView representative_view = {0};
    SidecarLiveView member_view = {0};
    if (sidecar_ok)
        sidecar_ok = sidecar_log_find(&log, resume_bytes("HL"),
                                      resume_bytes(""), &root_view) == 1 &&
                     sidecar_log_find(&log, resume_bytes("HL"),
                                      resume_bytes(representative_name),
                                      &representative_view) == 1 &&
                     sidecar_log_find(&log, resume_bytes("HL"),
                                      resume_bytes(member_name), &member_view) == 1 &&
                     root_view.entry->kind == SIDECAR_KIND_DIRECTORY &&
                     representative_view.entry->kind == SIDECAR_KIND_REGULAR &&
                     member_view.entry->kind == SIDECAR_KIND_HARDLINK &&
                     resume_bytes_match_text(member_view.entry->hardlink_root_id,
                                             "HL") &&
                     resume_bytes_equal(member_view.entry->hardlink_logical_path,
                                        representative_view.entry->logical_path);
    if (sidecar_open && sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        sidecar_ok = 0;
    check(payloads_ok && sidecar_ok &&
              resume_claim_state(container_fd, 3, 0, 3),
          "fresh hardlink resume preserves the assigned representative and consumes CLAIMs");
    close(container_fd);
}

static void test_fresh_directory_case(const char *base, const char *label,
                                      int nested)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    if (sigkill_fixture_paths(base, label, source_path, sizeof(source_path),
                              container_path, sizeof(container_path)) != 0)
        fixture_fatal("fresh directory fixture path is too long");
    make_directory(source_path);
    char nested_path[PATH_MAX];
    char nested_file[PATH_MAX];
    if (nested) {
        join_path(nested_path, sizeof(nested_path), source_path, "nested");
        make_directory(nested_path);
        join_path(nested_file, sizeof(nested_file), nested_path, "file");
        write_file(nested_file, "nested-directory");
    }

    PortableRootSpec root = root_spec("DIR", source_path, "DIR");
    PortableCaptureRequest request = request_for(&root, "f126");
    int container_fd = create_container(container_path);
    const char *kind = nested ? "nested" : "empty";
    char label_buffer[160];
    snprintf(label_buffer, sizeof(label_buffer),
             "fresh %s directory fixture has an empty container", kind);
    check(container_fd >= 0, label_buffer);
    if (container_fd < 0)
        return;

    check(run_fresh_sidecar_interrupt(container_fd, &request,
                                      PORTABLE_TEST_INTERRUPT_NONE,
                                      SIDECAR_TEST_BEFORE_ENTRY) == 0,
          nested ? "nested directory capture is killed before its first ENTRY"
                 : "empty directory capture is killed before its ENTRY");
    size_t expected_claims = nested ? 3 : 1;
    check(payload_directory(container_path, "data/DIR") &&
              resume_claim_state(container_fd, 0, expected_claims,
                                 expected_claims),
          nested ? "nested directory interruption leaves exact outstanding CLAIMs"
                 : "empty directory interruption leaves its exact outstanding CLAIM");

    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          nested ? "nested directory capture resumes from its CLAIMs"
                 : "empty directory capture resumes from its CLAIM");

    int payload_ok = payload_directory(container_path, "data/DIR");
    int sidecar_ok = 0;
    if (nested) {
        payload_ok = payload_ok &&
                     payload_directory(container_path, "data/DIR/nested");
        char payload_file[PATH_MAX];
        join_path(payload_file, sizeof(payload_file), container_path,
                  "data/DIR/nested/file");
        payload_ok = payload_ok && file_equals(payload_file,
                                               "nested-directory");
    }

    SidecarLog log = {0};
    int sidecar_open = sidecar_log_adopt_at(container_fd, &log) ==
                       SIDECAR_OPEN_RESUMABLE;
    if (sidecar_open) {
        SidecarLiveView root_view = {0};
        sidecar_ok = sidecar_log_find(&log, resume_bytes("DIR"),
                                      resume_bytes(""), &root_view) == 1 &&
                     root_view.entry->kind == SIDECAR_KIND_DIRECTORY;
        if (nested) {
            SidecarLiveView nested_view = {0};
            SidecarLiveView file_view = {0};
            sidecar_ok = sidecar_ok &&
                         sidecar_log_find(&log, resume_bytes("DIR"),
                                          resume_bytes("nested"),
                                          &nested_view) == 1 &&
                         sidecar_log_find(&log, resume_bytes("DIR"),
                                          resume_bytes("nested/file"),
                                          &file_view) == 1 &&
                         nested_view.entry->kind == SIDECAR_KIND_DIRECTORY &&
                         file_view.entry->kind == SIDECAR_KIND_REGULAR;
        }
        if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
            sidecar_ok = 0;
    }
    char recovery_label[160];
    snprintf(recovery_label, sizeof(recovery_label),
             "resumed %s directory has payload and exact live entries", kind);
    check(payload_ok && sidecar_ok &&
              resume_claim_state(container_fd, nested ? 3 : 1, 0,
                                 expected_claims),
          recovery_label);
    close(container_fd);
}

static void test_repeated_fresh_claim_resume(const char *base)
{
    printf(BLUE "::" NC " repeated fresh CLAIM interruption and resume\n");
    char source_dir[PATH_MAX];
    char source_file[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_dir, sizeof(source_dir), base,
              "fresh-repeated-source");
    join_path(container_path, sizeof(container_path), base,
              "fresh-repeated-container");
    make_directory(source_dir);
    join_path(source_file, sizeof(source_file), source_dir, "file");
    write_file(source_file, "fresh-repeated");

    PortableRootSpec root = root_spec("REPEAT", source_file, "REPEAT");
    PortableCaptureRequest request = request_for(&root, "f127");
    int container_fd = create_container(container_path);
    check(container_fd >= 0, "repeated CLAIM fixture has an empty container");
    if (container_fd < 0)
        return;

    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_PAYLOAD_REPLACE) == 0,
          "first interruption uses the after-payload-replace boundary");
    check(run_resume_interrupt(container_fd, &request,
                               PORTABLE_TEST_AFTER_PAYLOAD_WRITE,
                               SIDECAR_TEST_INTERRUPT_NONE) == 0,
          "second interruption uses the after-payload-write boundary");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(resume_claim_state(container_fd, 0, 1, 1),
          "repeated interruption retains one CLAIM without a duplicate");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0 &&
              file_equals(source_file, "fresh-repeated") &&
              payload_regular_size(container_path, "data/REPEAT", 14) &&
              resume_claim_state(container_fd, 1, 0, 1),
          "final resume consumes the reused CLAIM exactly once");
    close(container_fd);
}

static int prepare_foreign_destination(const char *base, const char *label,
                                       char *source_file,
                                       size_t source_file_size,
                                       char *container_path,
                                       size_t container_path_size,
                                       PortableRootSpec *root,
                                       PortableCaptureRequest *request,
                                       int mismatching_claim)
{
    char source_path[PATH_MAX];
    if (sigkill_fixture_paths(base, label, source_path, sizeof(source_path),
                              container_path, container_path_size) != 0)
        return -1;
    make_directory(source_path);
    join_path(source_file, source_file_size, source_path, "file");
    write_file(source_file, "source-content");
    *root = root_spec("FOREIGN", source_file, "FOREIGN");
    *request = request_for(root, "f128");

    int container_fd = create_container(container_path);
    if (container_fd < 0 ||
        run_fresh_interrupt(container_fd, request,
                            PORTABLE_TEST_AFTER_MANIFEST) != 0) {
        if (container_fd >= 0)
            close(container_fd);
        return -1;
    }
    if (mkdirat(container_fd, "data", 0700) != 0)
        fixture_fatal("could not create foreign data directory");
    char foreign_payload[PATH_MAX];
    join_path(foreign_payload, sizeof(foreign_payload), container_path,
              "data/FOREIGN");
    write_file(foreign_payload, "foreign-payload");

    SidecarLog log = {0};
    if (sidecar_log_create_at(container_fd, &log) != SIDECAR_OPEN_FRESH) {
        close(container_fd);
        return -1;
    }
    if (mismatching_claim) {
        SidecarClaim claim = {
            .root_id = resume_bytes("FOREIGN"),
            .logical_path = resume_bytes(""),
            .physical_path = resume_bytes("wrong-physical"),
            .kind = SIDECAR_KIND_REGULAR
        };
        if (sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK) {
            (void)sidecar_log_close(&log);
            close(container_fd);
            return -1;
        }
    }
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK) {
        close(container_fd);
        return -1;
    }
    return container_fd;
}

static void test_foreign_destination_claim_refusal(const char *base)
{
    printf(BLUE "::" NC " foreign destination and mismatching CLAIM refusal\n");
    char source_file[PATH_MAX];
    char container_path[PATH_MAX];
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd = prepare_foreign_destination(
        base, "fresh-foreign-no-claim", source_file, sizeof(source_file),
        container_path, sizeof(container_path), &root, &request, 0);
    check(container_fd >= 0,
          "foreign-node fixture has a valid sidecar and no CLAIM");
    if (container_fd >= 0) {
        check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
              "a foreign destination is rejected without a CLAIM");
        char payload_path[PATH_MAX];
        join_path(payload_path, sizeof(payload_path), container_path,
                  "data/FOREIGN");
        check(file_equals(payload_path, "foreign-payload") &&
                  resume_claim_state(container_fd, 0, 0, 0),
              "no-claim refusal leaves the foreign payload untouched");
        close(container_fd);
    }

    container_fd = prepare_foreign_destination(
        base, "fresh-foreign-mismatch", source_file, sizeof(source_file),
        container_path, sizeof(container_path), &root, &request, 1);
    check(container_fd >= 0,
          "mismatching-CLAIM fixture has a valid outstanding claim");
    if (container_fd >= 0) {
        check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
              "a mismatching CLAIM does not authorize a foreign destination");
        char payload_path[PATH_MAX];
        join_path(payload_path, sizeof(payload_path), container_path,
                  "data/FOREIGN");
        check(file_equals(payload_path, "foreign-payload") &&
                  resume_claim_state(container_fd, 0, 1, 1),
              "mismatching-CLAIM refusal leaves payload and CLAIM intact");
        close(container_fd);
    }
}

static const SigkillCase regular_sigkill_cases[] = {
    { "delete-before", PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "delete-after", PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-replace-before", PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-replace-after", PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-write-before", PORTABLE_TEST_BEFORE_PAYLOAD_WRITE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-write-after", PORTABLE_TEST_AFTER_PAYLOAD_WRITE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-close-before", PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-close-after", PORTABLE_TEST_AFTER_PAYLOAD_CLOSE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "entry-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY, 0 },
    { "xattr-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_XATTR, 1 },
    { "commit-before", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_BEFORE_ENTRY_COMMIT, 0 },
    { "commit-after", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_AFTER_ENTRY_COMMIT, 0 },
    { "commit-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY_COMMIT, 0 }
};

static const SigkillCase symlink_sigkill_cases[] = {
    { "delete-before", PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "delete-after", PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-replace-before", PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-replace-after", PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "entry-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY, 0 },
    { "xattr-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_XATTR, 1 },
    { "commit-before", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_BEFORE_ENTRY_COMMIT, 0 },
    { "commit-after", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_AFTER_ENTRY_COMMIT, 0 },
    { "commit-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY_COMMIT, 0 }
};

static const SigkillCase directory_sigkill_cases[] = {
    { "entry-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY, 0 },
    { "xattr-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_XATTR, 1 },
    { "commit-before", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_BEFORE_ENTRY_COMMIT, 0 },
    { "commit-after", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_AFTER_ENTRY_COMMIT, 0 },
    { "commit-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY_COMMIT, 0 }
};

static const SigkillCase hardlink_sigkill_cases[] = {
    { "delete-before", PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "delete-after", PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-replace-before", PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "payload-replace-after", PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
      SIDECAR_TEST_INTERRUPT_NONE, 0 },
    { "entry-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY, 0 },
    { "commit-before", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_BEFORE_ENTRY_COMMIT, 0 },
    { "commit-after", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_AFTER_ENTRY_COMMIT, 0 },
    { "commit-middle", PORTABLE_TEST_INTERRUPT_NONE,
      SIDECAR_TEST_MID_ENTRY_COMMIT, 0 }
};

static void run_sigkill_boundaries(const char *base,
                                   const SigkillKind *kind)
{
    printf(BLUE "::" NC " %s\n", kind->heading);
    int xattr_available = kind->xattr_available == NULL ||
                          kind->xattr_available() != 0;
    for (size_t index = 0; index < kind->case_count; index++) {
        const SigkillCase *test_case = &kind->cases[index];
        if (test_case->requires_xattr && !xattr_available) {
            skip_check(kind->xattr_skip_label);
            continue;
        }

        SigkillFixture fixture = { .container_fd = -1 };
        char label[NAME_MAX];
        int length = snprintf(label, sizeof(label), "%s%s",
                              kind->label_prefix, test_case->label);
        if (length < 0 || (size_t)length >= sizeof(label))
            fixture_fatal("interruption label is too long");
        int prepared = kind->prepare(base, label, &fixture);
        check(prepared == 0, kind->predecessor_label);
        if (prepared != 0 || fixture.container_fd < 0) {
            sigkill_fixture_close(&fixture);
            continue;
        }
        if (kind->mutate != NULL && kind->mutate(&fixture) != 0)
            fixture_fatal("could not mutate interruption fixture");
        if (test_case->requires_xattr) {
            int result;
            if (kind->xattr_mode == SIGKILL_XATTR_NOFOLLOW)
                result = lsetxattr(fixture.capture_path, kind->xattr_name,
                                   kind->xattr_value,
                                   strlen(kind->xattr_value), 0);
            else
                result = setxattr(fixture.capture_path, kind->xattr_name,
                                  kind->xattr_value,
                                  strlen(kind->xattr_value), 0);
            if (result != 0)
                fixture_fatal("could not create xattr interruption fixture");
        }

        int killed = run_resume_interrupt(fixture.container_fd,
                                          &fixture.request,
                                          test_case->portable_point,
                                          test_case->sidecar_point);
        check(killed == 0, test_case->label);
        portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
        sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
        int resumed = portable_capture_resume_at(fixture.container_fd,
                                                  &fixture.request, NULL);
        check(resumed == 0,
              kind->resumable_label);
        check(kind->validate(&fixture), kind->recovery_label);
        if (test_case->requires_xattr && kind->xattr_check_label != NULL) {
            const char *const names[1] = { kind->xattr_name };
            const char *const values[1] = { kind->xattr_value };
            check(live_xattr_set_exact(fixture.container_fd,
                                       kind->xattr_root_id, "", names, values,
                                       1),
                  kind->xattr_check_label);
        }
        sigkill_fixture_close(&fixture);
    }
}

static const SigkillKind regular_sigkill_kind = {
    .heading = "SIGKILL interruption boundaries",
    .label_prefix = "interrupt-",
    .predecessor_label = "interruption fixture has a committed predecessor",
    .resumable_label = "a killed capture remains resumable",
    .recovery_label = "source remains intact after interruption recovery",
    .xattr_skip_label = "xattr interruption fixture unavailable on this filesystem",
    .xattr_check_label = "xattr set is exact after a mid-XATTR SIGKILL: "
                         "the half-written record did not survive and the "
                         "completed record is present",
    .xattr_root_id = "ROOT",
    .xattr_name = "user.migr_resume",
    .xattr_value = "value",
    .xattr_mode = SIGKILL_XATTR_FOLLOW,
    .prepare = prepare_regular_sigkill,
    .mutate = mutate_regular_sigkill,
    .validate = regular_sigkill_recovered,
    .xattr_available = regular_xattr_fixture_available,
    .cases = regular_sigkill_cases,
    .case_count = sizeof(regular_sigkill_cases) / sizeof(regular_sigkill_cases[0])
};

static const SigkillKind symlink_sigkill_kind = {
    .heading = "symlink SIGKILL interruption boundaries",
    .label_prefix = "symlink-interrupt-",
    .predecessor_label = "symlink interruption fixture has a committed predecessor",
    .resumable_label = "a killed symlink capture remains resumable",
    .recovery_label = "resumed symlink capture has the target and placeholder",
    .xattr_skip_label = "symlink xattr interruption fixture unavailable",
    .xattr_root_id = "LINK",
    .xattr_name = "user.migr_symlink_resume",
    .xattr_value = "value",
    .xattr_mode = SIGKILL_XATTR_NOFOLLOW,
    .prepare = prepare_symlink_sigkill,
    .mutate = mutate_symlink_sigkill,
    .validate = symlink_sigkill_recovered,
    .xattr_available = symlink_xattr_fixture_available,
    .cases = symlink_sigkill_cases,
    .case_count = sizeof(symlink_sigkill_cases) / sizeof(symlink_sigkill_cases[0])
};

static const SigkillKind directory_sigkill_kind = {
    .heading = "directory SIGKILL interruption boundaries",
    .label_prefix = "directory-interrupt-",
    .predecessor_label = "directory interruption fixture has a committed predecessor",
    .resumable_label = "a killed directory capture remains resumable",
    .recovery_label = "resumed directory has its payload and metadata entry",
    .xattr_skip_label = "directory xattr interruption fixture unavailable",
    .xattr_check_label = "directory xattr set is exact after a mid-XATTR SIGKILL",
    .xattr_root_id = "DIR",
    .xattr_name = "user.migr_directory_resume",
    .xattr_value = "value",
    .xattr_mode = SIGKILL_XATTR_FOLLOW,
    .prepare = prepare_directory_sigkill,
    .mutate = mutate_directory_sigkill,
    .validate = directory_sigkill_recovered,
    .xattr_available = directory_xattr_fixture_available,
    .cases = directory_sigkill_cases,
    .case_count = sizeof(directory_sigkill_cases) / sizeof(directory_sigkill_cases[0])
};

static const SigkillKind hardlink_sigkill_kind = {
    .heading = "hardlink SIGKILL interruption boundaries",
    .label_prefix = "hardlink-interrupt-",
    .predecessor_label = "hardlink interruption fixture has a committed predecessor",
    .resumable_label = "a killed hardlink capture remains resumable",
    .recovery_label = "resumed hardlink group has one REGULAR and one HARDLINK payload",
    .xattr_mode = SIGKILL_XATTR_NONE,
    .prepare = prepare_hardlink_sigkill,
    .mutate = mutate_hardlink_sigkill,
    .validate = hardlink_sigkill_recovered,
    .cases = hardlink_sigkill_cases,
    .case_count = sizeof(hardlink_sigkill_cases) / sizeof(hardlink_sigkill_cases[0])
};

static void test_sigkill_boundaries(const char *base)
{
    run_sigkill_boundaries(base, &regular_sigkill_kind);
}

static int symlink_xattr_fixture_available(void)
{
    char base[] = "/tmp/migr_portable_resume_symlink_xattr_XXXXXX";
    if (mkdtemp(base) == NULL)
        return 0;
    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), base, "link");
    int available = symlink("target", link_path) == 0;
    if (available && lsetxattr(link_path, "user.migr_symlink_resume", "x", 1,
                               0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM)
            available = 0;
        else
            fixture_fatal("could not probe symlink xattr support");
    }
    if (unlink(link_path) != 0 || rmdir(base) != 0)
        fixture_fatal("could not remove symlink xattr probe");
    return available;
}

static void test_stale_xattr_interruption(const char *base)
{
    printf(BLUE "::" NC " stale xattr does not survive a mid-XATTR SIGKILL\n");
    if (!regular_xattr_fixture_available())
    {
        skip_check("xattr interruption fixture unavailable on this filesystem");
        return;
    }

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "stale-xattr-source");
    join_path(container_path, sizeof(container_path), base,
              "stale-xattr-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "content");
    if (setxattr(source_file, "user.migr_stale", "old", 3, 0) != 0)
        fixture_fatal("could not plant the stale xattr fixture");

    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "c2");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "predecessor is committed with the stale xattr");
    if (container_fd < 0)
        return;

    /* Replace the source's xattr set: the stale attribute is removed and a
     * fresh one added, so the interrupted run still has an XATTR record to
     * write (SIDECAR_TEST_MID_XATTR only fires while one is being written). */
    if (removexattr(source_file, "user.migr_stale") != 0 ||
        setxattr(source_file, "user.migr_fresh", "new", 3, 0) != 0)
        fixture_fatal("could not switch the source xattr set");

    check(run_resume_interrupt(container_fd, &request,
                               PORTABLE_TEST_INTERRUPT_NONE,
                               SIDECAR_TEST_MID_XATTR) == 0,
          "resume is killed mid-XATTR-record");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "interrupted resume recovers");

    const char *const names[1] = { "user.migr_fresh" };
    const char *const values[1] = { "new" };
    check(live_xattr_set_exact(container_fd, "ROOT", "",
                               names, values, 1),
          "live set is exactly the fresh attribute after recovery "
          "(stale attribute gone, no partial leftover)");
    close(container_fd);
}

static void test_symlink_sigkill_boundaries(const char *base)
{
    run_sigkill_boundaries(base, &symlink_sigkill_kind);
}

static void test_directory_sigkill_boundaries(const char *base)
{
    run_sigkill_boundaries(base, &directory_sigkill_kind);
}

static void test_hardlink_sigkill_boundaries(const char *base)
{
    run_sigkill_boundaries(base, &hardlink_sigkill_kind);
}

static void test_identity_mismatch(const char *base)
{
    printf(BLUE "::" NC " resume identity gate\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "identity-source");
    join_path(container_path, sizeof(container_path), base,
              "identity-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "identity");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "c1");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "identity fixture is captured");
    if (container_fd < 0)
        return;
    PortableCaptureRequest mismatch = request_for(&root, "c2");
    check(portable_capture_resume_at(container_fd, &mismatch, NULL) != 0,
          "a different source identity cannot adopt the partial");
    close(container_fd);
}

int main(void)
{
    printf(BLUE "::" NC " portable resume and interruption tests\n");
    char base[] = "/tmp/migr_portable_resume_XXXXXX";
    if (mkdtemp(base) == NULL)
        fixture_fatal("could not create fixture root");

    test_collision_suffix_resume_key();
    test_case_alias_claim_determinism(base);
    test_hardlink_representative_transition_determinism(base);
    test_resume_skips_and_replaces(base);
    test_resume_xattr_equivalence(base);
    test_encoded_resume(base);
    test_symlink_resume(base);
    test_missing_sidecar(base);
    test_nonempty_without_sidecar(base);
    test_unsafe_sidecar(base);
    test_truncated_tail(base);
    test_zero_claim_gate(base);
    test_claim_kind_changes(base);
    test_repeated_claim_kind_change_interrupt(base);
    test_fresh_regular_claim_resume(base);
    test_fresh_symlink_claim_resume(base);
    test_fresh_hardlink_claim_resume(base);
    test_fresh_directory_case(base, "fresh-directory-empty", 0);
    test_fresh_directory_case(base, "fresh-directory-nested", 1);
    test_repeated_fresh_claim_resume(base);
    test_foreign_destination_claim_refusal(base);
    test_sigkill_boundaries(base);
    test_stale_xattr_interruption(base);
    test_symlink_sigkill_boundaries(base);
    test_directory_sigkill_boundaries(base);
    test_hardlink_sigkill_boundaries(base);
    test_identity_mismatch(base);

    remove_tree(base);
    printf("portable resume tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
