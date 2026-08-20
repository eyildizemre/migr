// Unit tests for portable stale-entry reconciliation and the finalization
// gate (docs/DECISIONS.md D17), the third and final step of the
// portable capture core: after a full successful root walk, the previous
// run's committed live-key set is diffed against the keys visited this run,
// and every stale key is DELETE-committed in the sidecar and its physical
// payload removed fd-anchored, never following symlinks. A cleanup or
// final-inventory failure blocks finalization outright; a stale file must
// never survive in the final backup.
//
// Coverage: a file deleted from the source between two runs of a resumed
// capture does not survive in the final backup; a deleted subtree (directory
// and payload) is removed; an unlink/rmdir failure (payload made
// undeletable) blocks finalization; the final live-state/payload inventory
// consistency check catches a planted-payload mismatch and fails; and real
// SIGKILL fixtures (child processes, not synthetic stand-ins, sharing the
// fork+kill harness with tests/test_portable_resume.c) cover the new
// reconciliation interruption boundaries -- after the stale DELETE, before
// and after the stale payload unlink, and before the final inventory check.
// Each interrupted state must remain deterministically resumable, and the
// resumed reconciliation must complete to the expected payload inventory.
//
// The inventory consistency walk runs a full sidecar_foreach live-pass plus
// an fd-anchored payload scan, so these tests also exercise the
// sidecar_log_foreach() / sidecar_log_find_deleted() state-log entry points
// added for this step against real fixtures, not just unit-level synthetic
// keys.

#define _GNU_SOURCE

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

typedef struct {
    size_t count;
    int valid;
    uint64_t expected_generation;
} ClaimForeachResult;

static int claim_foreach_callback(const SidecarClaimView *view, void *argument)
{
    ClaimForeachResult *result = argument;
    if (result == NULL || view == NULL || view->claim == NULL)
        return 1;
    result->count++;
    if (view->claim->root_id.length != 4U ||
        memcmp(view->claim->root_id.data, "ITER", 4) != 0 ||
        view->claim->logical_path.length != 5U ||
        memcmp(view->claim->logical_path.data, "claim", 5) != 0 ||
        view->claim->physical_path.length != 13U ||
        memcmp(view->claim->physical_path.data, "payload/claim", 13) != 0 ||
        view->claim->kind != SIDECAR_KIND_REGULAR ||
        view->generation != result->expected_generation)
        result->valid = 0;
    return 0;
}

static void skip_check(const char *label)
{
    printf("  " YELLOW "-" NC " %s\n", label);
    skips++;
}

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "portable reconciliation fixture failure: %s\n", message);
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

static int path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int path_missing(const char *path)
{
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}

typedef struct {
    char source[PATH_MAX];
    char container[PATH_MAX];
    char payload_root[PATH_MAX];
    char payload_gone[PATH_MAX];
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd;
} Fixture;

typedef struct {
    char source[PATH_MAX];
    char container[PATH_MAX];
    char payload_claimed[PATH_MAX];
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd;
} ClaimDirectoryFixture;

static int prepare_fixture(const char *base, const char *label,
                           Fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->container_fd = -1;
    int source_length = snprintf(fixture->source, sizeof(fixture->source),
                                 "%s/%s-source", base, label);
    int container_length = snprintf(fixture->container,
                                    sizeof(fixture->container), "%s/%s-container",
                                    base, label);
    if (source_length < 0 || container_length < 0 ||
        (size_t)source_length >= sizeof(fixture->source) ||
        (size_t)container_length >= sizeof(fixture->container))
        return -1;
    make_directory(fixture->source);
    make_directory(fixture->container);

    char keep[PATH_MAX];
    char gone[PATH_MAX];
    join_path(keep, sizeof(keep), fixture->source, "keep");
    join_path(gone, sizeof(gone), fixture->source, "gone");
    write_file(keep, "keep");
    write_file(gone, "gone");

    join_path(fixture->payload_root, sizeof(fixture->payload_root),
              fixture->container, "data/ROOT");
    join_path(fixture->payload_gone, sizeof(fixture->payload_gone),
              fixture->payload_root, "gone");
    fixture->root = (PortableRootSpec){
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = fixture->source,
        .payload_path = "ROOT",
        .source_path = fixture->source,
        .restore_path = "fixture",
        .has_restore_path = 1
    };
    fixture->request = (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "b3c0",
        .source_uid = getuid(),
        .roots = &fixture->root,
        .root_count = 1,
        .nsec_exact = 1
    };
    fixture->container_fd = open(fixture->container,
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->container_fd < 0)
        return -1;
    int result = portable_capture_fresh_at(fixture->container_fd,
                                           &fixture->request, NULL);
    if (result != 0) {
        close(fixture->container_fd);
        fixture->container_fd = -1;
        return -1;
    }
    return 0;
}

static void close_fixture(Fixture *fixture)
{
    if (fixture != NULL && fixture->container_fd >= 0) {
        close(fixture->container_fd);
        fixture->container_fd = -1;
    }
}

static int prepare_claim_directory_fixture(const char *base,
                                           const char *label, int nested,
                                           ClaimDirectoryFixture *fixture)
{
    if (base == NULL || label == NULL || fixture == NULL)
        return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->container_fd = -1;
    int source_length = snprintf(fixture->source, sizeof(fixture->source),
                                 "%s/%s-source", base, label);
    int container_length = snprintf(fixture->container,
                                    sizeof(fixture->container),
                                    "%s/%s-container", base, label);
    if (source_length < 0 || container_length < 0 ||
        (size_t)source_length >= sizeof(fixture->source) ||
        (size_t)container_length >= sizeof(fixture->container))
        return -1;
    make_directory(fixture->source);
    make_directory(fixture->container);

    char keep[PATH_MAX];
    char claimed[PATH_MAX];
    join_path(keep, sizeof(keep), fixture->source, "keep");
    join_path(claimed, sizeof(claimed), fixture->source, "claimed");
    write_file(keep, "keep");
    make_directory(claimed);
    if (nested) {
        char child[PATH_MAX];
        join_path(child, sizeof(child), claimed, "child");
        write_file(child, "child");
    }

    fixture->root = (PortableRootSpec){
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = fixture->source,
        .payload_path = "ROOT",
        .source_path = fixture->source,
        .restore_path = "fixture",
        .has_restore_path = 1
    };
    fixture->request = (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "c7a1",
        .source_uid = getuid(),
        .roots = &fixture->root,
        .root_count = 1,
        .nsec_exact = 1
    };
    fixture->container_fd = open(fixture->container,
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->container_fd < 0)
        return -1;
    if (portable_capture_fresh_at(fixture->container_fd, &fixture->request,
                                  NULL) != 0) {
        close(fixture->container_fd);
        fixture->container_fd = -1;
        return -1;
    }
    join_path(fixture->payload_claimed, sizeof(fixture->payload_claimed),
              fixture->container, "data/ROOT/claimed");
    return 0;
}

static int convert_directory_to_claim(const ClaimDirectoryFixture *fixture)
{
    if (fixture == NULL || fixture->container_fd < 0)
        return -1;
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(fixture->container_fd, &log) !=
        SIDECAR_OPEN_RESUMABLE)
        return -1;
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"claimed", 7 }
    };
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"claimed", 7 },
        .physical_path = { (const unsigned char *)"claimed", 7 },
        .kind = SIDECAR_KIND_DIRECTORY
    };
    int result = sidecar_log_append_delete(&log, &deletion) ==
                     SIDECAR_STATUS_OK &&
                 sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        result = 0;
    return result ? 0 : -1;
}

static int outstanding_claim_count(int container_fd)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        return -1;
    size_t count = sidecar_log_claim_count(&log);
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return -1;
    return count > INT_MAX ? -1 : (int)count;
}

static void test_claim_foreach(const char *base)
{
    printf(BLUE "::" NC " outstanding CLAIM iteration\n");
    Fixture fixture;
    check(prepare_fixture(base, "claim-foreach", &fixture) == 0,
          "claim foreach fixture is captured");
    if (fixture.container_fd < 0)
        return;

    SidecarLog log = {0};
    SidecarClaim first = {
        .root_id = { (const unsigned char *)"ITER", 4 },
        .logical_path = { (const unsigned char *)"gone", 4 },
        .physical_path = { (const unsigned char *)"payload/gone", 12 },
        .kind = SIDECAR_KIND_REGULAR
    };
    SidecarClaim second = {
        .root_id = { (const unsigned char *)"ITER", 4 },
        .logical_path = { (const unsigned char *)"claim", 5 },
        .physical_path = { (const unsigned char *)"payload/claim", 13 },
        .kind = SIDECAR_KIND_REGULAR
    };
    SidecarDelete cancel = {
        .root_id = { (const unsigned char *)"ITER", 4 },
        .logical_path = { (const unsigned char *)"gone", 4 }
    };
    ClaimForeachResult result = { .valid = 1 };
    int setup = sidecar_log_adopt_at(fixture.container_fd, &log) ==
                    SIDECAR_OPEN_RESUMABLE &&
                sidecar_log_append_claim(&log, &first) == SIDECAR_STATUS_OK &&
                sidecar_log_append_claim(&log, &second) == SIDECAR_STATUS_OK &&
                sidecar_log_append_delete(&log, &cancel) == SIDECAR_STATUS_OK;
    SidecarClaimView surviving = {0};
    if (setup && sidecar_log_find_claim(
                     &log,
                     (SidecarBytes){ (const unsigned char *)"ITER", 4 },
                     (SidecarBytes){ (const unsigned char *)"claim", 5 },
                     &surviving) == 1)
        result.expected_generation = surviving.generation;
    int iterated = setup && result.expected_generation != 0U &&
                   sidecar_log_claim_foreach(&log, claim_foreach_callback,
                                             &result) == SIDECAR_STATUS_OK;
    check(iterated && result.count == 1U && result.valid &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "claim iteration visits only the outstanding claim with its generation");
    close_fixture(&fixture);
}

static int sidecar_state(const Fixture *fixture, const char *logical,
                         int *live, int *deleted)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(fixture->container_fd, &log) !=
        SIDECAR_OPEN_RESUMABLE)
        return -1;
    SidecarLiveView view;
    int found = sidecar_log_find(
        &log,
        (SidecarBytes){ (const unsigned char *)"ROOT", 4 },
        (SidecarBytes){ (const unsigned char *)logical, strlen(logical) },
        &view);
    int tombstone = sidecar_log_find_deleted(
        &log,
        (SidecarBytes){ (const unsigned char *)"ROOT", 4 },
        (SidecarBytes){ (const unsigned char *)logical, strlen(logical) },
        &view);
    int result = sidecar_log_close(&log) == SIDECAR_STATUS_OK ? 0 : -1;
    if (result == 0) {
        if (live != NULL)
            *live = found;
        if (deleted != NULL)
            *deleted = tombstone;
    }
    return result;
}

static int child_killed(int status)
{
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static int run_resume_interrupt(const Fixture *fixture,
                                PortableTestInterruptPoint point)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        portable_capture_test_set_interrupt(point);
        int result = portable_capture_resume_at(fixture->container_fd,
                                                &fixture->request, NULL);
        _exit(result == 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return child_killed(status) ? 0 : -1;
}

static void reset_interrupts(void)
{
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
}

static void test_deleted_file(const char *base)
{
    printf(BLUE "::" NC " stale file reconciliation\n");
    Fixture fixture;
    check(prepare_fixture(base, "file", &fixture) == 0,
          "initial capture creates a complete file fixture");
    if (fixture.container_fd < 0)
        return;

    char source_gone[PATH_MAX];
    join_path(source_gone, sizeof(source_gone), fixture.source, "gone");
    if (unlink(source_gone) != 0)
        fixture_fatal("could not remove source file");
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) == 0,
          "resume reconciles a source file deleted between runs");
    int live = -1;
    int deleted = -1;
    check(sidecar_state(&fixture, "gone", &live, &deleted) == 0 &&
          live == 0 && deleted == 1,
          "deleted file is non-live with retained deletion provenance");
    check(path_missing(fixture.payload_gone),
          "deleted file payload is removed from the container");
    close_fixture(&fixture);
}

static void test_deleted_symlink(const char *base)
{
    printf(BLUE "::" NC " stale symlink reconciliation\n");
    char source[PATH_MAX];
    char container[PATH_MAX];
    join_path(source, sizeof(source), base, "symlink-source");
    join_path(container, sizeof(container), base, "symlink-container");
    make_directory(source);
    make_directory(container);

    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source, "gone");
    if (symlink("gone-target", link_path) != 0)
        fixture_fatal("could not create stale symlink fixture");

    PortableRootSpec root = {
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "ROOT",
        .source_path = source,
        .restore_path = "fixture",
        .has_restore_path = 1
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "c3c1",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open stale symlink container");
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "initial capture creates a symlink placeholder");

    char payload[PATH_MAX];
    join_path(payload, sizeof(payload), container, "data/ROOT/gone");
    check(path_exists(payload),
          "captured symlink has a payload placeholder before deletion");
    if (unlink(link_path) != 0)
        fixture_fatal("could not remove stale symlink source");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume reconciles a deleted source symlink");
    int live = -1;
    int deleted = -1;
    check(sidecar_state(&(Fixture){ .container_fd = container_fd }, "gone",
                         &live, &deleted) == 0 && live == 0 && deleted == 1,
          "deleted symlink is non-live with retained deletion provenance");
    check(path_missing(payload),
          "deleted symlink placeholder is removed from the container");
    close(container_fd);
}

static void test_deleted_subtree(const char *base)
{
    printf(BLUE "::" NC " stale subtree reconciliation\n");
    char source[PATH_MAX];
    char container[PATH_MAX];
    int source_length = snprintf(source, sizeof(source), "%s/subtree-source",
                                 base);
    int container_length = snprintf(container, sizeof(container),
                                    "%s/subtree-container", base);
    if (source_length < 0 || container_length < 0 ||
        (size_t)source_length >= sizeof(source) ||
        (size_t)container_length >= sizeof(container))
        fixture_fatal("subtree fixture path is too long");
    make_directory(source);
    make_directory(container);
    char subtree[PATH_MAX];
    char child[PATH_MAX];
    join_path(subtree, sizeof(subtree), source, "tree");
    join_path(child, sizeof(child), subtree, "child");
    make_directory(subtree);
    write_file(child, "child");

    PortableRootSpec root = {
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "ROOT",
        .source_path = source,
        .restore_path = "fixture",
        .has_restore_path = 1
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "b3c0",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open subtree container");
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "subtree fixture is captured");
    if (unlink(child) != 0 || rmdir(subtree) != 0)
        fixture_fatal("could not remove source subtree");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume reconciles a deleted source subtree");
    char payload_subtree[PATH_MAX];
    join_path(payload_subtree, sizeof(payload_subtree), container,
              "data/ROOT/tree");
    check(path_missing(payload_subtree),
          "deleted subtree payload is removed recursively");
    int live = -1;
    int deleted = -1;
    check(sidecar_state(&(Fixture){ .container_fd = container_fd }, "tree",
                        &live, &deleted) == 0 && live == 0,
          "deleted subtree directory is no longer live");
    check(sidecar_state(&(Fixture){ .container_fd = container_fd },
                        "tree/child", &live, &deleted) == 0 && live == 0,
          "deleted subtree child is no longer live");
    close(container_fd);
}

static void remove_claimed_source(const ClaimDirectoryFixture *fixture,
                                  int nested)
{
    char source_claimed[PATH_MAX];
    join_path(source_claimed, sizeof(source_claimed), fixture->source,
              "claimed");
    if (nested) {
        char source_child[PATH_MAX];
        join_path(source_child, sizeof(source_child), source_claimed, "child");
        if (unlink(source_child) != 0)
            fixture_fatal("could not remove claimed source child");
    }
    if (rmdir(source_claimed) != 0)
        fixture_fatal("could not remove claimed source directory");
}

static void test_stale_empty_claim(const char *base)
{
    printf(BLUE "::" NC " stale empty CLAIM reconciliation\n");
    ClaimDirectoryFixture fixture;
    check(prepare_claim_directory_fixture(base, "claim-empty", 0,
                                          &fixture) == 0,
          "empty claimed-directory fixture is captured");
    if (fixture.container_fd < 0)
        return;
    check(convert_directory_to_claim(&fixture) == 0,
          "empty directory becomes an outstanding CLAIM");
    remove_claimed_source(&fixture, 0);
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) == 0,
          "resume removes an unvisited empty claimed directory");
    int live = -1;
    int deleted = -1;
    Fixture state = { .container_fd = fixture.container_fd };
    check(path_missing(fixture.payload_claimed) &&
              outstanding_claim_count(fixture.container_fd) == 0 &&
              sidecar_state(&state, "claimed", &live, &deleted) == 0 &&
              live == 0 && deleted == 1,
          "empty CLAIM cleanup leaves zero outstanding claims and a DELETE");
    close(fixture.container_fd);
}

static void test_stale_nested_claim(const char *base)
{
    printf(BLUE "::" NC " nested stale CLAIM reconciliation\n");
    ClaimDirectoryFixture fixture;
    check(prepare_claim_directory_fixture(base, "claim-nested", 1,
                                          &fixture) == 0,
          "nested claimed-directory fixture is captured");
    if (fixture.container_fd < 0)
        return;
    check(convert_directory_to_claim(&fixture) == 0,
          "nested directory becomes a CLAIM while its child stays LIVE");
    remove_claimed_source(&fixture, 1);
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) == 0,
          "resume cleans nested stale LIVE and CLAIM descendants deepest-first");
    char payload_child[PATH_MAX];
    join_path(payload_child, sizeof(payload_child), fixture.payload_claimed,
              "child");
    int live = -1;
    int deleted = -1;
    Fixture state = { .container_fd = fixture.container_fd };
    check(path_missing(fixture.payload_claimed) && path_missing(payload_child) &&
              outstanding_claim_count(fixture.container_fd) == 0 &&
              sidecar_state(&state, "claimed", &live, &deleted) == 0 &&
              live == 0 && deleted == 1 &&
              sidecar_state(&state, "claimed/child", &live, &deleted) == 0 &&
              live == 0 && deleted == 1,
          "nested cleanup removes every payload and leaves no CLAIM");
    close(fixture.container_fd);
}

static void test_foreign_child_blocks_claim_cleanup(const char *base)
{
    printf(BLUE "::" NC " foreign child blocks stale CLAIM cleanup\n");
    ClaimDirectoryFixture fixture;
    check(prepare_claim_directory_fixture(base, "claim-foreign", 0,
                                          &fixture) == 0,
          "foreign-child claimed-directory fixture is captured");
    if (fixture.container_fd < 0)
        return;
    check(convert_directory_to_claim(&fixture) == 0,
          "foreign-child directory becomes an outstanding CLAIM");
    char foreign[PATH_MAX];
    join_path(foreign, sizeof(foreign), fixture.payload_claimed, "foreign");
    write_file(foreign, "foreign");
    remove_claimed_source(&fixture, 0);
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) != 0,
          "foreign child rejects stale CLAIM reconciliation");
    check(path_exists(fixture.payload_claimed) && path_exists(foreign) &&
              outstanding_claim_count(fixture.container_fd) == 1,
          "foreign-child refusal leaves the whole payload and CLAIM intact");
    close(fixture.container_fd);
}

static void test_cleanup_failure(const char *base)
{
    printf(BLUE "::" NC " stale cleanup failure gate\n");
    if (geteuid() == 0) {
        skip_check("permission-based unlink failure requires a non-root user");
        return;
    }
    Fixture fixture;
    check(prepare_fixture(base, "cleanup", &fixture) == 0,
          "cleanup failure fixture is captured");
    if (fixture.container_fd < 0)
        return;
    char source_gone[PATH_MAX];
    join_path(source_gone, sizeof(source_gone), fixture.source, "gone");
    if (unlink(source_gone) != 0 || chmod(fixture.payload_root, 0500) != 0)
        fixture_fatal("could not prepare undeletable payload");
    int result = portable_capture_resume_at(fixture.container_fd,
                                             &fixture.request, NULL);
    check(result != 0, "unlink failure blocks portable finalization");
    check(path_exists(fixture.payload_gone),
          "failed cleanup leaves the payload for a later resume");
    if (chmod(fixture.payload_root, 0700) != 0)
        fixture_fatal("could not restore payload permissions");
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) == 0,
          "later resume retries and completes the cleanup");
    check(path_missing(fixture.payload_gone),
          "retry removes the previously protected payload");
    close_fixture(&fixture);
}

static void test_inventory_mismatch(const char *base)
{
    printf(BLUE "::" NC " final inventory gate\n");
    Fixture fixture;
    check(prepare_fixture(base, "inventory", &fixture) == 0,
          "inventory fixture is captured");
    if (fixture.container_fd < 0)
        return;
    char planted[PATH_MAX];
    join_path(planted, sizeof(planted), fixture.payload_root, "planted");
    write_file(planted, "unexpected");
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) != 0,
          "uncommitted payload blocks finalization");
    check(path_exists(planted),
          "inventory refusal does not delete an unknown payload");
    close_fixture(&fixture);
}

static void test_interrupt_boundary(const char *base,
                                    const char *label,
                                    PortableTestInterruptPoint point,
                                    int delete_source,
                                    int payload_survives)
{
    Fixture fixture;
    check(prepare_fixture(base, label, &fixture) == 0,
          "interruption fixture is captured");
    if (fixture.container_fd < 0)
        return;
    if (delete_source) {
        char source_gone[PATH_MAX];
        join_path(source_gone, sizeof(source_gone), fixture.source, "gone");
        if (unlink(source_gone) != 0)
            fixture_fatal("could not remove stale interruption source");
    }
    check(run_resume_interrupt(&fixture, point) == 0,
          "resume is killed at the requested reconciliation boundary");
    reset_interrupts();
    int live = -1;
    int deleted = -1;
    if (delete_source)
        check(sidecar_state(&fixture, "gone", &live, &deleted) == 0 &&
              live == 0 && deleted == 1,
              "interrupted stale key remains non-live");
    check(path_exists(fixture.payload_gone) == payload_survives,
          "payload state at the interruption boundary is deterministic");
    check(portable_capture_resume_at(fixture.container_fd,
                                     &fixture.request, NULL) == 0,
          "resume completes the interrupted reconciliation");
    check(path_exists(fixture.payload_gone) == !delete_source,
          "resumed reconciliation leaves the expected payload inventory");
    close_fixture(&fixture);
}

static void test_interruption_boundaries(const char *base)
{
    printf(BLUE "::" NC " reconciliation SIGKILL boundaries\n");
    test_interrupt_boundary(base, "after-delete", PORTABLE_TEST_AFTER_STALE_DELETE,
                            1, 1);
    test_interrupt_boundary(base, "before-unlink", PORTABLE_TEST_BEFORE_STALE_UNLINK,
                            1, 1);
    test_interrupt_boundary(base, "after-unlink", PORTABLE_TEST_AFTER_STALE_UNLINK,
                            1, 0);
    test_interrupt_boundary(base, "before-inventory",
                            PORTABLE_TEST_BEFORE_FINAL_INVENTORY, 0, 1);
}

int main(void)
{
    printf(BLUE "::" NC " portable stale reconciliation\n");
    char base[] = "/tmp/migr_portable_reconcile_XXXXXX";
    if (mkdtemp(base) == NULL)
        fixture_fatal("could not create fixture root");

    test_deleted_file(base);
    test_deleted_symlink(base);
    test_deleted_subtree(base);
    test_claim_foreach(base);
    test_stale_empty_claim(base);
    test_stale_nested_claim(base);
    test_foreign_child_blocks_claim_cleanup(base);
    test_cleanup_failure(base);
    test_inventory_mismatch(base);
    test_interruption_boundaries(base);

    remove_tree(base);
    printf("portable reconciliation tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
