// Scale test for portable stale-entry reconciliation (docs/DECISIONS.md
// D17): proof that the committed-live-key vs visited-set diff and the
// final inventory walk stay sub-quadratic at the SIDECAR_MAX_LIVE_ENTRIES
// scale, not just correct at the small fixture counts
// tests/test_portable_reconcile.c exercises.
//
// A 50,000-entry fixture is captured fresh, then half its keys are deleted
// from the source and the capture is resumed; reconciliation must remove
// 25,000 stale entries. The assertion is on probe count (visited-set +
// state-map probes combined) rather than wall-clock time, so the test stays
// deterministic across machines and load: the same pattern as
// tests/test_sidecar_scale.c and tests/test_portable_capture_scale.c, with
// the PORTABLE_CAPTURE_TEST_HOOKS / SIDECAR_STATE_TEST_HOOKS seams (D14).
// Linear work would cost O(n) probes total; quadratic work would exceed the
// asserted bound by orders of magnitude.

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

#include "portable.h"
#include "sidecar.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define SCALE_ENTRY_COUNT 50000U

extern uint64_t portable_capture_test_probe_count(void);
extern void portable_capture_test_reset_probe_count(void);
extern uint64_t sidecar_state_test_probe_count(void);
extern void sidecar_state_test_reset_probe_count(void);

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
    fprintf(stderr, "portable reconciliation scale fixture failure: %s\n",
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
        fixture_fatal("could not remove scale fixture tree");
    return 0;
}

static void remove_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not inspect scale fixture tree");
    }
    if (nftw(path, remove_callback_fatal, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fixture_fatal("could not walk scale fixture tree");
}

static int make_fixture_file(int source_fd, unsigned int index)
{
    char name[32];
    int length = snprintf(name, sizeof(name), "entry-%05u", index);
    if (length < 0 || (size_t)length >= sizeof(name))
        return -1;
    int fd = openat(source_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    return close(fd);
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

int main(void)
{
    printf(BLUE "::" NC " portable reconciliation hash scale\n");
    char fixture[] = "/tmp/migr_portable_reconcile_scale_XXXXXX";
    if (mkdtemp(fixture) == NULL)
        fixture_fatal("could not create scale fixture root");

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int source_length = snprintf(source_path, sizeof(source_path),
                                 "%s/source", fixture);
    int container_length = snprintf(container_path, sizeof(container_path),
                                    "%s/container", fixture);
    if (source_length < 0 || container_length < 0 ||
        (size_t)source_length >= sizeof(source_path) ||
        (size_t)container_length >= sizeof(container_path))
        fixture_fatal("scale fixture path is too long");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create scale fixture directories");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open scale fixture directories");
    for (unsigned int index = 0; index < SCALE_ENTRY_COUNT; index++)
        if (make_fixture_file(source_fd, index) != 0)
            fixture_fatal("could not create scale fixture file");

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "b3c0",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    check(portable_capture_fresh_at(container_fd, &request) == 0,
          "50,000-entry fixture captures successfully");

    for (unsigned int index = 0; index < SCALE_ENTRY_COUNT / 2U; index++) {
        char name[32];
        int length = snprintf(name, sizeof(name), "entry-%05u", index);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            unlinkat(source_fd, name, 0) != 0)
            fixture_fatal("could not remove scale source entries");
    }

    portable_capture_test_reset_probe_count();
    sidecar_state_test_reset_probe_count();
    check(portable_capture_resume_at(container_fd, &request) == 0,
          "resume reconciles 25,000 stale entries");
    uint64_t visited_probes = portable_capture_test_probe_count();
    uint64_t map_probes = sidecar_state_test_probe_count();
    uint64_t entries = (uint64_t)SCALE_ENTRY_COUNT + 1U;
    uint64_t probes = visited_probes + map_probes;
    printf("  visited_probes=%" PRIu64 " map_probes=%" PRIu64
           " total=%" PRIu64 " entries=%" PRIu64 "\n",
           visited_probes, map_probes, probes, entries);
    check(probes <= entries * UINT64_C(256),
          "reconciliation probes remain bounded linearly");
    check(probes < (entries * entries) / UINT64_C(1000),
          "reconciliation probes remain far below quadratic work");

    close(source_fd);
    close(container_fd);
    remove_tree(fixture);
    printf("portable reconciliation scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
