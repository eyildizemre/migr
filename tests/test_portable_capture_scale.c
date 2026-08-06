// Scale test for portable capture's in-walk duplicate-key guard
// (docs/DECISIONS.md D17): proof that the salted open-addressing hash set
// replacing its old linear scan is genuinely sub-quadratic. Same reasoning
// and shape as tests/test_sidecar_scale.c for the sidecar's own live-state
// map -- this guard serves a different purpose (catching two source objects
// colliding on the same logical key within a single walk, not cross-run
// resume) but had regressed to the identical O(n) mistake.
//
// 20,000 entries are captured under one directory root; the assertion is on
// probe count via the PORTABLE_CAPTURE_TEST_HOOKS seam (D14: test-only,
// never reachable from a release binary), not wall-clock time, for the same
// determinism reason as the sidecar scale test.

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

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define SCALE_ENTRY_COUNT 20000U

extern uint64_t portable_capture_test_probe_count(void);
extern void portable_capture_test_reset_probe_count(void);
extern uint64_t portable_capture_test_readback_scan_count(void);
extern void portable_capture_test_reset_readback_scan_count(void);

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

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "portable scale fixture failure: %s\n", message);
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
    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not inspect fixture tree");
    }
    if (nftw(path, remove_callback_fatal, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fixture_fatal("could not walk fixture tree");
}

static int make_named_fixture_file(int source_fd, const char *name)
{
    if (name == NULL)
        return -1;
    int fd = openat(source_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    return close(fd);
}

static int make_fixture_file(int source_fd, unsigned int index)
{
    char name[32];
    int length = snprintf(name, sizeof(name), "entry-%05u", index);
    if (length < 0 || (size_t)length >= sizeof(name))
        return -1;
    return make_named_fixture_file(source_fd, name);
}

static PortableRootSpec root_spec(const char *source)
{
    return (PortableRootSpec){
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "ROOT",
        .source_path = "",
        .restore_path = "",
        .has_restore_path = 1
    };
}

int main(void)
{
    printf(BLUE "::" NC " portable visited hash scale\n");
    char fixture[] = "/tmp/migr_portable_capture_scale_XXXXXX";
    if (mkdtemp(fixture) == NULL)
        fixture_fatal("could not create fixture root");

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int source_length = snprintf(source_path, sizeof(source_path), "%s/source",
                                 fixture);
    int container_length = snprintf(container_path, sizeof(container_path),
                                    "%s/container", fixture);
    if (source_length < 0 || container_length < 0 ||
        (size_t)source_length >= sizeof(source_path) ||
        (size_t)container_length >= sizeof(container_path))
        fixture_fatal("fixture path is too long");
    if (mkdir(source_path, 0700) != 0 || mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create fixture directories");

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || container_fd < 0)
        fixture_fatal("could not open fixture directories");
    if (mkdirat(container_fd, "data", 0700) != 0)
        fixture_fatal("could not create data directory");

    for (unsigned int index = 0; index < SCALE_ENTRY_COUNT; index++)
        if (make_fixture_file(source_fd, index) != 0)
            fixture_fatal("could not create scale fixture file");

    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0 ||
        sidecar_log_create_at(container_fd, &sidecar) != SIDECAR_OPEN_FRESH ||
        portable_capture_context_init(&context, data_fd, &sidecar, 1, 1) != 0)
        fixture_fatal("could not initialize portable capture");

    PortableRootSpec root = root_spec(source_path);
    portable_capture_test_reset_probe_count();
    portable_capture_test_reset_readback_scan_count();
    check(portable_capture_root(&context, &root) == 0,
          "capture of 20,000-file fixture succeeds");
    check(portable_capture_test_readback_scan_count() == 0,
          "ASCII-only directory skips destination read-back");
    check(sidecar_log_live_count(&sidecar) == SCALE_ENTRY_COUNT + 1U,
          "visited set admits the root and every child exactly once");

    uint64_t probes = portable_capture_test_probe_count();
    uint64_t count = (uint64_t)SCALE_ENTRY_COUNT + 1U;
    printf("  probes=%" PRIu64 " entries=%" PRIu64 "\n", probes, count);
    check(probes <= count * UINT64_C(32),
          "visited probes remain bounded linearly");
    check(probes < (count * count) / UINT64_C(1000),
          "visited probes remain far below quadratic work");

    static const char *utf8_names[] = { "日本", "ç", "🙂", "また" };
    for (size_t index = 0;
         index < sizeof(utf8_names) / sizeof(utf8_names[0]); index++)
        if (make_named_fixture_file(source_fd, utf8_names[index]) != 0)
            fixture_fatal("could not create UTF-8 scale fixture file");

    portable_capture_test_reset_readback_scan_count();
    check(portable_capture_root(&context, &root) == 0,
          "mixed ASCII and UTF-8 fixture captures successfully");
    check(portable_capture_test_readback_scan_count() == 1,
          "UTF-8 names trigger one batched destination read-back");

    portable_capture_context_close(&context);
    check(sidecar_log_close(&sidecar) == SIDECAR_STATUS_OK,
          "scale sidecar closes cleanly");
    close(data_fd);
    unlinkat(container_fd, SIDECAR_SLOT_NAME, 0);
    close(source_fd);
    close(container_fd);
    remove_tree(fixture);
    printf("portable capture scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
