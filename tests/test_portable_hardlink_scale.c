// Host-only scale tests for the portable hardlink maps (docs/DECISIONS.md
// D22).  Real hardlink pairs exercise the pre-scan inode set, the capture-time
// inode map, and the resume sticky-seed pass.  Assertions use deterministic
// probe and lstat counters rather than wall-clock timing.

#define _GNU_SOURCE

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

#define SCALE_GROUP_COUNT 5000U

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
    fprintf(stderr, "portable hardlink scale fixture failure: %s\n",
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
    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not inspect scale fixture tree");
    }
    if (nftw(path, remove_callback_fatal, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fixture_fatal("could not walk scale fixture tree");
}

static int make_hardlink_pair(int source_fd, unsigned int index)
{
    char first[32];
    char second[32];
    int first_length = snprintf(first, sizeof(first), "pair-%05u-a", index);
    int second_length = snprintf(second, sizeof(second), "pair-%05u-b", index);
    if (first_length < 0 || second_length < 0 ||
        (size_t)first_length >= sizeof(first) ||
        (size_t)second_length >= sizeof(second))
        return -1;

    int fd = openat(source_fd, first,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    const char content[] = "hardlink-scale";
    ssize_t written = write(fd, content, sizeof(content) - 1U);
    if (written != (ssize_t)(sizeof(content) - 1U))
    {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0)
        return -1;
    return linkat(source_fd, first, source_fd, second, 0);
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
    printf(BLUE "::" NC " portable hardlink hash scale\n");
    char fixture[] = "/tmp/migr_portable_hardlink_scale_XXXXXX";
    if (mkdtemp(fixture) == NULL)
        fixture_fatal("could not create scale fixture root");

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int source_length = snprintf(source_path, sizeof(source_path), "%s/source",
                                 fixture);
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
    for (unsigned int index = 0; index < SCALE_GROUP_COUNT; index++)
        if (make_hardlink_pair(source_fd, index) != 0)
            fixture_fatal("could not create hardlink scale fixture");

    PortableRootSpec root = root_spec(source_path);
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "a11ce",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    uint64_t groups = (uint64_t)SCALE_GROUP_COUNT;

    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    portable_capture_test_reset_prescan_inode_probe_count();
    check(portable_collision_plan_build(container_fd, &request, &report) == 0,
          "hardlink pre-scan succeeds");
    uint64_t prescan_probes =
        portable_capture_test_prescan_inode_probe_count();
    printf("  prescan_inode_probes=%" PRIu64 " groups=%" PRIu64 "\n",
           prescan_probes, groups);
    check(prescan_probes <= groups * UINT64_C(32),
          "pre-scan inode probes remain bounded linearly");
    portable_prescan_report_free(&report);

    portable_capture_test_reset_inode_map_probe_count();
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "fresh hardlink capture succeeds");
    uint64_t fresh_probes = portable_capture_test_inode_map_probe_count();
    printf("  fresh_inode_map_probes=%" PRIu64 " groups=%" PRIu64 "\n",
           fresh_probes, groups);
    check(fresh_probes <= groups * UINT64_C(32),
          "fresh inode-map probes remain bounded linearly");

    portable_capture_test_reset_inode_map_probe_count();
    portable_capture_test_reset_sticky_seed_lstat_count();
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume hardlink capture succeeds");
    uint64_t resume_probes = portable_capture_test_inode_map_probe_count();
    uint64_t lstat_calls = portable_capture_test_sticky_seed_lstat_count();
    printf("  resume_inode_map_probes=%" PRIu64
           " sticky_seed_lstats=%" PRIu64 " groups=%" PRIu64 "\n",
           resume_probes, lstat_calls, groups);
    check(lstat_calls == groups,
          "sticky seed performs one lstat per live regular entry");
    check(resume_probes <= groups * UINT64_C(64),
          "resume inode-map probes remain bounded linearly");

    if (close(source_fd) != 0 || close(container_fd) != 0)
        fixture_fatal("could not close scale fixture directories");
    remove_tree(fixture);
    printf("portable hardlink scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
