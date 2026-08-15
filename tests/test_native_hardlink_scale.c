// Host-only scale test for the native hardlink capture inode map
// (docs/DECISIONS.md D22). Real hardlink pairs exercise the fresh native
// capture path; probe-count assertions are deterministic and never wall-clock.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fileops.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define SCALE_GROUP_COUNT 5000U

static int failures;

extern int native_hardlink_identity_matches(const struct stat *linked,
                                            const struct stat *reference);

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
    fprintf(stderr, "native hardlink scale fixture failure: %s\n", message);
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
    const char content[] = "native-hardlink-scale";
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

static int pair_name(char *buffer, size_t size, unsigned int index,
                     char suffix)
{
    int length = snprintf(buffer, size, "pair-%05u-%c", index, suffix);
    return length < 0 || (size_t)length >= size ? -1 : 0;
}

int main(void)
{
    printf(BLUE "::" NC " native hardlink inode-map scale\n");
    char fixture[] = "/tmp/migr_native_hardlink_scale_XXXXXX";
    if (mkdtemp(fixture) == NULL)
        fixture_fatal("could not create scale fixture root");

    char source[PATH_MAX];
    char destination[PATH_MAX];
    int source_length = snprintf(source, sizeof(source), "%s/source", fixture);
    int destination_length = snprintf(destination, sizeof(destination),
                                      "%s/destination", fixture);
    if (source_length < 0 || destination_length < 0 ||
        (size_t)source_length >= sizeof(source) ||
        (size_t)destination_length >= sizeof(destination))
        fixture_fatal("scale fixture path is too long");
    if (mkdir(source, 0700) != 0 || mkdir(destination, 0700) != 0)
        fixture_fatal("could not create scale fixture directories");

    int source_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int destination_fd = open(destination,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || destination_fd < 0)
        fixture_fatal("could not open scale fixture directories");
    for (unsigned int index = 0; index < SCALE_GROUP_COUNT; index++)
        if (make_hardlink_pair(source_fd, index) != 0)
            fixture_fatal("could not create hardlink scale fixture");
    if (close(source_fd) != 0)
        fixture_fatal("could not close scale fixture source");

    void *inode_map = native_inode_map_create();
    if (inode_map == NULL)
        fixture_fatal("could not create native inode map");
    CloneContext context = {
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1,
        .metadata_preflight_done = 1,
        .inode_map = inode_map,
        .visited = NULL
    };
    uint64_t entries = (uint64_t)SCALE_GROUP_COUNT * 2U;

    native_inode_map_test_reset_probe_count();
    check(backup_capture_at(&context, source, destination_fd, "tree") == 0,
          "fresh native hardlink capture succeeds");
    uint64_t probes = native_inode_map_test_probe_count();
    printf("  inode_map_probes=%" PRIu64 " entries=%" PRIu64 "\n",
           probes, entries);
    check(probes <= entries * UINT64_C(32),
          "native inode-map probes remain bounded linearly");
    check(probes < (entries * entries) / UINT64_C(1000),
          "native inode-map probes remain far below quadratic work");

    int tree_fd = openat(destination_fd, "tree",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (tree_fd < 0)
        fixture_fatal("could not open captured native tree");
    int identity_ok = 1;
    for (unsigned int index = 0; index < SCALE_GROUP_COUNT; index++)
    {
        char first[32];
        char second[32];
        if (pair_name(first, sizeof(first), index, 'a') != 0 ||
            pair_name(second, sizeof(second), index, 'b') != 0)
            fixture_fatal("captured hardlink name is too long");
        struct stat first_st;
        struct stat second_st;
        if (fstatat(tree_fd, first, &first_st, AT_SYMLINK_NOFOLLOW) != 0 ||
            fstatat(tree_fd, second, &second_st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !native_hardlink_identity_matches(&first_st, &second_st))
            identity_ok = 0;
    }
    check(identity_ok, "all captured hardlink pairs retain inode identity");

    if (close(tree_fd) != 0)
        fixture_fatal("could not close captured native tree");
    native_inode_map_free(inode_map);
    if (close(destination_fd) != 0)
        fixture_fatal("could not close scale fixture destination");
    remove_tree(fixture);
    printf("native hardlink inode-map scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
