// Host-only scale test for the native visited-path set (docs/DECISIONS.md
// D23). A large flat capture proves visited-set insertion during capture,
// and reconciliation's destination scan proves the same set's lookup path,
// both stay within linear probe budgets. Deterministic probe counters,
// never wall-clock.

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

#include "fileops.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define SCALE_ENTRY_COUNT 20000U

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
    fprintf(stderr, "native reconcile scale fixture failure: %s\n", message);
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

int main(void)
{
    printf(BLUE "::" NC " native visited-set scale\n");
    char fixture[] = "/tmp/migr_native_reconcile_scale_XXXXXX";
    if (mkdtemp(fixture) == NULL)
        fixture_fatal("could not create scale fixture root");

    char source[PATH_MAX], destination[PATH_MAX];
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
    if (source_fd < 0)
        fixture_fatal("could not open scale fixture source");
    for (unsigned int index = 0; index < SCALE_ENTRY_COUNT; index++)
    {
        char name[32];
        int name_length = snprintf(name, sizeof(name), "file-%05u", index);
        if (name_length < 0 || (size_t)name_length >= sizeof(name))
            fixture_fatal("scale fixture file name is too long");
        int fd = openat(source_fd, name,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || close(fd) != 0)
            fixture_fatal("could not create scale fixture file");
    }
    if (close(source_fd) != 0)
        fixture_fatal("could not close scale fixture source");

    int destination_fd = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (destination_fd < 0)
        fixture_fatal("could not open scale fixture destination");
    void *visited = native_visited_create();
    if (visited == NULL)
        fixture_fatal("could not create scale fixture visited set");
    CloneContext context = {
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1,
        .metadata_preflight_done = 1,
        .visited = visited
    };
    uint64_t entries = (uint64_t)SCALE_ENTRY_COUNT + 1U;

    native_visited_test_reset_probe_count();
    check(backup_capture_at(&context, source, destination_fd, "tree") == 0,
          "large flat capture succeeds");
    uint64_t capture_probes = native_visited_test_probe_count();
    printf("  capture_probes=%" PRIu64 " entries=%" PRIu64 "\n",
           capture_probes, entries);
    check(capture_probes <= entries * UINT64_C(32),
          "capture-time visited probes remain bounded linearly");
    check(capture_probes < (entries * entries) / UINT64_C(1000),
          "capture-time visited probes remain far below quadratic work");

    native_visited_test_reset_probe_count();
    NativeReconcileReport report;
    check(native_reconcile_stale_at(visited, "tree", destination_fd,
                                    &report) == NATIVE_RECONCILE_OK,
          "reconciliation over the same fixture succeeds");
    uint64_t reconcile_probes = native_visited_test_probe_count();
    printf("  reconcile_probes=%" PRIu64 " entries=%" PRIu64 "\n",
           reconcile_probes, entries);
    check(reconcile_probes <= entries * UINT64_C(32),
          "reconcile-time visited probes remain bounded linearly");
    check(reconcile_probes < (entries * entries) / UINT64_C(1000),
          "reconcile-time visited probes remain far below quadratic work");

    native_visited_free(visited);
    if (close(destination_fd) != 0)
        fixture_fatal("could not close scale fixture destination");
    remove_tree(fixture);
    printf("native visited-set scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
