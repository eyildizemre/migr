// Native restore source-read refusal tests (docs/DECISIONS.md D17): an
// O_NOATIME denial is distinct from ordinary I/O failure, never falls back to
// an atime-changing read, and is reported before destination mutation.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fileops.h"
#include "metadata.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

static const CloneContext RESTORE_CTX = {
    .operation = CLONE_RESTORE,
    .representation = CLONE_NATIVE_TREE
};

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

static void fatal_fixture(const char *message)
{
    printf(RED "fixture: %s" NC "\n", message);
    exit(1);
}

static void fresh_root(char *path, size_t size)
{
    if ((size_t)snprintf(path, size, "/tmp/migr_restore_source_XXXXXX") >= size ||
        mkdtemp(path) == NULL)
        fatal_fixture("could not create temporary root");
}

static void join_path(char *out, size_t size, const char *left,
                      const char *right)
{
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    if (left_len + 1U + right_len + 1U > size)
        fatal_fixture("fixture path is too long");
    memcpy(out, left, left_len);
    out[left_len] = '/';
    memcpy(out + left_len + 1U, right, right_len + 1U);
}

static void write_file(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (file == NULL || fputs(text, file) == EOF || fclose(file) != 0)
        fatal_fixture("could not write source fixture");
}

static int open_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        fatal_fixture("could not open fixture directory");
    return fd;
}

static int remove_entry(const char *path, const struct stat *st,
                        int typeflag, struct FTW *ftwbuf)
{
    (void)st;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fatal_fixture("could not clean up fixture");
}

static int times_equal(const struct timespec *left, const struct timespec *right)
{
    return left->tv_sec == right->tv_sec && left->tv_nsec == right->tv_nsec;
}

static void test_validate_refusal(const char *source_root, const char *dest_root,
                                  int source_fd, int dest_fd)
{
    (void)dest_root;
    struct stat before;
    struct stat after;
    char entry_path[PATH_MAX];
    join_path(entry_path, sizeof(entry_path), source_root, "entry");
    check(stat(entry_path, &before) == 0, "source regular fixture is readable");

    restore_native_test_set_source_read_mode(RESTORE_TEST_SOURCE_READ_VALIDATE);
    RestoreNativeStatus regular_status = restore_native_preflight_at(
        &RESTORE_CTX, source_fd, "entry", dest_fd, "entry");
    RestoreNativeStatus directory_status = restore_native_preflight_at(
        &RESTORE_CTX, source_fd, "tree", dest_fd, "tree");
    restore_native_test_set_source_read_mode(RESTORE_TEST_SOURCE_READ_NONE);

    check(regular_status == RESTORE_NATIVE_SOURCE_SAFE_READ,
          "regular-source O_NOATIME refusal has a distinct validate status");
    check(directory_status == RESTORE_NATIVE_SOURCE_SAFE_READ,
          "directory-source O_NOATIME refusal has a distinct validate status");
    check(fstatat(dest_fd, "entry", &after, AT_SYMLINK_NOFOLLOW) != 0 &&
          errno == ENOENT &&
          fstatat(dest_fd, "tree", &after, AT_SYMLINK_NOFOLLOW) != 0 &&
          errno == ENOENT,
          "validate refusal creates no destination entries");
    check(stat(entry_path, &after) == 0 &&
          times_equal(&before.st_atim, &after.st_atim) &&
          times_equal(&before.st_mtim, &after.st_mtim),
          "validate refusal leaves source timestamps unchanged");
}

static void test_apply_refusal(const char *source_root, int source_fd, int dest_fd)
{
    char entry_path[PATH_MAX];
    join_path(entry_path, sizeof(entry_path), source_root, "entry");
    struct stat before;
    struct stat after;
    check(stat(entry_path, &before) == 0, "apply fixture source is readable");

    restore_native_test_set_source_read_mode(RESTORE_TEST_SOURCE_READ_APPLY);
    RestoreNativeReport report;
    RestoreNativeStatus status = restore_native_at_report(
        &RESTORE_CTX, source_fd, "entry", dest_fd, "entry", &report);
    restore_native_test_set_source_read_mode(RESTORE_TEST_SOURCE_READ_NONE);

    check(status == RESTORE_NATIVE_SOURCE_SAFE_READ,
          "apply-time source refusal propagates its distinct status");
    check(report.applied_count == 0 && report.failed_count == 1 &&
          strcmp(report.failed_logical_path, "entry") == 0,
          "apply refusal reports zero applied and the failing entry");
    check(fstatat(dest_fd, "entry", &after, AT_SYMLINK_NOFOLLOW) != 0 &&
          errno == ENOENT,
          "apply refusal creates no destination entry");
    check(stat(entry_path, &after) == 0 &&
          times_equal(&before.st_atim, &after.st_atim) &&
          times_equal(&before.st_mtim, &after.st_mtim),
          "apply refusal leaves source timestamps unchanged");
}

static int gid_is_allowed(gid_t gid)
{
    if (gid == getegid())
        return 1;
    int count = getgroups(0, NULL);
    if (count < 0)
        return 0;
    gid_t *groups = count == 0 ? NULL : malloc((size_t)count * sizeof(*groups));
    if (count != 0 && groups == NULL)
        fatal_fixture("could not inspect supplementary groups");
    int actual = count == 0 ? 0 : getgroups(count, groups);
    int allowed = 0;
    for (int i = 0; i < actual; i++)
        if (groups[i] == gid)
            allowed = 1;
    free(groups);
    return allowed;
}

static int effective_cap_chown(void)
{
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL)
        return -1;

    char line[128];
    int result = -1;
    while (fgets(line, sizeof(line), status) != NULL)
    {
        if (strncmp(line, "CapEff:", 7) != 0)
            continue;
        char *end = NULL;
        unsigned long long mask = strtoull(line + 7, &end, 16);
        if (end != line + 7)
            result = (mask & 1ULL) != 0;
        break;
    }
    fclose(status);
    return result;
}

static void test_destination_probe_rejection(int anchor_fd)
{
    if (geteuid() == 0)
    {
        printf("  " BLUE "i" NC " ownership probe refusal skipped for root\n");
        return;
    }

    if (effective_cap_chown() != 0)
    {
        printf("  " BLUE "i" NC " ownership probe refusal skipped: CAP_CHOWN is effective\n");
        return;
    }

    gid_t foreign_gid = 65534;
    if (gid_is_allowed(foreign_gid))
    {
        printf("  " BLUE "i" NC " ownership probe refusal skipped: fixture gid is allowed\n");
        return;
    }

    struct stat desired;
    if (fstat(anchor_fd, &desired) != 0)
        fatal_fixture("could not inspect probe anchor");
    desired.st_uid = geteuid();
    desired.st_gid = foreign_gid;
    desired.st_mode = S_IFREG | 0600;

    MetadataProfiles profiles;
    metadata_profiles_init(&profiles);
    check(metadata_profiles_add(&profiles, anchor_fd, &desired, NULL, "probe") == 0,
          "foreign destination group enters the ownership profile");
    int probe_status = metadata_profiles_probe(
        &profiles, (MetadataTimestampPolicy){ .configured = 1, .nsec_exact = 0 });
    if (probe_status == 0)
        printf("  " BLUE "i" NC " ownership probe refusal skipped: CAP_CHOWN is available\n");
    else
        check(probe_status != 0,
              "destination ownership probe rejects an unavailable foreign group");
    metadata_profiles_free(&profiles);
}

static void test_apply_partial_refusal(const char *source_root,
                                       int source_fd, int dest_fd)
{
    char tree_path[PATH_MAX];
    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    join_path(tree_path, sizeof(tree_path), source_root, "partial-tree");
    if (mkdir(tree_path, 0700) != 0)
        fatal_fixture("could not create partial-restore directory");
    join_path(first_path, sizeof(first_path), tree_path, "first");
    join_path(second_path, sizeof(second_path), tree_path, "second");
    write_file(first_path, "first payload\n");
    write_file(second_path, "second payload\n");

    struct stat before_tree;
    struct stat before_first;
    struct stat before_second;
    check(stat(tree_path, &before_tree) == 0 &&
          stat(first_path, &before_first) == 0 &&
          stat(second_path, &before_second) == 0,
          "partial-restore source timestamps are readable");

    restore_native_test_fail_source_read_after(2);
    RestoreNativeReport report;
    RestoreNativeStatus status = restore_native_at_report(
        &RESTORE_CTX, source_fd, "partial-tree", dest_fd, "partial-tree",
        &report);
    restore_native_test_set_source_read_mode(RESTORE_TEST_SOURCE_READ_NONE);

    check(status == RESTORE_NATIVE_SOURCE_SAFE_READ,
          "apply-time refusal remains distinct after an earlier successful entry");
    check(report.applied_count == 1 && report.failed_count == 1 &&
          strncmp(report.failed_logical_path, "partial-tree/", 13) == 0,
          "partial restore reports one applied entry and its failing entry");

    struct stat destination_tree;
    check(fstatat(dest_fd, "partial-tree", &destination_tree,
                  AT_SYMLINK_NOFOLLOW) == 0,
          "partial restore leaves the destination tree for the applied entry");

    struct stat after_tree;
    struct stat after_first;
    struct stat after_second;
    check(stat(tree_path, &after_tree) == 0 &&
          stat(first_path, &after_first) == 0 &&
          stat(second_path, &after_second) == 0 &&
          times_equal(&before_tree.st_atim, &after_tree.st_atim) &&
          times_equal(&before_first.st_atim, &after_first.st_atim) &&
          times_equal(&before_first.st_mtim, &after_first.st_mtim) &&
          times_equal(&before_second.st_atim, &after_second.st_atim) &&
          times_equal(&before_second.st_mtim, &after_second.st_mtim),
          "partial refusal leaves source timestamps unchanged");
}

int main(void)
{
    char base[PATH_MAX];
    char source_root[PATH_MAX];
    char dest_root[PATH_MAX];
    char path[PATH_MAX];
    fresh_root(base, sizeof(base));
    join_path(source_root, sizeof(source_root), base, "source");
    join_path(dest_root, sizeof(dest_root), base, "destination");
    if (mkdir(source_root, 0700) != 0 || mkdir(dest_root, 0700) != 0)
        fatal_fixture("could not create fixture roots");
    join_path(path, sizeof(path), source_root, "entry");
    write_file(path, "source payload\n");
    join_path(path, sizeof(path), source_root, "tree");
    if (mkdir(path, 0700) != 0)
        fatal_fixture("could not create source directory fixture");
    join_path(path, sizeof(path), source_root, "tree/child");
    write_file(path, "nested payload\n");

    int source_fd = open_directory(source_root);
    int dest_fd = open_directory(dest_root);
    printf(BLUE "::" NC " native restore source-read refusals (unit)\n");
    test_validate_refusal(source_root, dest_root, source_fd, dest_fd);
    test_apply_refusal(source_root, source_fd, dest_fd);
    test_apply_partial_refusal(source_root, source_fd, dest_fd);
    test_destination_probe_rejection(dest_fd);
    close(source_fd);
    close(dest_fd);
    remove_tree(base);
    if (failures != 0)
        printf(RED "%d source-read test(s) failed" NC "\n", failures);
    return failures == 0 ? 0 : 1;
}
