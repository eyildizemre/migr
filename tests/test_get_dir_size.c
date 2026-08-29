#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
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

static int make_root(char *root, size_t root_size)
{
    if (root_size == 0)
        return -1;
    root[0] = '\0';

    char template[] = "/tmp/get_dir_size_test_XXXXXX";
    char *created = mkdtemp(template);
    if (created == NULL)
        return -1;

    int n = snprintf(root, root_size, "%s", created);
    if (n < 0 || (size_t)n >= root_size)
    {
        rmdir(created);
        root[0] = '\0';
        return -1;
    }
    return 0;
}

static int fixture_path(char *out, size_t out_size,
                        const char *root, const char *suffix)
{
    int n = snprintf(out, out_size, "%s/%s", root, suffix);
    return (n >= 0 && (size_t)n < out_size) ? 0 : -1;
}

static int write_file(const char *path, size_t byte_count)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;

    int ok = 1;
    for (size_t written = 0; ok && written < byte_count; written++)
        if (write(fd, "x", 1) != 1)
            ok = 0;
    if (close(fd) != 0)
        ok = 0;
    return ok ? 0 : -1;
}

static void test_regular_file_adds_to_existing_size(void)
{
    char root[PATH_MAX] = {0};
    char file_path[PATH_MAX] = {0};
    int fixture_ok = make_root(root, sizeof(root)) == 0 &&
                     fixture_path(file_path, sizeof(file_path), root,
                                  "payload.bin") == 0 &&
                     write_file(file_path, 100) == 0;
    check(fixture_ok, "fixture: regular file is created");

    if (fixture_ok)
    {
        off_t size = 37;
        check(get_dir_size(file_path, &size) == 0 && size == 137,
              "regular file size is added to the existing accumulator");
    }

    if (file_path[0] != '\0')
        unlink(file_path);
    if (root[0] != '\0')
        rmdir(root);
}

static void test_symlink_counts_its_own_size_not_the_target(void)
{
    char root[PATH_MAX] = {0};
    char target_path[PATH_MAX] = {0};
    char link_path[PATH_MAX] = {0};
    int fixture_ok = make_root(root, sizeof(root)) == 0 &&
                     fixture_path(target_path, sizeof(target_path), root,
                                  "target.bin") == 0 &&
                     fixture_path(link_path, sizeof(link_path), root,
                                  "target.link") == 0 &&
                     write_file(target_path, 200) == 0 &&
                     symlink(target_path, link_path) == 0;
    check(fixture_ok, "fixture: symlink and target are created");

    if (fixture_ok)
    {
        struct stat link_stat;
        struct stat target_stat;
        int stats_ok = lstat(link_path, &link_stat) == 0 &&
                       lstat(target_path, &target_stat) == 0 &&
                       link_stat.st_size != target_stat.st_size;
        check(stats_ok, "fixture: symlink and target sizes are distinguishable");

        if (stats_ok)
        {
            off_t size = 11;
            check(get_dir_size(link_path, &size) == 0 &&
                      size == 11 + link_stat.st_size,
                  "symlink contributes its own lstat size, not target size");
        }
    }

    if (link_path[0] != '\0')
        unlink(link_path);
    if (target_path[0] != '\0')
        unlink(target_path);
    if (root[0] != '\0')
        rmdir(root);
}

static void test_directory_recurses_and_sums_children(void)
{
    char root[PATH_MAX] = {0};
    char first_path[PATH_MAX] = {0};
    char subdir_path[PATH_MAX] = {0};
    char second_path[PATH_MAX] = {0};
    int fixture_ok = make_root(root, sizeof(root)) == 0 &&
                     fixture_path(first_path, sizeof(first_path), root,
                                  "a.txt") == 0 &&
                     fixture_path(subdir_path, sizeof(subdir_path), root,
                                  "sub") == 0 &&
                     fixture_path(second_path, sizeof(second_path), subdir_path,
                                  "b.txt") == 0 &&
                     write_file(first_path, 40) == 0 &&
                     mkdir(subdir_path, 0700) == 0 &&
                     write_file(second_path, 60) == 0;
    check(fixture_ok, "fixture: recursive directory tree is created");

    if (fixture_ok)
    {
        struct stat root_stat;
        struct stat subdir_stat;
        int stats_ok = lstat(root, &root_stat) == 0 &&
                       lstat(subdir_path, &subdir_stat) == 0;
        check(stats_ok, "fixture: directory sizes are readable");

        if (stats_ok)
        {
            off_t size = 0;
            off_t expected = root_stat.st_size + subdir_stat.st_size + 100;
            check(get_dir_size(root, &size) == 0 && size == expected,
                  "directory recursion sums directory and regular-file sizes");
        }
    }

    if (second_path[0] != '\0')
        unlink(second_path);
    if (subdir_path[0] != '\0')
        rmdir(subdir_path);
    if (first_path[0] != '\0')
        unlink(first_path);
    if (root[0] != '\0')
        rmdir(root);
}

static void test_empty_directory(void)
{
    char root[PATH_MAX] = {0};
    char empty_path[PATH_MAX] = {0};
    int fixture_ok = make_root(root, sizeof(root)) == 0 &&
                     fixture_path(empty_path, sizeof(empty_path), root,
                                  "empty") == 0 &&
                     mkdir(empty_path, 0700) == 0;
    check(fixture_ok, "fixture: empty directory is created");

    if (fixture_ok)
    {
        struct stat empty_stat;
        int stat_ok = lstat(empty_path, &empty_stat) == 0;
        check(stat_ok, "fixture: empty directory size is readable");

        if (stat_ok)
        {
            off_t size = 0;
            check(get_dir_size(empty_path, &size) == 0 &&
                      size == empty_stat.st_size,
                  "clean readdir EOF succeeds for an empty directory");
        }
    }

    if (empty_path[0] != '\0')
        rmdir(empty_path);
    if (root[0] != '\0')
        rmdir(root);
}

static void test_nonexistent_path_fails(void)
{
    char root[PATH_MAX] = {0};
    char missing_path[PATH_MAX] = {0};
    int fixture_ok = make_root(root, sizeof(root)) == 0 &&
                     fixture_path(missing_path, sizeof(missing_path), root,
                                  "missing") == 0;
    check(fixture_ok, "fixture: nonexistent path is addressable");

    if (fixture_ok)
    {
        off_t size = 19;
        check(get_dir_size(missing_path, &size) == -1,
              "nonexistent path is reported as a failure");
    }

    if (root[0] != '\0')
        rmdir(root);
}

static void test_unreadable_subdirectory_fails(void)
{
    char root[PATH_MAX] = {0};
    char locked_path[PATH_MAX] = {0};
    char payload_path[PATH_MAX] = {0};
    int fixture_ok = make_root(root, sizeof(root)) == 0 &&
                     fixture_path(locked_path, sizeof(locked_path), root,
                                  "locked") == 0 &&
                     fixture_path(payload_path, sizeof(payload_path), locked_path,
                                  "payload.txt") == 0 &&
                     mkdir(locked_path, 0700) == 0 &&
                     write_file(payload_path, 32) == 0 &&
                     chmod(locked_path, 0) == 0;
    check(fixture_ok, "fixture: unreadable subdirectory is created");

    if (fixture_ok)
    {
        DIR *probe = opendir(locked_path);
        if (geteuid() == 0 || probe != NULL)
        {
            printf("  " BLUE "-" NC " unreadable-directory fixture bypassed by host privilege\n");
        }
        else
        {
            off_t size = 0;
            check(get_dir_size(root, &size) == -1,
                  "unreadable subdirectory makes recursive measurement fail");
        }
        if (probe != NULL)
            closedir(probe);
    }

    if (locked_path[0] != '\0')
        chmod(locked_path, 0700);
    if (payload_path[0] != '\0')
        unlink(payload_path);
    if (locked_path[0] != '\0')
        rmdir(locked_path);
    if (root[0] != '\0')
        rmdir(root);
}

int main(void)
{
    printf(BLUE "::" NC " get_dir_size (unit)\n");
    test_regular_file_adds_to_existing_size();
    test_symlink_counts_its_own_size_not_the_target();
    test_directory_recurses_and_sums_children();
    test_empty_directory();
    test_nonexistent_path_fails();
    test_unreadable_subdirectory_fails();

    printf("get_dir_size tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
