// Empirical atime regression coverage for the public restore() dispatch:
// source directory atime must survive metadata inventory and native
// validation/apply, and destination symlink atime must receive the exact
// pre-inventory value (docs/DECISIONS.md D17). Linux readlinkat() necessarily
// perturbs a source symlink's atime, so source-symlink preservation is not
// asserted here.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manifest.h"
#include "restore.h"
#include "utils.h"

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

static void die_fixture(const char *message)
{
    fprintf(stderr, RED "fixture: %s" NC "\n", message);
    exit(1);
}

static void fresh_mkdtemp(char *path, size_t path_size, const char *prefix)
{
    if ((size_t)snprintf(path, path_size, "/tmp/%s_XXXXXX", prefix) >= path_size ||
        mkdtemp(path) == NULL)
        die_fixture("could not create temporary directory");
}

static void join_path(char *out, size_t out_size, const char *parent,
                      const char *leaf)
{
    int n = snprintf(out, out_size, "%s/%s", parent, leaf);
    if (n < 0 || (size_t)n >= out_size)
        die_fixture("fixture path is too long");
}

static int remove_cb(const char *path, const struct stat *st, int typeflag,
                     struct FTW *ftwbuf)
{
    (void)st;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_cb, 16, FTW_DEPTH | FTW_PHYS) != 0)
        die_fixture("could not remove temporary tree");
}

static void write_file(const char *path, const char *contents)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        die_fixture("could not create payload file");
    size_t length = strlen(contents);
    if (write(fd, contents, length) != (ssize_t)length || close(fd) != 0)
        die_fixture("could not write payload file");
}

static int same_timespec(struct timespec left, struct timespec right)
{
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static void check_atime(const struct stat *expected, const struct stat *actual,
                        const char *label)
{
    int equal = expected != NULL && actual != NULL &&
                same_timespec(expected->st_atim, actual->st_atim);
    if (!equal && expected != NULL && actual != NULL)
        printf("    expected atime %lld.%09ld, observed %lld.%09ld\n",
               (long long)expected->st_atim.tv_sec,
               expected->st_atim.tv_nsec,
               (long long)actual->st_atim.tv_sec,
               actual->st_atim.tv_nsec);
    check(equal, label);
}

static int set_known_times(const char *path, int flags,
                           struct timespec atime, struct timespec mtime)
{
    struct timespec times[2] = { atime, mtime };
    return utimensat(AT_FDCWD, path, times, flags);
}

static int run_restore_with_confirmation(const char *source)
{
    int input[2];
    if (pipe(input) != 0)
        die_fixture("could not create restore input pipe");

    pid_t child = fork();
    if (child < 0)
        die_fixture("could not fork restore child");
    if (child == 0)
    {
        int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_fd < 0)
            _exit(125);
        close(input[1]);
        if (dup2(input[0], STDIN_FILENO) < 0 ||
            dup2(null_fd, STDOUT_FILENO) < 0)
            _exit(125);
        close(input[0]);
        close(null_fd);
        dry_run = 0;
        verbose = 0;
        int rc = restore(source);
        fflush(stdout);
        _exit(rc == 0 ? 0 : 1);
    }

    close(input[0]);
    const char answer[] = "y\n";
    if (write(input[1], answer, sizeof(answer) - 1) != (ssize_t)(sizeof(answer) - 1))
        die_fixture("could not confirm restore");
    if (close(input[1]) != 0)
        die_fixture("could not close restore input");

    int status;
    if (waitpid(child, &status, 0) != child)
        die_fixture("could not wait for restore child");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 125;
}

static void make_v1_manifest(Manifest *manifest, ManifestRoot *roots)
{
    memset(manifest, 0, sizeof(*manifest));
    manifest->version = MANIFEST_CURRENT_VERSION;
    manifest->representation = CLONE_NATIVE_TREE;
    manifest->scope = MANIFEST_SCOPE_EXPLICIT;
    manifest->root_count = 2;
    manifest->roots = roots;
}

static void create_directory_payload(const char *parent, const char *name,
                                     const char *child_contents,
                                     struct timespec known_time,
                                     struct stat *before)
{
    char directory_path[PATH_MAX];
    char child_path[PATH_MAX];
    join_path(directory_path, sizeof(directory_path), parent, name);
    if (mkdir(directory_path, 0700) != 0)
        die_fixture("could not create directory payload");
    join_path(child_path, sizeof(child_path), directory_path, "child.txt");
    write_file(child_path, child_contents);
    if (set_known_times(directory_path, 0, known_time, known_time) != 0 ||
        lstat(directory_path, before) != 0)
        die_fixture("could not snapshot source timestamps");
}

static void create_symlink_payload(const char *parent, const char *name,
                                   const char *target,
                                   struct timespec known_time,
                                   struct stat *before)
{
    char symlink_path[PATH_MAX];
    join_path(symlink_path, sizeof(symlink_path), parent, name);
    if (symlink(target, symlink_path) != 0 ||
        set_known_times(symlink_path, AT_SYMLINK_NOFOLLOW,
                        known_time, known_time) != 0 ||
        lstat(symlink_path, before) != 0)
        die_fixture("could not create or snapshot symlink payload");
}

static void reset_directory_time(const char *path, struct timespec known_time,
                                 struct stat *before)
{
    if (set_known_times(path, 0, known_time, known_time) != 0 ||
        lstat(path, before) != 0)
        die_fixture("could not reset directory timestamp");
}

static void test_legacy_directory_and_symlink_atime(void)
{
    printf(BLUE "::" NC " public legacy restore preserves directory and symlink atime\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "restore_atime_legacy_src");
    fresh_mkdtemp(home, sizeof(home), "restore_atime_legacy_home");
    setenv("HOME", home, 1);

    struct timespec directory_time = { 946684800, 123456789 };
    struct timespec symlink_time = { 946684900, 234567891 };
    struct timespec nested_symlink_time = { 946685000, 345678901 };
    char source_directory_path[PATH_MAX];
    join_path(source_directory_path, sizeof(source_directory_path), source, ".ssh");
    struct stat source_directory, source_symlink, source_nested_symlink;
    create_directory_payload(source, ".ssh", "legacy-child", directory_time,
                             &source_directory);
    create_symlink_payload(source, ".profile", "legacy-target", symlink_time,
                           &source_symlink);
    create_symlink_payload(source_directory_path, "nested-link",
                           "nested-target", nested_symlink_time,
                           &source_nested_symlink);
    reset_directory_time(source_directory_path, directory_time,
                         &source_directory);

    int rc = run_restore_with_confirmation(source);
    check(rc == 0, "legacy restore completes successfully");

    char destination_directory[PATH_MAX], destination_symlink[PATH_MAX];
    char destination_nested_symlink[PATH_MAX];
    join_path(destination_directory, sizeof(destination_directory), home, ".ssh");
    join_path(destination_symlink, sizeof(destination_symlink), home, ".profile");
    join_path(destination_nested_symlink, sizeof(destination_nested_symlink),
              destination_directory, "nested-link");
    struct stat restored_directory, restored_symlink, restored_nested_symlink;
    struct stat source_directory_after;
    check(lstat(destination_directory, &restored_directory) == 0 &&
          S_ISDIR(restored_directory.st_mode),
          "legacy directory was restored");
    check(lstat(destination_symlink, &restored_symlink) == 0 &&
          S_ISLNK(restored_symlink.st_mode),
          "legacy symlink was restored");
    check(lstat(destination_nested_symlink, &restored_nested_symlink) == 0 &&
          S_ISLNK(restored_nested_symlink.st_mode),
          "legacy nested symlink was restored");
    check(lstat(source_directory_path, &source_directory_after) == 0 &&
          same_timespec(source_directory.st_atim, source_directory_after.st_atim),
          "legacy source directory atime is unchanged after both passes");
    if (lstat(destination_directory, &restored_directory) == 0)
        check_atime(&source_directory, &restored_directory,
                    "legacy destination directory atime matches the validation snapshot");
    else
        check(0, "legacy destination directory atime matches the validation snapshot");
    if (lstat(destination_symlink, &restored_symlink) == 0)
        check_atime(&source_symlink, &restored_symlink,
                    "legacy destination symlink atime matches the validation snapshot");
    else
        check(0, "legacy destination symlink atime matches the validation snapshot");
    if (lstat(destination_nested_symlink, &restored_nested_symlink) == 0)
        check_atime(&source_nested_symlink, &restored_nested_symlink,
                    "legacy nested destination symlink atime matches the validation snapshot");
    else
        check(0, "legacy nested destination symlink atime matches the validation snapshot");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_directory_and_symlink_atime(void)
{
    printf(BLUE "::" NC " public v1 restore preserves directory and symlink atime\n");

    char parent[PATH_MAX], source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(parent, sizeof(parent), "restore_atime_v1_parent");
    join_path(source, sizeof(source), parent, "migr_backup_20260101_000000");
    if (mkdir(source, 0700) != 0)
        die_fixture("could not create versioned source");
    fresh_mkdtemp(home, sizeof(home), "restore_atime_v1_home");
    setenv("HOME", home, 1);

    char data[PATH_MAX], directory_payload[PATH_MAX];
    join_path(data, sizeof(data), source, "data");
    join_path(directory_payload, sizeof(directory_payload), data, "EXPLICIT_0");
    if (mkdir(data, 0700) != 0)
        die_fixture("could not create v1 payload directories");

    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, ".ssh");
    strcpy(roots[0].restore_path, ".ssh");
    roots[0].has_restore_path = 1;
    strcpy(roots[1].id, "EXPLICIT_1");
    roots[1].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[1].payload_path, "EXPLICIT_1");
    strcpy(roots[1].source_path, ".profile");
    strcpy(roots[1].restore_path, ".profile");
    roots[1].has_restore_path = 1;
    Manifest manifest;
    make_v1_manifest(&manifest, roots);
    if (manifest_write_v1(source, &manifest) != 0)
        die_fixture("could not write v1 manifest");

    struct timespec directory_time = { 946685000, 345678901 };
    struct timespec symlink_time = { 946685100, 456789012 };
    struct timespec nested_symlink_time = { 946685200, 567890123 };
    struct stat source_directory, source_symlink, source_nested_symlink;
    create_directory_payload(data, "EXPLICIT_0", "v1-child", directory_time,
                             &source_directory);
    create_symlink_payload(data, "EXPLICIT_1", "v1-target", symlink_time,
                           &source_symlink);
    create_symlink_payload(directory_payload, "nested-link", "v1-nested-target",
                           nested_symlink_time, &source_nested_symlink);
    reset_directory_time(directory_payload, directory_time, &source_directory);

    int rc = run_restore_with_confirmation(source);
    check(rc == 0, "v1 restore completes successfully");

    char destination_directory[PATH_MAX], destination_symlink[PATH_MAX];
    char destination_nested_symlink[PATH_MAX];
    join_path(destination_directory, sizeof(destination_directory), home, ".ssh");
    join_path(destination_symlink, sizeof(destination_symlink), home, ".profile");
    join_path(destination_nested_symlink, sizeof(destination_nested_symlink),
              destination_directory, "nested-link");
    struct stat restored_directory, restored_symlink, restored_nested_symlink;
    struct stat source_directory_after;
    check(lstat(destination_directory, &restored_directory) == 0 &&
          S_ISDIR(restored_directory.st_mode),
          "v1 directory was restored");
    check(lstat(destination_symlink, &restored_symlink) == 0 &&
          S_ISLNK(restored_symlink.st_mode),
          "v1 symlink was restored");
    check(lstat(destination_nested_symlink, &restored_nested_symlink) == 0 &&
          S_ISLNK(restored_nested_symlink.st_mode),
          "v1 nested symlink was restored");
    check(lstat(directory_payload, &source_directory_after) == 0 &&
          same_timespec(source_directory.st_atim, source_directory_after.st_atim),
          "v1 source directory atime is unchanged after both passes");
    if (lstat(destination_directory, &restored_directory) == 0)
        check_atime(&source_directory, &restored_directory,
                    "v1 destination directory atime matches the validation snapshot");
    else
        check(0, "v1 destination directory atime matches the validation snapshot");
    if (lstat(destination_symlink, &restored_symlink) == 0)
        check_atime(&source_symlink, &restored_symlink,
                    "v1 destination symlink atime matches the validation snapshot");
    else
        check(0, "v1 destination symlink atime matches the validation snapshot");
    if (lstat(destination_nested_symlink, &restored_nested_symlink) == 0)
        check_atime(&source_nested_symlink, &restored_nested_symlink,
                    "v1 nested destination symlink atime matches the validation snapshot");
    else
        check(0, "v1 nested destination symlink atime matches the validation snapshot");

    remove_tree(parent);
    remove_tree(home);
}

int main(void)
{
    printf(BLUE "::" NC " restore source atime (public dispatch)\n");
    dry_run = 0;
    verbose = 0;
    test_legacy_directory_and_symlink_atime();
    test_v1_directory_and_symlink_atime();
    if (failures != 0)
    {
        printf(RED "%d restore atime test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
