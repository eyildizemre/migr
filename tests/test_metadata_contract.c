// Unit tests for the native metadata contract (docs/DECISIONS.md D17) across
// regular files, directories, symlinks, FIFOs, sockets, and device nodes,
// exercised through the real backup_capture_at() and restore_native_at()
// entry points rather than a synthetic stand-in. Capture and restore both
// assert exact mode, atime/mtime, and (via the ownership preflight) uid/gid
// across the whole matrix.
//
// Content resume-skip is covered on both the capture and restore sides for
// regular files: matching size+mtime_sec+mtime_nsec keeps existing
// destination content when nsec_exact holds (the default fixture policy).
// test_capture_recopies_without_nsec_exact() checks the opposite -- on a
// coarse-timestamp destination, content is always recopied even on a
// same-size match, because size+mtime_sec alone cannot prove the content did
// not change.
// Symlinks additionally exercise dynamic target fidelity, capture-side
// metadata re-application, and the native restore refusal for an existing
// final destination symlink.
//
// test_foreign_ownership_gap() asserts the preflight's actual guarantee: a
// foreign uid/gid round-trips through capture and restore rather than being
// silently dropped. test_metadata_helper_failure_paths() exercises
// metadata.c's own error paths (invalid fd, NULL stat, NULL profile set)
// directly, since the matrix above only ever reaches its happy path.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "fileops.h"
#include "metadata.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
#define NC    "\033[0m"

static int failures;
static int skips;

typedef enum {
    KIND_REGULAR,
    KIND_DIRECTORY,
    KIND_SYMLINK,
    KIND_FIFO,
    KIND_SOCKET,
    KIND_DEVICE
} MatrixKind;

typedef struct {
    const char *name;
    MatrixKind kind;
    mode_t mode;
} MatrixCase;

static const CloneContext BACKUP_CTX = {
    .operation = CLONE_BACKUP,
    .representation = CLONE_NATIVE_TREE
};

static const CloneContext RESTORE_CTX = {
    .operation = CLONE_RESTORE,
    .representation = CLONE_NATIVE_TREE
};

static const struct timespec regular_times[2] = {
    { .tv_sec = 1700000101, .tv_nsec = 123456789 },
    { .tv_sec = 1700000202, .tv_nsec = 234567890 }
};

static const struct timespec directory_times[2] = {
    { .tv_sec = 1700000303, .tv_nsec = 345678901 },
    { .tv_sec = 1700000404, .tv_nsec = 456789012 }
};

static const struct timespec symlink_times[2] = {
    { .tv_sec = 1700000505, .tv_nsec = 567890123 },
    { .tv_sec = 1700000606, .tv_nsec = 678901234 }
};

static const struct timespec fifo_times[2] = {
    { .tv_sec = 1700000707, .tv_nsec = 789012345 },
    { .tv_sec = 1700000808, .tv_nsec = 890123456 }
};

static void check_result(int condition, const char *case_name, const char *property)
{
    if (condition)
        printf("  " GREEN "v" NC " %-8s %s\n", case_name, property);
    else
    {
        printf("  " RED "x" NC " %-8s %s\n", case_name, property);
        failures++;
    }
}

static void skip_case(const char *case_name, const char *reason)
{
    printf("  " YELLOW "-" NC " %-8s skipped: %s\n", case_name, reason);
    skips++;
}

static void fatal(const char *message)
{
    printf(RED "fixture failure: %s" NC "\n", message);
    exit(2);
}

static int remove_cb(const char *path, const struct stat *sb, int typeflag,
                     struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    if (remove(path) != 0)
        fatal("could not remove a fixture entry");
    return 0;
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_cb, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fatal("could not clean up a fixture tree");
}

static void make_temp_root(char *path, size_t path_size)
{
    int length = snprintf(path, path_size, "/tmp/migr_metadata_contract_XXXXXX");
    if (length < 0 || (size_t)length >= path_size || mkdtemp(path) == NULL)
        fatal("could not create a temporary root");
}

static void join_or_die(char *out, size_t out_size,
                        const char *dir, const char *name)
{
    if (path_join(out, out_size, dir, name) != 0)
        fatal("fixture path is too long");
}

static int open_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        fatal("could not open a fixture directory");
    return fd;
}

static void write_file(const char *path, const char *contents)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fatal("could not create a fixture file");

    size_t length = strlen(contents);
    size_t written = 0;
    while (written < length)
    {
        ssize_t result = write(fd, contents + written, length - written);
        if (result <= 0)
        {
            close(fd);
            fatal("could not write a fixture file");
        }
        written += (size_t)result;
    }

    if (close(fd) != 0)
        fatal("could not close a fixture file");
}

static int file_equals(const char *path, const char *expected)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;

    char buffer[128];
    size_t expected_length = strlen(expected);
    size_t received = 0;
    while (received < sizeof(buffer) - 1)
    {
        ssize_t result = read(fd, buffer + received,
                              sizeof(buffer) - 1 - received);
        if (result < 0)
        {
            close(fd);
            return 0;
        }
        if (result == 0)
            break;
        received += (size_t)result;
    }
    int close_ok = close(fd) == 0;
    buffer[received] = '\0';
    return close_ok && received == expected_length &&
           memcmp(buffer, expected, expected_length) == 0;
}

static void read_link_target_or_die(const char *path, char *target,
                                    size_t target_size)
{
    if (target_size == 0)
        fatal("symlink target buffer is empty");

    ssize_t length = readlink(path, target, target_size);
    if (length < 0 || (size_t)length >= target_size)
        fatal("could not read a complete symlink target");
    target[length] = '\0';
}

static int same_timespec(struct timespec left, struct timespec right)
{
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static int same_core_times(const struct stat *actual, const struct stat *expected)
{
    return same_timespec(actual->st_atim, expected->st_atim) &&
           same_timespec(actual->st_mtim, expected->st_mtim);
}

static int same_mode(const struct stat *actual, const struct stat *expected)
{
    return (actual->st_mode & 07777) == (expected->st_mode & 07777);
}

static int same_applied_metadata(const struct stat *left,
                                 const struct stat *right)
{
    return left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           same_timespec(left->st_atim, right->st_atim) &&
           same_timespec(left->st_mtim, right->st_mtim);
}

static ssize_t get_xattr_value(const char *path, const char *name,
                               void *value, size_t value_size, int nofollow)
{
    errno = 0;
    if (nofollow)
        return lgetxattr(path, name, value, value_size);
    return getxattr(path, name, value, value_size);
}

static int xattr_is_absent(const char *path, const char *name, int nofollow)
{
    ssize_t length = get_xattr_value(path, name, NULL, 0, nofollow);
    return length < 0 && errno == ENODATA;
}

static int xattr_value_equals(const char *path, const char *name,
                              const void *expected, size_t expected_length,
                              int nofollow)
{
    ssize_t length = get_xattr_value(path, name, NULL, 0, nofollow);
    if (length < 0 || (size_t)length != expected_length)
        return 0;
    if (expected_length == 0)
        return 1;

    unsigned char *value = malloc(expected_length);
    if (value == NULL)
        fatal("could not allocate xattr test buffer");
    ssize_t received = get_xattr_value(path, name, value, expected_length,
                                       nofollow);
    int matches = received == (ssize_t)expected_length &&
                  memcmp(value, expected, expected_length) == 0;
    free(value);
    return matches;
}

static size_t count_named_probe_entries(const char *root)
{
    DIR *dir = opendir(root);
    if (dir == NULL)
        fatal("could not scan the xattr probe fixture root");

    size_t count = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                closedir(dir);
                fatal("could not read the xattr probe fixture root");
            }
            break;
        }
        if (strncmp(entry->d_name, ".migr-xattr-probe-", 18) == 0)
            count++;
    }
    if (closedir(dir) != 0)
        fatal("could not close the xattr probe fixture root");
    return count;
}

static size_t count_entries(const char *root)
{
    DIR *dir = opendir(root);
    if (dir == NULL)
        fatal("could not scan the restore fixture root");

    size_t count = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                closedir(dir);
                fatal("could not read the restore fixture root");
            }
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            count++;
    }
    if (closedir(dir) != 0)
        fatal("could not close the restore fixture root");
    return count;
}

static int make_shm_root(char *path, size_t path_size)
{
    int length = snprintf(path, path_size, "/dev/shm/migr_metadata_gate_XXXXXX");
    if (length < 0 || (size_t)length >= path_size)
        return 0;
    return mkdtemp(path) != NULL;
}

static void set_metadata(const char *path, mode_t mode,
                         const struct timespec times[2], int nofollow)
{
    if (nofollow)
    {
        if (utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) != 0)
            fatal("could not set symlink timestamps");
    }
    else if (utimensat(AT_FDCWD, path, times, 0) != 0)
        fatal("could not set fixture timestamps");

    if (!nofollow && chmod(path, mode & 07777) != 0)
        fatal("could not set fixture mode");
}

static int expected_object(MatrixKind kind, const struct stat *st)
{
    switch (kind)
    {
    case KIND_REGULAR:
        return S_ISREG(st->st_mode);
    case KIND_DIRECTORY:
        return S_ISDIR(st->st_mode);
    case KIND_SYMLINK:
        return S_ISLNK(st->st_mode);
    case KIND_FIFO:
        return S_ISFIFO(st->st_mode);
    case KIND_SOCKET:
        return S_ISSOCK(st->st_mode);
    case KIND_DEVICE:
        return S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode);
    }
    return 0;
}

static const struct timespec *times_for_kind(MatrixKind kind)
{
    switch (kind)
    {
    case KIND_REGULAR:
        return regular_times;
    case KIND_DIRECTORY:
        return directory_times;
    case KIND_SYMLINK:
        return symlink_times;
    case KIND_FIFO:
        return fifo_times;
    case KIND_SOCKET:
    case KIND_DEVICE:
        return NULL;
    }
    return NULL;
}

static int setup_case(const MatrixCase *test_case, const char *source_root,
                      char *source_path, size_t source_path_size)
{
    if (test_case->kind == KIND_DEVICE)
    {
        struct stat st;
        if (lstat("/dev/null", &st) != 0 || !S_ISCHR(st.st_mode))
            return 0;
        if (strlen("/dev/null") >= source_path_size)
            fatal("device fixture path is too long");
        memcpy(source_path, "/dev/null", sizeof("/dev/null"));
        return 1;
    }

    if (test_case->kind == KIND_SOCKET)
    {
        int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0)
        {
            if (errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT)
                return 0;
            fatal("could not create a socket fixture");
        }

        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        join_or_die(source_path, source_path_size, source_root, "entry");
        if (strlen(source_path) >= sizeof(address.sun_path))
        {
            close(socket_fd);
            fatal("socket fixture path is too long");
        }
        memcpy(address.sun_path, source_path, strlen(source_path) + 1);
        if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        {
            int saved_errno = errno;
            close(socket_fd);
            if (saved_errno == EPERM || saved_errno == EACCES ||
                saved_errno == EAFNOSUPPORT)
                return 0;
            fatal("could not bind the socket fixture");
        }
        if (close(socket_fd) != 0)
            fatal("could not close the socket fixture");
        return 1;
    }

    join_or_die(source_path, source_path_size, source_root, "entry");
    if (test_case->kind == KIND_DIRECTORY)
    {
        if (mkdir(source_path, 0755) != 0)
            fatal("could not create the directory fixture");
        char child_path[PATH_MAX];
        join_or_die(child_path, sizeof(child_path), source_path, "child.txt");
        write_file(child_path, "directory-child");
        if (chmod(child_path, 0640) != 0)
            fatal("could not set directory child mode");
    }
    else if (test_case->kind == KIND_REGULAR)
        write_file(source_path, "0123456789abcdef");
    else if (test_case->kind == KIND_SYMLINK)
    {
        if (symlink("target.txt", source_path) != 0)
            fatal("could not create the symlink fixture");
    }
    else if (test_case->kind == KIND_FIFO)
    {
        if (mkfifo(source_path, test_case->mode) != 0)
            fatal("could not create the FIFO fixture");
    }

    const struct timespec *times = times_for_kind(test_case->kind);
    if (times != NULL)
        set_metadata(source_path, test_case->mode, times,
                     test_case->kind == KIND_SYMLINK);
    return 1;
}

static int check_payload_shape(const MatrixCase *test_case,
                               const char *path, const struct stat *source_st,
                               const char *expected_target,
                               const char *case_name, const char *phase)
{
    struct stat actual;
    if (lstat(path, &actual) != 0)
    {
        check_result(0, case_name, phase);
        return 0;
    }

    char property[64];
    if (snprintf(property, sizeof(property), "%s object type", phase) < 0)
        fatal("could not format a test label");
    check_result(expected_object(test_case->kind, &actual), case_name, property);

    if (test_case->kind == KIND_REGULAR || test_case->kind == KIND_DIRECTORY ||
        test_case->kind == KIND_FIFO)
    {
        if (snprintf(property, sizeof(property), "%s mode", phase) < 0)
            fatal("could not format a test label");
        check_result(same_mode(&actual, source_st), case_name, property);

        if (snprintf(property, sizeof(property), "%s atime/mtime", phase) < 0)
            fatal("could not format a test label");
        check_result(same_core_times(&actual, source_st), case_name, property);
    }
    else if (test_case->kind == KIND_SYMLINK)
    {
        /*
         * docs/DECISIONS.md D17/D18: Linux readlinkat() has no no-atime
         * variant, so reading a source symlink may perturb its atime. The
         * contract asserts destination link times exactly; source-symlink
         * atime preservation is not promised.
         */
        if (snprintf(property, sizeof(property), "%s link target", phase) < 0)
            fatal("could not format a test label");
        char target[PATH_MAX];
        ssize_t length = readlink(path, target, sizeof(target));
        size_t expected_length = expected_target == NULL
                                     ? 0
                                     : strlen(expected_target);
        int target_matches = expected_target != NULL && length >= 0 &&
                             (size_t)length == expected_length &&
                             memcmp(target, expected_target, expected_length) == 0;
        check_result(target_matches, case_name, property);

        if (snprintf(property, sizeof(property), "%s link times", phase) < 0)
            fatal("could not format a test label");
        check_result(same_core_times(&actual, source_st), case_name, property);
    }

    return 1;
}

static void check_directory_child(const char *root, const char *case_name,
                                  const char *phase)
{
    char child_path[PATH_MAX];
    join_or_die(child_path, sizeof(child_path), root, "child.txt");
    char property[64];
    if (snprintf(property, sizeof(property), "%s child exists", phase) < 0)
        fatal("could not format a test label");
    check_result(file_equals(child_path, "directory-child"), case_name, property);
}

static void run_matrix_case(const MatrixCase *test_case)
{
    char base[PATH_MAX];
    char source_root[PATH_MAX];
    char capture_root[PATH_MAX];
    char restore_root[PATH_MAX];
    char source_path[PATH_MAX];
    char capture_path[PATH_MAX];
    char restore_path[PATH_MAX];
    char source_target[PATH_MAX];

    make_temp_root(base, sizeof(base));
    join_or_die(source_root, sizeof(source_root), base, "source");
    join_or_die(capture_root, sizeof(capture_root), base, "capture");
    join_or_die(restore_root, sizeof(restore_root), base, "restore");
    if (mkdir(source_root, 0700) != 0 ||
        mkdir(capture_root, 0700) != 0 ||
        mkdir(restore_root, 0700) != 0)
        fatal("could not create matrix roots");

    if (!setup_case(test_case, source_root, source_path, sizeof(source_path)))
    {
        skip_case(test_case->name,
                  test_case->kind == KIND_DEVICE
                      ? "device fixture /dev/null is unavailable"
                      : "Unix socket fixture is unavailable");
        remove_tree(base);
        return;
    }

    const char *expected_target = NULL;
    if (test_case->kind == KIND_SYMLINK)
    {
        read_link_target_or_die(source_path, source_target,
                                sizeof(source_target));
        expected_target = source_target;
    }
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        fatal("could not inspect the source fixture");

    int capture_fd = open_directory(capture_root);
    int capture_rc = backup_capture_at(&BACKUP_CTX, source_path,
                                       capture_fd, "entry");
    check_result(capture_rc == 0, test_case->name, "capture result");

    join_or_die(capture_path, sizeof(capture_path), capture_root, "entry");
    if (test_case->kind == KIND_SOCKET || test_case->kind == KIND_DEVICE)
    {
        errno = 0;
        check_result(lstat(capture_path, &source_st) != 0 && errno == ENOENT,
                     test_case->name, "capture skips without a destination");
        close(capture_fd);
    }
    else
    {
        check_payload_shape(test_case, capture_path, &source_st,
                            expected_target,
                            test_case->name, "capture");
        if (test_case->kind == KIND_DIRECTORY)
            check_directory_child(capture_path, test_case->name, "capture");

        if (test_case->kind == KIND_REGULAR)
        {
            write_file(capture_path, "fedcba9876543210");
            if (utimensat(AT_FDCWD, capture_path, regular_times, 0) != 0)
                fatal("could not prepare the capture resume fixture");
            int resume_fd = open_directory(capture_root);
            check_result(backup_capture_at(&BACKUP_CTX, source_path,
                                           resume_fd, "entry") == 0,
                         test_case->name, "capture resume result");
            close(resume_fd);
            check_result(file_equals(capture_path, "fedcba9876543210"),
                         test_case->name, "capture resume skips matching size/mtime");
        }
        else if (test_case->kind == KIND_SYMLINK)
        {
            struct stat reapply_source_st;
            if (lstat(source_path, &reapply_source_st) != 0)
                fatal("could not inspect the source before capture reapply");
            set_metadata(capture_path, 0777, regular_times, 1);
            if (backup_capture_at(&BACKUP_CTX, source_path, capture_fd,
                                  "entry") != 0)
                fatal("could not reapply capture symlink metadata");
            check_payload_shape(test_case, capture_path, &reapply_source_st,
                                expected_target, test_case->name,
                                "capture reapply");
        }
        close(capture_fd);
    }

    struct stat captured_st;
    if (test_case->kind != KIND_SOCKET && test_case->kind != KIND_DEVICE &&
        lstat(capture_path, &captured_st) != 0)
        fatal("could not inspect the captured fixture");

    const char *restore_source_root = capture_root;
    const char *restore_source_rel = "entry";
    if (test_case->kind == KIND_SOCKET || test_case->kind == KIND_DEVICE)
    {
        restore_source_root = test_case->kind == KIND_DEVICE ? "/dev" : source_root;
        restore_source_rel = test_case->kind == KIND_DEVICE ? "null" : "entry";
    }
    int restore_source_fd = open_directory(restore_source_root);
    int restore_fd = open_directory(restore_root);
    int restore_rc = restore_native_at(&RESTORE_CTX, restore_source_fd,
                                       restore_source_rel,
                                       restore_fd, "entry");
    check_result(restore_rc == 0, test_case->name, "restore result");
    close(restore_source_fd);
    close(restore_fd);

    join_or_die(restore_path, sizeof(restore_path), restore_root, "entry");
    if (test_case->kind == KIND_SOCKET || test_case->kind == KIND_DEVICE)
    {
        errno = 0;
        check_result(lstat(restore_path, &source_st) != 0 && errno == ENOENT,
                     test_case->name, "restore skips without a destination");
    }
    else
    {
        check_payload_shape(test_case, restore_path, &captured_st,
                            expected_target,
                            test_case->name, "restore");
        if (test_case->kind == KIND_DIRECTORY)
            check_directory_child(restore_path, test_case->name, "restore");

        if (test_case->kind == KIND_REGULAR)
        {
            write_file(restore_path, "0011223344556677");
            if (utimensat(AT_FDCWD, restore_path, regular_times, 0) != 0)
                fatal("could not prepare the restore resume fixture");
            int source_fd = open_directory(capture_root);
            int destination_fd = open_directory(restore_root);
            check_result(restore_native_at(&RESTORE_CTX, source_fd, "entry",
                                           destination_fd, "entry") == 0,
                         test_case->name, "restore resume result");
            close(source_fd);
            close(destination_fd);
            check_result(file_equals(restore_path, "0011223344556677"),
                         test_case->name, "restore resume skips matching size/mtime");
        }
        else if (test_case->kind == KIND_SYMLINK)
        {
            struct stat before, after;
            char before_target[PATH_MAX];
            char after_target[PATH_MAX];
            read_link_target_or_die(restore_path, before_target,
                                    sizeof(before_target));
            if (lstat(restore_path, &before) != 0)
                fatal("could not inspect the restored symlink before refusal");
            int source_fd = open_directory(capture_root);
            int destination_fd = open_directory(restore_root);
            check_result(restore_native_at(&RESTORE_CTX, source_fd, "entry",
                                           destination_fd, "entry") != 0,
                         test_case->name,
                         "restore refuses an existing final symlink");
            close(source_fd);
            close(destination_fd);
            if (lstat(restore_path, &after) != 0)
                fatal("could not inspect the restored symlink after refusal");
            read_link_target_or_die(restore_path, after_target,
                                    sizeof(after_target));
            check_result(before.st_dev == after.st_dev &&
                             before.st_ino == after.st_ino &&
                             same_core_times(&before, &after),
                         test_case->name,
                         "restore refusal leaves symlink metadata untouched");
            check_result(strcmp(before_target, after_target) == 0,
                         test_case->name,
                         "restore refusal leaves symlink target untouched");
        }
    }

    remove_tree(base);
}

static void test_foreign_ownership_gap(void)
{
    const char *case_name = "foreign";
    if (geteuid() != 0)
    {
        skip_case(case_name, "requires root to create a foreign-owned fixture");
        return;
    }

    char base[PATH_MAX], source_root[PATH_MAX], capture_root[PATH_MAX];
    char restore_root[PATH_MAX], source_path[PATH_MAX], capture_path[PATH_MAX];
    char restore_path[PATH_MAX];
    make_temp_root(base, sizeof(base));
    join_or_die(source_root, sizeof(source_root), base, "source");
    join_or_die(capture_root, sizeof(capture_root), base, "capture");
    join_or_die(restore_root, sizeof(restore_root), base, "restore");
    if (mkdir(source_root, 0700) != 0 || mkdir(capture_root, 0700) != 0 ||
        mkdir(restore_root, 0700) != 0)
        fatal("could not create the ownership roots");
    join_or_die(source_path, sizeof(source_path), source_root, "entry");
    write_file(source_path, "foreign-owner");
    if (chown(source_path, 65534, 65534) != 0)
    {
        skip_case(case_name, "foreign uid/gid cannot be created on this host");
        remove_tree(base);
        return;
    }

    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        fatal("could not inspect the foreign-owned source");
    if (source_st.st_uid == geteuid() || source_st.st_gid == getegid())
    {
        skip_case(case_name, "fixture ownership did not become foreign");
        remove_tree(base);
        return;
    }

    int capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&BACKUP_CTX, source_path,
                                   capture_fd, "entry") == 0,
                 case_name, "capture result");
    close(capture_fd);
    join_or_die(capture_path, sizeof(capture_path), capture_root, "entry");
    struct stat captured_st;
    if (lstat(capture_path, &captured_st) != 0)
        fatal("could not inspect the captured ownership fixture");
    check_result(captured_st.st_uid == source_st.st_uid &&
                 captured_st.st_gid == source_st.st_gid,
                 case_name, "capture preserves uid/gid");

    int source_fd = open_directory(source_root);
    int restore_fd = open_directory(restore_root);
    check_result(restore_native_at(&RESTORE_CTX, source_fd, "entry",
                                   restore_fd, "entry") == 0,
                 case_name, "restore result");
    close(source_fd);
    close(restore_fd);
    join_or_die(restore_path, sizeof(restore_path), restore_root, "entry");
    struct stat restored_st;
    if (lstat(restore_path, &restored_st) != 0)
        fatal("could not inspect the restored ownership fixture");
    check_result(restored_st.st_uid == source_st.st_uid &&
                 restored_st.st_gid == source_st.st_gid,
                 case_name, "restore preserves uid/gid");

    remove_tree(base);
}

static void test_native_xattrs_captured(void)
{
    const char *case_name = "xattr";
    char base[PATH_MAX], source_root[PATH_MAX], capture_root[PATH_MAX];
    char restore_root[PATH_MAX], source_path[PATH_MAX], capture_path[PATH_MAX];
    char restore_path[PATH_MAX];
    char source_dir[PATH_MAX], capture_dir[PATH_MAX], restore_dir[PATH_MAX];
    char source_link[PATH_MAX], capture_link[PATH_MAX], restore_link[PATH_MAX];
    make_temp_root(base, sizeof(base));
    join_or_die(source_root, sizeof(source_root), base, "source");
    join_or_die(capture_root, sizeof(capture_root), base, "capture");
    join_or_die(restore_root, sizeof(restore_root), base, "restore");
    if (mkdir(source_root, 0700) != 0 || mkdir(capture_root, 0700) != 0 ||
        mkdir(restore_root, 0700) != 0)
        fatal("could not create the xattr roots");
    join_or_die(source_path, sizeof(source_path), source_root, "entry");
    write_file(source_path, "has-an-xattr");
    if (setxattr(source_path, "user.migr_test", "value", 5, 0) != 0)
    {
        if (errno == ENOTSUP || errno == EOPNOTSUPP ||
            errno == EPERM || errno == EACCES)
        {
            skip_case(case_name, "this filesystem does not support user xattrs");
            remove_tree(base);
            return;
        }
        fatal("could not create the xattr fixture");
    }
    unsigned int source_namespaces = 0;
    if (metadata_xattr_namespaces_path(source_path, &source_namespaces) != 0)
        fatal("could not inspect the xattr fixture namespaces");
    if ((source_namespaces & METADATA_XATTR_NS_SECURITY) != 0)
    {
        skip_case(case_name,
                  "automatic security labels are outside this xattr round-trip fixture");
        remove_tree(base);
        return;
    }

    int capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&BACKUP_CTX, source_path,
                                   capture_fd, "entry") == 0,
                 case_name, "capture result");
    close(capture_fd);
    join_or_die(capture_path, sizeof(capture_path), capture_root, "entry");
    check_result(xattr_value_equals(capture_path, "user.migr_test", "value", 5,
                                    0),
                 case_name, "fresh regular capture preserves xattr value");

    if (setxattr(source_path, "user.migr_other", "stale", 5, 0) != 0)
        fatal("could not create the second xattr fixture");
    capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&BACKUP_CTX, source_path,
                                   capture_fd, "entry") == 0,
                 case_name, "regular capture adds a second xattr");
    close(capture_fd);
    check_result(xattr_value_equals(capture_path, "user.migr_other", "stale", 5,
                                    0),
                 case_name, "fresh regular capture preserves all xattrs");

    if (removexattr(source_path, "user.migr_other") != 0)
        fatal("could not remove the source xattr fixture");
    capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&BACKUP_CTX, source_path,
                                   capture_fd, "entry") == 0,
                 case_name, "resume capture reconciles removed xattr");
    close(capture_fd);
    check_result(xattr_is_absent(capture_path, "user.migr_other", 0), case_name,
                 "resume capture removes a stale destination xattr");

    if (setxattr(source_path, "user.migr_test", "changed", 7, 0) != 0)
        fatal("could not change the source xattr fixture");
    capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&BACKUP_CTX, source_path,
                                   capture_fd, "entry") == 0,
                 case_name, "resume capture reconciles changed xattr");
    close(capture_fd);
    check_result(xattr_value_equals(capture_path, "user.migr_test", "changed", 7,
                                    0),
                 case_name, "resume capture updates a changed xattr value");

    int source_fd = open_directory(capture_root);
    int restore_fd = open_directory(restore_root);
    check_result(restore_native_at(&RESTORE_CTX, source_fd, "entry",
                                   restore_fd, "entry") == 0,
                 case_name, "restore result");
    close(source_fd);
    close(restore_fd);
    join_or_die(restore_path, sizeof(restore_path), restore_root, "entry");
    check_result(xattr_value_equals(restore_path, "user.migr_test", "changed",
                                    7, 0),
                 case_name, "native restore applies payload xattr value");

    if (setxattr(restore_path, "user.migr_stale", "stale", 5, 0) != 0)
        fatal("could not create the stale restore xattr fixture");
    source_fd = open_directory(capture_root);
    restore_fd = open_directory(restore_root);
    check_result(restore_native_at(&RESTORE_CTX, source_fd, "entry",
                                   restore_fd, "entry") == 0,
                 case_name, "restore removes a stale destination xattr");
    close(source_fd);
    close(restore_fd);
    check_result(xattr_is_absent(restore_path, "user.migr_stale", 0), case_name,
                 "native restore removes a stale xattr");

    if (setxattr(restore_path, "user.migr_test", "destination", 11, 0) != 0)
        fatal("could not change the destination xattr fixture");
    source_fd = open_directory(capture_root);
    restore_fd = open_directory(restore_root);
    check_result(restore_native_at(&RESTORE_CTX, source_fd, "entry",
                                   restore_fd, "entry") == 0,
                 case_name, "restore updates a changed destination xattr");
    close(source_fd);
    close(restore_fd);
    check_result(xattr_value_equals(restore_path, "user.migr_test", "changed",
                                    7, 0),
                 case_name, "native restore updates a changed xattr value");

    join_or_die(source_dir, sizeof(source_dir), source_root, "directory");
    join_or_die(capture_dir, sizeof(capture_dir), capture_root, "directory");
    join_or_die(restore_dir, sizeof(restore_dir), restore_root, "directory");
    if (mkdir(source_dir, 0700) != 0)
        fatal("could not create the directory xattr fixture");
    char child_path[PATH_MAX];
    join_or_die(child_path, sizeof(child_path), source_dir, "child");
    write_file(child_path, "directory-xattr-child");
    if (setxattr(source_dir, "user.migr_directory", "directory", 9, 0) != 0)
    {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM ||
            errno == EACCES)
            skip_case(case_name, "directory user xattrs are unavailable");
        else
            fatal("could not create the directory xattr fixture");
    }
    else
    {
        capture_fd = open_directory(capture_root);
        check_result(backup_capture_at(&BACKUP_CTX, source_dir,
                                       capture_fd, "directory") == 0,
                     case_name, "directory capture result");
        close(capture_fd);
        check_result(xattr_value_equals(capture_dir, "user.migr_directory",
                                        "directory", 9, 0),
                     case_name, "directory capture preserves xattr value");
        source_fd = open_directory(capture_root);
        restore_fd = open_directory(restore_root);
        check_result(restore_native_at(&RESTORE_CTX, source_fd, "directory",
                                       restore_fd, "directory") == 0,
                     case_name, "directory restore result");
        close(source_fd);
        close(restore_fd);
        check_result(xattr_value_equals(restore_dir, "user.migr_directory",
                                        "directory", 9, 0),
                     case_name, "directory restore applies xattr value");
    }

    join_or_die(source_link, sizeof(source_link), source_root, "link");
    join_or_die(capture_link, sizeof(capture_link), capture_root, "link");
    join_or_die(restore_link, sizeof(restore_link), restore_root, "link");
    if (symlink("target.txt", source_link) != 0)
        fatal("could not create the symlink xattr fixture");
    if (lsetxattr(source_link, "user.migr_symlink", "symlink", 7, 0) != 0)
    {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM ||
            errno == EACCES)
            skip_case(case_name, "symlink user xattrs are unavailable");
        else
            fatal("could not create the symlink xattr fixture");
    }
    else
    {
        capture_fd = open_directory(capture_root);
        check_result(backup_capture_at(&BACKUP_CTX, source_link,
                                       capture_fd, "link") == 0,
                     case_name, "symlink capture result");
        close(capture_fd);
        check_result(xattr_value_equals(capture_link, "user.migr_symlink",
                                        "symlink", 7, 1),
                     case_name, "symlink capture preserves xattr value");
        source_fd = open_directory(capture_root);
        restore_fd = open_directory(restore_root);
        check_result(restore_native_at(&RESTORE_CTX, source_fd, "link",
                                       restore_fd, "link") == 0,
                     case_name, "symlink restore result");
        close(source_fd);
        close(restore_fd);
        check_result(xattr_value_equals(restore_link, "user.migr_symlink",
                                        "symlink", 7, 1),
                     case_name, "symlink restore applies xattr value");
    }

    remove_tree(base);
}

static void test_capture_recopies_without_nsec_exact(void)
{
    const char *case_name = "coarse";
    char base[PATH_MAX], source_root[PATH_MAX], capture_root[PATH_MAX];
    char source_path[PATH_MAX], capture_path[PATH_MAX];
    make_temp_root(base, sizeof(base));
    join_or_die(source_root, sizeof(source_root), base, "source");
    join_or_die(capture_root, sizeof(capture_root), base, "capture");
    if (mkdir(source_root, 0700) != 0 || mkdir(capture_root, 0700) != 0)
        fatal("could not create the coarse timestamp roots");
    join_or_die(source_path, sizeof(source_path), source_root, "entry");
    join_or_die(capture_path, sizeof(capture_path), capture_root, "entry");
    write_file(source_path, "0123456789abcdef");
    set_metadata(source_path, 0600, regular_times, 0);

    const CloneContext coarse_ctx = {
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 0,
        .metadata_preflight_done = 1
    };
    int capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&coarse_ctx, source_path, capture_fd,
                                   "entry") == 0,
                 case_name, "initial capture result");
    close(capture_fd);

    write_file(capture_path, "fedcba9876543210");
    if (utimensat(AT_FDCWD, capture_path, regular_times, 0) != 0)
        fatal("could not prepare the coarse resume fixture");

    capture_fd = open_directory(capture_root);
    check_result(backup_capture_at(&coarse_ctx, source_path, capture_fd,
                                   "entry") == 0,
                 case_name, "coarse resume capture result");
    close(capture_fd);
    check_result(file_equals(capture_path, "0123456789abcdef"), case_name,
                 "coarse timestamp policy recopies same-size content");
    remove_tree(base);
}

static void test_metadata_helper_failure_paths(void)
{
    const char *case_name = "helpers";
    char base[PATH_MAX];
    make_temp_root(base, sizeof(base));

    char file_path[PATH_MAX];
    join_or_die(file_path, sizeof(file_path), base, "file");
    write_file(file_path, "metadata-helper");

    int root_fd = open_directory(base);
    struct stat st;
    if (fstat(root_fd, &st) != 0)
        fatal("could not inspect the helper fixture root");
    MetadataTimestampPolicy policy = { .nsec_exact = 1, .configured = 1 };

    check_result(metadata_apply_fd(-1, &st, policy) == -1,
                 case_name, "apply rejects an invalid fd");
    check_result(metadata_apply_fd(root_fd, NULL, policy) == -1,
                 case_name, "apply rejects a NULL desired stat");
    check_result(metadata_apply_symlink_at(-1, "file", &st, policy) == -1,
                 case_name, "symlink apply rejects an invalid directory fd");
    check_result(metadata_profiles_probe(NULL, policy) == -1,
                 case_name, "profile probe rejects a NULL profile set");

    MetadataProfiles profiles;
    metadata_profiles_init(&profiles);
    check_result(metadata_profiles_add(&profiles, -1, &st, NULL, NULL) == -1,
                 case_name, "profile collection rejects an invalid anchor fd");
    check_result(metadata_profiles_probe(&profiles, policy) == 0,
                 case_name, "an empty profile set needs no live probe");

    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);
    check_result(metadata_snapshot_record(&snapshots, &st) == 0,
                 case_name, "snapshot records a stat");
    check_result(metadata_snapshot_find(&snapshots, &st) != NULL,
                 case_name, "snapshot lookup finds the recorded object");
    check_result(metadata_snapshot_matches(metadata_snapshot_find(&snapshots, &st),
                                           &st),
                 case_name, "snapshot matches unchanged metadata");
    check_result(metadata_source_unchanged(&st, &st),
                 case_name, "source comparison accepts identical stats");

    metadata_snapshots_free(&snapshots);
    metadata_profiles_free(&profiles);
    check_result(close(root_fd) == 0, case_name, "helper fixture fd closes cleanly");
    remove_tree(base);
}

static int xattr_probe_fixture_unavailable(int value)
{
    return value == EINVAL || value == ENOTSUP || value == EOPNOTSUPP ||
           value == ENOSYS || value == EPERM || value == EACCES;
}

static void test_metadata_xattr_capability_probe(void)
{
    const char *case_name = "xattr-gate";
    char base[PATH_MAX];
    if (!make_shm_root(base, sizeof(base)))
    {
        skip_case(case_name, "a private tmpfs fixture is unavailable");
        return;
    }
    int root_fd = open_directory(base);

    MetadataXattrRequirements none = {0};
    check_result(metadata_xattr_capability_probe(root_fd, &none) == 0,
                 case_name, "no namespace flags are a true no-op");
    check_result(count_named_probe_entries(base) == 0,
                 case_name, "the no-op gate creates no scratch entry");

    const struct {
        const char *label;
        MetadataXattrRequirements required;
    } kinds[] = {
        { "regular user namespace", {
            .regular_namespaces = METADATA_XATTR_NS_USER
        } },
        { "directory user namespace", {
            .directory_namespaces = METADATA_XATTR_NS_USER
        } },
        { "symlink user namespace", {
            .symlink_namespaces = METADATA_XATTR_NS_USER
        } }
    };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
    {
        errno = 0;
        int result = metadata_xattr_capability_probe(root_fd,
                                                     &kinds[i].required);
        int saved_errno = errno;
        if (result != 0 && xattr_probe_fixture_unavailable(saved_errno))
            skip_case(case_name, kinds[i].label);
        else
            check_result(result == 0, case_name, kinds[i].label);
        check_result(count_named_probe_entries(base) == 0,
                     case_name, "the kind probe leaves no scratch entry");
    }

    check_result(close(root_fd) == 0, case_name,
                 "the capability fixture fd closes cleanly");
    remove_tree(base);
}

static void test_metadata_xattr_gate_no_unrelated_namespace(void)
{
    const char *case_name = "xattr-regression";
    char base[PATH_MAX];
    if (!make_shm_root(base, sizeof(base)))
    {
        skip_case(case_name, "a private tmpfs fixture is unavailable");
        return;
    }

    char source_root[PATH_MAX], destination_root[PATH_MAX];
    char source_path[PATH_MAX], destination_path[PATH_MAX];
    join_or_die(source_root, sizeof(source_root), base, "source");
    join_or_die(destination_root, sizeof(destination_root), base, "destination");
    if (mkdir(source_root, 0700) != 0 || mkdir(destination_root, 0700) != 0)
        fatal("could not create the xattr regression roots");
    join_or_die(source_path, sizeof(source_path), source_root, "entry");
    join_or_die(destination_path, sizeof(destination_path), destination_root,
                "entry");
    write_file(source_path, "xattr-regression");

    unsigned int namespaces = 0;
    if (metadata_xattr_namespaces_path(source_path, &namespaces) != 0)
        fatal("could not inspect the xattr regression source");
    if ((namespaces & (METADATA_XATTR_NS_SYSTEM |
                       METADATA_XATTR_NS_TRUSTED)) != 0)
    {
        skip_case(case_name,
                  "the fixture carries an unprobeable non-security namespace");
        remove_tree(base);
        return;
    }
    if ((namespaces & METADATA_XATTR_NS_SECURITY) == 0)
    {
        if (setxattr(source_path, "user.migr_regression", "user", 4, 0) != 0)
        {
            if (xattr_probe_fixture_unavailable(errno))
                skip_case(case_name, "user xattrs are unavailable");
            else
                fatal("could not create the user-only regression fixture");
            remove_tree(base);
            return;
        }
        if (metadata_xattr_namespaces_path(source_path, &namespaces) != 0)
            fatal("could not inspect the user-only regression source");
    }

    int source_fd = open_directory(source_root);
    int destination_fd = open_directory(destination_root);
    RestoreNativeReport report;
    RestoreNativeStatus result = restore_native_at_report(
        &RESTORE_CTX, source_fd, "entry", destination_fd, "entry", &report);
    check_result(result == RESTORE_NATIVE_OK, case_name,
                 (namespaces & METADATA_XATTR_NS_SECURITY) != 0
                     ? "security-only payload is not refused by the capability gate"
                     : "user-only payload succeeds without unrelated namespace probing");
    check_result(file_equals(destination_path, "xattr-regression"), case_name,
                 "the regression payload is restored");
    check_result(report.failed_count == 0 && report.applied_count > 0,
                 case_name, "the regression report is successful");
    close(source_fd);
    close(destination_fd);
    remove_tree(base);
}

static void test_metadata_apply_xattrs_tolerates_foreign_security(void)
{
    const char *case_name = "xattr-security-tolerance";
    char base[PATH_MAX];
    if (!make_shm_root(base, sizeof(base)))
    {
        skip_case(case_name, "a private tmpfs fixture is unavailable");
        return;
    }

    char path[PATH_MAX];
    join_or_die(path, sizeof(path), base, "entry");
    write_file(path, "security-tolerance");

    unsigned int namespaces = 0;
    if (metadata_xattr_namespaces_path(path, &namespaces) != 0)
        fatal("could not inspect the security-tolerance fixture");
    if ((namespaces & METADATA_XATTR_NS_SECURITY) == 0)
    {
        skip_case(case_name,
                  "the destination does not auto-assign a security.* xattr");
        remove_tree(base);
        return;
    }

    unsigned char label[256];
    ssize_t label_length = get_xattr_value(path, "security.selinux", label,
                                           sizeof(label), 0);
    if (label_length < 0)
        fatal("could not read the auto-assigned security label");

    /* An empty target set (SidecarXattr count 0) is exactly what a payload
     * captured on a non-SELinux source looks like: no security.* entry at
     * all. Applying it must not fail just because the destination's LSM
     * auto-assigned a security.selinux label this call didn't ask for and
     * can't remove without privilege -- it must tolerate that, not refuse
     * the whole entry (this is the exact regression E.3a's own tests hit
     * on an SELinux-enabled host before metadata_apply_xattrs_target
     * learned to tolerate EACCES/EPERM specifically for security.*). */
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        fatal("could not open the security-tolerance fixture");
    check_result(metadata_apply_xattrs_fd(fd, NULL, 0) == 0, case_name,
                 "applying an empty xattr set tolerates an unremovable "
                 "auto-assigned security.* attribute");
    check_result(xattr_value_equals(path, "security.selinux", label,
                                    (size_t)label_length, 0),
                 case_name,
                 "the untouched security.* attribute keeps its original value");
    close(fd);
    remove_tree(base);
}

static void test_metadata_xattr_gate_trusted_refusal(void)
{
    const char *case_name = "xattr-trusted";
    if (geteuid() == 0)
    {
        skip_case(case_name, "trusted namespace refusal needs a non-root process");
        return;
    }

    char base[PATH_MAX];
    if (!make_shm_root(base, sizeof(base)))
    {
        skip_case(case_name, "a private tmpfs fixture is unavailable");
        return;
    }
    char source_root[PATH_MAX], destination_root[PATH_MAX];
    char source_path[PATH_MAX], sentinel_path[PATH_MAX];
    join_or_die(source_root, sizeof(source_root), base, "source");
    join_or_die(destination_root, sizeof(destination_root), base, "destination");
    if (mkdir(source_root, 0700) != 0 || mkdir(destination_root, 0700) != 0)
        fatal("could not create the trusted xattr roots");
    join_or_die(source_path, sizeof(source_path), source_root, "entry");
    join_or_die(sentinel_path, sizeof(sentinel_path), destination_root,
                "sentinel");
    write_file(source_path, "trusted-payload");
    if (setxattr(source_path, "trusted.migr_test", "trusted", 7, 0) != 0)
    {
        if (xattr_probe_fixture_unavailable(errno))
            skip_case(case_name, "trusted xattrs are unavailable");
        else
            fatal("could not create the trusted xattr fixture");
        remove_tree(base);
        return;
    }
    unsigned int source_namespaces = 0;
    if (metadata_xattr_namespaces_path(source_path, &source_namespaces) != 0)
        fatal("could not inspect the trusted xattr fixture");
    if ((source_namespaces & METADATA_XATTR_NS_TRUSTED) == 0)
    {
        skip_case(case_name,
                  "the trusted fixture was not retained by the filesystem");
        remove_tree(base);
        return;
    }

    int destination_fd = open_directory(destination_root);
    MetadataXattrRequirements required = {
        .regular_namespaces = METADATA_XATTR_NS_TRUSTED
    };
    errno = 0;
    int probe_result = metadata_xattr_capability_probe(destination_fd, &required);
    int probe_errno = errno;
    if (probe_result == 0)
    {
        skip_case(case_name, "the destination supports trusted xattrs");
        close(destination_fd);
        remove_tree(base);
        return;
    }
    if (!xattr_probe_fixture_unavailable(probe_errno))
        fatal("trusted capability probe failed unexpectedly");

    write_file(sentinel_path, "untouched");
    size_t before_entries = count_entries(destination_root);
    int source_fd = open_directory(source_root);
    RestoreNativeReport report;
    RestoreNativeStatus result = restore_native_at_report(
        &RESTORE_CTX, source_fd, "entry", destination_fd, "entry", &report);
    check_result(result != RESTORE_NATIVE_OK, case_name,
                 "unsupported trusted namespace refuses restore");
    check_result(count_entries(destination_root) == before_entries, case_name,
                 "trusted refusal creates no destination entry");
    check_result(file_equals(sentinel_path, "untouched"), case_name,
                 "trusted refusal leaves the sentinel untouched");
    close(source_fd);
    close(destination_fd);
    remove_tree(base);
}

static void test_metadata_apply_split_equivalence(void)
{
    const char *case_name = "split";
    char base[PATH_MAX], file_legacy[PATH_MAX], file_split[PATH_MAX];
    char link_legacy[PATH_MAX], link_split[PATH_MAX];
    make_temp_root(base, sizeof(base));
    join_or_die(file_legacy, sizeof(file_legacy), base, "file-legacy");
    join_or_die(file_split, sizeof(file_split), base, "file-split");
    join_or_die(link_legacy, sizeof(link_legacy), base, "link-legacy");
    join_or_die(link_split, sizeof(link_split), base, "link-split");

    write_file(file_legacy, "split-equivalence");
    write_file(file_split, "split-equivalence");
    set_metadata(file_legacy, 0640, regular_times, 0);
    set_metadata(file_split, 0640, regular_times, 0);
    if (symlink("split-target", link_legacy) != 0 ||
        symlink("split-target", link_split) != 0)
        fatal("could not create split-equivalence symlinks");
    set_metadata(link_legacy, 0777, symlink_times, 1);
    set_metadata(link_split, 0777, symlink_times, 1);

    struct stat desired_file, desired_link;
    if (lstat(file_legacy, &desired_file) != 0 ||
        lstat(link_legacy, &desired_link) != 0)
        fatal("could not inspect split-equivalence fixtures");

    MetadataTimestampPolicy policy = { .nsec_exact = 1, .configured = 1 };
    int file_legacy_fd = open(file_legacy, O_RDWR | O_CLOEXEC);
    int file_split_fd = open(file_split, O_RDWR | O_CLOEXEC);
    if (file_legacy_fd < 0 || file_split_fd < 0)
        fatal("could not open split-equivalence files");
    check_result(metadata_apply_fd(file_legacy_fd, &desired_file, policy) == 0,
                 case_name, "fd wrapper result");
    check_result(metadata_apply_ownership_and_mode_fd(file_split_fd,
                                                      &desired_file) == 0 &&
                 metadata_apply_times_fd(file_split_fd, &desired_file,
                                         policy) == 0,
                 case_name, "fd split result");
    if (close(file_legacy_fd) != 0 || close(file_split_fd) != 0)
        fatal("could not close split-equivalence files");

    struct stat file_legacy_st, file_split_st;
    if (lstat(file_legacy, &file_legacy_st) != 0 ||
        lstat(file_split, &file_split_st) != 0)
        fatal("could not inspect split-equivalence file results");
    check_result(same_applied_metadata(&file_legacy_st, &file_split_st),
                 case_name, "fd results are equivalent");

    int root_fd = open_directory(base);
    check_result(metadata_apply_symlink_at(root_fd, "link-legacy", &desired_link,
                                           policy) == 0,
                 case_name, "symlink wrapper result");
    check_result(metadata_apply_symlink_ownership_at(root_fd, "link-split",
                                                     &desired_link) == 0 &&
                 metadata_apply_symlink_times_at(root_fd, "link-split",
                                                 &desired_link, policy) == 0,
                 case_name, "symlink split result");
    if (close(root_fd) != 0)
        fatal("could not close split-equivalence root");

    struct stat link_legacy_st, link_split_st;
    if (lstat(link_legacy, &link_legacy_st) != 0 ||
        lstat(link_split, &link_split_st) != 0)
        fatal("could not inspect split-equivalence symlink results");
    check_result(same_applied_metadata(&link_legacy_st, &link_split_st),
                 case_name, "symlink results are equivalent");

    remove_tree(base);
}

int main(void)
{
    printf(BLUE "::" NC " native file-kind metadata contract (entry gate)\n");

    static const MatrixCase cases[] = {
        { "regular", KIND_REGULAR, 0640 },
        { "directory", KIND_DIRECTORY, 0750 },
        { "symlink", KIND_SYMLINK, 0777 },
        { "fifo", KIND_FIFO, 0620 },
        { "socket", KIND_SOCKET, 0600 },
        { "device", KIND_DEVICE, 0600 }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        run_matrix_case(&cases[i]);
    test_capture_recopies_without_nsec_exact();
    test_metadata_helper_failure_paths();
    test_metadata_xattr_capability_probe();
    test_metadata_xattr_gate_no_unrelated_namespace();
    test_metadata_apply_xattrs_tolerates_foreign_security();
    test_metadata_xattr_gate_trusted_refusal();
    test_metadata_apply_split_equivalence();
    test_foreign_ownership_gap();
    test_native_xattrs_captured();

    if (failures != 0)
    {
        printf(RED "%d metadata contract test(s) failed" NC "\n", failures);
        return 1;
    }
    printf(GREEN "metadata contract passed" NC " (%d skipped)\n", skips);
    return 0;
}
