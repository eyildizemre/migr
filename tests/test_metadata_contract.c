// Unit tests pinning down the current paired capture/restore metadata contract
// (docs/DECISIONS.md D17) for every file kind -- regular files, directories,
// symlinks, FIFOs, sockets, and device nodes -- as a fixed baseline before any
// behaviour change, exercised through the real backup_capture_at() and
// restore_native_at() entry points rather than a synthetic stand-in.
//
// Regular file and directory capture, and regular/FIFO restore, assert exact
// mode and atime/mtime. Directory and symlink restore compare mtime only, on
// purpose: restore_entry_at()'s directory branch always recurses during
// RESTORE_VALIDATE (unlike the FIFO/regular branches, which return before
// touching content), so its own readdir() perturbs the source's atime before
// RESTORE_APPLY takes its metadata snapshot -- restored directory (and
// symlink) atime is not currently exact. This is a real gap in the as-built
// native path, not a weak assertion: docs/DECISIONS.md D17's "Source and
// restore safety" section requires O_NOATIME only on capture's reads, not on
// restore's own traversal of the payload it is restoring from. Tracked there
// as a follow-up fix for the native metadata-fidelity work, rather than
// silently asserted around here.
//
// The regular-file cases also cover resume-skip (matching size+mtime_sec keeps
// existing destination content) on both the capture and restore sides. The
// foreign-ownership case documents today's known loss -- a non-self uid/gid is
// not preserved -- rather than fixing it; the native metadata-fidelity work
// that follows is where that gets a preflight.

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
#include <time.h>
#include <unistd.h>

#include "fileops.h"
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

static int same_timespec(struct timespec left, struct timespec right)
{
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static int same_core_times(const struct stat *actual, const struct stat *expected)
{
    return same_timespec(actual->st_atim, expected->st_atim) &&
           same_timespec(actual->st_mtim, expected->st_mtim);
}

static int same_mtime(const struct stat *actual, const struct stat *expected)
{
    return same_timespec(actual->st_mtim, expected->st_mtim);
}

static int same_mode(const struct stat *actual, const struct stat *expected)
{
    return (actual->st_mode & 07777) == (expected->st_mode & 07777);
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
                               const char *case_name, const char *phase,
                               int compare_atime)
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

        if (snprintf(property, sizeof(property), "%s %s", phase,
                     compare_atime ? "atime/mtime" : "mtime") < 0)
            fatal("could not format a test label");
        check_result((compare_atime ? same_core_times(&actual, source_st)
                                    : same_mtime(&actual, source_st)),
                     case_name, property);
    }
    else if (test_case->kind == KIND_SYMLINK)
    {
        if (snprintf(property, sizeof(property), "%s link target", phase) < 0)
            fatal("could not format a test label");
        char target[PATH_MAX];
        ssize_t length = readlink(path, target, sizeof(target) - 1);
        if (length >= 0)
            target[length] = '\0';
        check_result(length == 10 && length >= 0 && strcmp(target, "target.txt") == 0,
                     case_name, property);

        if (snprintf(property, sizeof(property), "%s link %s", phase,
                     compare_atime ? "times" : "mtime") < 0)
            fatal("could not format a test label");
        check_result((compare_atime ? same_core_times(&actual, source_st)
                                    : same_mtime(&actual, source_st)),
                     case_name, property);
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
                            test_case->name, "capture", 1);
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
                            test_case->name, "restore",
                            test_case->kind == KIND_REGULAR ||
                            test_case->kind == KIND_FIFO);
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
    check_result(captured_st.st_uid != source_st.st_uid ||
                 captured_st.st_gid != source_st.st_gid,
                 case_name, "capture exposes current uid/gid loss");

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
    check_result(restored_st.st_uid != source_st.st_uid ||
                 restored_st.st_gid != source_st.st_gid,
                 case_name, "restore exposes current uid/gid loss");

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
    test_foreign_ownership_gap();

    if (failures != 0)
    {
        printf(RED "%d metadata contract test(s) failed" NC "\n", failures);
        return 1;
    }
    printf(GREEN "metadata contract passed" NC " (%d skipped)\n", skips);
    return 0;
}
