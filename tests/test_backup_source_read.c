// Source-safe-read refusal coverage for native backup metadata preflight and
// capture (docs/DECISIONS.md D17). The root-only cases use a dropped child
// identity so O_NOATIME receives a real kernel EPERM rather than a simulated
// status; ordinary users skip these privilege-dependent fixtures.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backup.h"
#include "fileops.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
#define NC    "\033[0m"

enum { CHILD_SKIP = 77 };

static int failures;
static int skips;

static int has_effective_cap_chown(void);
static int has_effective_cap_fowner(void);

static void check_result(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void skip_case(const char *label, const char *reason)
{
    printf("  " YELLOW "-" NC " %s skipped: %s\n", label, reason);
    skips++;
}

static void fatal(const char *message)
{
    printf(RED "fixture failure: %s" NC "\n", message);
    exit(2);
}

static int remove_callback(const char *path, const struct stat *st,
                           int typeflag, struct FTW *ftwbuf)
{
    (void)st;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_callback, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fatal("could not remove a fixture tree");
}

static void join_path(char *out, size_t out_size, const char *parent,
                      const char *name)
{
    int n = snprintf(out, out_size, "%s/%s", parent, name);
    if (n < 0 || (size_t)n >= out_size)
        fatal("fixture path is too long");
}

static void make_root(char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "/tmp/migr_backup_source_read_XXXXXX");
    if (n < 0 || (size_t)n >= out_size || mkdtemp(out) == NULL)
        fatal("could not create a fixture root");
    if (chmod(out, 0755) != 0)
        fatal("could not make the fixture root traversable");
}

static void make_directory(const char *path, uid_t uid, gid_t gid)
{
    if (mkdir(path, 0755) != 0)
        fatal("could not create a fixture directory");
    if (chown(path, uid, gid) != 0)
        fatal("could not assign fixture directory ownership");
}

static void write_file(const char *path, const char *contents,
                       uid_t uid, gid_t gid)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        fatal("could not create a fixture file");
    size_t length = strlen(contents);
    if (write(fd, contents, length) != (ssize_t)length || close(fd) != 0)
        fatal("could not write a fixture file");
    if (chown(path, uid, gid) != 0)
        fatal("could not assign fixture file ownership");
}

static void set_times(const char *path, struct timespec times[2])
{
    if (utimensat(AT_FDCWD, path, times, 0) != 0)
        fatal("could not set fixture timestamps");
}

static int same_times(const struct stat *left, const struct stat *right)
{
    return left->st_atim.tv_sec == right->st_atim.tv_sec &&
           left->st_atim.tv_nsec == right->st_atim.tv_nsec &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
}

static int directory_entry_count(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL)
        return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            count++;
    int close_status = closedir(dir);
    return close_status == 0 ? count : -1;
}

static int contains(const char *text, const char *needle)
{
    return text != NULL && needle != NULL && strstr(text, needle) != NULL;
}

static int count_occurrences(const char *text, const char *needle)
{
    int count = 0;
    size_t needle_length = strlen(needle);
    while (needle_length > 0 && (text = strstr(text, needle)) != NULL)
    {
        count++;
        text += needle_length;
    }
    return count;
}

static int drop_identity(uid_t uid, gid_t gid)
{
    return setgroups(0, NULL) == 0 && setgid(gid) == 0 && setuid(uid) == 0;
}

static int run_backup_as(const char *target, const char *home,
                         const char *source, uid_t uid, gid_t gid,
                         int require_no_cap_chown, char *output,
                         size_t output_size)
{
    int output_pipe[2];
    if (pipe(output_pipe) != 0)
        fatal("could not create the backup output pipe");

    pid_t child = fork();
    if (child < 0)
        fatal("could not fork the backup child");
    if (child == 0)
    {
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0)
            _exit(2);
        close(output_pipe[1]);
        if (!drop_identity(uid, gid) || setenv("HOME", home, 1) != 0 ||
            (require_no_cap_chown && has_effective_cap_chown()))
            _exit(CHILD_SKIP);
        dry_run = 0;
        char *paths[] = { (char *)source, NULL };
        int result = backup(target, BACKUP_EXPLICIT_PATHS, paths);
        fflush(stdout);
        _exit(result == 0 ? 0 : 1);
    }

    close(output_pipe[1]);
    size_t total = 0;
    while (total + 1 < output_size)
    {
        ssize_t received = read(output_pipe[0], output + total,
                                output_size - total - 1);
        if (received <= 0)
            break;
        total += (size_t)received;
    }
    output[total] = '\0';
    close(output_pipe[0]);

    int status = 0;
    if (waitpid(child, &status, 0) < 0)
        fatal("could not wait for the backup child");
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

typedef struct {
    int ready_fd;
    int release_fd;
    const char *pause_path;
} InventoryBarrier;

static void inventory_barrier_hook(const char *source_path, void *context)
{
    InventoryBarrier *barrier = context;
    if (barrier == NULL || strcmp(source_path, barrier->pause_path) != 0)
        return;

    char ready = 'r';
    char release;
    if (write(barrier->ready_fd, &ready, 1) != 1 ||
        read(barrier->release_fd, &release, 1) != 1)
        _exit(CHILD_SKIP);
}

static int run_backup_race(const char *target, const char *home,
                           const char *source, const char *pause_path,
                           uid_t uid, gid_t gid, char *output,
                           size_t output_size, struct stat *after)
{
    int ready[2], release[2], output_pipe[2];
    if (pipe(ready) != 0 || pipe(release) != 0 || pipe(output_pipe) != 0)
        fatal("could not create race pipes");

    InventoryBarrier barrier = {
        .ready_fd = ready[1],
        .release_fd = release[0],
        .pause_path = pause_path
    };
    backup_test_set_inventory_hook(inventory_barrier_hook, &barrier);

    pid_t child = fork();
    if (child < 0)
        fatal("could not fork the race child");
    if (child == 0)
    {
        close(ready[0]);
        close(release[1]);
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0)
            _exit(2);
        close(output_pipe[1]);
        if (!drop_identity(uid, gid) || setenv("HOME", home, 1) != 0)
            _exit(CHILD_SKIP);
        dry_run = 0;
        char *paths[] = { (char *)source, NULL };
        int result = backup(target, BACKUP_EXPLICIT_PATHS, paths);
        fflush(stdout);
        _exit(result == 0 ? 0 : 1);
    }

    close(ready[1]);
    close(release[0]);
    close(output_pipe[1]);
    char ready_byte;
    if (read(ready[0], &ready_byte, 1) != 1)
        fatal("inventory barrier was not reached");
    close(ready[0]);

    if (chown(pause_path, 0, 0) != 0)
        fatal("could not change the raced file owner");
    char release_byte = 'r';
    if (write(release[1], &release_byte, 1) != 1)
        fatal("could not release the inventory barrier");
    close(release[1]);

    size_t total = 0;
    while (total + 1 < output_size)
    {
        ssize_t received = read(output_pipe[0], output + total,
                                output_size - total - 1);
        if (received <= 0)
            break;
        total += (size_t)received;
    }
    output[total] = '\0';
    close(output_pipe[0]);

    int status = 0;
    if (waitpid(child, &status, 0) < 0)
        fatal("could not wait for the race child");
    if (stat(pause_path, after) != 0)
        fatal("could not stat the raced file after the inventory attempt");
    backup_test_set_inventory_hook(NULL, NULL);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int find_nobody(uid_t *uid, gid_t *gid)
{
    if (geteuid() != 0)
        return 0;
    struct passwd *nobody = getpwnam("nobody");
    if (nobody == NULL || nobody->pw_uid == 0)
        return 0;
    *uid = nobody->pw_uid;
    *gid = nobody->pw_gid;
    return 1;
}

static int has_effective_cap_chown(void)
{
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL)
        return 0;

    char line[128];
    unsigned long long effective = 0;
    while (fgets(line, sizeof(line), status) != NULL)
        if (sscanf(line, "CapEff: %llx", &effective) == 1)
            break;
    fclose(status);
    return (effective & 1ULL) != 0;
}

static int has_effective_cap_fowner(void)
{
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL)
        return 0;

    char line[128];
    unsigned long long effective = 0;
    while (fgets(line, sizeof(line), status) != NULL)
        if (sscanf(line, "CapEff: %llx", &effective) == 1)
            break;
    fclose(status);
    return (effective & (1ULL << 3)) != 0;
}

static void test_inventory_race(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " backup metadata preflight: ownership race becomes a source-safe-read refusal\n");

    char base[PATH_MAX], source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    char file[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(home, sizeof(home), base, "home");
    join_path(target, sizeof(target), base, "target");
    join_path(file, sizeof(file), source, "raced.txt");
    make_directory(source, uid, gid);
    make_directory(home, uid, gid);
    make_directory(target, uid, gid);
    write_file(file, "race", uid, gid);

    struct timespec times[2] = {
        { .tv_sec = 1700000101, .tv_nsec = 123456789 },
        { .tv_sec = 1700000202, .tv_nsec = 234567890 }
    };
    set_times(file, times);
    struct stat before, after;
    if (stat(file, &before) != 0)
        fatal("could not stat the raced file before backup");

    char output[32768];
    int result = run_backup_race(target, home, source, file, uid, gid,
                                 output, sizeof(output), &after);
    check_result(result == 1, "ownership change after lstat rejects the backup");
    check_result(contains(output, "could not safely read 1 source object(s)"),
                 "the race is reported as a source-safe-read refusal");
    check_result(contains(output, "no container was created"),
                 "the refusal occurs before container reservation");
    check_result(directory_entry_count(target) == 0,
                 "the destination has no container after the refusal");
    check_result(same_times(&before, &after),
                 "the refused O_NOATIME read leaves source atime/mtime unchanged");

    remove_tree(base);
}

static void test_bounded_examples(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " backup metadata preflight: refusal examples remain bounded\n");

    char base[PATH_MAX], source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(home, sizeof(home), base, "home");
    join_path(target, sizeof(target), base, "target");
    make_directory(source, uid, gid);
    make_directory(home, uid, gid);
    make_directory(target, uid, gid);
    for (int i = 0; i < 20; i++)
    {
        char path[PATH_MAX];
        char name[32];
        snprintf(name, sizeof(name), "foreign-%02d", i);
        join_path(path, sizeof(path), source, name);
        write_file(path, "x", 0, 0);
    }

    char output[65536];
    int result = run_backup_as(target, home, source, uid, gid, 0,
                               output, sizeof(output));
    check_result(result == 1, "foreign regular files reject the backup");
    check_result(contains(output, "could not safely read 20 source object(s)"),
                 "the refusal count includes every foreign file");
    check_result(count_occurrences(output, "source-read example:") == 16,
                 "only sixteen source-read examples are printed");
    check_result(directory_entry_count(target) == 0,
                 "bounded-example refusal leaves no container");
    remove_tree(base);
}

static void test_uninspected_subtree(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " backup metadata preflight: foreign directories are unknown subtrees\n");

    char base[PATH_MAX], source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    char foreign_dir[PATH_MAX], hidden_file[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(home, sizeof(home), base, "home");
    join_path(target, sizeof(target), base, "target");
    join_path(foreign_dir, sizeof(foreign_dir), source, "foreign-dir");
    join_path(hidden_file, sizeof(hidden_file), foreign_dir, "hidden");
    make_directory(source, uid, gid);
    make_directory(home, uid, gid);
    make_directory(target, uid, gid);
    make_directory(foreign_dir, 0, 0);
    write_file(hidden_file, "not inspected", 0, 0);

    char output[32768];
    int result = run_backup_as(target, home, source, uid, gid, 0,
                               output, sizeof(output));
    check_result(result == 1, "a foreign directory rejects the backup");
    check_result(contains(output, "could not safely read 1 source object(s)"),
                 "the foreign directory is a source-read blocker");
    check_result(contains(output, "1 source subtree(s) could not be inspected"),
                 "the report distinguishes an unknown subtree");
    check_result(!contains(output, "2 source object(s)"),
                 "the report does not invent a descendant object count");
    check_result(directory_entry_count(target) == 0,
                 "unknown-subtree refusal leaves no container");
    remove_tree(base);
}

static void test_ownership_probe_rejection(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " backup metadata preflight: ownership probe remains a separate gate\n");

    char base[PATH_MAX], source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    char file[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(home, sizeof(home), base, "home");
    join_path(target, sizeof(target), base, "target");
    join_path(file, sizeof(file), source, "foreign-group.txt");
    make_directory(source, uid, gid);
    make_directory(home, uid, gid);
    make_directory(target, uid, gid);
    write_file(file, "owned-by-user", uid, 0);

    char output[32768];
    int result = run_backup_as(target, home, source, uid, gid, 1,
                               output, sizeof(output));
    if (result == CHILD_SKIP)
    {
        skip_case("ownership probe", "dropped child retains CAP_CHOWN");
        remove_tree(base);
        return;
    }
    check_result(result == 1, "foreign group ownership rejects the backup");
    check_result(contains(output, "native metadata preflight failed"),
                 "ownership failure is distinct from source-safe-read refusal");
    check_result(directory_entry_count(target) == 0,
                 "ownership-probe refusal leaves no container");
    remove_tree(base);
}

static void test_self_owned_tree(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " backup metadata preflight: self-owned source remains successful\n");

    char base[PATH_MAX], source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    char file[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(home, sizeof(home), base, "home");
    join_path(target, sizeof(target), base, "target");
    join_path(file, sizeof(file), source, "owned.txt");
    make_directory(source, uid, gid);
    make_directory(home, uid, gid);
    make_directory(target, uid, gid);
    write_file(file, "healthy", uid, gid);

    char output[32768];
    int result = run_backup_as(target, home, source, uid, gid, 0,
                               output, sizeof(output));
    check_result(result == 0, "a self-owned source still completes");
    check_result(directory_entry_count(target) == 1,
                 "the successful self-owned backup publishes one container");
    remove_tree(base);
}

static int run_capture_as(const char *source, const char *destination,
                          uid_t uid, gid_t gid)
{
    pid_t child = fork();
    if (child < 0)
        fatal("could not fork the capture child");
    if (child == 0)
    {
        if (!drop_identity(uid, gid) || has_effective_cap_fowner())
            _exit(CHILD_SKIP);
        int destination_fd = open(destination, O_RDONLY | O_DIRECTORY |
                                   O_CLOEXEC);
        if (destination_fd < 0)
            _exit(2);
        BackupCaptureReport report;
        BackupCaptureStatus status = backup_capture_at_report(
            &(CloneContext){
                .operation = CLONE_BACKUP,
                .representation = CLONE_NATIVE_TREE,
                .timestamp_policy_configured = 1,
                .nsec_exact = 1,
                .metadata_preflight_done = 1
            }, source, destination_fd, "entry", &report);
        int okay = status == BACKUP_CAPTURE_SOURCE_SAFE_READ &&
                   strcmp(report.failed_source_path, source) == 0;
        close(destination_fd);
        _exit(okay ? 0 : 1);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0)
        fatal("could not wait for the capture child");
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int count_container_names(const char *path, int partial)
{
    const char prefix[] = "migr_backup_";
    const char suffix[] = ".partial";
    DIR *dir = opendir(path);
    if (dir == NULL)
        return -1;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1) != 0)
            continue;
        size_t length = strlen(entry->d_name);
        int is_partial = length >= sizeof(suffix) - 1 &&
                         strcmp(entry->d_name + length - (sizeof(suffix) - 1),
                                suffix) == 0;
        if (is_partial == partial)
            count++;
    }
    int close_status = closedir(dir);
    return close_status == 0 ? count : -1;
}

typedef struct {
    int ready_fd;
    int release_fd;
    const char *pause_path;
} CaptureBarrier;

static void capture_barrier_hook(const char *source_path, void *context)
{
    CaptureBarrier *barrier = context;
    if (barrier == NULL || strcmp(source_path, barrier->pause_path) != 0)
        return;

    char ready = has_effective_cap_fowner() ? 's' : 'r';
    char release;
    if (write(barrier->ready_fd, &ready, 1) != 1)
        _exit(CHILD_SKIP);
    if (ready == 's' || read(barrier->release_fd, &release, 1) != 1)
        _exit(CHILD_SKIP);
}

static int run_backup_capture_race(const char *target, const char *home,
                                   const char *source, const char *pause_path,
                                   uid_t uid, gid_t gid, char *output,
                                   size_t output_size)
{
    int ready[2], release[2], output_pipe[2];
    if (pipe(ready) != 0 || pipe(release) != 0 || pipe(output_pipe) != 0)
        fatal("could not create capture race pipes");

    CaptureBarrier barrier = {
        .ready_fd = ready[1],
        .release_fd = release[0],
        .pause_path = pause_path
    };
    backup_test_set_capture_hook(capture_barrier_hook, &barrier);

    pid_t child = fork();
    if (child < 0)
        fatal("could not fork the capture race child");
    if (child == 0)
    {
        close(ready[0]);
        close(release[1]);
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0)
            _exit(2);
        close(output_pipe[1]);
        if (!drop_identity(uid, gid) || setenv("HOME", home, 1) != 0)
        {
            char skipped = 's';
            (void)write(ready[1], &skipped, 1);
            _exit(CHILD_SKIP);
        }
        dry_run = 0;
        char *paths[] = { (char *)source, NULL };
        int result = backup(target, BACKUP_EXPLICIT_PATHS, paths);
        fflush(stdout);
        _exit(result == 0 ? 0 : 1);
    }

    close(ready[1]);
    close(release[0]);
    close(output_pipe[1]);
    char ready_byte;
    if (read(ready[0], &ready_byte, 1) != 1)
        fatal("capture barrier was not reached");
    close(ready[0]);

    if (ready_byte == 's')
    {
        close(release[1]);
        size_t skipped_total = 0;
        while (skipped_total + 1 < output_size)
        {
            ssize_t received = read(output_pipe[0], output + skipped_total,
                                    output_size - skipped_total - 1);
            if (received <= 0)
                break;
            skipped_total += (size_t)received;
        }
        output[skipped_total] = '\0';
        close(output_pipe[0]);
        int skipped_status = 0;
        if (waitpid(child, &skipped_status, 0) < 0)
            fatal("could not wait for the skipped capture child");
        backup_test_set_capture_hook(NULL, NULL);
        return CHILD_SKIP;
    }
    if (ready_byte != 'r')
        fatal("capture barrier sent an invalid status");

    if (chown(pause_path, 0, 0) != 0)
        fatal("could not change the captured file owner");
    char release_byte = 'r';
    if (write(release[1], &release_byte, 1) != 1)
        fatal("could not release the capture barrier");
    close(release[1]);

    size_t total = 0;
    while (total + 1 < output_size)
    {
        ssize_t received = read(output_pipe[0], output + total,
                                output_size - total - 1);
        if (received <= 0)
            break;
        total += (size_t)received;
    }
    output[total] = '\0';
    close(output_pipe[0]);

    int status = 0;
    if (waitpid(child, &status, 0) < 0)
        fatal("could not wait for the capture race child");
    backup_test_set_capture_hook(NULL, NULL);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_capture_refusal(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " native capture: O_NOATIME refusal is typed and identifies its source\n");

    char base[PATH_MAX], source[PATH_MAX], source_dir[PATH_MAX];
    char destination[PATH_MAX], destination_dir[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "foreign.txt");
    join_path(source_dir, sizeof(source_dir), base, "foreign-dir");
    join_path(destination, sizeof(destination), base, "destination");
    join_path(destination_dir, sizeof(destination_dir), base, "destination-dir");
    write_file(source, "foreign", 0, 0);
    make_directory(source_dir, 0, 0);
    make_directory(destination, uid, gid);
    make_directory(destination_dir, uid, gid);

    int result = run_capture_as(source, destination, uid, gid);
    if (result == CHILD_SKIP)
    {
        skip_case("capture refusal", "dropped child retained CAP_FOWNER");
        remove_tree(base);
        return;
    }
    check_result(result == 0, "capture returns the source-safe-read status");
    check_result(directory_entry_count(destination) == 0,
                 "capture refusal creates no destination entry");

    result = run_capture_as(source_dir, destination_dir, uid, gid);
    check_result(result == 0,
                 "directory capture returns the source-safe-read status");
    check_result(directory_entry_count(destination_dir) == 0,
                 "directory refusal creates no destination entry");
    remove_tree(base);
}

static void test_capture_race(uid_t uid, gid_t gid)
{
    printf(BLUE "::" NC " native capture: ownership change after inventory is a source-safe-read refusal\n");

    char base[PATH_MAX], source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    char file[PATH_MAX];
    make_root(base, sizeof(base));
    join_path(source, sizeof(source), base, "source");
    join_path(home, sizeof(home), base, "home");
    join_path(target, sizeof(target), base, "target");
    join_path(file, sizeof(file), source, "captured.txt");
    make_directory(source, uid, gid);
    make_directory(home, uid, gid);
    make_directory(target, uid, gid);
    write_file(file, "capture race", uid, gid);

    char output[65536];
    int result = run_backup_capture_race(target, home, source, file, uid, gid,
                                         output, sizeof(output));
    if (result == CHILD_SKIP)
    {
        skip_case("capture race", "dropped child retained CAP_FOWNER");
        remove_tree(base);
        return;
    }
    check_result(result == 1, "capture-time ownership change rejects the backup");
    check_result(contains(output, "Could not safely read source for"),
                 "capture reports a distinct source-safe-read refusal");
    check_result(contains(output, file),
                 "capture refusal identifies the failed source path");
    check_result(contains(output, "Incomplete backup kept for resume"),
                 "capture refusal keeps the existing partial container policy");
    check_result(count_container_names(target, 1) == 1,
                 "capture refusal leaves one partial container");
    check_result(count_container_names(target, 0) == 0,
                 "capture refusal publishes no final container");
    remove_tree(base);
}

int main(void)
{
    printf(BLUE "::" NC " native backup source-safe-read tests\n");

    uid_t uid = 0;
    gid_t gid = 0;
    if (!find_nobody(&uid, &gid))
    {
        skip_case("all cases", "root and an unprivileged nobody identity are required");
        return 0;
    }
    if (has_effective_cap_chown())
        printf(BLUE "  (parent retains CAP_CHOWN; child cases verify and skip only affected probes)\n" NC);

    test_inventory_race(uid, gid);
    test_bounded_examples(uid, gid);
    test_uninspected_subtree(uid, gid);
    test_ownership_probe_rejection(uid, gid);
    test_self_owned_tree(uid, gid);
    test_capture_refusal(uid, gid);
    test_capture_race(uid, gid);

    if (failures > 0)
    {
        printf(RED "%d source-read test(s) failed" NC "\n", failures);
        return 1;
    }
    printf(GREEN "source-read tests passed" NC "\n");
    return 0;
}
