// Unit tests for the portable capture core (docs/DECISIONS.md D17/D18): the
// fresh-capture-only walk over regular files and directories, behind the
// test-only direct API (D14 -- never reachable from a release binary). No
// resume, no adopt, no interruption testing here; those are separate steps
// built on top of this one.
//
// Regular/directory capture is checked byte-exact against the source, with
// xattrs captured and the resulting sidecar's group count verified. D17's
// source snapshot contract (final object opened `O_NOFOLLOW` +
// `O_NOATIME`, pre/post `fstat`) is exercised implicitly through every
// capture, not tested as a separate unit, since it has no observable effect
// beyond "the capture stays exact." Replacement ordering is checked
// directly -- the committed `DELETE` for an old key must be readable in the
// sidecar log before the new `ENTRY` group -- for both same-kind updates
// and type changes (regular to directory and back), including that a type
// change replaces the destination inode rather than truncating an existing
// one out from under a concurrent reader. Symlinks are captured as empty
// payload placeholders plus sidecar records; FIFOs remain fail-closed without
// ever being opened; sockets and devices are
// warning-and-skip, including tombstoning a previously captured version and
// removing its stale payload. `MANUAL_NATIVE` roots are refused before any
// portable mutation.

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
#include <sys/types.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "manifest.h"
#include "portable.h"
#include "sidecar.h"

extern int entry_from_stat(const char *root_id, const char *logical,
                           const char *physical,
                           const struct stat *st, int nsec_exact,
                           PortableXattrs *xattrs, SidecarEntry *out,
                           const SidecarBytes *symlink_target);
extern int append_physical(char *destination, size_t destination_size,
                           const char *parent, const char *encoded_leaf);
extern int prescan_report_add(PortablePrescanReport *report,
                              const PortablePrescanViolation *violation);
extern int entries_equal(const SidecarEntry *current,
                         const SidecarLiveView *previous,
                         const PortableXattrs *xattrs);

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
#define NC    "\033[0m"

static int failures;
static int skips;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void skip_check(const char *label)
{
    printf("  " YELLOW "-" NC " %s\n", label);
    skips++;
}

static void fixture_fatal(const char *message)
{
    fprintf(stderr, "portable fixture failure: %s\n", message);
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
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not inspect fixture tree");
    }
    if (nftw(path, remove_callback_fatal, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fixture_fatal("could not walk fixture tree");
}

static int remove_fd_entry(int parent_fd, const char *name);

static int remove_fd_children(int directory_fd)
{
    int scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (remove_fd_entry(directory_fd, entry->d_name) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int remove_fd_entry(int parent_fd, const char *name)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(parent_fd, name, 0) == 0 ? 0 : -1;

    int directory_fd = openat(parent_fd, name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
    if (directory_fd < 0)
        return -1;
    int failed = remove_fd_children(directory_fd);
    if (close(directory_fd) != 0)
        failed = -1;
    if (failed != 0)
        return -1;
    return unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 ? 0 : -1;
}

static void remove_tree_fd(const char *path)
{
    int directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not open fixture tree for fd cleanup");
    }
    if (remove_fd_children(directory_fd) != 0 || close(directory_fd) != 0 ||
        rmdir(path) != 0)
        fixture_fatal("could not remove fixture tree by descriptor");
}

static void join_path(char *out, size_t size, const char *left,
                      const char *right)
{
    int length = snprintf(out, size, "%s/%s", left, right);
    if (length < 0 || (size_t)length >= size)
        fixture_fatal("fixture path is too long");
}

static void make_directory(const char *path)
{
    if (mkdir(path, 0700) != 0)
        fixture_fatal("could not create fixture directory");
}

static void write_file(const char *path, const void *data, size_t length)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fixture_fatal("could not create fixture file");
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, (const unsigned char *)data + offset,
                                length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            fixture_fatal("could not write fixture file");
        offset += (size_t)written;
    }
    if (close(fd) != 0)
        fixture_fatal("could not close fixture file");
}

static int file_equals(const char *path, const char *expected)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    size_t expected_length = strlen(expected);
    unsigned char buffer[256];
    size_t received = 0;
    while (received < sizeof(buffer)) {
        ssize_t count = read(fd, buffer + received, sizeof(buffer) - received);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            close(fd);
            return 0;
        }
        if (count == 0)
            break;
        received += (size_t)count;
    }
    int result = close(fd) == 0 && received == expected_length &&
                 memcmp(buffer, expected, expected_length) == 0;
    return result;
}

static int directory_fd_is_empty(int directory_fd)
{
    int scan_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return 0;
    }

    int empty = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                empty = 0;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = 0;
            break;
        }
    }
    if (closedir(directory) != 0)
        empty = 0;
    return empty;
}

static int relative_directory_is_empty(int base_fd, const char *relative)
{
    if (base_fd < 0 || relative == NULL || relative[0] == '\0' ||
        strlen(relative) >= PATH_MAX)
        return 0;
    int directory_fd = openat(base_fd, relative,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC);
    if (directory_fd < 0)
        return 0;
    int result = directory_fd_is_empty(directory_fd);
    if (close(directory_fd) != 0)
        result = 0;
    return result;
}

static PortableRootSpec root_spec(const char *id, const char *source,
                                  const char *payload)
{
    return (PortableRootSpec){
        .id = id,
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = payload,
        .source_path = "",
        .restore_path = "",
        .has_restore_path = 1
    };
}

static SidecarBytes bytes(const char *text)
{
    return (SidecarBytes){ (const unsigned char *)text, strlen(text) };
}

static int sidecar_bytes_match_text(SidecarBytes value, const char *text)
{
    if (text == NULL)
        return 0;
    size_t length = strlen(text);
    return value.length == length &&
           (length == 0 || memcmp(value.data, text, length) == 0);
}

static int live_entry_paths(SidecarLog *log, const char *root,
                            const char *logical, const char *physical)
{
    SidecarLiveView view;
    int found = sidecar_log_find(log, bytes(root), bytes(logical), &view);
    return found == 1 &&
           sidecar_bytes_match_text(view.entry->logical_path, logical) &&
           sidecar_bytes_match_text(view.entry->physical_path, physical);
}

static void test_append_physical(void)
{
    printf(BLUE "::" NC " physical path joining\n");
    char output[32];

    check(append_physical(output, sizeof(output), "parent", "leaf") == 0 &&
              strcmp(output, "parent/leaf") == 0,
          "physical path joins a parent and encoded leaf");
    check(append_physical(output, sizeof(output), "", "leaf") == 0 &&
              strcmp(output, "leaf") == 0,
          "physical path omits the leading slash for an empty parent");
    check(append_physical(output, 10, "parent", "leaf") != 0,
          "physical path refuses a leaf that does not fit");
    check(append_physical(output, 6, "parent", "leaf") != 0,
          "physical path refuses a parent that does not fit");
}

static void test_prescan_report(void)
{
    printf(BLUE "::" NC " portable pre-scan report storage\n");
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(report.total_count == 0 && report.examples == NULL &&
              report.example_count == 0 && report.example_capacity == 0,
          "pre-scan report initializes empty");

    PortablePrescanViolation violation = {
        .kind = PORTABLE_PRESCAN_NAME_TOO_LONG,
        .limit = 255,
        .actual = 258
    };
    strcpy(violation.root_id, "ROOT");
    strcpy(violation.logical_path, "nested/illegal-name");
    check(prescan_report_add(&report, &violation) == 0,
          "pre-scan report accepts a violation");
    check(report.total_count == 1 && report.example_count == 1 &&
              report.examples[0].kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
              strcmp(report.examples[0].root_id, "ROOT") == 0 &&
              strcmp(report.examples[0].logical_path,
                     "nested/illegal-name") == 0 &&
              report.examples[0].limit == 255 &&
              report.examples[0].actual == 258,
          "pre-scan violation fields round-trip");

    for (size_t index = 1; index < PORTABLE_PRESCAN_MAX_EXAMPLES + 8U;
         index++) {
        PortablePrescanViolation extra = {
            .kind = PORTABLE_PRESCAN_PATH_TOO_LONG,
            .limit = PATH_MAX,
            .actual = PATH_MAX + index
        };
        if (prescan_report_add(&report, &extra) != 0)
            fixture_fatal("could not append pre-scan violation");
    }
    check(report.total_count == PORTABLE_PRESCAN_MAX_EXAMPLES + 8U &&
              report.example_count == PORTABLE_PRESCAN_MAX_EXAMPLES,
          "pre-scan examples are bounded while total count remains complete");
    portable_prescan_report_free(&report);
    check(report.total_count == 0 && report.examples == NULL &&
              report.example_count == 0 && report.example_capacity == 0,
          "pre-scan report frees all storage");
}

static void test_entry_helpers(const char *source)
{
    printf(BLUE "::" NC " portable symlink entry helpers\n");
    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source, "entry-helper-link");
    if (symlink("../target", link_path) != 0)
        fixture_fatal("could not create symlink helper fixture");

    struct stat link_stat;
    if (lstat(link_path, &link_stat) != 0)
        fixture_fatal("could not inspect symlink helper fixture");
    PortableXattrs empty_xattrs = {0};
    SidecarBytes target = bytes("../target");
    SidecarEntry entry;
    check(entry_from_stat("LINK", "item", "item", &link_stat, 1,
                          &empty_xattrs, &entry, &target) == 0,
          "entry_from_stat accepts a symlink target");
    check(entry.kind == SIDECAR_KIND_SYMLINK && entry.size == 0 &&
              entry.xattr_count == 0 &&
              entry.symlink_target.length == target.length &&
              memcmp(entry.symlink_target.data, target.data, target.length) == 0,
          "symlink entry preserves kind, zero size, and target bytes");

    SidecarEntry symlink_entry = entry;

    check(entry_from_stat("LINK", "item", "item", &link_stat, 1,
                          &empty_xattrs, &entry, NULL) != 0,
          "symlink entry without a target is rejected");
    SidecarBytes empty_target = {0};
    check(entry_from_stat("LINK", "item", "item", &link_stat, 1,
                          &empty_xattrs, &entry, &empty_target) != 0,
          "symlink entry with an empty target is rejected");

    SidecarEntry previous = symlink_entry;
    previous.symlink_target = target;
    SidecarLiveView view = {
        .entry = &previous,
        .xattrs = NULL,
        .xattr_count = 0,
        .generation = 0
    };
    entry = previous;
    check(entries_equal(&entry, &view, &empty_xattrs) != 0,
          "entries_equal accepts identical symlink targets");
    entry.physical_path = bytes("different-physical");
    check(entries_equal(&entry, &view, &empty_xattrs) == 0,
          "entries_equal rejects different physical paths");
    entry.physical_path = previous.physical_path;
    entry.symlink_target = bytes("other-target");
    check(entries_equal(&entry, &view, &empty_xattrs) == 0,
          "entries_equal rejects different symlink targets");

    if (unlink(link_path) != 0)
        fixture_fatal("could not remove symlink helper fixture");
}

static void test_encoded_payload_names(const char *base)
{
    printf(BLUE "::" NC " encoded payload names and sidecar paths\n");
    static const struct {
        const char *logical;
        const char *physical;
    } names[] = {
        { "colon:name", "colon%3Aname" },
        { "question?name", "question%3Fname" },
        { "space name", "space%20name" },
        { "percent%name", "percent%25name" },
        { "trailing.", "trailing%2E" },
        { "日本", "日本" },
        { "ç", "ç" },
        { "🙂", "🙂" }
    };
    static const char invalid_name[] = {
        'i', 'n', 'v', 'a', 'l', 'i', 'd', (char)0xff, 'n', 'a', 'm', 'e',
        '\0'
    };
    static const char invalid_physical[] = "invalid%FFname";

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "encoded-names-source");
    join_path(container_path, sizeof(container_path), base,
              "encoded-names-container");
    make_directory(source_path);
    make_directory(container_path);

    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        char path[PATH_MAX];
        join_path(path, sizeof(path), source_path, names[index].logical);
        write_file(path, "x", 1);
    }
    char invalid_path[PATH_MAX];
    join_path(invalid_path, sizeof(invalid_path), source_path, invalid_name);
    write_file(invalid_path, "x", 1);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open encoded-name container");
    PortableRootSpec root = root_spec("NAMES", source_path, "NAMES");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    check(portable_capture_fresh_at(container_fd, &request) == 0,
          "capture accepts escaped and valid UTF-8 names");

    char data_path[PATH_MAX];
    join_path(data_path, sizeof(data_path), container_path, "data/NAMES");
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        char payload[PATH_MAX];
        join_path(payload, sizeof(payload), data_path, names[index].physical);
        check(file_equals(payload, "x"),
              "payload uses the expected encoded or raw UTF-8 leaf");
    }
    char invalid_payload[PATH_MAX];
    join_path(invalid_payload, sizeof(invalid_payload), data_path,
              invalid_physical);
    check(file_equals(invalid_payload, "x"),
          "invalid UTF-8 bytes are escaped in the payload name");

    SidecarLog log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(adopted, "encoded-name sidecar can be reopened");
    if (adopted) {
        for (size_t index = 0; index < sizeof(names) / sizeof(names[0]);
             index++)
            check(live_entry_paths(&log, "NAMES", names[index].logical,
                                   names[index].physical),
                  "sidecar preserves logical and physical name paths");
        check(live_entry_paths(&log, "NAMES", invalid_name, invalid_physical),
              "sidecar preserves an invalid-byte logical name separately");
        check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
              "encoded-name sidecar closes cleanly");
    }
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_nested_encoded_directories(const char *base)
{
    printf(BLUE "::" NC " reconcile nested encoded directories\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "nested-encoded-source");
    join_path(container_path, sizeof(container_path), base,
              "nested-encoded-container");
    make_directory(source_path);
    make_directory(container_path);

    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    join_path(first_path, sizeof(first_path), source_path, "weird?dir");
    join_path(second_path, sizeof(second_path), first_path, "また:dir");
    make_directory(first_path);
    make_directory(second_path);

    char first_file[PATH_MAX];
    char second_file[PATH_MAX];
    join_path(first_file, sizeof(first_file), first_path, "inner.txt");
    join_path(second_file, sizeof(second_file), second_path, "deep.txt");
    write_file(first_file, "inner", sizeof("inner") - 1U);
    write_file(second_file, "deep", sizeof("deep") - 1U);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open nested encoded container");
    PortableRootSpec root = root_spec("NESTED", source_path, "NESTED");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    check(portable_capture_fresh_at(container_fd, &request) == 0,
          "nested encoded directories capture successfully");

    char payload_first[PATH_MAX];
    char payload_second[PATH_MAX];
    join_path(payload_first, sizeof(payload_first), container_path,
              "data/NESTED/weird%3Fdir");
    join_path(payload_second, sizeof(payload_second), payload_first,
              "また%3Adir");
    char payload_first_file[PATH_MAX];
    char payload_second_file[PATH_MAX];
    join_path(payload_first_file, sizeof(payload_first_file), payload_first,
              "inner.txt");
    join_path(payload_second_file, sizeof(payload_second_file), payload_second,
              "deep.txt");
    check(file_equals(payload_first_file, "inner"),
          "first encoded directory contains its file");
    check(file_equals(payload_second_file, "deep"),
          "second encoded directory contains its file");

    SidecarLog log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(adopted, "nested encoded sidecar can be reopened");
    if (adopted) {
        check(live_entry_paths(&log, "NESTED", "weird?dir",
                               "weird%3Fdir"),
              "first directory keeps logical and physical paths");
        check(live_entry_paths(&log, "NESTED", "weird?dir/inner.txt",
                               "weird%3Fdir/inner.txt"),
              "first nested file keeps logical and physical paths");
        check(live_entry_paths(&log, "NESTED", "weird?dir/また:dir",
                               "weird%3Fdir/また%3Adir"),
              "second directory keeps logical and physical paths");
        check(live_entry_paths(&log, "NESTED",
                               "weird?dir/また:dir/deep.txt",
                               "weird%3Fdir/また%3Adir/deep.txt"),
              "second nested file keeps logical and physical paths");
        check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
              "nested encoded sidecar closes cleanly");
    }
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_name_and_path_limits(const char *base)
{
    printf(BLUE "::" NC " encoded name and payload path limits\n");

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "name-limit-source");
    join_path(container_path, sizeof(container_path), base,
              "name-limit-container");
    make_directory(source_path);
    make_directory(container_path);

    char oversized_name[NAME_MAX + 1U];
    size_t oversized_length = NAME_MAX / 3U + 1U;
    memset(oversized_name, ':', oversized_length);
    oversized_name[oversized_length] = '\0';
    char oversized_path[PATH_MAX];
    join_path(oversized_path, sizeof(oversized_path), source_path,
              oversized_name);
    write_file(oversized_path, "x", 1);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open name-limit container");
    PortableRootSpec root = root_spec("NAMES", source_path, "NAMES");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    check(portable_capture_fresh_at(container_fd, &request) != 0,
          "an encoded leaf exceeding NAME_MAX refuses capture");
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(data_fd >= 0 && relative_directory_is_empty(data_fd, "NAMES"),
          "NAME_MAX refusal leaves no payload child");
    if (data_fd >= 0)
        close(data_fd);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base, "path-limit-source");
    join_path(container_path, sizeof(container_path), base,
              "path-limit-container");
    make_directory(source_path);
    make_directory(container_path);
    char child_path[PATH_MAX];
    join_path(child_path, sizeof(child_path), source_path, "child");
    write_file(child_path, "x", 1);

    char *long_payload = malloc(PATH_MAX);
    if (long_payload == NULL)
        fixture_fatal("could not allocate long payload path");
    size_t target_length = PATH_MAX - 1U;
    size_t offset = 0;
    while (offset + 2U < target_length) {
        long_payload[offset++] = 'a';
        long_payload[offset++] = '/';
    }
    long_payload[offset++] = 'a';
    long_payload[offset] = '\0';

    container_fd = open(container_path,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open path-limit container");
    root = root_spec("PATH", source_path, long_payload);
    request.roots = &root;
    check(portable_capture_fresh_at(container_fd, &request) != 0,
          "a physical payload path exceeding PATH_MAX refuses capture");
    data_fd = openat(container_fd, "data",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(data_fd >= 0 &&
              relative_directory_is_empty(data_fd, long_payload),
          "PATH_MAX refusal leaves no payload child");
    if (data_fd >= 0)
        close(data_fd);
    close(container_fd);
    free(long_payload);
    remove_tree(source_path);
    remove_tree_fd(container_path);
}

static int live_kind(SidecarLog *log, const char *root, const char *logical,
                     SidecarObjectKind kind)
{
    SidecarLiveView view;
    int found = sidecar_log_find(log, bytes(root), bytes(logical), &view);
    return found == 1 && view.entry->kind == kind;
}

typedef struct {
    int entries;
    int xattrs;
    int commits;
    int valid;
    int expected_xattr_seen;
    int symlink_seen;
    int symlink_target_ok;
    int symlink_xattr_seen;
    int symlink_regular_xattr_leaked;
    int symlink_xattr_count;
    int symlink_entry_xattr_count;
    int symlink_entry_open;
} FreshSidecarCheck;

static int fresh_sidecar_callback(const SidecarRecord *record, void *opaque)
{
    FreshSidecarCheck *check_state = opaque;
    if (record->type == SIDECAR_RECORD_ENTRY) {
        const SidecarEntry *entry = &record->value.entry;
        check_state->entries++;
        if (entry->root_id.length != 4 ||
            memcmp(entry->root_id.data, "ROOT", 4) != 0 ||
            (entry->kind != SIDECAR_KIND_DIRECTORY &&
             entry->kind != SIDECAR_KIND_REGULAR &&
             entry->kind != SIDECAR_KIND_SYMLINK))
            check_state->valid = 0;
        check_state->symlink_entry_open = entry->kind == SIDECAR_KIND_SYMLINK;
        if (check_state->symlink_entry_open) {
            static const char expected_path[] = "nested/link";
            static const char expected_target[] = "file.txt";
            check_state->symlink_seen = 1;
            check_state->symlink_entry_xattr_count =
                (int)entry->xattr_count;
            check_state->symlink_xattr_count = 0;
            check_state->symlink_target_ok =
                entry->logical_path.length == sizeof(expected_path) - 1U &&
                memcmp(entry->logical_path.data, expected_path,
                       sizeof(expected_path) - 1U) == 0 &&
                entry->size == 0 &&
                entry->symlink_target.length == sizeof(expected_target) - 1U &&
                memcmp(entry->symlink_target.data, expected_target,
                       sizeof(expected_target) - 1U) == 0;
        }
    } else if (record->type == SIDECAR_RECORD_XATTR) {
        const SidecarXattr *xattr = &record->value.xattr;
        static const char expected_name[] = "user.migr_test";
        static const char expected_value[] = "portable-xattr";
        static const char symlink_name[] = "user.migr_symlink";
        static const char symlink_value[] = "symlink-xattr";
        check_state->xattrs++;
        if (xattr->name.length == sizeof(expected_name) - 1U &&
            memcmp(xattr->name.data, expected_name,
                   sizeof(expected_name) - 1U) == 0 &&
            xattr->value.length == sizeof(expected_value) - 1U &&
            memcmp(xattr->value.data, expected_value,
                   sizeof(expected_value) - 1U) == 0)
            check_state->expected_xattr_seen = 1;
        if (check_state->symlink_entry_open) {
            check_state->symlink_xattr_count++;
            if (xattr->name.length == sizeof(expected_name) - 1U &&
                memcmp(xattr->name.data, expected_name,
                       sizeof(expected_name) - 1U) == 0)
                check_state->symlink_regular_xattr_leaked = 1;
            if (xattr->name.length == sizeof(symlink_name) - 1U &&
                memcmp(xattr->name.data, symlink_name,
                       sizeof(symlink_name) - 1U) == 0 &&
                xattr->value.length == sizeof(symlink_value) - 1U &&
                memcmp(xattr->value.data, symlink_value,
                       sizeof(symlink_value) - 1U) == 0)
                check_state->symlink_xattr_seen = 1;
        }
    } else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT) {
        check_state->commits++;
        if (check_state->symlink_entry_open) {
            if (check_state->symlink_xattr_count !=
                check_state->symlink_entry_xattr_count)
                check_state->valid = 0;
            check_state->symlink_entry_open = 0;
        }
    }
    return 0;
}

typedef struct {
    int delete_seen;
    int new_entry_seen;
    int new_commit_seen;
    int invalid_order;
    int target_entry_open;
} ReplacementOrder;

static int replacement_callback(const SidecarRecord *record, void *opaque)
{
    ReplacementOrder *order = opaque;
    if (record->type == SIDECAR_RECORD_ENTRY_COMMIT) {
        if (order->target_entry_open && order->new_entry_seen)
            order->new_commit_seen = 1;
        order->target_entry_open = 0;
        return 0;
    }
    SidecarBytes root = {0};
    SidecarBytes path = {0};
    if (record->type == SIDECAR_RECORD_ENTRY) {
        root = record->value.entry.root_id;
        path = record->value.entry.logical_path;
    } else if (record->type == SIDECAR_RECORD_DELETE) {
        root = record->value.deletion.root_id;
        path = record->value.deletion.logical_path;
    }
    int target = root.length == 4 && path.length == 0 &&
                 memcmp(root.data, "FILE", 4) == 0;
    if (!target)
        return 0;
    if (record->type == SIDECAR_RECORD_DELETE)
        order->delete_seen = 1;
    else if (record->type == SIDECAR_RECORD_ENTRY) {
        if (order->delete_seen)
            order->new_entry_seen = 1;
        else if (order->new_entry_seen)
            order->invalid_order = 1;
        order->target_entry_open = 1;
    }
    return 0;
}

static int create_live_capture(const char *container_path, int *container_fd,
                               SidecarLog *log,
                               PortableCaptureContext *context)
{
    if (mkdir(container_path, 0700) != 0)
        return -1;
    *container_fd = open(container_path,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (*container_fd < 0 || mkdirat(*container_fd, "data", 0700) != 0 ||
        sidecar_log_create_at(*container_fd, log) != SIDECAR_OPEN_FRESH)
        return -1;
    int data_fd = openat(*container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0 ||
        portable_capture_context_init(context, data_fd, log, 1, 1) != 0)
        return -1;
    return 0;
}

static void close_live_capture(int container_fd, SidecarLog *log,
                               PortableCaptureContext *context);

static void test_capture_context_flags(const char *base)
{
    printf(BLUE "::" NC " portable capture context capability flags\n");
    char container_path[PATH_MAX];
    join_path(container_path, sizeof(container_path), base,
              "context-flags-container");

    SidecarLog log = {0};
    PortableCaptureContext context = {0};
    int container_fd = -1;
    check(create_live_capture(container_path, &container_fd, &log,
                              &context) == 0,
          "capture context initializes for flag checks");
    if (container_fd < 0)
        return;
    check(context.case_sensitive == 1,
          "capture context preserves a case-sensitive verdict");

    int data_fd = context.data_fd;
    portable_capture_context_close(&context);
    check(portable_capture_context_init(&context, data_fd, &log, 1, 0) == 0,
          "capture context accepts a case-insensitive verdict");
    check(context.case_sensitive == 0,
          "capture context preserves a case-insensitive verdict");
    close_live_capture(container_fd, &log, &context);
    remove_tree(container_path);
}

static void close_live_capture(int container_fd, SidecarLog *log,
                               PortableCaptureContext *context)
{
    int data_fd = context->data_fd;
    portable_capture_context_close(context);
    if (data_fd >= 0)
        close(data_fd);
    sidecar_log_close(log);
    if (container_fd >= 0)
        close(container_fd);
}

static void test_fresh_capture(const char *source, int container_fd,
                               const char *container_path)
{
    printf(BLUE "::" NC " fresh regular and directory capture\n");
    char nested[PATH_MAX];
    char file[PATH_MAX];
    char link[PATH_MAX];
    join_path(nested, sizeof(nested), source, "nested");
    join_path(file, sizeof(file), nested, "file.txt");
    join_path(link, sizeof(link), nested, "link");
    make_directory(nested);
    write_file(file, "portable payload", 16);
    if (symlink("file.txt", link) != 0)
        fixture_fatal("could not create symlink fixture");

    int xattr_expected = 1;
    static const char xattr_name[] = "user.migr_test";
    static const char xattr_value[] = "portable-xattr";
    if (setxattr(file, xattr_name, xattr_value, sizeof(xattr_value) - 1U,
                 0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) {
            xattr_expected = 0;
            skip_check("xattr fixture unavailable on this filesystem");
        } else {
            fixture_fatal("could not create xattr fixture");
        }
    }

    int symlink_xattr_expected = 1;
    static const char symlink_xattr_name[] = "user.migr_symlink";
    static const char symlink_xattr_value[] = "symlink-xattr";
    if (lsetxattr(link, symlink_xattr_name, symlink_xattr_value,
                 sizeof(symlink_xattr_value) - 1U, 0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) {
            symlink_xattr_expected = 0;
            skip_check("symlink xattr fixture unavailable on this filesystem");
        } else {
            fixture_fatal("could not create symlink xattr fixture");
        }
    }

    PortableRootSpec root = root_spec("ROOT", source, "ROOT");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 0,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    check(portable_capture_fresh_at(container_fd, &request) == 0,
          "fresh portable capture succeeds");

    Manifest manifest;
    check(manifest_read_v1_at(container_fd, &manifest) == MANIFEST_STATUS_VALID &&
          manifest.representation == CLONE_PORTABLE_SIDECAR &&
          manifest.sidecar_version == SIDECAR_VERSION && manifest.root_count == 1,
          "fresh capture writes a portable sidecar manifest");
    manifest_free(&manifest);

    char payload[PATH_MAX];
    join_path(payload, sizeof(payload), container_path, "data/ROOT/nested/file.txt");
    check(file_equals(payload, "portable payload"),
          "regular payload is byte-exact under data");
    join_path(payload, sizeof(payload), container_path, "data/ROOT/nested/link");
    struct stat link_payload_stat;
    check(lstat(payload, &link_payload_stat) == 0 &&
              S_ISREG(link_payload_stat.st_mode) &&
              link_payload_stat.st_size == 0 && file_equals(payload, ""),
          "symlink payload is an empty regular placeholder");

    int slot_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                         O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FreshSidecarCheck sidecar_check = { .valid = 1 };
    SidecarParseResult parse_result;
    SidecarStatus parse_status = SIDECAR_STATUS_INVALID_ARGUMENT;
    if (slot_fd >= 0)
        parse_status = sidecar_parse_fd(slot_fd, fresh_sidecar_callback,
                                        &sidecar_check, &parse_result);
    check(slot_fd >= 0 &&
          parse_status == SIDECAR_STATUS_OK &&
          sidecar_check.valid && sidecar_check.entries == 4 &&
          sidecar_check.commits == 4 && sidecar_check.symlink_seen &&
          sidecar_check.symlink_target_ok &&
          !sidecar_check.symlink_regular_xattr_leaked &&
          (!symlink_xattr_expected ||
           (sidecar_check.symlink_xattr_seen &&
            sidecar_check.symlink_entry_xattr_count >= 1)) &&
          (!xattr_expected ||
           sidecar_check.expected_xattr_seen),
          "sidecar contains complete groups, symlink target, and xattrs");
    if (slot_fd >= 0)
        close(slot_fd);
}

static void test_replacement_and_type_change(const char *source,
                                             const char *base_path)
{
    printf(BLUE "::" NC " replacement ordering and type changes\n");
    char replacement_container[PATH_MAX];
    join_path(replacement_container, sizeof(replacement_container), base_path,
              "replacement-container");
    int container_fd = -1;
    SidecarLog log = {0};
    PortableCaptureContext context = {0};
    check(create_live_capture(replacement_container, &container_fd, &log,
                              &context) == 0,
          "fresh sidecar context is ready for replacement tests");
    if (container_fd < 0 || log.implementation == NULL)
        return;
    char file[PATH_MAX];
    join_path(file, sizeof(file), source, "replace-me");
    write_file(file, "first", 5);
    PortableRootSpec root = root_spec("FILE", file, "FILE");
    check(portable_capture_root(&context, &root) == 0,
          "a new regular root can be appended to the live sidecar");

    write_file(file, "second", 6);
    check(portable_capture_root(&context, &root) == 0,
          "replacement captures the changed regular payload");
    char payload[PATH_MAX];
    join_path(payload, sizeof(payload), replacement_container, "data/FILE");
    check(file_equals(payload, "second"),
          "replacement does not leave the old payload bytes");

    check(live_kind(&log, "FILE", "", SIDECAR_KIND_REGULAR),
          "replacement leaves one live regular entry");

    int fd = openat(container_fd, SIDECAR_SLOT_NAME, O_RDONLY | O_CLOEXEC);
    ReplacementOrder order = {0};
    SidecarParseResult result;
    check(fd >= 0 && sidecar_parse_fd(fd, replacement_callback, &order,
                                      &result) == SIDECAR_STATUS_OK &&
          order.delete_seen && order.new_entry_seen && order.new_commit_seen &&
          !order.invalid_order,
          "replacement log orders DELETE before the new ENTRY group");
    if (fd >= 0)
        close(fd);

    if (unlink(file) != 0)
        fixture_fatal("could not replace regular source with directory");
    make_directory(file);
    char child[PATH_MAX];
    join_path(child, sizeof(child), file, "child");
    write_file(child, "child", 5);
    check(portable_capture_root(&context, &root) == 0,
          "regular-to-directory replacement succeeds");
    struct stat st;
    check(lstat(payload, &st) == 0 && S_ISDIR(st.st_mode),
          "type change replaces the destination inode rather than truncating it");
    join_path(payload, sizeof(payload), replacement_container, "data/FILE/child");
    check(file_equals(payload, "child"),
          "directory replacement captures its child");

    if (unlink(child) != 0 || rmdir(file) != 0)
        fixture_fatal("could not replace directory source with regular file");
    write_file(file, "final", 5);
    check(portable_capture_root(&context, &root) == 0,
          "directory-to-regular replacement succeeds");
    join_path(payload, sizeof(payload), replacement_container, "data/FILE");
    check(lstat(payload, &st) == 0 && S_ISREG(st.st_mode),
          "directory-to-regular replacement removes the old subtree");
    check(file_equals(payload, "final"),
          "regular replacement leaves only the new payload bytes");
    check(sidecar_log_find(&log, bytes("FILE"), bytes("child"),
                           &(SidecarLiveView){0}) == 0,
          "directory-to-regular replacement tombstones old child state");

    if (unlink(file) != 0 || symlink("replacement-target", file) != 0)
        fixture_fatal("could not replace regular source with symlink");
    check(portable_capture_root(&context, &root) == 0,
          "regular-to-symlink replacement succeeds");
    join_path(payload, sizeof(payload), replacement_container, "data/FILE");
    check(lstat(payload, &st) == 0 && S_ISREG(st.st_mode) &&
              st.st_size == 0 && file_equals(payload, ""),
          "symlink replacement leaves an empty placeholder");
    SidecarLiveView symlink_view;
    int symlink_found = sidecar_log_find(&log, bytes("FILE"), bytes(""),
                                         &symlink_view);
    check(symlink_found == 1 && symlink_view.entry->kind == SIDECAR_KIND_SYMLINK &&
              symlink_view.entry->symlink_target.length ==
                  sizeof("replacement-target") - 1U &&
              memcmp(symlink_view.entry->symlink_target.data,
                     "replacement-target",
                     sizeof("replacement-target") - 1U) == 0,
          "replacement sidecar records the symlink target");
    if (unlink(file) != 0)
        fixture_fatal("could not remove symlink replacement fixture");
    close_live_capture(container_fd, &log, &context);
}

static void test_unsupported_types(const char *source, const char *base_path)
{
    printf(BLUE "::" NC " special-file policy\n");
    char special_container[PATH_MAX];
    join_path(special_container, sizeof(special_container), base_path,
              "special-container");
    int container_fd = -1;
    SidecarLog log = {0};
    PortableCaptureContext context = {0};
    check(create_live_capture(special_container, &container_fd, &log,
                              &context) == 0,
          "fresh sidecar context is ready for special-file tests");
    if (container_fd < 0 || log.implementation == NULL)
        return;
    char path[PATH_MAX];
    join_path(path, sizeof(path), source, "socket");
    write_file(path, "regular", 7);
    PortableRootSpec socket_root = root_spec("SOCKET", path, "SOCKET");
    check(portable_capture_root(&context, &socket_root) == 0,
          "regular special-file fixture is captured before replacement");

    if (unlink(path) != 0)
        fixture_fatal("could not replace regular file with socket");
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0)
        fixture_fatal("could not create socket fixture");
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path))
        fixture_fatal("socket fixture path is too long");
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (errno == EPERM || errno == EACCES) {
            skip_check("socket fixture unavailable in this sandbox");
            close(socket_fd);
            unlink(address.sun_path);
            close_live_capture(container_fd, &log, &context);
            return;
        }
        fixture_fatal("could not bind socket fixture");
    }

    check(portable_capture_root(&context, &socket_root) == 0,
          "socket is warning-and-skip, not a blocking read");
    check(sidecar_log_find(&log, bytes("SOCKET"), bytes(""),
                           &(SidecarLiveView){0}) == 0,
          "socket replacement tombstones the old committed state");
    join_path(path, sizeof(path), special_container, "data/SOCKET");
    struct stat st;
    check(lstat(path, &st) != 0 && errno == ENOENT,
          "socket skip removes the stale payload");
    close(socket_fd);
    unlink(address.sun_path);

    join_path(path, sizeof(path), source, "fifo");
    if (mkfifo(path, 0600) != 0)
        fixture_fatal("could not create FIFO fixture");
    PortableRootSpec fifo_root = root_spec("FIFO", path, "FIFO");
    check(portable_capture_root(&context, &fifo_root) != 0,
          "FIFO is fail-closed without opening or blocking");
    unlink(path);
    close_live_capture(container_fd, &log, &context);
}

static void test_preflight_refusal(const char *source)
{
    printf(BLUE "::" NC " fresh preflight boundaries\n");
    char container_path[] = "/tmp/migr_portable_empty_XXXXXX";
    int container_fd = mkstemp(container_path);
    check(container_fd >= 0, "empty container fixture is created");
    if (container_fd < 0)
        return;
    close(container_fd);
    unlink(container_path);
    if (mkdir(container_path, 0700) != 0)
        fixture_fatal("could not create empty container directory");
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    PortableRootSpec manual = root_spec("MANUAL", source, "MANUAL");
    manual.policy = ROOT_POLICY_MANUAL_NATIVE;
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &manual,
        .root_count = 1
    };
    check(portable_capture_fresh_at(container_fd, &request) != 0,
          "MANUAL_NATIVE is rejected before portable mutation");
    struct stat st;
    check(fstatat(container_fd, "manifest.txt", &st,
                  AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
          "a rejected portable plan leaves no manifest");
    close(container_fd);
    remove_tree(container_path);
}

int main(void)
{
    printf(BLUE "::" NC " portable capture core\n");
    char root_path[] = "/tmp/migr_portable_capture_XXXXXX";
    if (mkdtemp(root_path) == NULL)
        fixture_fatal("could not create fixture root");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), root_path, "source");
    join_path(container_path, sizeof(container_path), root_path, "container");
    make_directory(source_path);
    make_directory(container_path);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open container fixture");

    test_entry_helpers(source_path);
    test_append_physical();
    test_prescan_report();
    test_encoded_payload_names(root_path);
    test_nested_encoded_directories(root_path);
    test_name_and_path_limits(root_path);
    test_fresh_capture(source_path, container_fd, container_path);
    test_capture_context_flags(root_path);
    test_replacement_and_type_change(source_path, root_path);
    test_unsupported_types(source_path, root_path);
    test_preflight_refusal(source_path);

    close(container_fd);
    remove_tree(root_path);
    printf("portable capture tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
