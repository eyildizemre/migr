// Resume, adopt, and interruption-safety coverage for the portable capture
// seam (docs/DECISIONS.md D17/D21): committed-entry skip on unchanged regular and
// symlink sources (inode + metadata/xattr equality; symlink source atime is
// excluded per D18 because target reads may update it + on-disk payload shape),
// forced recapture on a missing or changed payload, and pristine-namespace
// gating before a fresh sidecar is ever recovered onto a partial (manifest written,
// data/
// absent or empty, sidecar absent), refusal (not silent freshening) of a
// non-empty data/ without a sidecar and of a corrupt or symlinked sidecar
// slot, truncated-tail adoption, a manifest-identity mismatch refusing to
// adopt someone else's partial, and real SIGKILL fixtures (child processes,
// not synthetic stand-ins) at every interruption boundary listed for B.3b:
// the replacement tombstone, payload replace/write/close, and the sidecar's
// own mid-ENTRY/mid-XATTR/ENTRY_COMMIT boundaries via the SIDECAR_TEST_HOOKS
// seam shared with tests/test_sidecar_state.c and friends.
//
// The xattr-middle interruption case is skipped (not failed) when the
// fixture filesystem rejects user xattrs -- the same ENOTSUP/EOPNOTSUPP/EPERM
// fallback tests/test_portable_capture.c already uses for its own xattr
// fixture, not a new asymmetry introduced here.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "manifest.h"
#include "portable.h"
#include "sidecar.h"

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
    fprintf(stderr, "portable resume fixture failure: %s\n", message);
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

static void write_file(const char *path, const char *text)
{
    size_t length = strlen(text);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        fixture_fatal("could not create fixture file");
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, text + offset, length - offset);
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

static int symlink_equals(const char *path, const char *expected)
{
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    ssize_t length = readlink(path, target, sizeof(target));
    if (length < 0 || (size_t)length >= sizeof(target))
        return 0;
    size_t expected_length = strlen(expected);
    return (size_t)length == expected_length &&
           memcmp(target, expected, expected_length) == 0;
}

static PortableRootSpec root_spec(const char *id, const char *source,
                                  const char *payload)
{
    return (PortableRootSpec){
        .id = id,
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = payload,
        .source_path = source,
        .restore_path = "",
        .has_restore_path = 1
    };
}

static PortableCaptureRequest request_for(const PortableRootSpec *root,
                                          const char *machine_id)
{
    return (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = machine_id,
        .source_uid = getuid(),
        .roots = root,
        .root_count = 1,
        .nsec_exact = 1
    };
}

static int create_container(const char *path)
{
    if (mkdir(path, 0700) != 0)
        return -1;
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int missing_at(int directory_fd, const char *name)
{
    struct stat st;
    return fstatat(directory_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
           errno == ENOENT;
}

static int child_killed_by(int status)
{
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static SidecarBytes resume_bytes(const char *text)
{
    return (SidecarBytes){ (const unsigned char *)text, strlen(text) };
}

static void test_collision_suffix_resume_key(void)
{
    printf(BLUE "::" NC " collision suffix resume identity\n");
    SidecarEntry current = {0};
    SidecarEntry previous = {0};
    current.root_id = previous.root_id = resume_bytes("ROOT");
    current.logical_path = previous.logical_path = resume_bytes("file");
    current.physical_path = previous.physical_path = resume_bytes("file");
    SidecarLiveView view = {
        .entry = &previous,
        .xattrs = NULL,
        .xattr_count = 0,
        .generation = 0
    };
    PortableXattrs no_xattrs = {0};

    current.collision_suffix = resume_bytes("%7E1");
    check(entries_equal(&current, &view, &no_xattrs) == 0,
          "a changed collision suffix forces resume replacement");

    current.collision_suffix = (SidecarBytes){0};
    check(entries_equal(&current, &view, &no_xattrs) != 0,
          "identical empty collision suffixes preserve resume equality");
}

static int run_fresh_interrupt(int container_fd,
                               const PortableCaptureRequest *request,
                               PortableTestInterruptPoint point)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        portable_capture_test_set_interrupt(point);
        int result = portable_capture_fresh_at(container_fd, request, NULL);
        _exit(result == 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return child_killed_by(status) ? 0 : -1;
}

static int run_resume_interrupt(int container_fd,
                                const PortableCaptureRequest *request,
                                PortableTestInterruptPoint portable_point,
                                SidecarTestInterruptPoint sidecar_point)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        portable_capture_test_set_interrupt(portable_point);
        sidecar_test_set_interrupt(sidecar_point);
        int result = portable_capture_resume_at(container_fd, request, NULL);
        _exit(result == 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return child_killed_by(status) ? 0 : -1;
}

static int fresh_capture(const char *container_path,
                         const PortableCaptureRequest *request,
                         int *container_fd)
{
    *container_fd = create_container(container_path);
    if (*container_fd < 0)
        return -1;
    return portable_capture_fresh_at(*container_fd, request, NULL);
}

static void test_resume_skips_and_replaces(const char *base)
{
    printf(BLUE "::" NC " resume live-state skip and replacement\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    char payload_a[PATH_MAX];
    char payload_b[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "skip-source");
    join_path(container_path, sizeof(container_path), base, "skip-container");
    join_path(payload_a, sizeof(payload_a), container_path, "data/A");
    join_path(payload_b, sizeof(payload_b), container_path, "data/B");
    make_directory(source_path);
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    join_path(source_a, sizeof(source_a), source_path, "a");
    join_path(source_b, sizeof(source_b), source_path, "b");
    write_file(source_a, "unchanged");
    write_file(source_b, "before");

    PortableRootSpec roots[2] = {
        root_spec("A", source_a, "A"),
        root_spec("B", source_b, "B")
    };
    PortableCaptureRequest request = request_for(&roots[0], "a1");
    request.roots = roots;
    request.root_count = 2;
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "fresh partial is available for resume");
    if (container_fd < 0)
        return;

    struct stat before_a;
    check(stat(payload_a, &before_a) == 0 && file_equals(payload_a, "unchanged"),
          "the committed payload exists before resume");
    if (unlink(payload_b) != 0)
        fixture_fatal("could not remove incomplete payload");
    write_file(source_b, "after");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume adopts the existing sidecar");

    struct stat after_a;
    check(stat(payload_a, &after_a) == 0 && after_a.st_ino == before_a.st_ino,
          "an unchanged committed regular file is skipped in place");
    check(file_equals(payload_b, "after"),
          "a missing or changed committed payload is recaptured");
    close(container_fd);
}

static int regular_xattr_fixture_available(void)
{
    char base[] = "/tmp/migr_portable_resume_xattr_XXXXXX";
    int fd = mkstemp(base);
    if (fd < 0)
        return 0;
    close(fd);
    int available = 1;
    if (setxattr(base, "user.migr_resume", "x", 1, 0) != 0 &&
        (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM))
        available = 0;
    unlink(base);
    return available;
}

/*
 * Answers "does this entry's live xattr set consist of exactly these
 * name/value pairs?" for a single-entry root. Returns 1 on exact match
 * (count included), 0 otherwise. view.xattrs is borrowed from the open
 * log, so the check happens before sidecar_log_close.
 */
static int live_xattr_set_exact(int container_fd, const char *root_id,
                                const char *logical,
                                const char *const *names,
                                const char *const *values, size_t count)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        return 0;
    SidecarLiveView view;
    int found = sidecar_log_find(
        &log,
        (SidecarBytes){ (const unsigned char *)root_id, strlen(root_id) },
        (SidecarBytes){ (const unsigned char *)logical, strlen(logical) },
        &view);
    if (found != 1 || view.entry == NULL)
    {
        (void)sidecar_log_close(&log);
        return 0;
    }
    /* Count only user.* xattrs: an SELinux-enabled host auto-assigns
     * security.selinux on every object, which capture faithfully records
     * (D20 E-1) but which is not part of what this test asserts. */
    size_t user_count = 0;
    for (size_t index = 0; index < view.xattr_count; index++)
        if (view.xattrs[index].name.length >= 5 &&
            memcmp(view.xattrs[index].name.data, "user.", 5) == 0)
            user_count++;
    if (user_count != count)
    {
        (void)sidecar_log_close(&log);
        return 0;
    }
    int exact = 1;
    for (size_t index = 0; index < count; index++)
    {
        int matched = 0;
        for (size_t candidate = 0; candidate < view.xattr_count; candidate++)
        {
            const SidecarXattr *xattr = &view.xattrs[candidate];
            if (xattr->name.length < 5 ||
                memcmp(xattr->name.data, "user.", 5) != 0)
                continue;
            size_t name_length = strlen(names[index]);
            size_t value_length = strlen(values[index]);
            if (xattr->name.length == name_length &&
                memcmp(xattr->name.data, names[index], name_length) == 0 &&
                xattr->value.length == value_length &&
                memcmp(xattr->value.data, values[index], value_length) == 0)
            {
                matched = 1;
                break;
            }
        }
        if (!matched)
            exact = 0;
    }
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return 0;
    return exact;
}

static void test_resume_xattr_equivalence(const char *base)
{
    printf(BLUE "::" NC " resume xattr equivalence (added/changed/removed)\n");

    if (!regular_xattr_fixture_available())
    {
        skip_check("xattr resume fixture unavailable on this filesystem");
        return;
    }

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "xattr-source");
    join_path(container_path, sizeof(container_path), base, "xattr-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "entry");
    write_file(source_file, "unchanged-content");

    PortableRootSpec roots[1] = { root_spec("X", source_file, "X") };
    PortableCaptureRequest request = request_for(&roots[0], "c1");
    request.roots = roots;
    request.root_count = 1;
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "xattr resume fixture is captured");
    if (container_fd < 0)
        return;

    static const char *const no_names[1] = { NULL };
    static const char *const no_values[1] = { NULL };

    /* Direction 1: added -- source gains an xattr it did not have. */
    check(setxattr(source_file, "user.migr_resume", "added", 5, 0) == 0,
          "fixture: an xattr is added to the source");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume after adding an xattr succeeds");
    const char *const added_names[1] = { "user.migr_resume" };
    const char *const added_values[1] = { "added" };
    check(live_xattr_set_exact(container_fd, "X", "",
                               added_names, added_values, 1),
          "live sidecar entry carries the added xattr exactly");

    /* Direction 2: changed -- same name, different value. */
    check(setxattr(source_file, "user.migr_resume", "changed", 7, 0) == 0,
          "fixture: the xattr value is changed on the source");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume after changing an xattr value succeeds");
    const char *const changed_names[1] = { "user.migr_resume" };
    const char *const changed_values[1] = { "changed" };
    check(live_xattr_set_exact(container_fd, "X", "",
                               changed_names, changed_values, 1),
          "live sidecar entry carries the changed xattr value exactly");

    /* Direction 3: removed -- source loses the xattr it had. Content and
     * size are identical across all three mutations, so only the sidecar's
     * recorded set (count included) proves the removal was re-captured. */
    check(removexattr(source_file, "user.migr_resume") == 0,
          "fixture: the xattr is removed from the source");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume after removing an xattr succeeds");
    check(live_xattr_set_exact(container_fd, "X", "",
                               no_names, no_values, 0),
          "live sidecar entry carries no xattrs after removal");

    close(container_fd);
}

static void test_encoded_resume(const char *base)
{
    printf(BLUE "::" NC " resume skip for an encoded payload leaf\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "encoded-resume-source");
    join_path(container_path, sizeof(container_path), base,
              "encoded-resume-container");
    make_directory(source_path);

    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "question?name");
    write_file(source_file, "encoded");

    PortableRootSpec root = root_spec("ENCODED", source_path, "ENCODED");
    PortableCaptureRequest request = request_for(&root, "a1e");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "encoded-name fixture is captured before resume");
    if (container_fd < 0)
        return;

    char payload_path[PATH_MAX];
    join_path(payload_path, sizeof(payload_path), container_path,
              "data/ENCODED/question%3Fname");
    char slot_path[PATH_MAX];
    join_path(slot_path, sizeof(slot_path), container_path,
              SIDECAR_SLOT_NAME);
    struct stat payload_before;
    struct stat sidecar_before;
    check(lstat(payload_path, &payload_before) == 0 &&
              file_equals(payload_path, "encoded") &&
              stat(slot_path, &sidecar_before) == 0,
          "encoded payload and sidecar exist before resume");

    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume accepts an unchanged encoded source");
    struct stat payload_after;
    check(lstat(payload_path, &payload_after) == 0 &&
              payload_after.st_ino == payload_before.st_ino,
          "unchanged encoded payload is skipped in place");
    close(container_fd);
}

static int prepare_symlink_replacement(const char *base, const char *label,
                                       PortableRootSpec *root,
                                       PortableCaptureRequest *request,
                                       int *container_fd)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, label);
    char container_name[PATH_MAX];
    int written = snprintf(container_name, sizeof(container_name),
                           "%s-container", label);
    if (written < 0 || (size_t)written >= sizeof(container_name))
        return -1;
    join_path(container_path, sizeof(container_path), base, container_name);
    make_directory(source_path);

    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source_path, "link");
    if (symlink("before-target", link_path) != 0)
        return -1;
    char *stable_link = strdup(link_path);
    if (stable_link == NULL)
        fixture_fatal("could not retain symlink source path");

    *root = root_spec("LINK", stable_link, "LINK");
    *request = request_for(root, "c3c0");
    if (fresh_capture(container_path, request, container_fd) != 0) {
        free(stable_link);
        return -1;
    }
    return 0;
}

static void replace_symlink_target(const char *path, const char *target)
{
    if (unlink(path) != 0 || symlink(target, path) != 0)
        fixture_fatal("could not replace symlink fixture target");
}

static int symlink_live_target(int container_fd, const char *expected)
{
    SidecarLog log = {0};
    if (sidecar_log_adopt_at(container_fd, &log) != SIDECAR_OPEN_RESUMABLE)
        return 0;
    SidecarLiveView view;
    int found = sidecar_log_find(
        &log,
        (SidecarBytes){ (const unsigned char *)"LINK", 4 },
        (SidecarBytes){ (const unsigned char *)"", 0 }, &view);
    size_t expected_length = strlen(expected);
    int result = found == 1 && view.entry->kind == SIDECAR_KIND_SYMLINK &&
                 view.entry->symlink_target.length == expected_length &&
                 memcmp(view.entry->symlink_target.data, expected,
                        expected_length) == 0;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        return 0;
    return result;
}

static int symlink_placeholder(int container_fd)
{
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0)
        return 0;
    struct stat st;
    int result = fstatat(data_fd, "LINK", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                 S_ISREG(st.st_mode) && st.st_size == 0;
    if (close(data_fd) != 0)
        result = 0;
    return result;
}

static void test_symlink_resume(const char *base)
{
    printf(BLUE "::" NC " symlink resume skip and target replacement\n");
    PortableRootSpec root;
    PortableCaptureRequest request;
    int container_fd = -1;
    char container_path[PATH_MAX];
    join_path(container_path, sizeof(container_path), base,
              "symlink-resume-container");
    check(prepare_symlink_replacement(base, "symlink-resume", &root,
                                      &request, &container_fd) == 0,
          "symlink resume fixture has a committed predecessor");
    if (container_fd < 0)
        return;

    char slot_path[PATH_MAX];
    join_path(slot_path, sizeof(slot_path), container_path,
              SIDECAR_SLOT_NAME);
    char payload_path[PATH_MAX];
    join_path(payload_path, sizeof(payload_path), container_path,
              "data/LINK");
    struct stat payload_before;
    struct stat sidecar_before;
    check(lstat(payload_path, &payload_before) == 0 &&
              S_ISREG(payload_before.st_mode) && payload_before.st_size == 0 &&
              stat(slot_path, &sidecar_before) == 0,
          "symlink placeholder and sidecar exist before resume");
    check(symlink_live_target(container_fd, "before-target"),
          "initial symlink entry records its target");

    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume accepts an unchanged symlink");
    struct stat payload_after;
    struct stat sidecar_after;
    check(lstat(payload_path, &payload_after) == 0 &&
              payload_after.st_ino == payload_before.st_ino &&
              stat(slot_path, &sidecar_after) == 0 &&
              sidecar_after.st_size == sidecar_before.st_size &&
              symlink_placeholder(container_fd) &&
              symlink_live_target(container_fd, "before-target"),
          "unchanged symlink resume leaves payload and sidecar untouched");

    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "a second unchanged symlink resume remains idempotent");
    check(stat(slot_path, &sidecar_after) == 0 &&
              sidecar_after.st_size == sidecar_before.st_size,
          "repeated unchanged resume appends no sidecar group");

    replace_symlink_target(root.capture_path, "after-target");
    check(symlink_equals(root.capture_path, "after-target"),
          "fixture exposes the changed symlink target");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume recaptures a changed symlink target");
    check(symlink_placeholder(container_fd) &&
              symlink_live_target(container_fd, "after-target") &&
              stat(slot_path, &sidecar_after) == 0 &&
              sidecar_after.st_size > sidecar_before.st_size,
          "changed symlink gets a fresh group and intact placeholder");

    close(container_fd);
    free((void *)root.capture_path);
}

static void test_missing_sidecar(const char *base)
{
    printf(BLUE "::" NC " pristine sidecar recovery\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "missing-source");
    join_path(container_path, sizeof(container_path), base,
              "missing-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "recoverable");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a2");
    int container_fd = create_container(container_path);
    if (container_fd < 0)
        fixture_fatal("could not create missing-sidecar container");

    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_MANIFEST) == 0,
          "SIGKILL after manifest leaves an adoptable boundary");
    check(!missing_at(container_fd, "manifest.txt") &&
          missing_at(container_fd, SIDECAR_SLOT_NAME),
          "manifest exists while sidecar is still absent");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume creates a sidecar only for the pristine namespace");
    check(!missing_at(container_fd, SIDECAR_SLOT_NAME),
          "recovery creates the sidecar slot");
    close(container_fd);
}

static void test_nonempty_without_sidecar(const char *base)
{
    printf(BLUE "::" NC " non-pristine sidecar refusal\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "orphan-source");
    join_path(container_path, sizeof(container_path), base,
              "orphan-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "orphan");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a3");
    int container_fd = create_container(container_path);
    if (container_fd < 0)
        fixture_fatal("could not create orphan container");
    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_MANIFEST) == 0,
          "orphan fixture starts at the manifest boundary");
    if (mkdirat(container_fd, "data", 0700) != 0)
        fixture_fatal("could not create orphan data directory");
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (data_fd < 0)
        fixture_fatal("could not open orphan data directory");
    int orphan_fd = openat(data_fd, "orphan", O_WRONLY | O_CREAT | O_EXCL |
                            O_CLOEXEC, 0600);
    if (orphan_fd < 0 || close(orphan_fd) != 0 || close(data_fd) != 0)
        fixture_fatal("could not create orphan payload");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "resume refuses a nonempty data namespace without a sidecar");
    check(missing_at(container_fd, SIDECAR_SLOT_NAME),
          "refusal does not silently create a fresh sidecar");
    struct stat st;
    check(fstatat(container_fd, "data/orphan", &st, AT_SYMLINK_NOFOLLOW) == 0,
          "refusal leaves the unclaimed payload untouched");
    close(container_fd);
}

static void test_unsafe_sidecar(const char *base)
{
    printf(BLUE "::" NC " corrupt and unsafe sidecar refusal\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    char target_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "unsafe-source");
    join_path(container_path, sizeof(container_path), base,
              "unsafe-container");
    join_path(target_path, sizeof(target_path), base, "sidecar-target");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "unsafe");
    write_file(target_path, "not a sidecar");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a4");
    int container_fd = create_container(container_path);
    if (container_fd < 0)
        fixture_fatal("could not create unsafe container");
    check(run_fresh_interrupt(container_fd, &request,
                              PORTABLE_TEST_AFTER_MANIFEST) == 0,
          "unsafe fixture starts at the manifest boundary");
    char slot_path[PATH_MAX];
    join_path(slot_path, sizeof(slot_path), container_path, SIDECAR_SLOT_NAME);
    if (symlink(target_path, slot_path) != 0)
        fixture_fatal("could not create unsafe sidecar symlink");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "a symlink sidecar is unusable rather than followed");
    check(missing_at(container_fd, "data"),
          "unsafe sidecar refusal leaves the missing data namespace absent");

    if (unlink(slot_path) != 0 || mkdirat(container_fd, "data", 0700) != 0)
        fixture_fatal("could not prepare malformed sidecar fixture");
    int malformed_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (malformed_fd < 0 || write(malformed_fd, "garbage", 7) != 7 ||
        close(malformed_fd) != 0)
        fixture_fatal("could not write malformed sidecar fixture");
    check(portable_capture_resume_at(container_fd, &request, NULL) != 0,
          "an interior-corrupt sidecar is unusable rather than freshened");
    check(file_equals(target_path, "not a sidecar"),
          "malformed-sidecar refusal leaves the unrelated target untouched");
    close(container_fd);
}

static void test_truncated_tail(const char *base)
{
    printf(BLUE "::" NC " truncated sidecar tail recovery\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    char slot_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "tail-source");
    join_path(container_path, sizeof(container_path), base, "tail-container");
    join_path(slot_path, sizeof(slot_path), container_path, SIDECAR_SLOT_NAME);
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "tail");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "a5");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "fresh capture creates a complete sidecar");
    if (container_fd < 0)
        return;
    int slot_fd = open(slot_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (slot_fd < 0)
        fixture_fatal("could not open sidecar for tail fixture");
    static const char tail[] = "ENTRY\0partial";
    if (write(slot_fd, tail, sizeof(tail) - 1U) !=
            (ssize_t)(sizeof(tail) - 1U) || close(slot_fd) != 0)
        fixture_fatal("could not append sidecar tail");
    struct stat before;
    if (stat(slot_path, &before) != 0)
        fixture_fatal("could not stat tailed sidecar");
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "resume truncates an incomplete final sidecar record");
    struct stat after;
    check(stat(slot_path, &after) == 0 && after.st_size < before.st_size,
          "tail recovery truncates only the incomplete suffix");
    close(container_fd);
}

static int prepare_replacement(const char *base, const char *label,
                               PortableRootSpec *root,
                               PortableCaptureRequest *request,
                               int *container_fd)
{
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, label);
    char container_name[PATH_MAX];
    int written = snprintf(container_name, sizeof(container_name),
                           "%s-container", label);
    if (written < 0 || (size_t)written >= sizeof(container_name))
        return -1;
    join_path(container_path, sizeof(container_path), base, container_name);
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "before");
    char *stable_source = strdup(source_file);
    if (stable_source == NULL)
        fixture_fatal("could not retain interruption source path");
    *root = root_spec("ROOT", stable_source, "ROOT");
    *request = request_for(root, "b1");
    if (fresh_capture(container_path, request, container_fd) != 0) {
        free(stable_source);
        return -1;
    }
    write_file(source_file, "after");
    return 0;
}

static void test_sigkill_boundaries(const char *base)
{
    printf(BLUE "::" NC " SIGKILL interruption boundaries\n");
    struct {
        const char *label;
        PortableTestInterruptPoint portable_point;
        SidecarTestInterruptPoint sidecar_point;
    } cases[] = {
        { "delete-before", PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "delete-after", PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-replace-before", PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-replace-after", PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-write-before", PORTABLE_TEST_BEFORE_PAYLOAD_WRITE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-write-after", PORTABLE_TEST_AFTER_PAYLOAD_WRITE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-close-before", PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-close-after", PORTABLE_TEST_AFTER_PAYLOAD_CLOSE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "entry-middle", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_MID_ENTRY },
        { "xattr-middle", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_MID_XATTR },
        { "commit-before", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_BEFORE_ENTRY_COMMIT },
        { "commit-after", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_AFTER_ENTRY_COMMIT },
        { "commit-middle", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_MID_ENTRY_COMMIT }
    };

    int xattr_available = regular_xattr_fixture_available();
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        if (!xattr_available && strcmp(cases[index].label, "xattr-middle") == 0) {
            skip_check("xattr interruption fixture unavailable on this filesystem");
            continue;
        }
        PortableRootSpec root;
        PortableCaptureRequest request;
        int container_fd = -1;
        char label[NAME_MAX];
        int length = snprintf(label, sizeof(label), "interrupt-%s",
                              cases[index].label);
        if (length < 0 || (size_t)length >= sizeof(label))
            fixture_fatal("interruption label is too long");
        check(prepare_replacement(base, label, &root, &request,
                                  &container_fd) == 0,
              "interruption fixture has a committed predecessor");
        if (container_fd < 0)
            continue;
        if (strcmp(cases[index].label, "xattr-middle") == 0) {
            if (setxattr(root.capture_path, "user.migr_resume", "value", 5,
                         0) != 0)
                fixture_fatal("could not create xattr interruption fixture");
        }
        int killed = run_resume_interrupt(container_fd, &request,
                                          cases[index].portable_point,
                                          cases[index].sidecar_point);
        check(killed == 0, cases[index].label);
        portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
        sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
        check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
              "a killed capture remains resumable");
        check(file_equals(root.capture_path, "after"),
              "source remains intact after interruption recovery");
        if (strcmp(cases[index].label, "xattr-middle") == 0)
        {
            const char *const names[1] = { "user.migr_resume" };
            const char *const values[1] = { "value" };
            check(live_xattr_set_exact(container_fd, "ROOT", "",
                                       names, values, 1),
                  "xattr set is exact after a mid-XATTR SIGKILL: "
                  "the half-written record did not survive and the "
                  "completed record is present");
        }
        close(container_fd);
        free((void *)root.capture_path);
    }
}

static int symlink_xattr_fixture_available(void)
{
    char base[] = "/tmp/migr_portable_resume_symlink_xattr_XXXXXX";
    if (mkdtemp(base) == NULL)
        return 0;
    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), base, "link");
    int available = symlink("target", link_path) == 0;
    if (available && lsetxattr(link_path, "user.migr_symlink_resume", "x", 1,
                               0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM)
            available = 0;
        else
            fixture_fatal("could not probe symlink xattr support");
    }
    if (unlink(link_path) != 0 || rmdir(base) != 0)
        fixture_fatal("could not remove symlink xattr probe");
    return available;
}

static void test_stale_xattr_interruption(const char *base)
{
    printf(BLUE "::" NC " stale xattr does not survive a mid-XATTR SIGKILL\n");
    if (!regular_xattr_fixture_available())
    {
        skip_check("xattr interruption fixture unavailable on this filesystem");
        return;
    }

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "stale-xattr-source");
    join_path(container_path, sizeof(container_path), base,
              "stale-xattr-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "content");
    if (setxattr(source_file, "user.migr_stale", "old", 3, 0) != 0)
        fixture_fatal("could not plant the stale xattr fixture");

    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "c2");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "predecessor is committed with the stale xattr");
    if (container_fd < 0)
        return;

    /* Replace the source's xattr set: the stale attribute is removed and a
     * fresh one added, so the interrupted run still has an XATTR record to
     * write (SIDECAR_TEST_MID_XATTR only fires while one is being written). */
    if (removexattr(source_file, "user.migr_stale") != 0 ||
        setxattr(source_file, "user.migr_fresh", "new", 3, 0) != 0)
        fixture_fatal("could not switch the source xattr set");

    check(run_resume_interrupt(container_fd, &request,
                               PORTABLE_TEST_INTERRUPT_NONE,
                               SIDECAR_TEST_MID_XATTR) == 0,
          "resume is killed mid-XATTR-record");
    portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
    sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
    check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
          "interrupted resume recovers");

    const char *const names[1] = { "user.migr_fresh" };
    const char *const values[1] = { "new" };
    check(live_xattr_set_exact(container_fd, "ROOT", "",
                               names, values, 1),
          "live set is exactly the fresh attribute after recovery "
          "(stale attribute gone, no partial leftover)");
    close(container_fd);
}

static void test_symlink_sigkill_boundaries(const char *base)
{
    printf(BLUE "::" NC " symlink SIGKILL interruption boundaries\n");
    struct {
        const char *label;
        PortableTestInterruptPoint portable_point;
        SidecarTestInterruptPoint sidecar_point;
    } cases[] = {
        { "delete-before", PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "delete-after", PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-replace-before", PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "payload-replace-after", PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
          SIDECAR_TEST_INTERRUPT_NONE },
        { "entry-middle", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_MID_ENTRY },
        { "xattr-middle", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_MID_XATTR },
        { "commit-before", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_BEFORE_ENTRY_COMMIT },
        { "commit-after", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_AFTER_ENTRY_COMMIT },
        { "commit-middle", PORTABLE_TEST_INTERRUPT_NONE,
          SIDECAR_TEST_MID_ENTRY_COMMIT }
    };
    int xattr_available = symlink_xattr_fixture_available();

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        if (!xattr_available && strcmp(cases[index].label, "xattr-middle") == 0) {
            skip_check("symlink xattr interruption fixture unavailable");
            continue;
        }

        PortableRootSpec root;
        PortableCaptureRequest request;
        int container_fd = -1;
        char label[NAME_MAX];
        int length = snprintf(label, sizeof(label), "symlink-interrupt-%s",
                              cases[index].label);
        if (length < 0 || (size_t)length >= sizeof(label))
            fixture_fatal("symlink interruption label is too long");
        check(prepare_symlink_replacement(base, label, &root, &request,
                                           &container_fd) == 0,
              "symlink interruption fixture has a committed predecessor");
        if (container_fd < 0)
            continue;

        replace_symlink_target(root.capture_path, "after-target");

        if (strcmp(cases[index].label, "xattr-middle") == 0 &&
            lsetxattr(root.capture_path, "user.migr_symlink_resume", "value",
                      5, 0) != 0)
            fixture_fatal("could not create symlink xattr interruption fixture");

        int killed = run_resume_interrupt(container_fd, &request,
                                          cases[index].portable_point,
                                          cases[index].sidecar_point);
        check(killed == 0, cases[index].label);
        portable_capture_test_set_interrupt(PORTABLE_TEST_INTERRUPT_NONE);
        sidecar_test_set_interrupt(SIDECAR_TEST_INTERRUPT_NONE);
        check(portable_capture_resume_at(container_fd, &request, NULL) == 0,
              "a killed symlink capture remains resumable");
        check(symlink_placeholder(container_fd) &&
                  symlink_live_target(container_fd, "after-target"),
              "resumed symlink capture has the target and placeholder");
        close(container_fd);
        free((void *)root.capture_path);
    }
}

static void test_identity_mismatch(const char *base)
{
    printf(BLUE "::" NC " resume identity gate\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "identity-source");
    join_path(container_path, sizeof(container_path), base,
              "identity-container");
    make_directory(source_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, "file");
    write_file(source_file, "identity");
    PortableRootSpec root = root_spec("ROOT", source_file, "ROOT");
    PortableCaptureRequest request = request_for(&root, "c1");
    int container_fd = -1;
    check(fresh_capture(container_path, &request, &container_fd) == 0,
          "identity fixture is captured");
    if (container_fd < 0)
        return;
    PortableCaptureRequest mismatch = request_for(&root, "c2");
    check(portable_capture_resume_at(container_fd, &mismatch, NULL) != 0,
          "a different source identity cannot adopt the partial");
    close(container_fd);
}

int main(void)
{
    printf(BLUE "::" NC " portable resume and interruption tests\n");
    char base[] = "/tmp/migr_portable_resume_XXXXXX";
    if (mkdtemp(base) == NULL)
        fixture_fatal("could not create fixture root");

    test_collision_suffix_resume_key();
    test_resume_skips_and_replaces(base);
    test_resume_xattr_equivalence(base);
    test_encoded_resume(base);
    test_symlink_resume(base);
    test_missing_sidecar(base);
    test_nonempty_without_sidecar(base);
    test_unsafe_sidecar(base);
    test_truncated_tail(base);
    test_sigkill_boundaries(base);
    test_stale_xattr_interruption(base);
    test_symlink_sigkill_boundaries(base);
    test_identity_mismatch(base);

    remove_tree(base);
    printf("portable resume tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
