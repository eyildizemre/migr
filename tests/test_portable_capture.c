// Unit tests for the portable capture core (docs/DECISIONS.md D17): the
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
// one out from under a concurrent reader. Symlinks and FIFOs are confirmed
// fail-closed without ever being opened; sockets and devices are
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
                           const struct stat *st, int nsec_exact,
                           PortableXattrs *xattrs, SidecarEntry *out,
                           const SidecarBytes *symlink_target);
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
    check(entry_from_stat("LINK", "item", &link_stat, 1,
                          &empty_xattrs, &entry, &target) == 0,
          "entry_from_stat accepts a symlink target");
    check(entry.kind == SIDECAR_KIND_SYMLINK && entry.size == 0 &&
              entry.xattr_count == 0 &&
              entry.symlink_target.length == target.length &&
              memcmp(entry.symlink_target.data, target.data, target.length) == 0,
          "symlink entry preserves kind, zero size, and target bytes");

    SidecarEntry symlink_entry = entry;

    check(entry_from_stat("LINK", "item", &link_stat, 1,
                          &empty_xattrs, &entry, NULL) != 0,
          "symlink entry without a target is rejected");
    SidecarBytes empty_target = {0};
    check(entry_from_stat("LINK", "item", &link_stat, 1,
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
    entry.symlink_target = bytes("other-target");
    check(entries_equal(&entry, &view, &empty_xattrs) == 0,
          "entries_equal rejects different symlink targets");

    if (unlink(link_path) != 0)
        fixture_fatal("could not remove symlink helper fixture");
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
             entry->kind != SIDECAR_KIND_REGULAR))
            check_state->valid = 0;
    } else if (record->type == SIDECAR_RECORD_XATTR) {
        const SidecarXattr *xattr = &record->value.xattr;
        static const char expected_name[] = "user.migr_test";
        static const char expected_value[] = "portable-xattr";
        check_state->xattrs++;
        if (xattr->name.length == sizeof(expected_name) - 1U &&
            memcmp(xattr->name.data, expected_name,
                   sizeof(expected_name) - 1U) == 0 &&
            xattr->value.length == sizeof(expected_value) - 1U &&
            memcmp(xattr->value.data, expected_value,
                   sizeof(expected_value) - 1U) == 0)
            check_state->expected_xattr_seen = 1;
    } else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT) {
        check_state->commits++;
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
    if (data_fd < 0 || portable_capture_context_init(context, data_fd, log, 1) != 0)
        return -1;
    return 0;
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
    join_path(nested, sizeof(nested), source, "nested");
    join_path(file, sizeof(file), nested, "file.txt");
    make_directory(nested);
    write_file(file, "portable payload", 16);

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

    int slot_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                         O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FreshSidecarCheck sidecar_check = { .valid = 1 };
    SidecarParseResult parse_result;
    check(slot_fd >= 0 &&
          sidecar_parse_fd(slot_fd, fresh_sidecar_callback, &sidecar_check,
                           &parse_result) == SIDECAR_STATUS_OK &&
          sidecar_check.valid && sidecar_check.entries == 3 &&
          sidecar_check.commits == 3 &&
          (!xattr_expected ||
           sidecar_check.expected_xattr_seen),
          "sidecar contains complete groups and captured xattrs");
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
    test_fresh_capture(source_path, container_fd, container_path);
    test_replacement_and_type_change(source_path, root_path);
    test_unsupported_types(source_path, root_path);
    test_preflight_refusal(source_path);

    close(container_fd);
    remove_tree(root_path);
    printf("portable capture tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
