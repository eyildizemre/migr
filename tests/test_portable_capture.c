// Unit tests for the portable capture core (docs/DECISIONS.md D17/D18/D19/D21):
// the fresh and resumed walks over regular files and directories, behind the
// test-only direct API (D14 -- never reachable from a release binary), including
// the collision plan's physical-name and source-plan invariants.
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
#include "portable_hashset_internal.h"
#include "portable_name.h"
#include "portable_prescan_internal.h" /* Direct prescan_request() validation
                                        * coverage uses this internal seam. */
#include "selection.h"
#include "sidecar.h"

extern int entry_from_stat(const char *root_id, const char *logical,
                           const char *physical_leaf,
                           const char *collision_suffix,
                           const struct stat *st, int nsec_exact,
                           PortableXattrs *xattrs, SidecarEntry *out,
                           const SidecarBytes *symlink_target,
                           const SidecarBytes *hardlink_root_id,
                           const SidecarBytes *hardlink_logical_path);
extern int append_physical(char *destination, size_t destination_size,
                           const char *parent, const char *encoded_leaf);
extern int prescan_report_add(PortablePrescanReport *report,
                              const PortablePrescanViolation *violation);
extern int reconcile_stale_live(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical);
extern void skeleton_copy(char *destination, size_t destination_size,
                          const char *source);
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

static int remove_fd_entry(int *parent_fd, const char *name);

static int remove_fd_children(int *directory_fd)
{
    for (;;) {
        int scan_fd = openat(*directory_fd, ".",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (directory == NULL) {
            if (scan_fd >= 0)
                close(scan_fd);
            return -1;
        }

        char child[NAME_MAX + 1U];
        int found = 0;
        int failed = 0;
        errno = 0;
        for (;;) {
            struct dirent *entry = readdir(directory);
            if (entry == NULL) {
                if (errno != 0)
                    failed = 1;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;
            size_t length = strlen(entry->d_name);
            if (length == 0 || length > NAME_MAX) {
                failed = 1;
                break;
            }
            memcpy(child, entry->d_name, length + 1U);
            found = 1;
            break;
        }
        if (closedir(directory) != 0)
            failed = 1;
        if (failed)
            return -1;
        if (!found)
            return 0;
        if (remove_fd_entry(directory_fd, child) != 0)
            return -1;
    }
}

static int remove_fd_entry(int *parent_fd, const char *name)
{
    struct stat st;
    if (fstatat(*parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(*parent_fd, name, 0) == 0 ? 0 : -1;

    int directory_fd = openat(*parent_fd, name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    if (close(*parent_fd) != 0) {
        close(directory_fd);
        return -1;
    }
    *parent_fd = -1;

    if (remove_fd_children(&directory_fd) != 0) {
        close(directory_fd);
        return -1;
    }

    int reopened_parent = openat(directory_fd, "..",
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (reopened_parent < 0) {
        close(directory_fd);
        return -1;
    }
    if (close(directory_fd) != 0 ||
        unlinkat(reopened_parent, name, AT_REMOVEDIR) != 0) {
        close(reopened_parent);
        return -1;
    }
    *parent_fd = reopened_parent;
    return 0;
}

static void remove_tree_fd(const char *path)
{
    int directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        if (errno == ENOENT)
            return;
        fixture_fatal("could not open fixture tree for fd cleanup");
    }
    if (remove_fd_children(&directory_fd) != 0 || close(directory_fd) != 0 ||
        rmdir(path) != 0)
        fixture_fatal("could not remove fixture tree by descriptor");
}

static int create_live_capture(const char *container_path, int *container_fd,
                               SidecarLog *log,
                               PortableCaptureContext *context);
static void close_live_capture(int container_fd, SidecarLog *log,
                               PortableCaptureContext *context);

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

static int live_entry_identity(SidecarLog *log, const char *root,
                               const char *logical, const char *physical_leaf,
                               const char *collision_suffix)
{
    SidecarLiveView view;
    int found = sidecar_log_find(log, bytes(root), bytes(logical), &view);
    return found == 1 &&
           sidecar_bytes_match_text(view.entry->logical_path, logical) &&
           sidecar_bytes_match_text(view.entry->physical_leaf, physical_leaf) &&
           sidecar_bytes_match_text(view.entry->collision_suffix,
                                    collision_suffix);
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

static void test_path_validation(void)
{
    printf(BLUE "::" NC " portable path-component grammar\n");
    char embedded_nul[] = { 'a', '\0', 'b' };
    check(portable_component_valid(embedded_nul, sizeof(embedded_nul)) == 0 &&
              portable_relative_bytes_valid(embedded_nul,
                                             sizeof(embedded_nul), 0) == 0,
          "length-based validation rejects embedded NUL bytes");
    check(portable_component_valid(embedded_nul, strlen(embedded_nul)) == 1 &&
              portable_relative_bytes_valid(embedded_nul,
                                             strlen(embedded_nul), 0) == 1,
          "capture-side validation retains the visible NUL-terminated path");
}

static void test_collision_suffix_parser(void)
{
    printf(BLUE "::" NC " collision suffix parser contract\n");
    uint64_t value = 0;
    check(portable_collision_suffix_parse("%7E1", 4, &value) && value == 1,
          "collision suffix parser returns the encoded number");
    check(portable_collision_suffix_parse(
              "%7E18446744073709551615", 23, &value) &&
              value == UINT64_MAX,
          "collision suffix parser accepts the uint64 ceiling");
    check(!portable_collision_suffix_parse("%7E01", 5, &value) &&
              !portable_collision_suffix_parse("%7e1", 4, &value),
          "collision suffix parser rejects zero-padded and lower-case forms");
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

    PortablePrescanReport collision_report;
    portable_prescan_report_init(&collision_report);
    PortablePrescanViolation collision = {
        .kind = PORTABLE_PRESCAN_CASE_COLLISION,
        .limit = 0,
        .actual = 0
    };
    strcpy(collision.root_id, "CASE");
    strcpy(collision.logical_path, "Foo");
    strcpy(collision.collides_with_logical_path, "foo");
    check(prescan_report_add(&collision_report, &collision) == 0 &&
              collision_report.total_count == 1 &&
              collision_report.example_count == 1 &&
              collision_report.examples[0].kind ==
                  PORTABLE_PRESCAN_CASE_COLLISION &&
              strcmp(collision_report.examples[0].root_id, "CASE") == 0 &&
              strcmp(collision_report.examples[0].logical_path, "Foo") == 0 &&
              strcmp(collision_report.examples[0].collides_with_logical_path,
                     "foo") == 0 &&
              collision_report.examples[0].limit == 0 &&
              collision_report.examples[0].actual == 0,
          "case-collision fields keep a non-empty pair and zero limit/actual");
    portable_prescan_report_free(&collision_report);

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

static void test_case_fold_helpers(void)
{
    printf(BLUE "::" NC " ASCII case-fold sibling set\n");
    char folded[32];
    ascii_fold_copy(folded, sizeof(folded), "Foo/BAR");
    check(strcmp(folded, "foo/bar") == 0,
          "ASCII letters are folded while separators remain unchanged");

    static const char non_ascii[] = "caf\xc3\x89";
    ascii_fold_copy(folded, sizeof(folded), non_ascii);
    check(strcmp(folded, non_ascii) == 0 &&
              (unsigned char)folded[3] == 0xc3U &&
              (unsigned char)folded[4] == 0x89U,
          "bytes outside ASCII are preserved byte-for-byte");

    struct {
        char bytes[4];
        char guard;
    } short_buffer = { { 0 }, '!' };
    ascii_fold_copy(short_buffer.bytes, sizeof(short_buffer.bytes), "ABCDE");
    check(strcmp(short_buffer.bytes, "abc") == 0 &&
              short_buffer.guard == '!',
          "ASCII folding terminates within a short destination");

    PortableCaseFoldSet set = { .hash_salt = sidecar_process_salt() };
    char *existing = NULL;
    check(case_fold_set_find_or_insert(&set, "foo", "Foo", &existing) == 0 &&
              existing == NULL,
          "a fresh folded sibling is inserted");
    check(case_fold_set_find_or_insert(&set, "foo", "foo", &existing) == 1 &&
              existing != NULL && strcmp(existing, "Foo") == 0,
          "a folded collision returns the first logical path");

    int inserted = 0;
    for (size_t index = 0; index < 40U; index++) {
        char key[32];
        char logical[32];
        int key_length = snprintf(key, sizeof(key), "key-%zu", index);
        int logical_length = snprintf(logical, sizeof(logical),
                                      "path-%zu", index);
        if (key_length < 0 || (size_t)key_length >= sizeof(key) ||
            logical_length < 0 || (size_t)logical_length >= sizeof(logical))
            fixture_fatal("could not build case-fold helper fixture");
        existing = NULL;
        if (case_fold_set_find_or_insert(&set, key, logical, &existing) != 0)
            fixture_fatal("case-fold sibling set rejected a fresh key");
        inserted++;
    }
    check(inserted == 40 && set.count == 41 && set.capacity >= 64U,
          "case-fold sibling set grows through open-addressing rehashes");
    case_fold_set_free(&set);
    check(set.slots == NULL && set.count == 0 && set.capacity == 0,
          "case-fold sibling set frees every stored path");

    char skeleton[32];
    skeleton_copy(skeleton, sizeof(skeleton), "cafe");
    check(strcmp(skeleton, "cafe") == 0,
          "ASCII skeleton preserves non-letter bytes");
    skeleton_copy(skeleton, sizeof(skeleton), "caf\xc3\xa9");
    char cafe_skeleton[32];
    strcpy(cafe_skeleton, skeleton);
    skeleton_copy(skeleton, sizeof(skeleton), "CAF\xc3\x89");
    check(strcmp(skeleton, cafe_skeleton) == 0 &&
              (unsigned char)skeleton[3] == 1U &&
              (unsigned char)skeleton[4] == 1U,
          "skeleton maps non-ASCII bytes to a common placeholder");
    char alpha_skeleton[32];
    char alpha_two_skeleton[32];
    skeleton_copy(alpha_skeleton, sizeof(alpha_skeleton), "alpha.txt");
    skeleton_copy(alpha_two_skeleton, sizeof(alpha_two_skeleton), "alpha2.txt");
    check(strcmp(alpha_skeleton, alpha_two_skeleton) != 0,
          "different ASCII skeletons remain separate candidates");
    struct {
        char bytes[4];
        char guard;
    } short_skeleton = { { 0 }, '!' };
    skeleton_copy(short_skeleton.bytes, sizeof(short_skeleton.bytes),
                  "caf\xc3\xa9");
    check(short_skeleton.bytes[3] == '\0' && short_skeleton.guard == '!',
          "skeleton folding terminates within a short destination");
}

static int missing_container_entry(int container_fd, const char *name)
{
    struct stat st;
    return fstatat(container_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
           errno == ENOENT;
}

static int empty_capture_container(int container_fd)
{
    return missing_container_entry(container_fd, "manifest.txt") &&
           missing_container_entry(container_fd, "data") &&
           missing_container_entry(container_fd, SIDECAR_SLOT_NAME);
}

static int collision_pair_matches(const PortablePrescanViolation *violation,
                                  const char *first, const char *second)
{
    if (violation == NULL ||
        violation->kind != PORTABLE_PRESCAN_CASE_COLLISION ||
        !violation->resolved)
        return 0;
    return (strcmp(violation->logical_path, first) == 0 &&
            strcmp(violation->collides_with_logical_path, second) == 0) ||
           (strcmp(violation->logical_path, second) == 0 &&
            strcmp(violation->collides_with_logical_path, first) == 0);
}

static int case_name_member(const char *name, const char *const *names,
                            size_t name_count)
{
    for (size_t index = 0; index < name_count; index++)
        if (strcmp(name, names[index]) == 0)
            return 1;
    return 0;
}

static int collision_example_matches_names(
    const PortablePrescanViolation *violation, const char *const *names,
    size_t name_count)
{
    if (violation == NULL || names == NULL ||
        violation->kind != PORTABLE_PRESCAN_CASE_COLLISION ||
        !violation->resolved ||
        strcmp(violation->root_id, "CASE") != 0 ||
        !case_name_member(violation->logical_path, names, name_count) ||
        !case_name_member(violation->collides_with_logical_path, names,
                          name_count) ||
        strcmp(violation->logical_path,
               violation->collides_with_logical_path) == 0)
        return 0;

    char left[SIDECAR_MAX_PATH + 1U];
    char right[SIDECAR_MAX_PATH + 1U];
    ascii_fold_copy(left, sizeof(left), violation->logical_path);
    ascii_fold_copy(right, sizeof(right),
                    violation->collides_with_logical_path);
    return strcmp(left, right) == 0;
}

static int run_case_fixture(const char *base, const char *label,
                            const char *const *names, size_t name_count,
                            int case_sensitive, char *source_path,
                            size_t source_size, char *container_path,
                            size_t container_size, int *container_fd,
                            PortablePrescanReport *report)
{
    join_path(source_path, source_size, base, label);
    char container_label[PATH_MAX];
    int label_length = snprintf(container_label, sizeof(container_label),
                                "%s-container", label);
    if (label_length < 0 || (size_t)label_length >= sizeof(container_label))
        fixture_fatal("case-fold fixture label is too long");
    join_path(container_path, container_size, base, container_label);
    make_directory(source_path);
    make_directory(container_path);

    for (size_t index = 0; index < name_count; index++) {
        char path[PATH_MAX];
        join_path(path, sizeof(path), source_path, names[index]);
        write_file(path, "x", 1);
    }

    *container_fd = open(container_path,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (*container_fd < 0)
        fixture_fatal("could not open case-fold container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = case_sensitive
    };
    portable_prescan_report_init(report);
    return portable_capture_fresh_at(*container_fd, &request, report);
}

static int run_case_plan_fixture(const char *base, const char *label,
                                 const char *const *names, size_t name_count,
                                 int case_sensitive, char *source_path,
                                 size_t source_size, char *container_path,
                                 size_t container_size, int *container_fd,
                                 PortablePrescanReport *report)
{
    join_path(source_path, source_size, base, label);
    char container_label[PATH_MAX];
    int label_length = snprintf(container_label, sizeof(container_label),
                                "%s-container", label);
    if (label_length < 0 || (size_t)label_length >= sizeof(container_label))
        fixture_fatal("case-plan fixture label is too long");
    join_path(container_path, container_size, base, container_label);
    make_directory(source_path);
    make_directory(container_path);

    for (size_t index = 0; index < name_count; index++) {
        char path[PATH_MAX];
        join_path(path, sizeof(path), source_path, names[index]);
        write_file(path, "x", 1);
    }

    *container_fd = open(container_path,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (*container_fd < 0)
        fixture_fatal("could not open case-plan container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = case_sensitive
    };
    portable_prescan_report_init(report);
    return portable_collision_plan_build(*container_fd, &request, report);
}

static void test_case_collision_prescan(const char *base)
{
    printf(BLUE "::" NC " ASCII case-collision pre-scan\n");
    static const char *const pair[] = { "Foo", "foo" };
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;

    int result = run_case_fixture(base, "case-collision", pair,
                                  sizeof(pair) / sizeof(pair[0]), 0,
                                  source_path, sizeof(source_path),
                                  container_path, sizeof(container_path),
                                  &container_fd, &report);
    check(result == 0 && report.total_count == 1 &&
              report.example_count == 1 &&
              strcmp(report.examples[0].root_id, "CASE") == 0 &&
              collision_pair_matches(&report.examples[0], "Foo", "foo"),
          "case-insensitive pre-scan reports both ASCII-colliding siblings");
    struct stat collision_stat;
    SidecarLog collision_log = {0};
    int collision_log_open = sidecar_log_adopt_at(container_fd,
                                                   &collision_log) ==
                             SIDECAR_OPEN_RESUMABLE;
    SidecarLiveView collision_upper = {0};
    SidecarLiveView collision_lower = {0};
    int collision_entries = collision_log_open &&
        sidecar_log_find(&collision_log, bytes("CASE"), bytes("Foo"),
                         &collision_upper) == 1 &&
        sidecar_log_find(&collision_log, bytes("CASE"), bytes("foo"),
                         &collision_lower) == 1;
    check(fstatat(container_fd, "data/CASE/Foo", &collision_stat,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(collision_stat.st_mode) &&
              fstatat(container_fd, "data/CASE/foo%7E1", &collision_stat,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(collision_stat.st_mode) &&
              collision_entries &&
              sidecar_bytes_match_text(collision_upper.entry->collision_suffix,
                                        "") &&
              sidecar_bytes_match_text(collision_lower.entry->collision_suffix,
                                        "%7E1"),
          "resolved collision writes both physical payloads and suffix fields");
    if (collision_log_open)
        sidecar_log_close(&collision_log);
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    result = run_case_fixture(base, "case-sensitive", pair,
                              sizeof(pair) / sizeof(pair[0]), 1,
                              source_path, sizeof(source_path),
                              container_path, sizeof(container_path),
                              &container_fd, &report);
    struct stat st;
    check(result == 0 && report.total_count == 0 &&
              report.shortening_count == 0 &&
              report.collision_plan.count == 0,
          "case-sensitive pre-scan permits distinct ASCII siblings");
    check(fstatat(container_fd, "data/CASE/Foo", &st,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode) &&
              fstatat(container_fd, "data/CASE/foo", &st,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode),
          "case-sensitive capture keeps both payload names");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const prefixes[] = { "Foo", "Foobar", "foo2" };
    result = run_case_fixture(base, "case-prefix", prefixes,
                              sizeof(prefixes) / sizeof(prefixes[0]), 0,
                              source_path, sizeof(source_path),
                              container_path, sizeof(container_path),
                              &container_fd, &report);
    check(result == 0 && report.total_count == 0,
          "case pre-scan does not confuse prefixes with collisions");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const three_way[] = { "Foo", "foo", "FOO" };
    result = run_case_fixture(base, "case-three-way", three_way,
                              sizeof(three_way) / sizeof(three_way[0]), 0,
                              source_path, sizeof(source_path),
                              container_path, sizeof(container_path),
                              &container_fd, &report);
    int pairs_are_valid = report.example_count == 2;
    for (size_t index = 0; index < report.example_count; index++) {
        const PortablePrescanViolation *violation = &report.examples[index];
        pairs_are_valid = pairs_are_valid &&
                          violation->kind == PORTABLE_PRESCAN_CASE_COLLISION &&
                          violation->logical_path[0] != '\0' &&
                          violation->collides_with_logical_path[0] != '\0' &&
                          strcmp(violation->logical_path,
                                 violation->collides_with_logical_path) != 0 &&
                          case_name_member(violation->logical_path, three_way,
                                           sizeof(three_way) /
                                               sizeof(three_way[0])) &&
                          case_name_member(
                              violation->collides_with_logical_path,
                              three_way,
                              sizeof(three_way) / sizeof(three_way[0]));
    }
    check(result == 0 && report.total_count == 2 && pairs_are_valid,
          "three ASCII case variants count each losing name (total_count == 2)");
    check(fstatat(container_fd, "data/CASE/FOO", &st,
                  AT_SYMLINK_NOFOLLOW) == 0 &&
              fstatat(container_fd, "data/CASE/Foo%7E1", &st,
                      AT_SYMLINK_NOFOLLOW) == 0 &&
              fstatat(container_fd, "data/CASE/foo%7E2", &st,
                      AT_SYMLINK_NOFOLLOW) == 0,
          "three-way collision writes every planned physical payload");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const non_ascii[] = { "caf\xc3\xa9", "caf\xc3\x89" };
    result = run_case_fixture(base, "case-non-ascii", non_ascii,
                              sizeof(non_ascii) / sizeof(non_ascii[0]), 0,
                              source_path, sizeof(source_path),
                              container_path, sizeof(container_path),
                              &container_fd, &report);
    check(result == 0 && report.total_count == 0,
          "non-ASCII case folding remains deferred to destination probing");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static int collision_plan_entry_matches(
    const PortableCollisionPlanEntry *entry, const char *root_id,
    const char *logical, const char *physical, const char *suffix)
{
    const char *slash = physical == NULL ? NULL : strrchr(physical, '/');
    const char *leaf = slash == NULL ? physical : slash + 1;
    return entry != NULL && strcmp(entry->root_id, root_id) == 0 &&
           strcmp(entry->logical_path, logical) == 0 &&
           leaf != NULL && strcmp(entry->physical_leaf, leaf) == 0 &&
           strcmp(entry->collision_suffix, suffix) == 0;
}

static void test_collision_plan(const char *base)
{
    printf(BLUE "::" NC " deterministic case-collision assignment plan\n");
    static const char *const pair[] = { "Foo", "foo" };
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;
    int result = run_case_fixture(
        base, "case-plan", pair, sizeof(pair) / sizeof(pair[0]), 0,
        source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);
    const PortableCollisionPlanEntry *upper =
        portable_collision_plan_find(&report.collision_plan, "CASE", "Foo");
    const PortableCollisionPlanEntry *lower =
        portable_collision_plan_find(&report.collision_plan, "CASE", "foo");
    check(result == 0 && report.collision_plan.count == 2 &&
              collision_plan_entry_matches(upper, "CASE", "Foo", "Foo", "") &&
              collision_plan_entry_matches(lower, "CASE", "foo",
                                            "foo%7E1", "%7E1"),
          "ASCII collision plan keeps the sorted representative and suffixes the loser");

    PortablePrescanReport direct;
    portable_prescan_report_init(&direct);
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    check(portable_collision_plan_build(container_fd, &request, &direct) == 0 &&
              direct.total_count == 1 && direct.collision_plan.count == 2 &&
              portable_collision_plan_find(&direct.collision_plan, "CASE",
                                           "foo") != NULL,
          "direct plan builder exposes collisions without opening the capture gate");
    portable_prescan_report_free(&direct);
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const three_way[] = { "Foo", "foo", "FOO" };
    result = run_case_fixture(
        base, "case-plan-three-way", three_way,
        sizeof(three_way) / sizeof(three_way[0]), 0, source_path,
        sizeof(source_path), container_path, sizeof(container_path),
        &container_fd, &report);
    const PortableCollisionPlanEntry *all_upper =
        portable_collision_plan_find(&report.collision_plan, "CASE", "FOO");
    upper = portable_collision_plan_find(&report.collision_plan, "CASE", "Foo");
    lower = portable_collision_plan_find(&report.collision_plan, "CASE", "foo");
    check(result == 0 && report.collision_plan.count == 3 &&
              collision_plan_entry_matches(all_upper, "CASE", "FOO", "FOO",
                                            "") &&
              collision_plan_entry_matches(upper, "CASE", "Foo", "Foo%7E1",
                                            "%7E1") &&
              collision_plan_entry_matches(lower, "CASE", "foo", "foo%7E2",
                                            "%7E2"),
          "three-way collision plan assigns canonical suffixes in byte order");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const suffix_alias[] = { "Foo", "foo", "foo~1" };
    result = run_case_fixture(
        base, "case-plan-reservation", suffix_alias,
        sizeof(suffix_alias) / sizeof(suffix_alias[0]), 0, source_path,
        sizeof(source_path), container_path, sizeof(container_path),
        &container_fd, &report);
    lower = portable_collision_plan_find(&report.collision_plan, "CASE",
                                         "foo");
    const PortableCollisionPlanEntry *literal_suffix =
        portable_collision_plan_find(&report.collision_plan, "CASE", "foo~1");
    check(result == 0 && report.collision_plan.count == 2 &&
              collision_plan_entry_matches(lower, "CASE", "foo",
                                            "foo%7E2", "%7E2") &&
              literal_suffix == NULL,
          "a source name already occupying %7E1 forces the collision plan to use %7E2");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const unicode_suffix_alias[] = {
        "Caf\xc3\xa9", "caf\xc3\xa9", "CAF\xc3\x89~1"
    };
    result = run_case_fixture(
        base, "case-plan-unicode-reservation", unicode_suffix_alias,
        sizeof(unicode_suffix_alias) / sizeof(unicode_suffix_alias[0]), 0,
        source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);
    const PortableCollisionPlanEntry *unicode_lower =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     "caf\xc3\xa9");
    int unicode_first_suffix =
        collision_plan_entry_matches(unicode_lower, "CASE", "caf\xc3\xa9",
                                     "caf\xc3\xa9%7E1", "%7E1");
    int unicode_second_suffix =
        collision_plan_entry_matches(unicode_lower, "CASE", "caf\xc3\xa9",
                                     "caf\xc3\xa9%7E2", "%7E2");
    check(result == 0 && report.collision_plan.count == 2 &&
              (unicode_first_suffix || unicode_second_suffix),
          "non-ASCII suffix reservation follows destination-backed equivalence");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    join_path(source_a, sizeof(source_a), base, "case-plan-root-a");
    join_path(source_b, sizeof(source_b), base, "case-plan-root-b");
    join_path(container_path, sizeof(container_path), base,
              "case-plan-root-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);
    char path_a[PATH_MAX];
    char path_b[PATH_MAX];
    join_path(path_a, sizeof(path_a), source_a, "Foo");
    write_file(path_a, "a", 1);
    join_path(path_a, sizeof(path_a), source_a, "foo");
    write_file(path_a, "b", 1);
    join_path(path_b, sizeof(path_b), source_b, "Foo");
    write_file(path_b, "c", 1);
    join_path(path_b, sizeof(path_b), source_b, "foo");
    write_file(path_b, "d", 1);
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open multi-root collision container");
    PortableRootSpec roots[2] = {
        root_spec("ROOT_A", source_a, "A"),
        root_spec("ROOT_B", source_b, "B")
    };
    request.roots = roots;
    request.root_count = 2;
    portable_prescan_report_init(&report);
    result = portable_capture_fresh_at(container_fd, &request, &report);
    const PortableCollisionPlanEntry *root_a_upper =
        portable_collision_plan_find(&report.collision_plan, "ROOT_A", "Foo");
    const PortableCollisionPlanEntry *root_a_lower =
        portable_collision_plan_find(&report.collision_plan, "ROOT_A", "foo");
    const PortableCollisionPlanEntry *root_b_upper =
        portable_collision_plan_find(&report.collision_plan, "ROOT_B", "Foo");
    const PortableCollisionPlanEntry *root_b_lower =
        portable_collision_plan_find(&report.collision_plan, "ROOT_B", "foo");
    check(result == 0 && report.collision_plan.count == 4 &&
              collision_plan_entry_matches(root_a_upper, "ROOT_A", "Foo",
                                            "Foo", "") &&
              collision_plan_entry_matches(root_a_lower, "ROOT_A", "foo",
                                            "foo%7E1", "%7E1") &&
              collision_plan_entry_matches(root_b_upper, "ROOT_B", "Foo",
                                            "Foo", "") &&
              collision_plan_entry_matches(root_b_lower, "ROOT_B", "foo",
                                            "foo%7E1", "%7E1"),
          "separate payload roots receive independent collision reservations");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base, "case-plan-nested");
    join_path(container_path, sizeof(container_path), base,
              "case-plan-nested-container");
    make_directory(source_path);
    make_directory(container_path);
    char upper_dir[PATH_MAX];
    char lower_dir[PATH_MAX];
    join_path(upper_dir, sizeof(upper_dir), source_path, "Foo");
    join_path(lower_dir, sizeof(lower_dir), source_path, "foo");
    make_directory(upper_dir);
    make_directory(lower_dir);
    char middle_dir[PATH_MAX];
    join_path(middle_dir, sizeof(middle_dir), lower_dir, "middle");
    make_directory(middle_dir);
    char upper_middle_dir[PATH_MAX];
    join_path(upper_middle_dir, sizeof(upper_middle_dir), upper_dir,
              "middle");
    make_directory(upper_middle_dir);
    char upper_child[PATH_MAX];
    char lower_child[PATH_MAX];
    join_path(upper_child, sizeof(upper_child), middle_dir, "A");
    join_path(lower_child, sizeof(lower_child), middle_dir, "a");
    write_file(upper_child, "x", 1);
    write_file(lower_child, "y", 1);
    join_path(upper_child, sizeof(upper_child), upper_middle_dir, "A");
    join_path(lower_child, sizeof(lower_child), upper_middle_dir, "a");
    write_file(upper_child, "u", 1);
    write_file(lower_child, "v", 1);
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open nested collision container");
    portable_prescan_report_init(&report);
    root = root_spec("CASE", source_path, "CASE");
    request.roots = &root;
    request.root_count = 1;
    result = portable_capture_fresh_at(container_fd, &request, &report);
    const PortableCollisionPlanEntry *nested_upper =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     "foo/middle/A");
    const PortableCollisionPlanEntry *nested_lower =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     "foo/middle/a");
    const PortableCollisionPlanEntry *upper_nested_upper =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     "Foo/middle/A");
    const PortableCollisionPlanEntry *upper_nested_lower =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     "Foo/middle/a");
    check(result == 0 && report.collision_plan.count == 6 &&
              collision_plan_entry_matches(
                  portable_collision_plan_find(&report.collision_plan, "CASE",
                                               "foo"),
                  "CASE", "foo", "foo%7E1", "%7E1") &&
              collision_plan_entry_matches(nested_upper, "CASE",
                                            "foo/middle/A",
                                            "foo%7E1/middle/A", "") &&
              collision_plan_entry_matches(nested_lower, "CASE",
                                            "foo/middle/a",
                                            "foo%7E1/middle/a%7E1",
                                            "%7E1") &&
              collision_plan_entry_matches(upper_nested_upper, "CASE",
                                            "Foo/middle/A", "Foo/middle/A",
                                            "") &&
              collision_plan_entry_matches(upper_nested_lower, "CASE",
                                            "Foo/middle/a", "Foo/middle/a%7E1",
                                            "%7E1"),
          "nested plans include both colliding subtrees and inherit their ancestors' prefixes");
    struct stat nested_payload_stat;
    check(fstatat(container_fd, "data/CASE/foo%7E1/middle/a%7E1",
                  &nested_payload_stat, AT_SYMLINK_NOFOLLOW) == 0 &&
              S_ISREG(nested_payload_stat.st_mode),
          "capture places a child under its suffixed ancestor");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    static const char *const non_ascii[] = {
        "caf\xc3\xa9", "caf\xc3\x89"
    };
    result = run_case_fixture(
        base, "case-plan-non-ascii", non_ascii,
        sizeof(non_ascii) / sizeof(non_ascii[0]), 0, source_path,
        sizeof(source_path), container_path, sizeof(container_path),
        &container_fd, &report);
    if (report.collision_plan.count == 0 && result == 0) {
        skip_check("non-ASCII plan is deferred when the measured host is case-sensitive");
    } else {
        check(result == 0 && report.collision_plan.count == 2,
              "destination-probed non-ASCII collision produces a plan");
    }
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_mixed_prescan_violations(const char *base)
{
    printf(BLUE "::" NC " mixed pre-scan violation fate\n");
    static const char *const collision_names[] = { "Foo", "foo" };
    char oversized_name[NAME_MAX + 1U];
    size_t oversized_length = NAME_MAX / 3U + 1U;
    memset(oversized_name, ':', oversized_length);
    oversized_name[oversized_length] = '\0';
    const char *names[] = {
        collision_names[0], collision_names[1], oversized_name
    };

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;
    int result = run_case_plan_fixture(
        base, "case-mixed-violations", names, sizeof(names) / sizeof(names[0]),
        0, source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);

    int name_shortening = 0;
    int collision_violation = 0;
    for (size_t index = 0; index < report.example_count; index++) {
        const PortablePrescanViolation *violation = &report.examples[index];
        if (violation->kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
            violation->resolved &&
            strcmp(violation->root_id, "CASE") == 0 &&
            strcmp(violation->logical_path, oversized_name) == 0 &&
            violation->limit == NAME_MAX &&
            violation->actual == oversized_length * 3U)
            name_shortening = 1;
        if (collision_example_matches_names(
                violation, collision_names,
                sizeof(collision_names) / sizeof(collision_names[0])) &&
            violation->limit == 0 && violation->actual == 0)
            collision_violation = 1;
    }
    PortablePhysicalName shortened;
    int mapped = portable_physical_name_map(oversized_name, 0, &shortened) == 0;
    check(result == 0 && report.total_count == 2 &&
              report.collision_count == 1 && report.shortening_count == 1 &&
              report.unresolved_count == 0 && report.example_count == 2,
          "case collision and NAME_MAX shortening are both resolved");
    check(name_shortening && collision_violation,
          "mixed resolved diagnostics retain exact NAME_MAX and collision fields");
    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     oversized_name);
    check(mapped && shortened.shortened && planned != NULL &&
              strcmp(planned->physical_leaf, shortened.physical_leaf) == 0 &&
              empty_capture_container(container_fd),
          "mixed resolved shortening is represented in the canonical plan without mutation");
    portable_prescan_report_free(&report);

    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    portable_prescan_report_init(&report);
    int capture_result = portable_capture_fresh_at(container_fd, &request,
                                                   &report);
    char case_payload[PATH_MAX];
    char shortened_payload[PATH_MAX];
    join_path(case_payload, sizeof(case_payload), container_path, "data/CASE");
    join_path(shortened_payload, sizeof(shortened_payload), case_payload,
              shortened.physical_leaf);
    SidecarLog live_log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &live_log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(capture_result == 0 && report.shortening_count == 1 &&
              report.unresolved_count == 0 &&
              file_equals(shortened_payload, "x") && adopted &&
              live_entry_identity(&live_log, "CASE", oversized_name,
                                  shortened.physical_leaf, "") &&
              sidecar_log_claim_count(&live_log) == 0,
          "case collision and shortening execute together under canonical leaves");
    if (live_log.implementation != NULL &&
        sidecar_log_close(&live_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close mixed-shortening sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_collision_plan_suffix_length_violation(const char *base)
{
    printf(BLUE "::" NC
           " collision suffix pushes an otherwise-fitting name over NAME_MAX\n");

    char winner[NAME_MAX + 1U];
    char loser[NAME_MAX + 1U];
    size_t fitting_length = (size_t)NAME_MAX - 2U;
    memset(winner, 'a', fitting_length);
    winner[0] = 'A';
    winner[fitting_length] = '\0';
    memset(loser, 'a', fitting_length);
    loser[fitting_length] = '\0';

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "collision-suffix-overflow-source");
    join_path(container_path, sizeof(container_path), base,
              "collision-suffix-overflow-container");
    make_directory(source_path);
    make_directory(container_path);
    char path[PATH_MAX];
    join_path(path, sizeof(path), source_path, winner);
    write_file(path, "w", 1);
    join_path(path, sizeof(path), source_path, loser);
    write_file(path, "l", 1);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open collision-suffix-overflow container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_collision_plan_build(container_fd, &request,
                                                &report);

    const PortableCollisionPlanEntry *kept =
        portable_collision_plan_find(&report.collision_plan, "CASE", winner);
    const PortableCollisionPlanEntry *shortened =
        portable_collision_plan_find(&report.collision_plan, "CASE", loser);
    PortablePhysicalName expected_shortened;
    int mapped = portable_physical_name_map(loser, 1,
                                            &expected_shortened) == 0;
    check(result == 0 && report.total_count == 2 &&
              report.collision_count == 1 && report.shortening_count == 1 &&
              report.unresolved_count == 0 &&
              report.collision_plan.count == 2 &&
              collision_plan_entry_matches(kept, "CASE", winner, winner, ""),
          "the fitting sibling keeps the deterministic unsuffixed slot");
    check(mapped && expected_shortened.shortened && shortened != NULL &&
              strcmp(shortened->physical_leaf,
                     expected_shortened.physical_leaf) == 0 &&
              strcmp(shortened->collision_suffix, "%7E1") == 0 &&
              strlen(shortened->physical_leaf) <= NAME_MAX,
          "suffix growth is rebudgeted through the canonical mapper");

    const PortablePrescanViolation *case_collision = NULL;
    const PortablePrescanViolation *overflow = NULL;
    for (size_t index = 0; index < report.example_count; index++)
        if (report.examples[index].kind == PORTABLE_PRESCAN_CASE_COLLISION)
            case_collision = &report.examples[index];
        else if (report.examples[index].kind == PORTABLE_PRESCAN_NAME_TOO_LONG)
            overflow = &report.examples[index];
    check(report.example_count == 2 && case_collision != NULL &&
              collision_pair_matches(case_collision, winner, loser) &&
              overflow != NULL && overflow->resolved &&
              strcmp(overflow->root_id, "CASE") == 0 &&
              strcmp(overflow->logical_path, loser) == 0 &&
              overflow->limit == NAME_MAX &&
              overflow->actual == fitting_length + 4U,
          "case collision and shortening remain distinct resolved diagnostics");
    check(empty_capture_container(container_fd),
          "plan-build pre-scan reporting the overflow does not mutate the "
          "container");

    portable_prescan_report_free(&report);
    portable_prescan_report_init(&report);
    int capture_result = portable_capture_fresh_at(container_fd, &request,
                                                   &report);
    char payload_root[PATH_MAX];
    char winner_payload[PATH_MAX];
    char loser_payload[PATH_MAX];
    join_path(payload_root, sizeof(payload_root), container_path, "data/CASE");
    join_path(winner_payload, sizeof(winner_payload), payload_root, winner);
    join_path(loser_payload, sizeof(loser_payload), payload_root,
              expected_shortened.physical_leaf);
    SidecarLog live_log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &live_log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(capture_result == 0 && report.unresolved_count == 0 &&
              report.shortening_count == 1 && file_equals(winner_payload, "w") &&
              file_equals(loser_payload, "l") && adopted &&
              live_entry_identity(&live_log, "CASE", winner, winner, "") &&
              live_entry_identity(&live_log, "CASE", loser,
                                  expected_shortened.physical_leaf, "%7E1") &&
              sidecar_log_claim_count(&live_log) == 0,
          "suffix-induced shortening executes the canonical live assignment");
    if (live_log.implementation != NULL &&
        sidecar_log_close(&live_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close suffix-shortening sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void make_forced_shortening_name(char out[NAME_MAX + 1U],
                                        unsigned char tail)
{
    const size_t prefix_length = 100U;
    memset(out, ':', prefix_length);
    out[prefix_length] = (char)tail;
    out[prefix_length + 1U] = '\0';
}

static void test_shortened_candidate_collision_determinism(const char *base)
{
    printf(BLUE "::" NC
           " forced shortened-candidate collision stays deterministic\n");
    const uint64_t fingerprint = UINT64_C(0x0123456789ABCDEF);
    char first[NAME_MAX + 1U];
    char second[NAME_MAX + 1U];
    make_forced_shortening_name(first, 'a');
    make_forced_shortening_name(second, 'b');

    PortablePhysicalName expected_first;
    PortablePhysicalName expected_second;
    if (portable_physical_name_map_with_fingerprint_for_test(
            first, 0, fingerprint, &expected_first) != 0 ||
        portable_physical_name_map_with_fingerprint_for_test(
            second, 1, fingerprint, &expected_second) != 0)
        fixture_fatal("could not build forced shortening expectations");

    char first_leaf[NAME_MAX + 1U];
    char first_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    char second_leaf[NAME_MAX + 1U];
    char second_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    char source_roots[3][MANIFEST_ID_MAX] = {{0}};
    char source_paths[3][SIDECAR_MAX_PATH + 1U] = {{0}};
    size_t source_count = 0;
    static const int orders[2][2] = { { 0, 1 }, { 1, 0 } };
    const char *all_names[2] = { first, second };

    for (size_t run = 0; run < 2U; run++) {
        const char *names[2] = {
            all_names[orders[run][0]], all_names[orders[run][1]]
        };
        char source_path[PATH_MAX];
        char container_path[PATH_MAX];
        char label[64];
        int label_length = snprintf(label, sizeof(label),
                                    "forced-shortening-collision-%zu", run);
        if (label_length < 0 || (size_t)label_length >= sizeof(label))
            fixture_fatal("could not build forced collision label");
        int container_fd;
        PortablePrescanReport report;

        portable_prescan_test_force_name_fingerprint(fingerprint);
        int result = run_case_plan_fixture(
            base, label, names, 2U, 1, source_path, sizeof(source_path),
            container_path, sizeof(container_path), &container_fd, &report);
        portable_prescan_test_clear_name_fingerprint();

        const PortableCollisionPlanEntry *first_entry =
            portable_collision_plan_find(&report.collision_plan, "CASE", first);
        const PortableCollisionPlanEntry *second_entry =
            portable_collision_plan_find(&report.collision_plan, "CASE", second);
        check(result == 0 && report.total_count == 2 &&
                  report.collision_count == 0 &&
                  report.shortening_count == 2 &&
                  report.unresolved_count == 0 &&
                  report.collision_plan.count == 2 && first_entry != NULL &&
                  second_entry != NULL &&
                  strcmp(first_entry->physical_leaf,
                         expected_first.physical_leaf) == 0 &&
                  strcmp(first_entry->collision_suffix, "") == 0 &&
                  strcmp(second_entry->physical_leaf,
                         expected_second.physical_leaf) == 0 &&
                  strcmp(second_entry->collision_suffix, "%7E1") == 0 &&
                  strcmp(first_entry->physical_leaf,
                         second_entry->physical_leaf) != 0 &&
                  empty_capture_container(container_fd),
              "planner resolves an exact shortened collision without relying on the fingerprint");

        int source_members_match = report.current_source.sorted &&
                                   report.current_source.count == 3U;
        if (run == 0 && source_members_match) {
            source_count = report.current_source.count;
            for (size_t index = 0; index < source_count; index++) {
                if (snprintf(source_roots[index], sizeof(source_roots[index]),
                             "%s", report.current_source.entries[index].root_id) < 0 ||
                    snprintf(source_paths[index], sizeof(source_paths[index]),
                             "%s",
                             report.current_source.entries[index].logical_path) < 0)
                    fixture_fatal("could not snapshot current-source ordering");
            }
        } else if (run == 1 && source_members_match) {
            for (size_t index = 0; index < source_count; index++)
                if (strcmp(source_roots[index],
                           report.current_source.entries[index].root_id) != 0 ||
                    strcmp(source_paths[index],
                           report.current_source.entries[index].logical_path) != 0) {
                    source_members_match = 0;
                    break;
                }
        }
        if (run == 1)
            check(source_members_match && source_count == 3U,
                  "reversing source creation order leaves prepared membership byte-for-byte stable");

        if (run == 0 && first_entry != NULL && second_entry != NULL) {
            snprintf(first_leaf, sizeof(first_leaf), "%s",
                     first_entry->physical_leaf);
            snprintf(first_suffix, sizeof(first_suffix), "%s",
                     first_entry->collision_suffix);
            snprintf(second_leaf, sizeof(second_leaf), "%s",
                     second_entry->physical_leaf);
            snprintf(second_suffix, sizeof(second_suffix), "%s",
                     second_entry->collision_suffix);
        } else if (run == 1) {
            check(first_entry != NULL && second_entry != NULL &&
                      strcmp(first_entry->physical_leaf, first_leaf) == 0 &&
                      strcmp(first_entry->collision_suffix, first_suffix) == 0 &&
                      strcmp(second_entry->physical_leaf, second_leaf) == 0 &&
                      strcmp(second_entry->collision_suffix, second_suffix) == 0,
                  "reversing source creation order leaves canonical assignments unchanged");
        }

        portable_prescan_report_free(&report);
        close(container_fd);
        remove_tree(source_path);
        remove_tree(container_path);
    }
}

static void test_current_source_membership(const char *base)
{
    printf(BLUE "::" NC " prepared current-source membership\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "current-source-membership-source");
    join_path(container_path, sizeof(container_path), base,
              "current-source-membership-container");
    make_directory(source_path);
    make_directory(container_path);

    char plain_path[PATH_MAX];
    char excluded_path[PATH_MAX];
    char socket_path[PATH_MAX];
    join_path(plain_path, sizeof(plain_path), source_path, "plain");
    join_path(excluded_path, sizeof(excluded_path), source_path, "excluded");
    join_path(socket_path, sizeof(socket_path), source_path, "skipped.sock");
    write_file(plain_path, "plain", 5);
    write_file(excluded_path, "excluded", 8);

    char shortened_name[NAME_MAX + 1U];
    memset(shortened_name, ':', 100U);
    shortened_name[100] = '\0';
    char shortened_path[PATH_MAX];
    join_path(shortened_path, sizeof(shortened_path), source_path,
              shortened_name);
    write_file(shortened_path, "short", 5);

    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (socket_fd < 0 || strlen(socket_path) >= sizeof(address.sun_path))
        fixture_fatal("could not prepare current-source socket fixture");
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);
    int socket_bound = 1;
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (errno != EPERM && errno != EACCES)
            fixture_fatal("could not bind current-source socket fixture");
        skip_check("current-source socket membership fixture unavailable in this sandbox");
        close(socket_fd);
        socket_fd = -1;
        unlink(address.sun_path);
        socket_bound = 0;
    }

    char *excluded[] = { "excluded" };
    SelectionRoot selection = {0};
    selection.excluded.paths = excluded;
    selection.excluded.count = 1U;

    PortableRootSpec root = root_spec("MEMBERS", source_path, "MEMBERS");
    if (snprintf(selection.root.capture_path,
                 sizeof(selection.root.capture_path), "%s", source_path) < 0 ||
        snprintf(selection.root.manifest_root.id,
                 sizeof(selection.root.manifest_root.id), "%s", root.id) < 0 ||
        snprintf(selection.root.manifest_root.payload_path,
                 sizeof(selection.root.manifest_root.payload_path), "%s",
                 root.payload_path) < 0 ||
        snprintf(selection.root.manifest_root.source_path,
                 sizeof(selection.root.manifest_root.source_path), "%s",
                 root.source_path) < 0 ||
        snprintf(selection.root.manifest_root.restore_path,
                 sizeof(selection.root.manifest_root.restore_path), "%s",
                 root.restore_path) < 0)
        fixture_fatal("could not bind current-source selection fixture");
    selection.root.manifest_root.policy = root.policy;
    selection.root.manifest_root.has_restore_path = root.has_restore_path;
    root.selection = &selection;
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open current-source membership container");
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_collision_plan_build(container_fd, &request, &report);
    check(result == 0 && report.current_source.sorted &&
              portable_current_source_contains(&report.current_source,
                                               "MEMBERS", "") == 1 &&
              portable_current_source_contains(&report.current_source,
                                               "MEMBERS", "plain") == 1 &&
              portable_current_source_contains(&report.current_source,
                                               "MEMBERS", shortened_name) == 1,
          "selected address-bearing objects populate prepared membership");
    check(portable_collision_plan_find(&report.collision_plan,
                                       "MEMBERS", "plain") == NULL &&
              portable_collision_plan_find(&report.collision_plan,
                                            "MEMBERS",
                                            shortened_name) != NULL,
          "prepared membership is independent of sparse collision planning");
    check(portable_current_source_contains(&report.current_source,
                                           "MEMBERS", "excluded") == 0,
          "excluded children stay outside prepared membership");
    if (socket_bound)
        check(portable_current_source_contains(&report.current_source,
                                               "MEMBERS", "skipped.sock") == 0,
              "skipped-special children stay outside prepared membership");

    portable_prescan_report_free(&report);
    close(container_fd);
    if (socket_fd >= 0)
        close(socket_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_prepared_shortening_plan_authority(const char *base)
{
    printf(BLUE "::" NC " prepared shortening plan remains authoritative\n");
    const uint64_t fingerprint = UINT64_C(0x0123456789ABCDEF);
    char first[NAME_MAX + 1U];
    char second[NAME_MAX + 1U];
    make_forced_shortening_name(first, 'a');
    make_forced_shortening_name(second, 'b');

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "prepared-shortening-source");
    join_path(container_path, sizeof(container_path), base,
              "prepared-shortening-container");
    make_directory(source_path);
    make_directory(container_path);
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, first);
    write_file(source_file, "a", 1);
    join_path(source_file, sizeof(source_file), source_path, second);
    write_file(source_file, "b", 1);

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open prepared shortening container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    PortablePreparedCapture prepared = {0};
    portable_prescan_test_force_name_fingerprint(fingerprint);
    int prepare_result = portable_capture_prepare(container_fd, &request,
                                                  &prepared);
    portable_prescan_test_clear_name_fingerprint();

    char first_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U] = {0};
    char first_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U] = {0};
    char second_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U] = {0};
    char second_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U] = {0};
    const PortableCollisionPlanEntry *first_entry = prepare_result == 0
        ? portable_collision_plan_find(&prepared.report.collision_plan,
                                       "CASE", first)
        : NULL;
    const PortableCollisionPlanEntry *second_entry = prepare_result == 0
        ? portable_collision_plan_find(&prepared.report.collision_plan,
                                       "CASE", second)
        : NULL;
    if (first_entry != NULL && second_entry != NULL) {
        snprintf(first_leaf, sizeof(first_leaf), "%s",
                 first_entry->physical_leaf);
        snprintf(first_suffix, sizeof(first_suffix), "%s",
                 first_entry->collision_suffix);
        snprintf(second_leaf, sizeof(second_leaf), "%s",
                 second_entry->physical_leaf);
        snprintf(second_suffix, sizeof(second_suffix), "%s",
                 second_entry->collision_suffix);
    }

    PortablePhysicalName production_first;
    PortablePhysicalName production_second;
    int production_mapped =
        portable_physical_name_map(first, 0, &production_first) == 0 &&
        portable_physical_name_map(second, 1, &production_second) == 0;
    int override_matters = first_entry != NULL && second_entry != NULL &&
        production_mapped &&
        (strcmp(first_leaf, production_first.physical_leaf) != 0 ||
         strcmp(second_leaf, production_second.physical_leaf) != 0);
    check(prepare_result == 0 && prepared.ready &&
              prepared.report.shortening_count == 2 &&
              prepared.report.unresolved_count == 0 &&
              first_entry != NULL && second_entry != NULL && override_matters,
          "prepared plan freezes the injected physical assignments");

    size_t live_count = 0;
    int capture_result = prepare_result == 0
        ? portable_capture_fresh_prepared_at(container_fd, &request, &prepared,
                                             &live_count, NULL)
        : -1;
    char payload_root[PATH_MAX];
    char first_payload[PATH_MAX];
    char second_payload[PATH_MAX];
    join_path(payload_root, sizeof(payload_root), container_path, "data/CASE");
    join_path(first_payload, sizeof(first_payload), payload_root, first_leaf);
    join_path(second_payload, sizeof(second_payload), payload_root, second_leaf);
    SidecarLog live_log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &live_log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(capture_result == 0 && live_count == 3 &&
              file_equals(first_payload, "a") &&
              file_equals(second_payload, "b") && adopted &&
              live_entry_identity(&live_log, "CASE", first, first_leaf,
                                  first_suffix) &&
              live_entry_identity(&live_log, "CASE", second, second_leaf,
                                  second_suffix) &&
              sidecar_log_claim_count(&live_log) == 0,
          "capture consumes the frozen leaves after the fingerprint override is cleared");
    if (live_log.implementation != NULL &&
        sidecar_log_close(&live_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close prepared-shortening sidecar");
    portable_prepared_capture_free(&prepared);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_raw_component_unsigned_tiebreak(const char *base)
{
    printf(BLUE "::" NC " raw component unsigned-byte collision tiebreak\n");
    const uint64_t fingerprint = UINT64_C(0xA5A5A5A5A5A5A5A5);
    char lower_byte[NAME_MAX + 1U];
    char higher_byte[NAME_MAX + 1U];
    make_forced_shortening_name(lower_byte, 0x80U);
    make_forced_shortening_name(higher_byte, 0xFFU);
    const char *names[] = { higher_byte, lower_byte };
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;

    portable_prescan_test_force_name_fingerprint(fingerprint);
    int result = run_case_plan_fixture(
        base, "raw-unsigned-tiebreak", names,
        sizeof(names) / sizeof(names[0]), 1, source_path, sizeof(source_path),
        container_path, sizeof(container_path), &container_fd, &report);
    portable_prescan_test_clear_name_fingerprint();

    PortablePhysicalName expected_low;
    PortablePhysicalName expected_high;
    int mapped = portable_physical_name_map_with_fingerprint_for_test(
                     lower_byte, 0, fingerprint, &expected_low) == 0 &&
                 portable_physical_name_map_with_fingerprint_for_test(
                     higher_byte, 1, fingerprint, &expected_high) == 0;
    const PortableCollisionPlanEntry *low_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE", lower_byte);
    const PortableCollisionPlanEntry *high_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE", higher_byte);
    check(result == 0 && mapped && low_entry != NULL && high_entry != NULL &&
              strcmp(low_entry->physical_leaf, expected_low.physical_leaf) == 0 &&
              strcmp(low_entry->collision_suffix, "") == 0 &&
              strcmp(high_entry->physical_leaf,
                     expected_high.physical_leaf) == 0 &&
              strcmp(high_entry->collision_suffix, "%7E1") == 0,
          "tied candidates are ordered by unsigned raw logical-component bytes");

    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_shortened_suffix_reserves_natural_candidate(const char *base)
{
    printf(BLUE "::" NC
           " shortened suffix allocation preserves natural sibling names\n");
    const uint64_t fingerprint = UINT64_C(0x0123456789ABCDEF);
    char winner[NAME_MAX + 1U];
    char loser[NAME_MAX + 1U];
    make_forced_shortening_name(winner, 'a');
    make_forced_shortening_name(loser, 'b');

    char natural_alias[NAME_MAX + 1U];
    memset(natural_alias, ':', 77U);
    snprintf(natural_alias + 77U, sizeof(natural_alias) - 77U,
             "~H0123456789ABCDEF~1");
    const char *names[] = { loser, natural_alias, winner };

    PortablePhysicalName suffix_one;
    PortablePhysicalName suffix_two;
    PortablePhysicalName alias_name;
    if (portable_physical_name_map_with_fingerprint_for_test(
            loser, 1, fingerprint, &suffix_one) != 0 ||
        portable_physical_name_map_with_fingerprint_for_test(
            loser, 2, fingerprint, &suffix_two) != 0 ||
        portable_physical_name_map_with_fingerprint_for_test(
            natural_alias, 0, fingerprint, &alias_name) != 0)
        fixture_fatal("could not build shortened reservation expectations");
    if (strcmp(suffix_one.physical_leaf, alias_name.physical_leaf) != 0)
        fixture_fatal("shortened reservation fixture does not alias suffix one");

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;
    portable_prescan_test_force_name_fingerprint(fingerprint);
    int result = run_case_plan_fixture(
        base, "shortened-natural-reservation", names,
        sizeof(names) / sizeof(names[0]), 1, source_path, sizeof(source_path),
        container_path, sizeof(container_path), &container_fd, &report);
    portable_prescan_test_clear_name_fingerprint();

    const PortableCollisionPlanEntry *loser_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE", loser);
    const PortableCollisionPlanEntry *alias_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     natural_alias);
    check(result == 0 && loser_entry != NULL && alias_entry == NULL &&
              strcmp(loser_entry->collision_suffix, "%7E2") == 0 &&
              strcmp(loser_entry->physical_leaf,
                     suffix_two.physical_leaf) == 0 &&
              strcmp(loser_entry->physical_leaf,
                     alias_name.physical_leaf) != 0,
          "generated shortened suffix skips a natural unsuffixed sibling reservation");

    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_shortened_ancestor_keeps_descendant_identity(const char *base)
{
    printf(BLUE "::" NC
           " shortened ancestor leaves descendant canonical identity stable\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "shortened-ancestor-source");
    join_path(container_path, sizeof(container_path), base,
              "shortened-ancestor-container");
    make_directory(source_path);
    make_directory(container_path);

    char parent[NAME_MAX + 1U];
    memset(parent, ':', 100U);
    parent[100] = '\0';
    char parent_path[PATH_MAX];
    join_path(parent_path, sizeof(parent_path), source_path, parent);
    make_directory(parent_path);
    char child_path[PATH_MAX];
    join_path(child_path, sizeof(child_path), parent_path, "A");
    write_file(child_path, "a", 1);
    join_path(child_path, sizeof(child_path), parent_path, "a");
    write_file(child_path, "b", 1);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open shortened ancestor container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_collision_plan_build(container_fd, &request, &report);

    char upper_logical[SIDECAR_MAX_PATH + 1U];
    char lower_logical[SIDECAR_MAX_PATH + 1U];
    snprintf(upper_logical, sizeof(upper_logical), "%s/A", parent);
    snprintf(lower_logical, sizeof(lower_logical), "%s/a", parent);
    const PortableCollisionPlanEntry *parent_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE", parent);
    const PortableCollisionPlanEntry *upper_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     upper_logical);
    const PortableCollisionPlanEntry *lower_entry =
        portable_collision_plan_find(&report.collision_plan, "CASE",
                                     lower_logical);
    PortablePhysicalName mapped_parent;
    int parent_mapped = portable_physical_name_map(parent, 0,
                                                   &mapped_parent) == 0;
    check(result == 0 && parent_mapped && mapped_parent.shortened &&
              report.collision_count == 1 && report.shortening_count == 1 &&
              report.unresolved_count == 0 && parent_entry != NULL &&
              upper_entry != NULL && lower_entry != NULL &&
              strcmp(parent_entry->physical_leaf,
                     mapped_parent.physical_leaf) == 0 &&
              strcmp(upper_entry->physical_leaf, "A") == 0 &&
              strcmp(upper_entry->collision_suffix, "") == 0 &&
              strcmp(lower_entry->physical_leaf, "a%7E1") == 0 &&
              strcmp(lower_entry->collision_suffix, "%7E1") == 0,
          "descendant canonical leaves stay independent of the shortened ancestor spelling");

    portable_prescan_report_free(&report);
    portable_prescan_report_init(&report);
    int capture_result = portable_capture_fresh_at(container_fd, &request,
                                                   &report);
    int data_fd = openat(container_fd, "data/CASE",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int parent_fd = data_fd < 0
        ? -1
        : openat(data_fd, mapped_parent.physical_leaf,
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int children_present = parent_fd >= 0 &&
        fstatat(parent_fd, "A", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        fstatat(parent_fd, "a%7E1", &st, AT_SYMLINK_NOFOLLOW) == 0;
    SidecarLog live_log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &live_log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(capture_result == 0 && report.unresolved_count == 0 &&
              children_present && adopted &&
              live_entry_identity(&live_log, "CASE", parent,
                                  mapped_parent.physical_leaf, "") &&
              live_entry_identity(&live_log, "CASE", upper_logical, "A", "") &&
              live_entry_identity(&live_log, "CASE", lower_logical,
                                  "a%7E1", "%7E1") &&
              sidecar_log_claim_count(&live_log) == 0,
          "shortened ancestor capture addresses descendants relative to its canonical leaf");
    if (parent_fd >= 0)
        close(parent_fd);
    if (data_fd >= 0)
        close(data_fd);
    if (live_log.implementation != NULL &&
        sidecar_log_close(&live_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close shortened-ancestor sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_shortening_report_cap(const char *base)
{
    printf(BLUE "::" NC " bounded shortening report\n");
    enum {
        SHORTENING_COUNT = PORTABLE_PRESCAN_MAX_EXAMPLES + 8U
    };
    char storage[SHORTENING_COUNT][NAME_MAX + 1U];
    const char *names[SHORTENING_COUNT];
    for (size_t index = 0; index < SHORTENING_COUNT; index++) {
        memset(storage[index], ':', 90U);
        int length = snprintf(storage[index] + 90U,
                              sizeof(storage[index]) - 90U, "%03zu", index);
        if (length < 0 ||
            (size_t)length >= sizeof(storage[index]) - 90U)
            fixture_fatal("could not build shortening report fixture");
        names[index] = storage[index];
    }

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;
    int result = run_case_plan_fixture(
        base, "shortening-report-cap", names, SHORTENING_COUNT, 1,
        source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);
    int examples_are_shortenings =
        report.example_count == PORTABLE_PRESCAN_MAX_EXAMPLES;
    for (size_t index = 0;
         index < report.example_count && examples_are_shortenings; index++)
        examples_are_shortenings =
            report.examples[index].kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
            report.examples[index].resolved;
    check(result == 0 && report.total_count == SHORTENING_COUNT &&
              report.shortening_count == SHORTENING_COUNT &&
              report.unresolved_count == 0 &&
              report.example_count == PORTABLE_PRESCAN_MAX_EXAMPLES &&
              report.collision_plan.count == SHORTENING_COUNT &&
              examples_are_shortenings && empty_capture_container(container_fd),
          "shortening counts remain exact after diagnostic examples reach the cap");

    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_case_collision_report_cap(const char *base)
{
    printf(BLUE "::" NC " bounded case-collision report\n");
    enum {
        COLLISION_PAIR_COUNT = PORTABLE_PRESCAN_MAX_EXAMPLES + 8U,
        COLLISION_NAME_COUNT = COLLISION_PAIR_COUNT * 2U
    };
    char storage[COLLISION_NAME_COUNT][32];
    const char *names[COLLISION_NAME_COUNT];
    for (size_t index = 0; index < COLLISION_PAIR_COUNT; index++) {
        int upper_length = snprintf(storage[index * 2U],
                                    sizeof(storage[index * 2U]), "Pair%03zu",
                                    index);
        int lower_length = snprintf(storage[index * 2U + 1U],
                                    sizeof(storage[index * 2U + 1U]),
                                    "pair%03zu", index);
        if (upper_length < 0 || lower_length < 0 ||
            (size_t)upper_length >= sizeof(storage[index * 2U]) ||
            (size_t)lower_length >= sizeof(storage[index * 2U + 1U]))
            fixture_fatal("could not build bounded collision fixture");
        names[index * 2U] = storage[index * 2U];
        names[index * 2U + 1U] = storage[index * 2U + 1U];
    }

    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;
    int result = run_case_fixture(
        base, "case-report-cap", names, COLLISION_NAME_COUNT, 0,
        source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);
    int examples_are_real = report.example_count ==
                                PORTABLE_PRESCAN_MAX_EXAMPLES;
    for (size_t index = 0;
         index < report.example_count && examples_are_real; index++)
        examples_are_real = collision_example_matches_names(
            &report.examples[index], names, COLLISION_NAME_COUNT);
    check(result == 0 && report.total_count == COLLISION_PAIR_COUNT &&
              report.example_count == PORTABLE_PRESCAN_MAX_EXAMPLES &&
              report.collision_plan.count == COLLISION_NAME_COUNT &&
              examples_are_real,
          "collision diagnostics stay bounded while the plan keeps every candidate");
    check(fstatat(container_fd, "data/CASE/Pair000", &((struct stat){0}),
                  AT_SYMLINK_NOFOLLOW) == 0,
          "bounded collision plan is consumed without losing payloads");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_case_probe_group_growth(const char *base)
{
    printf(BLUE "::" NC " case-probe group beyond its initial capacity\n");
    /* Nine names sharing one skeleton land in a single case-probe group,
     * growing its parallel name/path arrays twice past the initial four. */
    static const char *const names[] = {
        "Note", "note", "NOTE", "nOte", "noTe",
        "notE", "NOte", "NOTe", "nOTE"
    };
    const size_t name_count = sizeof(names) / sizeof(names[0]);
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;

    int result = run_case_fixture(
        base, "case-probe-group-growth", names, name_count, 0,
        source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);
    check(result == 0 && report.collision_plan.count == name_count,
          "a case-probe group growing past four retains every plan entry");

    int logical_seen[sizeof(names) / sizeof(names[0])] = {0};
    int logical_paths_valid = report.collision_plan.count == name_count;
    int physical_leaves_distinct = report.collision_plan.count == name_count;
    for (size_t index = 0; index < report.collision_plan.count; index++) {
        const PortableCollisionPlanEntry *entry =
            &report.collision_plan.entries[index];
        size_t name_index = 0;
        while (name_index < name_count &&
               strcmp(entry->logical_path, names[name_index]) != 0)
            name_index++;
        if (strcmp(entry->root_id, "CASE") != 0 ||
            name_index == name_count || logical_seen[name_index])
            logical_paths_valid = 0;
        else
            logical_seen[name_index] = 1;

        if (entry->physical_leaf[0] == '\0')
            physical_leaves_distinct = 0;
        for (size_t previous = 0; previous < index; previous++)
            if (strcmp(entry->physical_leaf,
                       report.collision_plan.entries[previous].physical_leaf) ==
                0)
                physical_leaves_distinct = 0;
    }
    for (size_t index = 0; index < name_count; index++)
        if (!logical_seen[index])
            logical_paths_valid = 0;

    check(logical_paths_valid,
          "grown case-probe arrays preserve every logical path exactly once");
    check(physical_leaves_distinct,
          "grown case-probe arrays assign distinct physical leaves");

    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_case_collision_directory_scope(const char *base)
{
    printf(BLUE "::" NC " directory-local case collisions\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "case-directory-scope");
    join_path(container_path, sizeof(container_path), base,
              "case-directory-scope-container");
    make_directory(source_path);
    make_directory(container_path);

    char left_path[PATH_MAX];
    char right_path[PATH_MAX];
    join_path(left_path, sizeof(left_path), source_path, "left");
    join_path(right_path, sizeof(right_path), source_path, "right");
    make_directory(left_path);
    make_directory(right_path);
    char path[PATH_MAX];
    join_path(path, sizeof(path), left_path, "Foo");
    write_file(path, "left", 4);
    join_path(path, sizeof(path), right_path, "foo");
    write_file(path, "right", 5);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open directory-scope container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_capture_fresh_at(container_fd, &request, &report);
    check(result == 0 && report.total_count == 0,
          "same names in different directories do not collide");
    check(report.collision_plan.count == 0,
          "directory-local non-collisions produce no assignment entries");
    struct stat st;
    check(fstatat(container_fd, "data/CASE/left/Foo", &st,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode) &&
              fstatat(container_fd, "data/CASE/right/foo", &st,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode),
          "directory-local names are both captured under their own parents");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static int prepare_collision_plan_capture(const char *source_path,
                                          const char *container_path,
                                          const char *const *names,
                                          size_t name_count,
                                          int *container_fd,
                                          SidecarLog *log,
                                          PortableCaptureContext *context,
                                          PortableRootSpec *root,
                                          PortablePrescanReport *report)
{
    if (source_path == NULL || container_path == NULL || names == NULL ||
        container_fd == NULL || log == NULL || context == NULL ||
        root == NULL || report == NULL)
        return -1;
    make_directory(source_path);
    for (size_t index = 0; index < name_count; index++) {
        char path[PATH_MAX];
        join_path(path, sizeof(path), source_path, names[index]);
        write_file(path, "x", 1);
    }
    *container_fd = -1;
    *log = (SidecarLog){0};
    *context = (PortableCaptureContext){0};
    if (create_live_capture(container_path, container_fd, log, context) != 0)
        return -1;
    *root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    portable_prescan_report_init(report);
    if (portable_collision_plan_build(*container_fd, &request, report) != 0)
        return -1;
    context->case_sensitive = 0;
    context->collision_plan = &report->collision_plan;
    context->current_source = &report->current_source;
    return 0;
}

static int capture_root_with_current_prescan(int container_fd,
                                             PortableCaptureContext *context,
                                             const PortableRootSpec *root)
{
    if (container_fd < 0 || context == NULL || root == NULL)
        return -1;
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = root,
        .root_count = 1,
        .nsec_exact = context->nsec_exact,
        .case_sensitive = context->case_sensitive
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_collision_plan_build(container_fd, &request, &report);
    if (result == 0) {
        context->collision_plan = &report.collision_plan;
        context->current_source = &report.current_source;
        result = portable_capture_root(context, root);
        context->collision_plan = NULL;
        context->current_source = NULL;
    }
    portable_prescan_report_free(&report);
    return result;
}

static void test_capture_source_plan_mismatch(const char *base)
{
    printf(BLUE "::" NC " source-plan mismatch is fail-closed\n");
    static const char *const pair[] = { "Foo", "foo" };
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "collision-mismatch-remove");
    join_path(container_path, sizeof(container_path), base,
              "collision-mismatch-remove-container");
    int container_fd = -1;
    SidecarLog log = {0};
    PortableCaptureContext context = {0};
    PortableRootSpec root = {0};
    PortablePrescanReport report;
    int prepared = prepare_collision_plan_capture(
        source_path, container_path, pair, sizeof(pair) / sizeof(pair[0]),
        &container_fd, &log, &context, &root, &report);
    check(prepared == 0 && report.collision_plan.count == 2,
          "a plan is built before the source is changed");
    if (prepared == 0) {
        char removed[PATH_MAX];
        join_path(removed, sizeof(removed), source_path, "foo");
        if (unlink(removed) != 0)
            fixture_fatal("could not remove the planned collision member");
        check(portable_capture_root(&context, &root) != 0,
              "a planned collision member disappearing aborts capture");
    }
    portable_prescan_report_free(&report);
    close_live_capture(container_fd, &log, &context);
    remove_tree(source_path);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base,
              "ordinary-mismatch-add");
    join_path(container_path, sizeof(container_path), base,
              "ordinary-mismatch-add-container");
    static const char *const one_ordinary[] = { "plain" };
    prepared = prepare_collision_plan_capture(
        source_path, container_path, one_ordinary,
        sizeof(one_ordinary) / sizeof(one_ordinary[0]), &container_fd, &log,
        &context, &root, &report);
    check(prepared == 0 && report.collision_plan.count == 0 &&
              portable_current_source_contains(&report.current_source,
                                               "CASE", "plain") == 1,
          "an ordinary source is frozen in prepared membership without a plan entry");
    if (prepared == 0) {
        char added[PATH_MAX];
        join_path(added, sizeof(added), source_path, "late");
        write_file(added, "x", 1);
        int capture_result = portable_capture_root(&context, &root);
        struct stat st;
        int late_absent = fstatat(context.data_fd, "CASE/late", &st,
                                  AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
        check(capture_result != 0 && late_absent,
              "a new ordinary source child absent from prepared membership is rejected before that payload is created");
    }
    portable_prescan_report_free(&report);
    close_live_capture(container_fd, &log, &context);
    remove_tree(source_path);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base,
              "collision-mismatch-add");
    join_path(container_path, sizeof(container_path), base,
              "collision-mismatch-add-container");
    static const char *const singleton[] = { "foo" };
    prepared = prepare_collision_plan_capture(
        source_path, container_path, singleton,
        sizeof(singleton) / sizeof(singleton[0]), &container_fd, &log,
        &context, &root, &report);
    check(prepared == 0 && report.collision_plan.count == 0,
          "a collision-free source produces no assignment entries");
    if (prepared == 0) {
        char added[PATH_MAX];
        join_path(added, sizeof(added), source_path, "Foo");
        write_file(added, "x", 1);
        check(portable_capture_root(&context, &root) != 0,
              "a new case twin absent from the plan aborts capture");
    }
    portable_prescan_report_free(&report);
    close_live_capture(container_fd, &log, &context);
    remove_tree(source_path);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base,
              "shortening-mismatch-add");
    join_path(container_path, sizeof(container_path), base,
              "shortening-mismatch-add-container");
    static const char *const ordinary[] = { "plain" };
    prepared = prepare_collision_plan_capture(
        source_path, container_path, ordinary,
        sizeof(ordinary) / sizeof(ordinary[0]), &container_fd, &log,
        &context, &root, &report);
    check(prepared == 0 && report.collision_plan.count == 0,
          "an ordinary source has no shortening assignment before mutation");
    if (prepared == 0) {
        char added_name[NAME_MAX + 1U];
        memset(added_name, ':', 100U);
        added_name[100] = '\0';
        PortablePhysicalName mapped;
        int mapped_ok = portable_physical_name_map(added_name, 0, &mapped) == 0 &&
                        mapped.shortened;
        char added[PATH_MAX];
        join_path(added, sizeof(added), source_path, added_name);
        write_file(added, "x", 1);
        int capture_result = portable_capture_root(&context, &root);
        int root_fd = openat(context.data_fd, "CASE",
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int shortened_absent = 0;
        if (root_fd < 0) {
            shortened_absent = errno == ENOENT;
        } else {
            struct stat st;
            shortened_absent = fstatat(root_fd, mapped.physical_leaf, &st,
                                       AT_SYMLINK_NOFOLLOW) != 0 &&
                               errno == ENOENT;
            close(root_fd);
        }
        check(mapped_ok && capture_result != 0 && shortened_absent,
              "a newly-shortened source child absent from the frozen plan aborts without fallback");
    }
    portable_prescan_report_free(&report);
    close_live_capture(container_fd, &log, &context);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_prepared_missing_member_precedes_relocation(const char *base)
{
    printf(BLUE "::" NC
           " prepared-source drift is checked before relocation mutation\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "prepared-drift-relocation-source");
    join_path(container_path, sizeof(container_path), base,
              "prepared-drift-relocation-container");
    make_directory(source_path);
    make_directory(container_path);

    char upper[PATH_MAX];
    char lower[PATH_MAX];
    char plain[PATH_MAX];
    join_path(upper, sizeof(upper), source_path, "Foo");
    join_path(lower, sizeof(lower), source_path, "foo");
    join_path(plain, sizeof(plain), source_path, "plain");
    write_file(upper, "upper", 5);
    write_file(lower, "lower", 5);
    write_file(plain, "plain", 5);

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open prepared-drift container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "prepared-drift predecessor is captured before the plan changes");

    request.case_sensitive = 0;
    PortablePreparedCapture prepared;
    int prepared_ok = portable_capture_prepare(container_fd, &request,
                                                &prepared) == 0;
    check(prepared_ok &&
              portable_current_source_contains(&prepared.report.current_source,
                                               "CASE", "plain") == 1 &&
              portable_collision_plan_find(&prepared.report.collision_plan,
                                            "CASE", "foo") != NULL,
          "prepared resume freezes both ordinary membership and relocation state");
    if (prepared_ok && unlink(plain) != 0)
        fixture_fatal("could not remove prepared ordinary member");

    int resume_result = prepared_ok
        ? portable_capture_resume_prepared_at(container_fd, &request, &prepared,
                                              NULL, NULL)
        : -1;
    struct stat st;
    int old_lower = fstatat(container_fd, "data/CASE/foo", &st,
                            AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode);
    int relocated_absent = fstatat(container_fd, "data/CASE/foo%7E1", &st,
                                   AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    int old_plain = fstatat(container_fd, "data/CASE/plain", &st,
                            AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode);
    SidecarLog log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(resume_result != 0 && old_lower && relocated_absent && old_plain &&
              adopted && live_entry_identity(&log, "CASE", "foo", "foo", "") &&
              live_entry_identity(&log, "CASE", "plain", "plain", ""),
          "a missing prepared member aborts before relocation or stale cleanup mutates old state");
    if (adopted && sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close prepared-drift sidecar");
    if (prepared_ok)
        portable_prepared_capture_free(&prepared);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_collision_resume_unplanning(const char *base)
{
    printf(BLUE "::" NC " resume returns a survivor to an unplanned leaf\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "collision-unplanning-source");
    join_path(container_path, sizeof(container_path), base,
              "collision-unplanning-container");
    make_directory(source_path);
    make_directory(container_path);

    char upper[PATH_MAX];
    char lower[PATH_MAX];
    join_path(upper, sizeof(upper), source_path, "Foo");
    join_path(lower, sizeof(lower), source_path, "foo");
    write_file(upper, "upper", 5);
    write_file(lower, "lower", 5);

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open collision-unplanning container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(portable_capture_fresh_at(container_fd, &request, &report) == 0 &&
              portable_collision_plan_find(&report.collision_plan,
                                            "CASE", "foo") != NULL,
          "collision survivor begins with a planned suffixed assignment");
    portable_prescan_report_free(&report);
    if (unlink(upper) != 0)
        fixture_fatal("could not remove collision winner");

    portable_prescan_report_init(&report);
    int resumed = portable_capture_resume_at(container_fd, &request, &report);
    struct stat st;
    int ordinary_present = fstatat(container_fd, "data/CASE/foo", &st,
                                   AT_SYMLINK_NOFOLLOW) == 0 &&
                           S_ISREG(st.st_mode);
    int old_suffix_absent = fstatat(container_fd, "data/CASE/foo%7E1", &st,
                                    AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    SidecarLog log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(resumed == 0 &&
              portable_current_source_contains(&report.current_source,
                                               "CASE", "foo") == 1 &&
              portable_collision_plan_find(&report.collision_plan,
                                            "CASE", "foo") == NULL &&
              ordinary_present && old_suffix_absent && adopted &&
              live_entry_identity(&log, "CASE", "foo", "foo", ""),
          "current membership keeps a planned-to-unplanned survivor live and relocates it back to its natural leaf");
    if (adopted && sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close collision-unplanning sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_suffix_induced_shortening_relocation(const char *base)
{
    printf(BLUE "::" NC " collision suffix growth relocates through shortening\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "suffix-shortening-relocation-source");
    join_path(container_path, sizeof(container_path), base,
              "suffix-shortening-relocation-container");
    make_directory(source_path);
    make_directory(container_path);

    char upper[NAME_MAX + 1U];
    char lower[NAME_MAX + 1U];
    memset(upper, 'A', 252U);
    memset(lower, 'a', 252U);
    upper[252] = '\0';
    lower[252] = '\0';
    PortablePhysicalName unsuffixed;
    PortablePhysicalName suffixed;
    if (portable_physical_name_map(lower, 0, &unsuffixed) != 0 ||
        portable_physical_name_map(lower, 1, &suffixed) != 0 ||
        unsuffixed.shortened || !suffixed.shortened ||
        strcmp(suffixed.collision_suffix, "%7E1") != 0)
        fixture_fatal("could not prepare suffix-induced shortening mapping");

    char lower_source[PATH_MAX];
    char upper_source[PATH_MAX];
    join_path(lower_source, sizeof(lower_source), source_path, lower);
    join_path(upper_source, sizeof(upper_source), source_path, upper);
    write_file(lower_source, "lower", 5);

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open suffix-shortening relocation container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "long predecessor is captured unsuffixed before the collision exists");
    write_file(upper_source, "upper", 5);
    request.case_sensitive = 0;

    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int resumed = portable_capture_resume_at(container_fd, &request, &report);
    const PortableCollisionPlanEntry *lower_plan =
        portable_collision_plan_find(&report.collision_plan, "CASE", lower);
    int root_fd = openat(container_fd, "data/CASE",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int old_absent = root_fd >= 0 &&
        fstatat(root_fd, unsuffixed.physical_leaf, &st,
                AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    int new_present = root_fd >= 0 &&
        fstatat(root_fd, suffixed.physical_leaf, &st,
                AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode);
    if (root_fd >= 0)
        close(root_fd);
    SidecarLog log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(resumed == 0 && lower_plan != NULL &&
              strcmp(lower_plan->physical_leaf, suffixed.physical_leaf) == 0 &&
              strcmp(lower_plan->collision_suffix, "%7E1") == 0 &&
              old_absent && new_present && adopted &&
              live_entry_identity(&log, "CASE", lower,
                                  suffixed.physical_leaf, "%7E1"),
          "suffix growth remaps, removes, and records the relocated shortened leaf exactly");
    if (adopted && sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close suffix-shortening relocation sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_ancestor_relocation_keeps_descendant_leaf(const char *base)
{
    printf(BLUE "::" NC
           " ancestor relocation preserves descendant canonical leaf\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "ancestor-relocation-source");
    join_path(container_path, sizeof(container_path), base,
              "ancestor-relocation-container");
    make_directory(source_path);
    make_directory(container_path);

    char lower_dir[PATH_MAX];
    char lower_child[PATH_MAX];
    char upper_dir[PATH_MAX];
    join_path(lower_dir, sizeof(lower_dir), source_path, "dir");
    join_path(lower_child, sizeof(lower_child), lower_dir, "child");
    join_path(upper_dir, sizeof(upper_dir), source_path, "Dir");
    make_directory(lower_dir);
    write_file(lower_child, "child", 5);

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open ancestor relocation container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "nested predecessor is captured before its parent address changes");
    make_directory(upper_dir);
    request.case_sensitive = 0;
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int resumed = portable_capture_resume_at(container_fd, &request, &report);

    int root_fd = openat(container_fd, "data/CASE",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int old_parent_absent = root_fd >= 0 &&
        fstatat(root_fd, "dir", &st, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT;
    int moved_parent_fd = root_fd < 0 ? -1 : openat(
        root_fd, "dir%7E1", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int child_present = moved_parent_fd >= 0 &&
        fstatat(moved_parent_fd, "child", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode);
    if (moved_parent_fd >= 0)
        close(moved_parent_fd);
    if (root_fd >= 0)
        close(root_fd);
    SidecarLog log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(resumed == 0 && old_parent_absent && child_present && adopted &&
              live_entry_identity(&log, "CASE", "dir", "dir%7E1", "%7E1") &&
              live_entry_identity(&log, "CASE", "dir/child", "child", ""),
          "ancestor address change cleans the old subtree while the descendant keeps its own leaf identity");
    if (adopted && sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close ancestor relocation sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_shortened_stale_source(const char *base)
{
    printf(BLUE "::" NC " absent shortened source is stale, not unplanned\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "shortened-stale-source");
    join_path(container_path, sizeof(container_path), base,
              "shortened-stale-container");
    make_directory(source_path);
    make_directory(container_path);

    char logical[NAME_MAX + 1U];
    memset(logical, ':', 100U);
    logical[100] = '\0';
    PortablePhysicalName mapped;
    if (portable_physical_name_map(logical, 0, &mapped) != 0 ||
        !mapped.shortened)
        fixture_fatal("could not map shortened stale fixture");
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_path, logical);
    write_file(source_file, "stale", 5);

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open shortened-stale container");
    PortableRootSpec root = root_spec("SHORT", source_path, "SHORT");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "shortened stale fixture is captured");
    if (unlink(source_file) != 0)
        fixture_fatal("could not remove shortened stale source");

    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int resumed = portable_capture_resume_at(container_fd, &request, &report);
    int member_absent = portable_current_source_contains(
        &report.current_source, "SHORT", logical) == 0;
    int plan_absent = portable_collision_plan_find(&report.collision_plan,
                                                   "SHORT", logical) == NULL;
    int root_fd = openat(container_fd, "data/SHORT",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    int payload_absent = root_fd >= 0 &&
        fstatat(root_fd, mapped.physical_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT;
    if (root_fd >= 0)
        close(root_fd);
    SidecarLog log = {0};
    SidecarLiveView deleted = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &log) ==
                  SIDECAR_OPEN_RESUMABLE;
    int live_absent = adopted &&
        sidecar_log_find(&log, bytes("SHORT"), bytes(logical),
                         &(SidecarLiveView){0}) == 0;
    int tombstoned = adopted &&
        sidecar_log_find_deleted(&log, bytes("SHORT"), bytes(logical),
                                 &deleted) == 1;
    check(resumed == 0 && member_absent && plan_absent && payload_absent &&
              live_absent && tombstoned,
          "an absent old shortened key is reconciled as stale without manufacturing a current unplanned assignment");
    if (adopted && sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close shortened-stale sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_collision_resume(const char *base)
{
    printf(BLUE "::" NC " owned collision names on resume\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "collision-resume-source");
    join_path(container_path, sizeof(container_path), base,
              "collision-resume-container");
    make_directory(source_path);
    make_directory(container_path);
    char upper[PATH_MAX];
    char lower[PATH_MAX];
    join_path(upper, sizeof(upper), source_path, "Foo");
    join_path(lower, sizeof(lower), source_path, "foo");
    write_file(upper, "upper", 5);
    write_file(lower, "lower", 5);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open collision resume container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(portable_capture_fresh_at(container_fd, &request, &report) == 0,
          "an unsuffixed predecessor is captured on a case-sensitive verdict");
    portable_prescan_report_free(&report);

    request.case_sensitive = 0;
    portable_prescan_report_init(&report);
    check(portable_capture_resume_at(container_fd, &request, &report) == 0,
          "resume consumes the new collision plan for the owned container");
    struct stat st;
    int upper_payload = fstatat(container_fd, "data/CASE/Foo", &st,
                                AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode);
    int lower_payload = fstatat(container_fd, "data/CASE/foo%7E1", &st,
                                AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode);
    int stale_payload = fstatat(container_fd, "data/CASE/foo", &st,
                                 AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    check(upper_payload && lower_payload && stale_payload,
          "resume relocates the owned loser and removes its stale physical name");

    SidecarLog log = {0};
    SidecarLiveView upper_view = {0};
    SidecarLiveView lower_view = {0};
    int opened = sidecar_log_adopt_at(container_fd, &log) ==
                 SIDECAR_OPEN_RESUMABLE;
    int found = opened &&
        sidecar_log_find(&log, bytes("CASE"), bytes("Foo"), &upper_view) == 1 &&
        sidecar_log_find(&log, bytes("CASE"), bytes("foo"), &lower_view) == 1;
    check(found && sidecar_bytes_match_text(upper_view.entry->physical_path,
                                            "Foo") &&
              sidecar_bytes_match_text(upper_view.entry->collision_suffix,
                                       "") &&
              sidecar_bytes_match_text(lower_view.entry->physical_path,
                                       "foo%7E1") &&
              sidecar_bytes_match_text(lower_view.entry->collision_suffix,
                                       "%7E1"),
          "resume records the owned physical relocation and planned suffix");
    if (opened)
        sidecar_log_close(&log);
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_collision_resume_renumbering(const char *base)
{
    printf(BLUE "::" NC " resume renumbers an owned collision predecessor\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "collision-renumber-source");
    join_path(container_path, sizeof(container_path), base,
              "collision-renumber-container");
    make_directory(source_path);
    make_directory(container_path);

    static const char *const winners[] = {
        "Ab", "Az", "Ba", "Foo", "Bar", "Baz"
    };
    static const char *const losers[] = {
        "aB", "aZ", "ba", "foo", "bar", "baz"
    };
    const char *winner = NULL;
    const char *loser = NULL;
    char winner_path[PATH_MAX];
    char loser_path[PATH_MAX];
    DIR *directory;
    struct dirent *first;
    for (size_t index = 0; index < sizeof(winners) / sizeof(winners[0]);
         index++) {
        join_path(winner_path, sizeof(winner_path), source_path,
                  winners[index]);
        join_path(loser_path, sizeof(loser_path), source_path,
                  losers[index]);
        write_file(loser_path, "original", 8);
        write_file(winner_path, "new", 3);

        /* The winner must be visited first; otherwise ordinary replacement
         * can remove the occupied slot before the relocation pass is used. */
        directory = opendir(source_path);
        if (directory == NULL)
            fixture_fatal("could not inspect collision source order");
        first = readdir(directory);
        while (first != NULL &&
               (strcmp(first->d_name, ".") == 0 ||
                strcmp(first->d_name, "..") == 0))
            first = readdir(directory);
        int winner_first = first != NULL &&
                           strcmp(first->d_name, winners[index]) == 0;
        if (closedir(directory) != 0)
            fixture_fatal("could not close collision source directory");
        if (unlink(winner_path) != 0 || unlink(loser_path) != 0)
            fixture_fatal("could not reset collision source fixture");
        if (winner_first) {
            winner = winners[index];
            loser = losers[index];
            break;
        }
    }
    if (winner == NULL || loser == NULL)
        fixture_fatal("could not find a winner-first collision fixture");
    join_path(winner_path, sizeof(winner_path), source_path, winner);
    join_path(loser_path, sizeof(loser_path), source_path, loser);
    write_file(loser_path, "original", 8);
    write_file(winner_path, "new", 3);
    directory = opendir(source_path);
    if (directory == NULL)
        fixture_fatal("could not verify final collision source order");
    first = readdir(directory);
    while (first != NULL &&
           (strcmp(first->d_name, ".") == 0 ||
            strcmp(first->d_name, "..") == 0))
        first = readdir(directory);
    int final_winner_first = first != NULL &&
                             strcmp(first->d_name, winner) == 0;
    if (closedir(directory) != 0 || !final_winner_first)
        fixture_fatal("collision source order changed while preparing fixture");

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open collision renumber container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    if (mkdirat(container_fd, "data", 0700) != 0 ||
        mkdirat(container_fd, "data/CASE", 0700) != 0)
        fixture_fatal("could not create collision payload namespace");

    ManifestRoot manifest_root = {0};
    if (snprintf(manifest_root.id, sizeof(manifest_root.id), "%s", root.id) < 0 ||
        snprintf(manifest_root.payload_path,
                 sizeof(manifest_root.payload_path), "%s", root.payload_path) < 0 ||
        snprintf(manifest_root.source_path,
                 sizeof(manifest_root.source_path), "%s", root.source_path) < 0 ||
        snprintf(manifest_root.restore_path,
                 sizeof(manifest_root.restore_path), "%s", root.restore_path) < 0)
        fixture_fatal("could not prepare collision manifest root");
    manifest_root.policy = root.policy;
    manifest_root.has_restore_path = root.has_restore_path;
    Manifest manifest = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .has_source_identity = 1,
        .source_uid = getuid(),
        .root_count = 1,
        .roots = &manifest_root
    };
    if (snprintf(manifest.machine_id, sizeof(manifest.machine_id),
                 "%s", "0123456789abcdef") < 0 ||
        manifest_write_v1_at(container_fd, &manifest) != 0)
        fixture_fatal("could not write collision manifest");

    char target_path[PATH_MAX];
    join_path(target_path, sizeof(target_path), container_path,
              "data/CASE");
    char occupied_path[PATH_MAX];
    join_path(occupied_path, sizeof(occupied_path), target_path, winner);
    /* This is a host-side alias fixture: byte-exact lookup cannot make
     * fstatat() treat two spellings as one slot.  The planted slot and the
     * predecessor's physical field therefore share the spelling probed by
     * the new winner; the logical key remains the loser being renumbered. */
    write_file(occupied_path, "original", 8);

    struct stat root_stat;
    struct stat loser_stat;
    if (stat(source_path, &root_stat) != 0 ||
        stat(loser_path, &loser_stat) != 0)
        fixture_fatal("could not stat collision predecessor");
    PortableXattrs empty_xattrs = {0};
    SidecarEntry root_predecessor = {0};
    SidecarEntry predecessor = {0};
    if (entry_from_stat("CASE", "", "", "", &root_stat, 1,
                        &empty_xattrs, &root_predecessor, NULL, NULL,
                        NULL) != 0 ||
        entry_from_stat("CASE", loser, winner, "", &loser_stat, 1,
                        &empty_xattrs, &predecessor, NULL, NULL, NULL) != 0)
        fixture_fatal("could not prepare collision predecessor");
    SidecarClaim root_claim = {
        .root_id = root_predecessor.root_id,
        .logical_path = root_predecessor.logical_path,
        .physical_leaf = root_predecessor.physical_leaf,
        .kind = root_predecessor.kind
    };
    SidecarClaim predecessor_claim = {
        .root_id = predecessor.root_id,
        .logical_path = predecessor.logical_path,
        .physical_leaf = predecessor.physical_leaf,
        .kind = predecessor.kind
    };
    SidecarLog predecessor_log = {0};
    if (sidecar_log_create_at(container_fd, &predecessor_log) !=
            SIDECAR_OPEN_FRESH ||
        sidecar_log_append_claim(&predecessor_log, &root_claim) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&predecessor_log, &root_predecessor) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&predecessor_log) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&predecessor_log, &predecessor_claim) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&predecessor_log, &predecessor) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&predecessor_log) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_close(&predecessor_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not write collision predecessor");

    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int resume_result = portable_capture_resume_at(container_fd, &request,
                                                   &report);
    check(resume_result == 0,
          "resume succeeds when a new lexical winner renumbers the owner");
    struct stat st;
    char expected_loser[NAME_MAX + 1];
    int suffix_length = snprintf(expected_loser, sizeof(expected_loser),
                                 "%s%%7E1", loser);
    if (suffix_length < 0 || (size_t)suffix_length >= sizeof(expected_loser))
        fixture_fatal("could not prepare collision suffix");
    char winner_payload_name[PATH_MAX];
    char loser_payload_name[PATH_MAX];
    join_path(winner_payload_name, sizeof(winner_payload_name), target_path,
              winner);
    join_path(loser_payload_name, sizeof(loser_payload_name), target_path,
              expected_loser);
    int winner_payload = stat(winner_payload_name, &st) == 0 &&
                         S_ISREG(st.st_mode);
    int loser_payload = stat(loser_payload_name, &st) == 0 &&
                        S_ISREG(st.st_mode);
    check(winner_payload && loser_payload &&
              file_equals(occupied_path, "new") &&
              file_equals(loser_payload_name, "original"),
          "resume leaves the winner and the renumbered predecessor intact");

    SidecarLog log = {0};
    SidecarLiveView upper_view = {0};
    SidecarLiveView lower_view = {0};
    int opened = sidecar_log_adopt_at(container_fd, &log) ==
                 SIDECAR_OPEN_RESUMABLE;
    int found = opened &&
        sidecar_log_find(&log, bytes("CASE"), bytes(winner), &upper_view) == 1 &&
        sidecar_log_find(&log, bytes("CASE"), bytes(loser), &lower_view) == 1;
    check(found && sidecar_bytes_match_text(upper_view.entry->physical_path,
                                            winner) &&
              sidecar_bytes_match_text(lower_view.entry->physical_path,
                                       expected_loser),
          "resume records both the winner and the renumbered physical path");
    if (opened)
        sidecar_log_close(&log);
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_collision_foreign_resume(const char *base)
{
    printf(BLUE "::" NC " foreign collision payload is not overwritten on resume\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "collision-foreign-source");
    join_path(container_path, sizeof(container_path), base,
              "collision-foreign-container");
    make_directory(source_path);
    char upper[PATH_MAX];
    char lower[PATH_MAX];
    join_path(upper, sizeof(upper), source_path, "Foo");
    join_path(lower, sizeof(lower), source_path, "foo");
    write_file(upper, "upper", 5);
    write_file(lower, "lower", 5);

    make_directory(container_path);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open foreign collision container");
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid()
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(portable_capture_fresh_at(container_fd, &request, &report) == 0,
          "foreign-resume predecessor is captured");
    portable_prescan_report_free(&report);

    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int payload_fd = data_fd < 0 ? -1 : openat(
        data_fd, "CASE", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int foreign_fd = payload_fd < 0 ? -1 : openat(
        payload_fd, "foo%7E1", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
        0600);
    if (foreign_fd < 0 || write(foreign_fd, "foreign", 7) != 7 ||
        close(foreign_fd) != 0) {
        if (foreign_fd >= 0)
            close(foreign_fd);
        if (payload_fd >= 0)
            close(payload_fd);
        if (data_fd >= 0)
            close(data_fd);
        fixture_fatal("could not plant foreign collision payload");
    }
    close(payload_fd);
    close(data_fd);

    request.case_sensitive = 0;
    portable_prescan_report_init(&report);
    check(portable_capture_resume_at(container_fd, &request, &report) != 0,
          "resume refuses a foreign planned payload instead of overwriting it");
    char foreign_path[PATH_MAX];
    join_path(foreign_path, sizeof(foreign_path), container_path,
              "data/CASE/foo%7E1");
    check(file_equals(foreign_path, "foreign"),
          "foreign payload content remains untouched after refusal");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

#define CASE_PROBE_DIR ".migr-case-probe"

static void test_case_probe(const char *base)
{
    printf(BLUE "::" NC " measured non-ASCII case pre-scan\n");
    static const char *const non_ascii[] = {
        "caf\xc3\xa9", "caf\xc3\x89"
    };
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    int container_fd;
    PortablePrescanReport report;

    int result = run_case_fixture(base, "case-probe", non_ascii,
                                  sizeof(non_ascii) / sizeof(non_ascii[0]), 0,
                                  source_path, sizeof(source_path),
                                  container_path, sizeof(container_path),
                                  &container_fd, &report);
    check(result == 0 && report.total_count == 0,
          "case-sensitive host measures non-ASCII candidates without refusing");
    check(missing_container_entry(container_fd, CASE_PROBE_DIR),
          "successful candidate probing removes its scratch directory");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base, "case-probe-ascii");
    join_path(container_path, sizeof(container_path), base,
              "case-probe-ascii-container");
    make_directory(source_path);
    make_directory(container_path);
    char ascii_path[PATH_MAX];
    join_path(ascii_path, sizeof(ascii_path), source_path, "alpha.txt");
    write_file(ascii_path, "x", 1);
    join_path(ascii_path, sizeof(ascii_path), source_path, "beta.txt");
    write_file(ascii_path, "y", 1);
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open ASCII probe container");
    int marker_fd = openat(container_fd, CASE_PROBE_DIR,
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker_fd < 0)
        fixture_fatal("could not create ASCII probe marker");
    close(marker_fd);
    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    portable_prescan_report_init(&report);
    check(portable_capture_fresh_at(container_fd, &request, &report) == 0 &&
              report.total_count == 0,
          "all-ASCII tree succeeds without attempting a case probe");
    struct stat marker_stat;
    check(fstatat(container_fd, CASE_PROBE_DIR, &marker_stat,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(marker_stat.st_mode),
          "all-ASCII tree leaves the pre-existing probe marker untouched");
    portable_prescan_report_free(&report);
    if (unlinkat(container_fd, CASE_PROBE_DIR, 0) != 0)
        fixture_fatal("could not remove ASCII probe marker");
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);

    join_path(source_path, sizeof(source_path), base, "case-probe-failure");
    join_path(container_path, sizeof(container_path), base,
              "case-probe-failure-container");
    make_directory(source_path);
    make_directory(container_path);
    for (size_t index = 0; index < sizeof(non_ascii) / sizeof(non_ascii[0]);
         index++) {
        char path[PATH_MAX];
        join_path(path, sizeof(path), source_path, non_ascii[index]);
        write_file(path, "x", 1);
    }
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open probe failure container");
    marker_fd = openat(container_fd, CASE_PROBE_DIR,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker_fd < 0)
        fixture_fatal("could not create probe failure marker");
    close(marker_fd);
    portable_prescan_report_init(&report);
    PortableRootSpec failure_root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest failure_request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &failure_root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    result = portable_capture_fresh_at(container_fd, &failure_request,
                                       &report);
    check(result != 0 && report.total_count == 0 &&
              report.example_count == 0 &&
              empty_capture_container(container_fd),
          "an unavailable probe scratch directory fails before mutation");
    check(fstatat(container_fd, CASE_PROBE_DIR, &marker_stat,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(marker_stat.st_mode),
          "probe failure does not remove an unrelated pre-existing entry");
    portable_prescan_report_free(&report);
    if (unlinkat(container_fd, CASE_PROBE_DIR, 0) != 0)
        fixture_fatal("could not remove probe failure marker");
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_prescan_request_validates_malformed_input(const char *base)
{
    printf(BLUE "::" NC " prescan request input validation\n");
    char container_path[PATH_MAX];
    join_path(container_path, sizeof(container_path), base,
              "prescan-request-validation-container");
    make_directory(container_path);
    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open prescan-request-validation container");

    /* A count above one exercises the invalid non-NULL pointer produced by
     * indexing past a NULL roots base, rather than only the index-zero case. */
    PortableCaptureRequest null_roots = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = NULL,
        .root_count = 4
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(prescan_request(container_fd, &null_roots, &report) != 0,
          "prescan_request refuses a nonzero root count with no roots array");
    portable_prescan_report_free(&report);

    PortableRootSpec placeholder = {0};
    PortableCaptureRequest bad_scope = {
        .scope = (ManifestScope)99,
        .roots = &placeholder,
        .root_count = 0
    };
    portable_prescan_report_init(&report);
    check(prescan_request(container_fd, &bad_scope, &report) != 0,
          "prescan_request refuses a scope outside the manifest enum range");
    portable_prescan_report_free(&report);

    close(container_fd);
    remove_tree(container_path);
}

static void test_stale_case_probe_directory_recovers(const char *base)
{
    printf(BLUE "::" NC " stale case-probe scratch directory recovers after a crash\n");
    static const char *const non_ascii[] = {
        "caf\xc3\xa9", "caf\xc3\x89"
    };
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base, "stale-probe-source");
    join_path(container_path, sizeof(container_path), base,
              "stale-probe-container");
    make_directory(source_path);
    make_directory(container_path);
    for (size_t index = 0; index < sizeof(non_ascii) / sizeof(non_ascii[0]);
         index++) {
        char path[PATH_MAX];
        join_path(path, sizeof(path), source_path, non_ascii[index]);
        write_file(path, "x", 1);
    }
    int container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open stale-probe container");

    /* Simulate a capture killed after case_probe_prepare() created the
     * scratch directory but before case_probe_cleanup() removed it, with
     * some leftover in-flight content still inside. */
    if (mkdirat(container_fd, CASE_PROBE_DIR, 0700) != 0)
        fixture_fatal("could not simulate stale case-probe scratch directory");
    int stale_fd = openat(container_fd, CASE_PROBE_DIR,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (stale_fd < 0 || mkdirat(stale_fd, "leftover-pair-0", 0700) != 0)
        fixture_fatal("could not simulate stale case-probe leftover content");
    close(stale_fd);

    PortableRootSpec root = root_spec("CASE", source_path, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(portable_capture_fresh_at(container_fd, &request, &report) == 0,
          "capture recovers from a stale case-probe scratch directory instead of failing forever");
    check(missing_container_entry(container_fd, CASE_PROBE_DIR),
          "the stale scratch directory is cleared, not left behind");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_entry_helpers(const char *source)
{
    printf(BLUE "::" NC " portable entry helpers\n");
    char link_path[PATH_MAX];
    char regular_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source, "entry-helper-link");
    join_path(regular_path, sizeof(regular_path), source,
              "entry-helper-regular");
    if (symlink("../target", link_path) != 0)
        fixture_fatal("could not create symlink helper fixture");
    write_file(regular_path, "hardlink-helper", 15);

    struct stat link_stat;
    if (lstat(link_path, &link_stat) != 0)
        fixture_fatal("could not inspect symlink helper fixture");
    struct stat regular_stat;
    if (stat(regular_path, &regular_stat) != 0)
        fixture_fatal("could not inspect regular helper fixture");
    PortableXattrs empty_xattrs = {0};
    SidecarBytes target = bytes("../target");
    SidecarEntry entry;
    check(entry_from_stat("LINK", "item", "item", "", &link_stat, 1,
                          &empty_xattrs, &entry, &target, NULL, NULL) == 0,
          "entry_from_stat accepts a symlink target");
    check(entry.kind == SIDECAR_KIND_SYMLINK && entry.size == 0 &&
              entry.xattr_count == 0 &&
              entry.symlink_target.length == target.length &&
              memcmp(entry.symlink_target.data, target.data, target.length) == 0,
          "symlink entry preserves kind, zero size, and target bytes");

    SidecarEntry symlink_entry = entry;

    check(entry_from_stat("LINK", "item", "item", "", &link_stat, 1,
                          &empty_xattrs, &entry, NULL, NULL, NULL) != 0,
          "symlink entry without a target is rejected");
    SidecarBytes empty_target = {0};
    check(entry_from_stat("LINK", "item", "item", "", &link_stat, 1,
                          &empty_xattrs, &entry, &empty_target, NULL, NULL) != 0,
          "symlink entry with an empty target is rejected");

    SidecarBytes hardlink_root = bytes("HL");
    SidecarBytes hardlink_logical = bytes("representative");
    check(entry_from_stat("HL", "alias", "alias", "", &regular_stat, 1,
                          &empty_xattrs, &entry, NULL, &hardlink_root,
                          &hardlink_logical) == 0 &&
              entry.kind == SIDECAR_KIND_HARDLINK && entry.size == 0 &&
              entry.xattr_count == 0 &&
              sidecar_bytes_match_text(entry.hardlink_root_id, "HL") &&
              sidecar_bytes_match_text(entry.hardlink_logical_path,
                                       "representative"),
          "entry_from_stat builds a zero-byte HARDLINK record");
    PortableXattrs one_xattr = {0};
    SidecarXattr xattr_item = {0};
    one_xattr.items = &xattr_item;
    one_xattr.count = 1;
    check(entry_from_stat("HL", "alias", "alias", "", &regular_stat, 1,
                          &one_xattr, &entry, NULL, &hardlink_root,
                          &hardlink_logical) != 0,
          "a HARDLINK record with non-empty xattrs is rejected");
    check(entry_from_stat("HL", "alias", "alias", "", &regular_stat, 1,
                          &empty_xattrs, &entry, NULL, &hardlink_root,
                          NULL) != 0,
          "a HARDLINK record with one missing reference is rejected");
    unsigned char nul_reference[] = {'H', 'L', '\0', 'x'};
    SidecarBytes nul_root = {nul_reference, sizeof(nul_reference)};
    check(entry_from_stat("HL", "alias", "alias", "", &regular_stat, 1,
                          &empty_xattrs, &entry, NULL, &nul_root,
                          &hardlink_logical) != 0,
          "a HARDLINK reference containing NUL is rejected");

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
    entry.physical_leaf = bytes("different-physical");
    check(entries_equal(&entry, &view, &empty_xattrs) == 0,
          "entries_equal rejects different physical leaves");
    entry.physical_leaf = previous.physical_leaf;
    entry.symlink_target = bytes("other-target");
    check(entries_equal(&entry, &view, &empty_xattrs) == 0,
          "entries_equal rejects different symlink targets");

    SidecarXattr previous_one[] = {
        { .name = bytes("user.a"), .value = bytes("one") }
    };
    SidecarXattr current_one[] = {
        { .name = bytes("user.a"), .value = bytes("one") }
    };
    PortableXattrs current_one_xattrs = {
        .items = current_one,
        .count = 1,
        .capacity = 1
    };
    SidecarLiveView xattr_view = {
        .entry = &previous,
        .xattrs = previous_one,
        .xattr_count = 1,
        .generation = 0
    };
    entry = previous;
    check(entries_equal(&entry, &xattr_view, &current_one_xattrs) != 0,
          "entries_equal accepts an identical xattr");

    SidecarXattr changed_value[] = {
        { .name = bytes("user.a"), .value = bytes("two") }
    };
    PortableXattrs changed_value_xattrs = {
        .items = changed_value,
        .count = 1,
        .capacity = 1
    };
    check(entries_equal(&entry, &xattr_view, &changed_value_xattrs) == 0,
          "entries_equal rejects a changed xattr value");

    SidecarXattr changed_name[] = {
        { .name = bytes("user.b"), .value = bytes("one") }
    };
    PortableXattrs changed_name_xattrs = {
        .items = changed_name,
        .count = 1,
        .capacity = 1
    };
    check(entries_equal(&entry, &xattr_view, &changed_name_xattrs) == 0,
          "entries_equal rejects a changed xattr name");

    SidecarXattr current_pair[] = {
        { .name = bytes("user.a"), .value = bytes("one") },
        { .name = bytes("user.b"), .value = bytes("two") }
    };
    PortableXattrs current_pair_xattrs = {
        .items = current_pair,
        .count = 2,
        .capacity = 2
    };
    check(entries_equal(&entry, &xattr_view, &current_pair_xattrs) == 0,
          "entries_equal rejects a different xattr count");

    SidecarXattr previous_pair[] = {
        { .name = bytes("user.a"), .value = bytes("one") },
        { .name = bytes("user.b"), .value = bytes("two") }
    };
    SidecarXattr swapped_pair[] = {
        { .name = bytes("user.b"), .value = bytes("two") },
        { .name = bytes("user.a"), .value = bytes("one") }
    };
    PortableXattrs swapped_pair_xattrs = {
        .items = swapped_pair,
        .count = 2,
        .capacity = 2
    };
    xattr_view.xattrs = previous_pair;
    xattr_view.xattr_count = 2;
    check(entries_equal(&entry, &xattr_view, &swapped_pair_xattrs) != 0,
          "entries_equal accepts the same xattrs in a different order");

    if (unlink(link_path) != 0)
        fixture_fatal("could not remove symlink helper fixture");
    if (unlink(regular_path) != 0)
        fixture_fatal("could not remove regular helper fixture");
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
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(portable_capture_fresh_at(container_fd, &request, &report) == 0 &&
              report.total_count == 0,
          "pre-scan accepts escaped and valid UTF-8 names");
    portable_prescan_report_free(&report);

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
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
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
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int name_result = portable_collision_plan_build(container_fd, &request,
                                                    &report);
    PortablePhysicalName shortened;
    int mapped = portable_physical_name_map(oversized_name, 0, &shortened) == 0;
    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(&report.collision_plan, "NAMES",
                                     oversized_name);
    check(name_result == 0 && report.total_count == 1 &&
              report.shortening_count == 1 && report.unresolved_count == 0 &&
              report.example_count == 1 && report.examples[0].resolved &&
              report.examples[0].kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
              strcmp(report.examples[0].root_id, "NAMES") == 0 &&
              strcmp(report.examples[0].logical_path, oversized_name) == 0 &&
              report.examples[0].limit == NAME_MAX &&
              report.examples[0].actual == oversized_length * 3U,
          "encoded NAME_MAX expansion is reported as a resolved shortening");
    struct stat st;
    check(mapped && shortened.shortened && planned != NULL &&
              strcmp(planned->physical_leaf, shortened.physical_leaf) == 0 &&
              strcmp(planned->collision_suffix, "") == 0 &&
              empty_capture_container(container_fd),
          "shortened NAME_MAX entry is planned under the canonical leaf without mutation");
    portable_prescan_report_free(&report);

    portable_prescan_report_init(&report);
    int capture_result = portable_capture_fresh_at(container_fd, &request,
                                                   &report);
    char payload_root[PATH_MAX];
    char shortened_payload[PATH_MAX];
    join_path(payload_root, sizeof(payload_root), container_path, "data/NAMES");
    join_path(shortened_payload, sizeof(shortened_payload), payload_root,
              shortened.physical_leaf);
    SidecarLog live_log = {0};
    int adopted = sidecar_log_adopt_at(container_fd, &live_log) ==
                  SIDECAR_OPEN_RESUMABLE;
    check(capture_result == 0 && report.shortening_count == 1 &&
              report.unresolved_count == 0 &&
              file_equals(shortened_payload, "x") && adopted &&
              live_entry_identity(&live_log, "NAMES", oversized_name,
                                  shortened.physical_leaf, "") &&
              sidecar_log_claim_count(&live_log) == 0,
          "live NAME_MAX shortening captures under the canonical physical leaf");
    if (live_log.implementation != NULL &&
        sidecar_log_close(&live_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close NAME_MAX sidecar");
    portable_prescan_report_free(&report);
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
    portable_prescan_report_init(&report);
    int path_plan_result = portable_collision_plan_build(container_fd, &request,
                                                         &report);
    int path_limit_reported = 0;
    for (size_t index = 0; index < report.example_count; index++)
        if (report.examples[index].kind == PORTABLE_PRESCAN_PATH_TOO_LONG)
            path_limit_reported = 1;
    check(path_plan_result == 0 && report.unresolved_count == 0 &&
              report.shortening_count == 0 && !path_limit_reported &&
              empty_capture_container(container_fd),
          "cumulative physical depth is no longer a prescan PATH_MAX refusal");
    portable_prescan_report_free(&report);

    portable_prescan_report_init(&report);
    int deep_capture = portable_capture_fresh_at(container_fd, &request, &report);
    path_limit_reported = 0;
    for (size_t index = 0; index < report.example_count; index++)
        if (report.examples[index].kind == PORTABLE_PRESCAN_PATH_TOO_LONG)
            path_limit_reported = 1;

    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    int root_fd = -1;
    int child_present = 0;
    if (data_fd >= 0 &&
        portable_open_relative_parent(data_fd, long_payload, &root_parent,
                                      root_leaf, sizeof(root_leaf)) == 0) {
        root_fd = openat(root_parent, root_leaf,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        child_present = root_fd >= 0 &&
                        fstatat(root_fd, "child", &st,
                                AT_SYMLINK_NOFOLLOW) == 0 &&
                        S_ISREG(st.st_mode);
    }
    if (root_fd >= 0)
        close(root_fd);
    if (root_parent >= 0)
        close(root_parent);
    if (data_fd >= 0)
        close(data_fd);

    live_log = (SidecarLog){0};
    adopted = sidecar_log_adopt_at(container_fd, &live_log) ==
              SIDECAR_OPEN_RESUMABLE;
    check(deep_capture == 0 && report.unresolved_count == 0 &&
              !path_limit_reported && child_present && adopted &&
              live_entry_identity(&live_log, "PATH", "child", "child", "") &&
              sidecar_log_claim_count(&live_log) == 0,
          "fd-relative capture succeeds beyond cumulative physical PATH_MAX");
    if (live_log.implementation != NULL &&
        sidecar_log_close(&live_log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not close deep-path sidecar");
    portable_prescan_report_free(&report);
    close(container_fd);
    free(long_payload);
    remove_tree(source_path);
    remove_tree_fd(container_path);
}

static int root_payload_violation_matches(
    const PortablePrescanViolation *violation, const char *root_id,
    const char *payload_path, const char *collides_with)
{
    return violation != NULL &&
           violation->kind == PORTABLE_PRESCAN_CASE_COLLISION &&
           !violation->resolved &&
           strcmp(violation->root_id, root_id) == 0 &&
           strcmp(violation->logical_path, payload_path) == 0 &&
           strcmp(violation->collides_with_logical_path,
                  collides_with) == 0;
}

static void test_root_payload_namespace(const char *base)
{
    printf(BLUE "::" NC " root payload namespace case-equivalence\n");
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char container_path[PATH_MAX];
    char file_path[PATH_MAX];
    join_path(source_a, sizeof(source_a), base, "root-namespace-a");
    join_path(source_b, sizeof(source_b), base, "root-namespace-b");
    join_path(container_path, sizeof(container_path), base,
              "root-namespace-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);
    join_path(file_path, sizeof(file_path), source_a, "a");
    write_file(file_path, "a", 1);
    join_path(file_path, sizeof(file_path), source_b, "b");
    write_file(file_path, "b", 1);

    PortableRootSpec roots[2] = {
        root_spec("ROOT_A", source_a, "Foo"),
        root_spec("ROOT_B", source_b, "foo")
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = roots,
        .root_count = 2,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open root namespace container");
    int result = portable_capture_fresh_at(container_fd, &request, &report);
    int root_violation = report.example_count == 1 &&
        root_payload_violation_matches(&report.examples[0], "ROOT_B", "foo",
                                       "Foo");
    check(result != 0 && report.total_count == 1 &&
              report.collision_count == 0 && report.unresolved_count == 1 &&
              root_violation,
          "ASCII case-equivalent root payload paths are refused before mutation");
    check(empty_capture_container(container_fd),
          "root namespace refusal leaves the container untouched");
    portable_prescan_report_free(&report);
    close(container_fd);

    join_path(container_path, sizeof(container_path), base,
              "root-namespace-plan-container");
    make_directory(container_path);
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open root namespace plan container");
    portable_prescan_report_init(&report);
    result = portable_collision_plan_build(container_fd, &request, &report);
    root_violation = report.example_count == 1 &&
        root_payload_violation_matches(&report.examples[0], "ROOT_B", "foo",
                                       "Foo");
    check(result == 0 && report.total_count == 1 &&
              report.collision_count == 0 && report.unresolved_count == 1 &&
              root_violation && empty_capture_container(container_fd),
          "plan-build pre-scan reports the root collision without mutation");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(container_path);
    remove_tree(source_a);
    remove_tree(source_b);

    join_path(container_path, sizeof(container_path), base,
              "root-namespace-overlap-container");
    make_directory(container_path);
    roots[0] = root_spec("ROOT_A", source_a, "a");
    roots[1] = root_spec("ROOT_B", source_b, "a/b");
    make_directory(source_a);
    make_directory(source_b);
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open root overlap container");
    portable_prescan_report_init(&report);
    result = portable_capture_fresh_at(container_fd, &request, &report);
    check(result != 0 && report.total_count == 1 &&
              report.unresolved_count == 1 &&
              root_payload_violation_matches(&report.examples[0], "ROOT_B",
                                             "a/b", "a"),
          "byte-wise root payload overlap remains refused");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);

    join_path(container_path, sizeof(container_path), base,
              "root-namespace-distinct-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);
    roots[0] = root_spec("ROOT_A", source_a, "Foo");
    roots[1] = root_spec("ROOT_B", source_b, "Bar");
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open distinct root namespace container");
    portable_prescan_report_init(&report);
    result = portable_capture_fresh_at(container_fd, &request, &report);
    struct stat st;
    check(result == 0 && report.total_count == 0 &&
              report.collision_plan.count == 0 &&
              fstatat(container_fd, "data/Foo", &st,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode) &&
              fstatat(container_fd, "data/Bar", &st,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode),
          "distinct root payload paths remain usable without a root suffix");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);

    static const char unicode_cafe[] = "Caf\xc3\xa9";
    static const char unicode_cafe_upper[] = "CAF\xc3\x89";
    join_path(container_path, sizeof(container_path), base,
              "root-namespace-unicode-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);
    roots[0] = root_spec("ROOT_A", source_a, unicode_cafe);
    roots[1] = root_spec("ROOT_B", source_b, unicode_cafe_upper);
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open Unicode root namespace container");
    portable_prescan_report_init(&report);
    result = portable_capture_fresh_at(container_fd, &request, &report);
    int unicode_allowed = result == 0 && report.total_count == 0 &&
        report.collision_plan.count == 0 &&
        fstatat(container_fd, "data/Caf\xc3\xa9", &st,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        fstatat(container_fd, "data/CAF\xc3\x89", &st,
                AT_SYMLINK_NOFOLLOW) == 0;
    int unicode_refused = result != 0 && report.total_count == 1 &&
        report.collision_count == 0 && report.unresolved_count == 1 &&
        report.example_count == 1 &&
        root_payload_violation_matches(&report.examples[0], "ROOT_B",
                                       "CAF\xc3\x89", "Caf\xc3\xa9") &&
        empty_capture_container(container_fd);
    check(unicode_allowed || unicode_refused,
          "non-ASCII root paths use destination probing or fail closed");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);

    join_path(container_path, sizeof(container_path), base,
              "root-namespace-id-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);
    roots[0] = root_spec("SAME", source_a, "Foo");
    roots[1] = root_spec("SAME", source_b, "Bar");
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open duplicate root id container");
    portable_prescan_report_init(&report);
    result = portable_capture_fresh_at(container_fd, &request, &report);
    check(result != 0 && empty_capture_container(container_fd),
          "duplicate root ids remain refused without introducing a suffix");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);
}

/* root_probe_make_path() dup_cloexec()'s the root fd, then advances it one
 * path component at a time, closing the previous "current" fd once the next
 * one is open. If that close() ever fails, the fd slot is released anyway
 * (Linux close() semantics) -- so the post-loop cleanup must not attempt a
 * second close() on the same, already-released descriptor number. Reaching
 * this code at all requires two non-ASCII root payload paths that skeleton-
 * fold to the same name (destination-probed, not resolved by ASCII folding
 * alone) with more than one path component, so the probe actually advances
 * past its first directory. */
static void test_root_probe_close_failure_does_not_double_close(
    const char *base)
{
    printf(BLUE "::" NC
           " root payload probe close failure does not double-close\n");

    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_a, sizeof(source_a), base, "root-probe-close-a");
    join_path(source_b, sizeof(source_b), base, "root-probe-close-b");
    join_path(container_path, sizeof(container_path), base,
              "root-probe-close-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);
    char file_path[PATH_MAX];
    join_path(file_path, sizeof(file_path), source_a, "a");
    write_file(file_path, "a", 1);
    join_path(file_path, sizeof(file_path), source_b, "b");
    write_file(file_path, "b", 1);

    static const char unicode_cafe[] = "dir/Caf\xc3\xa9";
    static const char unicode_cafe_upper[] = "dir/CAF\xc3\x89";
    PortableRootSpec roots[2] = {
        root_spec("ROOT_A", source_a, unicode_cafe),
        root_spec("ROOT_B", source_b, unicode_cafe_upper)
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = roots,
        .root_count = 2,
        .nsec_exact = 1
    };

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open root-probe-close container");

    portable_prescan_test_fail_root_probe_close_after(0);
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_collision_plan_build(container_fd, &request,
                                                &report);

    check(result == -1,
          "an injected close() failure inside the root-payload destination "
          "probe is reported as a failure, not silently swallowed");
    check(portable_prescan_test_root_probe_post_loop_close_count() == 0,
          "the post-loop cleanup does not attempt a second close() on the "
          "already-released probe directory fd");

    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);
}

static void test_prescan_multiple_roots(const char *base)
{
    printf(BLUE "::" NC " pre-scan aggregates shortenings across roots\n");
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_a, sizeof(source_a), base, "multi-source-a");
    join_path(source_b, sizeof(source_b), base, "multi-source-b");
    join_path(container_path, sizeof(container_path), base,
              "multi-container");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container_path);

    char oversized_name[NAME_MAX + 1U];
    size_t oversized_length = NAME_MAX / 3U + 1U;
    memset(oversized_name, ':', oversized_length);
    oversized_name[oversized_length] = '\0';
    char path[PATH_MAX];
    join_path(path, sizeof(path), source_a, oversized_name);
    write_file(path, "a", 1);
    join_path(path, sizeof(path), source_b, oversized_name);
    write_file(path, "b", 1);

    int container_fd = open(container_path,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open multi-root container");
    PortableRootSpec roots[2] = {
        root_spec("ROOT_A", source_a, "A"),
        root_spec("ROOT_B", source_b, "B")
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = roots,
        .root_count = 2,
        .nsec_exact = 1
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    int result = portable_collision_plan_build(container_fd, &request, &report);
    check(result == 0 && report.total_count == 2 &&
              report.shortening_count == 2 && report.unresolved_count == 0 &&
              report.example_count == 2 && report.collision_plan.count == 2,
          "pre-scan resolves every NAME_MAX expansion across multiple roots");
    int root_a_seen = 0;
    int root_b_seen = 0;
    for (size_t index = 0; index < report.example_count; index++) {
        const PortablePrescanViolation *violation = &report.examples[index];
        if (violation->kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
            violation->resolved &&
            strcmp(violation->logical_path, oversized_name) == 0) {
            if (strcmp(violation->root_id, "ROOT_A") == 0)
                root_a_seen = 1;
            if (strcmp(violation->root_id, "ROOT_B") == 0)
                root_b_seen = 1;
        }
    }
    check(root_a_seen && root_b_seen,
          "resolved shortening examples retain each root identity");
    PortablePhysicalName expected;
    int mapped = portable_physical_name_map(oversized_name, 0, &expected) == 0;
    const PortableCollisionPlanEntry *planned_a =
        portable_collision_plan_find(&report.collision_plan, "ROOT_A",
                                     oversized_name);
    const PortableCollisionPlanEntry *planned_b =
        portable_collision_plan_find(&report.collision_plan, "ROOT_B",
                                     oversized_name);
    check(mapped && expected.shortened && planned_a != NULL && planned_b != NULL &&
              strcmp(planned_a->physical_leaf, expected.physical_leaf) == 0 &&
              strcmp(planned_b->physical_leaf, expected.physical_leaf) == 0 &&
              empty_capture_container(container_fd),
          "multi-root shortening plans stay root-specific without mutation");
    check(portable_current_source_contains(&report.current_source,
                                           "ROOT_A", oversized_name) == 1 &&
              portable_current_source_contains(&report.current_source,
                                               "ROOT_B", oversized_name) == 1,
          "identical logical paths remain distinct prepared members across roots");
    portable_prescan_report_free(&report);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container_path);
}

static int live_kind(SidecarLog *log, const char *root, const char *logical,
                     SidecarObjectKind kind)
{
    SidecarLiveView view;
    int found = sidecar_log_find(log, bytes(root), bytes(logical), &view);
    return found == 1 && view.entry->kind == kind;
}

static int sidecar_bytes_equal_for_test(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 ||
            (left.data != NULL && right.data != NULL &&
             memcmp(left.data, right.data, left.length) == 0));
}

#define TEST_MAX_PENDING_CLAIMS 64U

typedef struct {
    unsigned char root_id[SIDECAR_MAX_ROOT_ID];
    unsigned char logical_path[SIDECAR_MAX_PATH];
    unsigned char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF];
    size_t root_length;
    size_t logical_length;
    size_t physical_leaf_length;
    SidecarObjectKind kind;
} PendingClaimForTest;

static int pending_claim_copy(PendingClaimForTest *destination,
                              const SidecarClaim *source)
{
    if (destination == NULL || source == NULL ||
        source->root_id.length > sizeof(destination->root_id) ||
        source->logical_path.length > sizeof(destination->logical_path) ||
        source->physical_leaf.length > sizeof(destination->physical_leaf))
        return -1;
    if (source->root_id.length != 0)
        memcpy(destination->root_id, source->root_id.data,
               source->root_id.length);
    if (source->logical_path.length != 0)
        memcpy(destination->logical_path, source->logical_path.data,
               source->logical_path.length);
    if (source->physical_leaf.length != 0)
        memcpy(destination->physical_leaf, source->physical_leaf.data,
               source->physical_leaf.length);
    destination->root_length = source->root_id.length;
    destination->logical_length = source->logical_path.length;
    destination->physical_leaf_length = source->physical_leaf.length;
    destination->kind = source->kind;
    return 0;
}

static int pending_claim_matches_entry(const PendingClaimForTest *claim,
                                       const SidecarEntry *entry)
{
    if (claim == NULL || entry == NULL)
        return 0;
    return sidecar_bytes_equal_for_test(
               (SidecarBytes){ claim->root_id, claim->root_length },
               entry->root_id) &&
           sidecar_bytes_equal_for_test(
               (SidecarBytes){ claim->logical_path, claim->logical_length },
               entry->logical_path) &&
           sidecar_bytes_equal_for_test(
               (SidecarBytes){ claim->physical_leaf,
                               claim->physical_leaf_length },
               entry->physical_leaf) &&
           claim->kind == entry->kind;
}

typedef struct {
    int valid;
    int claims;
    int entries;
    int commits;
    int group_open;
    size_t pending_count;
    PendingClaimForTest pending[TEST_MAX_PENDING_CLAIMS];
} ClaimOrder;

static int claim_order_callback(const SidecarRecord *record, void *opaque)
{
    ClaimOrder *order = opaque;
    if (record == NULL || order == NULL) {
        if (order != NULL)
            order->valid = 0;
        return 0;
    }
    if (record->type == SIDECAR_RECORD_CLAIM) {
        if (order->group_open ||
            order->pending_count >= TEST_MAX_PENDING_CLAIMS ||
            pending_claim_copy(&order->pending[order->pending_count],
                               &record->value.claim) != 0)
            order->valid = 0;
        else
            order->pending_count++;
        order->claims++;
    } else if (record->type == SIDECAR_RECORD_ENTRY) {
        size_t pending_index = TEST_MAX_PENDING_CLAIMS;
        for (size_t index = 0; index < order->pending_count; index++)
            if (pending_claim_matches_entry(&order->pending[index],
                                            &record->value.entry)) {
                pending_index = index;
                break;
            }
        if (pending_index == TEST_MAX_PENDING_CLAIMS)
            order->valid = 0;
        else {
            order->pending_count--;
            order->pending[pending_index] =
                order->pending[order->pending_count];
        }
        if (order->group_open)
            order->valid = 0;
        order->group_open = 1;
        order->entries++;
    } else if (record->type == SIDECAR_RECORD_XATTR) {
        if (!order->group_open)
            order->valid = 0;
    } else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT) {
        if (!order->group_open)
            order->valid = 0;
        order->group_open = 0;
        order->commits++;
    } else if (record->type == SIDECAR_RECORD_DELETE) {
        if (order->group_open)
            order->valid = 0;
    }
    return 0;
}

static int claim_order_complete(const ClaimOrder *order)
{
    return order != NULL && order->valid && order->pending_count == 0 &&
           !order->group_open && order->claims == order->entries &&
           order->entries == order->commits;
}

static int claim_absent(SidecarLog *log, const char *root,
                        const char *logical)
{
    SidecarClaimView view;
    return sidecar_log_find_claim(log, bytes(root), bytes(logical), &view) == 0;
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
    ClaimOrder claim_order;
} FreshSidecarCheck;

static int fresh_sidecar_callback(const SidecarRecord *record, void *opaque)
{
    FreshSidecarCheck *check_state = opaque;
    claim_order_callback(record, &check_state->claim_order);
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
    ClaimOrder claim_order;
} ReplacementOrder;

static int replacement_callback(const SidecarRecord *record, void *opaque)
{
    ReplacementOrder *order = opaque;
    claim_order_callback(record, &order->claim_order);
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
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
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
    FreshSidecarCheck sidecar_check = {
        .valid = 1,
        .claim_order = { .valid = 1 }
    };
    SidecarParseResult parse_result;
    SidecarStatus parse_status = SIDECAR_STATUS_INVALID_ARGUMENT;
    if (slot_fd >= 0)
        parse_status = sidecar_parse_fd(slot_fd, fresh_sidecar_callback,
                                        &sidecar_check, &parse_result);
    check(slot_fd >= 0 &&
          parse_status == SIDECAR_STATUS_OK &&
          sidecar_check.valid && sidecar_check.entries == 4 &&
          sidecar_check.commits == 4 && sidecar_check.symlink_seen &&
          claim_order_complete(&sidecar_check.claim_order) &&
          sidecar_check.claim_order.claims == 4 &&
          sidecar_check.symlink_target_ok &&
          !sidecar_check.symlink_regular_xattr_leaked &&
          (!symlink_xattr_expected ||
           (sidecar_check.symlink_xattr_seen &&
            sidecar_check.symlink_entry_xattr_count >= 1)) &&
          (!xattr_expected ||
           sidecar_check.expected_xattr_seen),
          "sidecar contains complete groups, symlink target, and xattrs");
    SidecarLog state_log = {0};
    int state_open = sidecar_log_adopt_at(container_fd, &state_log) ==
                     SIDECAR_OPEN_RESUMABLE;
    check(state_open && claim_absent(&state_log, "ROOT", "") &&
              claim_absent(&state_log, "ROOT", "nested") &&
              claim_absent(&state_log, "ROOT", "nested/file.txt") &&
              claim_absent(&state_log, "ROOT", "nested/link"),
          "fresh capture consumes every payload claim");
    if (state_open)
        sidecar_log_close(&state_log);
    if (slot_fd >= 0)
        close(slot_fd);
}

static int sidecar_view_physical_path(const SidecarLiveView *view,
                                      char *path, size_t path_size)
{
    if (view == NULL || view->entry == NULL || path == NULL || path_size == 0 ||
        view->entry->physical_path.length >= path_size ||
        (view->entry->physical_path.length != 0 &&
         view->entry->physical_path.data == NULL))
        return -1;
    memcpy(path, view->entry->physical_path.data,
           view->entry->physical_path.length);
    path[view->entry->physical_path.length] = '\0';
    return 0;
}

static void test_portable_hardlinks(const char *base)
{
    printf(BLUE "::" NC " portable hardlink capture and resume\n");
    char source[PATH_MAX];
    char container[PATH_MAX];
    char first[PATH_MAX];
    char second[PATH_MAX];
    char single[PATH_MAX];
    join_path(source, sizeof(source), base, "hardlink-source");
    join_path(container, sizeof(container), base, "hardlink-container");
    join_path(first, sizeof(first), source, "first");
    join_path(second, sizeof(second), source, "second");
    join_path(single, sizeof(single), source, "single");
    make_directory(source);
    make_directory(container);
    write_file(first, "hardlink-content", 16);
    if (link(first, second) != 0)
        fixture_fatal("could not create hardlink pair");
    if (chmod(first, 0640) != 0)
        fixture_fatal("could not set hardlink fixture mode");
    write_file(single, "singleton", 9);

    int xattr_expected = 1;
    static const char xattr_name[] = "user.migr_hardlink";
    static const char xattr_value[] = "shared-value";
    if (setxattr(second, xattr_name, xattr_value, sizeof(xattr_value) - 1U,
                 0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) {
            xattr_expected = 0;
            skip_check("hardlink xattr fixture unavailable on this filesystem");
        } else {
            fixture_fatal("could not create hardlink xattr fixture");
        }
    }

    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open hardlink container");
    PortableRootSpec root = root_spec("HL", source, "HL");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    PortablePrescanReport prescan_report;
    portable_prescan_report_init(&prescan_report);
    check(portable_collision_plan_build(container_fd, &request,
                                         &prescan_report) == 0 &&
              prescan_report.total_size == 25U &&
              prescan_report.total_size != 41U,
          "pre-scan counts a hardlink group once (25 bytes, not 41)");
    portable_prescan_report_free(&prescan_report);
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "hardlink pair capture succeeds");

    SidecarLog log = {0};
    SidecarOpenStatus open_status = sidecar_log_adopt_at(container_fd, &log);
    check(open_status == SIDECAR_OPEN_RESUMABLE,
          "hardlink sidecar can be reopened");
    if (open_status == SIDECAR_OPEN_RESUMABLE) {
        int slot_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                             O_RDONLY | O_CLOEXEC);
        ClaimOrder order = { .valid = 1 };
        SidecarParseResult parse_result;
        SidecarStatus parse_status = SIDECAR_STATUS_INVALID_ARGUMENT;
        if (slot_fd >= 0)
            parse_status = sidecar_parse_fd(slot_fd, claim_order_callback,
                                            &order, &parse_result);
        check(slot_fd >= 0 && parse_status == SIDECAR_STATUS_OK &&
                  claim_order_complete(&order) && order.claims == 4,
              "fresh hardlink capture orders and consumes every claim");
        if (slot_fd >= 0)
            close(slot_fd);

        SidecarLiveView first_view = {0};
        SidecarLiveView second_view = {0};
        SidecarLiveView single_view = {0};
        int first_found = sidecar_log_find(&log, bytes("HL"), bytes("first"),
                                           &first_view);
        int second_found = sidecar_log_find(&log, bytes("HL"), bytes("second"),
                                            &second_view);
        int pair_found = first_found == 1 && second_found == 1;
        int one_regular = pair_found &&
                          ((first_view.entry->kind == SIDECAR_KIND_REGULAR) !=
                           (second_view.entry->kind == SIDECAR_KIND_REGULAR));
        int one_hardlink = pair_found &&
                           ((first_view.entry->kind == SIDECAR_KIND_HARDLINK) !=
                            (second_view.entry->kind == SIDECAR_KIND_HARDLINK));
        check(one_regular && one_hardlink,
              "one hardlink member is regular and the other is HARDLINK");

        const SidecarLiveView *representative = NULL;
        const SidecarLiveView *hardlink = NULL;
        if (pair_found) {
            if (first_view.entry->kind == SIDECAR_KIND_REGULAR) {
                representative = &first_view;
                hardlink = &second_view;
            } else if (second_view.entry->kind == SIDECAR_KIND_REGULAR) {
                representative = &second_view;
                hardlink = &first_view;
            }
        }
        int reference_ok = pair_found && one_regular && one_hardlink &&
                           sidecar_bytes_match_text(
                               hardlink->entry->hardlink_root_id, "HL") &&
                           hardlink->entry->hardlink_logical_path.length ==
                               representative->entry->logical_path.length &&
                           memcmp(hardlink->entry->hardlink_logical_path.data,
                                  representative->entry->logical_path.data,
                                  representative->entry->logical_path.length) == 0;
        check(reference_ok,
              "HARDLINK record points to the first-seen representative");
        check(pair_found && representative != NULL && hardlink != NULL &&
                  hardlink->entry->size == 0 &&
                  hardlink->xattr_count == 0,
              "HARDLINK record owns an empty placeholder and no xattrs");
        check(!xattr_expected || (representative != NULL &&
                                  representative->xattr_count >= 1),
              "only the representative carries the shared xattr");

        char representative_path[PATH_MAX];
        char hardlink_path[PATH_MAX];
        int representative_path_ok =
            sidecar_view_physical_path(representative, representative_path,
                                       sizeof(representative_path)) == 0;
        int hardlink_path_ok =
            sidecar_view_physical_path(hardlink, hardlink_path,
                                       sizeof(hardlink_path)) == 0;
        char data_root[PATH_MAX];
        join_path(data_root, sizeof(data_root), container, "data/HL");
        char payload[PATH_MAX];
        struct stat hardlink_stat = {0};
        int representative_payload = 0;
        int hardlink_payload = 0;
        if (representative_path_ok && hardlink_path_ok) {
            join_path(payload, sizeof(payload), data_root, representative_path);
            representative_payload = file_equals(payload, "hardlink-content");
            join_path(payload, sizeof(payload), data_root, hardlink_path);
            hardlink_payload = lstat(payload, &hardlink_stat) == 0 &&
                               S_ISREG(hardlink_stat.st_mode) &&
                               hardlink_stat.st_size == 0;
        }
        check(representative_payload && hardlink_payload,
              "regular payload is copied once and HARDLINK payload is empty");

        check(sidecar_log_find(&log, bytes("HL"), bytes("single"),
                               &single_view) == 1 &&
                  single_view.entry->kind == SIDECAR_KIND_REGULAR,
              "a singly-linked file remains REGULAR");
        check(claim_absent(&log, "HL", "") &&
                  claim_absent(&log, "HL", "first") &&
                  claim_absent(&log, "HL", "second") &&
                  claim_absent(&log, "HL", "single"),
              "fresh hardlink capture leaves no outstanding claims");

        struct stat representative_before = {0};
        int representative_stat_ok = representative_path_ok;
        if (representative_stat_ok) {
            join_path(payload, sizeof(payload), data_root, representative_path);
            representative_stat_ok = stat(payload, &representative_before) == 0;
        }
        sidecar_log_close(&log);

        PortablePrescanReport report;
        portable_prescan_report_init(&report);
        check(portable_capture_resume_at(container_fd, &request, &report) == 0,
              "unchanged hardlink group resumes successfully");
        portable_prescan_report_free(&report);

        open_status = sidecar_log_adopt_at(container_fd, &log);
        SidecarLiveView resumed_first = {0};
        SidecarLiveView resumed_second = {0};
        int resumed_pair = open_status == SIDECAR_OPEN_RESUMABLE &&
                           sidecar_log_find(&log, bytes("HL"), bytes("first"),
                                            &resumed_first) == 1 &&
                           sidecar_log_find(&log, bytes("HL"), bytes("second"),
                                            &resumed_second) == 1;
        check(resumed_pair &&
                  ((resumed_first.entry->kind == SIDECAR_KIND_HARDLINK) !=
                   (resumed_second.entry->kind == SIDECAR_KIND_HARDLINK)),
              "resume preserves the hardlink classification");
        check(claim_absent(&log, "HL", "") &&
                  claim_absent(&log, "HL", "first") &&
                  claim_absent(&log, "HL", "second") &&
                  claim_absent(&log, "HL", "single"),
              "unchanged hardlink resume writes no outstanding claims");
        if (representative_stat_ok) {
            join_path(payload, sizeof(payload), data_root, representative_path);
            struct stat representative_after = {0};
            check(stat(payload, &representative_after) == 0 &&
                      representative_after.st_ino == representative_before.st_ino &&
                      representative_after.st_mtim.tv_sec ==
                          representative_before.st_mtim.tv_sec &&
                      representative_after.st_mtim.tv_nsec ==
                          representative_before.st_mtim.tv_nsec,
                  "resume does not rewrite an unchanged representative payload");
        }
        sidecar_log_close(&log);

        if (chmod(first, 0600) != 0)
            fixture_fatal("could not change hardlink fixture mode");
        portable_prescan_report_init(&prescan_report);
        check(portable_capture_resume_at(container_fd, &request,
                                          &prescan_report) == 0,
              "changed hardlink metadata is recaptured with claims");
        portable_prescan_report_free(&prescan_report);

        open_status = sidecar_log_adopt_at(container_fd, &log);
        SidecarLiveView changed_first = {0};
        SidecarLiveView changed_second = {0};
        int changed_pair = open_status == SIDECAR_OPEN_RESUMABLE &&
                           sidecar_log_find(&log, bytes("HL"), bytes("first"),
                                            &changed_first) == 1 &&
                           sidecar_log_find(&log, bytes("HL"), bytes("second"),
                                            &changed_second) == 1;
        check(changed_pair &&
                  (changed_first.entry->mode & 07777U) == 0600U &&
                  (changed_second.entry->mode & 07777U) == 0600U &&
                  ((changed_first.entry->kind == SIDECAR_KIND_HARDLINK) !=
                   (changed_second.entry->kind == SIDECAR_KIND_HARDLINK)),
              "hardlink replacement preserves the changed metadata and kinds");
        check(open_status == SIDECAR_OPEN_RESUMABLE &&
                  claim_absent(&log, "HL", "") &&
                  claim_absent(&log, "HL", "first") &&
                  claim_absent(&log, "HL", "second") &&
                  claim_absent(&log, "HL", "single"),
              "hardlink replacement consumes every claim");
        if (open_status == SIDECAR_OPEN_RESUMABLE) {
            int replacement_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                                         O_RDONLY | O_CLOEXEC);
            ClaimOrder replacement_order = { .valid = 1 };
            parse_status = SIDECAR_STATUS_INVALID_ARGUMENT;
            if (replacement_fd >= 0)
                parse_status = sidecar_parse_fd(
                    replacement_fd, claim_order_callback, &replacement_order,
                    &parse_result);
            check(replacement_fd >= 0 && parse_status == SIDECAR_STATUS_OK &&
                      claim_order_complete(&replacement_order) &&
                      replacement_order.claims > 4,
                  "hardlink replacement keeps CLAIM before each ENTRY");
            if (replacement_fd >= 0)
                close(replacement_fd);
            sidecar_log_close(&log);
        }
    }
    close(container_fd);
    remove_tree(source);
    remove_tree(container);
}

static void test_portable_hardlinks_sticky_seed(const char *base)
{
    printf(BLUE "::" NC " resume keeps the recorded hardlink representative\n");
    char source[PATH_MAX];
    char container[PATH_MAX];
    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    join_path(source, sizeof(source), base, "hardlink-sticky-source");
    join_path(container, sizeof(container), base, "hardlink-sticky-container");
    join_path(first_path, sizeof(first_path), source, "first");
    join_path(second_path, sizeof(second_path), source, "second");
    make_directory(source);
    make_directory(container);
    write_file(first_path, "sticky-content", 14);
    if (link(first_path, second_path) != 0)
        fixture_fatal("could not create sticky-seed hardlink pair");

    char first_seen[NAME_MAX + 1U];
    DIR *directory = opendir(source);
    if (directory == NULL)
        fixture_fatal("could not inspect sticky-seed source order");
    struct dirent *entry = NULL;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL)
            break;
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            break;
    }
    if (entry == NULL || strlen(entry->d_name) >= sizeof(first_seen) ||
        (strcmp(entry->d_name, "first") != 0 &&
         strcmp(entry->d_name, "second") != 0) ||
        snprintf(first_seen, sizeof(first_seen), "%s", entry->d_name) < 0 ||
        closedir(directory) != 0)
        fixture_fatal("could not determine sticky-seed source order");

    const char *old_representative = strcmp(first_seen, "first") == 0
        ? "second" : "first";
    const char *old_member = strcmp(old_representative, "first") == 0
        ? "second" : "first";

    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open sticky-seed container");
    if (mkdirat(container_fd, "data", 0700) != 0 ||
        mkdirat(container_fd, "data/HL", 0700) != 0)
        fixture_fatal("could not create sticky-seed payload namespace");

    char data_root[PATH_MAX];
    char representative_payload[PATH_MAX];
    char member_payload[PATH_MAX];
    join_path(data_root, sizeof(data_root), container, "data/HL");
    join_path(representative_payload, sizeof(representative_payload),
              data_root, old_representative);
    join_path(member_payload, sizeof(member_payload), data_root, old_member);
    write_file(representative_payload, "sticky-content", 14);
    write_file(member_payload, "", 0);

    struct stat source_root_stat;
    struct stat representative_stat;
    struct stat member_stat;
    if (stat(source, &source_root_stat) != 0 ||
        stat(strcmp(old_representative, "first") == 0 ? first_path :
             second_path, &representative_stat) != 0 ||
        stat(strcmp(old_member, "first") == 0 ? first_path : second_path,
             &member_stat) != 0)
        fixture_fatal("could not stat sticky-seed source fixture");

    int source_fd = open(strcmp(old_representative, "first") == 0
                              ? first_path : second_path,
                          O_RDONLY | O_NOATIME | O_CLOEXEC);
    PortableXattrs representative_xattrs = {0};
    if (source_fd < 0 || collect_xattrs(source_fd, &representative_xattrs) != 0 ||
        close(source_fd) != 0)
        fixture_fatal("could not collect sticky-seed source xattrs");

    PortableRootSpec root = root_spec("HL", source, "HL");
    ManifestRoot manifest_root = {
        .id = "HL",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .payload_path = "HL",
        .source_path = "",
        .restore_path = "",
        .has_restore_path = 1
    };
    Manifest manifest = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_PORTABLE_SIDECAR,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .sidecar_version = SIDECAR_VERSION,
        .has_source_identity = 1,
        .source_uid = getuid(),
        .root_count = 1,
        .roots = &manifest_root
    };
    if (snprintf(manifest.machine_id, sizeof(manifest.machine_id),
                 "%s", "0123456789abcdef") < 0 ||
        manifest_write_v1_at(container_fd, &manifest) != 0)
        fixture_fatal("could not write sticky-seed manifest");

    PortableXattrs empty_xattrs = {0};
    SidecarEntry root_entry = {0};
    SidecarEntry representative_entry = {0};
    SidecarEntry member_entry = {0};
    SidecarBytes hardlink_root_id = bytes("HL");
    SidecarBytes hardlink_logical_path = bytes(old_representative);
    if (entry_from_stat("HL", "", "", "", &source_root_stat, 1,
                        &empty_xattrs, &root_entry, NULL, NULL, NULL) != 0 ||
        entry_from_stat("HL", old_representative, old_representative, "",
                        &representative_stat, 1, &representative_xattrs,
                        &representative_entry, NULL, NULL, NULL) != 0 ||
        entry_from_stat("HL", old_member, old_member, "", &member_stat, 1,
                        &empty_xattrs, &member_entry, NULL,
                        &hardlink_root_id, &hardlink_logical_path) != 0)
        fixture_fatal("could not prepare sticky-seed sidecar entries");
    SidecarClaim root_claim = {
        .root_id = root_entry.root_id,
        .logical_path = root_entry.logical_path,
        .physical_leaf = root_entry.physical_leaf,
        .kind = root_entry.kind
    };
    SidecarClaim representative_claim = {
        .root_id = representative_entry.root_id,
        .logical_path = representative_entry.logical_path,
        .physical_leaf = representative_entry.physical_leaf,
        .kind = representative_entry.kind
    };
    SidecarClaim member_claim = {
        .root_id = member_entry.root_id,
        .logical_path = member_entry.logical_path,
        .physical_leaf = member_entry.physical_leaf,
        .kind = member_entry.kind
    };

    SidecarLog log = {0};
    if (sidecar_log_create_at(container_fd, &log) != SIDECAR_OPEN_FRESH ||
        sidecar_log_append_claim(&log, &root_claim) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &root_entry) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &representative_claim) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &representative_entry) !=
            SIDECAR_STATUS_OK)
        fixture_fatal("could not write sticky-seed sidecar");
    for (size_t index = 0; index < representative_xattrs.count; index++)
        if (sidecar_log_append_xattr(&log,
                                     &representative_xattrs.items[index]) !=
            SIDECAR_STATUS_OK)
            fixture_fatal("could not write sticky-seed xattrs");
    if (sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_append_claim(&log, &member_claim) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(&log, &member_entry) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK ||
        sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fixture_fatal("could not write sticky-seed sidecar");
    xattrs_free(&representative_xattrs);

    struct stat representative_before;
    struct stat member_before;
    int payload_stats = stat(representative_payload, &representative_before) == 0 &&
                        stat(member_payload, &member_before) == 0;
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    PortablePrescanReport report;
    portable_prescan_report_init(&report);
    check(payload_stats && portable_capture_resume_at(container_fd, &request,
                                                       &report) == 0,
          "resume succeeds with the recorded representative visited second");
    portable_prescan_report_free(&report);

    SidecarLiveView representative_view = {0};
    SidecarLiveView member_view = {0};
    int opened = sidecar_log_adopt_at(container_fd, &log) ==
                 SIDECAR_OPEN_RESUMABLE;
    int entries_found = opened &&
        sidecar_log_find(&log, bytes("HL"), bytes(old_representative),
                         &representative_view) == 1 &&
        sidecar_log_find(&log, bytes("HL"), bytes(old_member), &member_view) == 1;
    check(entries_found && representative_view.entry->kind ==
              SIDECAR_KIND_REGULAR &&
              member_view.entry->kind == SIDECAR_KIND_HARDLINK &&
              sidecar_bytes_match_text(member_view.entry->hardlink_root_id,
                                       "HL") &&
              sidecar_bytes_match_text(member_view.entry->hardlink_logical_path,
                                       old_representative),
          "resume preserves the recorded representative and hardlink reference");

    struct stat representative_after = {0};
    struct stat member_after = {0};
    int representative_after_ok = stat(representative_payload,
                                       &representative_after) == 0;
    int member_after_ok = stat(member_payload, &member_after) == 0;
    int payload_unchanged = payload_stats &&
        representative_after_ok && member_after_ok &&
        representative_after.st_ino == representative_before.st_ino &&
        representative_after.st_mtim.tv_sec == representative_before.st_mtim.tv_sec &&
        representative_after.st_mtim.tv_nsec == representative_before.st_mtim.tv_nsec &&
        member_after.st_ino == member_before.st_ino &&
        member_after.st_size == 0 &&
        member_after.st_mtim.tv_sec == member_before.st_mtim.tv_sec &&
        member_after.st_mtim.tv_nsec == member_before.st_mtim.tv_nsec;
    check(payload_unchanged,
          "resume leaves the representative and placeholder payloads untouched");
    check(entries_found && member_after_ok && member_after.st_size == 0,
          "hardlink placeholder remains present after reconciliation");
    if (opened)
        sidecar_log_close(&log);
    close(container_fd);
    remove_tree(source);
    remove_tree(container);
}

static void test_portable_hardlinks_cross_root(const char *base)
{
    printf(BLUE "::" NC " portable hardlink groups across roots\n");
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char container[PATH_MAX];
    char file_a[PATH_MAX];
    char file_b[PATH_MAX];
    join_path(source_a, sizeof(source_a), base, "hardlink-cross-a");
    join_path(source_b, sizeof(source_b), base, "hardlink-cross-b");
    join_path(container, sizeof(container), base, "hardlink-cross-container");
    join_path(file_a, sizeof(file_a), source_a, "file");
    join_path(file_b, sizeof(file_b), source_b, "alias");
    make_directory(source_a);
    make_directory(source_b);
    make_directory(container);
    write_file(file_a, "cross-root", 10);
    if (link(file_a, file_b) != 0)
        fixture_fatal("could not create cross-root hardlink");

    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open cross-root hardlink container");
    PortableRootSpec roots[] = {
        root_spec("ROOT_A", source_a, "A"),
        root_spec("ROOT_B", source_b, "B")
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = roots,
        .root_count = 2,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    PortablePrescanReport prescan_report;
    portable_prescan_report_init(&prescan_report);
    check(portable_collision_plan_build(container_fd, &request,
                                         &prescan_report) == 0 &&
              prescan_report.total_size == 10U &&
              prescan_report.total_size != 20U,
          "pre-scan counts a cross-root hardlink group once");
    portable_prescan_report_free(&prescan_report);
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "cross-root hardlink capture succeeds");
    SidecarLog log = {0};
    SidecarOpenStatus status = sidecar_log_adopt_at(container_fd, &log);
    SidecarLiveView first = {0};
    SidecarLiveView second = {0};
    int found = status == SIDECAR_OPEN_RESUMABLE &&
                sidecar_log_find(&log, bytes("ROOT_A"), bytes("file"),
                                 &first) == 1 &&
                sidecar_log_find(&log, bytes("ROOT_B"), bytes("alias"),
                                 &second) == 1;
    check(found && first.entry->kind == SIDECAR_KIND_REGULAR &&
              second.entry->kind == SIDECAR_KIND_HARDLINK,
          "the second root records a cross-root HARDLINK");
    check(found && sidecar_bytes_match_text(second.entry->hardlink_root_id,
                                            "ROOT_A") &&
              second.entry->hardlink_logical_path.length ==
                  first.entry->logical_path.length &&
              memcmp(second.entry->hardlink_logical_path.data,
                     first.entry->logical_path.data,
                     first.entry->logical_path.length) == 0,
          "cross-root HARDLINK references the first root's representative");
    sidecar_log_close(&log);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container);
}

static void test_portable_hardlinks_cross_root_bare_file(const char *base)
{
    printf(BLUE "::" NC " portable hardlink groups across roots with a bare-file representative\n");
    char source_a[PATH_MAX];
    char source_b[PATH_MAX];
    char container[PATH_MAX];
    char file_b[PATH_MAX];
    join_path(source_a, sizeof(source_a), base, "hardlink-cross-bare-a");
    join_path(source_b, sizeof(source_b), base, "hardlink-cross-bare-b");
    join_path(container, sizeof(container), base,
              "hardlink-cross-bare-container");
    join_path(file_b, sizeof(file_b), source_b, "alias");
    make_directory(source_b);
    make_directory(container);
    write_file(source_a, "cross-root", 10);
    if (link(source_a, file_b) != 0)
        fixture_fatal("could not create bare-file cross-root hardlink");

    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open bare-file cross-root hardlink container");
    PortableRootSpec roots[] = {
        root_spec("ROOT_A", source_a, "A"),
        root_spec("ROOT_B", source_b, "B")
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = roots,
        .root_count = 2,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "cross-root hardlink capture succeeds when the representative is a bare-file root");

    SidecarLog log = {0};
    SidecarOpenStatus status = sidecar_log_adopt_at(container_fd, &log);
    SidecarLiveView first = {0};
    SidecarLiveView second = {0};
    int found = status == SIDECAR_OPEN_RESUMABLE &&
                sidecar_log_find(&log, bytes("ROOT_A"), bytes(""),
                                 &first) == 1 &&
                sidecar_log_find(&log, bytes("ROOT_B"), bytes("alias"),
                                 &second) == 1;
    check(found && first.entry->kind == SIDECAR_KIND_REGULAR &&
              second.entry->kind == SIDECAR_KIND_HARDLINK,
          "the second root records a cross-root HARDLINK");
    check(found && sidecar_bytes_match_text(second.entry->hardlink_root_id,
                                            "ROOT_A") &&
              second.entry->hardlink_logical_path.length == 0,
          "cross-root HARDLINK references the bare-file representative's empty logical path");
    if (status == SIDECAR_OPEN_RESUMABLE)
        sidecar_log_close(&log);
    close(container_fd);
    remove_tree(source_a);
    remove_tree(source_b);
    remove_tree(container);
}

static void test_portable_hardlinks_collision(const char *base)
{
    printf(BLUE "::" NC " hardlinks under a suffixed collision parent\n");
    char source[PATH_MAX];
    char container[PATH_MAX];
    char upper[PATH_MAX];
    char lower[PATH_MAX];
    char target[PATH_MAX];
    char alias[PATH_MAX];
    join_path(source, sizeof(source), base, "hardlink-collision-source");
    join_path(container, sizeof(container), base,
              "hardlink-collision-container");
    join_path(upper, sizeof(upper), source, "Foo");
    join_path(lower, sizeof(lower), source, "foo");
    join_path(target, sizeof(target), lower, "target");
    join_path(alias, sizeof(alias), lower, "alias");
    make_directory(source);
    make_directory(container);
    make_directory(upper);
    make_directory(lower);
    write_file(target, "collision-hardlink", 18);
    if (link(target, alias) != 0)
        fixture_fatal("could not create collision hardlink");

    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open collision hardlink container");
    PortableRootSpec root = root_spec("CASE", source, "CASE");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 0
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "hardlink capture under a case collision succeeds");
    SidecarLog log = {0};
    SidecarOpenStatus status = sidecar_log_adopt_at(container_fd, &log);
    SidecarLiveView target_view = {0};
    SidecarLiveView alias_view = {0};
    int found = status == SIDECAR_OPEN_RESUMABLE &&
                sidecar_log_find(&log, bytes("CASE"), bytes("foo/target"),
                                 &target_view) == 1 &&
                sidecar_log_find(&log, bytes("CASE"), bytes("foo/alias"),
                                 &alias_view) == 1;
    char target_physical[PATH_MAX];
    char alias_physical[PATH_MAX];
    int paths_ok = found &&
                   sidecar_view_physical_path(&target_view, target_physical,
                                              sizeof(target_physical)) == 0 &&
                   sidecar_view_physical_path(&alias_view, alias_physical,
                                              sizeof(alias_physical)) == 0;
    check(paths_ok && strncmp(target_physical, "foo%7E1/", 8) == 0 &&
              strncmp(alias_physical, "foo%7E1/", 8) == 0,
          "hardlink payload paths inherit the collision suffix");
    check(found && ((target_view.entry->kind == SIDECAR_KIND_HARDLINK) !=
                   (alias_view.entry->kind == SIDECAR_KIND_HARDLINK)),
          "collision planning does not duplicate the hardlink group");
    sidecar_log_close(&log);
    close(container_fd);
    remove_tree(source);
    remove_tree(container);
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
    check(capture_root_with_current_prescan(container_fd, &context, &root) == 0,
          "a new regular root can be appended to the live sidecar");

    write_file(file, "second", 6);
    check(capture_root_with_current_prescan(container_fd, &context, &root) == 0,
          "replacement captures the changed regular payload");
    char payload[PATH_MAX];
    join_path(payload, sizeof(payload), replacement_container, "data/FILE");
    check(file_equals(payload, "second"),
          "replacement does not leave the old payload bytes");

    check(live_kind(&log, "FILE", "", SIDECAR_KIND_REGULAR),
          "replacement leaves one live regular entry");

    int fd = openat(container_fd, SIDECAR_SLOT_NAME, O_RDONLY | O_CLOEXEC);
    ReplacementOrder order = { .claim_order = { .valid = 1 } };
    SidecarParseResult result;
    check(fd >= 0 && sidecar_parse_fd(fd, replacement_callback, &order,
                                      &result) == SIDECAR_STATUS_OK &&
          order.delete_seen && order.new_entry_seen && order.new_commit_seen &&
          !order.invalid_order && claim_order_complete(&order.claim_order) &&
          order.claim_order.claims == 2,
          "replacement log orders DELETE, CLAIM, and ENTRY group");
    if (fd >= 0)
        close(fd);

    if (unlink(file) != 0)
        fixture_fatal("could not replace regular source with directory");
    make_directory(file);
    char child[PATH_MAX];
    join_path(child, sizeof(child), file, "child");
    write_file(child, "child", 5);
    check(capture_root_with_current_prescan(container_fd, &context, &root) == 0,
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
    check(capture_root_with_current_prescan(container_fd, &context, &root) == 0,
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
    check(capture_root_with_current_prescan(container_fd, &context, &root) == 0,
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

    fd = openat(container_fd, SIDECAR_SLOT_NAME, O_RDONLY | O_CLOEXEC);
    ReplacementOrder all_order = { .claim_order = { .valid = 1 } };
    SidecarStatus all_parse_status = SIDECAR_STATUS_INVALID_ARGUMENT;
    if (fd >= 0)
        all_parse_status = sidecar_parse_fd(
            fd, replacement_callback, &all_order, &(SidecarParseResult){0});
    check(fd >= 0 && all_parse_status == SIDECAR_STATUS_OK &&
              claim_order_complete(&all_order.claim_order) &&
              all_order.claim_order.claims == 6,
          "all uninterrupted replacement groups consume ordered claims");
    if (fd >= 0)
        close(fd);

    SidecarLog state_log = {0};
    int state_open = sidecar_log_adopt_at(container_fd, &state_log) ==
                     SIDECAR_OPEN_RESUMABLE;
    check(state_open && claim_absent(&state_log, "FILE", "") &&
              claim_absent(&state_log, "FILE", "child"),
          "replacement captures leave no outstanding claims");
    if (state_open)
        sidecar_log_close(&state_log);
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
    check(capture_root_with_current_prescan(container_fd, &context,
                                            &socket_root) == 0,
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

    check(capture_root_with_current_prescan(container_fd, &context,
                                            &socket_root) == 0,
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
    check(capture_root_with_current_prescan(container_fd, &context,
                                            &fifo_root) != 0,
          "FIFO is fail-closed without opening or blocking");
    unlink(path);
    close_live_capture(container_fd, &log, &context);
}

static void test_stale_live_root_reconciliation(const char *base_path)
{
    printf(BLUE "::" NC " stale live root reconciliation\n");

    char source[PATH_MAX];
    char child[PATH_MAX];
    char container[PATH_MAX];
    join_path(source, sizeof(source), base_path, "stale-live-source");
    join_path(child, sizeof(child), source, "child");
    join_path(container, sizeof(container), base_path,
              "stale-live-container");
    make_directory(source);
    write_file(child, "child", 5);

    int container_fd = -1;
    SidecarLog log = {0};
    PortableCaptureContext context = {0};
    check(create_live_capture(container, &container_fd, &log, &context) == 0,
          "stale-live fixture opens a fresh capture context");
    if (container_fd < 0 || log.implementation == NULL)
        goto cleanup_source;

    PortableRootSpec root = root_spec("STALELIVE", source, "STALELIVE");
    check(capture_root_with_current_prescan(container_fd, &context, &root) == 0,
          "stale-live fixture captures a directory root and child");
    int reset = visited_reset(context.visited);
    int marked = reset == 0 ? visited_add(context.visited, root.id, "") : -1;
    check(reset == 0 && marked == 0,
          "stale-live fixture matches a fresh capture traversal state");
    check(reset == 0 && marked == 0 &&
              reconcile_stale_live(&context, &root, "") == 0,
          "stale live root reconciliation removes the recorded subtree");
    check(sidecar_log_find(&log, bytes("STALELIVE"), bytes(""),
                           &(SidecarLiveView){0}) == 0 &&
              sidecar_log_find(&log, bytes("STALELIVE"), bytes("child"),
                               &(SidecarLiveView){0}) == 0,
          "stale root reconciliation tombstones the root and descendant state");

    char payload[PATH_MAX];
    join_path(payload, sizeof(payload), container, "data/STALELIVE");
    struct stat st;
    check(lstat(payload, &st) != 0 && errno == ENOENT,
          "stale root reconciliation removes the recorded payload subtree");

    close_live_capture(container_fd, &log, &context);
    remove_tree(container);

cleanup_source:
    remove_tree(source);
}

static void test_portable_special_file_non_ascii_name_in_directory(
    const char *base_path)
{
    printf(BLUE "::" NC " non-ASCII special-file child policy\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base_path,
              "special-non-ascii-source");
    join_path(container_path, sizeof(container_path), base_path,
              "special-non-ascii-container");
    make_directory(source_path);
    make_directory(container_path);

    static const char regular_name[] = "caf\xc3\xa9.txt";
    static const char socket_name[] = "s\xc3\xb6" "ck.sock";
    char regular_path[PATH_MAX];
    char socket_path[PATH_MAX];
    join_path(regular_path, sizeof(regular_path), source_path, regular_name);
    join_path(socket_path, sizeof(socket_path), source_path, socket_name);
    write_file(regular_path, "payload", sizeof("payload") - 1U);

    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0)
        fixture_fatal("could not create non-ASCII socket fixture");
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path))
        fixture_fatal("non-ASCII socket fixture path is too long");
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (errno == EPERM || errno == EACCES) {
            skip_check("socket fixture unavailable in this sandbox");
            close(socket_fd);
            unlink(address.sun_path);
            remove_tree(source_path);
            remove_tree(container_path);
            return;
        }
        fixture_fatal("could not bind non-ASCII socket fixture");
    }

    int container_fd = open(container_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fixture_fatal("could not open non-ASCII special-file container");
    PortableRootSpec root = root_spec("SPECIAL", source_path, "SPECIAL");
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1
    };
    check(portable_capture_fresh_at(container_fd, &request, NULL) == 0,
          "non-ASCII special-file child does not abort directory capture");

    char payload_path[PATH_MAX];
    join_path(payload_path, sizeof(payload_path), container_path,
              "data/SPECIAL");
    char regular_payload[PATH_MAX];
    char socket_payload[PATH_MAX];
    join_path(regular_payload, sizeof(regular_payload), payload_path,
              regular_name);
    join_path(socket_payload, sizeof(socket_payload), payload_path,
              socket_name);
    check(file_equals(regular_payload, "payload"),
          "non-ASCII regular sibling remains in the captured payload");
    struct stat st;
    check(lstat(socket_payload, &st) != 0 && errno == ENOENT,
          "non-ASCII socket child remains absent from the payload");

    close(container_fd);
    close(socket_fd);
    unlink(address.sun_path);
    remove_tree(source_path);
    remove_tree(container_path);
}

static void test_fresh_stray_destination_is_refused(const char *base)
{
    printf(BLUE "::" NC " fresh capture refuses an unexplained pre-existing destination\n");
    char source_path[PATH_MAX];
    char container_path[PATH_MAX];
    join_path(source_path, sizeof(source_path), base,
              "stray-destination-source");
    join_path(container_path, sizeof(container_path), base,
              "stray-destination-container");
    write_file(source_path, "real content", 12);

    int container_fd = -1;
    SidecarLog log = {0};
    PortableCaptureContext context = {0};
    check(create_live_capture(container_path, &container_fd, &log,
                              &context) == 0,
          "fresh sidecar context is ready for the stray-destination test");
    if (container_fd < 0 || log.implementation == NULL)
        return;

    /* Simulate a latent collision-plan/case-fold bug: something already
     * occupies the destination leaf before this root's first-ever
     * capture, with no sidecar record explaining it. */
    char stray_path[PATH_MAX];
    join_path(stray_path, sizeof(stray_path), container_path, "data/ROOT");
    write_file(stray_path, "STRAY FOREIGN DATA",
               sizeof("STRAY FOREIGN DATA") - 1U);

    PortableRootSpec root = root_spec("ROOT", source_path, "ROOT");
    check(capture_root_with_current_prescan(container_fd, &context, &root) != 0,
          "fresh capture refuses to overwrite an unexplained stray destination");
    check(file_equals(stray_path, "STRAY FOREIGN DATA"),
          "the foreign content survives untouched, not silently replaced");

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
    check(portable_capture_fresh_at(container_fd, &request, NULL) != 0,
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
    test_path_validation();
    test_collision_suffix_parser();
    test_prescan_report();
    test_case_fold_helpers();
    test_case_collision_prescan(root_path);
    test_collision_plan(root_path);
    test_mixed_prescan_violations(root_path);
    test_collision_plan_suffix_length_violation(root_path);
    test_shortened_candidate_collision_determinism(root_path);
    test_current_source_membership(root_path);
    test_prepared_shortening_plan_authority(root_path);
    test_raw_component_unsigned_tiebreak(root_path);
    test_shortened_suffix_reserves_natural_candidate(root_path);
    test_shortened_ancestor_keeps_descendant_identity(root_path);
    test_case_collision_report_cap(root_path);
    test_shortening_report_cap(root_path);
    test_case_probe_group_growth(root_path);
    test_case_collision_directory_scope(root_path);
    test_capture_source_plan_mismatch(root_path);
    test_prepared_missing_member_precedes_relocation(root_path);
    test_collision_resume(root_path);
    test_collision_resume_unplanning(root_path);
    test_suffix_induced_shortening_relocation(root_path);
    test_ancestor_relocation_keeps_descendant_leaf(root_path);
    test_collision_resume_renumbering(root_path);
    test_shortened_stale_source(root_path);
    test_collision_foreign_resume(root_path);
    test_case_probe(root_path);
    test_prescan_request_validates_malformed_input(root_path);
    test_stale_case_probe_directory_recovers(root_path);
    test_encoded_payload_names(root_path);
    test_nested_encoded_directories(root_path);
    test_name_and_path_limits(root_path);
    test_prescan_multiple_roots(root_path);
    test_root_payload_namespace(root_path);
    test_root_probe_close_failure_does_not_double_close(root_path);
    test_fresh_capture(source_path, container_fd, container_path);
    test_portable_hardlinks(root_path);
    test_portable_hardlinks_sticky_seed(root_path);
    test_portable_hardlinks_cross_root(root_path);
    test_portable_hardlinks_cross_root_bare_file(root_path);
    test_portable_hardlinks_collision(root_path);
    test_capture_context_flags(root_path);
    test_replacement_and_type_change(source_path, root_path);
    test_stale_live_root_reconciliation(root_path);
    test_unsupported_types(source_path, root_path);
    test_portable_special_file_non_ascii_name_in_directory(root_path);
    test_fresh_stray_destination_is_refused(root_path);
    test_preflight_refusal(source_path);

    close(container_fd);
    remove_tree(root_path);
    printf("portable capture tests: %d failure(s), %d skipped\n",
           failures, skips);
    return failures == 0 ? 0 : 1;
}
