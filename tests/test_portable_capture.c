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
#include "sidecar.h"

extern int entry_from_stat(const char *root_id, const char *logical,
                           const char *physical,
                           const char *collision_suffix,
                           const struct stat *st, int nsec_exact,
                           PortableXattrs *xattrs, SidecarEntry *out,
                           const SidecarBytes *symlink_target);
extern int append_physical(char *destination, size_t destination_size,
                           const char *parent, const char *encoded_leaf);
extern int prescan_report_add(PortablePrescanReport *report,
                              const PortablePrescanViolation *violation);
typedef struct {
    char *folded_key;
    char *logical_path;
    size_t key_length;
    uint64_t hash;
    size_t value_index;
} PortableCaseFoldSlot;
typedef struct {
    PortableCaseFoldSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} PortableCaseFoldSet;
extern void ascii_fold_copy(char *destination, size_t destination_size,
                            const char *source);
extern void skeleton_copy(char *destination, size_t destination_size,
                          const char *source);
extern int case_fold_set_find_or_insert(PortableCaseFoldSet *set,
                                        const char *folded_key,
                                        const char *logical_path,
                                        char **out_logical_path);
extern void case_fold_set_free(PortableCaseFoldSet *set);
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
    if (violation == NULL || violation->kind != PORTABLE_PRESCAN_CASE_COLLISION)
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
    check(result == 0 && report.total_count == 0,
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
    return entry != NULL && strcmp(entry->root_id, root_id) == 0 &&
           strcmp(entry->logical_path, logical) == 0 &&
           strcmp(entry->physical_path, physical) == 0 &&
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
    check(result == 0 && report.collision_plan.count == 2 &&
              collision_plan_entry_matches(unicode_lower, "CASE",
                                            "caf\xc3\xa9",
                                            "caf\xc3\xa9%7E2", "%7E2"),
          "the collision plan reserves Unicode-equivalent source names before choosing a suffix");
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

/* Mixed pre-scan baseline: resolved case collisions are no longer fatal, while
 * NAME_MAX and PATH_MAX violations remain fatal (docs/DECISIONS.md D21, F-4/F-6). */
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
    int result = run_case_fixture(
        base, "case-mixed-violations", names, sizeof(names) / sizeof(names[0]),
        0, source_path, sizeof(source_path), container_path,
        sizeof(container_path), &container_fd, &report);

    int name_violation = 0;
    int collision_violation = 0;
    for (size_t index = 0; index < report.example_count; index++) {
        const PortablePrescanViolation *violation = &report.examples[index];
        if (violation->kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
            strcmp(violation->root_id, "CASE") == 0 &&
            strcmp(violation->logical_path, oversized_name) == 0 &&
            violation->limit == NAME_MAX &&
            violation->actual == oversized_length * 3U)
            name_violation = 1;
        if (collision_example_matches_names(
                violation, collision_names,
                sizeof(collision_names) / sizeof(collision_names[0])) &&
            violation->limit == 0 && violation->actual == 0)
            collision_violation = 1;
    }
    check(result != 0 && report.total_count == 2 &&
              report.collision_count == 1 && report.unresolved_count == 1 &&
              report.example_count == 2,
          "a resolved collision is non-fatal, but the NAME_MAX violation remains fatal");
    check(name_violation && collision_violation,
          "mixed violations retain exact NAME_MAX and collision fields");
    check(empty_capture_container(container_fd),
          "mixed violation refusal leaves the container untouched");
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
    return 0;
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
                        &empty_xattrs, &root_predecessor, NULL) != 0 ||
        entry_from_stat("CASE", loser, winner, "", &loser_stat, 1,
                        &empty_xattrs, &predecessor, NULL) != 0)
        fixture_fatal("could not prepare collision predecessor");
    SidecarLog predecessor_log = {0};
    if (sidecar_log_create_at(container_fd, &predecessor_log) !=
            SIDECAR_OPEN_FRESH ||
        sidecar_log_append_entry(&predecessor_log, &root_predecessor) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_append_entry_commit(&predecessor_log) !=
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
    check(entry_from_stat("LINK", "item", "item", "", &link_stat, 1,
                          &empty_xattrs, &entry, &target) == 0,
          "entry_from_stat accepts a symlink target");
    check(entry.kind == SIDECAR_KIND_SYMLINK && entry.size == 0 &&
              entry.xattr_count == 0 &&
              entry.symlink_target.length == target.length &&
              memcmp(entry.symlink_target.data, target.data, target.length) == 0,
          "symlink entry preserves kind, zero size, and target bytes");

    SidecarEntry symlink_entry = entry;

    check(entry_from_stat("LINK", "item", "item", "", &link_stat, 1,
                          &empty_xattrs, &entry, NULL) != 0,
          "symlink entry without a target is rejected");
    SidecarBytes empty_target = {0};
    check(entry_from_stat("LINK", "item", "item", "", &link_stat, 1,
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
    check(portable_capture_fresh_at(container_fd, &request, &report) != 0 &&
              report.total_count == 1 && report.example_count == 1 &&
              report.examples[0].kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
              strcmp(report.examples[0].root_id, "NAMES") == 0 &&
              strcmp(report.examples[0].logical_path, oversized_name) == 0 &&
              report.examples[0].limit == NAME_MAX &&
              report.examples[0].actual == oversized_length * 3U,
          "NAME_MAX violation is reported before capture");
    struct stat st;
    check(fstatat(container_fd, "manifest.txt", &st,
                  AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
              fstatat(container_fd, "data", &st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
              fstatat(container_fd, SIDECAR_SLOT_NAME, &st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
          "NAME_MAX refusal leaves the container namespace untouched");
    check(portable_capture_fresh_at(container_fd, &request, NULL) != 0,
          "NAME_MAX refusal does not depend on a report consumer");
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
    check(portable_capture_fresh_at(container_fd, &request, &report) != 0 &&
              report.total_count == 1 && report.example_count == 1 &&
              report.examples[0].kind == PORTABLE_PRESCAN_PATH_TOO_LONG &&
              strcmp(report.examples[0].root_id, "PATH") == 0 &&
              strcmp(report.examples[0].logical_path, "child") == 0 &&
              report.examples[0].limit == PATH_MAX &&
              report.examples[0].actual == PATH_MAX + 5U,
          "PATH_MAX violation is reported before capture");
    check(fstatat(container_fd, "manifest.txt", &st,
                  AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
              fstatat(container_fd, "data", &st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
              fstatat(container_fd, SIDECAR_SLOT_NAME, &st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
          "PATH_MAX refusal leaves the container namespace untouched");
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

static void test_prescan_multiple_roots(const char *base)
{
    printf(BLUE "::" NC " pre-scan aggregates violations across roots\n");
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
    check(portable_capture_fresh_at(container_fd, &request, &report) != 0 &&
              report.total_count == 2 && report.example_count == 2,
          "pre-scan reports every violation across multiple roots");
    int root_a_seen = 0;
    int root_b_seen = 0;
    for (size_t index = 0; index < report.example_count; index++) {
        const PortablePrescanViolation *violation = &report.examples[index];
        if (violation->kind == PORTABLE_PRESCAN_NAME_TOO_LONG &&
            strcmp(violation->logical_path, oversized_name) == 0) {
            if (strcmp(violation->root_id, "ROOT_A") == 0)
                root_a_seen = 1;
            if (strcmp(violation->root_id, "ROOT_B") == 0)
                root_b_seen = 1;
        }
    }
    check(root_a_seen && root_b_seen,
          "pre-scan examples retain each violating root identity");
    struct stat st;
    check(fstatat(container_fd, "manifest.txt", &st,
                  AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
              fstatat(container_fd, "data", &st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
              fstatat(container_fd, SIDECAR_SLOT_NAME, &st,
                      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
          "multi-root refusal leaves the container untouched");
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
    test_prescan_report();
    test_case_fold_helpers();
    test_case_collision_prescan(root_path);
    test_collision_plan(root_path);
    test_mixed_prescan_violations(root_path);
    test_case_collision_report_cap(root_path);
    test_case_collision_directory_scope(root_path);
    test_capture_source_plan_mismatch(root_path);
    test_collision_resume(root_path);
    test_collision_resume_renumbering(root_path);
    test_collision_foreign_resume(root_path);
    test_case_probe(root_path);
    test_encoded_payload_names(root_path);
    test_nested_encoded_directories(root_path);
    test_name_and_path_limits(root_path);
    test_prescan_multiple_roots(root_path);
    test_root_payload_namespace(root_path);
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
