#define _GNU_SOURCE
#include "config.h"
#include "metadata.h"
#include "portable.h"
#include "selection.h"
#include "sidecar.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); failures++; } } while (0)
#define REQUIRE(x) do { if (!(x)) { perror(#x); exit(1); } } while (0)

static void write_file(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    REQUIRE(file != NULL);
    REQUIRE(fputs(text, file) >= 0);
    REQUIRE(fclose(file) == 0);
}

static int remove_entry(const char *path, const struct stat *st, int type,
                        struct FTW *walk)
{
    (void)st;
    (void)type;
    (void)walk;
    return remove(path);
}

static size_t find_root(const SelectionPlan *plan, const char *path)
{
    for (size_t index = 0; index < plan->root_count; index++)
        if (strcmp(plan->roots[index].root.capture_path, path) == 0)
            return index;
    fprintf(stderr, "missing root: %s\n", path);
    exit(1);
}

static int entry_exists(int data_fd, const char *root_id, const char *relative,
                        struct stat *out)
{
    char path[PATH_MAX];
    if (relative[0] == '\0') {
        if (snprintf(path, sizeof(path), "%s", root_id) < 0)
            return 0;
    } else if (path_join(path, sizeof(path), root_id, relative) != 0) {
        return 0;
    }
    struct stat st;
    if (fstatat(data_fd, path, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return 0;
    if (out != NULL)
        *out = st;
    return 1;
}

static int roots_equal(const Manifest *left, const Manifest *right)
{
    if (left->version != right->version ||
        left->scope != right->scope ||
        left->root_count != right->root_count ||
        left->exclude_count != right->exclude_count ||
        strcmp(left->source_home, right->source_home) != 0)
        return 0;
    for (int index = 0; index < left->root_count; index++)
        if (memcmp(&left->roots[index], &right->roots[index],
                   sizeof(left->roots[index])) != 0)
            return 0;
    for (size_t index = 0; index < left->exclude_count; index++)
        if (strcmp(left->excludes[index], right->excludes[index]) != 0)
            return 0;
    return 1;
}

static SidecarBytes bytes(const char *text)
{
    return (SidecarBytes){
        .data = (const unsigned char *)text,
        .length = strlen(text)
    };
}

static void make_test_base(char base[PATH_MAX])
{
    const char template[] = "/tmp/migr-portable-selection-r3-XXXXXX";
    REQUIRE(sizeof(template) <= PATH_MAX);
    memcpy(base, template, sizeof(template));
    REQUIRE(mkdtemp(base) != NULL);
}

static void make_directory(const char *path)
{
    REQUIRE(mkdir(path, 0700) == 0);
}

static int copy_regular_file(const char *source, const char *destination,
                             mode_t mode)
{
    int source_fd = open(source, O_RDONLY | O_CLOEXEC);
    if (source_fd < 0)
        return -1;
    int destination_fd = open(destination,
                               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                               mode & 0777);
    if (destination_fd < 0) {
        close(source_fd);
        return -1;
    }

    unsigned char buffer[8192];
    int result = 0;
    for (;;) {
        ssize_t received = read(source_fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0) {
            result = -1;
            break;
        }
        if (received == 0)
            break;
        size_t written_total = 0;
        while (written_total < (size_t)received) {
            ssize_t written = write(destination_fd, buffer + written_total,
                                     (size_t)received - written_total);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0) {
                result = -1;
                break;
            }
            written_total += (size_t)written;
        }
        if (result != 0)
            break;
    }
    int source_close = close(source_fd);
    int destination_close = close(destination_fd);
    if (source_close != 0 || destination_close != 0)
        result = -1;
    return result;
}

static int copy_tree(const char *source, const char *destination)
{
    struct stat source_stat;
    if (lstat(source, &source_stat) != 0)
        return -1;
    if (S_ISDIR(source_stat.st_mode)) {
        if (mkdir(destination, source_stat.st_mode & 0777) != 0)
            return -1;
        DIR *directory = opendir(source);
        if (directory == NULL)
            return -1;
        int result = 0;
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(directory);
            if (entry == NULL) {
                if (errno != 0)
                    result = -1;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;
            char source_child[PATH_MAX];
            char destination_child[PATH_MAX];
            if (path_join(source_child, sizeof(source_child), source,
                          entry->d_name) != 0 ||
                path_join(destination_child, sizeof(destination_child),
                          destination, entry->d_name) != 0 ||
                copy_tree(source_child, destination_child) != 0) {
                result = -1;
                break;
            }
        }
        if (closedir(directory) != 0)
            result = -1;
        return result;
    }
    if (S_ISREG(source_stat.st_mode))
        return copy_regular_file(source, destination, source_stat.st_mode);
    if (S_ISLNK(source_stat.st_mode)) {
        char target[PATH_MAX + 1];
        ssize_t length = readlink(source, target, sizeof(target) - 1);
        if (length < 0 || (size_t)length >= sizeof(target) - 1)
            return -1;
        target[length] = '\0';
        return symlink(target, destination);
    }
    return -1;
}

static ssize_t read_retry(int fd, void *buffer, size_t size)
{
    for (;;) {
        ssize_t result = read(fd, buffer, size);
        if (result < 0 && errno == EINTR)
            continue;
        return result;
    }
}

static int regular_files_equal(const char *left, const char *right,
                               off_t size)
{
    int left_fd = open(left, O_RDONLY | O_CLOEXEC);
    int right_fd = open(right, O_RDONLY | O_CLOEXEC);
    if (left_fd < 0 || right_fd < 0) {
        if (left_fd >= 0)
            close(left_fd);
        if (right_fd >= 0)
            close(right_fd);
        return 0;
    }

    unsigned char left_buffer[8192];
    unsigned char right_buffer[8192];
    int result = 1;
    off_t remaining = size;
    while (remaining > 0) {
        size_t request = (remaining > (off_t)sizeof(left_buffer))
            ? sizeof(left_buffer) : (size_t)remaining;
        ssize_t left_count = read_retry(left_fd, left_buffer, request);
        ssize_t right_count = read_retry(right_fd, right_buffer, request);
        if (left_count != (ssize_t)request ||
            right_count != (ssize_t)request ||
            memcmp(left_buffer, right_buffer, request) != 0) {
            result = 0;
            break;
        }
        remaining -= (off_t)request;
    }
    int left_close = close(left_fd);
    int right_close = close(right_fd);
    if (left_close != 0 || right_close != 0)
        result = 0;
    return result;
}

static int trees_equal(const char *left, const char *right)
{
    struct stat left_stat;
    struct stat right_stat;
    if (lstat(left, &left_stat) != 0 || lstat(right, &right_stat) != 0 ||
        (left_stat.st_mode & S_IFMT) != (right_stat.st_mode & S_IFMT))
        return 0;
    if (S_ISREG(left_stat.st_mode))
        return left_stat.st_size == right_stat.st_size &&
               regular_files_equal(left, right, left_stat.st_size);
    if (S_ISLNK(left_stat.st_mode)) {
        char left_target[PATH_MAX + 1];
        char right_target[PATH_MAX + 1];
        ssize_t left_length = readlink(left, left_target,
                                       sizeof(left_target) - 1);
        ssize_t right_length = readlink(right, right_target,
                                        sizeof(right_target) - 1);
        return left_length >= 0 && right_length >= 0 &&
               left_length == right_length &&
               memcmp(left_target, right_target, (size_t)left_length) == 0;
    }
    if (!S_ISDIR(left_stat.st_mode))
        return 0;

    DIR *left_directory = opendir(left);
    DIR *right_directory = opendir(right);
    if (left_directory == NULL || right_directory == NULL) {
        if (left_directory != NULL)
            closedir(left_directory);
        if (right_directory != NULL)
            closedir(right_directory);
        return 0;
    }

    int result = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(left_directory);
        if (entry == NULL) {
            if (errno != 0)
                result = 0;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char left_child[PATH_MAX];
        char right_child[PATH_MAX];
        if (path_join(left_child, sizeof(left_child), left,
                      entry->d_name) != 0 ||
            path_join(right_child, sizeof(right_child), right,
                      entry->d_name) != 0 ||
            !trees_equal(left_child, right_child)) {
            result = 0;
            break;
        }
    }
    if (result) {
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(right_directory);
            if (entry == NULL) {
                if (errno != 0)
                    result = 0;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;
            char left_child[PATH_MAX];
            struct stat left_child_stat;
            if (path_join(left_child, sizeof(left_child), left,
                          entry->d_name) != 0 ||
                lstat(left_child, &left_child_stat) != 0) {
                result = 0;
                break;
            }
        }
    }
    int left_close = closedir(left_directory);
    int right_close = closedir(right_directory);
    if (left_close != 0 || right_close != 0)
        result = 0;
    return result;
}

static void build_test_selection(const char *home, const char *rules,
                                 SelectionPlan *plan)
{
    Config config = {0};
    REQUIRE(config_parse(rules, strlen(rules), "r3-fixture", &config) == 0);
    int result = selection_plan_build(home, BACKUP_CRITICAL, &config, plan);
    config_free(&config);
    REQUIRE(result == 0);
}

static PortableCaptureRequest request_for_selection(
    const SelectionPlan *plan, PortableRootSpec **roots_out)
{
    PortableRootSpec *roots = plan->root_count == 0
        ? NULL : calloc(plan->root_count, sizeof(*roots));
    REQUIRE(plan->root_count == 0 || roots != NULL);
    PortableCaptureRequest request = {
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    REQUIRE(portable_capture_request_set_selection(
                &request, plan, roots, plan->root_count) == 0);
    *roots_out = roots;
    return request;
}

static PortableRootSpec direct_test_root(const char *source)
{
    return (PortableRootSpec){
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "ROOT",
        .source_path = source,
        .restore_path = "",
        .has_restore_path = 1
    };
}

static PortableCaptureRequest direct_test_request(
    const PortableRootSpec *root)
{
    return (PortableCaptureRequest){
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .roots = root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = 1
    };
}

static void annotate_capture_manifest(PortablePreparedCapture *prepared)
{
    prepared->manifest.has_self_binary = 1;
    strcpy(prepared->manifest.arch, "x86_64");
    prepared->manifest.has_network_config = 1;
}

static int entry_missing(int directory_fd, const char *name)
{
    struct stat st;
    errno = 0;
    return fstatat(directory_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
           errno == ENOENT;
}

static void test_prepared_request_mismatch_resume(void)
{
    char base[PATH_MAX];
    char home[PATH_MAX];
    char container[PATH_MAX];
    char snapshot[PATH_MAX];
    make_test_base(base);
    REQUIRE(path_join(home, sizeof(home), base, "home") == 0);
    REQUIRE(path_join(container, sizeof(container), base, "container") == 0);
    REQUIRE(path_join(snapshot, sizeof(snapshot), base, "snapshot") == 0);
    make_directory(home);
    make_directory(container);
    char keep[PATH_MAX];
    char stale[PATH_MAX];
    REQUIRE(path_join(keep, sizeof(keep), home, "keep") == 0);
    REQUIRE(path_join(stale, sizeof(stale), home, "stale") == 0);
    write_file(keep, "keep-before-resume\n");
    write_file(stale, "stale-before-resume\n");

    SelectionPlan plan_a = {0};
    SelectionPlan plan_b = {0};
    build_test_selection(home,
                         "[critical]\n[include]\n~/\n[exclude]\n",
                         &plan_a);
    build_test_selection(home,
                         "[critical]\n[include]\n~/\n[exclude]\nstale\n",
                         &plan_b);
    PortableRootSpec *roots_a = NULL;
    PortableRootSpec *roots_b = NULL;
    PortableCaptureRequest request_a = request_for_selection(&plan_a, &roots_a);
    PortableCaptureRequest request_b = request_for_selection(&plan_b, &roots_b);
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(container_fd >= 0);

    PortablePreparedCapture prepared_a = {0};
    REQUIRE(portable_capture_prepare(container_fd, &request_a,
                                     &prepared_a) == 0);
    REQUIRE(portable_capture_fresh_prepared_at(
                container_fd, &request_a, &prepared_a, NULL, NULL) == 0);
    REQUIRE(copy_tree(container, snapshot) == 0);

    int result = portable_capture_resume_prepared_at(
        container_fd, &request_b, &prepared_a, NULL, NULL);
    int unchanged = trees_equal(container, snapshot);
    printf("R3 mismatched resume: rc=%d, container_unchanged=%d\n",
           result, unchanged);
    CHECK(result != 0);
    CHECK(unchanged);

    portable_prepared_capture_free(&prepared_a);
    REQUIRE(close(container_fd) == 0);
    free(roots_a);
    free(roots_b);
    selection_plan_free(&plan_a);
    selection_plan_free(&plan_b);
    REQUIRE(nftw(base, remove_entry, 32, FTW_DEPTH | FTW_PHYS) == 0);
}

static void test_prepared_request_mismatch_fresh(void)
{
    char base[PATH_MAX];
    char home[PATH_MAX];
    char container[PATH_MAX];
    char snapshot[PATH_MAX];
    make_test_base(base);
    REQUIRE(path_join(home, sizeof(home), base, "home") == 0);
    REQUIRE(path_join(container, sizeof(container), base, "container") == 0);
    REQUIRE(path_join(snapshot, sizeof(snapshot), base, "snapshot") == 0);
    make_directory(home);
    make_directory(container);
    char stale[PATH_MAX];
    REQUIRE(path_join(stale, sizeof(stale), home, "stale") == 0);
    write_file(stale, "stale-before-fresh\n");

    SelectionPlan plan_a = {0};
    SelectionPlan plan_b = {0};
    build_test_selection(home,
                         "[critical]\n[include]\n~/\n[exclude]\n",
                         &plan_a);
    build_test_selection(home,
                         "[critical]\n[include]\n~/\n[exclude]\nstale\n",
                         &plan_b);
    PortableRootSpec *roots_a = NULL;
    PortableRootSpec *roots_b = NULL;
    PortableCaptureRequest request_a = request_for_selection(&plan_a, &roots_a);
    PortableCaptureRequest request_b = request_for_selection(&plan_b, &roots_b);
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(container_fd >= 0);

    PortablePreparedCapture prepared_a = {0};
    PortablePreparedCapture prepared_b = {0};
    REQUIRE(portable_capture_prepare(container_fd, &request_a,
                                     &prepared_a) == 0);
    REQUIRE(portable_capture_prepare(container_fd, &request_b,
                                     &prepared_b) == 0);
    REQUIRE(copy_tree(container, snapshot) == 0);

    int result = portable_capture_fresh_prepared_at(
        container_fd, &request_b, &prepared_a, NULL, NULL);
    int unchanged = trees_equal(container, snapshot);
    printf("R3 mismatched fresh: rc=%d, container_unchanged=%d, "
           "manifest_absent=%d, data_absent=%d\n",
           result, unchanged, entry_missing(container_fd, "manifest.txt"),
           entry_missing(container_fd, "data"));
    CHECK(result != 0);
    CHECK(unchanged);
    CHECK(entry_missing(container_fd, "manifest.txt"));
    CHECK(entry_missing(container_fd, "data"));

    portable_prepared_capture_free(&prepared_a);
    portable_prepared_capture_free(&prepared_b);
    REQUIRE(close(container_fd) == 0);
    free(roots_a);
    free(roots_b);
    selection_plan_free(&plan_a);
    selection_plan_free(&plan_b);
    REQUIRE(nftw(base, remove_entry, 32, FTW_DEPTH | FTW_PHYS) == 0);
}

static void test_equivalent_selection_objects_are_accepted(void)
{
    char base[PATH_MAX];
    char home[PATH_MAX];
    char container[PATH_MAX];
    make_test_base(base);
    REQUIRE(path_join(home, sizeof(home), base, "home") == 0);
    REQUIRE(path_join(container, sizeof(container), base, "container") == 0);
    make_directory(home);
    make_directory(container);
    char file[PATH_MAX];
    REQUIRE(path_join(file, sizeof(file), home, "file") == 0);
    write_file(file, "equivalent-selection\n");

    SelectionPlan plan_a = {0};
    SelectionPlan plan_b = {0};
    build_test_selection(home, "[critical]\n[include]\n~/\n", &plan_a);
    build_test_selection(home,
                         "[critical]\n[include]\n~/\n~/\n", &plan_b);
    PortableRootSpec *roots_a = NULL;
    PortableRootSpec *roots_b = NULL;
    PortableCaptureRequest request_a = request_for_selection(&plan_a, &roots_a);
    PortableCaptureRequest request_b = request_for_selection(&plan_b, &roots_b);
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(container_fd >= 0);

    PortablePreparedCapture prepared_a = {0};
    REQUIRE(portable_capture_prepare(container_fd, &request_a,
                                     &prepared_a) == 0);
    REQUIRE(portable_capture_fresh_prepared_at(
                container_fd, &request_a, &prepared_a, NULL, NULL) == 0);
    int result = portable_capture_resume_prepared_at(
        container_fd, &request_b, &prepared_a, NULL, NULL);
    printf("R3 equivalent selections: resume_rc=%d\n", result);
    CHECK(result == 0);
    portable_prepared_capture_free(&prepared_a);

    REQUIRE(close(container_fd) == 0);
    free(roots_a);
    free(roots_b);
    selection_plan_free(&plan_a);
    selection_plan_free(&plan_b);
    REQUIRE(nftw(base, remove_entry, 32, FTW_DEPTH | FTW_PHYS) == 0);
}

static void test_annotation_fields_do_not_break_binding(void)
{
    char base[PATH_MAX];
    char source[PATH_MAX];
    char source_file[PATH_MAX];
    char container[PATH_MAX];
    make_test_base(base);
    REQUIRE(path_join(source, sizeof(source), base, "source") == 0);
    REQUIRE(path_join(source_file, sizeof(source_file), source, "file") == 0);
    REQUIRE(path_join(container, sizeof(container), base, "container") == 0);
    make_directory(source);
    make_directory(container);
    write_file(source_file, "annotation-before\n");

    PortableRootSpec root = direct_test_root(source);
    PortableCaptureRequest request = direct_test_request(&root);
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(container_fd >= 0);

    PortablePreparedCapture prepared = {0};
    REQUIRE(portable_capture_prepare(container_fd, &request, &prepared) == 0);
    annotate_capture_manifest(&prepared);
    CHECK(prepared.request_identity.has_self_binary == 0 &&
          prepared.request_identity.has_network_config == 0);
    int fresh_result = portable_capture_fresh_prepared_at(
        container_fd, &request, &prepared, NULL, NULL);

    int resume_result = -1;
    int has_self_binary = 0;
    int has_network_config = 0;
    if (fresh_result == 0) {
        write_file(source_file, "annotation-after\n");
        PortablePreparedCapture resumed = {0};
        if (portable_capture_prepare(container_fd, &request, &resumed) == 0) {
            annotate_capture_manifest(&resumed);
            resume_result = portable_capture_resume_prepared_at(
                container_fd, &request, &resumed, NULL, NULL);
            portable_prepared_capture_free(&resumed);
        }
        Manifest existing = {0};
        if (manifest_read_v1_at(container_fd, &existing) ==
            MANIFEST_STATUS_VALID) {
            has_self_binary = existing.has_self_binary;
            has_network_config = existing.has_network_config;
        }
        manifest_free(&existing);
    }
    printf("R3 annotation control: fresh_rc=%d, resume_rc=%d, self=%d, "
           "network=%d\n", fresh_result, resume_result, has_self_binary,
           has_network_config);
    CHECK(fresh_result == 0);
    CHECK(resume_result == 0);
    CHECK(has_self_binary == 1 && has_network_config == 1);

    portable_prepared_capture_free(&prepared);
    REQUIRE(close(container_fd) == 0);
    REQUIRE(nftw(base, remove_entry, 32, FTW_DEPTH | FTW_PHYS) == 0);
}

int main(void)
{
    test_prepared_request_mismatch_resume();
    test_prepared_request_mismatch_fresh();
    test_equivalent_selection_objects_are_accepted();
    test_annotation_fields_do_not_break_binding();

    char temp[] = "/tmp/migr-portable-selection-XXXXXX";
    REQUIRE(mkdtemp(temp) != NULL);
    REQUIRE(chdir(temp) == 0);
    REQUIRE(mkdir("home", 0700) == 0);
    REQUIRE(mkdir("native-data", 0700) == 0);
    REQUIRE(mkdir("portable", 0700) == 0);
    REQUIRE(chdir("home") == 0);
    char *home = getcwd(NULL, 0);
    REQUIRE(home != NULL);

    REQUIRE(mkdir(".config", 0700) == 0);
    write_file(".config/user-dirs.dirs",
               "XDG_DOCUMENTS_DIR=\"$HOME/Belgeler\"\n");
    REQUIRE(mkdir("Belgeler", 0700) == 0);
    REQUIRE(mkdir("omit", 0700) == 0);
    write_file("keep", "shared-data\n");
    REQUIRE(link("keep", "Belgeler/alias") == 0);
    write_file("Belgeler/doc", "document\n");
    write_file("stale", "remove-on-resume\n");
    REQUIRE(mkfifo("omit/unsupported", 0600) == 0);

    Config config = {0};
    const char *rules =
        "[critical]\n[include]\n~/\n[exclude]\nomit\n";
    REQUIRE(config_parse(rules, strlen(rules), "fixture", &config) == 0);
    SelectionPlan plan = {0};
    REQUIRE(selection_plan_build(home, BACKUP_CRITICAL, &config, &plan) == 0);
    config_free(&config);
    REQUIRE(chmod("omit", 0000) == 0);

    char documents[PATH_MAX];
    REQUIRE(path_join(documents, sizeof(documents), home, "Belgeler") == 0);
    size_t parent = find_root(&plan, home);
    size_t child = find_root(&plan, documents);
    CHECK(plan.roots[child].parent == (int)parent);
    CHECK(selection_root_owns(&plan.roots[parent], "Belgeler") == 0);
    CHECK(selection_root_owns(&plan.roots[parent], "omit") == 0);

    Manifest native_manifest = {0};
    REQUIRE(selection_plan_manifest(&plan, &native_manifest) == 0);
    CHECK(native_manifest.version == MANIFEST_SELECTION_VERSION);

    PortableRootSpec *roots = calloc(plan.root_count, sizeof(*roots));
    REQUIRE(roots != NULL);
    PortableCaptureRequest request = {
        .has_source_identity = 1,
        .machine_id = "0123456789abcdef",
        .source_uid = getuid(),
        .nsec_exact = 1,
        .case_sensitive = 1
    };
    REQUIRE(portable_capture_request_set_selection(
                &request, &plan, roots, plan.root_count) == 0);

    REQUIRE(chdir("..") == 0);
    int portable_fd = open("portable", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int native_fd = open("native-data", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(portable_fd >= 0 && native_fd >= 0);

    PortablePreparedCapture prepared = {0};
    REQUIRE(portable_capture_prepare(portable_fd, &request, &prepared) == 0);
    CHECK(prepared.manifest.representation == CLONE_PORTABLE_SIDECAR);
    CHECK(prepared.manifest.sidecar_version == SIDECAR_VERSION);
    CHECK(roots_equal(&native_manifest, &prepared.manifest));

    MetadataProfiles profiles;
    metadata_profiles_init(&profiles);
    REQUIRE(backup_selection_inventory(&plan, native_fd, -1, &profiles) == 0);
    REQUIRE(metadata_profiles_probe(
                &profiles,
                (MetadataTimestampPolicy){.configured = 1, .nsec_exact = 1}) == 0);
    metadata_profiles_free(&profiles);
    CloneContext native_context = {
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .metadata_preflight_done = 1,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1
    };
    BackupCaptureReport native_report;
    backup_capture_report_init(&native_report);
    REQUIRE(backup_selection_capture(&native_context, &plan, native_fd,
                                     &native_report) == BACKUP_CAPTURE_OK);

    size_t live_count = 0;
    REQUIRE(portable_capture_fresh_prepared_at(
                portable_fd, &request, &prepared, &live_count, NULL) == 0);
    CHECK(live_count > 0);
    portable_prepared_capture_free(&prepared);

    int portable_data = openat(portable_fd, "data",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(portable_data >= 0);
    const char *parent_id = plan.roots[parent].root.manifest_root.payload_path;
    const char *child_id = plan.roots[child].root.manifest_root.payload_path;
    struct stat native_keep, native_alias;
    CHECK(entry_exists(native_fd, parent_id, "keep", &native_keep));
    CHECK(entry_exists(native_fd, child_id, "alias", &native_alias));
    CHECK(native_keep.st_dev == native_alias.st_dev &&
          native_keep.st_ino == native_alias.st_ino);
    CHECK(!entry_exists(native_fd, parent_id, "Belgeler", NULL));
    CHECK(!entry_exists(native_fd, parent_id, "omit", NULL));
    CHECK(entry_exists(native_fd, child_id, "doc", NULL));
    CHECK(entry_exists(portable_data, parent_id, "keep", NULL));
    CHECK(!entry_exists(portable_data, parent_id, "Belgeler", NULL));
    CHECK(!entry_exists(portable_data, parent_id, "omit", NULL));
    CHECK(entry_exists(portable_data, child_id, "doc", NULL));

    SidecarLog sidecar = {0};
    REQUIRE(sidecar_log_adopt_at(portable_fd, &sidecar) ==
            SIDECAR_OPEN_RESUMABLE);
    SidecarLiveView alias = {0};
    CHECK(sidecar_log_find(&sidecar, bytes(plan.roots[child].root.manifest_root.id),
                           bytes("alias"), &alias) == 1);
    if (alias.entry != NULL) {
        CHECK(alias.entry->kind == SIDECAR_KIND_HARDLINK);
        CHECK(alias.entry->hardlink_root_id.length == strlen(
                  plan.roots[parent].root.manifest_root.id) &&
              memcmp(alias.entry->hardlink_root_id.data,
                     plan.roots[parent].root.manifest_root.id,
                     alias.entry->hardlink_root_id.length) == 0);
        CHECK(alias.entry->hardlink_logical_path.length == strlen("keep") &&
              memcmp(alias.entry->hardlink_logical_path.data, "keep",
                     strlen("keep")) == 0);
    }
    REQUIRE(sidecar_log_close(&sidecar) == SIDECAR_STATUS_OK);

    REQUIRE(chdir("home") == 0);
    REQUIRE(unlink("stale") == 0);
    REQUIRE(chmod("omit", 0700) == 0);
    REQUIRE(mkfifo("omit/new-unsupported", 0600) == 0);
    REQUIRE(chmod("omit", 0000) == 0);
    REQUIRE(chdir("..") == 0);
    PortablePreparedCapture resumed = {0};
    CHECK(portable_capture_prepare(portable_fd, &request, &resumed) == 0);
    Manifest existing = {0};
    CHECK(manifest_read_v1_at(portable_fd, &existing) == MANIFEST_STATUS_VALID);
    CHECK(manifest_resume_identity_compare(&existing, &resumed.manifest) ==
          MANIFEST_IDENTITY_EQUAL);
    CHECK(portable_capture_resume_prepared_at(
              portable_fd, &request, &resumed, NULL, NULL) == 0);
    manifest_free(&existing);
    portable_prepared_capture_free(&resumed);
    CHECK(!entry_exists(portable_data, parent_id, "stale", NULL));
    CHECK(!entry_exists(portable_data, parent_id, "omit", NULL));

    REQUIRE(close(portable_data) == 0);
    REQUIRE(close(native_fd) == 0);
    REQUIRE(close(portable_fd) == 0);
    manifest_free(&native_manifest);
    free(roots);
    REQUIRE(chmod("home/omit", 0700) == 0);
    selection_plan_free(&plan);
    free(home);
    REQUIRE(chdir("/") == 0);
    REQUIRE(nftw(temp, remove_entry, 32, FTW_DEPTH | FTW_PHYS) == 0);
    printf("portable selection: %d failures\n", failures);
    return failures ? 1 : 0;
}
