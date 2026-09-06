#define _GNU_SOURCE
#include "config.h"
#include "metadata.h"
#include "portable.h"
#include "selection.h"
#include "sidecar.h"
#include "utils.h"

#include <fcntl.h>
#include <ftw.h>
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

int main(void)
{
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
