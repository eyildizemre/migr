#define _GNU_SOURCE
#include "selection.h"
#include "metadata.h"
#include "report.h"
#include "utils.h"
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
static int failure_triggered;
static void remove_child_before_open(const char *path, void *context)
{
    if (strcmp(path, context) != 0) return;
    if (unlink("Documents/alias") == 0 && rmdir("Documents") == 0)
        failure_triggered = 1;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); failures++; } } while (0)
#define REQUIRE(x) do { if (!(x)) { perror(#x); exit(1); } } while (0)

static void file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    REQUIRE(f != NULL);
    REQUIRE(fputs(text, f) >= 0);
    REQUIRE(fclose(f) == 0);
}
static int remove_entry(const char *p, const struct stat *st, int type, struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(p);
}
static size_t root_index(const SelectionPlan *plan, const char *path)
{
    for (size_t i = 0; i < plan->root_count; i++)
        if (!strcmp(plan->roots[i].root.capture_path, path)) return i;
    fprintf(stderr, "Missing root: %s\n", path);
    exit(1);
}
static void payload(char out[PATH_MAX], const SelectionPlan *plan, size_t i, const char *rel)
{
    REQUIRE(path_join(out, PATH_MAX, plan->roots[i].root.manifest_root.payload_path, rel) == 0);
}
static off_t size(const char *path)
{
    struct stat st;
    REQUIRE(lstat(path, &st) == 0);
    return st.st_size;
}
static char *read_report(const SelectionPlan *plan, int summary)
{
    REQUIRE(fflush(stdout) == 0);
    int saved = dup(STDOUT_FILENO);
    FILE *out = tmpfile();
    REQUIRE(saved >= 0 && out != NULL);
    REQUIRE(dup2(fileno(out), STDOUT_FILENO) >= 0);
    CHECK(report_selection(plan, summary, (ReportDepth){0}) == 0);
    REQUIRE(fflush(stdout) == 0);
    REQUIRE(dup2(saved, STDOUT_FILENO) >= 0);
    REQUIRE(close(saved) == 0);
    REQUIRE(fseek(out, 0, SEEK_END) == 0);
    long length = ftell(out);
    REQUIRE(length >= 0);
    rewind(out);
    char *text = calloc((size_t)length + 1, 1);
    REQUIRE(text != NULL);
    REQUIRE(fread(text, 1, (size_t)length, out) == (size_t)length);
    REQUIRE(fclose(out) == 0);
    return text;
}
int main(void)
{
    char temp[] = "/tmp/migr-native-selection-XXXXXX";
    REQUIRE(mkdtemp(temp) != NULL);
    REQUIRE(chdir(temp) == 0);
    REQUIRE(mkdir("home", 0700) == 0 && mkdir("data", 0700) == 0);
    int data = open("data", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(data >= 0 && chdir("home") == 0);
    char *home = getcwd(NULL, 0);
    REQUIRE(home != NULL);
    REQUIRE(mkdir("Documents", 0700) == 0);
    REQUIRE(mkdir("omit", 0700) == 0);
    file("keep", "shared content\n");
    REQUIRE(link("keep", "Documents/alias") == 0);
    REQUIRE(link("keep", "omit/large") == 0);
    REQUIRE(symlink("omit/large", "pointer") == 0);
    Config config = {0};
    const char *text = "[critical]\n[include]\n~/\n[exclude]\nomit\n";
    REQUIRE(config_parse(text, strlen(text), "fixture", &config) == 0);
    SelectionPlan plan = {0};
    REQUIRE(selection_plan_build(home, BACKUP_CRITICAL, &config, &plan) == 0);
    config_free(&config);
    REQUIRE(plan.root_count == 2);
    size_t parent = root_index(&plan, home);
    char docs[PATH_MAX];
    REQUIRE(path_join(docs, sizeof(docs), home, "Documents") == 0);
    size_t child = root_index(&plan, docs);
    CHECK(plan.roots[child].parent == (int)parent);
    CHECK(selection_source_owns(&plan.roots[parent], docs) == 0);
    CHECK(selection_source_owns(&plan.roots[parent], "/outside") == -1);
    REQUIRE(chmod("omit", 0000) == 0);

    off_t expected = size(".") + size("Documents") + size("keep") + size("pointer");
    off_t total = 0;
    int error = 0;
    selection_plan_estimate_size(&plan, 1, &total, &error);
    CHECK(!error && total == expected);
    selection_plan_estimate_size(&plan, 4096, &total, &error);
    CHECK(!error && total == expected - size("keep") + 4096);
    char expected_report[64];
    format_size(expected + size("keep"), expected_report, sizeof(expected_report));
    char *output = read_report(&plan, 1);
    CHECK(!strncmp(output, expected_report, strlen(expected_report)));
    free(output);
    verbose = 1;
    output = read_report(&plan, 0);
    CHECK(strstr(output, "omit") == NULL);
    CHECK(strstr(output, "Documents") != NULL);
    free(output);
    verbose = 0;

    MetadataProfiles profiles;
    metadata_profiles_init(&profiles);
    CHECK(backup_selection_inventory(&plan, data, -1, &profiles) == 0);
    CHECK(metadata_profiles_probe(&profiles, (MetadataTimestampPolicy){.configured=1, .nsec_exact=1}) == 0);
    metadata_profiles_free(&profiles);
    CloneContext ctx = {.operation=CLONE_BACKUP, .representation=CLONE_NATIVE_TREE,
                        .metadata_preflight_done=1, .timestamp_policy_configured=1, .nsec_exact=1};
    BackupCaptureReport report;
    backup_capture_report_init(&report);
    CHECK(backup_selection_capture(&ctx, &plan, data, &report) == BACKUP_CAPTURE_OK);
    char p[PATH_MAX], q[PATH_MAX];
    struct stat a, b;
    payload(p, &plan, parent, "Documents");
    CHECK(fstatat(data, p, &a, AT_SYMLINK_NOFOLLOW) < 0);
    payload(p, &plan, parent, "omit");
    CHECK(fstatat(data, p, &a, AT_SYMLINK_NOFOLLOW) < 0);
    payload(p, &plan, parent, "keep");
    payload(q, &plan, child, "alias");
    REQUIRE(fstatat(data, p, &a, 0) == 0 && fstatat(data, q, &b, 0) == 0);
    CHECK(a.st_ino == b.st_ino && a.st_dev == b.st_dev);
    ino_t original = a.st_ino;
    payload(q, &plan, parent, "pointer");
    CHECK(fstatat(data, q, &a, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(a.st_mode));

    /* An old excluded representative must not seed the retained hardlink group. */
    payload(q, &plan, parent, "omit");
    REQUIRE(mkdirat(data, q, 0700) == 0);
    payload(q, &plan, parent, "omit/large");
    int old = openat(data, q, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(old >= 0);
    REQUIRE(write(old, "shared content\n", 15) == 15);
    REQUIRE(stat("keep", &a) == 0);
    struct timespec completed[2] = {a.st_atim, a.st_mtim};
    REQUIRE(futimens(old, completed) == 0 && close(old) == 0);
    payload(q, &plan, parent, "Documents");
    REQUIRE(mkdirat(data, q, 0700) == 0);
    payload(q, &plan, parent, "stale");
    old = openat(data, q, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(old >= 0 && close(old) == 0);
    struct timespec times[2] = {{123456789, 12345}, {123456790, 54321}};
    REQUIRE(utimensat(AT_FDCWD, ".", times, 0) == 0);
    REQUIRE(utimensat(AT_FDCWD, "Documents", times, 0) == 0);
    CHECK(backup_selection_capture(&ctx, &plan, data, &report) == BACKUP_CAPTURE_OK);
    CHECK(fstatat(data, q, &a, 0) < 0);
    payload(q, &plan, parent, "omit");
    CHECK(fstatat(data, q, &a, 0) < 0);
    payload(q, &plan, parent, "Documents");
    CHECK(fstatat(data, q, &a, 0) < 0);
    CHECK(fstatat(data, p, &a, 0) == 0 && a.st_ino == original);
    REQUIRE(stat(".", &b) == 0);
    CHECK(b.st_atim.tv_sec == times[0].tv_sec && b.st_atim.tv_nsec == times[0].tv_nsec);
    CHECK(b.st_mtim.tv_sec == times[1].tv_sec && b.st_mtim.tv_nsec == times[1].tv_nsec);
    REQUIRE(fstatat(data, plan.roots[parent].root.manifest_root.payload_path, &a, 0) == 0);
    CHECK(a.st_mtim.tv_sec == times[1].tv_sec && a.st_mtim.tv_nsec == times[1].tv_nsec);
    CHECK(a.st_atim.tv_sec == times[0].tv_sec && a.st_atim.tv_nsec == times[0].tv_nsec);

    /* A later source failure leaves stale payload intact for a safe retry. */
    payload(q, &plan, parent, "stale");
    old = openat(data, q, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(old >= 0 && close(old) == 0);
    backup_test_set_capture_hook(remove_child_before_open, docs);
    CHECK(backup_selection_capture(&ctx, &plan, data, &report) != BACKUP_CAPTURE_OK);
    backup_test_set_capture_hook(NULL, NULL);
    CHECK(failure_triggered);
    CHECK(fstatat(data, q, &a, 0) == 0);
    ctx.operation = CLONE_RESTORE;
    CHECK(backup_selection_capture(&ctx, &plan, data, &report) == BACKUP_CAPTURE_ERROR);
    CHECK(fstatat(data, q, &a, 0) == 0);
    REQUIRE(chmod("omit", 0700) == 0);
    selection_plan_free(&plan);
    free(home);
    REQUIRE(close(data) == 0 && chdir("/") == 0);
    REQUIRE(nftw(temp, remove_entry, 32, FTW_DEPTH | FTW_PHYS) == 0);
    printf("native selection: %d failures\n", failures);
    return failures ? 1 : 0;
}
