#define _GNU_SOURCE
#include "selection.h"
#include "container.h"
#include "restore.h"
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
static void write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    CHECK(fputs(text, f) >= 0);
    CHECK(fclose(f) == 0);
}
static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st; (void)type; (void)ftw;
    return remove(path);
}
static void identity(Manifest *m)
{
    m->has_source_identity = 1;
    strcpy(m->machine_id, "0123456789abcdef0123456789abcdef");
    m->source_uid = getuid();
}
static int compile(const char *home, BackupMode mode, const char *rules, Manifest *out)
{
    Config config = {0};
    SelectionPlan plan = {0};
    int rc = config_parse(rules, strlen(rules), "fixture", &config);
    if (!rc) rc = selection_plan_build(home, mode, &config, &plan);
    if (!rc) rc = selection_plan_manifest(&plan, out);
    selection_plan_free(&plan);
    config_free(&config);
    if (!rc) identity(out);
    return rc;
}
static void malformed(const char *good, const char *from, const char *to, ManifestStatus status)
{
    const char *at = strstr(good, from);
    CHECK(at != NULL);
    if (!at) return;
    char *text = NULL;
    CHECK(asprintf(&text, "%.*s%s%s", (int)(at - good), good, to, at + strlen(from)) >= 0);
    if (!text) return;
    write_text("backup/manifest.txt", text);
    free(text);
    Manifest read = {0};
    CHECK(manifest_read_v1("backup", &read) == status);
    CHECK(read.roots == NULL && read.excludes == NULL);
    manifest_free(&read);
}
int main(void)
{
    char base[] = "/tmp/migr-policy-XXXXXX";
    CHECK(mkdtemp(base) != NULL);
    CHECK(chdir(base) == 0);
    CHECK(mkdir("home", 0700) == 0);
    CHECK(mkdir("home/Documents", 0700) == 0);
    CHECK(mkdir("backup", 0700) == 0);
    CHECK(mkdir("partials", 0700) == 0);
    char *home = realpath("home", NULL);
    CHECK(home != NULL);
    Manifest plain = {0}, empty = {0}, m = {0}, same = {0}, changed = {0};
    CHECK(compile(home, BACKUP_CRITICAL, "", &plain) == 0);
    CHECK(compile(home, BACKUP_CRITICAL, "# empty\n[critical]\n[include]\n", &empty) == 0);
    CHECK(plain.version == 1 && manifest_resume_identity_compare(&plain, &empty) == MANIFEST_IDENTITY_EQUAL);
    manifest_free(&empty);
    const char *rules = "[critical]\n[include]\n~/\n[exclude]\nDocuments/skip\n\"future\\npath\"\n";
    CHECK(compile(home, BACKUP_CRITICAL, rules, &m) == 0 && m.version == 2);
    CHECK(compile(home, BACKUP_CRITICAL, "[critical]\n[include]\nDocuments\n~/\n~/\n[exclude]\n\"future\\npath\"\nDocuments/skip/sub\nDocuments/skip\n", &same) == 0);
    CHECK(manifest_resume_identity_compare(&m, &same) == MANIFEST_IDENTITY_EQUAL);
    CHECK(compile(home, BACKUP_CRITICAL, "[critical]\n[include]\n~/\n[exclude]\nDocuments/other\n", &changed) == 0);
    CHECK(m.root_count == changed.root_count);
    CHECK(manifest_resume_identity_compare(&m, &changed) == MANIFEST_IDENTITY_DIFFERENT);
    CHECK(m.root_count == 2);
    if (m.root_count == 2)
    {
        CHECK(manifest_entry_owned(&m, 0, "Documents") == 0);
        CHECK(manifest_entry_owned(&m, 0, "Documents/file") == 0);
        CHECK(manifest_entry_owned(&m, 1, "") == 1);
        CHECK(manifest_entry_owned(&m, 1, "skip/file") == 0);
        CHECK(manifest_entry_owned(&m, 1, "skip-old/file") == 1);
        CHECK(manifest_entry_owned(&m, 1, "../escape") < 0);
    }
    BackupContainer reserved = {0}, adopted = {0};
    CHECK(container_reserve("partials", 1700000000, &reserved) == CONTAINER_OK);
    CHECK(manifest_write_v1_at(reserved.partial_fd, &m) == 0);
    struct stat before, after;
    CHECK(fstat(reserved.partial_fd, &before) == 0);
    container_close(&reserved);
    CHECK(container_adopt("partials", &changed, &adopted) == CONTAINER_ERR_NO_MATCH);
    CHECK(container_adopt("partials", &same, &adopted) == CONTAINER_OK);
    CHECK(fstat(adopted.partial_fd, &after) == 0 && before.st_ino == after.st_ino);
    container_close(&adopted);
    CHECK(mkdir("home/Extra", 0700) == 0);
    Manifest scope_a = {0}, scope_b = {0};
    CHECK(compile(home, BACKUP_CRITICAL, "[comprehensive]\n[include]\nExtra\n[exclude]\nDocuments\n", &scope_a) == 0);
    CHECK(manifest_resume_identity_compare(&plain, &scope_a) == MANIFEST_IDENTITY_EQUAL);
    manifest_free(&scope_a);
    CHECK(compile(home, BACKUP_COMPREHENSIVE, "", &scope_a) == 0);
    CHECK(compile(home, BACKUP_COMPREHENSIVE, "[critical]\n[exclude]\nDocuments\n", &scope_b) == 0);
    CHECK(manifest_resume_identity_compare(&scope_a, &scope_b) == MANIFEST_IDENTITY_EQUAL);
    manifest_free(&scope_b);
    CHECK(compile(home, BACKUP_COMPREHENSIVE, "[critical]\n[include]\nExtra\n", &scope_b) == 0);
    CHECK(manifest_resume_identity_compare(&scope_a, &scope_b) == MANIFEST_IDENTITY_DIFFERENT);
    manifest_free(&scope_a); manifest_free(&scope_b);
    CHECK(rmdir("home/Extra") == 0);
    /* Source addressing is data: reading and ownership checks do not need HOME. */
    CHECK(rmdir("home/Documents") == 0 && rmdir("home") == 0);
    for (int portable = 0; portable < 2; portable++)
    {
        m.representation = portable ? CLONE_PORTABLE_SIDECAR : CLONE_NATIVE_TREE;
        CHECK(manifest_write_v1("backup", &m) == 0);
        Manifest read = {0};
        CHECK(manifest_read_v1("backup", &read) == MANIFEST_STATUS_VALID);
        CHECK(manifest_resume_identity_compare(&m, &read) == MANIFEST_IDENTITY_EQUAL);
        CHECK(manifest_entry_owned(&read, 1, "skip") == 0);
        int fd = open("backup", O_RDONLY | O_DIRECTORY);
        CHECK(fd >= 0);
        manifest_free(&read);
        CHECK(manifest_read_v1_at(fd, &read) == MANIFEST_STATUS_VALID);
        CHECK(close(fd) == 0);
        manifest_free(&read);
    }
    FILE *f = fopen("backup/manifest.txt", "r");
    CHECK(f != NULL);
    char good[32768] = {0};
    if (f) { CHECK(fread(good, 1, sizeof(good) - 1, f) > 0); CHECK(fclose(f) == 0); }
    CHECK(strstr(good, "SOURCE_HOME=") != NULL && strstr(good, "EXCLUDE_COUNT=2\n") != NULL);
    malformed(good, "VERSION=2", "VERSION=9", MANIFEST_STATUS_UNKNOWN_VERSION);
    malformed(good, "SOURCE_HOME=", "SOURCE_HOME_BAD=", MANIFEST_STATUS_MALFORMED);
    malformed(good, "EXCLUDE_COUNT=2", "EXCLUDE_COUNT=4097", MANIFEST_STATUS_MALFORMED);
    malformed(good, "EXCLUDE_COUNT=2", "EXCLUDE_COUNT=1", MANIFEST_STATUS_MALFORMED);
    malformed(good, "EXCLUDE PATH=", "EXCLUDE OTHER=", MANIFEST_STATUS_MALFORMED);
    malformed(good, "EXCLUDE PATH=", "EXCLUDE PATH=%00", MANIFEST_STATUS_MALFORMED);
    malformed(good, "ROOT_COUNT=2", "ROOT_COUNT=0", MANIFEST_STATUS_MALFORMED);
    malformed(good, "SOURCE=", "SOURCE=../escape", MANIFEST_STATUS_MALFORMED);
    write_text("backup/manifest.txt", good);
    char *saved = m.excludes[1];
    m.excludes[1] = m.excludes[0];
    CHECK(manifest_write_v1("backup", &m) != 0);
    m.excludes[1] = saved;
    char payload[PATH_MAX];
    strcpy(payload, m.roots[1].payload_path);
    strcpy(m.roots[1].payload_path, m.roots[0].payload_path);
    CHECK(manifest_write_v1("backup", &m) != 0);
    strcpy(m.roots[1].payload_path, payload);
    Manifest intact = {0};
    CHECK(manifest_read_v1("backup", &intact) == MANIFEST_STATUS_VALID);
    CHECK(manifest_resume_identity_compare(&m, &intact) == MANIFEST_IDENTITY_EQUAL);
    manifest_free(&intact);
    FILE *diagnostic = tmpfile();
    int saved_stderr = dup(STDERR_FILENO);
    CHECK(diagnostic != NULL && saved_stderr >= 0);
    if (!diagnostic || saved_stderr < 0) exit(1);
    CHECK(fflush(stderr) == 0);
    CHECK(dup2(fileno(diagnostic), STDERR_FILENO) >= 0);
    dry_run = 1;
    CHECK(restore("backup") != 0);
    dry_run = 0;
    CHECK(fflush(stderr) == 0);
    CHECK(dup2(saved_stderr, STDERR_FILENO) >= 0);
    CHECK(close(saved_stderr) == 0);
    CHECK(fseek(diagnostic, 0, SEEK_SET) == 0);
    char message[1024] = {0};
    CHECK(fread(message, 1, sizeof(message) - 1, diagnostic) > 0);
    CHECK(strstr(message, "cannot replay filtered backup selections") != NULL);
    CHECK(fclose(diagnostic) == 0);
    /* Policy comparison precedes the zero-root fast path. */
    manifest_free(&m); manifest_free(&same); manifest_free(&changed);
    CHECK(mkdir("home", 0700) == 0);
    CHECK(compile(home, BACKUP_CRITICAL, "[critical]\n[exclude]\n~/\n", &m) == 0);
    CHECK(compile(home, BACKUP_CRITICAL, "[critical]\n[exclude]\n/\n", &changed) == 0);
    CHECK(m.root_count == 0 && changed.root_count == 0);
    CHECK(manifest_resume_identity_compare(&m, &changed) == MANIFEST_IDENTITY_DIFFERENT);
    CHECK(manifest_write_v1("backup", &m) == 0);
    CHECK(manifest_read_v1("backup", &same) == MANIFEST_STATUS_VALID);
    CHECK(manifest_resume_identity_compare(&m, &same) == MANIFEST_IDENTITY_EQUAL);
    manifest_free(&plain); manifest_free(&m); manifest_free(&same); manifest_free(&changed);
    CHECK(mkdir("external", 0700) == 0);
    CHECK(mkdir("external/google-chrome", 0700) == 0);
    CHECK(symlink("../external", "home/.config") == 0);
    CHECK(compile(home, BACKUP_CRITICAL, "[critical]\n[include]\n../external\n", &m) == 0);
    CHECK(m.version == 2 && m.root_count == 2);
    if (m.root_count == 2)
    {
        CHECK(m.roots[1].policy == ROOT_POLICY_HOME_RELATIVE && m.roots[1].source_path[0] == '/');
        CHECK(!strcmp(m.roots[1].restore_path, ".config/google-chrome"));
    }
    CHECK(manifest_write_v1("backup", &m) == 0);
    CHECK(manifest_read_v1("backup", &same) == MANIFEST_STATUS_VALID);
    CHECK(manifest_resume_identity_compare(&m, &same) == MANIFEST_IDENTITY_EQUAL);
    manifest_free(&m); manifest_free(&same);
    m = (Manifest){.version = MANIFEST_SELECTION_VERSION, .scope = MANIFEST_SCOPE_CRITICAL,
                   .representation = CLONE_NATIVE_TREE, .exclude_count = MANIFEST_MAX_EXCLUDES};
    strcpy(m.source_home, "/missing-source-home");
    identity(&m);
    m.excludes = calloc(m.exclude_count, sizeof(*m.excludes));
    CHECK(m.excludes != NULL);
    if (!m.excludes) exit(1);
    for (size_t i = 0; i < m.exclude_count; i++)
        CHECK(asprintf(&m.excludes[i], "/excluded-%04zu", i) >= 0);
    CHECK(manifest_write_v1("backup", &m) == 0);
    CHECK(manifest_read_v1("backup", &same) == MANIFEST_STATUS_VALID);
    CHECK(manifest_resume_identity_compare(&m, &same) == MANIFEST_IDENTITY_EQUAL);
    m.exclude_count++;
    CHECK(manifest_write_v1("backup", &m) != 0);
    m.exclude_count--;
    manifest_free(&m); manifest_free(&same);
    free(home);
    CHECK(chdir("/") == 0);
    CHECK(nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    printf("manifest selection tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
