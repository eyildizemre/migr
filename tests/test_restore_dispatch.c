// Unit tests for restore()'s manifest-driven dispatch (docs/DECISIONS.md D15/D16):
// a valid v1 manifest routes to the root-table walker; an unversioned or
// absent manifest routes to the isolated legacy path; an unknown version or
// malformed v1 manifest refuses the whole restore before any confirmation or
// mutation; a ".partial" source is refused outright (docs/DECISIONS.md D15).
//
// Most cases here run with dry_run forced on for the whole binary (set once
// in main(), inherited by every fork()ed restore() call below), so none of
// this ever needs an interactive confirm_action() prompt or touches a real
// destination. The space-refusal case also runs once with dry_run disabled:
// it must prove that the free-space gate precedes confirmation. Happy-path v1
// fixtures are written with the real manifest_write_v1() so the fixture can
// never silently drift from what the reader actually accepts;
// malformed/unknown-version fixtures are raw strings, so a writer bug can
// never mask a reader bug -- see tests/test_manifest.c for the same split.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backup.h"
#include "manifest.h"
#include "restore.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void force_no_free_space(off_t needed, off_t *free_bytes,
                                void *context)
{
    (void)needed;
    (void)context;
    if (free_bytes != NULL)
        *free_bytes = 0;
}

static void set_test_block_size(off_t *block_size, void *context)
{
    if (block_size != NULL && context != NULL)
        *block_size = *(const off_t *)context;
}

static void fresh_mkdtemp(char *buf, size_t bufsize, const char *prefix)
{
    if ((size_t)snprintf(buf, bufsize, "/tmp/%s_XXXXXX", prefix) >= bufsize || mkdtemp(buf) == NULL)
    {
        printf(RED "fixture: could not create a temp dir for %s" NC "\n", prefix);
        exit(1);
    }
}

static int remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_cb, 16, FTW_DEPTH | FTW_PHYS) != 0)
    {
        printf(RED "fixture: could not clean up %s" NC "\n", path);
        exit(1);
    }
}

static void join_path(char *out, size_t out_size, const char *a, const char *b)
{
    size_t a_len = strlen(a);
    size_t b_len = strlen(b);
    if (a_len + 1 + b_len + 1 > out_size)
    {
        printf(RED "fixture: path too long" NC "\n");
        exit(1);
    }
    memcpy(out, a, a_len);
    out[a_len] = '/';
    memcpy(out + a_len + 1, b, b_len + 1);
}

// Genuinely recursive (unlike mkdir(2)): creates every missing intermediate
// component, since fixtures below need "data/<payload>" and "data" itself is
// never created ahead of time.
static void mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(buf))
    {
        printf(RED "fixture: path too long: %s" NC "\n", path);
        exit(1);
    }
    memcpy(buf, path, len + 1);

    for (size_t i = 1; i < len; i++)
    {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        {
            printf(RED "fixture: could not mkdir %s" NC "\n", buf);
            exit(1);
        }
        buf[i] = '/';
    }

    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
    {
        printf(RED "fixture: could not mkdir %s" NC "\n", buf);
        exit(1);
    }
}

// Creates dir/rel (rel may have one level, e.g. "data/EXPLICIT_0") and writes
// content into dir/rel/name.
static void write_payload_file(const char *dir, const char *rel, const char *name, const char *content)
{
    char sub[PATH_MAX];
    join_path(sub, sizeof(sub), dir, rel);
    mkdir_p(sub);
    char file_path[PATH_MAX];
    join_path(file_path, sizeof(file_path), sub, name);
    FILE *f = fopen(file_path, "w");
    if (f == NULL)
    {
        printf(RED "fixture: could not write %s" NC "\n", file_path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

static void write_raw(const char *dir, const char *content)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), dir, "manifest.txt");
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "fixture: could not write %s" NC "\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

// Forks so restore()'s output can be captured in isolation per call (dry_run
// is already 1 for the whole process, inherited across the fork) without one
// test's output or any accidental global mutation leaking into the next.
static int run_restore_capturing(const char *source, char *output, size_t output_size)
{
    int pipefd[2];
    if (pipe(pipefd) != 0)
    {
        perror("pipe");
        exit(1);
    }
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork");
        exit(1);
    }
    if (pid == 0)
    {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(2);
        close(pipefd[1]);
        int rc = restore(source);
        fflush(stdout);
        fflush(stderr);
        _exit(rc == 0 ? 0 : 1);
    }

    close(pipefd[1]);
    size_t total = 0;
    ssize_t n;
    while (total < output_size - 1 &&
           (n = read(pipefd[0], output + total, output_size - 1 - total)) > 0)
        total += n;
    output[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ========================================================================= */
/* Dispatch: legacy vs. v1 vs. refusal                                     */
/* ========================================================================= */

static void test_dispatch_routes_missing_manifest_to_legacy(void)
{
    printf(BLUE "::" NC " restore dispatch: an absent manifest.txt routes to the legacy path\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_payload_file(source, ".", "note.txt", "irrelevant"); // no manifest.txt at all

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds with no manifest.txt present");
    check(strstr(output, "Main Directories") != NULL, "the legacy section header appears");
    check(strstr(output, "Roots") == NULL, "the v1 section header does not appear");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_routes_legacy_xdg_manifest_to_legacy(void)
{
    printf(BLUE "::" NC " restore dispatch: an unversioned XDG-key manifest routes to the legacy path\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_raw(source, "XDG_DOCUMENTS_DIR=Belgeler\n");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds with an old-style XDG-key manifest.txt");
    check(strstr(output, "Main Directories") != NULL, "the legacy section header appears");
    check(strstr(output, "Roots") == NULL, "the v1 section header does not appear");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_refuses_unknown_version(void)
{
    printf(BLUE "::" NC " restore dispatch: an unrecognized manifest version refuses the whole restore\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_raw(source, "MIGR_MANIFEST\nVERSION=999\n");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "restore refuses an unrecognized manifest version");
    check(strstr(output, "Main Directories") == NULL, "the legacy path is never attempted");
    check(strstr(output, "Roots") == NULL, "the v1 path is never attempted");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_refuses_malformed_v1(void)
{
    printf(BLUE "::" NC " restore dispatch: a malformed v1 manifest refuses the whole restore\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_raw(source, "MIGR_MANIFEST\nVERSION=1\n"); // truncated: declares a header, nothing more

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "restore refuses a malformed v1 manifest");
    check(strstr(output, "Main Directories") == NULL, "the legacy path is never attempted");
    check(strstr(output, "Roots") == NULL, "the v1 path is never attempted");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_refuses_partial_source(void)
{
    printf(BLUE "::" NC " restore dispatch: a \".partial\" source is refused before manifest dispatch\n");

    char parent[PATH_MAX];
    fresh_mkdtemp(parent, sizeof(parent), "dispatch_parent");
    char source[PATH_MAX];
    join_path(source, sizeof(source), parent, "migr_backup_20260101_000000.partial");
    mkdir_p(source);

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "restore refuses a .partial-named source directory");
    check(strstr(output, "in-progress or abandoned") != NULL,
          "the refusal names the reason: an in-progress/abandoned container");

    remove_tree(parent);
    remove_tree(home);
}

static void test_dispatch_requires_v1_manifest_for_final_container_name(void)
{
    printf(BLUE "::" NC " restore dispatch: a canonical final-container name requires a v1 manifest\n");

    char parent[PATH_MAX];
    fresh_mkdtemp(parent, sizeof(parent), "dispatch_parent");
    char source[PATH_MAX];
    join_path(source, sizeof(source), parent, "migr_backup_20260101_000000");
    mkdir_p(source);
    write_payload_file(source, "data/EXPLICIT_0", "note.txt", "orphaned-v1-payload");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "a finalized versioned name without manifest.txt is refused");
    check(strstr(output, "missing manifest.txt") != NULL,
          "the error identifies the missing versioned control artifact");
    check(strstr(output, "Main Directories") == NULL,
          "the manifest-absent container is not guessed to be legacy");

    char legacy_source[PATH_MAX];
    join_path(legacy_source, sizeof(legacy_source), parent,
              "migr_backup_20260101_000000-1");
    mkdir_p(legacy_source);
    write_raw(legacy_source, "XDG_DOCUMENTS_DIR=Belgeler\n");

    rc = run_restore_capturing(legacy_source, output, sizeof(output));
    check(rc != 0, "a finalized versioned name carrying a legacy manifest is refused");
    check(strstr(output, "carries a legacy manifest") != NULL,
          "the error identifies the contradictory version boundary");
    check(strstr(output, "Main Directories") == NULL,
          "the canonical versioned container never enters the legacy walker");

    remove_tree(parent);
    remove_tree(home);
}

/* ========================================================================= */
/* v1 root-table walker                                                    */
/* ========================================================================= */

static void make_v1_manifest(Manifest *m, ManifestRoot *roots, int root_count)
{
    memset(m, 0, sizeof(*m));
    m->version = MANIFEST_CURRENT_VERSION;
    m->representation = CLONE_NATIVE_TREE;
    m->scope = MANIFEST_SCOPE_EXPLICIT;
    m->sidecar_version = 0;
    m->has_source_identity = 0;
    m->root_count = root_count;
    m->roots = roots;
}

static void test_dispatch_refuses_portable_v1(void)
{
    printf(BLUE "::" NC " restore dispatch: portable v1 payload is never interpreted as a native tree\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "EXPLICIT_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "EXPLICIT_0");
    strcpy(root.source_path, "Documents/project");
    strcpy(root.restore_path, "Documents/project");
    root.has_restore_path = 1;

    Manifest m;
    make_v1_manifest(&m, &root, 1);
    m.representation = CLONE_PORTABLE_SIDECAR;
    m.sidecar_version = 1;
    check(manifest_write_v1(source, &m) == 0,
          "fixture: write a valid portable v1 manifest");
    write_payload_file(source, "data/EXPLICIT_0", "note.txt", "encoded-or-degraded-content");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "portable v1 restore is refused while its replay path is absent");
    check(strstr(output, "Portable restore preflight refused") != NULL,
          "the refusal identifies the portable preflight path");
    check(strstr(output, "Roots") == NULL,
          "portable payload never reaches the native root walker");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_refuses_missing_declared_payloads(void)
{
    printf(BLUE "::" NC " restore dispatch: every v1 root must have its declared payload\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));

    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "Documents/project");
    strcpy(roots[0].restore_path, "Documents/project");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "EXPLICIT_1");
    roots[1].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots[1].payload_path, "EXPLICIT_1");
    strcpy(roots[1].source_path, "/mnt/external/project");
    roots[1].has_restore_path = 0;

    Manifest m;
    make_v1_manifest(&m, roots, 2);
    check(manifest_write_v1(source, &m) == 0,
          "fixture: write a valid v1 manifest without its declared payloads");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "missing declared payloads refuse the versioned restore");
    check(strstr(output, "EXPLICIT_0 is missing its declared payload") != NULL,
          "the missing automatic root is reported");
    check(strstr(output, "EXPLICIT_1 is missing its declared payload") != NULL,
          "the missing manual root is reported");
    check(strstr(output, "backup location:") == NULL,
          "restore never advertises a nonexistent MANUAL_NATIVE payload");
    check(strstr(output, "Roots") == NULL,
          "payload validation fails before the root walker starts");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_restores_home_relative_and_xdg_reports_manual_native(void)
{
    printf(BLUE "::" NC " restore dispatch: a valid v1 manifest restores HOME_RELATIVE/XDG roots and reports MANUAL_NATIVE\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[3];
    memset(roots, 0, sizeof(roots));

    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "Documents/project");
    strcpy(roots[0].restore_path, "Documents/project");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "Belgeler");
    roots[1].has_restore_path = 0;

    strcpy(roots[2].id, "EXPLICIT_1");
    roots[2].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots[2].payload_path, "EXPLICIT_1");
    strcpy(roots[2].source_path, "/mnt/external/project");
    roots[2].has_restore_path = 0;

    Manifest m;
    make_v1_manifest(&m, roots, 3);
    check(manifest_write_v1(source, &m) == 0, "fixture: write a valid v1 manifest via the real writer");

    write_payload_file(source, "data/EXPLICIT_0", "note.txt", "home-relative-content");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "doc.txt", "xdg-content");
    write_payload_file(source, "data/EXPLICIT_1", "external.txt", "manual-native-content");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds on a valid v1 manifest");
    check(strstr(output, "Roots") != NULL, "the v1 section header appears");
    check(strstr(output, "Main Directories") == NULL, "the legacy path is never attempted");

    check(strstr(output, "Would restore: EXPLICIT_0 -> ~/Documents/project") != NULL,
          "the HOME_RELATIVE root is previewed at its recorded restore address");
    check(strstr(output, "Would restore: XDG_DOCUMENTS_DIR ->") != NULL,
          "the XDG root is previewed against the target locale's resolved directory");

    check(strstr(output, "Manual Roots") != NULL, "the manual-roots section appears");
    check(strstr(output, "EXPLICIT_1") != NULL, "the MANUAL_NATIVE root's id is listed");
    check(strstr(output, "/mnt/external/project") != NULL,
          "the MANUAL_NATIVE root's recorded source path is listed (docs/DECISIONS.md D16)");
    check(strstr(output, "data/EXPLICIT_1") != NULL,
          "the MANUAL_NATIVE root's backup payload location is listed");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_empty_restore_path_means_home_itself(void)
{
    printf(BLUE "::" NC " restore dispatch: an empty HOME_RELATIVE restore_path addresses $HOME itself (docs/DECISIONS.md D16)\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "EXPLICIT_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "EXPLICIT_0");
    strcpy(root.source_path, "");
    root.restore_path[0] = '\0';
    root.has_restore_path = 1;

    Manifest m;
    make_v1_manifest(&m, &root, 1);
    check(manifest_write_v1(source, &m) == 0, "fixture: write a valid v1 manifest with an empty restore_path");

    write_payload_file(source, "data/EXPLICIT_0", "inside.txt", "home-root-content");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds");
    check(strstr(output, "Would restore: EXPLICIT_0 -> ~\n") != NULL,
          "an empty restore_path previews as the home directory itself, not a trailing-slash address");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_restore_space_preflight(void)
{
    printf(BLUE "::" NC " native restore free-space preflight and hardlink estimate\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "EXPLICIT_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "EXPLICIT_0");
    strcpy(root.source_path, "Documents/hardlinks");
    strcpy(root.restore_path, "Documents/hardlinks");
    root.has_restore_path = 1;

    Manifest manifest;
    make_v1_manifest(&manifest, &root, 1);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write a valid v1 manifest for the space preflight");
    write_payload_file(source, "data/EXPLICIT_0", "first", "payload");

    char first[PATH_MAX], second[PATH_MAX];
    join_path(first, sizeof(first), source, "data/EXPLICIT_0/first");
    join_path(second, sizeof(second), source, "data/EXPLICIT_0/second");
    if (link(first, second) != 0)
    {
        check(0, "fixture: create a hardlinked second payload member");
        remove_tree(source);
        remove_tree(home);
        return;
    }

    char output[8192];
    int previous_dry_run = dry_run;
    dry_run = 1;
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0 && strstr(output, "Estimated restore size: 7B") != NULL &&
              strstr(output, "Estimated restore size: 14B") == NULL,
          "native restore estimate counts a hardlink group only once");

    off_t block_size = 1;
    backup_test_set_block_size_hook(set_test_block_size, &block_size);
    backup_test_set_free_space_hook(force_no_free_space, NULL);

    rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0 && strstr(output, "Estimated restore size: 7B") != NULL &&
              strstr(output, "Destination free space: 0B") != NULL &&
              strstr(output, "Error: not enough free space at ") != NULL &&
              strstr(output, home) != NULL && strstr(output, "Continue?") == NULL,
          "native dry-run refuses before confirmation when space is insufficient");

    dry_run = 0;
    rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0 && strstr(output, "Estimated restore size: 7B") != NULL &&
              strstr(output, "Destination free space: 0B") != NULL &&
              strstr(output, "Error: not enough free space at ") != NULL &&
              strstr(output, home) != NULL && strstr(output, "Continue?") == NULL,
          "native live restore refuses before confirmation when space is insufficient");
    dry_run = previous_dry_run;

    backup_test_set_block_size_hook(NULL, NULL);
    backup_test_set_free_space_hook(NULL, NULL);
    char restored[PATH_MAX];
    join_path(restored, sizeof(restored), home, "Documents/hardlinks");
    check(access(restored, F_OK) != 0,
          "native space refusal leaves the destination untouched");

    remove_tree(source);
    remove_tree(home);
}

int main(void)
{
    printf(BLUE "::" NC " restore dispatch (unit)\n");

    dry_run = 1; // inherited by every fork()ed restore() call below; no confirm_action() prompt is ever reached

    test_dispatch_routes_missing_manifest_to_legacy();
    test_dispatch_routes_legacy_xdg_manifest_to_legacy();
    test_dispatch_refuses_unknown_version();
    test_dispatch_refuses_malformed_v1();
    test_dispatch_refuses_partial_source();
    test_dispatch_requires_v1_manifest_for_final_container_name();
    test_dispatch_refuses_portable_v1();
    test_v1_refuses_missing_declared_payloads();

    test_v1_restores_home_relative_and_xdg_reports_manual_native();
    test_v1_empty_restore_path_means_home_itself();
    test_v1_restore_space_preflight();

    if (failures > 0)
    {
        printf(RED "%d restore dispatch test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
