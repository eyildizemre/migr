// Unit tests for the deterministic backup root planner (docs/DECISIONS.md
// D16): backup_plan_build()/backup_plan_free(), declared in
// backup_plan.h. Covers the built-in catalog (XDG main directories,
// dotfiles, browser profiles, comprehensive-only Projects), explicit-path
// normalization and classification (HOME containment at component
// boundaries, leaf-symlink vs. ancestor-symlink handling, and "/" edge
// cases), whole-set duplicate/overlap validation and
// EXPLICIT_n determinism, and backup()'s production-level use of the plan:
// a rejected plan must never touch the destination, live or --dry-run alike.
//
// The "production" section below calls backup() itself (declared in
// backup.h) through a fork()+pipe helper mirroring
// tests/test_restore_dispatch.c's run_restore_capturing(). Unlike restore(),
// backup() never calls confirm_action(), so dry_run is toggled per test
// rather than forced globally for the whole binary.

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
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backup.h"
#include "backup_plan.h"
#include "manifest.h"
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
// component.
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

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "fixture: could not write %s" NC "\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

static const BackupPlanRoot *find_root(const BackupPlan *plan, const char *id)
{
    for (int i = 0; i < plan->root_count; i++)
        if (strcmp(plan->roots[i].manifest_root.id, id) == 0)
            return &plan->roots[i];
    return NULL;
}

static void make_full_home(const char *home)
{
    mkdir_p(home);
    const char *dirs[] = {
        "Documents", "Downloads", "Pictures", "Desktop", "Videos", "Music",
        "Projects", ".ssh", ".gnupg", ".mozilla",
        ".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
        ".config/vivaldi", ".config/microsoft-edge", ".config/opera",
        NULL
    };
    for (int i = 0; dirs[i] != NULL; i++)
    {
        char p[PATH_MAX];
        join_path(p, sizeof(p), home, dirs[i]);
        mkdir_p(p);
    }
    const char *files[] = { ".gitconfig", ".bashrc", ".profile", NULL };
    for (int i = 0; files[i] != NULL; i++)
    {
        char p[PATH_MAX];
        join_path(p, sizeof(p), home, files[i]);
        write_file(p, "x");
    }
}

/* ========================================================================= */
/* Model and built-in selection                                              */
/* ========================================================================= */

static void test_critical_root_set(void)
{
    printf(BLUE "::" NC " model: --critical plans Documents/Downloads/Pictures, dotfiles, and browsers\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    make_full_home(home);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &plan) == 0, "critical plan builds");

    check(find_root(&plan, "XDG_DOCUMENTS_DIR") != NULL, "Documents is planned");
    check(find_root(&plan, "XDG_DOWNLOAD_DIR") != NULL, "Downloads is planned");
    check(find_root(&plan, "XDG_PICTURES_DIR") != NULL, "Pictures is planned");
    check(find_root(&plan, "XDG_DESKTOP_DIR") == NULL, "Desktop is NOT planned under --critical");
    check(find_root(&plan, "XDG_VIDEOS_DIR") == NULL, "Videos is NOT planned under --critical");
    check(find_root(&plan, "XDG_MUSIC_DIR") == NULL, "Music is NOT planned under --critical");
    check(find_root(&plan, "BUILTIN_PROJECTS") == NULL, "Projects is NOT planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_SSH") != NULL, ".ssh is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_GNUPG") != NULL, ".gnupg is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_GITCONFIG") != NULL, ".gitconfig is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_BASHRC") != NULL, ".bashrc is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_PROFILE") != NULL, ".profile is planned under --critical");
    check(find_root(&plan, "BUILTIN_BROWSER_MOZILLA") != NULL, "browser profiles are planned under --critical");
    check(plan.scope == MANIFEST_SCOPE_CRITICAL, "scope is MANIFEST_SCOPE_CRITICAL");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_comprehensive_adds_extra_roots(void)
{
    printf(BLUE "::" NC " model: --comprehensive adds Desktop/Videos/Music/Projects\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    make_full_home(home);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_COMPREHENSIVE, NULL, &plan) == 0, "comprehensive plan builds");

    check(find_root(&plan, "XDG_DESKTOP_DIR") != NULL, "Desktop is planned under --comprehensive");
    check(find_root(&plan, "XDG_VIDEOS_DIR") != NULL, "Videos is planned under --comprehensive");
    check(find_root(&plan, "XDG_MUSIC_DIR") != NULL, "Music is planned under --comprehensive");
    check(find_root(&plan, "BUILTIN_PROJECTS") != NULL, "Projects is planned under --comprehensive");
    check(plan.scope == MANIFEST_SCOPE_COMPREHENSIVE, "scope is MANIFEST_SCOPE_COMPREHENSIVE");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_missing_optional_builtin_is_skipped_not_fatal(void)
{
    printf(BLUE "::" NC " model: a genuinely absent built-in is left out of the plan, not an error\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char docs[PATH_MAX];
    join_path(docs, sizeof(docs), home, "Documents");
    mkdir_p(docs);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_COMPREHENSIVE, NULL, &plan) == 0,
          "a mostly-empty home still builds a plan (missing built-ins are not fatal)");
    check(find_root(&plan, "XDG_DOCUMENTS_DIR") != NULL, "the one present built-in is planned");
    check(find_root(&plan, "XDG_DOWNLOAD_DIR") == NULL, "an absent built-in is simply left out");
    check(find_root(&plan, "BUILTIN_DOT_SSH") == NULL, "an absent dotfile is simply left out");
    check(find_root(&plan, "BUILTIN_BROWSER_MOZILLA") == NULL, "an absent browser profile is simply left out");
    check(find_root(&plan, "BUILTIN_PROJECTS") == NULL, "an absent Projects is simply left out");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_localized_xdg_uses_canonical_id(void)
{
    printf(BLUE "::" NC " model: a localized XDG source is planned under its canonical id\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char belgeler[PATH_MAX];
    join_path(belgeler, sizeof(belgeler), home, "Belgeler");
    mkdir_p(belgeler);
    char config_dir[PATH_MAX];
    join_path(config_dir, sizeof(config_dir), home, ".config");
    mkdir_p(config_dir);
    char user_dirs[PATH_MAX];
    join_path(user_dirs, sizeof(user_dirs), config_dir, "user-dirs.dirs");
    write_file(user_dirs, "XDG_DOCUMENTS_DIR=\"$HOME/Belgeler\"\n");

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &plan) == 0,
          "plan builds with a localized user-dirs.dirs");
    const BackupPlanRoot *r = find_root(&plan, "XDG_DOCUMENTS_DIR");
    check(r != NULL, "the localized directory is planned under the canonical XDG_DOCUMENTS_DIR id");
    if (r != NULL)
        check(strstr(r->capture_path, "/Belgeler") != NULL,
              "its capture_path points at the actual localized directory");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_fixed_builtin_fields(void)
{
    printf(BLUE "::" NC " model: a built-in root has its fixed id/policy/payload/restore fields\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    make_full_home(home);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &plan) == 0, "plan builds");
    const BackupPlanRoot *r = find_root(&plan, "BUILTIN_DOT_SSH");
    check(r != NULL, ".ssh is planned");
    if (r != NULL)
    {
        check(r->manifest_root.policy == ROOT_POLICY_HOME_RELATIVE, "policy is HOME_RELATIVE");
        check(strcmp(r->manifest_root.payload_path, "BUILTIN_DOT_SSH") == 0, "payload_path is the fixed id");
        check(strcmp(r->manifest_root.restore_path, ".ssh") == 0, "restore_path is the home-relative address");
        check(r->manifest_root.has_restore_path == 1, "has_restore_path is set");
        check(r->group == BACKUP_ROOT_DOTFILE, "presentation group is DOTFILE");
    }

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_zero_root_builtin_plan_is_safe(void)
{
    printf(BLUE "::" NC " model: an entirely empty home still yields a safe, empty plan\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &plan) == 0,
          "an empty home still builds (a valid zero-root plan)");
    check(plan.root_count == 0, "root_count is 0");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_builtin_ancestor_symlink_alias_is_detected_as_duplicate(void)
{
    printf(BLUE "::" NC " model: an XDG root and a built-in that alias the same real directory through an ancestor symlink are caught as a duplicate\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);

    // .config is itself a symlink to a real "altconfig" directory: the
    // browser built-in's home_rel (".config/google-chrome") only names
    // ".config" as an ANCESTOR component, not its own leaf, so it must be
    // resolved through the symlink like any other ancestor -- unlike a leaf
    // symlink, which is never dereferenced.
    char altconfig[PATH_MAX];
    join_path(altconfig, sizeof(altconfig), home, "altconfig");
    mkdir_p(altconfig);
    char chrome_real[PATH_MAX];
    join_path(chrome_real, sizeof(chrome_real), altconfig, "google-chrome");
    mkdir_p(chrome_real);

    char config_link[PATH_MAX];
    join_path(config_link, sizeof(config_link), home, ".config");
    check(symlink(altconfig, config_link) == 0, "fixture: make .config a symlink to altconfig");

    // A localized (or just unusually configured) XDG_DOCUMENTS_DIR pointing
    // directly at the exact same real directory, with no symlink involved
    // on this side at all -- two lexically different addresses for the
    // same object, exactly the class of alias a leaf-preserving-only (not
    // ancestor-resolving) join would miss.
    char user_dirs_path[PATH_MAX];
    join_path(user_dirs_path, sizeof(user_dirs_path), config_link, "user-dirs.dirs");
    char user_dirs_line[PATH_MAX + 64];
    snprintf(user_dirs_line, sizeof(user_dirs_line), "XDG_DOCUMENTS_DIR=\"%s\"\n", chrome_real);
    write_file(user_dirs_path, user_dirs_line);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &plan) != 0,
          "the alias through an ancestor symlink is caught as a duplicate root, not accepted as two");
    check(plan.root_count == 0 && plan.roots == NULL, "the rejected plan is left safely empty");

    remove_tree(home);
}

static void test_backup_plan_free_null_and_zero_init(void)
{
    printf(BLUE "::" NC " model: backup_plan_free() is safe on NULL and on a zero-initialized plan\n");

    backup_plan_free(NULL);
    check(1, "backup_plan_free(NULL) does not crash");

    BackupPlan plan = {0};
    backup_plan_free(&plan);
    check(1, "backup_plan_free() on a zero-initialized plan does not crash");
}

/* ========================================================================= */
/* Explicit-path normalization and policy                                    */
/* ========================================================================= */

static void test_explicit_relative_path_becomes_absolute(void)
{
    printf(BLUE "::" NC " explicit: a relative path normalizes to an absolute capture_path\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char target_dir[PATH_MAX];
    join_path(target_dir, sizeof(target_dir), home, "relroot");
    mkdir_p(target_dir);
    char expected[PATH_MAX];
    check(realpath(target_dir, expected) != NULL, "fixture: realpath the expected target");

    char cwd_saved[PATH_MAX];
    check(getcwd(cwd_saved, sizeof(cwd_saved)) != NULL, "fixture: save cwd");
    check(chdir(home) == 0, "fixture: chdir into home");

    char *paths[] = { (char *)"relroot", NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a relative explicit path resolves");
    check(plan.root_count == 1 && plan.roots[0].capture_path[0] == '/', "capture_path is absolute");
    check(plan.root_count == 1 && strcmp(plan.roots[0].capture_path, expected) == 0,
          "capture_path matches the real absolute address");

    backup_plan_free(&plan);
    check(chdir(cwd_saved) == 0, "fixture: restore cwd");
    remove_tree(home);
}

static void test_explicit_spelling_variants_of_same_path_are_duplicate(void)
{
    printf(BLUE "::" NC " explicit: 'x', './x', and 'dir/../x' all normalize to the same root and are rejected\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char x[PATH_MAX], dir[PATH_MAX];
    join_path(x, sizeof(x), home, "x");
    mkdir_p(x);
    join_path(dir, sizeof(dir), home, "dir");
    mkdir_p(dir);

    char cwd_saved[PATH_MAX];
    check(getcwd(cwd_saved, sizeof(cwd_saved)) != NULL, "fixture: save cwd");
    check(chdir(home) == 0, "fixture: chdir into home");

    char *paths[] = { (char *)"x", (char *)"./x", (char *)"dir/../x", NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) != 0,
          "three spellings of the same path are rejected as duplicates");
    check(plan.root_count == 0 && plan.roots == NULL, "the rejected plan is left safely empty");

    check(chdir(cwd_saved) == 0, "fixture: restore cwd");
    remove_tree(home);
}

static void test_explicit_home_itself_is_home_relative_empty_restore_path(void)
{
    printf(BLUE "::" NC " explicit: HOME itself is HOME_RELATIVE with an empty restore_path\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char home_real[PATH_MAX];
    check(realpath(home, home_real) != NULL, "fixture: realpath home");

    char *paths[] = { home_real, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "HOME itself is a valid explicit root");
    check(plan.root_count == 1, "exactly one root");
    if (plan.root_count == 1)
    {
        check(plan.roots[0].manifest_root.policy == ROOT_POLICY_HOME_RELATIVE, "policy is HOME_RELATIVE");
        check(plan.roots[0].manifest_root.has_restore_path == 1, "has_restore_path is set");
        check(plan.roots[0].manifest_root.restore_path[0] == '\0',
              "restore_path is empty (the root is $HOME itself)");
    }

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_explicit_normal_root_under_home_is_home_relative(void)
{
    printf(BLUE "::" NC " explicit: an ordinary root under HOME is HOME_RELATIVE\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char proj[PATH_MAX];
    join_path(proj, sizeof(proj), home, "proj");
    mkdir_p(proj);

    char *paths[] = { proj, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "an ordinary root under HOME is a valid explicit root");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_HOME_RELATIVE,
          "policy is HOME_RELATIVE");
    check(plan.root_count == 1 && strcmp(plan.roots[0].manifest_root.restore_path, "proj") == 0,
          "restore_path is the home-relative address");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_explicit_home2_prefix_trap_is_manual_native(void)
{
    printf(BLUE "::" NC " explicit: a '$HOME'-plus-suffix sibling is never mistaken for HOME_RELATIVE\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char home_real[PATH_MAX];
    check(realpath(home, home_real) != NULL, "fixture: realpath home");

    char sibling[PATH_MAX];
    int n = snprintf(sibling, sizeof(sibling), "%s2", home_real);
    check(n > 0 && (size_t)n < sizeof(sibling), "fixture: build sibling path");
    mkdir_p(sibling);

    char *paths[] = { sibling, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "the sibling path is a valid explicit root");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_MANUAL_NATIVE,
          "a lexical '$HOME2'-style prefix is classified MANUAL_NATIVE, not HOME_RELATIVE");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(sibling);
}

static void test_explicit_outside_home_is_manual_native(void)
{
    printf(BLUE "::" NC " explicit: a root entirely outside HOME is MANUAL_NATIVE\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char outside[PATH_MAX];
    fresh_mkdtemp(outside, sizeof(outside), "plan_outside");

    char *paths[] = { outside, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a root outside HOME is a valid explicit root");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_MANUAL_NATIVE,
          "policy is MANUAL_NATIVE");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(outside);
}

static void test_explicit_final_leaf_symlink_outside_is_home_relative(void)
{
    printf(BLUE "::" NC " explicit: a HOME-side leaf symlink pointing outside stays HOME_RELATIVE (its target is never followed)\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char outside[PATH_MAX];
    fresh_mkdtemp(outside, sizeof(outside), "plan_outside");
    char target[PATH_MAX];
    join_path(target, sizeof(target), outside, "file");
    write_file(target, "x");

    char link[PATH_MAX];
    join_path(link, sizeof(link), home, "link");
    check(symlink(target, link) == 0, "fixture: create the leaf symlink pointing outside HOME");

    char *paths[] = { link, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "the outward-pointing leaf symlink is a valid explicit root");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_HOME_RELATIVE,
          "the symlink OBJECT itself (not its target) is classified HOME_RELATIVE");
    check(plan.root_count == 1 && strcmp(plan.roots[0].manifest_root.restore_path, "link") == 0,
          "restore_path is the symlink's own home-relative address");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(outside);
}

static void test_explicit_dangling_leaf_symlink_is_valid(void)
{
    printf(BLUE "::" NC " explicit: a dangling leaf symlink is a valid root\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char link[PATH_MAX];
    join_path(link, sizeof(link), home, "danglink");
    check(symlink("/nonexistent/nowhere/at/all", link) == 0, "fixture: create a dangling symlink");

    char *paths[] = { link, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a dangling leaf symlink is accepted as a valid root");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_HOME_RELATIVE,
          "it is classified HOME_RELATIVE like any other object directly under HOME");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_explicit_ancestor_symlink_escaping_home_is_manual_native(void)
{
    printf(BLUE "::" NC " explicit: an ancestor symlink that escapes HOME resolves to its real (outside) parent\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char outside[PATH_MAX];
    fresh_mkdtemp(outside, sizeof(outside), "plan_outside");
    char realdir[PATH_MAX];
    join_path(realdir, sizeof(realdir), outside, "realdir");
    mkdir_p(realdir);
    char file[PATH_MAX];
    join_path(file, sizeof(file), realdir, "file");
    write_file(file, "x");

    char linkdir[PATH_MAX];
    join_path(linkdir, sizeof(linkdir), home, "linkdir");
    check(symlink(realdir, linkdir) == 0, "fixture: create an ancestor symlink to a directory outside HOME");

    char path[PATH_MAX];
    join_path(path, sizeof(path), linkdir, "file"); // string concat: "$HOME/linkdir/file"

    char realdir_real[PATH_MAX], expected[PATH_MAX];
    check(realpath(realdir, realdir_real) != NULL, "fixture: realpath realdir");
    join_path(expected, sizeof(expected), realdir_real, "file");

    char *paths[] = { path, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a path through an ancestor symlink is a valid explicit root");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_MANUAL_NATIVE,
          "resolving the real (outside) parent classifies the root MANUAL_NATIVE");
    check(plan.root_count == 1 && strcmp(plan.roots[0].capture_path, expected) == 0,
          "capture_path is the real parent's address, not a lexical join through the symlink name");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(outside);
}

static void test_explicit_dotdot_through_ancestor_symlink_matches_kernel(void)
{
    printf(BLUE "::" NC " explicit: '..' through an ancestor symlink follows real kernel semantics, not lexical cancellation\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char outer[PATH_MAX];
    fresh_mkdtemp(outer, sizeof(outer), "plan_outer");
    char inner[PATH_MAX];
    join_path(inner, sizeof(inner), outer, "inner");
    mkdir_p(inner);

    char linkdir[PATH_MAX];
    join_path(linkdir, sizeof(linkdir), home, "linkdir");
    check(symlink(inner, linkdir) == 0, "fixture: create an ancestor symlink to outer/inner");

    char path[PATH_MAX];
    join_path(path, sizeof(path), linkdir, ".."); // "$HOME/linkdir/.."

    char home_real[PATH_MAX], outer_real[PATH_MAX];
    check(realpath(home, home_real) != NULL, "fixture: realpath home");
    check(realpath(outer, outer_real) != NULL, "fixture: realpath outer");

    char *paths[] = { path, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "'linkdir/..' is a valid explicit root");
    check(plan.root_count == 1 && strcmp(plan.roots[0].capture_path, outer_real) == 0,
          "the kernel resolves the symlink first, then applies '..': the real parent of 'inner', not $HOME");
    check(plan.root_count == 1 && strcmp(plan.roots[0].capture_path, home_real) != 0,
          "it is NOT lexically cancelled back to $HOME");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(outer);
}

static void test_root_slash_is_valid_manual_native(void)
{
    printf(BLUE "::" NC " explicit: '/' itself is a valid MANUAL_NATIVE root\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);

    char *paths[] = { (char *)"/", NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "'/' is accepted by the planner");
    check(plan.root_count == 1 && strcmp(plan.roots[0].capture_path, "/") == 0, "capture_path is '/'");
    check(plan.root_count == 1 && plan.roots[0].manifest_root.policy == ROOT_POLICY_MANUAL_NATIVE,
          "policy is MANUAL_NATIVE");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_home_slash_classifies_descendant_as_home_relative(void)
{
    printf(BLUE "::" NC " explicit: when HOME is '/', every descendant is HOME_RELATIVE\n");

    char fixture[PATH_MAX];
    fresh_mkdtemp(fixture, sizeof(fixture), "plan_root_home");
    char source[PATH_MAX];
    join_path(source, sizeof(source), fixture, "item");
    write_file(source, "x");

    char *paths[] = { source, NULL };
    BackupPlan plan;
    check(backup_plan_build("/", BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a descendant of '/' is accepted when HOME is '/'");
    check(plan.root_count == 1, "exactly one root");
    if (plan.root_count == 1)
    {
        check(plan.roots[0].manifest_root.policy == ROOT_POLICY_HOME_RELATIVE,
              "the descendant is HOME_RELATIVE, not MANUAL_NATIVE");
        check(plan.roots[0].manifest_root.has_restore_path,
              "the root has an automatic restore address");
        check(strcmp(plan.roots[0].manifest_root.restore_path,
                     plan.roots[0].capture_path + 1) == 0,
              "restore_path is the absolute capture path without its leading slash");
    }

    backup_plan_free(&plan);
    remove_tree(fixture);
}

/* ========================================================================= */
/* Set validation and determinism                                          */
/* ========================================================================= */

static void test_destination_inside_a_root_is_a_conflict(void)
{
    printf(BLUE "::" NC " set: a destination equal to or below a selected root is reported as a conflict\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char docs[PATH_MAX];
    join_path(docs, sizeof(docs), home, "Documents");
    mkdir_p(docs);
    char outside[PATH_MAX];
    fresh_mkdtemp(outside, sizeof(outside), "plan_outside");

    char *paths[] = { docs, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "the plan builds");

    char inside[PATH_MAX], deeper[PATH_MAX], sibling[PATH_MAX];
    join_path(inside, sizeof(inside), docs, "backup");      // does not exist yet
    join_path(deeper, sizeof(deeper), docs, "a");
    mkdir_p(deeper);
    char deeper_child[PATH_MAX];
    join_path(deeper_child, sizeof(deeper_child), deeper, "b");
    // A lexical near-miss: "Documents2" shares a prefix but not a component
    // boundary, so it is a perfectly good destination.
    int n = snprintf(sibling, sizeof(sibling), "%s2", docs);
    check(n > 0 && (size_t)n < sizeof(sibling), "fixture: build the prefix-trap sibling");
    mkdir_p(sibling);

    check(backup_plan_destination_conflicts(&plan, docs) == 1,
          "a destination equal to the root itself conflicts");
    check(backup_plan_destination_conflicts(&plan, inside) == 1,
          "a not-yet-existing destination directly inside the root conflicts");
    check(backup_plan_destination_conflicts(&plan, deeper_child) == 1,
          "a destination deeper inside the root conflicts");
    check(backup_plan_destination_conflicts(&plan, sibling) == 0,
          "a lexical-prefix sibling of the root is not a conflict");
    check(backup_plan_destination_conflicts(&plan, outside) == 0,
          "a destination outside every root is not a conflict");

    // A destination is a place to write into, so unlike a root it must be
    // followed through its final symlink: a link that lives outside every root
    // but points inside one still writes inside one.
    char alias[PATH_MAX], alias_target[PATH_MAX];
    join_path(alias, sizeof(alias), outside, "target_link");
    join_path(alias_target, sizeof(alias_target), docs, "aliased");
    mkdir_p(alias_target);
    check(symlink(alias_target, alias) == 0,
          "fixture: a symlink outside every root pointing to a directory inside one");
    check(backup_plan_destination_conflicts(&plan, alias) == 1,
          "a destination symlink resolving into a root conflicts, despite living outside it");

    char benign_alias[PATH_MAX], benign_target[PATH_MAX];
    join_path(benign_target, sizeof(benign_target), outside, "real_destination");
    mkdir_p(benign_target);
    join_path(benign_alias, sizeof(benign_alias), outside, "benign_link");
    check(symlink(benign_target, benign_alias) == 0,
          "fixture: a symlink pointing to a directory outside every root");
    check(backup_plan_destination_conflicts(&plan, benign_alias) == 0,
          "a destination symlink resolving outside every root is still usable");
    check(backup_plan_destination_conflicts(NULL, outside) == 0 &&
          backup_plan_destination_conflicts(&plan, NULL) == 0,
          "NULL arguments report no conflict rather than crashing");

    backup_plan_free(&plan);

    // "/" is every other path's ancestor, so no destination can ever sit
    // outside it.
    char *root_paths[] = { (char *)"/", NULL };
    BackupPlan root_plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)root_paths, &root_plan) == 0,
          "a plan whose only root is '/' builds");
    check(backup_plan_destination_conflicts(&root_plan, outside) == 1,
          "with '/' selected, every destination conflicts");
    backup_plan_free(&root_plan);

    remove_tree(home); // sibling lives inside it, so this removes both
    remove_tree(outside);
}

static void test_duplicate_explicit_root_is_rejected(void)
{
    printf(BLUE "::" NC " set: an explicit root repeated verbatim is rejected as a duplicate\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char x[PATH_MAX];
    join_path(x, sizeof(x), home, "x");
    mkdir_p(x);

    char *paths[] = { x, x, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) != 0,
          "the same path given twice is rejected");
    check(plan.root_count == 0 && plan.roots == NULL, "the rejected plan is left safely empty");

    remove_tree(home);
}

static void test_directory_ancestor_descendant_overlap_is_rejected(void)
{
    printf(BLUE "::" NC " set: a directory root and its own descendant are rejected as overlapping\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char dir[PATH_MAX], sub[PATH_MAX];
    join_path(dir, sizeof(dir), home, "dir");
    mkdir_p(dir);
    join_path(sub, sizeof(sub), dir, "sub");
    mkdir_p(sub);

    char *paths[] = { dir, sub, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) != 0,
          "an ancestor/descendant pair is rejected as overlapping");
    check(plan.root_count == 0 && plan.roots == NULL, "the rejected plan is left safely empty");

    remove_tree(home);
}

static void test_leaf_symlink_root_does_not_falsely_overlap_target(void)
{
    printf(BLUE "::" NC " set: a leaf-symlink root and an object under its target are NOT a false overlap\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char outside[PATH_MAX];
    fresh_mkdtemp(outside, sizeof(outside), "plan_outside");
    char child[PATH_MAX];
    join_path(child, sizeof(child), outside, "child_file");
    write_file(child, "x");

    char linkdir[PATH_MAX];
    join_path(linkdir, sizeof(linkdir), home, "linkdir");
    check(symlink(outside, linkdir) == 0, "fixture: create a leaf symlink to the outside directory");

    char *paths[] = { linkdir, child, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a leaf-symlink root alongside a file under its unresolved target is accepted, not flagged as overlap");
    check(plan.root_count == 2, "both roots are present");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(outside);
}

static void test_reversed_argv_produces_same_explicit_ids(void)
{
    printf(BLUE "::" NC " set: reversed argv order produces the identical EXPLICIT_n mapping\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char a[PATH_MAX], b[PATH_MAX];
    join_path(a, sizeof(a), home, "aaa");
    mkdir_p(a);
    join_path(b, sizeof(b), home, "bbb");
    mkdir_p(b);

    char *forward[] = { a, b, NULL };
    char *reversed[] = { b, a, NULL };

    BackupPlan p1, p2;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)forward, &p1) == 0,
          "forward order builds");
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)reversed, &p2) == 0,
          "reversed order builds");

    int same = p1.root_count == 2 && p2.root_count == 2;
    for (int i = 0; same && i < 2; i++)
    {
        same = strcmp(p1.roots[i].manifest_root.id, p2.roots[i].manifest_root.id) == 0 &&
               strcmp(p1.roots[i].capture_path, p2.roots[i].capture_path) == 0;
    }
    check(same, "argv order never changes which path gets which EXPLICIT_n id");

    backup_plan_free(&p1);
    backup_plan_free(&p2);
    remove_tree(home);
}

static void test_same_basename_different_paths_are_two_roots(void)
{
    printf(BLUE "::" NC " set: two explicit roots with the same basename are two distinct roots (planner accepts this)\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char dir_a[PATH_MAX], dir_b[PATH_MAX], same_a[PATH_MAX], same_b[PATH_MAX];
    join_path(dir_a, sizeof(dir_a), home, "dir_a");
    mkdir_p(dir_a);
    join_path(dir_b, sizeof(dir_b), home, "dir_b");
    mkdir_p(dir_b);
    join_path(same_a, sizeof(same_a), dir_a, "same.txt");
    write_file(same_a, "A");
    join_path(same_b, sizeof(same_b), dir_b, "same.txt");
    write_file(same_b, "B");

    char *paths[] = { same_a, same_b, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "two files sharing a basename under different directories both plan successfully");
    check(plan.root_count == 2, "both are present as distinct roots");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_socket_root_is_rejected(void)
{
    printf(BLUE "::" NC " set: a Unix domain socket cannot be a backup root\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char sockpath[PATH_MAX];
    join_path(sockpath, sizeof(sockpath), home, "sock");

    if (strlen(sockpath) >= sizeof(((struct sockaddr_un *)0)->sun_path))
    {
        printf(BLUE "  (skipped: sun_path too short for this test root's path)\n" NC);
        remove_tree(home);
        return;
    }

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    check(sock_fd >= 0, "fixture: create a Unix domain socket");
    if (sock_fd >= 0)
    {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, sockpath, strlen(sockpath) + 1);
        int bind_rc = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
        if (bind_rc == 0)
        {
            check(1, "fixture: bind the socket");
            char *paths[] = { sockpath, NULL };
            BackupPlan plan;
            check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                                    (const char *const *)paths, &plan) != 0,
                  "a socket is refused as a backup root");
            check(plan.root_count == 0 && plan.roots == NULL,
                  "the rejected plan is left safely empty");
            backup_plan_free(&plan);
            unlink(sockpath);
        }
        else if (errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT)
            printf(BLUE "  (skipped: Unix socket bind unavailable on this host)\n" NC);
        else
            check(0, "fixture: bind the socket");

        close(sock_fd);
    }

    remove_tree(home);
}

static void test_fifo_root_is_accepted(void)
{
    printf(BLUE "::" NC " set: a FIFO is a valid backup root\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char fifo[PATH_MAX];
    join_path(fifo, sizeof(fifo), home, "myfifo");
    check(mkfifo(fifo, 0600) == 0, "fixture: create a FIFO");

    char *paths[] = { fifo, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) == 0,
          "a FIFO is accepted as a backup root");
    check(plan.root_count == 1, "the FIFO is present in the plan");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_root_count_ceiling_is_enforced(void)
{
    printf(BLUE "::" NC " set: exceeding MANIFEST_MAX_ROOTS rejects the whole plan\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    char many[PATH_MAX];
    join_path(many, sizeof(many), home, "many");
    mkdir_p(many);

    enum { N = MANIFEST_MAX_ROOTS + 1 };
    char **paths = malloc((size_t)(N + 1) * sizeof(char *));
    if (paths == NULL)
    {
        printf(RED "fixture: out of memory" NC "\n");
        exit(1);
    }
    // Sized a little past PATH_MAX: gcc's conservative worst-case analysis of
    // "%s/f%06d" (many could be up to PATH_MAX-1 bytes) would otherwise flag a
    // -Wformat-truncation false positive against an exactly-PATH_MAX buffer,
    // even though `many`'s real length here is nowhere close to that bound.
    enum { PATH_BUF = PATH_MAX + 16 };
    for (int i = 0; i < N; i++)
    {
        paths[i] = malloc(PATH_BUF);
        if (paths[i] == NULL)
        {
            printf(RED "fixture: out of memory" NC "\n");
            exit(1);
        }
        snprintf(paths[i], PATH_BUF, "%s/f%06d", many, i);
        write_file(paths[i], "");
    }
    paths[N] = NULL;

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, (const char *const *)paths, &plan) != 0,
          "one more root than MANIFEST_MAX_ROOTS rejects the whole plan");
    check(plan.root_count == 0 && plan.roots == NULL, "the rejected plan is left safely empty");

    for (int i = 0; i < N; i++)
        free(paths[i]);
    free(paths);
    remove_tree(home);
}

/* ========================================================================= */
/* Production integration (backup())                                        */
/* ========================================================================= */

static int run_backup_capturing(const char *target, BackupMode mode, char *const *paths,
                                char *output, size_t output_size)
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
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int rc = backup(target, mode, (char **)paths);
        fflush(stdout);
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

static int dir_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

// Locates the single finalized container under target and writes its data/
// path, which is where every planned root's payload lands. A leftover
// ".partial" is deliberately not accepted: a successful backup never leaves
// one, so treating it as the result would mask exactly that failure.
static int find_payload_dir(const char *target, char *out, size_t out_size)
{
    DIR *d = opendir(target);
    if (d == NULL)
        return 0;

    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)) != NULL)
    {
        size_t len = strlen(e->d_name);
        if (strncmp(e->d_name, "migr_backup_", 12) != 0)
            continue;
        if (len >= 8 && strcmp(e->d_name + len - 8, ".partial") == 0)
            continue;

        char container[PATH_MAX];
        join_path(container, sizeof(container), target, e->d_name);
        join_path(out, out_size, container, "data");
        found = 1;
        break;
    }
    closedir(d);
    return found;
}

static int directory_empty(const char *path)
{
    DIR *d = opendir(path);
    if (d == NULL)
        return 0;

    struct dirent *entry;
    int empty = 1;
    while ((entry = readdir(d)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
        {
            empty = 0;
            break;
        }
    }
    closedir(d);
    return empty;
}

static void force_no_free_space(off_t needed, off_t *free_bytes, void *context)
{
    (void)needed;
    (void)context;
    *free_bytes = 0;
}

static void test_plan_estimate_tolerates_missing_root(void)
{
    printf(BLUE "::" NC " model: size estimation tolerates a root that vanishes after planning\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char first[PATH_MAX], second[PATH_MAX];
    join_path(first, sizeof(first), home, "first");
    join_path(second, sizeof(second), home, "second");
    write_file(first, "first payload");
    write_file(second, "second payload");
    char *paths[] = { first, second, NULL };

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                            (const char *const *)paths, &plan) == 0,
          "the two-root estimate fixture builds");

    struct stat first_st;
    check(lstat(first, &first_st) == 0, "the surviving root can be measured");
    check(unlink(second) == 0, "one planned root vanishes before estimation");

    off_t total = -1;
    int had_error = -1;
    backup_plan_estimate_size(&plan, &total, &had_error);
    check(had_error == 0, "a vanished root is not an estimation error");
    check(total == first_st.st_size,
          "a vanished root contributes zero to the estimated total");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_destination_space_preflight(void)
{
    printf(BLUE "::" NC " production: destination free-space preflight covers refusal, rollback, and normal explicit backups\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char source[PATH_MAX];
    join_path(source, sizeof(source), home, "source.txt");
    write_file(source, "space-preflight payload");
    char *paths[] = { source, NULL };

    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "plan_target_parent");
    char target[PATH_MAX];
    join_path(target, sizeof(target), target_parent, "existing_target");
    mkdir_p(target);

    backup_test_set_free_space_hook(force_no_free_space, NULL);
    char live_output[8192];
    char dry_output[8192];
    dry_run = 0;
    int live_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                       paths, live_output, sizeof(live_output));
    dry_run = 1;
    int dry_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                      paths, dry_output, sizeof(dry_output));
    struct stat source_st = {0};
    int source_stat_ok = lstat(source, &source_st) == 0;
    check(source_stat_ok,
          "the refusal fixture source remains measurable");
    char shortfall_text[32];
    format_size(source_stat_ok ? source_st.st_size : 0,
                shortfall_text, sizeof(shortfall_text));
    check(live_rc == 1 && dry_rc == 1,
          "insufficient space refuses both live and dry-run backups");
    check(strcmp(live_output, dry_output) == 0,
          "insufficient-space output is identical live and dry-run");
    check(strstr(live_output, "Estimated backup size:") != NULL &&
          strstr(live_output, "Destination free space:") != NULL &&
          strstr(live_output, "Error: not enough free space at") != NULL &&
          strstr(live_output, "(need ") != NULL &&
          strstr(live_output, shortfall_text) != NULL &&
          strstr(live_output, " more)") != NULL &&
          strstr(live_output, ", have ") == NULL,
          "the refusal reports the additional space required");
    check(directory_empty(target),
          "an existing destination receives no container, data, or manifest on refusal");

    char created_target[PATH_MAX];
    join_path(created_target, sizeof(created_target), target_parent,
              "created_then_refused");
    dry_run = 0;
    char rollback_output[8192];
    int rollback_rc = run_backup_capturing(created_target,
                                           BACKUP_EXPLICIT_PATHS, paths,
                                           rollback_output,
                                           sizeof(rollback_output));
    check(rollback_rc == 1 && !dir_exists(created_target),
          "a newly created destination is rolled back on space refusal");

    backup_test_set_free_space_hook(NULL, NULL);
    char normal_dry_target[PATH_MAX];
    fresh_mkdtemp(normal_dry_target, sizeof(normal_dry_target), "plan_space_dry");
    dry_run = 1;
    char normal_dry_output[8192];
    int normal_dry_rc = run_backup_capturing(
        normal_dry_target, BACKUP_EXPLICIT_PATHS, paths,
        normal_dry_output, sizeof(normal_dry_output));
    check(normal_dry_rc == 0 &&
          strstr(normal_dry_output, "Estimated backup size:") != NULL &&
          strstr(normal_dry_output, "Destination free space:") != NULL,
          "a fitting dry-run prints both space summaries and succeeds");

    char normal_live_target[PATH_MAX];
    fresh_mkdtemp(normal_live_target, sizeof(normal_live_target), "plan_space_live");
    dry_run = 0;
    char normal_live_output[8192];
    int normal_live_rc = run_backup_capturing(
        normal_live_target, BACKUP_EXPLICIT_PATHS, paths,
        normal_live_output, sizeof(normal_live_output));
    char payload_dir[PATH_MAX];
    check(normal_live_rc == 0 &&
          strstr(normal_live_output, "Estimated backup size:") != NULL &&
          strstr(normal_live_output, "Destination free space:") != NULL &&
          find_payload_dir(normal_live_target, payload_dir,
                           sizeof(payload_dir)),
          "a fitting explicit backup prints both summaries and completes");

    dry_run = 0;
    backup_test_set_free_space_hook(NULL, NULL);
    remove_tree(home);
    remove_tree(target_parent);
    remove_tree(normal_dry_target);
    remove_tree(normal_live_target);
}

static void test_missing_explicit_path_rejects_before_target_creation(void)
{
    printf(BLUE "::" NC " production: a missing explicit path refuses the whole backup before the destination exists\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "plan_target_parent");
    char dest[PATH_MAX];
    join_path(dest, sizeof(dest), target_parent, "does_not_exist_yet");

    char missing[PATH_MAX];
    join_path(missing, sizeof(missing), home, "nonexistent_explicit_root");
    char *paths[] = { missing, NULL };

    dry_run = 0;
    char output[8192];
    int rc = run_backup_capturing(dest, BACKUP_EXPLICIT_PATHS, paths, output, sizeof(output));
    check(rc != 0, "backup refuses a missing explicit path");
    check(!dir_exists(dest), "the destination directory was never created");

    remove_tree(home);
    remove_tree(target_parent);
}

static void test_overlap_rejected_before_destination_created_live_and_dry_run(void)
{
    printf(BLUE "::" NC " production: overlapping explicit roots refuse before the destination exists, live and dry-run alike\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char dir[PATH_MAX], sub[PATH_MAX];
    join_path(dir, sizeof(dir), home, "dir");
    mkdir_p(dir);
    join_path(sub, sizeof(sub), dir, "sub");
    mkdir_p(sub);
    char *paths[] = { dir, sub, NULL };

    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "plan_target_parent");

    for (int live = 0; live < 2; live++)
    {
        char dest[PATH_MAX];
        join_path(dest, sizeof(dest), target_parent, live ? "live_dest" : "dry_dest");

        dry_run = live ? 0 : 1;
        char output[8192];
        int rc = run_backup_capturing(dest, BACKUP_EXPLICIT_PATHS, paths, output, sizeof(output));
        check(rc != 0, live ? "overlap refused live" : "overlap refused in dry-run");
        check(!dir_exists(dest), live ? "no destination created live" : "no destination created in dry-run");
    }
    dry_run = 0;

    remove_tree(home);
    remove_tree(target_parent);
}

static void test_dangling_explicit_leaf_symlink_is_captured_as_symlink(void)
{
    printf(BLUE "::" NC " production: a dangling explicit leaf symlink is captured as a symlink, not skipped or dereferenced\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);
    char link[PATH_MAX];
    join_path(link, sizeof(link), home, "danglink");
    check(symlink("/nonexistent/target/at/all", link) == 0, "fixture: create a dangling symlink");
    char *paths[] = { link, NULL };

    char target[PATH_MAX];
    fresh_mkdtemp(target, sizeof(target), "plan_target");

    dry_run = 0;
    char output[8192];
    int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths, output, sizeof(output));
    check(rc == 0, "backup succeeds capturing a dangling leaf symlink");

    char payload_dir[PATH_MAX];
    check(find_payload_dir(target, payload_dir, sizeof(payload_dir)),
          "a finalized container with a data/ namespace was created");

    char copied_link[PATH_MAX];
    join_path(copied_link, sizeof(copied_link), payload_dir, "EXPLICIT_0");
    struct stat st;
    check(lstat(copied_link, &st) == 0 && S_ISLNK(st.st_mode),
          "the dangling symlink was captured as a symlink, not skipped or turned into something else");

    remove_tree(home);
    remove_tree(target);
}

static void test_dangling_builtin_dotfile_is_captured_not_silently_dropped(void)
{
    printf(BLUE "::" NC " production: a dangling built-in dotfile symlink is actually captured, not silently dropped\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);
    char profile[PATH_MAX];
    join_path(profile, sizeof(profile), home, ".profile");
    check(symlink("/nonexistent/wherever/it/went", profile) == 0,
          "fixture: make .profile a dangling symlink (planner already accepts this as a valid root)");

    char *paths[] = { NULL };
    char target[PATH_MAX];
    fresh_mkdtemp(target, sizeof(target), "plan_target");

    dry_run = 0;
    char output[8192];
    int rc = run_backup_capturing(target, BACKUP_CRITICAL, paths, output, sizeof(output));
    check(rc == 0, "backup succeeds");

    char payload_dir[PATH_MAX];
    check(find_payload_dir(target, payload_dir, sizeof(payload_dir)),
          "a finalized container with a data/ namespace was created");
    char copied_profile[PATH_MAX];
    join_path(copied_profile, sizeof(copied_profile), payload_dir, "BUILTIN_DOT_PROFILE");
    struct stat st;
    check(lstat(copied_profile, &st) == 0 && S_ISLNK(st.st_mode),
          "the dangling .profile symlink the plan promised to capture actually made it into the backup");

    remove_tree(home);
    remove_tree(target);
}

static void test_unusable_target_does_not_leak_the_plan(void)
{
    printf(BLUE "::" NC " production: a destination that cannot even be inspected does not leak the plan\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);
    char profile[PATH_MAX];
    join_path(profile, sizeof(profile), home, ".profile");
    write_file(profile, "x");

    // A target too long for the kernel to resolve at all: it fails at the very
    // first stat(), after the plan has been built and before a container exists.
    char target[PATH_MAX];
    size_t fill = sizeof(target) - 10;
    memset(target, 'x', fill);
    target[fill] = '\0';

    char *paths[] = { NULL };
    dry_run = 0;
    char output[8192];
    int rc = run_backup_capturing(target, BACKUP_CRITICAL, paths, output, sizeof(output));
    check(rc != 0, "backup refuses a target it cannot inspect");
    check(strstr(output, "Could not access") != NULL, "the refusal names the reason");
    // Valgrind (run separately over this binary) is what actually proves the
    // plan built for this call was freed rather than leaked; this test's own
    // job is just to exercise the exact code path that leak lived on.

    remove_tree(home);
}

int main(void)
{
    printf(BLUE "::" NC " backup root planner (unit)\n");

    test_critical_root_set();
    test_comprehensive_adds_extra_roots();
    test_missing_optional_builtin_is_skipped_not_fatal();
    test_localized_xdg_uses_canonical_id();
    test_fixed_builtin_fields();
    test_zero_root_builtin_plan_is_safe();
    test_builtin_ancestor_symlink_alias_is_detected_as_duplicate();
    test_backup_plan_free_null_and_zero_init();

    test_explicit_relative_path_becomes_absolute();
    test_explicit_spelling_variants_of_same_path_are_duplicate();
    test_explicit_home_itself_is_home_relative_empty_restore_path();
    test_explicit_normal_root_under_home_is_home_relative();
    test_explicit_home2_prefix_trap_is_manual_native();
    test_explicit_outside_home_is_manual_native();
    test_explicit_final_leaf_symlink_outside_is_home_relative();
    test_explicit_dangling_leaf_symlink_is_valid();
    test_explicit_ancestor_symlink_escaping_home_is_manual_native();
    test_explicit_dotdot_through_ancestor_symlink_matches_kernel();
    test_root_slash_is_valid_manual_native();
    test_home_slash_classifies_descendant_as_home_relative();

    test_destination_inside_a_root_is_a_conflict();
    test_duplicate_explicit_root_is_rejected();
    test_directory_ancestor_descendant_overlap_is_rejected();
    test_leaf_symlink_root_does_not_falsely_overlap_target();
    test_reversed_argv_produces_same_explicit_ids();
    test_same_basename_different_paths_are_two_roots();
    test_socket_root_is_rejected();
    test_fifo_root_is_accepted();
    test_root_count_ceiling_is_enforced();

    test_plan_estimate_tolerates_missing_root();
    test_destination_space_preflight();
    test_missing_explicit_path_rejects_before_target_creation();
    test_overlap_rejected_before_destination_created_live_and_dry_run();
    test_dangling_explicit_leaf_symlink_is_captured_as_symlink();
    test_dangling_builtin_dotfile_is_captured_not_silently_dropped();
    test_unusable_target_does_not_leak_the_plan();

    if (failures > 0)
    {
        printf(RED "%d backup plan test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
