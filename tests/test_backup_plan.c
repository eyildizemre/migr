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
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/mman.h>
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

static void write_large_file(const char *path, size_t size)
{
    unsigned char buffer[8192];
    for (size_t index = 0; index < sizeof(buffer); index++)
        buffer[index] = (unsigned char)(index * 17U + 3U);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        printf(RED "fixture: could not create large progress fixture" NC "\n");
        exit(1);
    }
    size_t written_total = 0;
    while (written_total < size)
    {
        size_t request = size - written_total;
        if (request > sizeof(buffer))
            request = sizeof(buffer);
        ssize_t written = write(fd, buffer, request);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
        {
            printf(RED "fixture: could not write large progress fixture" NC "\n");
            exit(1);
        }
        written_total += (size_t)written;
    }
    if (close(fd) != 0)
    {
        printf(RED "fixture: could not close large progress fixture" NC "\n");
        exit(1);
    }
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

static int run_backup_capturing_with_options(const char *target, BackupMode mode,
                                             char *const *paths, int include_self,
                                             int include_network_config,
                                             char *output, size_t output_size)
{
    int pipefd[2];
    if (pipe(pipefd) != 0)
    {
        perror("pipe");
        exit(1);
    }
    // Every check()/printf() so far in this process may still be sitting
    // unflushed in stdio's buffer (fully buffered, since stdout/stderr
    // aren't a tty here) -- fork() copies that buffer into the child, whose
    // own fflush() below would otherwise duplicate all of it into the pipe
    // this function is trying to capture as this one backup's own output.
    fflush(stdout);
    fflush(stderr);
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
        int rc = backup(target, mode, (char **)paths, include_self,
                        include_network_config);
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

static int run_backup_capturing(const char *target, BackupMode mode,
                                char *const *paths, char *output,
                                size_t output_size)
{
    return run_backup_capturing_with_options(target, mode, paths, 0, 0,
                                             output, output_size);
}

typedef struct {
    off_t previous;
    off_t estimated;
    size_t count;
    int monotonic;
    char expected_paths[2][PATH_MAX];
    size_t expected_path_count;
    unsigned int seen_paths;
    int paths_valid;
    struct timespec first_sample_time;
    struct timespec last_sample_time;
    off_t last_sample_bytes;
    double previous_elapsed_seconds;
    size_t timing_count;
    int timing_valid;
} BackupProgressTrace;

static void record_backup_progress(off_t bytes_copied, off_t estimated_total,
                                   const char *current_path, void *context)
{
    BackupProgressTrace *trace = context;
    if (trace == NULL)
        return;
    if (trace->count != 0 && bytes_copied < trace->previous)
        trace->monotonic = 0;
    trace->previous = bytes_copied;
    trace->estimated = estimated_total;

    size_t matched_path = trace->expected_path_count;
    for (size_t index = 0; index < trace->expected_path_count; index++)
    {
        if (current_path != NULL &&
            strcmp(current_path, trace->expected_paths[index]) == 0)
        {
            matched_path = index;
            break;
        }
    }
    if (matched_path == trace->expected_path_count)
        trace->paths_valid = 0;
    else
        trace->seen_paths |= 1U << matched_path;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        trace->timing_valid = 0;
    else
    {
        if (trace->timing_count == 0)
            trace->first_sample_time = now;
        double elapsed_seconds = timespec_elapsed_seconds(
            &trace->first_sample_time, &now);
        double sample_seconds = trace->timing_count == 0 ? 0.0
            : timespec_elapsed_seconds(&trace->last_sample_time, &now);
        off_t delta = bytes_copied > trace->last_sample_bytes
            ? bytes_copied - trace->last_sample_bytes : 0;
        double speed = sample_seconds > 0.0
            ? (double)delta / sample_seconds : 0.0;
        if (!isfinite(elapsed_seconds) || elapsed_seconds < 0.0 ||
            (trace->timing_count != 0 &&
             elapsed_seconds < trace->previous_elapsed_seconds) ||
            !isfinite(speed) || speed < 0.0)
            trace->timing_valid = 0;
        trace->previous_elapsed_seconds = elapsed_seconds;
        trace->last_sample_time = now;
        trace->last_sample_bytes = bytes_copied;
        trace->timing_count++;
    }
    trace->count++;
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
static int find_container_dir(const char *target, char *out, size_t out_size)
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

        join_path(out, out_size, target, e->d_name);
        found = 1;
        break;
    }
    closedir(d);
    return found;
}

static int find_partial_container_dir(const char *target, char *out,
                                      size_t out_size)
{
    DIR *d = opendir(target);
    if (d == NULL)
        return 0;

    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)) != NULL)
    {
        size_t len = strlen(e->d_name);
        if (strncmp(e->d_name, "migr_backup_", 12) != 0 ||
            len < 8 || strcmp(e->d_name + len - 8, ".partial") != 0)
            continue;

        join_path(out, out_size, target, e->d_name);
        found = 1;
        break;
    }
    closedir(d);
    return found;
}

static int find_payload_dir(const char *target, char *out, size_t out_size)
{
    char container[PATH_MAX];
    if (!find_container_dir(target, container, sizeof(container)))
        return 0;
    join_path(out, out_size, container, "data");
    return 1;
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

static void write_exact_at(int fd, const void *buf, size_t size, off_t offset)
{
    const unsigned char *bytes = buf;
    size_t done = 0;
    while (done < size)
    {
        ssize_t n = pwrite(fd, bytes + done, size - done,
                           offset + (off_t)done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
        {
            printf(RED "fixture: could not write static ELF sibling" NC "\n");
            exit(1);
        }
        done += (size_t)n;
    }
}

static void make_static_sibling_fixture(void)
{
    const char *path = "tests/migr-static";
    if (unlink(path) != 0 && errno != ENOENT)
    {
        printf(RED "fixture: could not remove stale tests/migr-static" NC "\n");
        exit(1);
    }

    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (fd < 0)
    {
        printf(RED "fixture: could not create tests/migr-static" NC "\n");
        exit(1);
    }

    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phoff = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 1;

    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;

    write_exact_at(fd, &ehdr, sizeof(ehdr), 0);
    write_exact_at(fd, &phdr, sizeof(phdr), (off_t)ehdr.e_phoff);
    if (close(fd) != 0)
    {
        printf(RED "fixture: could not close tests/migr-static" NC "\n");
        exit(1);
    }
}

static int files_are_equal(const char *a_path, const char *b_path)
{
    int a = open(a_path, O_RDONLY | O_CLOEXEC);
    int b = open(b_path, O_RDONLY | O_CLOEXEC);
    if (a < 0 || b < 0)
    {
        if (a >= 0) close(a);
        if (b >= 0) close(b);
        return 0;
    }

    unsigned char a_buf[4096], b_buf[4096];
    int equal = 1;
    for (;;)
    {
        ssize_t an;
        do { an = read(a, a_buf, sizeof(a_buf)); } while (an < 0 && errno == EINTR);
        ssize_t bn;
        do { bn = read(b, b_buf, sizeof(b_buf)); } while (bn < 0 && errno == EINTR);
        if (an < 0 || bn < 0 || an != bn)
        {
            equal = 0;
            break;
        }
        if (an == 0)
            break;
        if (memcmp(a_buf, b_buf, (size_t)an) != 0)
        {
            equal = 0;
            break;
        }
    }

    int a_close = close(a);
    int b_close = close(b);
    if (a_close != 0 || b_close != 0)
        equal = 0;
    return equal;
}

static void force_no_free_space(off_t needed, off_t *free_bytes, void *context)
{
    (void)needed;
    (void)context;
    *free_bytes = 0;
}

static void set_test_block_size(off_t *block_size, void *context)
{
    *block_size = *(const off_t *)context;
}

static void provide_free_space(off_t needed, off_t *free_bytes, void *context)
{
    (void)context;
    *free_bytes = needed + 1;
}

static void provide_fixed_free_space(off_t needed, off_t *free_bytes,
                                     void *context)
{
    (void)needed;
    *free_bytes = *(const off_t *)context;
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
    backup_plan_estimate_size(&plan, 0, &total, &had_error);
    check(had_error == 0, "a vanished root is not an estimation error");
    check(total == first_st.st_size,
          "a vanished root contributes zero to the estimated total");

    backup_plan_free(&plan);
    remove_tree(home);
}

#ifdef BACKUP_PLAN_TEST_HOOKS
static void rename_directory_out_from_under_its_open_fd(int parent_fd,
                                                         const char *name)
{
    if (strcmp(name, "subdir") != 0)
        return;
    backup_plan_test_set_dir_open_hook(NULL);

    if (renameat(parent_fd, name, parent_fd, "subdir-original") != 0)
    {
        printf(RED "fixture: could not stash the original directory during the race: %s" NC "\n",
              strerror(errno));
        exit(1);
    }
    if (mkdirat(parent_fd, name, 0700) != 0)
    {
        printf(RED "fixture: could not create the substitute directory during the race" NC "\n");
        exit(1);
    }
}

static void test_estimate_survives_ancestor_rename_mid_walk(void)
{
    printf(BLUE "::" NC " model: size estimation stays anchored to an already-opened "
                "directory across a mid-walk ancestor rename\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_race_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char root[PATH_MAX], subdir[PATH_MAX], grandchild[PATH_MAX];
    join_path(root, sizeof(root), home, "root");
    join_path(subdir, sizeof(subdir), root, "subdir");
    join_path(grandchild, sizeof(grandchild), subdir, "grandchild.txt");
    mkdir_p(subdir);
    write_file(grandchild, "grandchild payload");

    struct stat root_st, subdir_st, grandchild_st;
    check(lstat(root, &root_st) == 0 && lstat(subdir, &subdir_st) == 0 &&
              lstat(grandchild, &grandchild_st) == 0,
          "fixture: root/subdir/grandchild.txt is measurable before the race");
    off_t expected_total =
        root_st.st_size + subdir_st.st_size + grandchild_st.st_size;

    char *paths[] = { root, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                            (const char *const *)paths, &plan) == 0,
          "the ancestor-rename estimate fixture builds");

    backup_plan_test_set_dir_open_hook(
        rename_directory_out_from_under_its_open_fd);

    off_t total = -1;
    int had_error = -1;
    backup_plan_estimate_size(&plan, 0, &total, &had_error);

    check(had_error == 0,
          "a rename of an already-opened ancestor directory is not an estimation error");
    check(total == expected_total,
          "the estimate still reflects the original subtree, not whatever "
          "now occupies the renamed directory's old name");

    backup_plan_free(&plan);
    remove_tree(home);
}
#endif

static void test_allocation_aware_estimate(void)
{
    printf(BLUE "::" NC " model: size estimation rounds regular files and deduplicates hardlinks\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char first[PATH_MAX], second[PATH_MAX], hardlink_first[PATH_MAX];
    char hardlink_second[PATH_MAX];
    join_path(first, sizeof(first), home, "first");
    join_path(second, sizeof(second), home, "second");
    join_path(hardlink_first, sizeof(hardlink_first), home, "hard-a");
    join_path(hardlink_second, sizeof(hardlink_second), home, "hard-b");
    write_large_file(first, 3);
    write_large_file(second, 5);
    write_large_file(hardlink_first, 7);
    check(link(hardlink_first, hardlink_second) == 0,
          "fixture: create a hardlinked estimate pair");

    char *paths[] = { first, second, hardlink_first, hardlink_second, NULL };
    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                            (const char *const *)paths, &plan) == 0,
          "the allocation estimate fixture builds");

    off_t total = -1;
    int had_error = -1;
    backup_plan_estimate_size(&plan, 4, &total, &had_error);
    check(had_error == 0 && total == 20,
          "rounded regular files and the hardlinked pair contribute once");

    backup_plan_estimate_size(&plan, 0, &total, &had_error);
    check(had_error == 0 && total == 15,
          "block size zero disables rounding but keeps hardlink deduplication");
    backup_plan_estimate_size(&plan, 1, &total, &had_error);
    check(had_error == 0 && total == 15,
          "block size one disables rounding but keeps hardlink deduplication");
    backup_plan_free(&plan);

    char dense_dir[PATH_MAX], dense_seed[PATH_MAX];
    join_path(dense_dir, sizeof(dense_dir), home, "dense-hardlinks");
    if (mkdir(dense_dir, 0755) != 0)
    {
        printf(RED "fixture: could not create %s" NC "\n", dense_dir);
        exit(1);
    }
    join_path(dense_seed, sizeof(dense_seed), dense_dir, "seed");
    write_large_file(dense_seed, 11);
    enum { DENSE_HARDLINK_COUNT = 40 };
    for (int index = 0; index < DENSE_HARDLINK_COUNT; index++)
    {
        char name[32], link_path[PATH_MAX];
        snprintf(name, sizeof(name), "link-%02d", index);
        join_path(link_path, sizeof(link_path), dense_dir, name);
        if (link(dense_seed, link_path) != 0)
        {
            printf(RED "fixture: could not create dense hardlink %s" NC "\n",
                   link_path);
            exit(1);
        }
    }

    char *dense_paths[] = { dense_dir, NULL };
    BackupPlan dense_plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                            (const char *const *)dense_paths,
                            &dense_plan) == 0,
          "the dense hardlink estimate fixture builds");
    struct stat dense_dir_st, dense_seed_st;
    check(lstat(dense_dir, &dense_dir_st) == 0 &&
              lstat(dense_seed, &dense_seed_st) == 0,
          "the dense hardlink fixture can be measured");
    backup_plan_estimate_size(&dense_plan, 0, &total, &had_error);
    check(had_error == 0 &&
              total == dense_dir_st.st_size + dense_seed_st.st_size,
          "the estimate hash set finds entries across a capacity rehash");
    backup_plan_free(&dense_plan);

    off_t injected_block_size = 4;
    backup_test_set_block_size_hook(set_test_block_size, &injected_block_size);
    backup_test_set_free_space_hook(provide_free_space, NULL);
    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "plan_target_parent");
    char target[PATH_MAX];
    join_path(target, sizeof(target), target_parent, "allocation-aware");
    dry_run = 0;
    char output[8192];
    backup_test_set_progress_hook(record_backup_progress, NULL);
    int result = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
    backup_test_set_progress_hook(NULL, NULL);
    check(result == 0 && strstr(output, "Estimated backup size: 15B") != NULL &&
              strstr(output, "Estimated backup size: 20B") == NULL,
          "backup() displays the raw source estimate");
    check(result == 0 && strstr(output, "\rProgress: 15B/15B copied") != NULL,
          "live progress uses the raw source total");

    dry_run = 1;
    char dry_output[8192];
    int dry_result = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                          paths, dry_output,
                                          sizeof(dry_output));
    dry_run = 0;
    check(dry_result == 0 &&
              strstr(dry_output, "Estimated backup size: 15B") != NULL &&
              strstr(dry_output, "Estimated backup size: 20B") == NULL,
          "dry-run displays the raw source estimate");

    off_t raw_free_bytes = 15;
    backup_test_set_free_space_hook(provide_fixed_free_space,
                                    &raw_free_bytes);
    char fit_target[PATH_MAX];
    join_path(fit_target, sizeof(fit_target), target_parent,
              "rounded-fit-check");
    char fit_output[8192];
    int fit_result = run_backup_capturing(fit_target, BACKUP_EXPLICIT_PATHS,
                                          paths, fit_output,
                                          sizeof(fit_output));
    backup_test_set_block_size_hook(NULL, NULL);
    backup_test_set_free_space_hook(NULL, NULL);
    check(fit_result == 1 &&
              strstr(fit_output, "Estimated backup size: 15B") != NULL &&
              strstr(fit_output, "Destination free space: 15B") != NULL &&
              strstr(fit_output, "need 5B more") != NULL,
          "the free-space fit check still uses the rounded estimate");

    remove_tree(home);
    remove_tree(target_parent);
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

    off_t no_rounding_block_size = 1;
    backup_test_set_block_size_hook(set_test_block_size,
                                    &no_rounding_block_size);
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
          strstr(live_output, "Destination free space:") != NULL,
          "the refusal keeps both absolute space summaries");
    check(strstr(live_output, "Error: not enough free space at") != NULL,
          "the refusal names the destination");
    check(strstr(live_output, "(need ") != NULL &&
          strstr(live_output, shortfall_text) != NULL &&
          strstr(live_output, " more)") != NULL,
          "the refusal reports the additional space required");
    check(strstr(live_output, ", have ") == NULL,
          "the refusal does not repeat the absolute free-space value");
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

    backup_test_set_block_size_hook(NULL, NULL);
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

static void test_include_self_backup(void)
{
    printf(BLUE "::" NC " production: --include-self validates, copies, records, and dry-runs\n");

    if (unlink("tests/migr-static") != 0 && errno != ENOENT)
    {
        printf(RED "fixture: could not remove tests/migr-static" NC "\n");
        exit(1);
    }

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_self_home");
    setenv("HOME", home, 1);
    char source[PATH_MAX];
    join_path(source, sizeof(source), home, "source.txt");
    write_file(source, "self-copy payload");
    char *paths[] = { source, NULL };

    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "plan_self_target_parent");
    char missing_target[PATH_MAX];
    join_path(missing_target, sizeof(missing_target), target_parent, "missing-static");
    dry_run = 0;
    char missing_output[8192];
    int missing_rc = run_backup_capturing_with_options(
        missing_target, BACKUP_EXPLICIT_PATHS, paths, 1, 0,
        missing_output, sizeof(missing_output));
    check(missing_rc == 1 && !dir_exists(missing_target),
          "an absent migr-static fails before creating a destination container");
    check(strstr(missing_output, "make migr-static") != NULL,
          "the missing-static refusal tells the user how to build it");

    make_static_sibling_fixture();

    char live_target[PATH_MAX];
    fresh_mkdtemp(live_target, sizeof(live_target), "plan_self_live");
    char live_output[8192];
    int live_rc = run_backup_capturing_with_options(
        live_target, BACKUP_EXPLICIT_PATHS, paths, 1, 0,
        live_output, sizeof(live_output));
    char container[PATH_MAX];
    int have_container = find_container_dir(live_target, container,
                                             sizeof(container));
    check(live_rc == 0 && have_container,
          "a valid static sibling produces a finalized include-self backup");

    if (have_container)
    {
        char copied[PATH_MAX];
        join_path(copied, sizeof(copied), container, "migr");
        check(files_are_equal("tests/migr-static", copied),
              "the container-root migr is byte-identical to the validated source binary");

        Manifest manifest;
        ManifestStatus status = manifest_read_v1(container, &manifest);
        check(status == MANIFEST_STATUS_VALID,
              "the include-self backup manifest remains valid");
        if (status == MANIFEST_STATUS_VALID)
        {
            check(manifest.has_self_binary == 1 &&
                      strcmp(manifest.arch, "x86_64") == 0,
                  "the manifest records the copied binary architecture");
            manifest_free(&manifest);
        }
    }

    char dry_target[PATH_MAX];
    fresh_mkdtemp(dry_target, sizeof(dry_target), "plan_self_dry");
    dry_run = 1;
    char dry_output[8192];
    int dry_rc = run_backup_capturing_with_options(
        dry_target, BACKUP_EXPLICIT_PATHS, paths, 1, 0,
        dry_output, sizeof(dry_output));
    dry_run = 0;
    check(dry_rc == 0 && directory_empty(dry_target),
          "an include-self dry run writes nothing to the destination");
    check(strstr(dry_output,
                 "Would copy migr-static (x86_64) to the container root as migr") != NULL,
          "the dry run reports the binary and architecture it would copy");

    if (unlink("tests/migr-static") != 0 && errno != ENOENT)
    {
        printf(RED "fixture: could not remove tests/migr-static" NC "\n");
        exit(1);
    }
    remove_tree(home);
    remove_tree(target_parent);
    remove_tree(live_target);
    remove_tree(dry_target);
}

static void test_include_network_config_backup(void)
{
    printf(BLUE "::" NC " production: --include-network-config handles multiple network backends\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_network_home");
    setenv("HOME", home, 1);
    char source[PATH_MAX];
    join_path(source, sizeof(source), home, "source.txt");
    write_file(source, "network-copy payload");
    char *paths[] = { source, NULL };

    char missing_nm[PATH_MAX], missing_netplan[PATH_MAX], missing_networkd[PATH_MAX];
    join_path(missing_nm, sizeof(missing_nm), home, "missing-networkmanager");
    join_path(missing_netplan, sizeof(missing_netplan), home, "missing-netplan");
    join_path(missing_networkd, sizeof(missing_networkd), home,
              "missing-systemd-networkd");

    backup_test_set_network_config_source_dir("wpa_supplicant", missing_nm);
    backup_test_set_network_config_source_dir("netctl", missing_nm);

    char network_source[PATH_MAX];
    fresh_mkdtemp(network_source, sizeof(network_source), "plan_network_source");
    char wifi[PATH_MAX], vpn[PATH_MAX], link[PATH_MAX], fifo[PATH_MAX];
    char denied_dir[PATH_MAX];
    join_path(wifi, sizeof(wifi), network_source, "home.nmconnection");
    join_path(vpn, sizeof(vpn), network_source, "work-vpn.nmconnection");
    join_path(link, sizeof(link), network_source, "linked.nmconnection");
    join_path(fifo, sizeof(fifo), network_source, "runtime.lock");
    join_path(denied_dir, sizeof(denied_dir), network_source, "private-state");
    write_file(wifi, "[wifi-security]\npsk=not-a-real-password\n");
    write_file(vpn, "[vpn]\nservice-type=fixture\n");
    if (chmod(wifi, 0600) != 0 || chmod(vpn, 0640) != 0 ||
        symlink("home.nmconnection", link) != 0 || mkfifo(fifo, 0600) != 0 ||
        mkdir(denied_dir, 0700) != 0 ||
        (geteuid() != 0 && chmod(denied_dir, 0000) != 0))
    {
        printf(RED "fixture: could not prepare network configuration source" NC "\n");
        exit(1);
    }
    backup_test_set_network_config_source_dir("NetworkManager", network_source);
    backup_test_set_network_config_source_dir("netplan", missing_netplan);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              missing_networkd);

    char live_target[PATH_MAX];
    fresh_mkdtemp(live_target, sizeof(live_target), "plan_network_live");
    dry_run = 0;
    char live_output[8192];
    int live_rc = run_backup_capturing_with_options(
        live_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        live_output, sizeof(live_output));

    char container[PATH_MAX];
    int have_container = find_container_dir(live_target, container,
                                             sizeof(container));
    check(live_rc == 0 && have_container,
          "a readable synthetic NetworkManager directory produces a finalized backup");

    if (have_container)
    {
        char network_dir[PATH_MAX], nm_dir[PATH_MAX];
        char copied_wifi[PATH_MAX], copied_vpn[PATH_MAX];
        char skipped_link[PATH_MAX], skipped_fifo[PATH_MAX], skipped_denied_dir[PATH_MAX];
        join_path(network_dir, sizeof(network_dir), container, "network");
        join_path(nm_dir, sizeof(nm_dir), network_dir, "networkmanager");
        join_path(copied_wifi, sizeof(copied_wifi), nm_dir,
                  "home.nmconnection");
        join_path(copied_vpn, sizeof(copied_vpn), nm_dir,
                  "work-vpn.nmconnection");
        join_path(skipped_link, sizeof(skipped_link), nm_dir,
                  "linked.nmconnection");
        join_path(skipped_fifo, sizeof(skipped_fifo), nm_dir,
                  "runtime.lock");
        join_path(skipped_denied_dir, sizeof(skipped_denied_dir), nm_dir,
                  "private-state");

        check(files_are_equal(wifi, copied_wifi) &&
                  files_are_equal(vpn, copied_vpn),
              "NetworkManager files are copied byte-for-byte under network/networkmanager/");

        struct stat source_st, copied_st;
        int source_mode_ok = stat(wifi, &source_st) == 0;
        int copied_mode_ok = stat(copied_wifi, &copied_st) == 0;
        check(source_mode_ok && copied_mode_ok &&
                  (source_st.st_mode & 0777) == (copied_st.st_mode & 0777),
              "connection-file mode bits are preserved on a native destination");

        struct stat skipped_st;
        check(lstat(skipped_link, &skipped_st) != 0 && errno == ENOENT,
              "a symlinked connection entry is not followed or copied");
        check(lstat(skipped_fifo, &skipped_st) != 0 && errno == ENOENT,
              "a non-regular connection entry is skipped");
        check(lstat(skipped_denied_dir, &skipped_st) != 0 && errno == ENOENT,
              "an unreadable non-regular entry is classified and skipped");

        Manifest manifest;
        ManifestStatus status = manifest_read_v1(container, &manifest);
        check(status == MANIFEST_STATUS_VALID,
              "the network-config backup manifest remains valid");
        if (status == MANIFEST_STATUS_VALID)
        {
            check(manifest.has_network_config == 1,
                  "the manifest records NETWORK_CONFIG=1");
            manifest_free(&manifest);
        }
    }

    check(strstr(live_output, "WiFi passwords") != NULL &&
              strstr(live_output, "plain text") != NULL &&
              strstr(live_output, "Captured NetworkManager") != NULL &&
              strstr(live_output, "/network/") != NULL,
          "NetworkManager completion names the backend and warns about plaintext secrets");
    check(strstr(live_output, "skipping symbolic link") != NULL &&
              strstr(live_output, "skipping non-regular") != NULL,
          "odd source entries are reported and skipped");

    char empty_source[PATH_MAX];
    fresh_mkdtemp(empty_source, sizeof(empty_source), "plan_network_empty_source");
    backup_test_set_network_config_source_dir("NetworkManager", empty_source);
    backup_test_set_network_config_source_dir("netplan", missing_netplan);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              missing_networkd);
    char empty_target[PATH_MAX];
    fresh_mkdtemp(empty_target, sizeof(empty_target), "plan_network_empty_target");
    char empty_output[8192];
    int empty_rc = run_backup_capturing_with_options(
        empty_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        empty_output, sizeof(empty_output));
    char empty_container[PATH_MAX], empty_network[PATH_MAX], empty_nm[PATH_MAX];
    int have_empty_container = find_container_dir(
        empty_target, empty_container, sizeof(empty_container));
    if (have_empty_container)
    {
        join_path(empty_network, sizeof(empty_network), empty_container, "network");
        join_path(empty_nm, sizeof(empty_nm), empty_network, "networkmanager");
    }
    check(empty_rc == 0 && have_empty_container && dir_exists(empty_network) &&
              dir_exists(empty_nm) && directory_empty(empty_nm),
          "an empty readable backend creates its empty subdirectory and still succeeds");
    if (have_empty_container)
    {
        Manifest manifest;
        ManifestStatus status = manifest_read_v1(empty_container, &manifest);
        check(status == MANIFEST_STATUS_VALID &&
                  manifest.has_network_config == 1,
              "an empty readable backend is still recorded as NETWORK_CONFIG=1");
        if (status == MANIFEST_STATUS_VALID)
            manifest_free(&manifest);
    }

    backup_test_set_network_config_source_dir("NetworkManager", missing_nm);
    backup_test_set_network_config_source_dir("netplan", missing_netplan);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              missing_networkd);
    char missing_target[PATH_MAX];
    fresh_mkdtemp(missing_target, sizeof(missing_target), "plan_network_missing");
    char missing_output[8192];
    int missing_rc = run_backup_capturing_with_options(
        missing_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        missing_output, sizeof(missing_output));
    char missing_container[PATH_MAX], missing_network[PATH_MAX];
    int have_missing_container = find_container_dir(
        missing_target, missing_container, sizeof(missing_container));
    if (have_missing_container)
        join_path(missing_network, sizeof(missing_network), missing_container,
                  "network");
    struct stat missing_network_st;
    check(missing_rc == 0 && have_missing_container &&
              lstat(missing_network, &missing_network_st) != 0 &&
              errno == ENOENT,
          "all-ENOENT backends still produce a successful backup with no network/");
    if (have_missing_container)
    {
        Manifest manifest;
        ManifestStatus status = manifest_read_v1(missing_container, &manifest);
        check(status == MANIFEST_STATUS_VALID &&
                  manifest.has_network_config == 0,
              "all-ENOENT backends leave NETWORK_CONFIG unset");
        if (status == MANIFEST_STATUS_VALID)
            manifest_free(&manifest);
    }
    check(strstr(missing_output, "found no network configuration") != NULL &&
              strstr(missing_output,
                     "NetworkManager, netplan, systemd-networkd, wpa_supplicant and netctl") != NULL,
          "all-ENOENT completion reports that no supported backend was found");

    if (geteuid() != 0)
    {
        char denied_source[PATH_MAX];
        fresh_mkdtemp(denied_source, sizeof(denied_source), "plan_network_denied");
        if (chmod(denied_source, 0000) != 0)
        {
            printf(RED "fixture: could not restrict network source" NC "\n");
            exit(1);
        }
        backup_test_set_network_config_source_dir("NetworkManager", denied_source);
        backup_test_set_network_config_source_dir("netplan", missing_netplan);
        backup_test_set_network_config_source_dir("systemd-networkd",
                                                  missing_networkd);
        char denied_target[PATH_MAX];
        fresh_mkdtemp(denied_target, sizeof(denied_target), "plan_network_denied_target");
        char denied_output[8192];
        int denied_rc = run_backup_capturing_with_options(
            denied_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
            denied_output, sizeof(denied_output));
        check(denied_rc == 1 && directory_empty(denied_target),
              "an unreadable backend still refuses when the other backends are absent");
        check(strstr(denied_output, "NetworkManager") != NULL &&
                  strstr(denied_output, "Root privileges are required") != NULL,
              "the permission refusal names the backend and required privilege");
        chmod(denied_source, 0700);
        remove_tree(denied_source);
        remove_tree(denied_target);
    }

    if (geteuid() != 0)
    {
        char failing_source[PATH_MAX];
        fresh_mkdtemp(failing_source, sizeof(failing_source),
                      "plan_network_copy_failure_source");
        char unreadable[PATH_MAX];
        join_path(unreadable, sizeof(unreadable), failing_source,
                  "unreadable.nmconnection");
        write_file(unreadable, "[connection]\nid=fixture\n");
        if (chmod(unreadable, 0000) != 0)
        {
            printf(RED "fixture: could not restrict network file" NC "\n");
            exit(1);
        }

        backup_test_set_network_config_source_dir("NetworkManager", failing_source);
        backup_test_set_network_config_source_dir("netplan", missing_netplan);
        backup_test_set_network_config_source_dir("systemd-networkd",
                                                  missing_networkd);
        char failing_target[PATH_MAX];
        fresh_mkdtemp(failing_target, sizeof(failing_target),
                      "plan_network_copy_failure_target");
        char failing_output[8192];
        int failing_rc = run_backup_capturing_with_options(
            failing_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
            failing_output, sizeof(failing_output));

        char partial[PATH_MAX], partial_network[PATH_MAX];
        int have_partial = find_partial_container_dir(
            failing_target, partial, sizeof(partial));
        if (have_partial)
            join_path(partial_network, sizeof(partial_network), partial, "network");
        struct stat network_st;
        check(failing_rc == 1 && have_partial &&
                  lstat(partial_network, &network_st) != 0 && errno == ENOENT,
              "a per-file copy failure removes network/ from the resumable partial");
        check(strstr(failing_output, "unreadable.nmconnection") != NULL,
              "a per-file copy failure names the connection file that failed");

        chmod(unreadable, 0600);
        remove_tree(failing_source);
        remove_tree(failing_target);
    }

    char netplan_source[PATH_MAX];
    fresh_mkdtemp(netplan_source, sizeof(netplan_source),
                  "plan_network_netplan_source");
    char netplan_yaml[PATH_MAX];
    join_path(netplan_yaml, sizeof(netplan_yaml), netplan_source,
              "00-installer-config.yaml");
    write_file(netplan_yaml,
               "network:\n  wifis:\n    wlan0:\n      password: fixture-secret\n");
    backup_test_set_network_config_source_dir("NetworkManager", missing_nm);
    backup_test_set_network_config_source_dir("netplan", netplan_source);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              missing_networkd);
    char netplan_target[PATH_MAX];
    fresh_mkdtemp(netplan_target, sizeof(netplan_target),
                  "plan_network_netplan_target");
    char netplan_output[8192];
    int netplan_rc = run_backup_capturing_with_options(
        netplan_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        netplan_output, sizeof(netplan_output));
    char netplan_container[PATH_MAX], copied_netplan[PATH_MAX];
    int have_netplan_container = find_container_dir(
        netplan_target, netplan_container, sizeof(netplan_container));
    if (have_netplan_container)
    {
        char netplan_dir[PATH_MAX];
        join_path(netplan_dir, sizeof(netplan_dir), netplan_container,
                  "network/netplan");
        join_path(copied_netplan, sizeof(copied_netplan), netplan_dir,
                  "00-installer-config.yaml");
    }
    check(netplan_rc == 0 && have_netplan_container &&
              files_are_equal(netplan_yaml, copied_netplan),
          "a netplan-only source is captured under network/netplan/");
    if (have_netplan_container)
    {
        Manifest manifest;
        ManifestStatus status = manifest_read_v1(netplan_container, &manifest);
        check(status == MANIFEST_STATUS_VALID &&
                  manifest.has_network_config == 1,
              "a netplan-only backup records NETWORK_CONFIG=1");
        if (status == MANIFEST_STATUS_VALID)
            manifest_free(&manifest);
    }
    check(strstr(netplan_output, "Captured netplan") != NULL &&
              strstr(netplan_output, "WiFi passwords") != NULL &&
              strstr(netplan_output, "plain text") != NULL,
          "netplan completion names netplan and warns about plaintext secrets");

    char networkd_source[PATH_MAX];
    fresh_mkdtemp(networkd_source, sizeof(networkd_source),
                  "plan_network_networkd_source");
    char networkd_file[PATH_MAX];
    join_path(networkd_file, sizeof(networkd_file), networkd_source,
              "20-wired.network");
    write_file(networkd_file, "[Match]\nName=en*\n[Network]\nDHCP=yes\n");
    backup_test_set_network_config_source_dir("NetworkManager", missing_nm);
    backup_test_set_network_config_source_dir("netplan", missing_netplan);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              networkd_source);
    char networkd_target[PATH_MAX];
    fresh_mkdtemp(networkd_target, sizeof(networkd_target),
                  "plan_network_networkd_target");
    char networkd_output[8192];
    int networkd_rc = run_backup_capturing_with_options(
        networkd_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        networkd_output, sizeof(networkd_output));
    char networkd_container[PATH_MAX], copied_networkd[PATH_MAX];
    int have_networkd_container = find_container_dir(
        networkd_target, networkd_container, sizeof(networkd_container));
    if (have_networkd_container)
    {
        char networkd_dir[PATH_MAX];
        join_path(networkd_dir, sizeof(networkd_dir), networkd_container,
                  "network/systemd-networkd");
        join_path(copied_networkd, sizeof(copied_networkd), networkd_dir,
                  "20-wired.network");
    }
    check(networkd_rc == 0 && have_networkd_container &&
              files_are_equal(networkd_file, copied_networkd),
          "a systemd-networkd-only source is captured under network/systemd-networkd/");
    if (have_networkd_container)
    {
        Manifest manifest;
        ManifestStatus status = manifest_read_v1(networkd_container, &manifest);
        check(status == MANIFEST_STATUS_VALID &&
                  manifest.has_network_config == 1,
              "a systemd-networkd-only backup records NETWORK_CONFIG=1");
        if (status == MANIFEST_STATUS_VALID)
            manifest_free(&manifest);
    }
    check(strstr(networkd_output, "Captured systemd-networkd") != NULL &&
              strstr(networkd_output, "WiFi passwords") != NULL &&
              strstr(networkd_output, "VPN keys") != NULL,
          "systemd-networkd-only completion warns about plaintext secrets "
          "(networkd .netdev files can hold a WireGuard private key)");

    backup_test_set_network_config_source_dir("NetworkManager", network_source);
    backup_test_set_network_config_source_dir("netplan", netplan_source);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              networkd_source);
    char all_target[PATH_MAX];
    fresh_mkdtemp(all_target, sizeof(all_target), "plan_network_all_target");
    char all_output[8192];
    int all_rc = run_backup_capturing_with_options(
        all_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        all_output, sizeof(all_output));
    char all_container[PATH_MAX], all_nm[PATH_MAX], all_netplan[PATH_MAX];
    char all_networkd[PATH_MAX];
    int have_all_container = find_container_dir(
        all_target, all_container, sizeof(all_container));
    if (have_all_container)
    {
        join_path(all_nm, sizeof(all_nm), all_container,
                  "network/networkmanager");
        join_path(all_netplan, sizeof(all_netplan), all_container,
                  "network/netplan");
        join_path(all_networkd, sizeof(all_networkd), all_container,
                  "network/systemd-networkd");
    }
    check(all_rc == 0 && have_all_container && dir_exists(all_nm) &&
              dir_exists(all_netplan) && dir_exists(all_networkd),
          "all three present backends produce all three network subdirectories");
    check(strstr(all_output,
                 "Captured NetworkManager, netplan and systemd-networkd") != NULL,
          "completion enumerates every backend that was captured");

    char wpa_source[PATH_MAX], netctl_source[PATH_MAX];
    join_path(wpa_source, sizeof(wpa_source), home, "wpa_supplicant");
    join_path(netctl_source, sizeof(netctl_source), home, "netctl");
    mkdir_p(wpa_source);
    mkdir_p(netctl_source);
    char wpa_conf[PATH_MAX], wpa_iface_conf[PATH_MAX], netctl_profile[PATH_MAX];
    join_path(wpa_conf, sizeof(wpa_conf), wpa_source, "wpa_supplicant.conf");
    join_path(wpa_iface_conf, sizeof(wpa_iface_conf), wpa_source, "wpa_supplicant-wlan0.conf");
    join_path(netctl_profile, sizeof(netctl_profile), netctl_source, "home-wifi");
    write_file(wpa_conf, "network={psk=\"fixture-secret\"}\n");
    write_file(wpa_iface_conf, "network={ssid=\"fixture\"}\n");
    write_file(netctl_profile, "Interface=wlan0\nKey=fixture-secret\n");
    const char *excluded[] = { "functions.sh", "a", "old.conf.bak" };
    for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++)
    {
        char helper[PATH_MAX];
        join_path(helper, sizeof(helper), wpa_source, excluded[i]);
        write_file(helper, "package helper");
        if (chmod(helper, 0000) != 0)
            exit(1);
    }
    char hooks[PATH_MAX], hook_file[PATH_MAX];
    join_path(hooks, sizeof(hooks), netctl_source, "hooks");
    mkdir_p(hooks);
    join_path(hook_file, sizeof(hook_file), hooks, "helper");
    write_file(hook_file, "hook body");

    const char *backend_names[] = { "NetworkManager", "netplan", "systemd-networkd",
                                    "wpa_supplicant", "netctl" };
    const char *backend_subdirs[] = { "networkmanager", "netplan", "systemd-networkd",
                                      "wpa_supplicant", "netctl" };
    const char *backend_sources[] = { network_source, netplan_source, networkd_source,
                                      wpa_source, netctl_source };
    const char *backend_files[] = { "home.nmconnection", "00-installer-config.yaml",
                                    "20-wired.network", "wpa_supplicant.conf", "home-wifi" };
    const size_t backend_count = sizeof(backend_names) / sizeof(backend_names[0]);
    for (size_t scenario = 3; scenario <= backend_count; scenario++)
    {
        for (size_t i = 0; i < backend_count; i++)
            backup_test_set_network_config_source_dir(
                backend_names[i], scenario == backend_count || scenario == i ?
                backend_sources[i] : missing_nm);
        char target[PATH_MAX], output[8192], captured[PATH_MAX];
        fresh_mkdtemp(target, sizeof(target), "plan_network_extended");
        int rc = run_backup_capturing_with_options(
            target, BACKUP_EXPLICIT_PATHS, paths, 0, 1, output, sizeof(output));
        int have_captured = find_container_dir(target, captured, sizeof(captured));
        check(rc == 0 && have_captured, "new backends produce a finalized backup");
        if (have_captured)
        {
            char network[PATH_MAX];
            join_path(network, sizeof(network), captured, "network");
            for (size_t i = 0; i < backend_count; i++)
            {
                char dir[PATH_MAX], copied[PATH_MAX], original[PATH_MAX];
                join_path(dir, sizeof(dir), network, backend_subdirs[i]);
                join_path(copied, sizeof(copied), dir, backend_files[i]);
                join_path(original, sizeof(original), backend_sources[i], backend_files[i]);
                if (scenario == backend_count || scenario == i)
                    check(dir_exists(dir) && files_are_equal(original, copied),
                          "each present backend gets its own directory and exact saved bytes");
                else
                    check(access(dir, F_OK) != 0,
                          "absent backends do not acquire a captured directory");
            }
            if (scenario == 3 || scenario == backend_count)
            {
                char dir[PATH_MAX], copied[PATH_MAX];
                join_path(dir, sizeof(dir), network, "wpa_supplicant");
                join_path(copied, sizeof(copied), dir, "wpa_supplicant-wlan0.conf");
                check(files_are_equal(wpa_iface_conf, copied),
                      "interface-specific wpa_supplicant configuration is captured");
                for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++)
                {
                    join_path(copied, sizeof(copied), dir, excluded[i]);
                    check(access(copied, F_OK) != 0,
                          "non-conf files, including short names and backup suffixes, are excluded");
                }
                check(strstr(output, "skipping non-configuration file") != NULL,
                      "wpa_supplicant reports excluded package helper files");
            }
            if (scenario == 4 || scenario == backend_count)
            {
                char copied_hooks[PATH_MAX];
                join_path(copied_hooks, sizeof(copied_hooks), network, "netctl/hooks");
                check(access(copied_hooks, F_OK) != 0 &&
                      strstr(output, "skipping non-regular network configuration entry: hooks") != NULL,
                      "netctl hooks are skipped as a directory rather than captured recursively");
            }
            Manifest manifest;
            ManifestStatus status = manifest_read_v1(captured, &manifest);
            check(status == MANIFEST_STATUS_VALID && manifest.has_network_config == 1,
                  "new backend captures record NETWORK_CONFIG=1");
            if (status == MANIFEST_STATUS_VALID)
                manifest_free(&manifest);
        }
        check(strstr(output, "WiFi passwords") != NULL && strstr(output, "plain text") != NULL,
              "both new backends warn that saved files may contain plaintext secrets");
        if (scenario == backend_count)
            check(strstr(output, "Captured NetworkManager, netplan, systemd-networkd, "
                                "wpa_supplicant and netctl under ") != NULL,
                  "five-backend completion uses commas and a final conjunction");
        else
        {
            char expected[128];
            snprintf(expected, sizeof(expected), "Captured %s under ", backend_names[scenario]);
            check(strstr(output, expected) != NULL, "single-backend completion names only that backend");
        }
        remove_tree(target);
    }
    for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++)
    {
        char helper[PATH_MAX];
        join_path(helper, sizeof(helper), wpa_source, excluded[i]);
        if (chmod(helper, 0600) != 0)
            exit(1);
    }
    backup_test_set_network_config_source_dir("wpa_supplicant", missing_nm);
    backup_test_set_network_config_source_dir("netctl", missing_nm);

    backup_test_set_network_config_source_dir("NetworkManager", network_source);
    backup_test_set_network_config_source_dir("netplan", missing_netplan);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              missing_networkd);
    char dry_target[PATH_MAX];
    fresh_mkdtemp(dry_target, sizeof(dry_target), "plan_network_dry");
    dry_run = 1;
    char dry_output[8192];
    int dry_rc = run_backup_capturing_with_options(
        dry_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        dry_output, sizeof(dry_output));
    dry_run = 0;
    check(dry_rc == 0 && directory_empty(dry_target),
          "an include-network-config dry run writes nothing");
    check(strstr(dry_output,
                 "Would capture network configuration from NetworkManager under network/") != NULL,
          "the dry run previews the backend that would be captured");

    backup_test_set_network_config_source_dir("NetworkManager", NULL);
    backup_test_set_network_config_source_dir("netplan", NULL);
    backup_test_set_network_config_source_dir("systemd-networkd", NULL);
    backup_test_set_network_config_source_dir("wpa_supplicant", NULL);
    backup_test_set_network_config_source_dir("netctl", NULL);
    if (geteuid() != 0)
        chmod(denied_dir, 0700);
    remove_tree(home);
    remove_tree(network_source);
    remove_tree(live_target);
    remove_tree(empty_source);
    remove_tree(empty_target);
    remove_tree(missing_target);
    remove_tree(netplan_source);
    remove_tree(netplan_target);
    remove_tree(networkd_source);
    remove_tree(networkd_target);
    remove_tree(all_target);
    remove_tree(dry_target);
}

static void test_format_duration(void)
{
    printf(BLUE "::" NC " utility: duration formatting for progress output\n");
    char formatted[32];
    format_duration(0, formatted, sizeof(formatted));
    check(strcmp(formatted, "00:00") == 0, "zero seconds format as 00:00");
    format_duration(59, formatted, sizeof(formatted));
    check(strcmp(formatted, "00:59") == 0, "sub-minute durations keep mm:ss");
    format_duration(60, formatted, sizeof(formatted));
    check(strcmp(formatted, "01:00") == 0, "one minute formats as 01:00");
    format_duration(3599, formatted, sizeof(formatted));
    check(strcmp(formatted, "59:59") == 0, "under an hour formats as mm:ss");
    format_duration(3600, formatted, sizeof(formatted));
    check(strcmp(formatted, "1:00:00") == 0, "one hour formats as h:mm:ss");
    format_duration(7322, formatted, sizeof(formatted));
    check(strcmp(formatted, "2:02:02") == 0,
          "multi-hour durations preserve minute and second padding");
}

static void test_live_progress(void)
{
    printf(BLUE "::" NC " production: live backup progress is chunked, final-flushed, and tty-gated\n");
    enum { PROGRESS_SIZE = 1048576 };
    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "progress_home");
    mkdir_p(home);
    setenv("HOME", home, 1);

    char source[PATH_MAX], second_source[PATH_MAX];
    join_path(source, sizeof(source), home, "large.bin");
    join_path(second_source, sizeof(second_source), home, "small.bin");
    write_large_file(source, PROGRESS_SIZE);
    const char second_contents[] = "small progress\n";
    write_file(second_source, second_contents);
    char *paths[] = { source, second_source, NULL };
    off_t expected_total = PROGRESS_SIZE + (off_t)strlen(second_contents);

    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "progress_target_parent");
    char target[PATH_MAX];
    join_path(target, sizeof(target), target_parent, "with_progress");

    BackupProgressTrace *trace = mmap(NULL, sizeof(*trace),
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (trace == MAP_FAILED)
    {
        printf(RED "fixture: could not create shared progress trace" NC "\n");
        exit(1);
    }
    *trace = (BackupProgressTrace){
        .monotonic = 1,
        .paths_valid = 1,
        .timing_valid = 1
    };
    trace->expected_path_count = 2;
    snprintf(trace->expected_paths[0], sizeof(trace->expected_paths[0]),
             "%s", source);
    snprintf(trace->expected_paths[1], sizeof(trace->expected_paths[1]),
             "%s", second_source);
    backup_test_set_progress_hook(record_backup_progress, trace);
    dry_run = 0;
    char output[16384];
    int result = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
    backup_test_set_progress_hook(NULL, NULL);
    check(result == 0, "a multi-chunk live backup succeeds with progress enabled");
    check(trace->count >= 3 && trace->monotonic &&
              trace->previous == expected_total &&
              trace->estimated == expected_total && trace->paths_valid &&
              trace->seen_paths == 3 && trace->timing_valid &&
              trace->timing_count >= 3,
          "progress is monotonic and final-flushed at the estimated total");
    check(strstr(output, "\rProgress:") != NULL &&
              strstr(output, "\n\nFinalizing (syncing to disk)...") != NULL &&
              strstr(output, "Packages") == NULL &&
              strstr(output, "package list") == NULL,
          "progress overwrites in place and explicit backups omit package output");
    check(strstr(output, source) != NULL &&
              strstr(output, second_source) != NULL,
          "progress output identifies the current file");
    check(strstr(output, "elapsed 00:") != NULL &&
              strstr(output, "speed ") != NULL,
          "progress output includes elapsed time and speed");
    const char *long_progress =
        strstr(output, "\rProgress: 1000.0K/1.0M copied");
    const char *short_progress =
        strstr(output, "\rProgress: 1.0M/1.0M copied");
    const char *line_clear = long_progress == NULL
        ? NULL : strstr(long_progress, "\033[K");
    check(long_progress != NULL && short_progress != NULL &&
              short_progress > long_progress && line_clear != NULL &&
              line_clear < short_progress,
          "shrinking progress lines erase their stale tail");

    char quiet_target[PATH_MAX];
    join_path(quiet_target, sizeof(quiet_target), target_parent, "without_progress");
    char quiet_output[8192];
    result = run_backup_capturing(quiet_target, BACKUP_EXPLICIT_PATHS, paths,
                                   quiet_output, sizeof(quiet_output));
    check(result == 0 && strstr(quiet_output, "\rProgress:") == NULL,
          "a captured non-tty backup installs no progress callback");

    dry_run = 0;
    if (munmap(trace, sizeof(*trace)) != 0)
    {
        printf(RED "fixture: could not release shared progress trace" NC "\n");
        exit(1);
    }
    remove_tree(home);
    remove_tree(target_parent);
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
    check(strstr(output, "\nPackages\n") != NULL,
          "a normal backup still prints the Packages section");
    check(strstr(output, "  OK: Backup complete") != NULL,
          "successful backup output carries the OK marker");

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
#ifdef BACKUP_PLAN_TEST_HOOKS
    test_estimate_survives_ancestor_rename_mid_walk();
#endif
    test_allocation_aware_estimate();
    test_destination_space_preflight();
    test_include_self_backup();
    test_include_network_config_backup();
    test_format_duration();
    test_live_progress();
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
