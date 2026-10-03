// Unit tests for the deterministic backup root planner (docs/DECISIONS.md
// D16): backup_plan_build()/backup_plan_free(), declared in
// backup_plan.h. Covers the built-in catalog (XDG main directories,
// dotfiles, browser profiles, and comprehensive-only media), explicit-path
// normalization and classification (HOME containment at component
// boundaries, leaf-symlink vs. ancestor-symlink handling, and "/" edge
// cases), whole-set duplicate/overlap validation and
// EXPLICIT_n determinism, and backup()'s production-level use of the plan:
// a rejected plan must never touch the destination, live or --dry-run alike.
//
// The "production" section below calls backup() itself (declared in
// backup.h) through a fork()+pipe helper mirroring
// tests/test_restore_dispatch.c's run_restore_capturing(). Scoped backup only
// prompts when its compiled selection owns a shell-history path, so dry_run
// remains a per-test choice for the ordinary fixtures used here.

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
#include "packages.h"
#include "groups.h"
#include "selection.h"
#include "sidecar.h"
#include "utils.h"
#include "writer_apps.h"

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
        "Projects", ".ssh", ".gnupg", ".mozilla", ".config",
        ".local/share", ".local/state", ".local/bin",
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
    const char *files[] = {
        ".gitconfig", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
        ".bash_aliases", ".profile", ".zshenv", ".zprofile", ".zshrc", ".zlogin",
        ".zlogout", ".inputrc", ".tmux.conf", ".screenrc", NULL
    };
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
    printf(BLUE "::" NC " model: --critical plans personal content and persistent user state\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    make_full_home(home);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &plan) == 0, "critical plan builds");

    check(find_root(&plan, "XDG_DOCUMENTS_DIR") != NULL, "Documents is planned");
    check(find_root(&plan, "XDG_DOWNLOAD_DIR") != NULL, "Downloads is planned");
    check(find_root(&plan, "XDG_PICTURES_DIR") != NULL, "Pictures is planned");
    check(find_root(&plan, "XDG_DESKTOP_DIR") != NULL, "Desktop is planned under --critical");
    check(find_root(&plan, "XDG_VIDEOS_DIR") == NULL, "Videos is NOT planned under --critical");
    check(find_root(&plan, "XDG_MUSIC_DIR") == NULL, "Music is NOT planned under --critical");
    check(find_root(&plan, "BUILTIN_PROJECTS") == NULL, "Projects is NOT planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_SSH") != NULL, ".ssh is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_GNUPG") != NULL, ".gnupg is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_GITCONFIG") != NULL, ".gitconfig is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_BASHRC") != NULL, ".bashrc is planned under --critical");
    check(find_root(&plan, "BUILTIN_DOT_PROFILE") != NULL, ".profile is planned under --critical");
    const struct {
        const char *id;
        const char *path;
    } persistent[] = {
        { "BUILTIN_DOT_CONFIG", ".config" },
        { "BUILTIN_LOCAL_SHARE", ".local/share" },
        { "BUILTIN_LOCAL_STATE", ".local/state" },
        { "BUILTIN_LOCAL_BIN", ".local/bin" },
        { "BUILTIN_DOT_BASH_PROFILE", ".bash_profile" },
        { "BUILTIN_DOT_BASH_LOGIN", ".bash_login" },
        { "BUILTIN_DOT_BASH_LOGOUT", ".bash_logout" },
        { "BUILTIN_DOT_BASH_ALIASES", ".bash_aliases" },
        { "BUILTIN_DOT_ZSHENV", ".zshenv" },
        { "BUILTIN_DOT_ZPROFILE", ".zprofile" },
        { "BUILTIN_DOT_ZSHRC", ".zshrc" },
        { "BUILTIN_DOT_ZLOGIN", ".zlogin" },
        { "BUILTIN_DOT_ZLOGOUT", ".zlogout" },
        { "BUILTIN_DOT_INPUTRC", ".inputrc" },
        { "BUILTIN_DOT_TMUX_CONF", ".tmux.conf" },
        { "BUILTIN_DOT_SCREENRC", ".screenrc" },
    };
    for (size_t i = 0; i < sizeof(persistent) / sizeof(persistent[0]); i++)
    {
        char label[128];
        snprintf(label, sizeof(label), "%s is planned under --critical", persistent[i].path);
        check(find_root(&plan, persistent[i].id) != NULL, label);
    }
    check(find_root(&plan, "BUILTIN_BROWSER_MOZILLA") != NULL, "browser profiles are planned under --critical");
    check(find_root(&plan, "BUILTIN_BROWSER_GOOGLE_CHROME") == NULL,
          "the .config root absorbs the Chrome descendant in the legacy plan");
    check(plan.scope == MANIFEST_SCOPE_CRITICAL, "scope is MANIFEST_SCOPE_CRITICAL");

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_comprehensive_adds_extra_roots(void)
{
    printf(BLUE "::" NC " model: --comprehensive adds Videos/Music only\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    make_full_home(home);

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_COMPREHENSIVE, NULL, &plan) == 0, "comprehensive plan builds");

    check(find_root(&plan, "XDG_DESKTOP_DIR") != NULL, "Desktop is planned under --comprehensive");
    check(find_root(&plan, "XDG_VIDEOS_DIR") != NULL, "Videos is planned under --comprehensive");
    check(find_root(&plan, "XDG_MUSIC_DIR") != NULL, "Music is planned under --comprehensive");
    check(find_root(&plan, "BUILTIN_PROJECTS") == NULL, "Projects is NOT planned under --comprehensive");
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
    check(find_root(&plan, "BUILTIN_LOCAL_STATE") == NULL,
          "an absent persistent-state root is simply left out");
    check(find_root(&plan, "BUILTIN_DOT_BASH_HISTORY") == NULL,
          "an absent .bash_history is simply left out");
    check(find_root(&plan, "BUILTIN_DOT_ZSH_HISTORY") == NULL,
          "an absent .zsh_history is simply left out");

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
    {
        check(strstr(r->capture_path, "/Belgeler") != NULL,
              "its capture_path points at the actual localized directory");
        check(strcmp(r->manifest_root.payload_path, "Belgeler") == 0,
              "its payload folder keeps the localized name");
    }

    backup_plan_free(&plan);
    remove_tree(home);
}

static const BackupPlanRoot *find_root_at(const BackupPlan *plan,
                                          const char *home,
                                          const char *relative)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), home, relative);
    for (int i = 0; i < plan->root_count; i++)
        if (strcmp(plan->roots[i].capture_path, path) == 0)
            return &plan->roots[i];
    return NULL;
}

static int payload_is(const BackupPlan *plan, const char *home,
                      const char *relative, const char *expected)
{
    const BackupPlanRoot *root = find_root_at(plan, home, relative);
    return root != NULL &&
           strcmp(root->manifest_root.payload_path, expected) == 0;
}

static void test_payload_names(void)
{
    printf(BLUE "::" NC " model: payload folders carry names the user can read (D82)\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    char path[PATH_MAX];
    join_path(path, sizeof(path), home, "a");
    mkdir_p(path);
    join_path(path, sizeof(path), home, "b");
    mkdir_p(path);
    // The first four are folders, the rest files.
    static const char *const roots[] = {
        "Projects", "Settings", ".config/Code", "work/.hidden",
        "a/same.txt", "b/same.txt", "Foo", "foo", "what?.", "bad\xff"
    };
    enum { ROOTS = sizeof(roots) / sizeof(roots[0]) };
    char storage[ROOTS][PATH_MAX];
    char *paths[ROOTS + 2];
    for (int i = 0; i < ROOTS; i++)
    {
        join_path(storage[i], sizeof(storage[i]), home, roots[i]);
        if (i < 4)
            mkdir_p(storage[i]);
        else
            write_file(storage[i], "x");
        paths[i] = storage[i];
    }
    char outside[PATH_MAX];
    fresh_mkdtemp(outside, sizeof(outside), "plan_outside");
    paths[ROOTS] = outside;
    paths[ROOTS + 1] = NULL;

    BackupPlan plan;
    check(backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                            (const char *const *)paths, &plan) == 0,
          "plan builds");
    check(payload_is(&plan, home, "Projects", "Projects"),
          "a folder of the user's keeps its name at the top of data/");
    check(payload_is(&plan, home, ".config/Code", "settings/config-code") &&
              payload_is(&plan, home, "work/.hidden", "settings/work-hidden"),
          "a path with a hidden component goes in settings/, lowercase and "
          "without dots");
    check(payload_is(&plan, home, "Settings", "Settings-2"),
          "a user folder named like settings/ takes a suffix");
    check(payload_is(&plan, home, "a/same.txt", "same.txt") &&
              payload_is(&plan, home, "b/same.txt", "same.txt-2"),
          "a second root of the same name takes -2");
    check(payload_is(&plan, home, "Foo", "Foo") &&
              payload_is(&plan, home, "foo", "foo-2"),
          "names that differ only in case collide");
    check(payload_is(&plan, home, "what?.", "what-"),
          "characters FAT, exFAT, and NTFS refuse are replaced, a trailing "
          "dot dropped");
    const BackupPlanRoot *bad = find_root_at(&plan, home, "bad\xff");
    check(bad != NULL &&
              strcmp(bad->manifest_root.payload_path, bad->manifest_root.id) == 0,
          "a name that is not UTF-8 falls back to the root's id");
    check(plan.root_count > 0 &&
              strcmp(plan.roots[plan.root_count - 1].manifest_root.payload_path,
                     strrchr(outside, '/') + 1) == 0,
          "a root outside HOME is named after its last component");

    backup_plan_free(&plan);
    remove_tree(home);
    remove_tree(outside);
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
        check(strcmp(r->manifest_root.payload_path, "settings/ssh") == 0, "payload_path is settings/ and the catalog name");
        check(strcmp(r->manifest_root.restore_path, ".ssh") == 0, "restore_path is the home-relative address");
        check(r->manifest_root.has_restore_path == 1, "has_restore_path is set");
        check(r->group == BACKUP_ROOT_DOTFILE, "presentation group is DOTFILE");
    }
    r = find_root(&plan, "BUILTIN_LOCAL_SHARE");
    check(r != NULL, ".local/share is planned");
    if (r != NULL)
    {
        check(r->manifest_root.policy == ROOT_POLICY_HOME_RELATIVE,
              ".local/share policy is HOME_RELATIVE");
        check(strcmp(r->manifest_root.payload_path, "settings/local-share") == 0,
              ".local/share payload_path uses its catalog name");
        check(strcmp(r->manifest_root.restore_path, ".local/share") == 0,
              ".local/share restore_path is home-relative");
        check(r->group == BACKUP_ROOT_DOTFILE,
              ".local/share uses the Dotfiles & Config presentation group");
    }

    backup_plan_free(&plan);
    remove_tree(home);
}

static void test_builtin_config_collapses_browser_descendant(void)
{
    printf(BLUE "::" NC " selection: built-in .config owns Chromium-family descendants once\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    make_full_home(home);

    SelectionPlan plan = {0};
    check(selection_plan_build(home, BACKUP_CRITICAL, NULL, &plan) == 0,
          "selection plan builds with .config and Chrome present");

    int config_seen = 0;
    int chrome_seen = 0;
    for (size_t i = 0; i < plan.root_count; i++)
    {
        const char *id = plan.roots[i].root.manifest_root.id;
        if (strcmp(id, "BUILTIN_DOT_CONFIG") == 0)
            config_seen++;
        if (strcmp(id, "BUILTIN_BROWSER_GOOGLE_CHROME") == 0)
            chrome_seen++;
    }
    check(config_seen == 1, "the built-in .config root appears exactly once");
    check(chrome_seen == 0, "Chrome is not emitted as a duplicate descendant root");
    check(selection_plan_validate(&plan) == 0, "the collapsed ownership plan validates");

    selection_plan_free(&plan);
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

// input, if not NULL, is what the backup reads on stdin; otherwise stdin is
// inherited.
static int run_backup_capturing_input(const char *target, BackupMode mode,
                                      char *const *paths, int include_self,
                                      int include_network_config,
                                      const char *input, char *output,
                                      size_t output_size)
{
    int pipefd[2];
    int input_pipe[2] = { -1, -1 };
    if (pipe(pipefd) != 0 || (input != NULL && pipe(input_pipe) != 0))
    {
        perror("pipe");
        exit(1);
    }
    if (input != NULL)
    {
        size_t length = strlen(input);
        if (write(input_pipe[1], input, length) != (ssize_t)length)
        {
            perror("write");
            exit(1);
        }
        close(input_pipe[1]);
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
            dup2(pipefd[1], STDERR_FILENO) < 0 ||
            (input != NULL && dup2(input_pipe[0], STDIN_FILENO) < 0))
            _exit(125);
        close(pipefd[1]);
        if (input != NULL)
            close(input_pipe[0]);
        int rc = backup(target, mode, (char **)paths, include_self,
                        include_network_config);
        fflush(stdout);
        fflush(stderr);
        _exit(rc);
    }

    close(pipefd[1]);
    if (input != NULL)
        close(input_pipe[0]);
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

static int run_backup_capturing_with_options(const char *target, BackupMode mode,
                                             char *const *paths, int include_self,
                                             int include_network_config,
                                             char *output, size_t output_size)
{
    return run_backup_capturing_input(target, mode, paths, include_self,
                                      include_network_config, NULL, output,
                                      output_size);
}

static int run_backup_capturing(const char *target, BackupMode mode,
                                char *const *paths, char *output,
                                size_t output_size)
{
    return run_backup_capturing_with_options(target, mode, paths, 0, 0,
                                             output, output_size);
}

static int run_scoped_backup_capturing_input(const char *target, BackupMode mode,
                                             const Config *config, const char *input,
                                             char *output, size_t output_size)
{
    int input_pipe[2];
    int output_pipe[2];
    if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0)
    {
        perror("pipe");
        exit(1);
    }
    if (input != NULL)
    {
        size_t length = strlen(input);
        if (write(input_pipe[1], input, length) != (ssize_t)length)
        {
            perror("write");
            exit(1);
        }
    }
    close(input_pipe[1]);

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
        close(output_pipe[0]);
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0)
            _exit(125);
        close(input_pipe[0]);
        close(output_pipe[1]);

        SelectionPlan selection = {0};
        const char *home = getenv("HOME");
        int rc = home == NULL || selection_plan_build(home, mode, config, &selection) != 0
            ? 1 : backup_selection(target, mode, &selection, 0, 0);
        selection_plan_free(&selection);
        fflush(stdout);
        fflush(stderr);
        _exit(rc);
    }

    close(input_pipe[0]);
    close(output_pipe[1]);
    size_t total = 0;
    ssize_t n;
    while (total < output_size - 1 &&
           (n = read(output_pipe[0], output + total,
                     output_size - 1 - total)) > 0)
        total += (size_t)n;
    output[total] = '\0';
    close(output_pipe[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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

static void record_backup_progress(off_t bytes_copied, off_t bytes_unchanged,
                                   off_t estimated_total,
                                   const char *current_path, void *context)
{
    (void)bytes_unchanged;
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

static int proc_thread_count(void)
{
    DIR *dir = opendir("/proc/self/task");
    if (dir == NULL)
        return -1;

    int count = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            count++;
    int saved_errno = errno;
    if (closedir(dir) != 0 || saved_errno != 0)
        return -1;
    return count;
}

typedef struct {
    const char *path;
} ProgressStall;

static void stall_before_capture(const char *source_path, void *context)
{
    ProgressStall *stall = context;
    if (stall == NULL || source_path == NULL ||
        strcmp(source_path, stall->path) != 0)
        return;

    const long stall_ms = PROGRESS_STALL_MS + 1750L;
    struct timespec remaining = {
        .tv_sec = stall_ms / 1000L,
        .tv_nsec = (stall_ms % 1000L) * 1000000L
    };
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR)
        ;
}

static int progress_output_lines_fit(const char *output, size_t max_length)
{
    const char prefix[] = "\rProgress: ";
    const char *cursor = output;
    int found = 0;

    while ((cursor = strstr(cursor, prefix)) != NULL)
    {
        const char *line_end = strstr(cursor, "\033[K");
        if (line_end == NULL)
            return 0;
        if ((size_t)(line_end - (cursor + 1)) > max_length)
            return 0;
        found = 1;
        cursor = line_end + 3;
    }
    return found;
}

static int stalled_progress_advanced_elapsed_without_bytes(const char *output)
{
    const char prefix[] = "\rProgress: ";
    const char *cursor = output;
    char stable_bytes[32] = "";
    char first_elapsed[32] = "";

    while ((cursor = strstr(cursor, prefix)) != NULL)
    {
        const char *line_end = strstr(cursor, "\033[K");
        if (line_end == NULL)
            break;
        const char *slash = strchr(cursor + sizeof(prefix) - 1U, '/');
        const char *elapsed = strstr(cursor, "elapsed ");
        if (slash == NULL || slash >= line_end ||
            elapsed == NULL || elapsed >= line_end)
        {
            cursor = line_end + 3;
            continue;
        }

        const char *bytes_start = cursor + sizeof(prefix) - 1U;
        size_t bytes_len = (size_t)(slash - bytes_start);
        elapsed += strlen("elapsed ");
        const char *elapsed_end = strchr(elapsed, ',');
        if (bytes_len == 0 || bytes_len >= sizeof(stable_bytes) ||
            elapsed_end == NULL || elapsed_end >= line_end)
        {
            cursor = line_end + 3;
            continue;
        }
        size_t elapsed_len = (size_t)(elapsed_end - elapsed);
        if (elapsed_len == 0 || elapsed_len >= sizeof(first_elapsed))
        {
            cursor = line_end + 3;
            continue;
        }

        char elapsed_text[32];
        memcpy(elapsed_text, elapsed, elapsed_len);
        elapsed_text[elapsed_len] = '\0';
        if (strcmp(elapsed_text, "00:00") == 0)
        {
            cursor = line_end + 3;
            continue;
        }

        if (stable_bytes[0] == '\0')
        {
            memcpy(stable_bytes, bytes_start, bytes_len);
            stable_bytes[bytes_len] = '\0';
        }
        else if (strlen(stable_bytes) != bytes_len ||
                 memcmp(stable_bytes, bytes_start, bytes_len) != 0)
            return 0;

        if (first_elapsed[0] == '\0')
            memcpy(first_elapsed, elapsed_text, elapsed_len + 1U);
        else if (strcmp(first_elapsed, elapsed_text) != 0)
            return 1;

        cursor = line_end + 3;
    }
    return 0;
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
        if (strncmp(e->d_name, "migr-", 5) != 0)
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
        if (strncmp(e->d_name, "migr-", 5) != 0 ||
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

static char *prepend_test_path(const char *prefix)
{
    const char *current = getenv("PATH");
    char *saved = strdup(current != NULL ? current : "");
    if (saved == NULL)
    {
        printf(RED "fixture: could not save PATH" NC "\n");
        exit(1);
    }

    size_t needed = strlen(prefix) + strlen(saved) + 2U;
    char *updated = malloc(needed);
    if (updated == NULL)
    {
        free(saved);
        printf(RED "fixture: could not build PATH" NC "\n");
        exit(1);
    }
    if (saved[0] != '\0')
        snprintf(updated, needed, "%s:%s", prefix, saved);
    else
        snprintf(updated, needed, "%s", prefix);
    if (setenv("PATH", updated, 1) != 0)
    {
        free(updated);
        free(saved);
        printf(RED "fixture: could not update PATH" NC "\n");
        exit(1);
    }
    free(updated);
    return saved;
}

static void restore_test_path(char *saved)
{
    if (setenv("PATH", saved, 1) != 0)
    {
        free(saved);
        printf(RED "fixture: could not restore PATH" NC "\n");
        exit(1);
    }
    free(saved);
}

typedef struct {
    const char *path;
    int failed;
} FailBeforeCapture;

// A removed source is left out without failing the backup (D63), so a
// failed capture comes from a read error injected into the source's open.
static void fail_before_capture(const char *source_path, void *context)
{
    FailBeforeCapture *fixture = context;
    if (fixture == NULL || source_path == NULL ||
        fixture->failed || strcmp(source_path, fixture->path) != 0)
        return;
    backup_test_fail_next_source_open(EIO);
    fixture->failed = 1;
}

static void test_vscode_extension_snapshot(void)
{
    printf(BLUE "::" NC " production: scoped backups snapshot VS Code extensions and explicit resumes clear stale snapshots\n");

    char home[PATH_MAX], stub_dir[PATH_MAX], target[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "vscode_home");
    fresh_mkdtemp(stub_dir, sizeof(stub_dir), "vscode_stub");
    setenv("HOME", home, 1);

    char profile[PATH_MAX];
    join_path(profile, sizeof(profile), home, ".profile");
    write_file(profile, "export PATH\n");

    char code_stub[PATH_MAX];
    join_path(code_stub, sizeof(code_stub), stub_dir, "code");
    write_file(code_stub,
               "#!/bin/sh\n"
               "printf '%s\\n' 'publisher.alpha@1.2.3' 'publisher.beta@4.5.6'\n");
    if (chmod(code_stub, 0700) != 0)
    {
        printf(RED "fixture: could not make fake code executable" NC "\n");
        exit(1);
    }

    char expected[PATH_MAX];
    join_path(expected, sizeof(expected), stub_dir, "expected.txt");
    write_file(expected, "publisher.alpha@1.2.3\npublisher.beta@4.5.6\n");

    char *saved_path = prepend_test_path(stub_dir);
    char *no_paths[] = { NULL };
    char output[32768], container[PATH_MAX], snapshot[PATH_MAX];

    fresh_mkdtemp(target, sizeof(target), "vscode_success_target");
    int rc = run_backup_capturing(target, BACKUP_CRITICAL, no_paths,
                                  output, sizeof(output));
    int have_container = find_container_dir(target, container, sizeof(container));
    if (have_container)
        join_path(snapshot, sizeof(snapshot), container, "vs-code-extensions.txt");
    check(rc == 0 && have_container && files_are_equal(expected, snapshot),
          "a scoped backup writes the exact deterministic extension snapshot");
    check(strstr(output,
                 "Saved VS Code extension list to vs-code-extensions.txt") != NULL,
          "a successful extension snapshot is reported");

    char user[ACCOUNT_NAME_MAX];
    char *groups = local_account_name(getuid(), user) == 0
        ? groups_collect(user) : NULL;
    if (groups != NULL && have_container)
    {
        join_path(expected, sizeof(expected), stub_dir, "groups.txt");
        write_file(expected, groups);
        join_path(snapshot, sizeof(snapshot), container, "groups.txt");
        check(files_are_equal(expected, snapshot) &&
                  strstr(output, " to groups.txt") != NULL,
              "a scoped backup saves the user's group memberships");
    }
    free(groups);

    // tests/stubs/flatpak, ahead on PATH, lists one application.
    if (have_container)
    {
        join_path(expected, sizeof(expected), stub_dir, "flatpak-apps.txt");
        write_file(expected, "flathub\tcom.example.MigrStub\n");
        join_path(snapshot, sizeof(snapshot), container, "flatpak-apps.txt");
    }
    check(have_container && files_are_equal(expected, snapshot) &&
              strstr(output, "Saved 1 Flatpak application to "
                             "flatpak-apps.txt") != NULL,
          "a scoped backup lists the system-wide Flatpak applications");
    remove_tree(target);

    write_file(code_stub, "#!/bin/sh\nexit 7\n");
    if (chmod(code_stub, 0700) != 0)
    {
        printf(RED "fixture: could not update fake code executable" NC "\n");
        exit(1);
    }

    fresh_mkdtemp(target, sizeof(target), "vscode_failure_target");
    rc = run_backup_capturing(target, BACKUP_CRITICAL, no_paths,
                              output, sizeof(output));
    have_container = find_container_dir(target, container, sizeof(container));
    if (have_container)
        join_path(snapshot, sizeof(snapshot), container, "vs-code-extensions.txt");
    check(rc == 0 && have_container && access(snapshot, F_OK) != 0,
          "an unavailable or failing code command leaves no snapshot without failing backup");
    check(strstr(output,
                 "Note: no VS Code extension list was captured for this backup.") != NULL,
          "a skipped extension snapshot is reported as a note");
    remove_tree(target);
    restore_test_path(saved_path);

    char explicit_source[PATH_MAX];
    join_path(explicit_source, sizeof(explicit_source), home, "explicit.txt");
    write_file(explicit_source, "resume payload\n");
    char *explicit_paths[] = { explicit_source, NULL };

    fresh_mkdtemp(target, sizeof(target), "vscode_explicit_target");
    // Resume identity includes scope, so a scoped partial cannot be adopted by
    // an explicit invocation. Plant the stale control into a matching explicit
    // partial instead, which exercises the same post-adoption clearing path.
    FailBeforeCapture fail_fixture = { .path = explicit_source };
    backup_test_set_capture_hook(fail_before_capture, &fail_fixture);
    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, explicit_paths,
                              output, sizeof(output));
    backup_test_set_capture_hook(NULL, NULL);

    char partial[PATH_MAX];
    int have_partial = find_partial_container_dir(target, partial, sizeof(partial));
    check(rc != 0 && have_partial,
          "fixture leaves a resumable explicit partial before stale-control cleanup");
    if (have_partial)
    {
        join_path(snapshot, sizeof(snapshot), partial, "vs-code-extensions.txt");
        write_file(snapshot, "stale@9.9.9\n");
        join_path(snapshot, sizeof(snapshot), partial, "groups.txt");
        write_file(snapshot, "stale\n");
        join_path(snapshot, sizeof(snapshot), partial, "flatpak-apps.txt");
        write_file(snapshot, "stale\tcom.example.Stale\n");
    }
    write_file(explicit_source, "resume payload\n");

    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, explicit_paths,
                              output, sizeof(output));
    have_container = find_container_dir(target, container, sizeof(container));
    if (have_container)
        join_path(snapshot, sizeof(snapshot), container, "vs-code-extensions.txt");
    check(rc == 0 && have_container &&
              strstr(output, "Resuming an interrupted backup of this install.") != NULL,
          "the second explicit run adopts and completes the matching partial");
    check(have_container && access(snapshot, F_OK) != 0,
          "an adopted explicit backup clears a stale VS Code extension snapshot");
    if (have_container)
        join_path(snapshot, sizeof(snapshot), container, "groups.txt");
    check(have_container && access(snapshot, F_OK) != 0,
          "an adopted explicit backup clears a stale group list");
    if (have_container)
        join_path(snapshot, sizeof(snapshot), container, "flatpak-apps.txt");
    check(have_container && access(snapshot, F_OK) != 0,
          "an adopted explicit backup clears a stale Flatpak application list");

    remove_tree(target);
    remove_tree(home);
    remove_tree(stub_dir);
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

// The forked backup sees free space just short of what it needs.
static void provide_almost_enough_space(off_t needed, off_t *free_bytes,
                                        void *context)
{
    (void)context;
    *free_bytes = needed - 1;
}

static void provide_just_enough_space(off_t needed, off_t *free_bytes,
                                      void *context)
{
    (void)context;
    *free_bytes = needed;
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

// Any plain read under relatime would move a year-2000 access time forward.
#define OLD_ATIME 946684800

static void set_old_atime(const char *path)
{
    struct timespec times[2] = { { OLD_ATIME, 0 }, { 0, UTIME_OMIT } };
    if (utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) != 0)
    {
        printf(RED "fixture: could not set the access time of %s" NC "\n", path);
        exit(1);
    }
}

static int atime_is_old(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && st.st_atim.tv_sec == OLD_ATIME;
}

static void test_planning_keeps_access_times(void)
{
    printf(BLUE "::" NC " model: planning a backup leaves folders' access times as they are\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_atime_home");
    setenv("HOME", home, 1);

    static const char *const folders[] = {
        "picked/sub", "left/sub", ".var/app/org.example.App",
        ".local/share/flatpak/app", ".local/share/flatpak/runtime",
        "picked", "left", ".var", ".var/app", ".local", ".local/share",
        ".local/share/flatpak",
    };
    enum { FOLDER_COUNT = sizeof(folders) / sizeof(folders[0]) };
    char paths[FOLDER_COUNT][PATH_MAX];
    for (size_t i = 0; i < FOLDER_COUNT; i++)
    {
        join_path(paths[i], sizeof(paths[i]), home, folders[i]);
        mkdir_p(paths[i]);
    }
    char picked[PATH_MAX], picked_sub[PATH_MAX], file[PATH_MAX];
    join_path(picked, sizeof(picked), home, "picked");
    join_path(picked_sub, sizeof(picked_sub), picked, "sub");
    join_path(file, sizeof(file), picked_sub, "picked.txt");
    write_file(file, "picked payload");
    join_path(file, sizeof(file), home, "left/sub/left.txt");
    write_file(file, "left payload");
    set_old_atime(home);
    for (size_t i = 0; i < FOLDER_COUNT; i++)
        set_old_atime(paths[i]);

    char *roots[] = { picked, NULL };
    BackupPlan plan;
    off_t total = 0;
    int had_error = -1;
    if (backup_plan_build(home, BACKUP_EXPLICIT_PATHS,
                          (const char *const *)roots, &plan) == 0)
    {
        backup_plan_estimate_size(&plan, 0, &total, &had_error);
        backup_plan_free(&plan);
    }
    check(had_error == 0 && atime_is_old(picked) && atime_is_old(picked_sub),
          "the size estimate");

    SelectionPlan selection;
    SelectionUncovered *items = NULL;
    size_t count = 0;
    check(selection_plan_build(home, BACKUP_CRITICAL, NULL, &selection) == 0 &&
              selection_plan_uncovered(&selection, &items, &count) == 0 &&
              count > 0,
          "the plan and the list of what it leaves out are built");
    free(items);
    selection_plan_free(&selection);
    int kept = atime_is_old(home);
    for (size_t i = 0; i < FOLDER_COUNT; i++)
        kept = kept && atime_is_old(paths[i]);
    check(kept, "the Flatpak checks and the list of what is left out");

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
    check(fit_result == 2 &&
              strstr(fit_output, "Estimated backup size: 15B") != NULL &&
              strstr(fit_output, "Destination free space: 15B") != NULL &&
              strstr(fit_output, "need 5B more") != NULL,
          "the free-space fit check still uses the rounded estimate");

    remove_tree(home);
    remove_tree(target_parent);
}

static void test_update_counts_the_backup_it_replaces(int portable)
{
    printf(BLUE "::" NC " production: a %s update needs space only for what grew, and shows what it checked\n",
           portable ? "portable" : "native");
    backup_test_force_portable_representation(portable);

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    mkdir_p(home);
    setenv("HOME", home, 1);
    char docs[PATH_MAX], kept[PATH_MAX], added[PATH_MAX];
    join_path(docs, sizeof(docs), home, "docs");
    mkdir_p(docs);
    join_path(kept, sizeof(kept), docs, "kept.bin");
    write_large_file(kept, 4000);
    join_path(added, sizeof(added), docs, "added.txt");
    char *paths[] = { docs, NULL };

    char target_parent[PATH_MAX];
    fresh_mkdtemp(target_parent, sizeof(target_parent), "plan_target_parent");
    char target[PATH_MAX];
    join_path(target, sizeof(target), target_parent, "update-space");

    off_t no_rounding_block_size = 1;
    backup_test_set_block_size_hook(set_test_block_size,
                                    &no_rounding_block_size);
    backup_test_set_free_space_hook(provide_free_space, NULL);
    dry_run = 0;
    char output[8192];
    check(run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths, output,
                               sizeof(output)) == 0,
          "the first backup completes");
    char container[PATH_MAX];
    Manifest manifest = {0};
    int container_fd = find_container_dir(target, container, sizeof(container))
        ? open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
    check(container_fd >= 0 &&
              manifest_read_v1_at(container_fd, &manifest) ==
                  MANIFEST_STATUS_VALID &&
              manifest.size >= 4000,
          "the manifest records the backup's size");
    manifest_free(&manifest);
    if (container_fd >= 0)
        close(container_fd);

    write_large_file(added, 100);
    backup_test_set_free_space_hook(provide_almost_enough_space, NULL);
    dry_run = 1;
    int dry_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
    // The shortfall is reported against free space one byte short of the
    // need, so that free space shows what the update asked for.
    const char *free_line = strstr(output, "Destination free space: ");
    intmax_t free_shown = -1;
    char unit = '\0';
    if (free_line != NULL)
        (void)sscanf(free_line, "Destination free space: %jd%c", &free_shown,
                     &unit);
    check(dry_rc == 2 && unit == 'B' && free_shown < 4000 &&
              strstr(output, "Size of the backup being updated: ") != NULL &&
              strstr(output, "need 1B more") != NULL,
          "a dry-run update asks only for the growth beyond the old backup");

    backup_test_set_free_space_hook(provide_just_enough_space, NULL);
    backup_test_set_progress_hook(record_backup_progress, NULL);
    dry_run = 0;
    int live_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                       output, sizeof(output));
    backup_test_set_progress_hook(NULL, NULL);
    backup_test_set_free_space_hook(NULL, NULL);
    backup_test_set_block_size_hook(NULL, NULL);
    backup_test_force_portable_representation(0);
    check(live_rc == 0, "the update fits when only its growth fits");
    check(strstr(output, "Progress: 4.0K/") != NULL &&
              strstr(output, " checked, 100B copied") != NULL,
          "update progress shows the checked bytes beside the copied ones");

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
    check(live_rc == 2 && dry_rc == 2,
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
    check(rollback_rc == 2 && !dir_exists(created_target),
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
    check(missing_rc == 2 && !dir_exists(missing_target),
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

static void unlink_source_before_open(const char *source_path, void *context)
{
    if (strcmp(source_path, (const char *)context) == 0)
        unlink(source_path);
}

// Rewrites the source after every read, the way a file under constant
// writing looks to a backup.
static void rewrite_source_after_copy(const char *source_path, void *context)
{
    if (strcmp(source_path, (const char *)context) == 0)
        write_file(source_path, "rewritten while read");
}

static int rewrite_once_count;

static void rewrite_source_once_after_copy(const char *source_path,
                                           void *context)
{
    if (strcmp(source_path, (const char *)context) == 0 &&
        rewrite_once_count++ == 0)
        write_file(source_path, "rewritten once");
}

static int file_text_is(const char *path, const char *expected)
{
    char buffer[256];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t length = read(fd, buffer, sizeof(buffer));
    close(fd);
    return length == (ssize_t)strlen(expected) &&
           memcmp(buffer, expected, (size_t)length) == 0;
}

// Native capture of a live source (D63): a vanished file is left out, a
// file written while read is read again, and one still changing is kept as
// last read; the backup completes either way and exits 1 when anything
// changed.
static void test_native_backup_of_a_changing_source(void)
{
    printf(BLUE "::" NC " production: a native backup completes when its source changes under it\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_live_home");
    setenv("HOME", home, 1);
    char source[PATH_MAX], stable[PATH_MAX], vanishing[PATH_MAX];
    char busy[PATH_MAX];
    join_path(source, sizeof(source), home, "work");
    mkdir_p(source);
    join_path(stable, sizeof(stable), source, "stable.txt");
    join_path(vanishing, sizeof(vanishing), source, "vanishing.txt");
    join_path(busy, sizeof(busy), source, "busy.txt");
    write_file(stable, "stable");
    write_file(vanishing, "about to go");
    write_file(busy, "original");
    char *paths[] = { source, NULL };
    dry_run = 0;

    char target[PATH_MAX], container[PATH_MAX], payload[PATH_MAX];
    char output[8192];
    fresh_mkdtemp(target, sizeof(target), "plan_live_vanish");
    backup_test_set_capture_hook(unlink_source_before_open, vanishing);
    int rc = run_backup_capturing_with_options(
        target, BACKUP_EXPLICIT_PATHS, paths, 0, 0, output, sizeof(output));
    backup_test_set_capture_hook(NULL, NULL);
    int found = find_container_dir(target, container, sizeof(container));
    if (found)
        join_path(payload, sizeof(payload), container,
                  "data/work/vanishing.txt");
    check(rc == 1 && found && access(payload, F_OK) != 0 &&
              strstr(output, "Backup complete") != NULL &&
              strstr(output, "1 item removed before it could be read") !=
                  NULL &&
              strstr(output, vanishing) != NULL,
          "a file removed before it is read is left out, listed, and the "
          "backup still completes with status 1");

    write_file(vanishing, "back again");
    fresh_mkdtemp(target, sizeof(target), "plan_live_busy");
    // Shared: the backup runs in a child.
    BackupProgressTrace *busy_trace = mmap(NULL, sizeof(*busy_trace),
                                           PROT_READ | PROT_WRITE,
                                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (busy_trace == MAP_FAILED)
    {
        printf(RED "fixture: could not create shared progress trace" NC "\n");
        exit(1);
    }
    *busy_trace = (BackupProgressTrace){0};
    backup_test_set_progress_hook(record_backup_progress, busy_trace);
    backup_test_set_after_copy_hook(rewrite_source_after_copy, busy);
    rc = run_backup_capturing_with_options(
        target, BACKUP_EXPLICIT_PATHS, paths, 0, 0, output, sizeof(output));
    backup_test_set_after_copy_hook(NULL, NULL);
    backup_test_set_progress_hook(NULL, NULL);
    found = find_container_dir(target, container, sizeof(container));
    if (found)
        join_path(payload, sizeof(payload), container,
                  "data/work/busy.txt");
    check(rc == 1 && found && file_text_is(payload, "rewritten while read") &&
              strstr(output, "1 file kept as last read") != NULL &&
              strstr(output, busy) != NULL,
          "a file still changing after every reread is kept as last read "
          "and listed");
    check(busy_trace->previous == (off_t)(strlen("stable") +
                                          strlen("back again") +
                                          strlen("rewritten while read")),
          "progress counts the bytes of the read kept, not of every read");
    munmap(busy_trace, sizeof(*busy_trace));
    struct stat busy_st, payload_st;
    check(found && stat(busy, &busy_st) == 0 &&
              stat(payload, &payload_st) == 0 &&
              (busy_st.st_mtim.tv_sec != payload_st.st_mtim.tv_sec ||
               busy_st.st_mtim.tv_nsec != payload_st.st_mtim.tv_nsec),
          "it keeps the times from before the last read, so the next update "
          "reads it again");

    write_file(busy, "original");
    fresh_mkdtemp(target, sizeof(target), "plan_live_once");
    rewrite_once_count = 0;
    backup_test_set_after_copy_hook(rewrite_source_once_after_copy, busy);
    rc = run_backup_capturing_with_options(
        target, BACKUP_EXPLICIT_PATHS, paths, 0, 0, output, sizeof(output));
    backup_test_set_after_copy_hook(NULL, NULL);
    found = find_container_dir(target, container, sizeof(container));
    if (found)
        join_path(payload, sizeof(payload), container,
                  "data/work/busy.txt");
    check(rc == 0 && found && file_text_is(payload, "rewritten once") &&
              strstr(output, "changed while they were being backed up") ==
                  NULL,
          "a file written once while it is read is read again and captured "
          "cleanly, with status 0");

    // Resume: a file captured by an interrupted run and removed before the
    // resuming run reads it must not keep its stale payload.
    char first_root[PATH_MAX], second_root[PATH_MAX], captured[PATH_MAX];
    join_path(first_root, sizeof(first_root), home, "resume_dir");
    mkdir_p(first_root);
    join_path(captured, sizeof(captured), first_root, "captured.txt");
    write_file(captured, "captured by the first run");
    join_path(second_root, sizeof(second_root), home, "resume_file.txt");
    write_file(second_root, "fails in the first run");
    char *resume_paths[] = { first_root, second_root, NULL };
    fresh_mkdtemp(target, sizeof(target), "plan_live_resume");
    FailBeforeCapture fail_fixture = { .path = second_root };
    backup_test_set_capture_hook(fail_before_capture, &fail_fixture);
    rc = run_backup_capturing_with_options(
        target, BACKUP_EXPLICIT_PATHS, resume_paths, 0, 0, output,
        sizeof(output));
    backup_test_set_capture_hook(NULL, NULL);
    char partial[PATH_MAX];
    int have_partial = find_partial_container_dir(target, partial,
                                                  sizeof(partial));
    if (have_partial)
        join_path(payload, sizeof(payload), partial,
                  "data/resume_dir/captured.txt");
    check(rc != 0 && have_partial && access(payload, F_OK) == 0,
          "fixture: an interrupted run leaves a partial holding the first "
          "root's file");
    backup_test_set_capture_hook(unlink_source_before_open, captured);
    rc = run_backup_capturing_with_options(
        target, BACKUP_EXPLICIT_PATHS, resume_paths, 0, 0, output,
        sizeof(output));
    backup_test_set_capture_hook(NULL, NULL);
    found = find_container_dir(target, container, sizeof(container));
    if (found)
        join_path(payload, sizeof(payload), container,
                  "data/resume_dir/captured.txt");
    check(rc == 1 && found && access(payload, F_OK) != 0 &&
              strstr(output, "Resuming an interrupted backup") != NULL,
          "a resumed backup drops the stale payload of a file that vanished "
          "before it was read");
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

    char policy_source[PATH_MAX], policy_expected[PATH_MAX];
    join_path(policy_source, sizeof(policy_source), home, "crypto-policy-config");
    join_path(policy_expected, sizeof(policy_expected), home,
              "crypto-policy-expected");
    write_file(policy_source, "# system-wide crypto policy\n\n  DEFAULT:SHA1 \n");
    write_file(policy_expected, "DEFAULT:SHA1\n");
    backup_test_set_crypto_policy_source(policy_source);

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

        char copied_policy[PATH_MAX];
        join_path(copied_policy, sizeof(copied_policy), network_dir,
                  "crypto-policy");
        check(files_are_equal(policy_expected, copied_policy),
              "the system crypto policy name is recorded as network/crypto-policy");

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
    write_file(policy_source, "# no policy line\nnot/a/policy\n");
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
        char empty_policy[PATH_MAX];
        struct stat policy_st;
        join_path(empty_policy, sizeof(empty_policy), empty_network,
                  "crypto-policy");
        check(lstat(empty_policy, &policy_st) != 0 && errno == ENOENT,
              "an unrecognized crypto policy file is not recorded");
    }
    backup_test_set_crypto_policy_source(NULL);
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
        check(denied_rc == 2 && directory_empty(denied_target),
              "an unreadable backend still refuses when the other backends are absent");
        check(strstr(denied_output, "NetworkManager") != NULL &&
                  strstr(denied_output, "same migr command with sudo") != NULL,
              "the permission refusal names the backend and gives the sudo retry");
        chmod(denied_source, 0700);
        remove_tree(denied_source);
        remove_tree(denied_target);
    }

    char not_directory[PATH_MAX], not_directory_source[PATH_MAX];
    join_path(not_directory, sizeof(not_directory), home,
              "network-backend-not-directory");
    write_file(not_directory, "not a directory\n");
    join_path(not_directory_source, sizeof(not_directory_source),
              not_directory, "backend");
    backup_test_set_network_config_source_dir("NetworkManager",
                                              not_directory_source);
    backup_test_set_network_config_source_dir("netplan", missing_netplan);
    backup_test_set_network_config_source_dir("systemd-networkd",
                                              missing_networkd);
    char operational_target[PATH_MAX];
    fresh_mkdtemp(operational_target, sizeof(operational_target),
                  "plan_network_operational_target");
    char operational_output[8192];
    int operational_rc = run_backup_capturing_with_options(
        operational_target, BACKUP_EXPLICIT_PATHS, paths, 0, 1,
        operational_output, sizeof(operational_output));
    check(operational_rc == 2 && directory_empty(operational_target),
          "a non-permission backend probe failure still refuses before capture");
    check(strstr(operational_output, "NetworkManager") != NULL &&
              strstr(operational_output, "cannot read") != NULL &&
              strstr(operational_output, "sudo") == NULL &&
              strstr(operational_output, "Root privileges") == NULL,
          "a non-permission backend failure does not claim sudo is the remedy");
    unlink(not_directory);
    remove_tree(operational_target);

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

        check(failing_rc == 2 && directory_empty(failing_target),
              "an unreadable network configuration file refuses before container creation");
        check(strstr(failing_output, "unreadable.nmconnection") != NULL &&
                  strstr(failing_output, "same migr command with sudo") != NULL,
              "a per-file permission refusal names the connection file and gives the sudo retry");

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

static void test_portable_prescan_failure_diagnostics(void)
{
    printf(BLUE "::" NC " production: portable pre-scan failures name their cause\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_portable_diag_home");
    setenv("HOME", home, 1);
    char source[PATH_MAX];
    join_path(source, sizeof(source), home, "source");
    mkdir_p(source);

    char fifo[PATH_MAX];
    join_path(fifo, sizeof(fifo), source, "blocked-fifo");
    if (mkfifo(fifo, 0600) != 0)
    {
        printf(RED "fixture: could not create portable diagnostic FIFO" NC "\n");
        exit(1);
    }
    char upper[PATH_MAX];
    char lower[PATH_MAX];
    join_path(upper, sizeof(upper), source, "Foo");
    join_path(lower, sizeof(lower), source, "foo");
    write_file(upper, "upper\n");
    write_file(lower, "lower\n");

    char *paths[] = { source, NULL };
    char target[PATH_MAX];
    fresh_mkdtemp(target, sizeof(target), "plan_portable_diag_target");
    char output[8192];
    backup_test_force_portable_representation(1);
    backup_test_force_case_insensitive_destination(1);
    int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output));
    backup_test_force_case_insensitive_destination(0);
    backup_test_force_portable_representation(0);
    check(rc == 2 && directory_empty(target),
          "an unresolved portable pre-scan violation refuses before container creation");
    check(strstr(output, "unresolved issue") != NULL &&
              strstr(output, "blocked-fifo") != NULL &&
              strstr(output, "unsupported file kind") != NULL &&
              strstr(output, "collides with") == NULL,
          "the portable refusal reports only the unresolved path, not a resolved case collision");
    remove_tree(target);

    fresh_mkdtemp(target, sizeof(target), "plan_portable_diag_target");
    dry_run = 1;
    backup_test_force_portable_representation(1);
    backup_test_force_case_insensitive_destination(1);
    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                              output, sizeof(output));
    backup_test_force_case_insensitive_destination(0);
    backup_test_force_portable_representation(0);
    dry_run = 0;
    check(rc == 2 && directory_empty(target),
          "a dry-run portable pre-scan violation refuses without creating a container");
    check(strstr(output, "nothing would be created") != NULL &&
              strstr(output, "blocked-fifo") != NULL &&
              strstr(output, "unsupported file kind") != NULL &&
              strstr(output, "collides with") == NULL,
          "the dry-run portable refusal reports the unresolved path before freeing its report");
    remove_tree(target);

    if (unlink(fifo) != 0)
    {
        printf(RED "fixture: could not remove portable diagnostic FIFO" NC "\n");
        exit(1);
    }

    if (geteuid() != 0)
    {
        char blocked[PATH_MAX];
        join_path(blocked, sizeof(blocked), source, "blocked-directory");
        mkdir_p(blocked);
        if (chmod(blocked, 0000) != 0)
        {
            printf(RED "fixture: could not restrict portable diagnostic directory" NC "\n");
            exit(1);
        }

        fresh_mkdtemp(target, sizeof(target), "plan_portable_diag_target");
        backup_test_force_portable_representation(1);
        rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output));
        backup_test_force_portable_representation(0);
        check(rc == 2 && directory_empty(target),
              "an operational portable pre-scan failure refuses before container creation");
        check(strstr(output, "could not scan blocked-directory") != NULL &&
                  (strstr(output, "Permission denied") != NULL ||
                   strstr(output, "Operation not permitted") != NULL),
              "the portable refusal reports the unreadable path and operating-system error");

        if (chmod(blocked, 0700) != 0)
        {
            printf(RED "fixture: could not restore portable diagnostic directory permissions" NC "\n");
            exit(1);
        }
        remove_tree(target);
    }

    remove_tree(home);
}

// Counts the target's published (".partial"-less) and in-progress containers.
static void count_containers(const char *target, int *published, int *partial)
{
    *published = 0;
    *partial = 0;
    DIR *dir = opendir(target);
    if (dir == NULL)
        return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strncmp(entry->d_name, "migr-", 5) != 0)
            continue;
        size_t length = strlen(entry->d_name);
        if (length > 8 && strcmp(entry->d_name + length - 8, ".partial") == 0)
            (*partial)++;
        else
            (*published)++;
    }
    closedir(dir);
}

// Stands in for a drive that stored a different cluster than the one
// written: a run of zero bytes replaces part of the journal on disk.
static void damage_sidecar_on_disk(int container_fd, void *context)
{
    (void)context;
    int fd = openat(container_fd, "sidecar.migr", O_WRONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size < 64)
        _exit(3);
    char zeros[32] = {0};
    if (pwrite(fd, zeros, sizeof(zeros), st.st_size / 3) !=
            (ssize_t)sizeof(zeros) ||
        close(fd) != 0)
        _exit(3);
}

static void test_portable_sidecar_readback(void)
{
    printf(BLUE "::" NC " production: portable journal is read back before publishing\n");
    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_readback_home");
    setenv("HOME", home, 1);
    char source[PATH_MAX], file[PATH_MAX], nested[PATH_MAX];
    join_path(source, sizeof(source), home, "source");
    join_path(nested, sizeof(nested), source, "nested");
    mkdir_p(nested);
    join_path(file, sizeof(file), source, "a.txt");
    write_file(file, "alpha\n");
    join_path(file, sizeof(file), nested, "b.txt");
    write_file(file, "beta\n");
    char *paths[] = { source, NULL };

    char target[PATH_MAX];
    char output[8192];
    int published = 0, partial = 0;
    fresh_mkdtemp(target, sizeof(target), "plan_readback_target");
    backup_test_force_portable_representation(1);
    int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output));
    backup_test_force_portable_representation(0);
    count_containers(target, &published, &partial);
    check(rc == 0 && published == 1 && partial == 0 &&
              strstr(output, "Backup complete") != NULL,
          "a journal that reads back intact is published");
    remove_tree(target);

    fresh_mkdtemp(target, sizeof(target), "plan_readback_target");
    backup_test_force_portable_representation(1);
    backup_test_set_sidecar_readback_hook(damage_sidecar_on_disk, NULL);
    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                              output, sizeof(output));
    backup_test_set_sidecar_readback_hook(NULL, NULL);
    backup_test_force_portable_representation(0);
    count_containers(target, &published, &partial);
    check(rc == 2 && published == 0 && partial == 1,
          "a journal damaged on the drive keeps the backup unpublished");
    check(strstr(output, "sidecar.migr") != NULL &&
              strstr(output, "is damaged at byte") != NULL &&
              strstr(output, "did not keep what was written") != NULL &&
              strstr(output, "Backup complete") == NULL,
          "the damaged journal is reported with its offset, not as complete");
    remove_tree(target);
    remove_tree(home);
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

static void test_progress_speed_is_cumulative_average(void)
{
    printf(BLUE "::" NC " utility: progress speed is a cumulative average, "
                "not the last-interval rate\n");
    struct timespec started_at = { .tv_sec = 1000, .tv_nsec = 0 };

    // A long syncfs()-style stall: 60s elapsed, almost nothing copied yet.
    struct timespec after_stall = { .tv_sec = 1060, .tv_nsec = 0 };
    off_t speed_during_stall =
        backup_test_progress_speed(100, &started_at, &after_stall);
    check(speed_during_stall == 100 / 60,
          "speed during a stall reflects the (tiny) average so far");

    // A one-second burst that lands the bulk of the bytes right after the
    // stall unblocks. The interval-only formula would report the burst rate
    // here (~609900 B/s); the cumulative average must not.
    struct timespec after_burst = { .tv_sec = 1061, .tv_nsec = 0 };
    off_t speed_after_burst =
        backup_test_progress_speed(610000, &started_at, &after_burst);
    check(speed_after_burst == 10000,
          "speed after a burst is total_bytes / elapsed since start (10000), "
          "not the burst-only rate");
    check(speed_after_burst < 609900 / 2,
          "speed after a burst is nowhere near the burst-only interval rate");

    // Guard clauses carried over from the interval formula.
    check(backup_test_progress_speed(0, &started_at, &after_burst) == 0,
          "zero bytes copied yields zero speed");
    check(backup_test_progress_speed(610000, &started_at, &started_at) == 0,
          "non-positive elapsed time yields zero speed");
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
    check(progress_output_lines_fit(output, 79U),
          "forced non-tty progress redraws fit the 80-column fallback row");
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

    char joined_target[PATH_MAX];
    join_path(joined_target, sizeof(joined_target), target_parent,
              "joined_progress");
    char *joined_paths[] = { second_source, NULL };
    backup_test_set_progress_hook(record_backup_progress, NULL);
    int threads_before = proc_thread_count();
    result = backup(joined_target, BACKUP_EXPLICIT_PATHS, joined_paths, 0, 0);
    int threads_after = proc_thread_count();
    backup_test_set_progress_hook(NULL, NULL);
    check(result == 0 && threads_before > 0 && threads_after == threads_before,
          "a live backup joins its progress ticker before returning");

    dry_run = 0;
    if (munmap(trace, sizeof(*trace)) != 0)
    {
        printf(RED "fixture: could not release shared progress trace" NC "\n");
        exit(1);
    }
    remove_tree(home);
    remove_tree(target_parent);
}

static void test_stalled_progress_ticker(void)
{
    printf(BLUE "::" NC " production: stalled copy keeps elapsed progress live\n");
    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "progress_stall_home");
    setenv("HOME", home, 1);

    char first[PATH_MAX], stalled[PATH_MAX];
    join_path(first, sizeof(first), home, "a-first.bin");
    join_path(stalled, sizeof(stalled), home, "z-stalled.bin");
    write_large_file(first, 65536);
    write_large_file(stalled, 65536);
    char *paths[] = { first, stalled, NULL };

    char target[PATH_MAX];
    fresh_mkdtemp(target, sizeof(target), "progress_stall_target");
    ProgressStall stall = { .path = stalled };
    backup_test_set_capture_hook(stall_before_capture, &stall);
    backup_test_set_progress_hook(record_backup_progress, NULL);
    dry_run = 0;
    char output[32768];
    int result = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
    backup_test_set_progress_hook(NULL, NULL);
    backup_test_set_capture_hook(NULL, NULL);

    check(result == 0, "the injected single-path copy stall still completes");
    check(stalled_progress_advanced_elapsed_without_bytes(output),
          "ticker advances elapsed at least twice while copied bytes stay fixed");

    remove_tree(home);
    remove_tree(target);
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
    join_path(copied_link, sizeof(copied_link), payload_dir, "danglink");
    struct stat st;
    check(lstat(copied_link, &st) == 0 && S_ISLNK(st.st_mode),
          "the dangling symlink was captured as a symlink, not skipped or turned into something else");

    remove_tree(home);
    remove_tree(target);
}

static int owned_by(const char *path, uid_t uid, gid_t gid)
{
    struct stat st;
    return lstat(path, &st) == 0 && st.st_uid == uid && st.st_gid == gid;
}

// A sudo backup belongs to the user who ran sudo (D70); the payload keeps
// the owner it was captured with. Needs root to hand anything over.
static void test_sudo_backup_belongs_to_invoker(void)
{
    printf(BLUE "::" NC " production: a sudo backup's container belongs to the user who ran sudo\n");
    if (geteuid() != 0)
    {
        // Without root the handover fails, and the warning names why.
        char home[PATH_MAX], target[PATH_MAX], file[PATH_MAX], output[8192];
        fresh_mkdtemp(home, sizeof(home), "plan_home");
        setenv("HOME", home, 1);
        join_path(file, sizeof(file), home, "payload.txt");
        write_file(file, "payload");
        char *paths[] = { file, NULL };
        fresh_mkdtemp(target, sizeof(target), "plan_target");
        dry_run = 0;
        backup_test_set_invoker(1, getuid() + 1, getgid());
        int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
        backup_test_set_invoker(0, 0, 0);
        check(rc == 0 && strstr(output, "to the user who ran sudo: "
                                        "Operation not permitted") != NULL,
              "a handover that fails is a warning naming its cause");
        remove_tree(home);
        remove_tree(target);
        printf(BLUE "  (the rest needs root to hand files to another user)\n" NC);
        return;
    }
    const uid_t invoker_uid = 4242;
    const gid_t invoker_gid = 4343;

    char home[PATH_MAX], parent[PATH_MAX], target[PATH_MAX], file[PATH_MAX];
    char hidden[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(file, sizeof(file), home, "payload.txt");
    write_file(file, "payload");
    join_path(hidden, sizeof(hidden), home, ".hidden");
    write_file(hidden, "hidden");
    char *paths[] = { file, hidden, NULL };
    fresh_mkdtemp(parent, sizeof(parent), "plan_target");
    join_path(target, sizeof(target), parent, "created-by-migr");

    dry_run = 0;
    char output[8192];
    backup_test_set_invoker(1, invoker_uid, invoker_gid);
    int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output));
    backup_test_set_invoker(0, 0, 0);

    char container[PATH_MAX], data[PATH_MAX], manifest[PATH_MAX];
    char payload[PATH_MAX], settings[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(data, sizeof(data), container, "data");
    join_path(manifest, sizeof(manifest), container, "manifest.txt");
    join_path(payload, sizeof(payload), data, "payload.txt");
    join_path(settings, sizeof(settings), data, "settings");
    check(rc == 0 && found &&
              owned_by(target, invoker_uid, invoker_gid) &&
              owned_by(container, invoker_uid, invoker_gid) &&
              owned_by(data, invoker_uid, invoker_gid) &&
              owned_by(settings, invoker_uid, invoker_gid) &&
              owned_by(manifest, invoker_uid, invoker_gid),
          "the folder migr created, the container, data/, data/settings/, "
          "and manifest.txt belong to the invoker");
    check(owned_by(payload, 0, 0) && owned_by(parent, 0, 0),
          "the payload keeps its captured owner, and a folder migr did not "
          "create is left alone");
    Manifest recorded;
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int manifest_ok = container_fd >= 0 &&
                      manifest_read_v1_at(container_fd, &recorded) ==
                          MANIFEST_STATUS_VALID;
    check(manifest_ok && recorded.has_source_identity &&
              recorded.source_uid == invoker_uid,
          "the manifest records the invoker as whose data this is");
    if (manifest_ok)
        manifest_free(&recorded);
    if (container_fd >= 0)
        close(container_fd);

    remove_tree(target);
    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths, output,
                              sizeof(output));
    found = find_container_dir(target, container, sizeof(container));
    check(rc == 0 && found && owned_by(target, 0, 0) &&
              owned_by(container, 0, 0),
          "a backup that does not run through sudo hands nothing over");

    // A portable destination gets ownership from its mount, not from chown.
    remove_tree(target);
    backup_test_force_portable_representation(1);
    backup_test_set_invoker(1, invoker_uid, invoker_gid);
    char *home_paths[] = { NULL };
    rc = run_backup_capturing(target, BACKUP_CRITICAL, home_paths, output,
                              sizeof(output));
    backup_test_set_invoker(0, 0, 0);
    backup_test_force_portable_representation(0);
    found = find_container_dir(target, container, sizeof(container));
    container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    manifest_ok = container_fd >= 0 &&
                  manifest_read_v1_at(container_fd, &recorded) ==
                      MANIFEST_STATUS_VALID;
    check(rc == 0 && found && owned_by(container, 0, 0) && manifest_ok &&
              recorded.source_uid == invoker_uid,
          "a portable backup hands nothing over, and records the invoker too");
    if (manifest_ok)
        manifest_free(&recorded);
    if (container_fd >= 0)
        close(container_fd);

    remove_tree(home);
    remove_tree(parent);
}

static int count_final_containers(const char *target)
{
    DIR *dir = opendir(target);
    if (dir == NULL)
        return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        count += strncmp(entry->d_name, "migr-", 5) == 0 &&
                 strchr(entry->d_name, '.') == NULL;
    closedir(dir);
    return count;
}

typedef struct {
    const char *root_id;
    size_t count;
} RootEntryCount;

static int count_root_entries(const SidecarLiveView *view, void *context)
{
    RootEntryCount *counter = context;
    counter->count += view->entry->root_id.length == strlen(counter->root_id) &&
                      memcmp(view->entry->root_id.data, counter->root_id,
                             view->entry->root_id.length) == 0;
    return 0;
}

// Live journal entries of root_id in a portable container, or SIZE_MAX.
static size_t journal_root_entries(const char *container, const char *root_id)
{
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    SidecarLog log = {0};
    RootEntryCount counter = { .root_id = root_id };
    int ok = container_fd >= 0 &&
             sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE;
    if (ok)
        ok = sidecar_log_foreach(&log, count_root_entries, &counter) ==
             SIDECAR_STATUS_OK;
    if (ok)
        sidecar_log_close(&log);
    if (container_fd >= 0)
        close(container_fd);
    return ok ? counter.count : SIZE_MAX;
}

// A folder removed and backed up, then made again: the journal still holds
// the removed folder's deletions when the next updates run.
static void test_update_recaptures_a_recreated_folder(int portable)
{
    printf(BLUE "::" NC " production: a %s update captures a folder made again after its removal\n",
           portable ? "portable" : "native");

    char home[PATH_MAX], target[PATH_MAX], dir[PATH_MAX], sub[PATH_MAX];
    char file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(dir, sizeof(dir), home, "notes");
    join_path(sub, sizeof(sub), dir, "sub");
    join_path(file, sizeof(file), sub, "file.txt");
    mkdir_p(sub);
    write_file(file, "first");
    // Enough live items that the update keeps the deletions in the journal
    // rather than rewriting it (D73).
    for (int i = 0; i < 32; i++)
    {
        char name[32], other[PATH_MAX];
        snprintf(name, sizeof(name), "keep-%02d.txt", i);
        join_path(other, sizeof(other), dir, name);
        write_file(other, "kept");
    }
    fresh_mkdtemp(target, sizeof(target), "plan_target");

    dry_run = 0;
    backup_test_force_portable_representation(portable);
    char output[8192];
    char *paths[] = { dir, NULL };
    int first_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                        output, sizeof(output));
    remove_tree(sub);
    int second_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                         output, sizeof(output));
    int unchanged_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                            paths, output, sizeof(output));
    mkdir_p(sub);
    write_file(file, "again");
    int third_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                        output, sizeof(output));
    backup_test_force_portable_representation(0);

    char container[PATH_MAX], payload[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(payload, sizeof(payload), container, "data/notes/sub/file.txt");
    check(first_rc == 0 && second_rc == 0 && unchanged_rc == 0,
          "an update after the removal, changed or not, succeeds");
    check(third_rc == 0 && found && file_text_is(payload, "again"),
          "the folder is captured again");

    remove_tree(home);
    remove_tree(target);
}

// A root left out and a new root under the same id, as when an explicit
// path sorts ahead of an earlier one: the new root is captured afresh.
static void test_update_reuses_a_dropped_root_id(int portable)
{
    printf(BLUE "::" NC " production: a %s update captures a new root under a dropped root's id\n",
           portable ? "portable" : "native");

    char home[PATH_MAX], target[PATH_MAX], a[PATH_MAX], b[PATH_MAX];
    char file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(a, sizeof(a), home, "a/dir");
    join_path(b, sizeof(b), home, "b/dir");
    join_path(file, sizeof(file), a, "sub");
    mkdir_p(file);
    join_path(file, sizeof(file), a, "sub/file.txt");
    write_file(file, "a");
    join_path(file, sizeof(file), b, "sub");
    mkdir_p(file);
    join_path(file, sizeof(file), b, "sub/file.txt");
    write_file(file, "b");
    fresh_mkdtemp(target, sizeof(target), "plan_target");

    dry_run = 0;
    backup_test_force_portable_representation(portable);
    char output[8192];
    char *first_paths[] = { b, NULL };
    int first_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                        first_paths, output, sizeof(output));
    char *second_paths[] = { a, b, NULL };
    int second_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                         second_paths, output, sizeof(output));
    backup_test_force_portable_representation(0);

    char container[PATH_MAX], payload[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(payload, sizeof(payload), container, "data/dir/sub/file.txt");
    int a_kept = file_text_is(payload, "a");
    join_path(payload, sizeof(payload), container, "data/dir-2/sub/file.txt");
    check(first_rc == 0 && second_rc == 0 && found && a_kept &&
              file_text_is(payload, "b"),
          "both roots are captured, each in its own folder");

    remove_tree(home);
    remove_tree(target);
}

static void write_fake_process(const char *proc_root, const char *pid,
                               const char *comm)
{
    char dir[PATH_MAX], file[PATH_MAX], content[128];
    join_path(dir, sizeof(dir), proc_root, pid);
    mkdir_p(dir);
    join_path(file, sizeof(file), dir, "comm");
    snprintf(content, sizeof(content), "%s\n", comm);
    write_file(file, content);
    join_path(file, sizeof(file), dir, "status");
    uintmax_t uid = (uintmax_t)geteuid();
    snprintf(content, sizeof(content), "Name:\t%s\nUid:\t%ju\t%ju\t%ju\t%ju\n",
             comm, uid, uid, uid, uid);
    write_file(file, content);
}

// Visual Studio Code open, and so still running at the end (a fake /proc
// entry), while a live source is backed up: .config goes last (D84).
static void test_open_application_settings_are_backed_up_last(int portable)
{
    printf(BLUE "::" NC " production: a %s backup captures an open application's settings last\n",
           portable ? "portable" : "native");

    char home[PATH_MAX], target[PATH_MAX], config[PATH_MAX], notes[PATH_MAX];
    char file[PATH_MAX], proc_root[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(config, sizeof(config), home, ".config");
    join_path(file, sizeof(file), config, "Code");
    mkdir_p(file);
    join_path(file, sizeof(file), config, "Code/settings.json");
    write_file(file, "{}");
    join_path(notes, sizeof(notes), home, "notes");
    mkdir_p(notes);
    join_path(file, sizeof(file), notes, "a.txt");
    write_file(file, "a");
    join_path(proc_root, sizeof(proc_root), home, "fake-proc");
    write_fake_process(proc_root, "4242", "code");

    dry_run = 0;
    int previous_verbose = verbose;
    verbose = 1;
    backup_test_force_portable_representation(portable);
    writer_apps_test_set_proc_root(proc_root);
    char *paths[] = { config, notes, NULL };
    char unanswered[16384], again[16384], anyway[16384], closed[16384];
    const char *inputs[] = { "", "\n", "c\n" };
    char *outputs[] = { unanswered, again, anyway };
    int rcs[3];
    int saved[3];
    for (int run = 0; run < 3; run++)
    {
        fresh_mkdtemp(target, sizeof(target), "plan_target");
        rcs[run] = run_backup_capturing_input(target, BACKUP_EXPLICIT_PATHS,
                                              paths, 0, 0, inputs[run],
                                              outputs[run], sizeof(unanswered));
        char container[PATH_MAX], payload[PATH_MAX];
        saved[run] = find_container_dir(target, container, sizeof(container));
        join_path(payload, sizeof(payload), container,
                  "data/settings/config/Code/settings.json");
        saved[run] = saved[run] && file_text_is(payload, "{}");
        remove_tree(target);
    }
    writer_apps_test_set_proc_root("/nonexistent/migr-test-proc");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    int closed_rc = run_backup_capturing_input(target, BACKUP_EXPLICIT_PATHS,
                                               paths, 0, 0, "", closed,
                                               sizeof(closed));
    remove_tree(target);
    backup_test_force_portable_representation(0);
    verbose = previous_verbose;

    char announcement[PATH_MAX + 128], config_line[PATH_MAX + 32];
    char notes_line[PATH_MAX + 32];
    snprintf(announcement, sizeof(announcement),
             "Visual Studio Code is open, so %s is backed up last", config);
    snprintf(config_line, sizeof(config_line), "Capturing: %s ->", config);
    snprintf(notes_line, sizeof(notes_line), "Capturing: %s ->", notes);
    const char *prompt = "Visual Studio Code is still open. Close it and "
                         "press Enter";
    const char *note = "Note: Visual Studio Code was open while its settings "
                       "were backed up";
    const char *config_at = strstr(unanswered, config_line);
    const char *notes_at = strstr(unanswered, notes_line);
    const char *prompt_at = strstr(unanswered, prompt);
    check(rcs[0] == 0 && saved[0] && strstr(unanswered, announcement) != NULL &&
              notes_at != NULL && prompt_at != NULL && config_at != NULL &&
              notes_at < prompt_at && prompt_at < config_at,
          "the settings' root is named up front and captured after the "
          "others, once asked");
    check(strstr(unanswered, "No answer; backing them up as they are.") &&
              strstr(unanswered, note) != NULL,
          "with nobody to answer, they are captured and the summary says the "
          "application was open");
    prompt_at = strstr(again, prompt);
    check(rcs[1] == 0 && saved[1] && prompt_at != NULL &&
              strstr(prompt_at + 1, prompt) != NULL,
          "Enter checks again and asks again while it is still open");
    check(rcs[2] == 0 && saved[2] && strstr(anyway, prompt) != NULL &&
              strstr(anyway, "No answer") == NULL &&
              strstr(anyway, note) == NULL,
          "c captures them as they are, with no note");
    config_at = strstr(closed, config_line);
    notes_at = strstr(closed, notes_line);
    check(closed_rc == 0 && strstr(closed, "is backed up last") == NULL &&
              strstr(closed, "still open") == NULL && config_at != NULL &&
              notes_at != NULL && config_at < notes_at,
          "with no application open, nothing waits");

    remove_tree(home);
}

// Makes container's backup look taken on another machine.
static int mark_as_another_install(const char *container)
{
    int fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    Manifest manifest;
    int ok = fd >= 0 &&
             manifest_read_v1_at(fd, &manifest) == MANIFEST_STATUS_VALID;
    if (ok)
    {
        strcpy(manifest.machine_id, "00000000000000000000000000000000");
        ok = manifest_write_v1_at(fd, &manifest) == 0;
        manifest_free(&manifest);
    }
    if (fd >= 0)
        close(fd);
    return ok;
}

static int manifest_machine_id_is(const char *container, const char *id)
{
    int fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    Manifest manifest;
    int ok = fd >= 0 &&
             manifest_read_v1_at(fd, &manifest) == MANIFEST_STATUS_VALID;
    if (ok)
    {
        ok = strcmp(manifest.machine_id, id) == 0;
        manifest_free(&manifest);
    }
    if (fd >= 0)
        close(fd);
    return ok;
}

// A backup another install took is updated from this one only when the user
// says so; otherwise a new one is made next to it (D88).
static void test_update_takes_another_installs_backup_on_yes(int portable)
{
    printf(BLUE "::" NC " production: a %s backup of another install is updated only on yes\n",
           portable ? "portable" : "native");

    char home[PATH_MAX], target[PATH_MAX], dir[PATH_MAX], file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(dir, sizeof(dir), home, "notes");
    mkdir_p(dir);
    join_path(file, sizeof(file), dir, "file.txt");
    char *paths[] = { dir, NULL };
    static const char question[] = "was taken on another install";
    char output[8192], container[PATH_MAX];

    dry_run = 0;
    backup_test_force_portable_representation(portable);
    for (int answer_yes = 1; answer_yes >= 0; answer_yes--)
    {
        fresh_mkdtemp(target, sizeof(target), "plan_target");
        write_file(file, "first");
        int first_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                            paths, output, sizeof(output));
        int marked = first_rc == 0 &&
                     find_container_dir(target, container,
                                        sizeof(container)) &&
                     mark_as_another_install(container);
        write_file(file, "second, longer");
        int rc = run_backup_capturing_input(
            target, BACKUP_EXPLICIT_PATHS, paths, 0, 0,
            answer_yes ? "y\n" : "", output, sizeof(output));
        char payload[PATH_MAX];
        join_path(payload, sizeof(payload), container, "data/notes/file.txt");
        if (answer_yes)
            check(marked && rc == 0 && strstr(output, question) != NULL &&
                      strstr(output, "Updating the other install's backup "
                                     "in place") != NULL &&
                      count_final_containers(target) == 1 &&
                      file_text_is(payload, "second, longer") &&
                      !manifest_machine_id_is(
                          container, "00000000000000000000000000000000"),
                  "on yes, it is updated and becomes this install's");
        else
            check(marked && rc == 0 && strstr(output, question) != NULL &&
                      count_final_containers(target) == 2 &&
                      file_text_is(payload, "first"),
                  "with nobody to answer, a new backup is made next to it");
        remove_tree(target);
    }
    backup_test_force_portable_representation(0);
    remove_tree(home);
}

// A record of root_id/logical in a portable backup's journal.
static int journal_record(const char *container, const char *root_id,
                          const char *logical, uint32_t *mode,
                          uint64_t *digest)
{
    int fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    SidecarLog log = {0};
    int ok = fd >= 0 &&
             sidecar_log_adopt_at(fd, &log) == SIDECAR_OPEN_RESUMABLE;
    if (ok)
    {
        SidecarLiveView view;
        ok = sidecar_log_find(
                 &log,
                 (SidecarBytes){ (const unsigned char *)root_id,
                                 strlen(root_id) },
                 (SidecarBytes){ (const unsigned char *)logical,
                                 strlen(logical) },
                 &view) == 1;
        if (ok)
        {
            *mode = view.entry->mode;
            *digest = view.entry->content_digest;
        }
        sidecar_log_close(&log);
    }
    if (fd >= 0)
        close(fd);
    return ok;
}

// A portable update records a file whose metadata alone changed without
// copying it again, as a native update does (D88).
static void test_portable_update_records_a_metadata_change(void)
{
    printf(BLUE "::" NC " production: a portable update does not recopy a file whose metadata alone changed\n");

    char home[PATH_MAX], target[PATH_MAX], dir[PATH_MAX], file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(dir, sizeof(dir), home, "notes");
    mkdir_p(dir);
    join_path(file, sizeof(file), dir, "file.txt");
    write_file(file, "content");
    check(chmod(file, 0644) == 0, "fixture: set the file's mode");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    char *paths[] = { dir, NULL };
    char output[8192], container[PATH_MAX], payload[PATH_MAX];

    dry_run = 0;
    backup_test_force_portable_representation(1);
    uint32_t mode = 0, second_mode = 0;
    uint64_t digest = 0, second_digest = 0;
    int ok = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output)) == 0 &&
             find_container_dir(target, container, sizeof(container)) &&
             journal_record(container, "EXPLICIT_0", "file.txt", &mode,
                            &digest);
    join_path(payload, sizeof(payload), container, "data/notes/file.txt");
    // Same length, other bytes: a copy made again would put "content" back.
    write_file(payload, "CONTENT");
    check(ok && chmod(file, 0600) == 0, "fixture: back up, then change the mode");

    int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths, output,
                                  sizeof(output));
    check(rc == 0 && file_text_is(payload, "CONTENT") &&
              journal_record(container, "EXPLICIT_0", "file.txt",
                             &second_mode, &second_digest) &&
              (second_mode & 07777) == 0600 && (mode & 07777) == 0644 &&
              second_digest == digest,
          "the new mode is recorded with the same digest, and the payload is "
          "not written");

    write_file(file, "changed content");
    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths, output,
                              sizeof(output));
    check(rc == 0 && file_text_is(payload, "changed content"),
          "a changed file is still copied again");
    backup_test_force_portable_representation(0);
    remove_tree(home);
    remove_tree(target);
}

// A second backup of the same install updates the first in place (D72):
// changed files are recopied, removed ones leave the payload, and a root
// the new selection lacks is removed with its journal records.
static void test_backup_updates_in_place(int portable)
{
    printf(BLUE "::" NC " production: a second %s backup updates the first in place\n",
           portable ? "portable" : "native");

    char home[PATH_MAX], target[PATH_MAX], dir[PATH_MAX], kept[PATH_MAX];
    char removed[PATH_MAX], dropped[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(dir, sizeof(dir), home, "notes");
    mkdir_p(dir);
    join_path(kept, sizeof(kept), dir, "kept.txt");
    join_path(removed, sizeof(removed), dir, "removed.txt");
    join_path(dropped, sizeof(dropped), home, "dropped.txt");
    write_file(kept, "first");
    write_file(removed, "removed");
    write_file(dropped, "dropped");
    fresh_mkdtemp(target, sizeof(target), "plan_target");

    dry_run = 0;
    backup_test_force_portable_representation(portable);
    char output[8192];
    char *first_paths[] = { dir, dropped, NULL };
    int first_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                        first_paths, output, sizeof(output));
    char container[PATH_MAX];
    struct stat first_st = {0};
    int found = find_container_dir(target, container, sizeof(container)) &&
                stat(container, &first_st) == 0;

    write_file(kept, "second, longer");
    check(unlink(removed) == 0, "fixture: remove a backed-up file");
    char *second_paths[] = { dir, NULL };
    int second_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS,
                                         second_paths, output, sizeof(output));
    backup_test_force_portable_representation(0);

    struct stat second_st = {0};
    char payload[PATH_MAX];
    check(first_rc == 0 && second_rc == 0 && found &&
              count_final_containers(target) == 1 &&
              stat(container, &second_st) == 0 &&
              second_st.st_ino == first_st.st_ino &&
              find_partial_container_dir(target, payload, sizeof(payload)) == 0 &&
              strstr(output, "Updating this install's backup in place.") != NULL,
          "the same container is updated and published under the same name");

    join_path(payload, sizeof(payload), container, "data/notes/kept.txt");
    check(file_text_is(payload, "second, longer"), "a changed file is recopied");
    join_path(payload, sizeof(payload), container, "data/notes/removed.txt");
    check(access(payload, F_OK) != 0, "a removed file leaves the payload");
    join_path(payload, sizeof(payload), container, "data/dropped.txt");
    check(access(payload, F_OK) != 0,
          "a root the new selection lacks leaves the payload");

    Manifest recorded;
    int container_fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int manifest_ok = container_fd >= 0 &&
                      manifest_read_v1_at(container_fd, &recorded) ==
                          MANIFEST_STATUS_VALID;
    check(manifest_ok && recorded.root_count == 1 &&
              strcmp(recorded.roots[0].id, "EXPLICIT_0") == 0 &&
              recorded.updated > 0,
          "the manifest lists the new selection and when it was taken");
    if (manifest_ok)
        manifest_free(&recorded);
    if (container_fd >= 0)
        close(container_fd);
    if (portable)
        check(journal_root_entries(container, "EXPLICIT_1") == 0 &&
                  journal_root_entries(container, "EXPLICIT_0") == 2,
              "the journal keeps the kept root's entries and none of the "
              "dropped root's");

    remove_tree(home);
    remove_tree(target);
}

// Updating a finished portable backup trusts that its payload matched its
// journal and skips the item-by-item payload walk (D72), so what the walk
// would have caught must still be covered: an item whose payload is gone is
// copied again, and a stray file does not stop the update.
static void test_update_repairs_payload_without_walking_it(void)
{
    printf(BLUE "::" NC " production: a portable update recopies a missing payload file\n");

    char home[PATH_MAX], target[PATH_MAX], dir[PATH_MAX], file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(dir, sizeof(dir), home, "notes");
    mkdir_p(dir);
    join_path(file, sizeof(file), dir, "file.txt");
    write_file(file, "payload");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    char *paths[] = { dir, NULL };
    char output[8192];
    dry_run = 0;
    backup_test_force_portable_representation(1);

    int first_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                        output, sizeof(output));
    char container[PATH_MAX], payload[PATH_MAX], stray[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(payload, sizeof(payload), container, "data/notes/file.txt");
    join_path(stray, sizeof(stray), container, "data/notes/stray.txt");
    check(first_rc == 0 && found && unlink(payload) == 0,
          "fixture: remove an item's payload from a finished backup");
    write_file(stray, "not in the journal");

    int second_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                         output, sizeof(output));
    backup_test_force_portable_representation(0);
    check(second_rc == 0 && file_text_is(payload, "payload") &&
              journal_root_entries(container, "EXPLICIT_0") == 2,
          "the update copies the missing item again, and a stray file does "
          "not stop it");

    remove_tree(home);
    remove_tree(target);
}

// Every update appends to a portable journal; once dead records outweigh
// live ones it is rewritten to its live state (D73), and the next update
// takes the rewritten journal over like any other.
static void test_updates_rewrite_a_grown_journal(void)
{
    printf(BLUE "::" NC " production: repeated updates rewrite a grown journal\n");

    char home[PATH_MAX], target[PATH_MAX], dir[PATH_MAX], file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(dir, sizeof(dir), home, "notes");
    mkdir_p(dir);
    join_path(file, sizeof(file), dir, "file.txt");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    char *paths[] = { dir, NULL };
    char output[8192];
    dry_run = 0;
    backup_test_force_portable_representation(1);

    int rewritten = 0, failed = 0;
    for (int run = 0; run < 8 && !rewritten && !failed; run++)
    {
        char content[32];
        snprintf(content, sizeof(content), "version %d", run);
        write_file(file, content);
        failed = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output)) != 0;
        rewritten = strstr(output, "Rewrote the backup journal without its "
                                   "old records") != NULL;
    }
    write_file(file, "after the rewrite");
    int after_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                        output, sizeof(output));
    backup_test_force_portable_representation(0);

    char container[PATH_MAX], payload[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(payload, sizeof(payload), container, "data/notes/file.txt");
    check(!failed && rewritten, "the journal is rewritten once it has grown");
    check(after_rc == 0 && found && file_text_is(payload, "after the rewrite") &&
              journal_root_entries(container, "EXPLICIT_0") == 2,
          "the next update takes the rewritten journal over");

    remove_tree(home);
    remove_tree(target);
}

// An update that stops before changing anything gives the finished backup its
// name back instead of leaving it looking unfinished (D72).
static void test_failed_update_keeps_the_finished_backup(void)
{
    printf(BLUE "::" NC " production: an update that stops before changing anything keeps the backup as it was\n");

    char home[PATH_MAX], target[PATH_MAX], file[PATH_MAX], inside[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(file, sizeof(file), home, "item");
    write_file(file, "before");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    char *paths[] = { file, NULL };
    char output[8192];
    dry_run = 0;

    int first_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                        output, sizeof(output));
    char container[PATH_MAX], payload[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(payload, sizeof(payload), container, "data/item");

    // The item is now a folder where the backup holds a file, which the
    // metadata preflight refuses.
    unlink(file);
    mkdir_p(file);
    join_path(inside, sizeof(inside), file, "inside.txt");
    write_file(inside, "now a folder");
    int second_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                         output, sizeof(output));
    char updating[PATH_MAX + 16];
    snprintf(updating, sizeof(updating), "%s.updating", container);
    check(first_rc == 0 && found && second_rc == 2 &&
              strstr(output, "metadata preflight failed") != NULL &&
              access(container, F_OK) == 0 && access(updating, F_OK) != 0 &&
              file_text_is(payload, "before"),
          "the backup keeps its finished name and content");

    remove_tree(home);
    remove_tree(target);
}

typedef struct {
    const char *folder;   /* Gets a new file when the preflight opens it. */
    const char *vanished; /* Removed when the preflight opens it. */
} PreflightChange;

static void change_source_during_preflight(const char *source_path,
                                           void *context)
{
    const PreflightChange *change = context;
    if (strcmp(source_path, change->vanished) == 0)
        unlink(source_path);
    if (strcmp(source_path, change->folder) == 0)
    {
        char added[PATH_MAX];
        join_path(added, sizeof(added), source_path, "added.txt");
        write_file(added, "written meanwhile");
    }
}

// The native metadata preflight walks the whole source before capture; what
// changes under it meanwhile is left to capture (D63), not a refusal.
static void test_native_preflight_of_a_changing_source(void)
{
    printf(BLUE "::" NC " production: a native preflight goes on when its source changes under it\n");

    char home[PATH_MAX], target[PATH_MAX], work[PATH_MAX], gone[PATH_MAX];
    char kept[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(work, sizeof(work), home, "work");
    mkdir_p(work);
    join_path(gone, sizeof(gone), work, "gone.txt");
    join_path(kept, sizeof(kept), work, "kept.txt");
    write_file(gone, "removed during the preflight");
    write_file(kept, "kept");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    char *paths[] = { work, NULL };
    char output[8192];
    dry_run = 0;

    PreflightChange change = { .folder = work, .vanished = gone };
    backup_test_set_inventory_hook(change_source_during_preflight, &change);
    int rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output));
    backup_test_set_inventory_hook(NULL, NULL);
    char container[PATH_MAX], payload[PATH_MAX];
    int found = find_container_dir(target, container, sizeof(container));
    join_path(payload, sizeof(payload), container,
              "data/work/kept.txt");
    check(rc == 0 && found && strstr(output, "preflight failed") == NULL &&
              file_text_is(payload, "kept"),
          "a file removed and a folder written during the preflight do not "
          "stop the backup");

    remove_tree(home);
    remove_tree(target);
}

// A backup of this user's name that belongs to another install is left alone
// (D71, D72): this install gets a dated backup of its own and updates it.
static void test_backup_leaves_another_install_alone(void)
{
    printf(BLUE "::" NC " production: another install's backup is left alone\n");

    char home[PATH_MAX], target[PATH_MAX], file[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "plan_home");
    setenv("HOME", home, 1);
    join_path(file, sizeof(file), home, "file.txt");
    write_file(file, "old install");
    fresh_mkdtemp(target, sizeof(target), "plan_target");
    char *paths[] = { file, NULL };
    char output[8192];
    dry_run = 0;

    backup_test_set_machine_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    int old_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
    char old_container[PATH_MAX], old_payload[PATH_MAX];
    int found = find_container_dir(target, old_container,
                                   sizeof(old_container));
    join_path(old_payload, sizeof(old_payload), old_container,
              "data/file.txt");

    write_file(file, "new install");
    backup_test_set_machine_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    int new_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                      output, sizeof(output));
    check(old_rc == 0 && new_rc == 0 && found &&
              count_final_containers(target) == 2 &&
              file_text_is(old_payload, "old install") &&
              strstr(output, "belongs to another install") != NULL,
          "the new install gets its own dated backup; the old one is untouched");

    new_rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, paths,
                                  output, sizeof(output));
    backup_test_set_machine_id(NULL);
    check(new_rc == 0 && count_final_containers(target) == 2 &&
              strstr(output, "Updating this install's backup in place.") != NULL &&
              file_text_is(old_payload, "old install"),
          "the next run updates the new install's backup, not the old one");

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
    join_path(copied_profile, sizeof(copied_profile), payload_dir, "settings/profile");
    struct stat st;
    check(lstat(copied_profile, &st) == 0 && S_ISLNK(st.st_mode),
          "the dangling .profile symlink the plan promised to capture actually made it into the backup");

    remove_tree(home);
    remove_tree(target);
}

// Where name's "Capturing:" line starts in output, or NULL.
static const char *capture_line(const char *output, const char *home,
                                const char *name)
{
    char line[PATH_MAX + 32];
    snprintf(line, sizeof(line), "Capturing: %s/%s -> ", home, name);
    return strstr(output, line);
}

static void test_comprehensive_captures_critical_roots_first(void)
{
    printf(BLUE "::" NC " production: --comprehensive captures the --critical roots first\n");

    char home[PATH_MAX], target[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "critical_first_home");
    setenv("HOME", home, 1);
    static const char *const critical[] = { "Documents", ".ssh", "notes" };
    static const char *const later[] = { "Music", "Videos", "Projects" };
    for (size_t i = 0; i < 3; i++)
    {
        char path[PATH_MAX];
        join_path(path, sizeof(path), home, critical[i]);
        mkdir_p(path);
        join_path(path, sizeof(path), home, later[i]);
        mkdir_p(path);
    }
    char projects[PATH_MAX], notes[PATH_MAX];
    join_path(projects, sizeof(projects), home, "Projects");
    join_path(notes, sizeof(notes), home, "notes");
    ConfigRule rules[] = {
        { .scope = CONFIG_COMPREHENSIVE, .action = CONFIG_INCLUDE,
          .path = projects, .line = 1 },
        { .scope = CONFIG_CRITICAL, .action = CONFIG_INCLUDE,
          .path = notes, .line = 2 },
    };
    Config config = { .rules = rules, .count = 2 };

    SelectionPlan plan = {0};
    check(selection_plan_build(home, BACKUP_COMPREHENSIVE, &config, &plan) == 0,
          "the comprehensive plan builds");
    int flags_ok = plan.root_count == 6;
    for (size_t i = 0; i < plan.root_count; i++)
    {
        const char *leaf = strrchr(plan.roots[i].root.capture_path, '/') + 1;
        int expected = strcmp(leaf, "Music") == 0 ||
                       strcmp(leaf, "Videos") == 0 ||
                       strcmp(leaf, "Projects") == 0;
        flags_ok = flags_ok &&
                   plan.roots[i].root.comprehensive_only == expected;
    }
    check(flags_ok, "Videos, Music, and a comprehensive include are the "
                    "roots only --comprehensive takes");
    selection_plan_free(&plan);

    fresh_mkdtemp(target, sizeof(target), "critical_first_target");
    int previous_verbose = verbose;
    verbose = 1;
    dry_run = 0;
    char output[32768];
    int rc = run_scoped_backup_capturing_input(
        target, BACKUP_COMPREHENSIVE, &config, NULL, output, sizeof(output));
    verbose = previous_verbose;
    const char *last_critical = output;
    const char *first_later = NULL;
    int all_found = 1;
    for (size_t i = 0; i < 3; i++)
    {
        const char *c = capture_line(output, home, critical[i]);
        const char *l = capture_line(output, home, later[i]);
        all_found = all_found && c != NULL && l != NULL;
        if (c != NULL && c > last_critical)
            last_critical = c;
        if (l != NULL && (first_later == NULL || l < first_later))
            first_later = l;
    }
    check(rc == 0 && all_found && last_critical < first_later,
          "every critical root is captured before the first comprehensive one");

    remove_tree(target);
    remove_tree(home);
}

static void test_shell_history_consent_gate(void)
{
    printf(BLUE "::" NC " production: scoped shell-history capture requires explicit consent\n");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "history_home");
    setenv("HOME", home, 1);
    char bash_history[PATH_MAX];
    char zsh_history[PATH_MAX];
    join_path(bash_history, sizeof(bash_history), home, ".bash_history");
    join_path(zsh_history, sizeof(zsh_history), home, ".zsh_history");
    write_file(bash_history, "token typed by accident\n");
    write_file(zsh_history, "another secret-shaped line\n");

    BackupPlan catalog_plan;
    check(backup_plan_build(home, BACKUP_CRITICAL, NULL, &catalog_plan) == 0,
          "history fixture builds a critical catalog plan");
    check(find_root(&catalog_plan, "BUILTIN_DOT_BASH_HISTORY") != NULL,
          ".bash_history is a critical built-in when present");
    check(find_root(&catalog_plan, "BUILTIN_DOT_ZSH_HISTORY") != NULL,
          ".zsh_history is a critical built-in when present");
    backup_plan_free(&catalog_plan);

    Config empty_config = {0};
    char output[16384];
    char target[PATH_MAX];

    fresh_mkdtemp(target, sizeof(target), "history_target");
    dry_run = 0;
    int rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, "n\n", output, sizeof(output));
    check(rc == 0, "declining shell-history capture is a successful cancellation");
    check(strstr(output, ".bash_history, .zsh_history") != NULL &&
          strstr(output, "[Y/n]") != NULL,
          "the consent prompt names both selected history files and shows default yes");
    check(directory_empty(target), "decline leaves no backup container behind");
    remove_tree(target);

    fresh_mkdtemp(target, sizeof(target), "history_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, NULL, output, sizeof(output));
    check(rc == 0 && strstr(output, "Backup cancelled") != NULL,
          "true EOF declines the default-yes backup prompt");
    check(directory_empty(target), "EOF cancellation leaves no backup container behind");
    remove_tree(target);

    fresh_mkdtemp(target, sizeof(target), "history_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, "y\n", output, sizeof(output));
    check(rc == 0, "explicit y accepts shell-history capture");
    char payload[PATH_MAX];
    check(find_payload_dir(target, payload, sizeof(payload)),
          "accepted shell-history backup publishes a container");
    char copied[PATH_MAX];
    join_path(copied, sizeof(copied), payload, "settings/bash-history");
    check(access(copied, F_OK) == 0, "accepted backup captures .bash_history");
    join_path(copied, sizeof(copied), payload, "settings/zsh-history");
    check(access(copied, F_OK) == 0, "accepted backup captures .zsh_history");
    remove_tree(target);

    fresh_mkdtemp(target, sizeof(target), "history_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, "\n", output, sizeof(output));
    check(rc == 0 && find_payload_dir(target, payload, sizeof(payload)),
          "bare Enter accepts the displayed default and runs the backup");
    remove_tree(target);

    check(unlink(zsh_history) == 0, "fixture removes only .zsh_history");
    fresh_mkdtemp(target, sizeof(target), "history_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, "n\n", output, sizeof(output));
    check(rc == 0 && strstr(output, ".bash_history") != NULL &&
          strstr(output, ".zsh_history") == NULL,
          "single-file prompt names only the history file that is selected");
    remove_tree(target);

    check(unlink(bash_history) == 0, "fixture removes .bash_history too");
    fresh_mkdtemp(target, sizeof(target), "history_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, NULL, output, sizeof(output));
    check(rc == 0 && strstr(output, "[Y/n]") == NULL,
          "a scoped backup with no history files never prompts");
    remove_tree(target);

    write_file(bash_history, "bash\n");
    write_file(zsh_history, "zsh\n");
    fresh_mkdtemp(target, sizeof(target), "history_target");
    dry_run = 1;
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, NULL, output, sizeof(output));
    check(rc == 0 && strstr(output, "Security notice:") != NULL &&
          strstr(output, ".bash_history, .zsh_history") != NULL,
          "dry-run reports the selected secret-capable history files");
    check(strstr(output, "[Y/n]") == NULL,
          "dry-run does not prompt even with closed stdin");
    dry_run = 0;
    remove_tree(target);

    ConfigRule broad_rule = {
        .scope = CONFIG_CRITICAL,
        .action = CONFIG_INCLUDE,
        .path = home,
        .line = 1,
    };
    Config broad_config = { .rules = &broad_rule, .count = 1 };
    SelectionPlan broad_selection = {0};
    check(selection_plan_build(home, BACKUP_CRITICAL, &broad_config,
                               &broad_selection) == 0,
          "broad HOME include compiles for the ownership regression");
    int broader_owner = 0;
    for (size_t i = 0; i < broad_selection.root_count; i++)
    {
        const char *id = broad_selection.roots[i].root.manifest_root.id;
        if (strcmp(id, "BUILTIN_DOT_BASH_HISTORY") != 0 &&
            selection_source_owns(&broad_selection.roots[i], bash_history) == 1)
            broader_owner = 1;
    }
    check(broader_owner, "a broader compiled root owns .bash_history in the fixture");
    selection_plan_free(&broad_selection);
    fresh_mkdtemp(target, sizeof(target), "history_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &broad_config, "n\n", output, sizeof(output));
    check(rc == 0 && strstr(output, ".bash_history") != NULL,
          "the consent gate fires when a broader compiled root owns history");
    check(directory_empty(target), "broad-root decline still creates no container");
    remove_tree(target);

    fresh_mkdtemp(target, sizeof(target), "history_target");
    char *explicit_paths[] = { bash_history, NULL };
    rc = run_backup_capturing(target, BACKUP_EXPLICIT_PATHS, explicit_paths,
                              output, sizeof(output));
    check(rc == 0 && strstr(output, "[Y/n]") == NULL,
          "explicit-path history backup is not gated");
    check(find_payload_dir(target, payload, sizeof(payload)),
          "explicit history backup publishes a container");
    join_path(copied, sizeof(copied), payload, "settings/bash-history");
    check(access(copied, F_OK) == 0, "explicit history path is captured");
    remove_tree(target);

    remove_tree(home);
}

// A backup that takes the login keyring ends by asking for the same password
// on the new system (D87).
static void test_login_keyring_note(void)
{
    printf(BLUE "::" NC " production: a backup with the login keyring asks for the same password\n");

    char home[PATH_MAX], keyrings[PATH_MAX], keyring[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "keyring_home");
    setenv("HOME", home, 1);
    join_path(keyrings, sizeof(keyrings), home, ".local/share/keyrings");
    mkdir_p(keyrings);
    join_path(keyring, sizeof(keyring), keyrings, "login.keyring");
    write_file(keyring, "encrypted");

    static const char note[] = "Use the same password for your user on the "
                               "new system.";
    Config empty_config = {0};
    char output[16384];
    char target[PATH_MAX];
    dry_run = 0;
    fresh_mkdtemp(target, sizeof(target), "keyring_target");
    int rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, NULL, output, sizeof(output));
    const char *at = strstr(output, note);
    check(rc == 0 && at != NULL && strstr(at, "Location:") == NULL,
          "the note ends the run");
    remove_tree(target);

    ConfigRule exclude = {
        .scope = CONFIG_CRITICAL,
        .action = CONFIG_EXCLUDE,
        .path = keyrings,
        .line = 1,
    };
    Config excluding = { .rules = &exclude, .count = 1 };
    fresh_mkdtemp(target, sizeof(target), "keyring_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &excluding, NULL, output, sizeof(output));
    check(rc == 0 && strstr(output, note) == NULL,
          "an excluded keyring gets no note");
    remove_tree(target);

    dry_run = 1;
    fresh_mkdtemp(target, sizeof(target), "keyring_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, NULL, output, sizeof(output));
    dry_run = 0;
    check(rc == 0 && strstr(output, note) == NULL,
          "a dry run gets no note");
    remove_tree(target);

    check(unlink(keyring) == 0, "fixture removes the keyring");
    fresh_mkdtemp(target, sizeof(target), "keyring_target");
    rc = run_scoped_backup_capturing_input(
        target, BACKUP_CRITICAL, &empty_config, NULL, output, sizeof(output));
    check(rc == 0 && strstr(output, note) == NULL,
          "a home without a keyring gets no note");
    remove_tree(target);

    remove_tree(home);
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
    // A direct sudo run must not aim restores at the invoking user's home
    // (D38); make and test.sh drop SUDO_UID already.
    unsetenv("SUDO_UID");
    // Nor on which applications happen to be running on the test machine.
    writer_apps_test_set_proc_root("/nonexistent/migr-test-proc");
    printf(BLUE "::" NC " backup root planner (unit)\n");

    test_critical_root_set();
    test_comprehensive_adds_extra_roots();
    test_missing_optional_builtin_is_skipped_not_fatal();
    test_localized_xdg_uses_canonical_id();
    test_fixed_builtin_fields();
    test_payload_names();
    test_builtin_config_collapses_browser_descendant();
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
    test_planning_keeps_access_times();
#ifdef BACKUP_PLAN_TEST_HOOKS
    test_estimate_survives_ancestor_rename_mid_walk();
#endif
    test_allocation_aware_estimate();
    test_destination_space_preflight();
    test_update_counts_the_backup_it_replaces(0);
    test_update_counts_the_backup_it_replaces(1);
    test_include_self_backup();
    test_native_backup_of_a_changing_source();
    test_include_network_config_backup();
    test_portable_prescan_failure_diagnostics();
    test_portable_sidecar_readback();
    test_vscode_extension_snapshot();
    test_format_duration();
    test_progress_speed_is_cumulative_average();
    test_live_progress();
    test_stalled_progress_ticker();
    test_missing_explicit_path_rejects_before_target_creation();
    test_overlap_rejected_before_destination_created_live_and_dry_run();
    test_dangling_explicit_leaf_symlink_is_captured_as_symlink();
    test_sudo_backup_belongs_to_invoker();
    test_backup_updates_in_place(0);
    test_backup_updates_in_place(1);
    test_update_takes_another_installs_backup_on_yes(0);
    test_update_takes_another_installs_backup_on_yes(1);
    test_portable_update_records_a_metadata_change();
    test_update_reuses_a_dropped_root_id(0);
    test_update_reuses_a_dropped_root_id(1);
    test_update_recaptures_a_recreated_folder(0);
    test_update_recaptures_a_recreated_folder(1);
    test_open_application_settings_are_backed_up_last(0);
    test_open_application_settings_are_backed_up_last(1);
    test_backup_leaves_another_install_alone();
    test_failed_update_keeps_the_finished_backup();
    test_native_preflight_of_a_changing_source();
    test_update_repairs_payload_without_walking_it();
    test_updates_rewrite_a_grown_journal();
    test_dangling_builtin_dotfile_is_captured_not_silently_dropped();
    test_shell_history_consent_gate();
    test_comprehensive_captures_critical_roots_first();
    test_login_keyring_note();
    test_unusable_target_does_not_leak_the_plan();

    if (failures > 0)
    {
        printf(RED "%d backup plan test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
