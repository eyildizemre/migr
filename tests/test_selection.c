#define _GNU_SOURCE
#include "selection.h"
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); failures++; } } while (0)

static void file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    CHECK(fputs(contents, f) >= 0);
    CHECK(fclose(f) == 0);
}
static int remove_entry(const char *p, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st; (void)type; (void)ftw;
    return remove(p);
}
static int build(const char *home, BackupMode mode, const char *text, SelectionPlan *plan)
{
    Config config = {0};
    CHECK(config_parse(text, strlen(text), "fixture", &config) == 0);
    int rc = selection_plan_build(home, mode, &config, plan);
    config_free(&config);
    return rc;
}
static int find_root(const SelectionPlan *plan, const char *leaf)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s%s", plan->home, *leaf ? "/" : "", leaf);
    for (size_t i = 0; i < plan->root_count; i++)
        if (!strcmp(plan->roots[i].root.capture_path, path)) return (int)i;
    return -1;
}
static int same(const SelectionPlan *a, const SelectionPlan *b)
{
    if (a->root_count != b->root_count || a->excludes.count != b->excludes.count) return 0;
    for (size_t i = 0; i < a->root_count; i++)
        if (memcmp(&a->roots[i].root, &b->roots[i].root, sizeof(BackupPlanRoot)) ||
            a->roots[i].parent != b->roots[i].parent || a->roots[i].xdg_aliases != b->roots[i].xdg_aliases) return 0;
    for (size_t i = 0; i < a->excludes.count; i++)
        if (strcmp(a->excludes.paths[i], b->excludes.paths[i])) return 0;
    return 1;
}
int main(void)
{
    char temp[] = "/tmp/migr-selection-XXXXXX";
    CHECK(mkdtemp(temp) != NULL);
    CHECK(chdir(temp) == 0);
    CHECK(mkdir("home", 0700) == 0);
    CHECK(chdir("home") == 0);
    char *home = getcwd(NULL, 0);
    CHECK(home != NULL);
    CHECK(mkdir("Documents", 0700) == 0);
    CHECK(mkdir("Downloads", 0700) == 0);
    CHECK(mkdir("Downloads/ISO", 0700) == 0);
    CHECK(mkdir("Pictures", 0700) == 0);
    CHECK(mkdir(".config", 0700) == 0);
    CHECK(mkdir(".config/google-chrome", 0700) == 0);
    CHECK(mkdir("extra", 0700) == 0);
    CHECK(mkdir("extra/child", 0700) == 0);
    file(".profile", "profile\n");
    SelectionPlan a = {0}, b = {0};
    CHECK(selection_plan_build(home, BACKUP_CRITICAL, NULL, &a) == 0);
    CHECK(build(home, BACKUP_CRITICAL, "", &b) == 0 && same(&a, &b));
    BackupPlan legacy = {0};
    CHECK(backup_plan_build(home, BACKUP_CRITICAL, NULL, &legacy) == 0);
    CHECK((size_t)legacy.root_count == a.root_count);
    for (int i = 0; i < legacy.root_count; i++)
    {
        int found = 0;
        for (size_t j = 0; j < a.root_count; j++)
            if (!memcmp(&legacy.roots[i], &a.roots[j].root, sizeof(BackupPlanRoot))) found = 1;
        CHECK(found);
    }
    backup_plan_free(&legacy);
    selection_plan_free(&b);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nDocuments\nDocuments\n.config/google-chrome\n", &b) == 0 && same(&a, &b));
    selection_plan_free(&a); selection_plan_free(&b);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nextra/child\n.config\nextra\nextra\n", &a) == 0);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nextra\n.config\nextra/child\n", &b) == 0 && same(&a, &b));
    CHECK(find_root(&a, ".config") >= 0 && find_root(&a, ".config/google-chrome") < 0);
    CHECK(find_root(&a, "extra/child") < 0);
    selection_plan_free(&a); selection_plan_free(&b);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\n~/\n[exclude]\nDownloads/ISO\nDownloads/ISO/missing\n", &a) == 0);
    int owner = find_root(&a, ""), docs = find_root(&a, "Documents"), downloads = find_root(&a, "Downloads");
    CHECK(owner >= 0 && docs >= 0 && downloads >= 0);
    if (owner >= 0 && docs >= 0 && downloads >= 0)
    {
        CHECK(a.roots[docs].parent == owner);
        CHECK(selection_plan_validate(&a) == 0);
        a.roots[docs].parent = -1;
        CHECK(selection_plan_validate(&a) < 0);
        a.roots[docs].parent = owner;
        CHECK(selection_root_owns(&a.roots[owner], "Documents") == 0);
        CHECK(selection_root_owns(&a.roots[owner], "Documents/file") == 0);
        CHECK(selection_root_owns(&a.roots[owner], "Documents-old/file") == 1);
        CHECK(selection_root_owns(&a.roots[docs], "") == 1);
        CHECK(selection_root_owns(&a.roots[downloads], "ISO/file") == 0);
        CHECK(selection_root_owns(&a.roots[downloads], "ISO-old") == 1);
        CHECK(selection_root_owns(&a.roots[downloads], "../elsewhere") < 0);
        char destination[PATH_MAX];
        snprintf(destination, sizeof(destination), "%s/Downloads/ISO/new", home);
        CHECK(selection_destination_conflicts(&a, destination) == 1);
    }
    CHECK(a.excludes.count == 1);
    selection_plan_free(&a);
    const char *scopes = "[critical]\n[include]\nextra\n[exclude]\nDocuments\n[comprehensive]\n[exclude]\nPictures\n";
    CHECK(build(home, BACKUP_CRITICAL, scopes, &a) == 0);
    CHECK(find_root(&a, "Documents") < 0 && find_root(&a, "Pictures") >= 0);
    CHECK(build(home, BACKUP_COMPREHENSIVE, scopes, &b) == 0);
    CHECK(find_root(&b, "extra") >= 0 && find_root(&b, "Documents") >= 0 && find_root(&b, "Pictures") < 0);
    selection_plan_free(&a); selection_plan_free(&b);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nmissing/deep\n[exclude]\nmissing\n", &a) == 0);
    selection_plan_free(&a);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nmissing/deep\n", &a) < 0);
    CHECK(a.root_count == 0 && a.roots == NULL);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nmissing/../Documents\n", &a) < 0);
    CHECK(chmod("Downloads", 0000) == 0);
    if (geteuid() != 0)
    {
        CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nDownloads\n", &a) < 0);
        /* D34: an unreadable *built-in* root is not the same as a missing
         * one, but it must still be skippable at plan-build time -- only a
         * configured include that survives to be unreadable fails the
         * build. With no config at all, selection_plan_build() must succeed
         * and carry the unreadable built-in through exactly as the legacy
         * backup_plan_build() planner does, leaving the metadata preflight
         * to report it later. */
        SelectionPlan unreadable_builtin = {0};
        CHECK(build(home, BACKUP_CRITICAL, "", &unreadable_builtin) == 0);
        BackupPlan legacy_unreadable = {0};
        CHECK(backup_plan_build(home, BACKUP_CRITICAL, NULL, &legacy_unreadable) == 0);
        CHECK((size_t)legacy_unreadable.root_count == unreadable_builtin.root_count);
        for (int i = 0; i < legacy_unreadable.root_count; i++)
        {
            int found = 0;
            for (size_t j = 0; j < unreadable_builtin.root_count; j++)
                if (!memcmp(&legacy_unreadable.roots[i], &unreadable_builtin.roots[j].root,
                            sizeof(BackupPlanRoot))) found = 1;
            CHECK(found);
        }
        backup_plan_free(&legacy_unreadable);
        selection_plan_free(&unreadable_builtin);
    }
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nDownloads/private/deep\n[exclude]\nDownloads/private\nDownloads\n", &a) == 0);
    CHECK(find_root(&a, "Downloads") < 0 && a.excludes.count == 1);
    selection_plan_free(&a);
    CHECK(chmod("Downloads", 0700) == 0);
    char invalid[PATH_MAX];
    strcpy(invalid, "[critical]\n[include]\nDownloads/");
    size_t prefix = strlen(invalid);
    memset(invalid + prefix, 'a', NAME_MAX + 1U);
    strcpy(invalid + prefix + NAME_MAX + 1U, "\n[exclude]\nDownloads\n");
    CHECK(build(home, BACKUP_CRITICAL, invalid, &a) < 0);
    CHECK(symlink("extra", "alias") == 0);
    CHECK(symlink("missing", "dangling") == 0);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nalias/\n", &a) == 0);
    CHECK(find_root(&a, "alias") >= 0 && find_root(&a, "extra") < 0);
    selection_plan_free(&a);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nalias/.\n", &a) == 0);
    CHECK(find_root(&a, "extra") >= 0 && find_root(&a, "alias") < 0);
    selection_plan_free(&a);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\nalias/child\nextra/child\ndangling\n", &a) == 0);
    CHECK(find_root(&a, "extra/child") >= 0 && find_root(&a, "alias/child") < 0 && find_root(&a, "dangling") >= 0);
    selection_plan_free(&a);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\n../\n", &a) == 0);
    CHECK(a.root_count >= 1 && a.roots[0].root.manifest_root.policy == ROOT_POLICY_MANUAL_NATIVE);
    selection_plan_free(&a);
    file(".config/user-dirs.dirs", "XDG_DOCUMENTS_DIR=\"$HOME/extra\"\nXDG_DOWNLOAD_DIR=\"$HOME/extra\"\nXDG_PICTURES_DIR=\"$HOME/extra/child\"\n");
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\n~/\n", &a) == 0);
    int extra = find_root(&a, "extra"), child = find_root(&a, "extra/child");
    CHECK(extra >= 0 && child >= 0);
    if (extra >= 0 && child >= 0)
    {
        CHECK(!strcmp(a.roots[extra].root.manifest_root.id, "XDG_DOCUMENTS_DIR"));
        CHECK(a.roots[extra].xdg_aliases == 3);
        CHECK(a.roots[child].parent == extra);
        CHECK(selection_root_owns(&a.roots[extra], "child") == 0);
    }
    selection_plan_free(&a);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\n~/\n[exclude]\nextra\n", &a) == 0);
    CHECK(find_root(&a, "extra") < 0 && find_root(&a, "extra/child") < 0);
    selection_plan_free(&a);
    file(".config/user-dirs.dirs", "XDG_DOCUMENTS_DIR=\"$HOME\"\n");
    CHECK(build(home, BACKUP_CRITICAL, "", &a) == 0);
    owner = find_root(&a, "");
    CHECK(owner >= 0);
    if (owner >= 0) CHECK(a.roots[owner].root.manifest_root.policy == ROOT_POLICY_HOME_RELATIVE);
    selection_plan_free(&a);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[exclude]\n~/\n", &a) == 0 && a.root_count == 0);
    selection_plan_free(&a);
    CHECK(unlink(".config/user-dirs.dirs") == 0);
    CHECK(rename(".config", "../config-outside") == 0);
    CHECK(symlink("../config-outside", ".config") == 0);
    CHECK(build(home, BACKUP_CRITICAL, "[critical]\n[include]\n../config-outside\n", &a) == 0);
    int mapped_browser = 0;
    for (size_t i = 0; i < a.root_count; i++)
        if (!strcmp(a.roots[i].root.manifest_root.id, "BUILTIN_BROWSER_GOOGLE_CHROME"))
        {
            CHECK(a.roots[i].parent >= 0);
            CHECK(a.roots[i].root.manifest_root.policy == ROOT_POLICY_HOME_RELATIVE);
            CHECK(!strcmp(a.roots[i].root.manifest_root.restore_path, ".config/google-chrome"));
            mapped_browser = 1;
        }
    CHECK(mapped_browser);
    selection_plan_free(&a);
    const char *paths[] = {"extra", "extra/child", NULL};
    CHECK(backup_plan_build(home, BACKUP_EXPLICIT_PATHS, paths, &legacy) < 0);
    backup_plan_free(&legacy);
    CHECK(chdir("/") == 0);
    CHECK(nftw(temp, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    free(home);
    printf("selection tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
