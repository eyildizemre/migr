#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <errno.h>

#include "backup.h"
#include "backup_plan.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "packages.h"
#include "utils.h"
#include "xdg.h"

// Return the final path component as a span, ignoring trailing slashes.
static size_t path_leaf(const char *path, const char **leaf)
{
    const char *end = path + strlen(path);
    while (end > path && end[-1] == '/')
        end--;

    const char *start = end;
    while (start > path && start[-1] != '/')
        start--;

    *leaf = start;
    return (size_t)(end - start);
}

// create directory if it doesn't exist
static int create_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            printf("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    if (errno != ENOENT)
    {
        // A real access failure (e.g. EACCES) must not masquerade as "absent";
        // otherwise dry-run would promise to create something it cannot reach.
        printf("Error: Could not access %s\n", path);
        return 1;
    }

    if (dry_run)
    {
        printf("[dry-run] Would create directory: %s\n", path);
        return 0;
    }

    if (mkdir(path, 0755) != 0)
    {
        printf("Error: Could not create directory %s\n", path);
        return 1;
    }
    return 0;
}

// Validate and, if needed, create the top-level backup destination.
// Sets *created only when THIS call made the directory, so a later refusal can
// roll back exactly what we created — never a pre-existing directory, and never
// one a racing process slipped in between our check and mkdir.
static int ensure_target_root(const char *path, int *created)
{
    *created = 0;

    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            printf("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    if (errno != ENOENT)
    {
        printf("Error: Could not access %s\n", path);
        return 1;
    }

    if (dry_run)
    {
        printf("[dry-run] Would create directory: %s\n", path);
        return 0;
    }

    if (mkdir(path, 0755) == 0)
    {
        *created = 1;
        return 0;
    }
    if (errno == EEXIST)
    {
        // Lost a race: someone created the path between our stat and mkdir.
        // Accept it only if it is a directory, and never claim we made it.
        if (stat(path, &st) != 0)
        {
            printf("Error: Could not access %s\n", path);
            return 1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            printf("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    printf("Error: Could not create directory %s\n", path);
    return 1;
}

static int clone_item(const CloneContext *ctx, const char *src, const char *dest)
{
    // Compute the destination before the dry-run branch so a path that would be
    // refused live is refused in dry-run too: the preview must match reality.
    const char *name;
    size_t name_len = path_leaf(src, &name);
    if (name_len == 0)
    {
        printf("Error: Path has no destination name: %s\n", src);
        return 1;
    }

    char full_dest[PATH_MAX];
    if (path_join_n(full_dest, sizeof(full_dest), dest, name, name_len) != 0)
    {
        printf("Error: Destination path too long for %s\n", src);
        return 1;
    }

    if (dry_run)
    {
        printf("  Would copy: %s -> %s\n", src, full_dest);
        return 0;
    }

    if (verbose)
        printf("  Copying: %s\n", src);

    if (backup_capture(ctx, src, full_dest) != 0)
    {
        printf("Error: Failed to copy %s\n", src);
        return 1;
    }
    return 0;
}

// Clones a known-existing source into backup_dir/rel_path, preserving
// rel_path's own directory structure (its parent components, e.g. ".config",
// are created first). Unlike the flat clone_item(), rel_path may itself
// contain '/'.
//
// src is the caller's already-resolved, already-verified source address
// (BackupPlanRoot.capture_path) -- never re-derived from home+rel_path here,
// and checked with lstat() rather than a symlink-following stat(): the plan
// already proved this exact object (a dangling symlink included) exists, so
// re-deriving the path and re-stat()ing it could silently disagree with the
// plan for a dangling leaf symlink, dropping a promised root without ever
// reporting an error. A source that has genuinely vanished (or become
// inaccessible) since planning is therefore a real error here, never a
// silent "not found, skip" -- the plan already promised this root would be
// captured. Returns 1 if copied, -1 on error.
static int clone_nested(const CloneContext *ctx, const char *src, const char *backup_dir, const char *rel_path)
{
    struct stat st;
    if (lstat(src, &st) != 0)
    {
        printf("Error: Could not access %s\n", src);
        return -1;
    }

    char dest[PATH_MAX];
    if (path_join(dest, sizeof(dest), backup_dir, rel_path) != 0)
        return -1;

    // Split the path to create parent directories first.
    // The OS kernel will throw ENOENT if we try to copy into a non-existent parent directory.
    const char *slash = strrchr(rel_path, '/');
    if (slash)
    {
        char parent[PATH_MAX];
        if (path_join_n(parent, sizeof(parent), backup_dir, rel_path, (size_t)(slash - rel_path)) != 0)
            return -1;
        if (create_dir(parent) != 0)
            return -1;
    }

    if (dry_run)
    {
        printf("  Would copy: %s -> %s\n", src, dest);
        return 1;
    }

    if (verbose)
        printf("  Copying: %s\n", src);

    if (backup_capture(ctx, src, dest) != 0)
    {
        printf("Error: Failed to copy %s\n", src);
        return -1;
    }
    return 1;
}

// Transitional flat-layout compatibility gates (docs/DECISIONS.md D16
// roadmap): the planner itself accepts two explicit roots sharing a
// basename, and a "/" MANUAL_NATIVE root, as legitimate distinct roots --
// but today's writer still clones every root to a single flat
// backup_dir/<basename>, which cannot represent either. Both checks belong
// here, not in backup_plan.c, and must be deleted outright once A2.6's
// data/EXPLICIT_n addressing replaces this writer.
static int flat_layout_incompatible(const BackupPlan *plan)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        if (plan->roots[i].group != BACKUP_ROOT_EXPLICIT)
            continue;

        const char *name_i;
        size_t len_i = path_leaf(plan->roots[i].capture_path, &name_i);
        if (len_i == 0)
        {
            printf("Error: '%s' has no destination name; the current flat backup layout "
                   "cannot represent it.\n", plan->roots[i].capture_path);
            return 1;
        }

        for (int j = i + 1; j < plan->root_count; j++)
        {
            if (plan->roots[j].group != BACKUP_ROOT_EXPLICIT)
                continue;

            const char *name_j;
            size_t len_j = path_leaf(plan->roots[j].capture_path, &name_j);
            if (len_i == len_j && memcmp(name_i, name_j, len_i) == 0)
            {
                printf("Error: these paths share the name '%.*s' and would overwrite each other:\n",
                       (int)len_i, name_i);
                printf("  %s\n  %s\n", plan->roots[i].capture_path, plan->roots[j].capture_path);
                printf("Rename one or back them up separately.\n");
                return 1;
            }
        }
    }
    return 0;
}

// Clones one planned root according to its presentation group: MAIN and
// EXPLICIT roots are flat-copied by basename (clone_item); DOTFILE and
// BROWSER roots preserve their home-relative structure (clone_nested), since
// several of them nest under a shared parent (e.g. ".config/google-chrome").
// Both pass root->capture_path -- the plan's own already-verified source
// address -- directly; neither re-derives or re-classifies it.
static void clone_plan_root(const CloneContext *ctx, const char *backup_dir,
                           const BackupPlanRoot *root, int *count, int *had_error)
{
    if (root->group == BACKUP_ROOT_DOTFILE || root->group == BACKUP_ROOT_BROWSER)
    {
        if (clone_nested(ctx, root->capture_path, backup_dir, root->manifest_root.restore_path) > 0)
            (*count)++;
        else
            *had_error = 1;
        return;
    }

    if (clone_item(ctx, root->capture_path, backup_dir) == 0)
        (*count)++;
    else
        *had_error = 1;
}

static void free_xdg_dirs_arr(char **dirs)
{
    for (int i = 0; i < XDG_KEY_COUNT; i++)
        free(dirs[i]);
}

int backup(const char *target, BackupMode mode, char **paths)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    // The plan is built before anything about the destination is even looked
    // at: it is read-only over the source side (never touches target, never
    // reads dry_run), so a rejected plan -- live or --dry-run alike -- never
    // creates or mutates anything (docs/DECISIONS.md D16 roadmap, A2.5).
    BackupPlan plan;
    if (backup_plan_build(home, mode, (const char *const *)paths, &plan) != 0)
        return 1;

    if (flat_layout_incompatible(&plan))
    {
        backup_plan_free(&plan);
        return 1;
    }

    // The legacy manifest.txt format always records all six XDG basenames,
    // including roots --critical does not capture. They therefore still need
    // a resolution separate from the selected plan roots, but use the shared
    // canonical key table and the same canonical HOME basis. Resolve them
    // before any destination mutation -- not after the dated directory,
    // packages, or copies already exist -- so a lexically long raw HOME cannot
    // make this legacy-only step fail after the planner already succeeded
    // (docs/DECISIONS.md D16 roadmap).
    char *xdg_dirs[XDG_KEY_COUNT] = { NULL };
    const char *basenames[XDG_KEY_COUNT] = { NULL };
    if (mode != BACKUP_EXPLICIT_PATHS)
    {
        char home_real[PATH_MAX];
        if (realpath(home, home_real) == NULL ||
            xdg_resolve(home_real, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_KEY_COUNT) != 0)
        {
            printf("Error: HOME path too long to resolve user directories\n");
            free_xdg_dirs_arr(xdg_dirs);
            backup_plan_free(&plan);
            return 1;
        }
        for (int i = 0; i < XDG_KEY_COUNT; i++)
        {
            const char *last_slash = strrchr(xdg_dirs[i], '/');
            basenames[i] = last_slash ? last_slash + 1 : xdg_dirs[i];
        }
    }

    // Build the dated backup path first: it is pure string work, so a path that
    // is too long fails before we create anything and needs no rollback.
    char backup_dir[PATH_MAX];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    int dir_len = snprintf(backup_dir, sizeof(backup_dir), "%s/migr_backup_%04d%02d%02d",
                           target, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
    if (dir_len < 0 || (size_t)dir_len >= sizeof(backup_dir))
    {
        printf("Error: Backup path too long: %s\n", target);
        free_xdg_dirs_arr(xdg_dirs);
        backup_plan_free(&plan);
        return 1;
    }

    int target_created = 0;
    if (ensure_target_root(target, &target_created) != 0)
    {
        free_xdg_dirs_arr(xdg_dirs);
        backup_plan_free(&plan);
        return 1;
    }

    // Probe the destination and choose a representation before creating anything more.
    // --dry-run skips it: the probe writes to the destination, which would break the
    // "no changes" contract, so dry-run keeps the native preview. Native proceeds as
    // before; portable is refused (not built yet); an unreliable probe is fatal, never a
    // silent fall-through. If we created the destination root this run and then refuse,
    // roll it back so a rejected attempt leaves nothing behind.
    CloneRepresentation repr = CLONE_NATIVE_TREE;
    if (!dry_run)
    {
        FsCapabilityProfile profile;
        if (fsprobe(target, &profile) != 0)
        {
            printf("Error: could not probe the destination filesystem at %s\n", target);
            if (target_created) rmdir(target);
            free_xdg_dirs_arr(xdg_dirs);
            backup_plan_free(&plan);
            return 1;
        }
        if (select_representation(&profile, &repr) != 0)
        {
            printf("Error: the destination filesystem at %s is not usable for backup\n", target);
            if (target_created) rmdir(target);
            free_xdg_dirs_arr(xdg_dirs);
            backup_plan_free(&plan);
            return 1;
        }
        if (repr != CLONE_NATIVE_TREE)
        {
            printf("Error: %s cannot natively hold Linux file metadata, and portable mode is "
                   "not implemented yet — refusing rather than losing it.\n", target);
            if (target_created) rmdir(target);
            free_xdg_dirs_arr(xdg_dirs);
            backup_plan_free(&plan);
            return 1;
        }
    }

    if (create_dir(backup_dir) != 0)
    {
        if (target_created) rmdir(target);
        free_xdg_dirs_arr(xdg_dirs);
        backup_plan_free(&plan);
        return 1;
    }

    if (dry_run)
        printf("Dry run mode enabled. No changes will be made.\n\n");

    printf("Backing up to: %s\n\n", backup_dir);

    int count = 0;
    int had_error = 0; // set when any file copy fails, so success is never faked

    // Representation chosen by the probe above (native here; portable already refused).
    CloneContext ctx = { .operation = CLONE_BACKUP, .representation = repr };

    if (mode == BACKUP_EXPLICIT_PATHS)
    {
        printf("[Explicit Paths]\n");
        for (int i = 0; i < plan.root_count; i++)
            clone_plan_root(&ctx, backup_dir, &plan.roots[i], &count, &had_error);
    }
    else
    {
        printf("[Main Directories]\n");
        for (int i = 0; i < plan.root_count; i++)
            if (plan.roots[i].group == BACKUP_ROOT_MAIN)
                clone_plan_root(&ctx, backup_dir, &plan.roots[i], &count, &had_error);

        printf("\n[Dotfiles]\n");
        for (int i = 0; i < plan.root_count; i++)
            if (plan.roots[i].group == BACKUP_ROOT_DOTFILE)
                clone_plan_root(&ctx, backup_dir, &plan.roots[i], &count, &had_error);

        printf("\n[Browser Profiles]\n");
        for (int i = 0; i < plan.root_count; i++)
            if (plan.roots[i].group == BACKUP_ROOT_BROWSER)
                clone_plan_root(&ctx, backup_dir, &plan.roots[i], &count, &had_error);

        printf("\n[Packages]\n");
        char pkg_path[PATH_MAX];
        if (path_join(pkg_path, sizeof(pkg_path), backup_dir, "packages.txt") != 0)
        {
            printf("  Warning: package list path too long, skipping\n");
            had_error = 1;
        }
        else if (dry_run)
            printf("  Would export package list to: %s\n", pkg_path);
        else
            packages(pkg_path);

        if (dry_run)
            printf("  Would write manifest: %s/manifest.txt\n", backup_dir);
        else
            legacy_manifest_write(backup_dir, basenames, XDG_KEY_COUNT);
    }

    free_xdg_dirs_arr(xdg_dirs);
    backup_plan_free(&plan);

    printf("\n===========================================================\n");
    if (dry_run)
        printf("Dry run complete: %d items would be copied\n", count);
    else if (had_error)
        printf("Backup finished with errors: %d items copied, some items failed\n", count);
    else
        printf("Backup complete: %d items copied\n", count);
    printf("Location: %s\n", backup_dir);
    printf("===========================================================\n");

    return had_error ? 1 : 0;
}
