#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>

#include "backup.h"
#include "fileops.h"
#include "manifest.h"
#include "packages.h"
#include "utils.h"
#include "xdg.h"

// create directory if it doesn't exist
static int create_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return 0;

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

static int clone_item(const char *src, const char *dest)
{
    if (dry_run)
    {
        printf("  Would copy: %s -> %s\n", src, dest);
        return 0;
    }

    if (verbose)
    {
        printf("  Copying: %s\n", src);
    }

    const char *name = strrchr(src, '/');
    name = name ? name + 1 : src;

    char full_dest[PATH_MAX];
    snprintf(full_dest, sizeof(full_dest), "%s/%s", dest, name);

    if (clone_recursive(src, full_dest) != 0)
    {
        printf("Error: Failed to copy %s\n", src);
        return 1;
    }
    return 0;
}

// Clone a home-relative path (e.g. ".config/google-chrome") into backup_dir,
// preserving the directory structure. Returns 1 if copied, 0 if not found, -1 on error.
static int clone_nested(const char *home, const char *backup_dir, const char *rel_path)
{
    char src[PATH_MAX], dest[PATH_MAX];
    snprintf(src, sizeof(src), "%s/%s", home, rel_path);

    struct stat st;
    if (stat(src, &st) != 0)
        return 0;

    snprintf(dest, sizeof(dest), "%s/%s", backup_dir, rel_path);

    // Split the path to create parent directories first.
    // The OS kernel will throw ENOENT if we try to copy into a non-existent parent directory.
    const char *slash = strrchr(rel_path, '/');
    if (slash)
    {
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s/%.*s", backup_dir, (int)(slash - rel_path), rel_path);
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

    if (clone_recursive(src, dest) != 0)
    {
        printf("Error: Failed to copy %s\n", src);
        return -1;
    }
    return 1;
}

int backup(const char *target, BackupMode mode, char **paths)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    if (mode == BACKUP_EXPLICIT_PATHS && (paths == NULL || paths[0] == NULL))
    {
        printf("Error: explicit-paths mode requires at least one path argument.\n");
        return 1;
    }

    if (create_dir(target) != 0)
        return 1;

    char backup_dir[PATH_MAX];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(backup_dir, sizeof(backup_dir), "%s/migr_backup_%04d%02d%02d",
             target, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

    if (create_dir(backup_dir) != 0)
        return 1;

    if (dry_run)
        printf("Dry run mode enabled. No changes will be made.\n\n");

    printf("Backing up to: %s\n\n", backup_dir);

    struct stat st;
    int count = 0;

    if (mode == BACKUP_EXPLICIT_PATHS)
    {
        printf("[Explicit Paths]\n");
        for (int i = 0; paths[i] != NULL; i++)
        {
            if (stat(paths[i], &st) == 0)
            {
                clone_item(paths[i], backup_dir);
                count++;
            }
            else
            {
                printf("  Warning: Path not found, skipping: %s\n", paths[i]);
            }
        }
    }
    else
    {
        // Resolve localized XDG directory paths from ~/.config/user-dirs.dirs;
        // silently falls back to English names if the file is absent or a key is missing.
        // Note: the XDG key for downloads is XDG_DOWNLOAD_DIR (singular).
        static const char * const xdg_keys[]      = {
            "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR", "XDG_PICTURES_DIR",
            "XDG_DESKTOP_DIR",   "XDG_VIDEOS_DIR",   "XDG_MUSIC_DIR"
        };
        static const char * const xdg_fallbacks[] = {
            "Documents", "Downloads", "Pictures",
            "Desktop",   "Videos",   "Music"
        };
        enum { XDG_DIR_COUNT = 6 };
        char *xdg_dirs[XDG_DIR_COUNT];
        xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_DIR_COUNT);

        // Capture basenames for cross-locale restoration (e.g. "/home/user/Belgeler" -> "Belgeler").
        // Instead of allocating new memory, use pointer arithmetic to point directly 
        // to the character following the last '/' in the existing path string.
        const char *basenames[XDG_DIR_COUNT];
        for (int i = 0; i < XDG_DIR_COUNT; i++)
        {
            const char *last_slash = strrchr(xdg_dirs[i], '/');
            basenames[i] = last_slash ? last_slash + 1 : xdg_dirs[i];
        }

        // Projects is not a standard XDG directory
        char projects_path[PATH_MAX];
        snprintf(projects_path, sizeof(projects_path), "%s/Projects", home);

        // indices: 0=Documents 1=Downloads 2=Pictures 3=Desktop 4=Videos 5=Music
        // NULL terminators are used to mark the end of the arrays for iteration
        const char *critical_dirs[]      = {xdg_dirs[0], xdg_dirs[1], xdg_dirs[2], NULL};
        const char *comprehensive_dirs[] = {xdg_dirs[0], xdg_dirs[1], xdg_dirs[2],
                                            xdg_dirs[3], xdg_dirs[4], xdg_dirs[5], projects_path, NULL};
        const char *dotfiles[]           = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

        // main_dirs acts as a pointer to the first char* element of the selected array
        const char **main_dirs = (mode == BACKUP_COMPREHENSIVE) ? comprehensive_dirs : critical_dirs;

        char src[PATH_MAX];

        printf("[Main Directories]\n");
        for (int i = 0; main_dirs[i] != NULL; i++) // NULL terminator indicates end of array
        {
            // main_dirs[i] is a full absolute path from xdg_resolve (or projects_path)
            if (stat(main_dirs[i], &st) == 0)
            {
                clone_item(main_dirs[i], backup_dir);
                count++;
            }
        }

        printf("\n[Dotfiles]\n");
        for (int i = 0; dotfiles[i] != NULL; i++)
        {
            snprintf(src, sizeof(src), "%s/%s", home, dotfiles[i]);
            if (stat(src, &st) == 0)
            {
                clone_item(src, backup_dir);
                count++;
            }
        }

        const char *browser_configs[] = {
            ".mozilla",
            ".config/google-chrome",
            ".config/chromium",
            ".config/BraveSoftware",
            ".config/vivaldi",
            ".config/microsoft-edge",
            ".config/opera",
            NULL
        };

        printf("\n[Browser Profiles]\n");
        for (int i = 0; browser_configs[i] != NULL; i++)
        {
            int r = clone_nested(home, backup_dir, browser_configs[i]);
            if (r > 0) count++;
        }

        printf("\n[Packages]\n");
        char pkg_path[PATH_MAX + sizeof("/packages.txt")]; // ensure enough space for path + filename
        snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", backup_dir);

        if (dry_run)
            printf("  Would export package list to: %s\n", pkg_path);
        else
            packages(pkg_path);

        if (dry_run)
            printf("  Would write manifest: %s/manifest.txt\n", backup_dir);
        else
            manifest_write(backup_dir, basenames, XDG_DIR_COUNT);

        for (int i = 0; i < XDG_DIR_COUNT; i++)
            free(xdg_dirs[i]);
    }

    printf("\n===========================================================\n");
    if (dry_run)
        printf("Dry run complete: %d items would be copied\n", count);
    else
        printf("Backup complete: %d items copied\n", count);
    printf("Location: %s\n", backup_dir);
    printf("===========================================================\n");

    return 0;
}
