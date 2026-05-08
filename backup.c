#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>

#include "backup.h"
#include "fileops.h"
#include "packages.h"
#include "utils.h"

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

    if (mode == BACKUP_PATHS && (paths == NULL || paths[0] == NULL))
    {
        printf("Error: -paths requires at least one path argument.\n");
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

    if (mode == BACKUP_PATHS)
    {
        printf("[Custom Paths]\n");
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
        const char *critical_dirs[]      = {"Documents", "Downloads", "Pictures", NULL};
        const char *comprehensive_dirs[] = {"Documents", "Desktop", "Downloads", "Pictures",
                                            "Videos", "Music", "Projects", NULL};
        const char *dotfiles[]           = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

        const char **main_dirs = (mode == BACKUP_COMPREHENSIVE) ? comprehensive_dirs : critical_dirs; // use comprehensive list for comprehensive mode, otherwise critical list

        char src[PATH_MAX];

        printf("[Main Directories]\n");
        for (int i = 0; main_dirs[i] != NULL; i++)
        {
            snprintf(src, sizeof(src), "%s/%s", home, main_dirs[i]);
            if (stat(src, &st) == 0)
            {
                clone_item(src, backup_dir);
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
