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

static int copy_item(const char *src, const char *dest)
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

int backup(const char *target)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    // create target directory
    if (create_dir(target) != 0)
    {
        return 1;
    }

    // create backup directory with date
    char backup_dir[PATH_MAX];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(backup_dir, sizeof(backup_dir), "%s/migr_backup_%04d%02d%02d",
             target, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

    if (create_dir(backup_dir) != 0)
        return 1;

    if (dry_run)
    {
        printf("Dry run mode enabled. No changes will be made.\n\n");
    }

    printf("Backing up to: %s\n\n", backup_dir);

    // copy main directories
    const char *main_dirs[] = {"Documents", "Desktop", "Projects", NULL};

    // copy dotfiles
    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    char src[PATH_MAX];
    struct stat st;
    int count = 0;

    printf("[Main Directories]\n");
    for (int i = 0; main_dirs[i] != NULL; i++)
    {
        snprintf(src, sizeof(src), "%s/%s", home, main_dirs[i]);
        if (stat(src, &st) == 0)
        {
            copy_item(src, backup_dir);
            count++;
        }
    }

    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        snprintf(src, sizeof(src), "%s/%s", home, dotfiles[i]);
        if (stat(src, &st) == 0)
        {
            copy_item(src, backup_dir);
            count++;
        }
    }

    // package list
    printf("\n[Packages]\n");
    char pkg_path[PATH_MAX + sizeof("/packages.txt")]; // ensure enough space for path + filename
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", backup_dir);

    if (dry_run)
    {
        printf("  Would export package list to: %s\n", pkg_path);
    }
    else
    {
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
