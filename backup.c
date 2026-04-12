#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "backup.h"
#include "packages.h"
#include "utils.h"

extern int verbose;

// create directory if it doesn't exist
static int create_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return 0;
    
    if (mkdir(path, 0755) != 0)
    {
        printf("Error: Could not create directory %s\n", path);
        return 1;
    }
    return 0;
}

// copy with cp -r
static int copy_item(const char *src, const char *dest)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cp -r '%s' '%s' 2>/dev/null", src, dest);
    
    if (verbose)
    {
        printf("  Copying: %s\n", src);
    }
    
    return system(cmd);
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
    char backup_dir[512];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(backup_dir, sizeof(backup_dir), "%s/migr_backup_%04d%02d%02d",
             target, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

    if (create_dir(backup_dir) != 0)
        return 1;

    printf("Backing up to: %s\n\n", backup_dir);

    // copy main directories
    const char *main_dirs[] = {"Documents", "Desktop", "Projects", NULL};
    
    // copy dotfiles
    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    char src[512];
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
    char pkg_path[512];
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", backup_dir);
    packages(pkg_path);

    printf("\n===========================================================\n");
    printf("Backup complete: %d items copied\n", count);
    printf("Location: %s\n", backup_dir);
    printf("===========================================================\n");

    return 0;
}