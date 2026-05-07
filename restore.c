#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#include "restore.h"
#include "detect.h"
#include "fileops.h"
#include "utils.h"

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

static int clone_to_home(const char *src, const char *home)
{
    if (dry_run)
    {
        printf("  Would restore: %s -> %s/\n", src, home);
        return 0;
    }

    if (verbose)
    {
        printf("  Restoring: %s\n", src);
    }

    const char *name = strrchr(src, '/');
    name = name ? name + 1 : src;

    char full_dest[PATH_MAX];
    snprintf(full_dest, sizeof(full_dest), "%s/%s", home, name);

    if (clone_recursive(src, full_dest) != 0)
    {
        printf("Error: Failed to restore %s\n", src);
        return 1;
    }
    return 0;
}

int restore(const char *source)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    // check source directory exists
    struct stat st;
    if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        printf("Error: Source directory not found: %s\n", source);
        return 1;
    }

    if (dry_run)
    {
        printf("Dry run mode enabled. No changes will be made.\n\n");
    }
    else if (!confirm_action("This will restore files to your home directory. Continue?"))
    {
        printf("Cancelled.\n");
        return 0;
    }

    printf("Restoring from: %s\n\n", source);

    const char *main_dirs[] = {"Documents", "Desktop", "Projects", NULL};
    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    char src_path[PATH_MAX];
    int count = 0;

    printf("[Main Directories]\n");
    for (int i = 0; main_dirs[i] != NULL; i++)
    {
        snprintf(src_path, sizeof(src_path), "%s/%s", source, main_dirs[i]);
        if (file_exists(src_path))
        {
            clone_to_home(src_path, home);
            count++;
        }
    }

    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        snprintf(src_path, sizeof(src_path), "%s/%s", source, dotfiles[i]);
        if (file_exists(src_path))
        {
            clone_to_home(src_path, home);
            count++;
        }
    }

    char pkg_path[PATH_MAX];
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", source);

    if (file_exists(pkg_path))
    {
        printf("\n[Packages]\n");

        distro_t distro = detect_distro();

        char *const debian_cmd[] = {"xargs", "-a", pkg_path, "sudo", "apt-get", "install", "-y", NULL};
        char *const fedora_cmd[] = {"xargs", "-a", pkg_path, "sudo", "dnf", "install", "-y", NULL};
        char *const arch_cmd[]   = {"xargs", "-a", pkg_path, "sudo", "pacman", "-S", "--needed", "--noconfirm", NULL};
        char *const *cmd_args = NULL;

        switch (distro)
        {
            case DISTRO_DEBIAN: cmd_args = debian_cmd; break;
            case DISTRO_FEDORA: cmd_args = fedora_cmd; break;
            case DISTRO_ARCH:   cmd_args = arch_cmd;   break;
            default:
                printf("Warning: Unknown distro, skipping package install.\n");
                break;
        }

        if (cmd_args != NULL)
        {
            if (dry_run)
            {
                printf("  Would install packages from: %s\n", pkg_path);
            }
            else
            {
                printf("Installing packages (this may take a while)...\n");
                if (verbose)
                {
                    printf("Running: xargs -a %s ...\n", pkg_path);
                }
                run_command(cmd_args);
            }
        }
    }
    else
    {
        printf("\nNote: packages.txt not found, skipping package restore.\n");
    }

    printf("\n===========================================================\n");
    if (dry_run)
        printf("Dry run complete: %d items would be restored\n", count);
    else
        printf("Restore complete: %d items restored\n", count);
    printf("===========================================================\n");

    return 0;
}
