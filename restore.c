#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "restore.h"
#include "detect.h"
#include "utils.h"

extern int verbose;

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

static int copy_to_home(const char *src, const char *home)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cp -r '%s' '%s/'", src, home);
    
    if (verbose)
    {
        printf("  Restoring: %s\n", src);
    }
    
    return system(cmd);
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

    if (!confirm_action("This will restore files to your home directory. Continue?"))
    {
        printf("Cancelled.\n");
        return 0;
    }

    printf("Restoring from: %s\n\n", source);

    const char *main_dirs[] = {"Documents", "Desktop", "Projects", NULL};
    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    char src_path[512];
    int count = 0;

    printf("[Main Directories]\n");
    for (int i = 0; main_dirs[i] != NULL; i++)
    {
        snprintf(src_path, sizeof(src_path), "%s/%s", source, main_dirs[i]);
        if (file_exists(src_path))
        {
            copy_to_home(src_path, home);
            count++;
        }
    }

    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        snprintf(src_path, sizeof(src_path), "%s/%s", source, dotfiles[i]);
        if (file_exists(src_path))
        {
            copy_to_home(src_path, home);
            count++;
        }
    }

    char pkg_path[512];
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", source);
    
    if (file_exists(pkg_path))
    {
        printf("\n[Packages]\n");
        
        distro_t distro = detect_distro();
        char cmd[1024];
        
        switch (distro)
        {
            case DISTRO_DEBIAN:
                printf("Installing packages (this may take a while)...\n");
                snprintf(cmd, sizeof(cmd), 
                    "sudo dpkg --set-selections < '%s' && sudo apt-get dselect-upgrade -y", 
                    pkg_path);
                break;
            case DISTRO_FEDORA:
                printf("Installing packages (this may take a while)...\n");
                snprintf(cmd, sizeof(cmd), 
                    "sudo dnf install -y $(cat '%s')", 
                    pkg_path);
                break;
            case DISTRO_ARCH:
                printf("Installing packages (this may take a while)...\n");
                snprintf(cmd, sizeof(cmd), 
                    "sudo pacman -S --needed - < '%s'", 
                    pkg_path);
                break;
            default:
                printf("Warning: Unknown distro, skipping package install.\n");
                cmd[0] = '\0';
                break;
        }
        
        if (cmd[0] != '\0')
        {
            if (verbose)
            {
                printf("Running: %s\n", cmd);
            }
            system(cmd);
        }
    }
    else
    {
        printf("\nNote: packages.txt not found, skipping package restore.\n");
    }

    printf("\n===========================================================\n");
    printf("Restore complete: %d items restored\n", count);
    printf("===========================================================\n");

    return 0;
}