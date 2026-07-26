#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include "report.h"
#include "detect.h"
#include "fileops.h"
#include "utils.h"

extern int verbose;

static int dir_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}


static void format_size(off_t bytes, char *buf, size_t len)
{
    if (bytes >= 1073741824)
    {
        snprintf(buf, len, "%.1fG", bytes / 1073741824.0);
    }
    else if (bytes >= 1048576)
    {
        snprintf(buf, len, "%.1fM", bytes / 1048576.0);
    }
    else if (bytes >= 1024)
    {
        snprintf(buf, len, "%.1fK", bytes / 1024.0);
    }
    else
    {
        snprintf(buf, len, "%lldB", (long long)bytes);
    }
}

static void print_section(const char *title)
{
    printf("\n[%s]\n", title);
    printf("-----------------------------------------------------------\n");
}

static void print_item(const char *name, const char *size)
{
    printf("  %-30s %10s\n", name, size);
}

int report(void)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    distro_t distro = detect_distro();
    printf("===========================================================\n");
    printf("              BACKUP ANALYSIS REPORT\n");
    printf("===========================================================\n");
    printf("Distro: %s\n", get_distro_name(distro));
    printf("Home:   %s\n", home);

    char path[PATH_MAX];
    char size[32];
    int had_error = 0; // set if any path could not be built, so the estimate never lies

    // main user directories
    const char *main_dirs[] = {"Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "Projects", NULL};

    print_section("MAIN DIRECTORIES");
    for (int i = 0; main_dirs[i] != NULL; i++)
    {
        if (path_join(path, sizeof(path), home, main_dirs[i]) != 0)
        {
            had_error = 1;
            continue;
        }
        if (dir_exists(path))
        {
            off_t bytes_size = 0;
            get_dir_size(path, &bytes_size);
            format_size(bytes_size, size, sizeof(size));
            print_item(main_dirs[i], size);
        }
    }

    // Dotfiles
    const char *dotfiles[] = {".ssh", ".gnupg", ".config", ".local/share", ".bashrc", ".profile", ".gitconfig", NULL};

    print_section("DOTFILES & CONFIG");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        if (path_join(path, sizeof(path), home, dotfiles[i]) != 0)
        {
            had_error = 1;
            continue;
        }
        if (file_exists(path))
        {
            off_t bytes_size = 0;
            get_dir_size(path, &bytes_size);
            format_size(bytes_size, size, sizeof(size));
            print_item(dotfiles[i], size);
        }
    }

    // developer tools
    const char *dev_dirs[] = {".npm", ".cargo", ".rustup", ".pub-cache", ".gradle", ".nvm", NULL};

    print_section("DEV TOOLS (re-downloadable)");
    for (int i = 0; dev_dirs[i] != NULL; i++)
    {
        if (path_join(path, sizeof(path), home, dev_dirs[i]) != 0)
        {
            had_error = 1;
            continue;
        }
        if (dir_exists(path))
        {
            off_t bytes_size = 0;
            get_dir_size(path, &bytes_size);
            format_size(bytes_size, size, sizeof(size));
            print_item(dev_dirs[i], size);
        }
    }

    // browsers
    const char *browsers[] = {".mozilla/firefox", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", NULL};
    const char *browser_names[] = {"Firefox", "Chrome", "Chromium", "Brave", NULL};

    print_section("BROWSERS");
    for (int i = 0; browsers[i] != NULL; i++)
    {
        if (path_join(path, sizeof(path), home, browsers[i]) != 0)
        {
            had_error = 1;
            continue;
        }
        if (dir_exists(path))
        {
            off_t bytes_size = 0;
            get_dir_size(path, &bytes_size);
            format_size(bytes_size, size, sizeof(size));
            print_item(browser_names[i], size);
        }
    }

    // most important paths for backup
    const char *critical_dirs[] = {"Documents", "Downloads", "Pictures", NULL};
    const char *critical_dots[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", NULL};
    
    off_t critical_total = 0;

    for (int i = 0; critical_dirs[i] != NULL; i++)
    {
        if (path_join(path, sizeof(path), home, critical_dirs[i]) != 0)
        {
            had_error = 1;
            continue;
        }
        if (file_exists(path))
        {
            off_t temp_size = 0;
            get_dir_size(path, &temp_size);
            critical_total += temp_size;
        }
    }

    for (int i = 0; critical_dots[i] != NULL; i++)
    {
        if (path_join(path, sizeof(path), home, critical_dots[i]) != 0)
        {
            had_error = 1;
            continue;
        }
        if (file_exists(path))
        {
            off_t temp_size = 0;
            get_dir_size(path, &temp_size);
            critical_total += temp_size;
        }
    }

    char critical_size[32];
    format_size(critical_total, critical_size, sizeof(critical_size));

    printf("\n===========================================================\n");
    printf("CRITICAL BACKUP ESTIMATE:\n");
    printf("  %s\n", critical_size);
    printf("  (Documents, Downloads, Pictures, .ssh, .gnupg, .gitconfig, .bashrc)\n");
    printf("===========================================================\n");

    if (had_error)
    {
        printf("\nWarning: some paths could not be built (HOME too long); "
               "this report is incomplete.\n");
        return 1;
    }
    return 0;
}