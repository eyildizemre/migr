#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "report.h"
#include "detect.h"
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

static void get_size(const char *path, char *size_buf, size_t buf_len)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "du -sh '%s' 2>/dev/null | cut -f1", path);

    FILE *pipe = popen(cmd, "r");
    if (pipe == NULL)
    {
        strncpy(size_buf, "???", buf_len);
        return;
    }

    if (fgets(size_buf, buf_len, pipe) == NULL)
    {
        strncpy(size_buf, "???", buf_len);
    }
    else
    {
        size_buf[strcspn(size_buf, "\n")] = '\0';
    }

    pclose(pipe);
}

static long get_size_bytes(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "du -sb '%s' 2>/dev/null | cut -f1", path);

    FILE *pipe = popen(cmd, "r");
    if (pipe == NULL)
    {
        return 0;
    }

    char buf[64];
    long size = 0;
    if (fgets(buf, sizeof(buf), pipe) != NULL)
    {
        size = atol(buf);
    }

    pclose(pipe);
    return size;
}

static void format_size(long bytes, char *buf, size_t len)
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
        snprintf(buf, len, "%ldB", bytes);
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

    char path[512];
    char size[32];

    // main user directories
    const char *main_dirs[] = {"Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "Projects", NULL};

    print_section("MAIN DIRECTORIES");
    for (int i = 0; main_dirs[i] != NULL; i++)
    {
        snprintf(path, sizeof(path), "%s/%s", home, main_dirs[i]);
        if (dir_exists(path))
        {
            get_size(path, size, sizeof(size));
            print_item(main_dirs[i], size);
        }
    }

    // Dotfiles
    const char *dotfiles[] = {".ssh", ".gnupg", ".config", ".local/share", ".bashrc", ".profile", ".gitconfig", NULL};

    print_section("DOTFILES & CONFIG");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        snprintf(path, sizeof(path), "%s/%s", home, dotfiles[i]);
        if (file_exists(path))
        {
            get_size(path, size, sizeof(size));
            print_item(dotfiles[i], size);
        }
    }

    // developer tools
    const char *dev_dirs[] = {".npm", ".cargo", ".rustup", ".pub-cache", ".gradle", ".nvm", NULL};

    print_section("DEV TOOLS (re-downloadable)");
    for (int i = 0; dev_dirs[i] != NULL; i++)
    {
        snprintf(path, sizeof(path), "%s/%s", home, dev_dirs[i]);
        if (dir_exists(path))
        {
            get_size(path, size, sizeof(size));
            print_item(dev_dirs[i], size);
        }
    }

    // browsers
    const char *browsers[] = {".mozilla/firefox", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", NULL};
    const char *browser_names[] = {"Firefox", "Chrome", "Chromium", "Brave", NULL};

    print_section("BROWSERS");
    for (int i = 0; browsers[i] != NULL; i++)
    {
        snprintf(path, sizeof(path), "%s/%s", home, browsers[i]);
        if (dir_exists(path))
        {
            get_size(path, size, sizeof(size));
            print_item(browser_names[i], size);
        }
    }

    // most important paths for backup
    const char *critical_dirs[] = {"Documents", "Desktop", "Projects", NULL};
    const char *critical_dots[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", NULL};
    
    long critical_total = 0;

    for (int i = 0; critical_dirs[i] != NULL; i++)
    {
        snprintf(path, sizeof(path), "%s/%s", home, critical_dirs[i]);
        if (file_exists(path))
        {
            critical_total += get_size_bytes(path);
        }
    }

    for (int i = 0; critical_dots[i] != NULL; i++)
    {
        snprintf(path, sizeof(path), "%s/%s", home, critical_dots[i]);
        if (file_exists(path))
        {
            critical_total += get_size_bytes(path);
        }
    }

    char critical_size[32];
    format_size(critical_total, critical_size, sizeof(critical_size));

    printf("\n===========================================================\n");
    printf("CRITICAL BACKUP ESTIMATE:\n");
    printf("  %s\n", critical_size);
    printf("  (Documents, Desktop, Projects, .ssh, .gnupg, .gitconfig, .bashrc)\n");
    printf("===========================================================\n");

    return 0;
}