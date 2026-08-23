#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include "backup_plan.h"
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

static const char *scoped_group_title(BackupRootGroup group)
{
    switch (group)
    {
    case BACKUP_ROOT_MAIN:
        return "MAIN DIRECTORIES";
    case BACKUP_ROOT_DOTFILE:
        return "DOTFILES & CONFIG";
    case BACKUP_ROOT_BROWSER:
        return "BROWSERS";
    case BACKUP_ROOT_EXPLICIT:
        return "EXPLICIT PATHS";
    }
    return "OTHER";
}

static const char *scoped_root_name(const char *home,
                                    const BackupPlanRoot *root)
{
    if (root->group == BACKUP_ROOT_BROWSER && home != NULL)
    {
        static const struct {
            const char *home_relative;
            const char *display_name;
        } browser_names[] = {
            { ".mozilla",              "Firefox" },
            { ".config/google-chrome", "Chrome" },
            { ".config/chromium",      "Chromium" },
            { ".config/BraveSoftware", "Brave" },
            { ".config/vivaldi",       "Vivaldi" },
            { ".config/microsoft-edge", "Edge" },
            { ".config/opera",         "Opera" },
        };
        char home_real[PATH_MAX];

        /* backup_plan_build() canonicalizes HOME before building capture_path. */
        if (realpath(home, home_real) != NULL)
        {
            const char *relative = NULL;
            size_t home_len = strlen(home_real);

            if (strcmp(home_real, "/") == 0)
                relative = root->capture_path + 1;
            else if (strcmp(root->capture_path, home_real) == 0)
                relative = root->capture_path + home_len;
            else if (strncmp(root->capture_path, home_real, home_len) == 0 &&
                     root->capture_path[home_len] == '/')
                relative = root->capture_path + home_len + 1;

            if (relative != NULL)
            {
                for (size_t i = 0;
                     i < sizeof(browser_names) / sizeof(browser_names[0]);
                     i++)
                {
                    if (strcmp(relative, browser_names[i].home_relative) == 0)
                        return browser_names[i].display_name;
                }
            }
        }
    }

    const char *slash = strrchr(root->capture_path, '/');
    if (slash == NULL || slash[1] == '\0')
        return root->capture_path;
    return slash + 1;
}

/*
 * A built-in root can disappear between plan construction and measurement.
 * That is the same benign absence the legacy loops tolerate; other failures
 * make the estimate incomplete. A directory child can disappear during the
 * recursive walk as well, so get_dir_size() is given the same treatment when
 * it reports ENOENT/ENOTDIR.
 */
static int measure_scoped_root(const char *path, off_t *bytes, int *present)
{
    struct stat st;
    *bytes = 0;
    *present = 0;

    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT || errno == ENOTDIR)
            return 0;
        return -1;
    }

    errno = 0;
    if (get_dir_size(path, bytes) != 0)
    {
        if (errno == ENOENT || errno == ENOTDIR)
        {
            *bytes = 0;
            return 0;
        }
        return -1;
    }

    *present = 1;
    return 0;
}

static int report_scoped(const char *home, BackupMode mode, int summary)
{
    BackupPlan plan;
    if (backup_plan_build(home, mode, NULL, &plan) != 0)
        return 1;

    off_t total = 0;
    int had_error = 0;
    int printed_group[4] = { 0, 0, 0, 0 };

    if (!summary)
    {
        distro_t distro = detect_distro();
        printf("===========================================================\n");
        printf("              BACKUP ANALYSIS REPORT\n");
        printf("===========================================================\n");
        printf("Distro: %s\n", get_distro_name(distro));
        printf("Home:   %s\n", home);
    }

    for (int i = 0; i < plan.root_count; i++)
    {
        const BackupPlanRoot *root = &plan.roots[i];
        off_t bytes = 0;
        int present = 0;
        if (measure_scoped_root(root->capture_path, &bytes, &present) != 0)
        {
            had_error = 1;
            continue;
        }
        if (!present)
            continue;

        total += bytes;
        if (!summary)
        {
            if (root->group >= 0 && root->group < 4 &&
                !printed_group[root->group])
            {
                print_section(scoped_group_title(root->group));
                printed_group[root->group] = 1;
            }

            char size[32];
            format_size(bytes, size, sizeof(size));
            print_item(scoped_root_name(home, root), size);
        }
    }

    char total_size[32];
    format_size(total, total_size, sizeof(total_size));
    if (summary)
    {
        printf("%s\n", total_size);
        if (had_error)
            fprintf(stderr, "Warning: some paths could not be measured; "
                            "this report is incomplete.\n");
    }
    else
    {
        const char *label = mode == BACKUP_COMPREHENSIVE
                                ? "COMPREHENSIVE"
                                : "CRITICAL";
        printf("\n===========================================================\n");
        printf("%s BACKUP ESTIMATE:\n", label);
        printf("  %s\n", total_size);
        printf("===========================================================\n");
        if (had_error)
        {
            printf("\nWarning: some paths could not be measured; "
                   "this report is incomplete.\n");
        }
    }

    backup_plan_free(&plan);
    return had_error ? 1 : 0;
}

int report(BackupMode mode, int scope_requested, int summary)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    if (scope_requested)
        return report_scoped(home, mode, summary);

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
            if (get_dir_size(path, &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
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
            if (get_dir_size(path, &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
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
            if (get_dir_size(path, &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
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
            if (get_dir_size(path, &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
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
            if (get_dir_size(path, &temp_size) == 0)
                critical_total += temp_size;
            else
                had_error = 1;
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
            if (get_dir_size(path, &temp_size) == 0)
                critical_total += temp_size;
            else
                had_error = 1;
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
        printf("\nWarning: some paths could not be measured; "
               "this report is incomplete.\n");
        return 1;
    }
    return 0;
}
