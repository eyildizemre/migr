#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include "backup_plan.h"
#include "report.h"
#include "detect.h"
#include "fileops.h"
#include "utils.h"

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


static void print_section(const char *title)
{
    printf("\n%s\n", title);
}

static void print_report_header(const char *home)
{
    distro_t distro = detect_distro();
    printf("Backup Analysis · %s\n", get_distro_name(distro));
    printf("%s\n", home);
}

static void print_item(const char *name, const char *size)
{
    printf("  %-30s %10s\n", name, size);
}

static const char *path_leaf(const char *path)
{
    const char *slash = strrchr(path, '/');
    if (slash == NULL || slash[1] == '\0')
        return path;
    return slash + 1;
}

static void print_item_with_path(const char *name, const char *size,
                                 const char *path, size_t depth)
{
    fputs("  ", stdout);
    for (size_t i = 0; i < depth; i++)
        fputs("  ", stdout);
    printf("%-30s %10s  (%s)\n", name, size, path);
}

typedef struct {
    char path[PATH_MAX];
    off_t size;
    size_t depth;
} ReportBreakdownEntry;

typedef struct {
    ReportBreakdownEntry *entries;
    size_t count;
    size_t capacity;
} ReportBreakdown;

static void report_breakdown_free(ReportBreakdown *breakdown)
{
    free(breakdown->entries);
    breakdown->entries = NULL;
    breakdown->count = 0;
    breakdown->capacity = 0;
}

static int report_breakdown_add(ReportBreakdown *breakdown,
                               const char *path, size_t depth,
                               size_t *entry_index)
{
    if (breakdown->count == breakdown->capacity)
    {
        size_t new_capacity = breakdown->capacity == 0
                                  ? 16
                                  : breakdown->capacity * 2;
        if (new_capacity < breakdown->capacity ||
            new_capacity > SIZE_MAX / sizeof(*breakdown->entries))
        {
            errno = ENOMEM;
            return -1;
        }

        ReportBreakdownEntry *new_entries = realloc(
            breakdown->entries, new_capacity * sizeof(*new_entries));
        if (new_entries == NULL)
        {
            errno = ENOMEM;
            return -1;
        }
        breakdown->entries = new_entries;
        breakdown->capacity = new_capacity;
    }

    ReportBreakdownEntry *entry = &breakdown->entries[breakdown->count];
    if (strlen(path) >= sizeof(entry->path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(entry->path, path);
    entry->size = 0;
    entry->depth = depth;
    *entry_index = breakdown->count;
    breakdown->count++;
    return 0;
}

static int report_depth_includes(ReportDepth depth, size_t level)
{
    if (level == 0)
        return 0;
    if (depth.kind == REPORT_DEPTH_LIMITED)
        return level <= depth.value;
    return level <= 1;
}

/*
 * Measures one root and records each requested directory subtotal during the
 * same bottom-up walk. Files and symlinks contribute to their containing
 * directory but never become breakdown entries, matching du's directory-only
 * listing semantics.
 */
static int measure_report_tree(const char *path, size_t depth,
                               ReportDepth depth_limit,
                               ReportBreakdown *breakdown, off_t *size)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return -1;

    if (S_ISLNK(st.st_mode) || S_ISREG(st.st_mode))
    {
        *size = st.st_size;
        return 0;
    }

    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode) ||
        S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
    {
        *size = 0;
        return 0;
    }

    if (!S_ISDIR(st.st_mode))
    {
        errno = EOPNOTSUPP;
        return -1;
    }

    size_t entry_index = SIZE_MAX;
    if (report_depth_includes(depth_limit, depth) &&
        report_breakdown_add(breakdown, path, depth, &entry_index) != 0)
        return -1;

    off_t subtotal = st.st_size;
    DIR *dir = opendir(path);
    if (dir == NULL)
        return -1;

    while (1)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                return -1;
            }
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_path[PATH_MAX];
        if (path_join(child_path, sizeof(child_path), path, entry->d_name) != 0)
        {
            closedir(dir);
            errno = ENAMETOOLONG;
            return -1;
        }

        size_t child_depth = depth == SIZE_MAX ? SIZE_MAX : depth + 1;
        off_t child_size = 0;
        if (measure_report_tree(child_path, child_depth, depth_limit,
                                breakdown, &child_size) != 0)
        {
            int saved_errno = errno;
            closedir(dir);
            errno = saved_errno;
            return -1;
        }
        subtotal += child_size;
    }

    if (closedir(dir) != 0)
        return -1;

    if (entry_index != SIZE_MAX)
        breakdown->entries[entry_index].size = subtotal;
    *size = subtotal;
    return 0;
}

static void print_report_breakdown(const ReportBreakdown *breakdown)
{
    for (size_t i = 0; i < breakdown->count; i++)
    {
        char size[32];
        format_size(breakdown->entries[i].size, size, sizeof(size));
        print_item_with_path(path_leaf(breakdown->entries[i].path), size,
                             breakdown->entries[i].path,
                             breakdown->entries[i].depth);
    }
}

static const char *scoped_group_title(BackupRootGroup group)
{
    switch (group)
    {
    case BACKUP_ROOT_MAIN:
        return "Main Directories";
    case BACKUP_ROOT_DOTFILE:
        return "Dotfiles & Config";
    case BACKUP_ROOT_BROWSER:
        return "Browsers";
    case BACKUP_ROOT_EXPLICIT:
        return "Explicit Paths";
    }
    return "Other";
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

static int measure_scoped_root_verbose(const char *path, ReportDepth depth,
                                       off_t *bytes, int *present,
                                       ReportBreakdown *breakdown)
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
    if (measure_report_tree(path, 0, depth, breakdown, bytes) != 0)
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

static int measure_and_print_item(const char *name, const char *path,
                                  ReportDepth depth, off_t *bytes)
{
    ReportBreakdown breakdown = { NULL, 0, 0 };
    int rc;

    if (verbose)
        rc = measure_report_tree(path, 0, depth, &breakdown, bytes);
    else
        rc = get_dir_size(path, bytes);
    if (rc != 0)
    {
        report_breakdown_free(&breakdown);
        return -1;
    }

    char size[32];
    format_size(*bytes, size, sizeof(size));
    if (verbose)
    {
        print_item_with_path(name, size, path, 0);
        print_report_breakdown(&breakdown);
    }
    else
    {
        print_item(name, size);
    }
    report_breakdown_free(&breakdown);
    return 0;
}

enum { LEGACY_CRITICAL_COUNT = 7 };

static int legacy_critical_slot(const char *name)
{
    static const char *critical_names[LEGACY_CRITICAL_COUNT] = {
        "Documents", "Downloads", "Pictures", ".ssh", ".gnupg",
        ".gitconfig", ".bashrc"
    };

    for (int i = 0; i < LEGACY_CRITICAL_COUNT; i++)
    {
        if (strcmp(name, critical_names[i]) == 0)
            return i;
    }
    return -1;
}

static void legacy_cache_store(const char *name, off_t size,
                               off_t *cached_sizes,
                               unsigned char *cached_valid)
{
    int slot = legacy_critical_slot(name);
    if (slot >= 0)
    {
        cached_sizes[slot] = size;
        cached_valid[slot] = 1;
    }
}

static int report_scoped(const char *home, BackupMode mode, int summary,
                         ReportDepth depth)
{
    BackupPlan plan;
    if (backup_plan_build(home, mode, NULL, &plan) != 0)
        return 1;

    off_t total = 0;
    int had_error = 0;
    int printed_group[4] = { 0, 0, 0, 0 };

    if (!summary)
        print_report_header(home);

    for (int i = 0; i < plan.root_count; i++)
    {
        const BackupPlanRoot *root = &plan.roots[i];
        off_t bytes = 0;
        int present = 0;
        ReportBreakdown breakdown = { NULL, 0, 0 };
        int measure_rc;

        if (!summary && verbose)
            measure_rc = measure_scoped_root_verbose(
                root->capture_path, depth, &bytes, &present, &breakdown);
        else
            measure_rc = measure_scoped_root(root->capture_path, &bytes,
                                             &present);

        if (measure_rc != 0)
        {
            had_error = 1;
            report_breakdown_free(&breakdown);
            continue;
        }
        if (!present)
        {
            report_breakdown_free(&breakdown);
            continue;
        }

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
            if (verbose)
            {
                print_item_with_path(scoped_root_name(home, root), size,
                                     root->capture_path, 0);
                print_report_breakdown(&breakdown);
            }
            else
            {
                print_item(scoped_root_name(home, root), size);
            }
        }
        report_breakdown_free(&breakdown);
    }

    char total_size[32];
    format_size(total, total_size, sizeof(total_size));
    if (summary)
    {
        printf("%s\n", total_size);
        if (had_error)
        {
            /* Keep summary stdout to one value; this stderr warning is intentionally plain. */
            fprintf(stderr, "Warning: some paths could not be measured; "
                            "this report is incomplete.\n");
        }
    }
    else
    {
        const char *label = mode == BACKUP_COMPREHENSIVE
                                ? "Comprehensive estimate"
                                : "Critical estimate";
        printf("\n");
        print_item(label, total_size);
        if (had_error)
        {
            printf("\nWarning: some paths could not be measured; "
                   "this report is incomplete.\n");
        }
    }

    backup_plan_free(&plan);
    return had_error ? 1 : 0;
}

int report(BackupMode mode, int scope_requested, int summary,
           ReportDepth depth)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        print_error("Error: Could not get HOME directory.\n");
        return 1;
    }

    if (scope_requested)
        return report_scoped(home, mode, summary, depth);

    print_report_header(home);

    char path[PATH_MAX];
    int had_error = 0; // set if any path could not be built, so the estimate never lies
    const char *critical_dirs[] = {"Documents", "Downloads", "Pictures", NULL};
    const char *critical_dots[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", NULL};
    off_t cached_critical_sizes[LEGACY_CRITICAL_COUNT] = { 0 };
    unsigned char cached_critical_valid[LEGACY_CRITICAL_COUNT] = { 0 };

    // main user directories
    const char *main_dirs[] = {"Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "Projects", NULL};

    print_section("Main Directories");
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
            if (measure_and_print_item(main_dirs[i], path, depth,
                                       &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
            legacy_cache_store(main_dirs[i], bytes_size,
                               cached_critical_sizes, cached_critical_valid);
        }
    }

    // Dotfiles
    const char *dotfiles[] = {".ssh", ".gnupg", ".config", ".local/share", ".bashrc", ".profile", ".gitconfig", NULL};

    print_section("Dotfiles & Config");
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
            if (measure_and_print_item(dotfiles[i], path, depth,
                                       &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
            legacy_cache_store(dotfiles[i], bytes_size,
                               cached_critical_sizes, cached_critical_valid);
        }
    }

    // developer tools
    const char *dev_dirs[] = {".npm", ".cargo", ".rustup", ".pub-cache", ".gradle", ".nvm", NULL};

    print_section("Dev Tools (re-downloadable)");
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
            if (measure_and_print_item(dev_dirs[i], path, depth,
                                       &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
        }
    }

    // browsers
    const char *browsers[] = {".mozilla/firefox", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", NULL};
    const char *browser_names[] = {"Firefox", "Chrome", "Chromium", "Brave", NULL};

    print_section("Browsers");
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
            if (measure_and_print_item(browser_names[i], path, depth,
                                       &bytes_size) != 0)
            {
                had_error = 1;
                continue;
            }
        }
    }

    // most important paths for backup
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
            int slot = legacy_critical_slot(critical_dirs[i]);
            if (verbose && slot >= 0 && cached_critical_valid[slot])
            {
                critical_total += cached_critical_sizes[slot];
            }
            else
            {
                off_t temp_size = 0;
                if (get_dir_size(path, &temp_size) == 0)
                    critical_total += temp_size;
                else
                    had_error = 1;
            }
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
            int slot = legacy_critical_slot(critical_dots[i]);
            if (verbose && slot >= 0 && cached_critical_valid[slot])
            {
                critical_total += cached_critical_sizes[slot];
            }
            else
            {
                off_t temp_size = 0;
                if (get_dir_size(path, &temp_size) == 0)
                    critical_total += temp_size;
                else
                    had_error = 1;
            }
        }
    }

    char critical_size[32];
    format_size(critical_total, critical_size, sizeof(critical_size));

    printf("\n");
    print_item("Critical estimate", critical_size);
    printf("  (Documents, Downloads, Pictures, .ssh, .gnupg, .gitconfig, .bashrc)\n");

    if (had_error)
    {
        printf("\nWarning: some paths could not be measured; "
               "this report is incomplete.\n");
        return 1;
    }
    return 0;
}
