#define _GNU_SOURCE
#include <assert.h>
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
#include "utils.h"

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
        ReportBreakdownEntry *new_entries = array_reserve(
            breakdown->entries, &breakdown->capacity, breakdown->count, 1U,
            sizeof(*new_entries), 16U,
            SIZE_MAX / sizeof(*new_entries));
        if (new_entries == NULL)
            return -1;
        breakdown->entries = new_entries;
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
    if (breakdown != NULL &&
        report_depth_includes(depth_limit, depth) &&
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
    assert(0 && "scoped_group_title: unhandled BackupRootGroup value");
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
        const char *restore_rel = NULL;

        /* backup_plan_build() canonicalizes HOME before building capture_path. */
        if (realpath(home, home_real) != NULL &&
            backup_plan_home_relative(home_real, root->capture_path,
                                      &restore_rel))
        {
            for (size_t i = 0;
                 i < sizeof(browser_names) / sizeof(browser_names[0]);
                 i++)
            {
                if (strcmp(restore_rel, browser_names[i].home_relative) == 0)
                    return browser_names[i].display_name;
            }
        }
    }

    const char *slash = strrchr(root->capture_path, '/');
    if (slash == NULL || slash[1] == '\0')
        return root->capture_path;
    return slash + 1;
}

/*
 * Measures one root. A root that has disappeared since plan construction --
 * or a directory child that disappears mid-walk -- is reported absent
 * (*present = 0), not a hard error; that benign-absence tolerance is shared
 * by every root category. breakdown may be NULL when the caller has no use
 * for per-directory subtotals (measure_report_tree() tolerates that, see
 * above).
 */
static int measure_scoped_root(const char *path, ReportDepth depth_limit,
                               ReportBreakdown *breakdown, off_t *bytes,
                               int *present)
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
    if (measure_report_tree(path, 0, depth_limit, breakdown, bytes) != 0)
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
        int want_breakdown = !summary && verbose;
        int measure_rc = measure_scoped_root(root->capture_path, depth,
                                             want_breakdown ? &breakdown : NULL,
                                             &bytes, &present);

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

int report(BackupMode mode, int summary, ReportDepth depth)
{
    const char *home = getenv("HOME");
    if (home == NULL)
    {
        print_error("Error: Could not get HOME directory.\n");
        return 1;
    }

    return report_scoped(home, mode, summary, depth);
}
