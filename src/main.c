#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "backup.h"
#include "config.h"
#include "report.h"
#include "restore.h"
#include "selection.h"
#include "utils.h"

typedef enum {
    ACTION_NONE,
    ACTION_REPORT,
    ACTION_BACKUP,
    ACTION_RESTORE,
    ACTION_CONF,
    ACTION_HELP
} Action;

static void action_lookup(const char *arg, Action *action)
{
    if (strcmp(arg, "report") == 0)
        *action = ACTION_REPORT;
    else if (strcmp(arg, "backup") == 0)
        *action = ACTION_BACKUP;
    else if (strcmp(arg, "restore") == 0)
        *action = ACTION_RESTORE;
    else if (strcmp(arg, "conf") == 0)
        *action = ACTION_CONF;
    else if (strcmp(arg, "help") == 0)
        *action = ACTION_HELP;
    else
        *action = ACTION_NONE;
}

static int load_selection(BackupMode mode, SelectionPlan *selection,
                          int show_diagnostic)
{
    const char *home = getenv("HOME");
    if (home == NULL)
    {
        print_error("Error: Could not get HOME directory.\n");
        return -1;
    }
    const char *config_home = getenv("XDG_CONFIG_HOME");
    if ((config_home == NULL || config_home[0] != '/') &&
        strnlen(home, PATH_MAX) >= PATH_MAX)
    {
        print_error("Error: HOME path too long to resolve user directories\n");
        return -1;
    }

    char *path = NULL;
    Config config = {0};
    int result = -1;
    if (config_path(&path) != 0 || config_load(path, &config) != 0)
        goto done;

    if (show_diagnostic)
        printf("Scope config: %s (%zu active rule%s)\n\n", path,
               config.count, config.count == 1 ? "" : "s");
    if (selection_plan_build(home, mode, &config, selection) != 0)
        goto done;
    result = 0;

done:
    config_free(&config);
    free(path);
    return result;
}

static int run_scoped_report(BackupMode mode, int summary, ReportDepth depth)
{
    SelectionPlan selection = {0};
    if (load_selection(mode, &selection, verbose && !summary) != 0)
        return 1;
    int result = report_selection(&selection, summary, depth);
    selection_plan_free(&selection);
    return result;
}

static int parse_report_depth(const char *argument, ReportDepth *depth)
{
    if (argument[0] == '\0')
        return -1;
    for (const unsigned char *p = (const unsigned char *)argument;
         *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
            return -1;
    }

    errno = 0;
    uintmax_t value = strtoumax(argument, NULL, 10);
    if (errno == ERANGE || value > SIZE_MAX)
        return -1;

    depth->kind = REPORT_DEPTH_LIMITED;
    depth->value = (size_t)value;
    return 0;
}

int main(int argc, char *argv[])
{
    raise_fd_limit();
    color_enabled = isatty(fileno(stderr));

    ReportDepth depth = { REPORT_DEPTH_DEFAULT, 0 };

    if (argc < 2) // No arguments provided; default to report action
        return run_scoped_report(BACKUP_CRITICAL, 0, depth);

    static struct option long_options[] = {
        {"dry-run",        no_argument,       NULL, 'n'},
        {"verbose",        no_argument,       NULL, 'v'},
        {"help",           no_argument,       NULL, 'h'},
        {"critical",       no_argument,       NULL, 'c'},
        {"comprehensive",  no_argument,       NULL, 'C'},
        {"summary",        no_argument,       NULL, 's'},
        {"max-depth",      required_argument, NULL, 'd'},
        {"include-self",   no_argument,       NULL, 'I'},
        {"include-network-config", no_argument, NULL, 'N'},
        {NULL,             0,                 NULL,  0 }
    };

    Action action;

    if (argv[1][0] == '-')
    {
        action = ACTION_NONE;
        optind = 1; // Start parsing from the first argument
    }
    else 
    {
        action_lookup(argv[1], &action);
        if (action == ACTION_NONE)
        {
            print_error("Unknown command: %s\n", argv[1]);
            return 1;
        }
        optind = 2; // Start parsing after the first argument (the action)
    }

    char *path = NULL;
    BackupMode mode = BACKUP_CRITICAL;
    static char *no_paths[] = { NULL }; // Used when no user-supplied paths are given
    char **user_paths = no_paths;
    int opt;
    int mode_flag_given = 0;
    int summary_flag = 0;
    int max_depth_given = 0;
    int include_self = 0;
    int include_network_config = 0;
    int non_help_option_given = 0;

    // Parse options only. optind was set above to skip the command word, or left
    // at 1 when no command was given (e.g. `migr --help`). getopt_long permutes
    // argv as it scans, so once the loop ends every non-option argument sits
    // contiguously starting at argv[optind] — that is where positionals are read.
    while ((opt = getopt_long(argc, argv, "nvhs", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'v':
            non_help_option_given = 1;
            verbose = 1;
            break;
        case 'n':
            non_help_option_given = 1;
            dry_run = 1;
            break;
        case 'h':
            action = ACTION_HELP;
            break;
        case 'c':
        case 'C':
            non_help_option_given = 1;
            // Both flags write the same variable, so a second one would silently
            // overwrite the first. Reject instead of letting the last one win.
            if (mode_flag_given)
            {
                print_error("Error: --critical and --comprehensive are mutually exclusive.\n");
                return 1;
            }
            mode = (opt == 'C') ? BACKUP_COMPREHENSIVE : BACKUP_CRITICAL;
            mode_flag_given = 1;
            break;
        case 's':
            non_help_option_given = 1;
            summary_flag = 1;
            break;
        case 'd':
            non_help_option_given = 1;
            if (parse_report_depth(optarg, &depth) != 0)
            {
                print_error("Error: --max-depth must be a non-negative integer.\n");
                return 1;
            }
            max_depth_given = 1;
            verbose = 1;
            break;
        case 'I':
            non_help_option_given = 1;
            include_self = 1;
            break;
        case 'N':
            non_help_option_given = 1;
            include_network_config = 1;
            break;
        case '?':
        default:
            print_error("For help: ./migr --help\n");
            return 1;
        }
    }

    // -h/--help (or the "help" command word) always shows help, regardless of
    // what other flags were given alongside it -- checked before the
    // cross-cutting scope checks below, which would otherwise read the
    // now-overwritten action and reject an unrelated flag/action combination
    // instead of ever reaching the ACTION_HELP dispatch.
    if (action == ACTION_HELP)
    {
        print_help();
        return 0;
    }

    if (optind < argc)
    {
        // First positional is the destination (or source, for restore). Any further
        // positionals are user-supplied paths; they point into argv rather than
        // heap memory, and are NULL-terminated for free because argv[argc] is NULL.
        path = argv[optind];
        user_paths = &argv[optind + 1];

        // If user-supplied paths are present, the mode must be BACKUP_EXPLICIT_PATHS. 
        // If a mode flag was also given, that's an error.
        if (user_paths[0] != NULL)
        {
            if (mode_flag_given)
            {
                print_error("Error: cannot combine --critical/--comprehensive with explicit paths.\n");
                return 1;
            }
            mode = BACKUP_EXPLICIT_PATHS;
        }
    }

    if (action == ACTION_CONF && path != NULL)
    {
        print_error("Error: 'conf' takes no arguments.\n");
        return 1;
    }
    if (action == ACTION_CONF && non_help_option_given)
    {
        print_error("Error: 'conf' does not accept backup/report options.\n");
        return 1;
    }

    // Cross-cutting checks: reject inputs the chosen command has no use for.
    // Required-argument checks stay with their command in the dispatch below.
    if (mode_flag_given && action != ACTION_BACKUP &&
        action != ACTION_REPORT && action != ACTION_NONE)
    {
        print_error("Error: --critical/--comprehensive apply only to 'backup' or 'report'.\n");
        return 1;
    }
    if (summary_flag && action != ACTION_REPORT && action != ACTION_NONE)
    {
        print_error("Error: --summary applies only to 'report'.\n");
        return 1;
    }
    if (max_depth_given && action != ACTION_REPORT && action != ACTION_NONE)
    {
        print_error("Error: --max-depth applies only to 'report'.\n");
        return 1;
    }
    if (dry_run && action != ACTION_BACKUP && action != ACTION_RESTORE)
    {
        print_error("Error: --dry-run applies only to 'backup' or 'restore'.\n");
        return 1;
    }
    if (include_self && action != ACTION_BACKUP)
    {
        print_error("Error: --include-self applies only to 'backup'.\n");
        return 1;
    }
    if (include_network_config && action != ACTION_BACKUP)
    {
        print_error("Error: --include-network-config applies only to 'backup'.\n");
        return 1;
    }
    if (path != NULL && (action == ACTION_REPORT || action == ACTION_NONE))
    {
        print_error("Error: 'report' takes no arguments.\n");
        return 1;
    }
    // --- EXECUTION PHASE ---
    // Dispatching only after parsing completes means option position is irrelevant
    // (`migr backup -n /mnt` and `migr backup /mnt -n` behave identically), and the
    // positional arguments above are already settled by getopt's permutation.
    int ret = 0;
    switch (action)
    {
        case ACTION_NONE:
        case ACTION_REPORT:
            ret = run_scoped_report(mode, summary_flag, depth);
            break;
        case ACTION_BACKUP:
            if (path == NULL)
            {
                print_error("Usage: ./migr backup <PATH> [--critical | --comprehensive | <PATH...>]\n");
                ret = 1;
                break;
            }
            if (mode == BACKUP_EXPLICIT_PATHS)
                ret = backup(path, mode, user_paths, include_self,
                             include_network_config);
            else
            {
                SelectionPlan selection = {0};
                if (load_selection(mode, &selection, verbose || dry_run) != 0)
                    ret = 1;
                else
                {
                    ret = backup_selection(path, mode, &selection, include_self,
                                           include_network_config);
                    selection_plan_free(&selection);
                }
            }
            break;
        case ACTION_RESTORE:
            if (path == NULL)
            {
                print_error("Usage: ./migr restore <SOURCE>\n");
                ret = 1;
                break;
            }
            if (user_paths[0] != NULL)
            {
                print_error("Error: restore does not accept additional paths.\n");
                ret = 1;
                break;
            }
            ret = restore(path);
            break;
        case ACTION_CONF:
            ret = config_edit() == 0 ? 0 : 1;
            break;
        case ACTION_HELP:
            // Unreachable: handled immediately after the getopt loop, above.
            break;
    }

    return ret;
}
