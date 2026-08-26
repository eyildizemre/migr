#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "backup.h"
#include "report.h"
#include "restore.h"
#include "utils.h"

typedef enum {
    ACTION_NONE,
    ACTION_REPORT,
    ACTION_BACKUP,
    ACTION_RESTORE,
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
    else if (strcmp(arg, "help") == 0)
        *action = ACTION_HELP;
    else
        *action = ACTION_NONE;
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
        return report(BACKUP_CRITICAL, 0, 0, depth);

    static struct option long_options[] = {
        {"dry-run",        no_argument,       NULL, 'n'},
        {"verbose",        no_argument,       NULL, 'v'},
        {"help",           no_argument,       NULL, 'h'},
        {"critical",       no_argument,       NULL, 'c'},
        {"comprehensive",  no_argument,       NULL, 'C'},
        {"summary",        no_argument,       NULL, 's'},
        {"max-depth",      required_argument, NULL, 'd'},
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
            printf("Unknown command: %s\n", argv[1]);
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

    // Parse options only. optind was set above to skip the command word, or left
    // at 1 when no command was given (e.g. `migr --help`). getopt_long permutes
    // argv as it scans, so once the loop ends every non-option argument sits
    // contiguously starting at argv[optind] — that is where positionals are read.
    while ((opt = getopt_long(argc, argv, "nvhs", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'v':
            verbose = 1;
            break;
        case 'n':
            dry_run = 1;
            break;
        case 'h':
            action = ACTION_HELP;
            break;
        case 'c':
        case 'C':
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
            summary_flag = 1;
            break;
        case 'd':
            if (parse_report_depth(optarg, &depth) != 0)
            {
                print_error("Error: --max-depth must be a non-negative integer.\n");
                return 1;
            }
            max_depth_given = 1;
            verbose = 1;
            break;
        case '?':
        default:
            printf("For help: ./migr --help\n");
            return 1;
        }
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
            ret = report(mode, mode_flag_given || summary_flag || max_depth_given,
                         summary_flag, depth);
            break;
        case ACTION_BACKUP:
            if (path == NULL)
            {
                print_error("Usage: ./migr backup <PATH> [--critical | --comprehensive | <PATH...>]\n");
                ret = 1;
                break;
            }
            ret = backup(path, mode, user_paths);
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
        case ACTION_HELP:
            print_help();
            break;
    }

    return ret;
}
