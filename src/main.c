#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "backup.h"
#include "packages.h"
#include "report.h"
#include "restore.h"
#include "utils.h"

typedef enum {
    ACTION_NONE,
    ACTION_REPORT,
    ACTION_BACKUP,
    ACTION_PACKAGES,
    ACTION_RESTORE,
    ACTION_HELP
} Action;

int main(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"report",         no_argument,       NULL, 'r'},
        {"backup",         required_argument, NULL, 'b'},
        {"packages",       no_argument,       NULL, 'p'},
        {"restore",        required_argument, NULL, 's'},
        {"dry-run",        no_argument,       NULL, 'n'},
        {"help",           no_argument,       NULL, 'h'},
        {"critical",       no_argument,       NULL, 'c'},
        {"comprehensive",  no_argument,       NULL, 'C'},
        {"paths",          no_argument,       NULL, 'P'},
        {NULL,             0,                 NULL,  0 }
    };

    Action action = ACTION_NONE;
    char *path = NULL;
    BackupMode mode = BACKUP_CRITICAL;
    char **user_paths = NULL;
    int path_count = 0;
    int opt;

    // Use getopt_long_only to support single-dash long arguments seamlessly
    // (e.g., './migr -backup' instead of requiring './migr --backup')
    while ((opt = getopt_long_only(argc, argv, "nv", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'v': verbose = 1;                   break;
            case 'n': dry_run = 1;                   break;
            case 'r': action = ACTION_REPORT;        break;
            case 'b': action = ACTION_BACKUP;        path = optarg; break;
            case 'p':
                action = ACTION_PACKAGES;
                // WORKAROUND: getopt's `optional_argument` strictly requires '=' syntax (-packages=file).
                // To support space-separated syntax (-packages file.txt) and match our CLI design,
                // we declare it as `no_argument` and manually peek ahead at argv[optind].
                if (optind < argc && argv[optind][0] != '-')
                    path = argv[optind++];
                break;
            case 's': action = ACTION_RESTORE;       path = optarg; break;
            case 'h': action = ACTION_HELP;          break;
            case 'c': mode = BACKUP_CRITICAL;        break;
            case 'C': mode = BACKUP_COMPREHENSIVE;   break;
            case 'P':
                mode = BACKUP_PATHS;
                while (optind < argc && argv[optind][0] != '-')
                {
                    user_paths = realloc(user_paths, (path_count + 2) * sizeof(char *));
                    user_paths[path_count++] = argv[optind++];
                    user_paths[path_count] = NULL;
                }
                break;
            case '?':
            default:
                printf("For help: ./migr -help\n");
                free(user_paths);
                return 1;
        }
    }

    // --- EXECUTION PHASE ---
    // Dispatching actions only after all flags are fully parsed ensures
    // that argument order does not matter (e.g., `-n -backup path` vs `-backup path -n`).
    int ret = 0;
    switch (action)
    {
        case ACTION_NONE:
        case ACTION_REPORT:
            ret = report();
            break;
        case ACTION_BACKUP:
            if (path == NULL)
            {
                printf("Usage: ./migr -backup <PATH> [-critical | -comprehensive | -paths <PATH...>]\n");
                ret = 1;
                break;
            }
            ret = backup(path, mode, user_paths);
            break;
        case ACTION_PACKAGES:
            if (path == NULL)
            {
                printf("Usage: ./migr -packages <FILE>\n");
                ret = 1;
                break;
            }
            ret = packages(path);
            break;
        case ACTION_RESTORE:
            if (path == NULL)
            {
                printf("Usage: ./migr -restore <SOURCE>\n");
                ret = 1;
                break;
            }
            ret = restore(path);
            break;
        case ACTION_HELP:
            print_help();
            break;
    }

    free(user_paths);
    return ret;
}
