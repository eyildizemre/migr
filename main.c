#include <stdio.h>
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
        {"report",   no_argument,       NULL, 'r'},
        {"backup",   required_argument, NULL, 'b'},
        {"packages", no_argument,       NULL, 'p'},
        {"restore",  required_argument, NULL, 's'},
        {"dry-run",  no_argument,       NULL, 'n'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,       0,                 NULL,  0 }
    };

    Action action = ACTION_NONE;
    char *path = NULL;
    int opt;

    // Use getopt_long_only to support single-dash long arguments seamlessly
    // (e.g., './migr -backup' instead of requiring './migr --backup')
    while ((opt = getopt_long_only(argc, argv, "nv", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'v': verbose = 1;              break;
            case 'n': dry_run = 1;              break;
            case 'r': action = ACTION_REPORT;   break;
            case 'b': action = ACTION_BACKUP;   path = optarg; break;
            case 'p':
                action = ACTION_PACKAGES;
                // WORKAROUND: getopt's `optional_argument` strictly requires '=' syntax (-packages=file).
                // To support space-separated syntax (-packages file.txt) and match our CLI design,
                // we declare it as `no_argument` and manually peek ahead at argv[optind].
                if (optind < argc && argv[optind][0] != '-')
                    path = argv[optind++];
                break;
            case 's': action = ACTION_RESTORE;  path = optarg; break;
            case 'h': action = ACTION_HELP;     break;
            case '?':
            default:
                printf("For help: ./migr -help\n");
                return 1;
        }
    }

    // --- EXECUTION PHASE ---
    // Dispatching actions only after all flags are fully parsed ensures 
    // that argument order does not matter (e.g., `-n -backup path` vs `-backup path -n`).
    switch (action)
    {
        case ACTION_NONE:
        case ACTION_REPORT:
            return report();
        case ACTION_BACKUP:
            if (path == NULL)
            {
                printf("Usage: ./migr -backup <PATH>\n");
                return 1;
            }
            return backup(path);
        case ACTION_PACKAGES:
            return packages(path);
        case ACTION_RESTORE:
            if (path == NULL)
            {
                printf("Usage: ./migr -restore <SOURCE>\n");
                return 1;
            }
            return restore(path);
        case ACTION_HELP:
            print_help();
            break;
    }

    return 0;
}
