#include <stdio.h>
#include <string.h>

#include "detect.h"
#include "report.h"
#include "backup.h"
#include "packages.h"
#include "restore.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    char *command = NULL;
    char *arg = NULL;

    if (argc < 2)
    {
        report();
        return 0;
    }

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-v") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0)
        {
            dry_run = 1;
        }
        else if (command == NULL)
        {
            command = argv[i];
        }
        else if (arg == NULL)
        {
            arg = argv[i];
        }
    }

    if (command == NULL)
    {
        report();
    }
    else if (strcmp(command, "-report") == 0)
    {
        report();
    }
    else if (strcmp(command, "-backup") == 0)
    {
        if (arg == NULL)
        {
            printf("Usage: migr -backup <PATH>\n");
            return 1;
        }
        backup(arg);
    }
    else if (strcmp(command, "-packages") == 0)
    {
        packages(arg);
    }
    else if (strcmp(command, "-restore") == 0)
    {
        if (arg == NULL)
        {
            printf("Usage: migr -restore <source>\n");
            return 1;
        }
        restore(arg);
    }
    else if (strcmp(command, "-help") == 0)
    {
        print_help();
    }
    else
    {
        printf("Unknown flag: %s\n", command);
        printf("For help: migr -help\n");
        return 1;
    }

    return 0;
}
