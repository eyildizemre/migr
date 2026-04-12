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
    // If no arguments or only -report flag, show report
    if (argc < 2)
    {
        report();
        return 0;
    }

    // -v flag control (verbose mode)
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-v") == 0)
        {
            verbose = 1;
        }
    }

    // Check main flags
    if (strcmp(argv[1], "-report") == 0)
    {
        report();
    }
    else if (strcmp(argv[1], "-backup") == 0)
    {
        if (argc < 3)
        {
            printf("Usage: migr -backup <PATH>\n");
            return 1;
        }
        backup(argv[2]);
    }
    else if (strcmp(argv[1], "-packages") == 0)
    {
        char *path = (argc >= 3) ? argv[2] : NULL;
        packages(path);
    }
    else if (strcmp(argv[1], "-restore") == 0)
    {
        if (argc < 3)
        {
            printf("Usage: migr -restore <source>\n");
            return 1;
        }
        restore(argv[2]);
    }
    else if (strcmp(argv[1], "-help") == 0)
    {
        print_help();
    }
    else
    {
        printf("Unknown flag: %s\n", argv[1]);
        printf("For help: migr -help\n");
        return 1;
    }

    return 0;
}