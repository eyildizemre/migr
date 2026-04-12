#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packages.h"
#include "detect.h"
#include "utils.h"

extern int verbose;

int packages(const char *path)
{
    distro_t distro = detect_distro();
    const char *cmd = get_package_cmd(distro);

    if (cmd == NULL)
    {
        printf("Error: Could not detect distribution.\n");
        return 1;
    }

    if (verbose)
    {
        printf("Detected: %s\n", get_distro_name(distro));
        printf("Running: %s\n", cmd);
    }

    FILE *pipe = popen(cmd, "r");
    if (pipe == NULL)
    {
        printf("Error: Could not run package command.\n");
        return 1;
    }

    FILE *out = NULL;
    if (path != NULL)
    {
        out = fopen(path, "w");
        if (out == NULL)
        {
            printf("Error: Could not open %s for writing.\n", path);
            pclose(pipe);
            return 1;
        }
    }

    char line[512];
    int count = 0;

    while (fgets(line, sizeof(line), pipe))
    {
        if (path != NULL)
        {
            fputs(line, out);
        }
        else
        {
            printf("%s", line);
        }
        count++;
    }

    pclose(pipe);

    if (out != NULL)
    {
        fclose(out);
        printf("Saved %d packages to %s\n", count, path);
    }
    else if (verbose)
    {
        printf("\nTotal: %d packages\n", count);
    }

    return 0;
}