#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packages.h"
#include "detect.h"
#include "fileops.h"
#include "utils.h"

extern int verbose;

int packages(const char *path)
{
    distro_t distro = detect_distro();
    char *const *cmd = get_package_cmd(distro);

    if (cmd == NULL)
    {
        printf("Error: Could not detect distribution.\n");
        return 1;
    }

    if (verbose)
    {
        printf("Detected: %s\n", get_distro_name(distro));
        printf("Running: %s %s\n", cmd[0], cmd[1]);
    }

    size_t buf_size = 5 * 1024 * 1024; // 5 MB
    char *buffer = malloc(buf_size);
    if (buffer == NULL)
    {
        printf("Error: Could not allocate buffer.\n");
        return 1;
    }

    buffer[0] = '\0';

    if (run_command_capture(cmd, buffer, buf_size) != 0)
    {
        printf("Error: Could not run package command.\n");
        free(buffer);
        return 1;
    }

    int count = 0;
    for (char *p = buffer; *p; p++)
    {
        if (*p == '\n')
            count++;
    }

    if (path != NULL)
    {
        FILE *out = fopen(path, "w");
        if (out == NULL)
        {
            printf("Error: Could not open %s for writing.\n", path);
            free(buffer);
            return 1;
        }
        fputs(buffer, out);
        fclose(out);
        printf("Saved %d packages to %s\n", count, path);
    }
    else
    {
        printf("%s", buffer);
        if (verbose)
        {
            printf("\nTotal: %d packages\n", count);
        }
    }

    free(buffer);
    return 0;
}