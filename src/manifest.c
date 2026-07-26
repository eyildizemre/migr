#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "manifest.h"
#include "utils.h" // path_join

const char * const manifest_keys[MANIFEST_XDG_COUNT] = {
    "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR", "XDG_PICTURES_DIR",
    "XDG_DESKTOP_DIR",   "XDG_VIDEOS_DIR",   "XDG_MUSIC_DIR"
};

int manifest_write(const char *backup_dir, const char * const *basenames, int n)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), backup_dir, "manifest.txt") != 0)
    {
        printf("Warning: Could not write manifest.txt\n");
        return 1;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf("Warning: Could not write manifest.txt\n");
        return 1;
    }

    for (int i = 0; i < n; i++)
    {
        // Write key-value pairs to manifest
        fprintf(f, "%s=%s\n", manifest_keys[i], basenames[i]);
    }
    
    fclose(f);
    return 0;
}

int manifest_read(const char *backup_dir, char **out, int n)
{
    for (int i = 0; i < n; i++)
        out[i] = NULL;

    char path[PATH_MAX];
    if (path_join(path, sizeof(path), backup_dir, "manifest.txt") != 0)
        return 1;

    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 1;

    char line[PATH_MAX + 32];
    while (fgets(line, sizeof(line), f) != NULL)
    {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        // Find the delimiter ('=')
        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;

        // Calculate key length using pointer arithmetic
        size_t key_len = (size_t)(eq - line);

        for (int i = 0; i < n; i++)
        {
            // Skip if already parsed
            if (out[i] != NULL)
                continue;
                
            // Optimization: Skip strncmp if lengths don't match
            if (strlen(manifest_keys[i]) != key_len)
                continue;
                
            // Match found
            if (strncmp(line, manifest_keys[i], key_len) != 0)
                continue;

            // Extract value starting right after '='
            char *val = eq + 1;
            size_t vlen = strlen(val);
            
            // Strip trailing newlines (CRLF/LF)
            while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r'))
                val[--vlen] = '\0';

            // Duplicate the string to heap and break inner loop
            out[i] = strdup(val);
            break;
        }
    }

    fclose(f);
    return 0;
}
