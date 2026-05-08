#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "xdg.h"

void xdg_resolve(const char *home,
                 const char * const *keys,
                 const char * const *fallbacks,
                 char **out,
                 int n)
{
    for (int i = 0; i < n; i++)
        out[i] = NULL;

    char config[PATH_MAX];
    snprintf(config, sizeof(config), "%s/.config/user-dirs.dirs", home);

    FILE *f = fopen(config, "r");
    if (f != NULL)
    {
        char line[PATH_MAX + 32];
        while (fgets(line, sizeof(line), f) != NULL)
        {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
                continue;

            char *eq = strchr(line, '=');
            if (eq == NULL)
                continue;

            size_t key_len = (size_t)(eq - line);

            for (int i = 0; i < n; i++)
            {
                if (out[i] != NULL)
                    continue;
                if (strlen(keys[i]) != key_len || strncmp(line, keys[i], key_len) != 0)
                    continue;

                // value format: ="$HOME/path" or ="/absolute/path"
                char *val = eq + 1;
                if (*val == '"') val++;

                // strip trailing '"', newline, carriage return
                size_t vlen = strlen(val);
                while (vlen > 0 && (val[vlen-1] == '"' || val[vlen-1] == '\n' || val[vlen-1] == '\r'))
                    val[--vlen] = '\0';

                char resolved[PATH_MAX];
                if (strncmp(val, "$HOME/", 6) == 0)
                    snprintf(resolved, sizeof(resolved), "%s/%s", home, val + 6);
                else if (val[0] == '/')
                    snprintf(resolved, sizeof(resolved), "%s", val);
                else
                    snprintf(resolved, sizeof(resolved), "%s/%s", home, fallbacks[i]);

                out[i] = strdup(resolved);
                break;
            }
        }
        fclose(f);
    }

    // fill in any keys not found in the config with English defaults
    for (int i = 0; i < n; i++)
    {
        if (out[i] == NULL)
        {
            char fallback[PATH_MAX];
            snprintf(fallback, sizeof(fallback), "%s/%s", home, fallbacks[i]);
            out[i] = strdup(fallback);
        }
    }
}
