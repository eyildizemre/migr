#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "xdg.h"
#include "utils.h" // path_join

const char * const xdg_keys[XDG_KEY_COUNT]      = {
    "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR", "XDG_PICTURES_DIR",
    "XDG_DESKTOP_DIR",   "XDG_VIDEOS_DIR",   "XDG_MUSIC_DIR"
};
const char * const xdg_fallbacks[XDG_KEY_COUNT] = {
    "Documents", "Downloads", "Pictures",
    "Desktop",   "Videos",   "Music"
};

int xdg_resolve(const char *home,
                const char * const *keys,
                const char * const *fallbacks,
                char **out,
                int n)
{
    for (int i = 0; i < n; i++)
        out[i] = NULL;

    char config[PATH_MAX];
    FILE *f = NULL;
    int read_failed = 0;
    if (path_join(config, sizeof(config), home, ".config/user-dirs.dirs") != 0)
        read_failed = 1;
    else
    {
        f = fopen(config, "r");
        if (f == NULL && errno != ENOENT)
            read_failed = 1;
    }
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
                int rn;
                if (strncmp(val, "$HOME/", 6) == 0)
                    rn = snprintf(resolved, sizeof(resolved), "%s/%s", home, val + 6);
                else if (val[0] == '/')
                    rn = snprintf(resolved, sizeof(resolved), "%s", val);
                else
                    rn = snprintf(resolved, sizeof(resolved), "%s/%s", home, fallbacks[i]);

                // On truncation leave out[i] NULL; the fallback loop below fills it.
                if (rn >= 0 && (size_t)rn < sizeof(resolved))
                {
                    out[i] = strdup(resolved);
                    if (out[i] == NULL)
                        read_failed = 1;
                }
                break;
            }
        }
        if (ferror(f))
            read_failed = 1;
        fclose(f);
    }

    if (read_failed)
        return -1;

    // Fill any key not found in the config with the English default. Every path
    // must stay absolute: a bare relative name would resolve against the caller's
    // CWD, so if even home/<fallback> overflows PATH_MAX we leave the entry NULL
    // and report failure instead of storing something unsafe.
    int ok = 1;
    for (int i = 0; i < n; i++)
    {
        if (out[i] == NULL)
        {
            char fallback[PATH_MAX];
            if (path_join(fallback, sizeof(fallback), home, fallbacks[i]) != 0)
                ok = 0;
            else if ((out[i] = strdup(fallback)) == NULL)
                ok = 0;
        }
    }
    return ok ? 0 : -1;
}
