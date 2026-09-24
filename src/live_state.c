#include "live_state.h"

#include <string.h>

typedef struct {
    const char *root_id;
    const char *logical_prefix;
} LiveStatePath;

static const LiveStatePath live_state_paths[] = {
    { "BUILTIN_LOCAL_SHARE", "gvfs-metadata" },
    { "BUILTIN_DOT_CONFIG", "dconf/user" },
    { "BUILTIN_LOCAL_SHARE", "gnome-shell/application_state" },
    { "BUILTIN_LOCAL_SHARE", "flatpak" },
    { "BUILTIN_LOCAL_SHARE", "org.gnome.TextEditor" }
};

int live_state_path(const char *root_id, size_t root_id_length,
                    const char *logical, size_t logical_length)
{
    if (root_id == NULL || logical == NULL)
        return 0;
    for (size_t index = 0;
         index < sizeof(live_state_paths) / sizeof(live_state_paths[0]);
         index++)
    {
        const char *live_root = live_state_paths[index].root_id;
        const char *prefix = live_state_paths[index].logical_prefix;
        size_t live_root_length = strlen(live_root);
        size_t prefix_length = strlen(prefix);
        if (root_id_length != live_root_length ||
            memcmp(root_id, live_root, live_root_length) != 0 ||
            logical_length < prefix_length ||
            memcmp(logical, prefix, prefix_length) != 0)
            continue;
        if (logical_length == prefix_length || logical[prefix_length] == '/')
            return 1;
    }
    return 0;
}
