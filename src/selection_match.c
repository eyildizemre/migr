#include "selection.h"
#include <string.h>

int selection_path_covers(const char *parent, const char *path)
{
    size_t n = strlen(parent);
    return !strcmp(parent, path) || (n == 1 && parent[0] == '/' && path[0] == '/') ||
           (n && !strncmp(parent, path, n) && path[n] == '/');
}

static int excluded_path(const SelectionPaths *excludes, const char *path)
{
    if (excludes)
        for (size_t i = 0; i < excludes->count; i++)
            if (selection_path_covers(excludes->paths[i], path)) return 1;
    return 0;
}

int selection_root_owns(const SelectionRoot *root, const char *rel)
{
    if (!root || !rel || *rel == '/' || strlen(rel) >= PATH_MAX) return -1;
    for (const char *p = rel; *p; )
    {
        size_t n = strcspn(p, "/");
        if (!n || (n == 1 && p[0] == '.') || (n == 2 && !memcmp(p, "..", 2))) return -1;
        p += n;
        if (*p && !*++p) return -1;
    }
    if (excluded_path(&root->excluded, rel) || excluded_path(&root->delegated, rel)) return 0;
    return 1;
}

int selection_source_owns(const SelectionRoot *root, const char *source)
{
    if (!root || !source) return -1;
    const char *base = root->root.capture_path;
    if (!selection_path_covers(base, source)) return -1;
    if (!strcmp(base, source)) return selection_root_owns(root, "");
    return selection_root_owns(root, source + strlen(base) + (strcmp(base, "/") != 0));
}
