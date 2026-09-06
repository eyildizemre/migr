#include "selection.h"
#include "utils.h" // path_covers
#include <string.h>

/* Thin wrapper: the inclusive containment rule itself lives in utils.c so
 * manifest.c and restore.c can share it without depending on selection.h --
 * manifest reading must stay independent of the selection compiler. This
 * name stays because src/selection.c calls it throughout. */
int selection_path_covers(const char *parent, const char *path)
{
    return path_covers(parent, path);
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
        /* NAME_MAX matches manifest.c's canonical_path(): every caller here
         * builds rel from a real readdir() entry, whose name the filesystem
         * already bounded to NAME_MAX, so this never rejects a real path --
         * it only keeps the rule that decides ownership identical on both
         * sides instead of letting it drift, as canonical_path()'s already did. */
        if (!n || n > NAME_MAX || (n == 1 && p[0] == '.') || (n == 2 && !memcmp(p, "..", 2))) return -1;
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
