#include <stdio.h>
#include <string.h>

#include "live_state.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static int live(const char *root, const char *logical)
{
    return live_state_path(root, strlen(root), logical, strlen(logical));
}

int main(void)
{
    printf(BLUE "::" NC " confirmed live desktop state paths\n");
    check(live("BUILTIN_LOCAL_SHARE", "gvfs-metadata") &&
              live("BUILTIN_LOCAL_SHARE", "gvfs-metadata/root-1a2b.log"),
          "gvfs-metadata and everything below it is live");
    check(live("BUILTIN_DOT_CONFIG", "dconf/user"),
          "the dconf user database is live");
    check(live("BUILTIN_LOCAL_SHARE", "containers/storage/storage.lock"),
          "Podman's storage lock is live");
    check(!live("BUILTIN_LOCAL_SHARE", "containers/storage/overlay/x"),
          "the rest of Podman's storage is not");
    check(!live("BUILTIN_LOCAL_SHARE", "gvfs-metadata-x/file") &&
              !live("BUILTIN_LOCAL_SHARE", "gvfs-metadatax"),
          "a sibling sharing the prefix is not live");
    check(!live("BUILTIN_DOT_CONFIG", "gvfs-metadata"),
          "the same logical path under another root is not live");
    check(!live("BUILTIN_LOCAL_SHARE", "gvfs") &&
              !live("BUILTIN_LOCAL_SHARE", ""),
          "a parent of a live path is not itself live");
    check(!live_state_path(NULL, 0, "gvfs-metadata", 13) &&
              !live_state_path("BUILTIN_LOCAL_SHARE", 19, NULL, 0),
          "missing arguments are never live");
    if (failures != 0)
    {
        printf("%d live-state test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
