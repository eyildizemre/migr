// Unit tests for the parts of source_snapshot.c that need neither root nor
// btrfs (docs/DECISIONS.md D64); the snapshot itself is exercised by
// test.sh's btrfs phase, which runs as root.
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "source_snapshot.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define NC "\033[0m"

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

int main(void)
{
    printf(BLUE "::" NC " source snapshot helpers\n");

    char path[] = "/home/user/My\\040Drive/tab\\011here/back\\134slash";
    source_snapshot_unescape_mount_path(path);
    check(strcmp(path, "/home/user/My Drive/tab\there/back\\slash") == 0,
          "mountinfo octal escapes decode to the real path");

    char plain[] = "/home/user/no-escapes\\";
    source_snapshot_unescape_mount_path(plain);
    check(strcmp(plain, "/home/user/no-escapes\\") == 0,
          "a path without a full escape is left as it is");

    if (geteuid() != 0)
    {
        SourceSnapshot snapshot;
        source_snapshot_init(&snapshot);
        const char *paths[] = { "/home" };
        char note[128] = "stale";
        size_t count = source_snapshot_begin(&snapshot, paths, 1, "/tmp",
                                             note, sizeof(note));
        source_snapshot_end(&snapshot);
        check(count == 0 && note[0] == '\0' && snapshot.saved_namespace_fd < 0,
              "without root no snapshot is attempted and nothing is noted");
    }

    if (failures != 0)
    {
        printf(RED "%d source snapshot test failure%s" NC "\n", failures,
               failures == 1 ? "" : "s");
        return 1;
    }
    printf(GREEN "source snapshot tests passed" NC "\n");
    return 0;
}
