// Unit tests for path_join() / path_join_n().
//
// These join a directory and a name into a fixed buffer and must report
// truncation instead of silently acting on a cut-off path. The truncation
// boundary is an off-by-one trap (does an exact fit count as truncated?),
// so the cases below pin down the buffer size where success flips to failure.

#include <stdio.h>
#include <string.h>

#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

// Expect success: returns 0 and the buffer holds exactly want.
static void ok(const char *label, int rc, const char *buf, const char *want)
{
    if (rc == 0 && strcmp(buf, want) == 0)
        printf("  " GREEN "v" NC " %s -> \"%s\"\n", label, buf);
    else
    {
        printf("  " RED "x" NC " %s: rc=%d buf=\"%s\" (wanted rc=0 \"%s\")\n",
               label, rc, buf, want);
        failures++;
    }
}

// Expect truncation: returns -1.
static void truncated(const char *label, int rc)
{
    if (rc == -1)
        printf("  " GREEN "v" NC " %s -> refused (-1)\n", label);
    else
    {
        printf("  " RED "x" NC " %s: rc=%d (wanted -1)\n", label, rc);
        failures++;
    }
}

int main(void)
{
    printf(BLUE "::" NC " path_join (unit)\n");

    char buf[64];

    // Plain joins insert exactly one separator.
    ok("simple", path_join(buf, sizeof(buf), "abc", "de"), buf, "abc/de");
    ok("empty name", path_join(buf, sizeof(buf), "abc", ""), buf, "abc/");
    ok("nested name", path_join(buf, sizeof(buf), "/home/u", ".config/x"),
       buf, "/home/u/.config/x");

    // Boundary: "abc/de" is 6 chars and needs 7 bytes with the NUL.
    char small[7];
    ok("exact fit (size 7)", path_join(small, sizeof(small), "abc", "de"), small, "abc/de");
    truncated("one byte short (size 6)", path_join(small, 6, "abc", "de"));
    truncated("far too small (size 2)", path_join(small, 2, "abc", "de"));

    // path_join_n takes only the first name_len bytes of name, so a longer
    // source string (e.g. a parent-directory span up to a '/') is not read past.
    ok("span prefix", path_join_n(buf, sizeof(buf), "dir", "foo/bar/baz", 3),
       buf, "dir/foo");
    ok("span full length", path_join_n(buf, sizeof(buf), "dir", "name", 4),
       buf, "dir/name");
    truncated("span truncates", path_join_n(small, 6, "dir", "foo/bar", 3));

    if (failures > 0)
    {
        printf(RED "%d path_join test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
