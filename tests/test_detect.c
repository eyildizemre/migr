// Unit tests for detect_distro_from().
//
// Distro detection cannot be exercised through the CLI: it reads /etc/os-release,
// so on any given machine only one branch is reachable. These tests feed synthetic
// os-release files instead, which is the only way to verify the ID_LIKE fallback
// without installing the derivative distributions it exists for.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "detect.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

// Writes contents to a temporary file, runs detect_distro_from() against it, and
// compares the result to what the case expects.
static void check(const char *label, const char *contents, distro_t expected)
{
    char path[] = "/tmp/migr_osrelease_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
    {
        printf("  " RED "x" NC " %s: could not create temp file\n", label);
        failures++;
        return;
    }

    FILE *f = fdopen(fd, "w");
    if (f == NULL)
    {
        printf("  " RED "x" NC " %s: could not open temp file\n", label);
        failures++;
        close(fd);
        unlink(path);
        return;
    }
    fputs(contents, f);
    fclose(f);

    distro_t got = detect_distro_from(path);
    unlink(path);

    if (got == expected)
    {
        printf("  " GREEN "v" NC " %s -> %s\n", label, get_distro_name(got));
    }
    else
    {
        printf("  " RED "x" NC " %s: expected %s, got %s\n",
               label, get_distro_name(expected), get_distro_name(got));
        failures++;
    }
}

int main(void)
{
    printf(BLUE "::" NC " Phase 0: distro detection (unit)\n");

    // ID= alone, for the families named directly
    check("Debian (ID=debian)",
          "NAME=\"Debian GNU/Linux\"\nID=debian\n", DISTRO_DEBIAN);
    check("Fedora (ID=fedora)",
          "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n", DISTRO_FEDORA);
    check("Arch (ID=arch)",
          "NAME=\"Arch Linux\"\nID=arch\n", DISTRO_ARCH);

    // Derivatives: ID= is unrecognized, ID_LIKE= names the parent family.
    // These are the cases that returned DISTRO_UNKNOWN before ID_LIKE was read.
    check("Pop!_OS (ID_LIKE=ubuntu debian)",
          "NAME=\"Pop!_OS\"\nID=pop\nID_LIKE=\"ubuntu debian\"\n", DISTRO_DEBIAN);
    check("elementary (ID_LIKE=ubuntu)",
          "NAME=\"elementary OS\"\nID=elementary\nID_LIKE=ubuntu\n", DISTRO_DEBIAN);
    check("Raspberry Pi OS (ID_LIKE=debian)",
          "NAME=\"Raspbian\"\nID=raspbian\nID_LIKE=debian\n", DISTRO_DEBIAN);
    check("Nobara (ID_LIKE=fedora)",
          "NAME=\"Nobara Linux\"\nID=nobara\nID_LIKE=fedora\n", DISTRO_FEDORA);
    check("Garuda (ID_LIKE=arch)",
          "NAME=\"Garuda Linux\"\nID=garuda\nID_LIKE=arch\n", DISTRO_ARCH);

    // ID= wins over ID_LIKE=, and must do so regardless of which line comes first.
    check("ID beats ID_LIKE",
          "ID=fedora\nID_LIKE=\"ubuntu debian\"\n", DISTRO_FEDORA);
    check("ID beats ID_LIKE (reversed order)",
          "ID_LIKE=\"ubuntu debian\"\nID=fedora\n", DISTRO_FEDORA);

    // Unsupported package manager must stay UNKNOWN rather than guess a family.
    check("openSUSE stays unknown (zypper unsupported)",
          "NAME=\"openSUSE Tumbleweed\"\nID=opensuse-tumbleweed\n"
          "ID_LIKE=\"opensuse suse\"\n", DISTRO_UNKNOWN);

    // Degenerate inputs
    check("no ID field at all",
          "NAME=\"Mystery Linux\"\nVERSION_ID=1\n", DISTRO_UNKNOWN);
    check("empty file", "", DISTRO_UNKNOWN);

    // A missing file must not crash; checked directly since check() writes a file.
    if (detect_distro_from("/nonexistent/os-release") == DISTRO_UNKNOWN)
        printf("  " GREEN "v" NC " missing file -> Unknown\n");
    else
    {
        printf("  " RED "x" NC " missing file: expected Unknown\n");
        failures++;
    }

    if (failures > 0)
    {
        printf(RED "%d detection test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
