#include <stdio.h>
#include <string.h>

#include "detect.h"

// Map a distro identifier to the family whose package manager we support.
// The argument is the value part of an os-release line, never the whole line,
// so a key name can never be mistaken for an identifier.
static distro_t match_keywords(const char *value)
{
    if (strstr(value, "ubuntu") || strstr(value, "debian") || strstr(value, "mint"))
        return DISTRO_DEBIAN;
    if (strstr(value, "fedora") || strstr(value, "rhel") || strstr(value, "centos"))
        return DISTRO_FEDORA;
    if (strstr(value, "arch") || strstr(value, "manjaro") || strstr(value, "endeavour"))
        return DISTRO_ARCH;
    return DISTRO_UNKNOWN;
}

distro_t detect_distro_from(const char *os_release_path)
{
    FILE *fp = fopen(os_release_path, "r");
    if (fp == NULL)
    {
        return DISTRO_UNKNOWN;
    }

    distro_t from_id      = DISTRO_UNKNOWN;
    distro_t from_id_like = DISTRO_UNKNOWN;

    // Read the file to the end before deciding: os-release does not guarantee
    // key order, so returning on the first match could miss the other key.
    // Reading to completion also means exactly one fclose, on every path.
    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "ID=", 3) == 0)
            from_id = match_keywords(line + 3);
        else if (strncmp(line, "ID_LIKE=", 8) == 0)
            from_id_like = match_keywords(line + 8);
    }

    fclose(fp);

    // ID= is the distro's own identity and wins. ID_LIKE= names the families it
    // derives from, and is consulted only when ID= is not one we recognise —
    // that is what makes derivatives like Pop!_OS or Nobara resolve correctly.
    return (from_id != DISTRO_UNKNOWN) ? from_id : from_id_like;
}

distro_t detect_distro(void)
{
    return detect_distro_from("/etc/os-release");
}

char *const *get_package_cmd(distro_t distro)
{
    // Each command lists only explicitly-installed packages, one plain name per line.
    // See docs/DECISIONS.md D12.
    static char *const debian_cmd[] = {"apt-mark", "showmanual", NULL};

    // dnf's queryformat requires the two-character escape "\\n". A real newline byte is
    // copied through uninterpreted, collapsing the entire output into one record.
    static char *const fedora_cmd[] = {"dnf", "repoquery", "--userinstalled",
                                       "--qf", "%{name}\\n", NULL};

    // -q strips the version column that plain -Qe appends after each name.
    static char *const arch_cmd[]   = {"pacman", "-Qeq", NULL};

    switch (distro)
    {
        case DISTRO_DEBIAN: return debian_cmd;
        case DISTRO_FEDORA: return fedora_cmd;
        case DISTRO_ARCH:   return arch_cmd;
        default:            return NULL;
    }
}

const char* get_distro_name(distro_t distro)
{
    switch (distro)
    {
        case DISTRO_DEBIAN:
            return "Debian/Ubuntu";
        case DISTRO_FEDORA:
            return "Fedora/RHEL";
        case DISTRO_ARCH:
            return "Arch";
        default:
            return "Unknown";
    }
}