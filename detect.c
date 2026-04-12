#include <stdio.h>
#include <string.h>

#include "detect.h"

distro_t detect_distro(void)
{
    FILE *fp = fopen("/etc/os-release", "r");
    if (fp == NULL)
    {
        return DISTRO_UNKNOWN;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "ID=", 3) == 0)
        {
            fclose(fp);
            
            // check for known distro keywords
            if (strstr(line, "ubuntu") || strstr(line, "debian") || strstr(line, "mint"))
            {
                return DISTRO_DEBIAN;
            }
            else if (strstr(line, "fedora") || strstr(line, "rhel") || strstr(line, "centos"))
            {
                return DISTRO_FEDORA;
            }
            else if (strstr(line, "arch") || strstr(line, "manjaro") || strstr(line, "endeavour"))
            {
                return DISTRO_ARCH;
            }
        }
    }

    fclose(fp);
    return DISTRO_UNKNOWN;
}

const char* get_package_cmd(distro_t distro)
{
    switch (distro)
    {
        case DISTRO_DEBIAN:
            return "dpkg --get-selections";
        case DISTRO_FEDORA:
            return "rpm -qa";
        case DISTRO_ARCH:
            return "pacman -Qe";
        default:
            return NULL;
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