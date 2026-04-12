#ifndef DETECT_H
#define DETECT_H

typedef enum
{
    DISTRO_UNKNOWN,
    DISTRO_DEBIAN,
    DISTRO_FEDORA,
    DISTRO_ARCH
} distro_t;

distro_t detect_distro(void);
const char* get_package_cmd(distro_t distro);
const char* get_distro_name(distro_t distro);

#endif