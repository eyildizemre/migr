#ifndef DETECT_H
#define DETECT_H

typedef enum
{
    DISTRO_UNKNOWN, /**< Unrecognized distribution or /etc/os-release not found. */
    DISTRO_DEBIAN,  /**< Debian, Ubuntu, or Linux Mint. */
    DISTRO_FEDORA,  /**< Fedora, RHEL, or CentOS. */
    DISTRO_ARCH     /**< Arch Linux, Manjaro, or EndeavourOS. */
} distro_t;

/**
 * @brief Identifies the running Linux distribution by parsing /etc/os-release.
 *
 * Reads the ID= field and matches it against known keywords for Debian-based,
 * Fedora-based, and Arch-based families.
 *
 * @return The detected distro_t value, or DISTRO_UNKNOWN if the file is missing
 *         or the ID value is not recognized.
 */
distro_t detect_distro(void);

/**
 * @brief Returns the package-listing argv for the given distribution.
 *
 * The returned array is statically allocated and must not be freed.
 * Debian → dpkg --get-selections; Fedora → rpm -qa; Arch → pacman -Qe.
 *
 * @param distro The detected distribution.
 * @return A NULL-terminated argv suitable for run_command_capture(), or NULL for DISTRO_UNKNOWN.
 */
char *const *get_package_cmd(distro_t distro);

/**
 * @brief Returns a human-readable name string for a distro_t value.
 *
 * @param distro The detected distribution.
 * @return A statically allocated string such as "Debian/Ubuntu" or "Unknown".
 */
const char* get_distro_name(distro_t distro);

#endif