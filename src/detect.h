#ifndef DETECT_H
#define DETECT_H

#include <stddef.h>

typedef enum
{
    DISTRO_UNKNOWN, /**< Unrecognized distribution or /etc/os-release not found. */
    DISTRO_DEBIAN,  /**< Debian, Ubuntu, or Linux Mint. */
    DISTRO_FEDORA,  /**< Fedora, RHEL, or CentOS. */
    DISTRO_ARCH     /**< Arch Linux, Manjaro, or EndeavourOS. */
} distro_t;

/**
 * @brief Identifies a Linux distribution by parsing an os-release file at a given path.
 *
 * Reads both the ID= and ID_LIKE= fields and matches their values against known
 * keywords for the Debian, Fedora, and Arch families. ID= takes precedence; ID_LIKE=
 * is consulted only when ID= is unrecognized, which is what lets derivatives such as
 * Pop!_OS, elementary, or Nobara resolve to their parent family. The whole file is
 * read before deciding, since os-release does not guarantee key order.
 *
 * Exposed separately from detect_distro() so the parsing logic can be exercised
 * against synthetic os-release files without depending on the host system.
 *
 * @param os_release_path Path to the os-release file to parse.
 * @return The detected distro_t value, or DISTRO_UNKNOWN if the file is missing
 *         or neither field names a supported family.
 */
distro_t detect_distro_from(const char *os_release_path);

/**
 * @brief Identifies the running Linux distribution by parsing /etc/os-release.
 *
 * Thin wrapper over detect_distro_from() using the system os-release path.
 *
 * @return The detected distro_t value, or DISTRO_UNKNOWN if the file is missing
 *         or the distribution is not recognized.
 */
distro_t detect_distro(void);

/**
 * @brief Returns the package-listing argv for the given distribution.
 *
 * Every command lists only explicitly-installed packages — not transitive
 * dependencies — and emits one plain package name per line, so all three
 * distributions produce the same file format.
 *
 * Debian → apt-mark showmanual; Fedora → dnf repoquery --userinstalled;
 * Arch → pacman -Qeq.
 *
 * The returned array is statically allocated and must not be freed.
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

/**
 * @brief Reads the system's own name (PRETTY_NAME) from an os-release file.
 *
 * @param os_release_path Path to an os-release-formatted file.
 * @param out             Receives the name, without quotes; truncated to fit.
 * @param out_size        Size of out.
 * @return 0 on success, -1 if the file is missing or names no system.
 */
int detect_system_name_from(const char *os_release_path, char *out,
                            size_t out_size);

/**
 * @brief detect_system_name_from() on the system os-release path.
 */
int detect_system_name(char *out, size_t out_size);

#endif