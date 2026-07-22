#ifndef PACKAGES_H
#define PACKAGES_H

/**
 * @brief Exports the list of installed packages using the distro's native tool.
 *
 * Detects the distribution, runs the appropriate listing command (apt-mark
 * showmanual, dnf repoquery --userinstalled, or pacman -Qeq), and writes the
 * output to path. Only explicitly-installed packages are listed; transitive
 * dependencies are left for the target system's package manager to resolve.
 *
 * @param path Destination file path for the package list.
 * @return 0 on success, 1 on error (unrecognized distro, allocation failure, or I/O error).
 */
int packages(const char *path);

#endif