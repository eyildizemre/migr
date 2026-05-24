#ifndef PACKAGES_H
#define PACKAGES_H

/**
 * @brief Exports the list of installed packages using the distro's native tool.
 *
 * Detects the distribution, runs the appropriate listing command (dpkg
 * --get-selections, rpm -qa, or pacman -Qe), and writes the output to path.
 *
 * @param path Destination file path for the package list.
 * @return 0 on success, 1 on error (unrecognized distro, allocation failure, or I/O error).
 */
int packages(const char *path);

#endif