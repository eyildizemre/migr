#ifndef PACKAGES_H
#define PACKAGES_H

/**
 * @brief Exports the list of installed packages using the distro's native tool.
 *
 * Detects the distribution, runs the appropriate listing command (dpkg
 * --get-selections, rpm -qa, or pacman -Qe), and captures the output.
 * If path is non-NULL the output is written to that file; otherwise it
 * is printed to stdout.
 *
 * @param path Destination file path for the package list, or NULL to print to stdout.
 * @return 0 on success, 1 on error (unrecognized distro, allocation failure, or I/O error).
 */
int packages(const char *path);

#endif