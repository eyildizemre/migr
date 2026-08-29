#ifndef PACKAGES_H
#define PACKAGES_H

#include <stdio.h>

/**
 * @brief Exports the same package list into an open container directory.
 *
 * How production writes packages.txt: the container's directory fd is already
 * open and locked, so the file is created with openat() and O_NOFOLLOW rather
 * than through a rebuilt path string a symlink could redirect.
 *
 * Nothing already occupying leaf is ever opened or written into: the name is
 * removed first and the list is written to an inode this call creates with
 * O_EXCL. That is what keeps a FIFO from blocking the backup forever, and a
 * hardlink to a file outside the container from being truncated and
 * overwritten with the package list.
 *
 * A failed export never leaves something usable-looking behind either. leaf is
 * cleared when the list cannot be produced, cannot be created safely, or
 * cannot be written in full -- so a container that goes on to be finalized
 * carries either a complete package list or none at all, never a stale,
 * hostile, or truncated one. The three return values exist because those are
 * three different situations for the caller: a missing package list is
 * tolerable, an unclearable control slot is not.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to create beneath it; a single component.
 * @return 0 when a complete list was written; 1 when no list was written and
 *         the slot was left empty; -1 when the slot could not be made safe, in
 *         which case the container must not be finalized.
 */
int packages_at(int container_fd, const char *leaf);

/**
 * @brief Ensures no object occupies a control-artifact slot in a container.
 *
 * Used where a package list must not be present at all -- an explicit-paths
 * backup exports none, and an adopted container may still hold one a previous
 * run (or someone else) left behind. Restore acts on whatever packages.txt it
 * finds without re-deriving the backup's scope, so leaving a stale one inside a
 * finalized container would let it drive package installs the backup never
 * recorded.
 *
 * A symlink is removed as itself, never followed.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to clear beneath it; a single component.
 * @return 0 when nothing occupies leaf afterwards (including when nothing did),
 *         -1 when something is still there.
 */
int packages_clear_at(int container_fd, const char *leaf);

/**
 * @brief Reports whether a package name is safe to use as a package-manager
 * argv element.
 *
 * Real backups only ever write plain names (docs/DECISIONS.md D12); a token
 * beginning with '-' would otherwise be interpreted by apt-get/dnf/pacman as
 * an option rather than a package name when it reaches the privileged install
 * invocation. Exposed for direct testing.
 *
 * @param token NUL-terminated candidate package name; NULL is rejected.
 * @return 1 if safe to use as an argv element, 0 otherwise.
 */
int package_token_is_safe(const char *token);

/**
 * @brief Reads and validates the package-name list from an open packages.txt
 * stream.
 *
 * Every line's first whitespace-delimited token is checked with
 * package_token_is_safe(); a rejected token is skipped the same way an
 * old-format dpkg "pkg\tdeinstall" entry is already skipped. A stream error,
 * failed growth allocation, or failed per-entry allocation sets *had_error.
 * Successfully parsed entries before a failure are still returned.
 *
 * On return, *pkgs_out is either NULL when the initial array allocation failed
 * or an array of *pkg_count_out heap-owned strings. The caller owns the
 * strings and the array.
 *
 * @param pkg_file      Open, readable stream positioned at the file start.
 * @param pkgs_out      Receives the parsed package-name array.
 * @param pkg_count_out Receives the number of entries in *pkgs_out.
 * @param had_error     Set to 1 on any read/allocation failure; untouched
 *                      otherwise.
 */
void read_package_list(FILE *pkg_file, char ***pkgs_out, int *pkg_count_out,
                       int *had_error);

/**
 * @brief Installs packages listed in a restored packages.txt.
 *
 * Reads packages.txt from source_root_fd, detects the distro, and invokes the
 * distro's package manager. A dry run only previews; a missing or non-regular
 * packages.txt and an unrecognized distro are skipped without making the
 * restore fatal, while failures to read or inspect the file set had_error.
 *
 * @param source_root_fd Directory fd the restored packages.txt is read from.
 * @param home           Home directory path, used for the skipped-packages log.
 * @param had_error      Set to 1 on a real failure; untouched otherwise.
 */
void restore_packages(int source_root_fd, const char *home, int *had_error);

#endif
