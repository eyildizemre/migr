#ifndef RESTORE_H
#define RESTORE_H

/**
 * @brief Restores files and packages from a backup directory to HOME.
 *
 * Prompts for user confirmation, then copies main directories, dotfiles, and
 * browser profiles from source back to their correct locations in HOME. Reads
 * manifest.txt to resolve cross-locale XDG directory names (e.g. "Belgeler"
 * on the source system maps to Documents on an English target system). Falls
 * back to the target system's basename if manifest.txt is absent. If
 * packages.txt is present, installs the listed packages via the distro's
 * package manager.
 *
 * @param source Path to the dated backup directory (e.g. /mnt/drive/migr_backup_20260519).
 * @return 0 on success or user cancellation, 1 on error.
 */
int restore(const char *source);

#endif