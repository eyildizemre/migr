#ifndef BACKUP_H
#define BACKUP_H

typedef enum {
    BACKUP_CRITICAL,      /**< Documents, Downloads, Pictures, dotfiles, browser profiles, and packages. */
    BACKUP_COMPREHENSIVE, /**< Everything in BACKUP_CRITICAL plus Desktop, Videos, Music, and Projects. */
    BACKUP_EXPLICIT_PATHS          /**< Only the caller-supplied paths; no dotfiles, packages, or manifest. */
} BackupMode;

/**
 * @brief Backs up files from HOME to a dated subdirectory inside target.
 *
 * Creates target/migr_backup_YYYYMMDD/ and copies files according to mode.
 * BACKUP_CRITICAL copies Documents, Downloads, Pictures, dotfiles, browser
 * profiles, and the package list. BACKUP_COMPREHENSIVE adds Desktop, Videos,
 * Music, and Projects. BACKUP_EXPLICIT_PATHS copies only the caller-supplied paths.
 * A manifest.txt recording XDG directory names is written for all modes except
 * BACKUP_EXPLICIT_PATHS.
 *
 * @param target Destination directory; the dated backup subdirectory is created inside it.
 * @param mode   Selects which files are included (BACKUP_CRITICAL, BACKUP_COMPREHENSIVE, or BACKUP_EXPLICIT_PATHS).
 * @param paths  NULL-terminated array of paths (absolute, or relative to the
 *               current working directory); required when mode is
 *               BACKUP_EXPLICIT_PATHS, ignored otherwise.
 * @return 0 on success, 1 on error.
 */
int backup(const char *target, BackupMode mode, char **paths);

#endif
