#ifndef BACKUP_H
#define BACKUP_H

#include <sys/types.h> /* off_t */

typedef enum {
    BACKUP_CRITICAL,      /**< Documents, Downloads, Pictures, dotfiles, browser profiles, and packages. */
    BACKUP_COMPREHENSIVE, /**< Everything in BACKUP_CRITICAL plus Desktop, Videos, Music, and Projects. */
    BACKUP_EXPLICIT_PATHS          /**< Only the caller-supplied paths; no dotfiles and no package list. */
} BackupMode;

/**
 * @brief Backs up files from HOME into a versioned container inside target.
 *
 * Writes to target/migr_backup_YYYYMMDD_HHMMSS[-N].partial/ and publishes it
 * with an atomic no-replace rename to the same name without the suffix, so an
 * interrupted backup can never look complete (docs/DECISIONS.md D15). Every
 * captured object lives below the container's data/, addressed by its manifest
 * root id; manifest.txt and packages.txt are migr-owned control artifacts at
 * the container root.
 *
 * BACKUP_CRITICAL copies Documents, Downloads, Pictures, dotfiles, browser
 * profiles, and the package list. BACKUP_COMPREHENSIVE adds Desktop, Videos,
 * Music, and Projects. BACKUP_EXPLICIT_PATHS copies only the caller-supplied
 * paths and exports no package list. Every mode writes a versioned manifest.txt:
 * it carries the format version, representation and root table, so a container
 * without one is not a backup migr can restore.
 *
 * When an earlier run of the same job (docs/DECISIONS.md D15: representation,
 * scope, root table, machine id and uid) left exactly one unfinished container
 * behind, this resumes into it instead of starting a second one.
 *
 * @param target Destination directory; the dated backup subdirectory is created inside it.
 * @param mode   Selects which files are included (BACKUP_CRITICAL, BACKUP_COMPREHENSIVE, or BACKUP_EXPLICIT_PATHS).
 * @param paths  NULL-terminated array of paths (absolute, or relative to the
 *               current working directory); required when mode is
 *               BACKUP_EXPLICIT_PATHS, ignored otherwise.
 * @return 0 on success, 1 on error.
 */
int backup(const char *target, BackupMode mode, char **paths);

#ifdef BACKUP_TEST_HOOKS
typedef void (*BackupTestInventoryHook)(const char *source_path,
                                        void *context);

void backup_test_set_inventory_hook(BackupTestInventoryHook hook,
                                    void *context);

typedef void (*BackupTestFreeSpaceHook)(off_t needed, off_t *free_bytes,
                                        void *context);

void backup_test_set_free_space_hook(BackupTestFreeSpaceHook hook,
                                     void *context);

typedef void (*BackupTestBlockSizeHook)(off_t *block_size, void *context);

void backup_test_set_block_size_hook(BackupTestBlockSizeHook hook,
                                     void *context);

typedef void (*BackupTestProgressHook)(off_t bytes_copied,
                                       off_t estimated_total, void *context);

void backup_test_set_progress_hook(BackupTestProgressHook hook,
                                   void *context);
#endif

#endif
