#ifndef DCONF_RESTORE_H
#define DCONF_RESTORE_H

#include <stddef.h>

typedef enum {
    /* The database's settings were loaded into the running dconf service. */
    DCONF_RESTORE_APPLIED,
    /* No session bus for the target user: nothing runs a dconf service that
     * could overwrite the restored file, so the file is already the result. */
    DCONF_RESTORE_NO_SESSION,
    /* dconf is not installed, so no running session can hold settings. */
    DCONF_RESTORE_UNAVAILABLE,
    /* A session exists but its settings could not be loaded. */
    DCONF_RESTORE_FAILED
} DconfRestoreStatus;

/**
 * @brief Loads a restored dconf database into the target user's session.
 *
 * A running dconf service keeps the user database in memory and writes it
 * back on the next change, so replacing ~/.config/dconf/user underneath it is
 * lost. This reads database_fd (the backup's copy, not the destination file)
 * with `dconf dump /` through a private profile, then applies the result with
 * `dconf load /` over the user's session bus. Under sudo both commands run as
 * the invoking user. Keys absent from the backup keep their current values.
 *
 * @param database_fd  Readable fd of the backed-up database; borrowed.
 * @param applied_keys Receives the number of keys loaded on success; may be
 *                     NULL.
 */
DconfRestoreStatus dconf_restore_apply(int database_fd, size_t *applied_keys);

/* Nonzero when dconf_restore_apply() would load into a running session:
 * the target user has a session bus and dconf is installed. */
int dconf_restore_session_loads(void);

#ifdef DCONF_RESTORE_TEST_HOOKS
/* Replaces "/run/user" as the parent of the per-uid runtime directory. */
void dconf_restore_test_set_runtime_root(const char *path);
/* Replaces the dump size limit so the oversized path can be exercised. */
void dconf_restore_test_set_dump_limit(size_t bytes);
#endif

#endif
