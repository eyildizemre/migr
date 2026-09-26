#ifndef VERIFY_H
#define VERIFY_H

#include "manifest.h"

/**
 * @brief Opens a finished portable container for reading its journal.
 *
 * Refuses, with a printed reason, a partial container, a missing or unreadable
 * manifest, a native backup, and a journal version this build does not read.
 * On success the caller owns *manifest (manifest_free) and *container_fd_out.
 */
int portable_container_open(const char *path, Manifest *manifest,
                            int *container_fd_out);

/**
 * @brief Checks a finished portable backup against its own capture record.
 *
 * Every live journal entry must have its payload node in the container, and
 * every regular file must still have the size and content digest recorded
 * when it was captured (docs/DECISIONS.md D59). Reads only; nothing in the
 * backup is changed.
 *
 * @return MIGR_EXIT_OK when everything matches, MIGR_EXIT_CHANGED on a
 *         mismatch, and MIGR_EXIT_FAILURE when the backup cannot be checked
 *         (D68).
 */
int verify_backup(const char *path);

#endif
