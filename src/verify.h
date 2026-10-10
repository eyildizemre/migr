#ifndef VERIFY_H
#define VERIFY_H

#include "manifest.h"

/**
 * @brief Opens a finished portable container for reading its journal.
 *
 * Refuses, with a printed reason, a partial container, a missing or unreadable
 * manifest, a native backup, which has no journal, and a journal version this
 * build does not read.
 * On success the caller owns *manifest (manifest_free) and *container_fd_out.
 */
int portable_container_open(const char *path, Manifest *manifest,
                            int *container_fd_out);

/**
 * @brief Checks a finished backup before its source system is replaced.
 *
 * A portable backup is checked against its own capture record: every live
 * journal entry must have its payload node in the container, and every
 * regular file must still have the size and content digest recorded when it
 * was captured (docs/DECISIONS.md D59). A native backup records no content,
 * so each of its files and symlinks is compared with its source; a source
 * changed since the backup is counted as not checked (D106). Reads only;
 * nothing in the backup is changed.
 *
 * @return MIGR_EXIT_OK when everything checked matches, MIGR_EXIT_CHANGED on a
 *         mismatch, and MIGR_EXIT_FAILURE when the backup cannot be checked,
 *         including a native backup none of whose files has its source here
 *         (D68).
 */
int verify_backup(const char *path);

#endif
