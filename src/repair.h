#ifndef REPAIR_H
#define REPAIR_H

#include "manifest.h"
#include "sidecar.h"
#include "utils.h"

/**
 * @brief Rebuilds the journal of a damaged portable backup in place
 *        (docs/DECISIONS.md D111), for the case it is made for: a restore on
 *        a new install that refuses the backup.
 *
 * The journal is replayed record by record through the state layer's own
 * validation into a new one in staging/: a damaged region is skipped up to
 * the next record start, groups the state layer rejects are dropped, and an
 * item whose records were lost is re-created from its payload with the
 * metadata of the recorded folder above it (D61 rule 3); what holds nothing
 * to keep is left out. Every lost or re-created path is reported. The new
 * journal is read back and renamed over the old one, the only step that
 * replaces it.
 *
 * @return 0 when the backup was repaired or needed no repair, 1 on any
 *         error.
 */
int repair_backup(const char *source);

/**
 * @brief Rebuilds the journal of the portable backup in container_fd, whose
 *        lock the caller holds, as repair_backup() does, when it is damaged
 *        (D111). A journal cut off in its last record, written by a newer
 *        migr, or not readable is left to the caller; source names the backup
 *        in what is printed.
 *
 * @return 0 when the journal is usable or was rebuilt, -1 on an error, which
 *         it reports.
 */
int repair_damaged_journal_at(int container_fd, const char *source);

/**
 * @brief Records the payload node leaf in parent_fd, which no record or claim
 *        owns, by repair's rules (D111): under address (root id, logical
 *        path, physical leaf, collision suffix; an empty logical path for a
 *        root's own node), and a folder with everything in it, each item
 *        below under the name its leaf gives. payload_path is the root's,
 *        relative to data_fd.
 *
 * @return 0, or -1 with the step that failed in *failed.
 */
int repair_adopt_payload(SidecarLog *log, int data_fd,
                         const char *payload_path, int parent_fd,
                         const char *leaf, const SidecarEntry *address,
                         FailedStep *failed);

#ifdef REPAIR_TEST_HOOKS
#include <stddef.h>

/* Replays journal bytes into log the way repair_backup() does, without a
 * manifest or payload, so open claims stay as they are. Returns 0 when the
 * journal was replayed and -1 when it was refused; the counts say how many
 * damaged regions were skipped and records rejected. */
int repair_test_salvage(SidecarLog *log, const unsigned char *data,
                        size_t length, size_t *damaged_regions,
                        size_t *rejected);
#endif

#endif
