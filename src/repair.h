#ifndef REPAIR_H
#define REPAIR_H

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

#ifdef REPAIR_TEST_HOOKS
#include <stddef.h>

#include "sidecar.h"

/* Replays journal bytes into log the way repair_backup() does, without a
 * manifest or payload, so open claims stay as they are. Returns 0 when the
 * journal was replayed and -1 when it was refused; the counts say how many
 * damaged regions were skipped and records rejected. */
int repair_test_salvage(SidecarLog *log, const unsigned char *data,
                        size_t length, size_t *damaged_regions,
                        size_t *rejected);
#endif

#endif
