#ifndef REPAIR_H
#define REPAIR_H

/**
 * @brief Rebuilds a damaged portable backup as a new container under dest_root.
 *
 * The original container is only read. Its journal is replayed record by
 * record through the state layer's own validation; a damaged region is skipped
 * up to the next record start, groups the state layer rejects are dropped, a
 * directory whose capture began but never committed is re-created with its
 * nearest recorded ancestor's metadata, and any other unfinished item is left
 * out. Every lost or re-created path is reported. The payload and the other
 * top-level files are then copied next to the rebuilt journal, and the copy is
 * published under a new finished container name (docs/DECISIONS.md D61).
 *
 * @return 0 when the repaired copy was published or nothing needed repair,
 *         1 on any error.
 */
int repair_backup(const char *source, const char *dest_root);

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
