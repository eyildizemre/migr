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

#endif
