#ifndef PACKAGES_H
#define PACKAGES_H

/**
 * @brief Exports the same package list into an open container directory.
 *
 * How production writes packages.txt: the container's directory fd is already
 * open and locked, so the file is created with openat() and O_NOFOLLOW rather
 * than through a rebuilt path string a symlink could redirect.
 *
 * Nothing already occupying leaf is ever opened or written into: the name is
 * removed first and the list is written to an inode this call creates with
 * O_EXCL. That is what keeps a FIFO from blocking the backup forever, and a
 * hardlink to a file outside the container from being truncated and
 * overwritten with the package list.
 *
 * A failed export never leaves something usable-looking behind either. leaf is
 * cleared when the list cannot be produced, cannot be created safely, or
 * cannot be written in full -- so a container that goes on to be finalized
 * carries either a complete package list or none at all, never a stale,
 * hostile, or truncated one. The three return values exist because those are
 * three different situations for the caller: a missing package list is
 * tolerable, an unclearable control slot is not.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to create beneath it; a single component.
 * @return 0 when a complete list was written; 1 when no list was written and
 *         the slot was left empty; -1 when the slot could not be made safe, in
 *         which case the container must not be finalized.
 */
int packages_at(int container_fd, const char *leaf);

/**
 * @brief Ensures no object occupies a control-artifact slot in a container.
 *
 * Used where a package list must not be present at all -- an explicit-paths
 * backup exports none, and an adopted container may still hold one a previous
 * run (or someone else) left behind. Restore acts on whatever packages.txt it
 * finds without re-deriving the backup's scope, so leaving a stale one inside a
 * finalized container would let it drive package installs the backup never
 * recorded.
 *
 * A symlink is removed as itself, never followed.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to clear beneath it; a single component.
 * @return 0 when nothing occupies leaf afterwards (including when nothing did),
 *         -1 when something is still there.
 */
int packages_clear_at(int container_fd, const char *leaf);

#endif
