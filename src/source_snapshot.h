#ifndef SOURCE_SNAPSHOT_H
#define SOURCE_SNAPSHOT_H

#include <limits.h>
#include <stddef.h>

#define SOURCE_SNAPSHOT_MAX 8U
#define SOURCE_SNAPSHOT_PREFIX ".migr-snapshot-"

typedef struct {
    /* Where the subvolume's root is visible, e.g. "/home". */
    char subvolume_path[PATH_MAX];
    /* The live subvolume root, opened before anything is mounted over it. */
    int subvolume_fd;
    /* SOURCE_SNAPSHOT_PREFIX<pid>, directly inside the subvolume root. */
    char name[64];
} SourceSnapshotEntry;

/**
 * @brief Read-only btrfs snapshots a backup reads its sources from
 *        (docs/DECISIONS.md D64).
 *
 * source_snapshot_begin() snapshots every btrfs subvolume that holds one of
 * the given source paths and, in a mount namespace private to the calling
 * thread, mounts each snapshot over its subvolume's own path. Every absolute
 * source path then reads one point in time, with no path rewritten anywhere.
 * Nested subvolumes and mounts below a snapshotted path are mounted back
 * from the live tree, so nothing reads as empty. source_snapshot_end()
 * returns to the original namespace and deletes the snapshots.
 *
 * Only root can do this. A subvolume mounted at "/", or one holding the
 * backup destination, is left live. Any failure leaves every source live and
 * is reported through the note, never as an error.
 */
typedef struct {
    size_t count;
    SourceSnapshotEntry entries[SOURCE_SNAPSHOT_MAX];
    int saved_namespace_fd;
    int entered;
} SourceSnapshot;

void source_snapshot_init(SourceSnapshot *snapshot);

/* Returns how many subvolumes are now read from a snapshot. When some could
 * not be, note (if not NULL) says why in one sentence. */
size_t source_snapshot_begin(SourceSnapshot *snapshot,
                             const char *const *source_paths,
                             size_t source_count, const char *destination,
                             char *note, size_t note_size);

/* Idempotent; safe on an initialized snapshot that never began. */
void source_snapshot_end(SourceSnapshot *snapshot);

/* Undoes one /proc/self/mountinfo path field escape (\040 and the like) in
 * place. Exposed for tests. */
void source_snapshot_unescape_mount_path(char *path);

#endif
