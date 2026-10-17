#ifndef MOVE_H
#define MOVE_H

#include <stddef.h>
#include <sys/types.h>

#include "manifest.h"
#include "portable.h"
#include "sidecar.h"

struct SelectionRoot;
struct RecopyList;

/*
 * Folders an update moves inside the backup instead of copying them again
 * and removing their old copies (docs/DECISIONS.md D108). A root is named by
 * its id and payload path, a place in it by its logical path, "" for the
 * root itself.
 */
typedef struct {
    char *from_id;
    char *from_payload;
    char *from_path;
    char *to_id;
    char *to_payload;
    char *to_path;
    char *from_shown; /* As its user names it. */
    char *to_shown;
    off_t bytes;
    int moved; /* Set once the move is done. */
} MoveItem;

typedef struct {
    MoveItem *items;
    size_t count;
    size_t capacity;
} MovePlan;

void move_plan_free(MovePlan *plan);

/* Moves the items of more to the end of plan, leaving more empty. 0, or -1
 * with both unchanged. */
int move_plan_append(MovePlan *plan, MovePlan *more);

/* Prints the number and size of the folders moved, or of those a dry run
 * would move, and with --verbose each of them. Prints nothing for none. */
void move_plan_print(const MovePlan *plan, int dry_run);

/* True when an item of the plan moves the whole of previous's root id. */
int move_plan_moves_root(const MovePlan *plan, const char *id);

/*
 * Plans moving the payload of previous's dropped roots (those no root of
 * current equals) that current still selects: a root at the same source
 * path, a root inside one, or one inside a root. A root with files verify
 * found damaged, keyed by recopy_key (its payload path for native, its id
 * for portable), is copied again instead. 0, or -1 with errno.
 */
int move_plan_roots(const Manifest *previous, const unsigned char *dropped,
                    const Manifest *current, const struct RecopyList *recopy,
                    int portable, MovePlan *plan);

typedef struct {
    const char *capture_path;
    const char *payload_path;
    const struct SelectionRoot *selection; /* Optional. */
} NativeMoveRoot;

/*
 * Plans the folders moved inside each native root: a folder of the payload
 * whose source is gone, and a new source folder of the same name whose
 * children are mostly the folder's own (name, kind, size, and modification
 * time). Payload folders are opened with O_NOATIME, so the times the backup
 * records stay as they are. 0, or -1 with errno.
 */
int native_moves_plan(int data_fd, const NativeMoveRoot *roots, size_t count,
                      int nsec_exact, const struct RecopyList *recopy,
                      MovePlan *plan);

/* Renames each planned folder in data_fd to its new place, creating the
 * folders above it. One whose place is taken is left to the capture. 0, or
 * -1 with errno. */
int native_moves_apply(int data_fd, MovePlan *plan);

/*
 * The portable counterparts. Planning reads the journal and the source
 * set the pre-scan built; a journal with unfinished items plans nothing.
 * Applying records each move in the journal before and after renaming its
 * payload (D25), so an interruption leaves the folder to be copied again.
 */
int portable_moves_plan(SidecarLog *log,
                        const PortableCaptureRequest *request,
                        const PortablePrescanReport *report,
                        const struct RecopyList *recopy, MovePlan *plan);

int portable_moves_apply(SidecarLog *log, int container_fd, int data_fd,
                         const PortablePrescanReport *report,
                         MovePlan *plan);

#endif
