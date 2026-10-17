#ifndef MOVE_INTERNAL_H
#define MOVE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "move.h"

/* Shared between move.c and portable_move.c. */

typedef enum {
    MOVE_KIND_OTHER = 0,
    MOVE_KIND_DIRECTORY,
    MOVE_KIND_REGULAR,
    MOVE_KIND_SYMLINK
} MoveKind;

/* A recorded child of a folder whose source is gone. */
typedef struct {
    char *name;
    MoveKind kind;
    off_t size;
    int64_t mtime_sec;
    long mtime_nsec;
} MoveChild;

/* A folder of the backup whose source is gone, which a new source folder
 * of the same name in the same root may take. */
typedef struct {
    size_t root;
    char *path; /* In its root. */
    const char *leaf;
    MoveChild *children;
    size_t child_count;
    size_t child_capacity;
    off_t bytes;
    int used;
} MoveCandidate;

typedef struct {
    MoveCandidate *items;
    size_t count;
    size_t capacity;
} MoveCandidates;

MoveKind move_kind_of_mode(mode_t mode);
int move_candidates_add(MoveCandidates *list, size_t root, const char *path);
int move_candidate_add_child(MoveCandidate *candidate, const char *name,
                             MoveKind kind, off_t size, int64_t mtime_sec,
                             long mtime_nsec);
void move_candidates_free(MoveCandidates *list);
/* Sorts by root, then leaf, for move_pick(). */
void move_candidates_sort(MoveCandidates *list);
/* True when a candidate of root has this leaf. */
int move_candidates_have_leaf(const MoveCandidates *list, size_t root,
                              const char *leaf);

/*
 * The unused candidate of root named leaf that the source folder open at
 * source_fd takes: the one with the most children that match the folder's
 * in name, kind and, for files, size and modification time, when they are
 * at least half of its own and no other candidate matches as many. NULL
 * when none qualifies.
 */
MoveCandidate *move_pick(MoveCandidates *list, size_t root, const char *leaf,
                         int source_fd, int nsec_exact);

/* The bytes of the regular files in the source folder open at fd, which it
 * keeps open, a file with several names counted once over them; files it
 * cannot inspect count nothing. */
off_t move_source_tree_bytes(int fd);

/* Opens a source folder below parent_fd without following a symlink or
 * changing its access time. */
int move_open_source_dir(int parent_fd, const char *name);

/* "~/rest" for a path inside the target home, else the path itself, with
 * path inside it appended; NULL on allocation failure. */
char *move_shown_path(const char *base, const char *path);

MoveItem *move_plan_add(MovePlan *plan, const char *from_id,
                        const char *from_payload, const char *from_path,
                        const char *to_id, const char *to_payload,
                        const char *to_path);

#endif
