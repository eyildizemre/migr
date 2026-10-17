#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "container.h"
#include "move.h"
#include "move_internal.h"
#include "portable.h"
#include "portable_fsops_internal.h"
#include "portable_reconcile_internal.h"
#include "sidecar.h"

/* Folder moves in a portable backup (docs/DECISIONS.md D108). Planning reads
 * the journal; applying rekeys a folder's records to the new place and
 * renames its payload, in D25's order: DELETE of the old keys and a CLAIM
 * of each new one, synced, then the rename, then each ENTRY group. */

static SidecarBytes text_bytes(const char *text)
{
    return (SidecarBytes){ (const unsigned char *)text, strlen(text) };
}

static int bytes_are(SidecarBytes bytes, const char *text)
{
    size_t length = strlen(text);
    return bytes.length == length &&
           (length == 0 || memcmp(bytes.data, text, length) == 0);
}

// Whether logical, of length length, is path or lies below it; "" holds all.
static int bytes_within(SidecarBytes logical, const char *path)
{
    size_t length = strlen(path);
    if (length == 0)
        return 1;
    return logical.length >= length &&
           memcmp(logical.data, path, length) == 0 &&
           (logical.length == length || logical.data[length] == '/');
}

static int root_index_of(const PortableCaptureRequest *request,
                         SidecarBytes id, size_t *out)
{
    for (size_t i = 0; i < request->root_count; i++)
        if (bytes_are(id, request->roots[i].id))
        {
            *out = i;
            return 1;
        }
    return 0;
}

static MoveKind kind_of_record(SidecarObjectKind kind)
{
    switch (kind)
    {
    case SIDECAR_KIND_DIRECTORY:
        return MOVE_KIND_DIRECTORY;
    case SIDECAR_KIND_REGULAR:
    case SIDECAR_KIND_HARDLINK:
        return MOVE_KIND_REGULAR;
    case SIDECAR_KIND_SYMLINK:
        return MOVE_KIND_SYMLINK;
    default:
        return MOVE_KIND_OTHER;
    }
}

/* ------------------------------------------------------------------------- */
/* Planning                                                                  */
/* ------------------------------------------------------------------------- */

typedef struct {
    const PortableCaptureRequest *request;
    const PortableCurrentSourceSet *source;
    const struct RecopyList *recopy;
    MoveCandidates gone;
    int failed;
} PortableScan;

static int key_present(const PortableCurrentSourceSet *source,
                       const char *root_id, const char *logical)
{
    return portable_current_source_contains(source, root_id, logical) == 1;
}

// A recorded folder, not a root, whose source is gone while its parent's
// is there: the top of something that left the source.
static int collect_gone(const SidecarLiveView *view, void *context)
{
    PortableScan *scan = context;
    const SidecarEntry *entry = view->entry;
    size_t root;
    if (entry->kind != SIDECAR_KIND_DIRECTORY ||
        entry->logical_path.length == 0 ||
        !root_index_of(scan->request, entry->root_id, &root))
        return 0;
    const char *root_id = scan->request->roots[root].id;
    char *logical = NULL;
    if (sidecar_bytes_to_text(entry->logical_path, &logical) != 0)
    {
        scan->failed = 1;
        return 1;
    }
    char *slash = strrchr(logical, '/');
    int gone = !key_present(scan->source, root_id, logical) &&
               !recopy_list_covers(scan->recopy, root_id, logical);
    if (gone)
    {
        if (slash != NULL)
            *slash = '\0';
        gone = key_present(scan->source, root_id, slash != NULL ? logical : "");
        if (slash != NULL)
            *slash = '/';
    }
    if (gone && move_candidates_add(&scan->gone, root, logical) != 0)
        scan->failed = 1;
    free(logical);
    return scan->failed;
}

static int candidate_path_compare(const void *left, const void *right)
{
    const MoveCandidate *a = left, *b = right;
    if (a->root != b->root)
        return a->root < b->root ? -1 : 1;
    return strcmp(a->path, b->path);
}

static MoveCandidate *find_candidate(MoveCandidates *list, size_t root,
                                     const char *path)
{
    MoveCandidate key = { .root = root, .path = (char *)path };
    return bsearch(&key, list->items, list->count, sizeof(*list->items),
                   candidate_path_compare);
}

// The candidate whose folder holds logical, itself included, or NULL.
static MoveCandidate *holding_candidate(PortableScan *scan, size_t root,
                                        SidecarBytes logical)
{
    char path[SIDECAR_MAX_PATH + 1U];
    if (logical.length == 0 || logical.length > SIDECAR_MAX_PATH)
        return NULL;
    memcpy(path, logical.data, logical.length);
    path[logical.length] = '\0';
    for (;;)
    {
        MoveCandidate *candidate = find_candidate(&scan->gone, root, path);
        if (candidate != NULL)
            return candidate;
        char *slash = strrchr(path, '/');
        if (slash == NULL)
            return NULL;
        *slash = '\0';
    }
}

// Gives each candidate its children and the bytes below it, and takes out
// of the running a folder a hardlink record ties to anything outside it.
static int collect_children(const SidecarLiveView *view, void *context)
{
    PortableScan *scan = context;
    const SidecarEntry *entry = view->entry;
    size_t root;
    if (!root_index_of(scan->request, entry->root_id, &root))
        return 0;
    MoveCandidate *holder = holding_candidate(scan, root, entry->logical_path);
    if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        size_t target_root;
        MoveCandidate *target =
            root_index_of(scan->request, entry->hardlink_root_id,
                          &target_root)
                ? holding_candidate(scan, target_root,
                                    entry->hardlink_logical_path)
                : NULL;
        if (target != holder)
        {
            if (target != NULL)
                target->used = 1;
            if (holder != NULL)
                holder->used = 1;
        }
    }
    if (holder == NULL)
        return 0;
    if (entry->kind == SIDECAR_KIND_REGULAR)
        holder->bytes += (off_t)entry->size;

    size_t holder_length = strlen(holder->path);
    SidecarBytes logical = entry->logical_path;
    if (logical.length <= holder_length + 1U ||
        memchr(logical.data + holder_length + 1U, '/',
               logical.length - holder_length - 1U) != NULL)
        return 0;
    char name[NAME_MAX + 1];
    size_t name_length = logical.length - holder_length - 1U;
    if (name_length > NAME_MAX)
        return 0;
    memcpy(name, logical.data + holder_length + 1U, name_length);
    name[name_length] = '\0';
    if (move_candidate_add_child(holder, name, kind_of_record(entry->kind),
                                 (off_t)entry->size, entry->mtime_sec,
                                 (long)entry->mtime_nsec) != 0)
    {
        scan->failed = 1;
        return 1;
    }
    return 0;
}

static int under_any(char **paths, const size_t *roots, size_t count,
                     size_t root, const char *path)
{
    for (size_t i = 0; i < count; i++)
        if (roots[i] == root && path_covers(paths[i], path))
            return 1;
    return 0;
}

int portable_moves_plan(SidecarLog *log,
                        const PortableCaptureRequest *request,
                        const PortablePrescanReport *report,
                        const struct RecopyList *recopy, MovePlan *plan)
{
    if (sidecar_log_claim_count(log) != 0)
        return 0;
    PortableScan scan = {
        .request = request,
        .source = &report->current_source,
        .recopy = recopy
    };
    int failed =
        sidecar_log_foreach(log, collect_gone, &scan) != SIDECAR_STATUS_OK ||
        scan.failed;
    if (!failed && scan.gone.count > 1)
        qsort(scan.gone.items, scan.gone.count, sizeof(*scan.gone.items),
              candidate_path_compare);
    if (!failed && scan.gone.count != 0)
        failed = sidecar_log_foreach(log, collect_children, &scan) !=
                     SIDECAR_STATUS_OK ||
                 scan.failed;
    move_candidates_sort(&scan.gone);

    char **matched = NULL;
    size_t *matched_roots = NULL;
    size_t matched_count = 0;
    const PortableCurrentSourceSet *source = scan.source;
    for (size_t i = 0; !failed && scan.gone.count != 0 && i < source->count;
         i++)
    {
        const PortableCurrentSourceEntry *current = &source->entries[i];
        size_t root;
        if (current->logical_path[0] == '\0' ||
            !root_index_of(request, text_bytes(current->root_id), &root))
            continue;
        const char *slash = strrchr(current->logical_path, '/');
        const char *leaf = slash != NULL ? slash + 1 : current->logical_path;
        SidecarLiveView live;
        if (!move_candidates_have_leaf(&scan.gone, root, leaf) ||
            under_any(matched, matched_roots, matched_count, root,
                      current->logical_path) ||
            sidecar_log_find(log, text_bytes(current->root_id),
                             text_bytes(current->logical_path), &live) != 0)
            continue;
        const PortableRootSpec *spec = &request->roots[root];
        char path[PATH_MAX];
        if (path_join(path, sizeof(path), spec->capture_path,
                      current->logical_path) != 0)
            continue;
        int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                                O_CLOEXEC);
        if (fd < 0)
            continue;
        MoveCandidate *candidate = move_pick(&scan.gone, root, leaf, fd, 1);
        close(fd);
        if (candidate == NULL)
            continue;
        MoveItem *item = move_plan_add(plan, spec->id, spec->payload_path,
                                       candidate->path, spec->id,
                                       spec->payload_path,
                                       current->logical_path);
        char **grown_paths = item != NULL
            ? realloc(matched, (matched_count + 1U) * sizeof(*matched))
            : NULL;
        if (grown_paths != NULL)
            matched = grown_paths;
        size_t *grown_roots = grown_paths != NULL
            ? realloc(matched_roots,
                      (matched_count + 1U) * sizeof(*matched_roots))
            : NULL;
        if (grown_roots != NULL)
            matched_roots = grown_roots;
        if (grown_roots == NULL)
        {
            failed = 1;
            break;
        }
        matched[matched_count] = current->logical_path;
        matched_roots[matched_count++] = root;
        item->from_shown = move_shown_path(spec->capture_path,
                                           candidate->path);
        item->to_shown = move_shown_path(spec->capture_path,
                                         current->logical_path);
        item->bytes = candidate->bytes;
        candidate->used = 1;
        if (item->from_shown == NULL || item->to_shown == NULL)
            failed = 1;
    }
    free(matched);
    free(matched_roots);
    move_candidates_free(&scan.gone);
    if (failed && errno == 0)
        errno = ENOMEM;
    return failed ? -1 : 0;
}

/* ------------------------------------------------------------------------- */
/* Applying                                                                  */
/* ------------------------------------------------------------------------- */

typedef struct {
    SidecarEntry entry;
    SidecarXattr *xattrs;
    size_t depth;
} OwnedRecord;

typedef struct {
    const MoveItem *item;
    OwnedRecord *records;
    size_t count;
    size_t capacity;
    int crosses; /* A hardlink record ties the folder to something outside. */
    int occupied; /* The new place has records of its own. */
    int failed;
} Subtree;

static size_t depth_of(SidecarBytes logical)
{
    if (logical.length == 0)
        return 0;
    size_t depth = 1;
    for (size_t i = 0; i < logical.length; i++)
        depth += logical.data[i] == '/';
    return depth;
}

static int collect_subtree(const SidecarLiveView *view, void *context)
{
    Subtree *subtree = context;
    const SidecarEntry *entry = view->entry;
    const MoveItem *item = subtree->item;
    int inside = bytes_are(entry->root_id, item->from_id) &&
                 bytes_within(entry->logical_path, item->from_path);
    if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        int target_inside =
            bytes_are(entry->hardlink_root_id, item->from_id) &&
            bytes_within(entry->hardlink_logical_path, item->from_path);
        if (inside != target_inside)
            subtree->crosses = 1;
    }
    if (!inside && bytes_are(entry->root_id, item->to_id) &&
        bytes_within(entry->logical_path, item->to_path))
        subtree->occupied = 1;
    if (!inside)
        return 0;
    if (subtree->count == subtree->capacity)
    {
        size_t capacity = subtree->capacity == 0 ? 64U
                                                 : subtree->capacity * 2U;
        OwnedRecord *records = realloc(subtree->records,
                                       capacity * sizeof(*records));
        if (records == NULL)
        {
            subtree->failed = 1;
            return 1;
        }
        subtree->records = records;
        subtree->capacity = capacity;
    }
    OwnedRecord *record = &subtree->records[subtree->count];
    if (sidecar_entry_dup(entry, &record->entry) != 0)
    {
        subtree->failed = 1;
        return 1;
    }
    record->xattrs = sidecar_xattrs_dup(view->xattrs, view->xattr_count);
    if (record->xattrs == NULL)
    {
        sidecar_entry_dup_free(&record->entry);
        subtree->failed = 1;
        return 1;
    }
    record->depth = depth_of(entry->logical_path);
    subtree->count++;
    return 0;
}

static void subtree_free(Subtree *subtree)
{
    for (size_t i = 0; i < subtree->count; i++)
    {
        sidecar_entry_dup_free(&subtree->records[i].entry);
        sidecar_xattrs_dup_free(subtree->records[i].xattrs,
                                subtree->records[i].entry.xattr_count);
    }
    free(subtree->records);
}

static int record_depth_compare(const void *left, const void *right)
{
    const OwnedRecord *a = left, *b = right;
    if (a->depth != b->depth)
        return a->depth < b->depth ? -1 : 1;
    size_t length = a->entry.logical_path.length < b->entry.logical_path.length
        ? a->entry.logical_path.length : b->entry.logical_path.length;
    int order = length != 0 ? memcmp(a->entry.logical_path.data,
                                     b->entry.logical_path.data, length)
                            : 0;
    if (order != 0)
        return order;
    return a->entry.logical_path.length < b->entry.logical_path.length ? -1
         : a->entry.logical_path.length > b->entry.logical_path.length;
}

// The key a record of the folder takes at its new place: from_path's part
// of it replaced by to_path.
static char *moved_logical(const MoveItem *item, SidecarBytes logical)
{
    size_t from = strlen(item->from_path);
    const char *tail = (const char *)logical.data + from;
    size_t tail_length = logical.length - from;
    if (from != 0 && tail_length != 0)
    {
        tail++;
        tail_length--;
    }
    int separator = item->to_path[0] != '\0' && tail_length != 0;
    char *joined = NULL;
    if (asprintf(&joined, "%s%s%.*s", item->to_path, separator ? "/" : "",
                 (int)tail_length, tail) < 0)
        return NULL;
    return joined;
}

static int journal_sync(int container_fd)
{
    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int result = fd >= 0 && fsync(fd) == 0 ? 0 : -1;
    if (fd >= 0)
        close(fd);
    return result;
}

// Whether the journal holds key for something that stays: a live record
// outside the folder being moved, or a claim. *leaf is then its physical
// leaf. 1 held, 0 free, -1 on a failure.
static int key_held(SidecarLog *log, const MoveItem *item, const char *id,
                    const char *path,
                    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U])
{
    SidecarLiveView live;
    SidecarClaimView claim;
    SidecarBytes found = {0};
    int live_found = sidecar_log_find(log, text_bytes(id), text_bytes(path),
                                      &live);
    if (live_found < 0)
        return -1;
    if (live_found == 1 &&
        !(strcmp(id, item->from_id) == 0 &&
          bytes_within(text_bytes(path), item->from_path)))
    {
        if (live.entry->kind != SIDECAR_KIND_DIRECTORY)
            return -1;
        found = live.entry->physical_leaf;
    }
    else
    {
        int claim_found = sidecar_log_find_claim(log, text_bytes(id),
                                                 text_bytes(path), &claim);
        if (claim_found <= 0)
            return claim_found;
        if (claim.claim->kind != SIDECAR_KIND_DIRECTORY)
            return -1;
        found = claim.claim->physical_leaf;
    }
    if (found.length > SIDECAR_MAX_PHYSICAL_LEAF)
        return -1;
    if (found.length != 0)
        memcpy(leaf, found.data, found.length);
    leaf[found.length] = '\0';
    return 1;
}

// Opens, below current, the folder key names when the journal holds it, or
// with probe checks that it is missing from the payload, or else claims and
// creates it (D25). 1 with *next open, 2 for a probe that found it missing,
// 0 when the move is left to the capture, -1 on a failure.
static int open_new_folder(SidecarLog *log, const MoveItem *item,
                           int current, const char *key, const char *name,
                           int probe, int *next)
{
    char held_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    int held = key_held(log, item, item->to_id, key, held_leaf);
    struct stat st;
    if (held < 0)
        return -1;
    if (held == 1)
    {
        if (key[0] != '\0' && strcmp(held_leaf, name) != 0)
            return 0;
        *next = open_child_directory(current, name);
        return *next >= 0 ? 1 : 0;
    }
    if (fstatat(current, name, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        return 0;
    if (probe)
        return 2;
    SidecarClaim claim = {
        .root_id = text_bytes(item->to_id),
        .logical_path = text_bytes(key),
        .physical_leaf = text_bytes(key[0] != '\0' ? name : ""),
        .kind = SIDECAR_KIND_DIRECTORY
    };
    if (sidecar_log_append_claim(log, &claim) != SIDECAR_STATUS_OK ||
        mkdirat(current, name, 0700) != 0)
        return -1;
    *next = open_child_directory(current, name);
    return *next >= 0 ? 1 : -1;
}

// Opens the folder that is to hold the new place of item, and names the new
// place's leaf: the root's own folder, then each one down to the parent,
// named as the pre-scan names them. With probe nothing is changed: a folder
// that would be created ends the check. 1 with *out open (-1 after such a
// probe), 0 when the move is left to the capture, -1 on a failure.
static int open_new_parent(SidecarLog *log, const PortablePrescanReport *report,
                           int data_fd, const MoveItem *item, int probe,
                           int *out, char new_leaf[NAME_MAX + 1])
{
    *out = -1;
    int current = -1;
    char leaf[NAME_MAX + 1];
    int opened = probe
        ? open_existing_payload_parent(data_fd, item->to_payload, &current,
                                       leaf, sizeof(leaf))
        : portable_open_relative_parent(data_fd, item->to_payload, &current,
                                        leaf, sizeof(leaf));
    if (opened != 0)
        return probe && errno == ENOENT ? 1 : 0;
    if (item->to_path[0] == '\0')
    {
        strcpy(new_leaf, leaf);
        *out = current;
        return 1;
    }

    char key[SIDECAR_MAX_PATH + 1U];
    char suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    size_t length = strlen(item->to_path);
    if (length > SIDECAR_MAX_PATH ||
        portable_assignment_for(&report->collision_plan,
                                &report->current_source, item->to_id,
                                item->to_path, new_leaf, suffix) != 0)
    {
        close(current);
        return 0;
    }
    int next = -1;
    int result = open_new_folder(log, item, current, "", leaf, probe, &next);
    close(current);
    current = next;
    for (size_t at = 0; result == 1 && at < length; at++)
    {
        if (item->to_path[at] != '/')
            continue;
        memcpy(key, item->to_path, at);
        key[at] = '\0';
        char name[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
        if (portable_assignment_for(&report->collision_plan,
                                    &report->current_source, item->to_id,
                                    key, name, suffix) != 0)
            result = 0;
        else
        {
            next = -1;
            result = open_new_folder(log, item, current, key, name, probe,
                                     &next);
        }
        close(current);
        current = next;
    }
    if (result == 2)
        return 1;
    if (result != 1)
    {
        if (current >= 0)
            close(current);
        return result;
    }
    *out = current;
    return 1;
}

// Opens the folder holding the folder's recorded payload, by the physical
// leaves its ancestors' records give; 1 with *out open and its leaf in leaf.
static int open_old_parent(SidecarLog *log, int data_fd, const MoveItem *item,
                           const OwnedRecord *top, int *out,
                           char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U])
{
    if (item->from_path[0] == '\0')
        return open_existing_payload_parent(data_fd, item->from_payload, out,
                                            leaf, NAME_MAX + 1) == 0
            ? 1 : 0;
    int current = -1;
    char root_leaf[NAME_MAX + 1];
    int parent = -1;
    if (open_existing_payload_parent(data_fd, item->from_payload, &parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return 0;
    current = open_child_directory(parent, root_leaf);
    close(parent);
    if (current < 0)
        return 0;
    char prefix[SIDECAR_MAX_PATH + 1U];
    strcpy(prefix, item->from_path);
    char *cursor = prefix;
    for (char *slash; (slash = strchr(cursor, '/')) != NULL; cursor = slash + 1)
    {
        *slash = '\0';
        SidecarLiveView live;
        int found = sidecar_log_find(log, text_bytes(item->from_id),
                                     text_bytes(prefix), &live);
        char ancestor[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
        int next = -1;
        if (found == 1 && live.entry->physical_leaf.length != 0 &&
            live.entry->physical_leaf.length <= SIDECAR_MAX_PHYSICAL_LEAF)
        {
            memcpy(ancestor, live.entry->physical_leaf.data,
                   live.entry->physical_leaf.length);
            ancestor[live.entry->physical_leaf.length] = '\0';
            next = open_child_directory(current, ancestor);
        }
        close(current);
        if (next < 0)
            return found < 0 ? -1 : 0;
        current = next;
        *slash = '/';
    }
    size_t length = top->entry.physical_leaf.length;
    memcpy(leaf, top->entry.physical_leaf.data, length);
    leaf[length] = '\0';
    *out = current;
    return 1;
}

static int sync_directory(int fd)
{
    return fsync(fd) == 0 || errno == EINVAL || errno == EROFS ? 0 : -1;
}

// Moves one folder. 1 moved, 0 left to the capture, -1 on a failure that
// leaves the journal to the next run.
static int move_one(SidecarLog *log, int container_fd, int data_fd,
                    const PortablePrescanReport *report, MoveItem *item)
{
    Subtree subtree = { .item = item };
    if (sidecar_log_foreach(log, collect_subtree, &subtree) !=
            SIDECAR_STATUS_OK ||
        subtree.failed)
    {
        subtree_free(&subtree);
        errno = ENOMEM;
        return -1;
    }
    SidecarClaimView claim;
    if (subtree.count == 0 || subtree.crosses || subtree.occupied ||
        sidecar_log_find_claim(log, text_bytes(item->to_id),
                               text_bytes(item->to_path), &claim) != 0)
    {
        subtree_free(&subtree);
        return 0;
    }
    qsort(subtree.records, subtree.count, sizeof(*subtree.records),
          record_depth_compare);
    const OwnedRecord *top = &subtree.records[0];
    if (!bytes_are(top->entry.logical_path, item->from_path))
    {
        subtree_free(&subtree);
        return 0;
    }

    char top_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U] = "";
    char top_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U] = "";
    if (item->to_path[0] != '\0' &&
        portable_assignment_for(&report->collision_plan,
                                &report->current_source, item->to_id,
                                item->to_path, top_leaf, top_suffix) != 0)
    {
        subtree_free(&subtree);
        return 0;
    }

    // Nothing is written until both places check out: the old one holds
    // the folder, and the new one is free below folders the journal holds
    // or the payload lacks.
    int same_place = strcmp(item->from_payload, item->to_payload) == 0 &&
                     item->from_path[0] == '\0' && item->to_path[0] == '\0';
    int old_parent = -1, new_parent = -1;
    char old_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U] = "";
    char new_leaf[NAME_MAX + 1] = "";
    int result = 1;
    if (!same_place)
    {
        struct stat st;
        result = open_old_parent(log, data_fd, item, top, &old_parent,
                                 old_leaf);
        if (result == 1 &&
            fstatat(old_parent, old_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
            result = 0;
        if (result == 1)
            result = open_new_parent(log, report, data_fd, item, 1,
                                     &new_parent, new_leaf);
        if (result == 1 && new_parent >= 0 &&
            (fstatat(new_parent, new_leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
             errno != ENOENT))
            result = 0;
        if (new_parent >= 0)
            close(new_parent);
        new_parent = -1;
    }

    for (size_t i = subtree.count; result == 1 && i-- > 0;)
    {
        SidecarDelete deletion = {
            .root_id = subtree.records[i].entry.root_id,
            .logical_path = subtree.records[i].entry.logical_path
        };
        if (sidecar_log_append_delete(log, &deletion) != SIDECAR_STATUS_OK)
            result = -1;
    }
    // The old keys are gone, so a root's own record the folder held no
    // longer stands in the way of the new place's folders.
    if (result == 1 && !same_place &&
        open_new_parent(log, report, data_fd, item, 0, &new_parent,
                        new_leaf) != 1)
        result = -1;
    char **keys = result == 1 ? calloc(subtree.count, sizeof(*keys)) : NULL;
    if (result == 1 && keys == NULL)
        result = -1;
    for (size_t i = 0; result == 1 && i < subtree.count; i++)
    {
        const SidecarEntry *entry = &subtree.records[i].entry;
        keys[i] = moved_logical(item, entry->logical_path);
        SidecarClaim claim = {
            .root_id = text_bytes(item->to_id),
            .logical_path = keys[i] != NULL ? text_bytes(keys[i])
                                            : text_bytes(""),
            .physical_leaf = i == 0 ? text_bytes(top_leaf)
                                    : entry->physical_leaf,
            .kind = entry->kind
        };
        if (keys[i] == NULL ||
            sidecar_log_append_claim(log, &claim) != SIDECAR_STATUS_OK)
            result = -1;
    }
    if (result == 1 && journal_sync(container_fd) != 0)
        result = -1;
    if (result == 1)
        portable_test_interrupt_if(PORTABLE_TEST_MOVE_AFTER_CLAIMS);
    if (result == 1 && !same_place &&
        (renameat2(old_parent, old_leaf, new_parent, new_leaf,
                   RENAME_NOREPLACE) != 0 ||
         sync_directory(old_parent) != 0 || sync_directory(new_parent) != 0))
        result = -1;
    if (result == 1)
        portable_test_interrupt_if(PORTABLE_TEST_MOVE_AFTER_RENAME);
    for (size_t i = 0; result == 1 && i < subtree.count; i++)
    {
        SidecarEntry entry = subtree.records[i].entry;
        entry.root_id = text_bytes(item->to_id);
        entry.logical_path = text_bytes(keys[i]);
        if (i == 0)
        {
            entry.physical_leaf = text_bytes(top_leaf);
            entry.collision_suffix = text_bytes(top_suffix);
        }
        char *target = NULL;
        if (entry.kind == SIDECAR_KIND_HARDLINK)
        {
            target = moved_logical(item, entry.hardlink_logical_path);
            if (target == NULL)
            {
                result = -1;
                break;
            }
            entry.hardlink_root_id = text_bytes(item->to_id);
            entry.hardlink_logical_path = text_bytes(target);
        }
        if (sidecar_log_append_group(
                log, &entry,
                entry.xattr_count != 0 ? subtree.records[i].xattrs : NULL) !=
            SIDECAR_STATUS_OK)
            result = -1;
        free(target);
    }

    int saved = errno;
    for (size_t i = 0; keys != NULL && i < subtree.count; i++)
        free(keys[i]);
    free(keys);
    if (old_parent >= 0)
        close(old_parent);
    if (new_parent >= 0)
        close(new_parent);
    subtree_free(&subtree);
    errno = saved;
    return result;
}

int portable_moves_apply(SidecarLog *log, int container_fd, int data_fd,
                         const PortablePrescanReport *report,
                         MovePlan *plan)
{
    if (sidecar_log_claim_count(log) != 0)
        return 0;
    for (size_t i = 0; i < plan->count; i++)
    {
        int result = move_one(log, container_fd, data_fd, report,
                              &plan->items[i]);
        if (result < 0)
            return -1;
        plan->items[i].moved = result == 1;
    }
    return 0;
}
