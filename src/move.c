#define _GNU_SOURCE

#include <dirent.h>
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
#include "portable_fsops_internal.h"
#include "selection.h"
#include "utils.h"

/* ------------------------------------------------------------------------- */
/* Plans                                                                     */
/* ------------------------------------------------------------------------- */

static void move_item_free(MoveItem *item)
{
    free(item->from_id);
    free(item->from_payload);
    free(item->from_path);
    free(item->to_id);
    free(item->to_payload);
    free(item->to_path);
    free(item->from_shown);
    free(item->to_shown);
}

void move_plan_free(MovePlan *plan)
{
    for (size_t i = 0; i < plan->count; i++)
        move_item_free(&plan->items[i]);
    free(plan->items);
    memset(plan, 0, sizeof(*plan));
}

MoveItem *move_plan_add(MovePlan *plan, const char *from_id,
                        const char *from_payload, const char *from_path,
                        const char *to_id, const char *to_payload,
                        const char *to_path)
{
    if (plan->count == plan->capacity)
    {
        size_t capacity = plan->capacity == 0 ? 16U : plan->capacity * 2U;
        MoveItem *items = realloc(plan->items, capacity * sizeof(*items));
        if (items == NULL)
            return NULL;
        plan->items = items;
        plan->capacity = capacity;
    }
    MoveItem *item = &plan->items[plan->count];
    memset(item, 0, sizeof(*item));
    item->from_id = strdup(from_id);
    item->from_payload = strdup(from_payload);
    item->from_path = strdup(from_path);
    item->to_id = strdup(to_id);
    item->to_payload = strdup(to_payload);
    item->to_path = strdup(to_path);
    if (item->from_id == NULL || item->from_payload == NULL ||
        item->from_path == NULL || item->to_id == NULL ||
        item->to_payload == NULL || item->to_path == NULL)
    {
        move_item_free(item);
        errno = ENOMEM;
        return NULL;
    }
    plan->count++;
    return item;
}

int move_plan_append(MovePlan *plan, MovePlan *more)
{
    if (plan->count + more->count > plan->capacity)
    {
        size_t capacity = plan->count + more->count;
        MoveItem *items = realloc(plan->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        plan->items = items;
        plan->capacity = capacity;
    }
    if (more->count != 0)
        memcpy(plan->items + plan->count, more->items,
               more->count * sizeof(*more->items));
    plan->count += more->count;
    free(more->items);
    memset(more, 0, sizeof(*more));
    return 0;
}

void move_plan_print(const MovePlan *plan, int dry_run)
{
    size_t folders = 0;
    off_t bytes = 0;
    for (size_t i = 0; i < plan->count; i++)
        if (dry_run || plan->items[i].moved)
        {
            folders++;
            bytes += plan->items[i].bytes;
        }
    if (folders == 0)
        return;
    char size[32];
    format_size(bytes, size, sizeof(size));
    printf("%s inside the backup: %zu folder%s, %s\n",
           dry_run ? "\nWould move" : "Moved", folders,
           folders == 1 ? "" : "s", size);
    if (!verbose)
        return;
    for (size_t i = 0; i < plan->count; i++)
    {
        const MoveItem *item = &plan->items[i];
        if (!dry_run && !item->moved)
            continue;
        if (strcmp(item->from_shown, item->to_shown) == 0)
            printf("  %s\n", item->from_shown);
        else
            printf("  %s -> %s\n", item->from_shown, item->to_shown);
    }
}

int move_plan_moves_root(const MovePlan *plan, const char *id)
{
    for (size_t i = 0; i < plan->count; i++)
        if (plan->items[i].moved && plan->items[i].from_path[0] == '\0' &&
            strcmp(plan->items[i].from_id, id) == 0)
            return 1;
    return 0;
}

char *move_shown_path(const char *base, const char *path)
{
    char home[PATH_MAX];
    int home_known = resolve_target_home(home) == 0;
    char joined[PATH_MAX * 2];
    snprintf(joined, sizeof(joined), "%s%s%s", base,
             path[0] != '\0' ? "/" : "", path);
    char *shown = NULL;
    if (home_known && path_covers(home, joined))
    {
        const char *rest = joined + strlen(home);
        if (asprintf(&shown, "~%s", rest) < 0)
            shown = NULL;
    }
    else
        shown = strdup(joined);
    return shown;
}

/* ------------------------------------------------------------------------- */
/* Roots                                                                     */
/* ------------------------------------------------------------------------- */

static int is_kept(const Manifest *previous, const ManifestRoot *root)
{
    for (int i = 0; i < previous->root_count; i++)
        if (manifest_root_equal(&previous->roots[i], root))
            return 1;
    return 0;
}

// A move whose new place lies in, or holds, the payload of another root the
// update removes would be removed with it.
static int target_is_dropped(const Manifest *previous,
                             const unsigned char *dropped, int source,
                             const char *target)
{
    for (int k = 0; k < previous->root_count; k++)
        if (k != source && dropped[k] &&
            (path_covers(previous->roots[k].payload_path, target) ||
             path_covers(target, previous->roots[k].payload_path)))
            return 1;
    return 0;
}

int move_plan_roots(const Manifest *previous, const unsigned char *dropped,
                    const Manifest *current, const struct RecopyList *recopy,
                    int portable, MovePlan *plan)
{
    for (int i = 0; i < previous->root_count; i++)
    {
        if (!dropped[i])
            continue;
        const ManifestRoot *old_root = &previous->roots[i];
        char old_path[PATH_MAX + 2];
        manifest_root_user_path(previous->source_home, old_root, old_path,
                                sizeof(old_path));
        for (int j = 0; j < current->root_count; j++)
        {
            const ManifestRoot *new_root = &current->roots[j];
            if (is_kept(previous, new_root))
                continue;
            char new_path[PATH_MAX + 2];
            manifest_root_user_path(current->source_home, new_root, new_path,
                                    sizeof(new_path));
            const char *from = NULL, *to = NULL;
            if (strcmp(old_path, new_path) == 0)
                from = to = "";
            else if (path_covers(old_path, new_path))
            {
                from = new_path + strlen(old_path) + 1;
                to = "";
            }
            else if (path_covers(new_path, old_path))
            {
                from = "";
                to = old_path + strlen(new_path) + 1;
            }
            else
                continue;
            if (recopy_list_covers(recopy, portable ? old_root->id
                                                    : old_root->payload_path,
                                   from))
                continue;
            char target[PATH_MAX * 2 + 2];
            snprintf(target, sizeof(target), "%s%s%s",
                     new_root->payload_path, to[0] != '\0' ? "/" : "", to);
            if (target_is_dropped(previous, dropped, i, target))
                continue;

            char source[PATH_MAX];
            int source_known = manifest_root_source_path(current, j,
                                                         source) == 0;
            MoveItem *item = move_plan_add(plan, old_root->id,
                                           old_root->payload_path, from,
                                           new_root->id,
                                           new_root->payload_path, to);
            if (item == NULL)
                return -1;
            item->from_shown = move_shown_path(source_known ? source
                                                            : new_path, to);
            item->to_shown = item->from_shown != NULL
                ? strdup(item->from_shown) : NULL;
            if (item->from_shown == NULL || item->to_shown == NULL)
            {
                errno = ENOMEM;
                return -1;
            }
            int fd = source_known
                ? open(source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_NOATIME | O_CLOEXEC)
                : -1;
            if (fd >= 0)
            {
                int child = to[0] != '\0' ? openat(fd, to, O_RDONLY |
                                                   O_DIRECTORY | O_NOFOLLOW |
                                                   O_NOATIME | O_CLOEXEC)
                                          : dup(fd);
                if (child >= 0)
                {
                    item->bytes = move_source_tree_bytes(child);
                    close(child);
                }
                close(fd);
            }
            else if (source_known)
            {
                struct stat st;
                if (lstat(source, &st) == 0 && S_ISREG(st.st_mode))
                    item->bytes = st.st_size;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Matching                                                                  */
/* ------------------------------------------------------------------------- */

MoveKind move_kind_of_mode(mode_t mode)
{
    if (S_ISDIR(mode))
        return MOVE_KIND_DIRECTORY;
    if (S_ISREG(mode))
        return MOVE_KIND_REGULAR;
    if (S_ISLNK(mode))
        return MOVE_KIND_SYMLINK;
    return MOVE_KIND_OTHER;
}

int move_candidates_add(MoveCandidates *list, size_t root, const char *path)
{
    if (list->count == list->capacity)
    {
        size_t capacity = list->capacity == 0 ? 16U : list->capacity * 2U;
        MoveCandidate *items = realloc(list->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        list->items = items;
        list->capacity = capacity;
    }
    MoveCandidate *candidate = &list->items[list->count];
    memset(candidate, 0, sizeof(*candidate));
    candidate->root = root;
    candidate->path = strdup(path);
    if (candidate->path == NULL)
        return -1;
    const char *slash = strrchr(candidate->path, '/');
    candidate->leaf = slash != NULL ? slash + 1 : candidate->path;
    list->count++;
    return 0;
}

int move_candidate_add_child(MoveCandidate *candidate, const char *name,
                             MoveKind kind, off_t size, int64_t mtime_sec,
                             long mtime_nsec)
{
    if (candidate->child_count == candidate->child_capacity)
    {
        size_t capacity = candidate->child_capacity == 0
            ? 8U : candidate->child_capacity * 2U;
        MoveChild *children = realloc(candidate->children,
                                      capacity * sizeof(*children));
        if (children == NULL)
            return -1;
        candidate->children = children;
        candidate->child_capacity = capacity;
    }
    MoveChild *child = &candidate->children[candidate->child_count];
    child->name = strdup(name);
    if (child->name == NULL)
        return -1;
    child->kind = kind;
    child->size = size;
    child->mtime_sec = mtime_sec;
    child->mtime_nsec = mtime_nsec;
    candidate->child_count++;
    return 0;
}

void move_candidates_free(MoveCandidates *list)
{
    for (size_t i = 0; i < list->count; i++)
    {
        MoveCandidate *candidate = &list->items[i];
        for (size_t j = 0; j < candidate->child_count; j++)
            free(candidate->children[j].name);
        free(candidate->children);
        free(candidate->path);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int candidate_order(size_t left_root, const char *left_leaf,
                           size_t right_root, const char *right_leaf)
{
    if (left_root != right_root)
        return left_root < right_root ? -1 : 1;
    return strcmp(left_leaf, right_leaf);
}

static int candidate_compare(const void *left, const void *right)
{
    const MoveCandidate *a = left, *b = right;
    int order = candidate_order(a->root, a->leaf, b->root, b->leaf);
    return order != 0 ? order : strcmp(a->path, b->path);
}

void move_candidates_sort(MoveCandidates *list)
{
    if (list->count > 1)
        qsort(list->items, list->count, sizeof(*list->items),
              candidate_compare);
}

// The first candidate of root named leaf, or count when there is none.
static size_t candidates_lower_bound(const MoveCandidates *list, size_t root,
                                     const char *leaf)
{
    size_t low = 0, high = list->count;
    while (low < high)
    {
        size_t middle = low + (high - low) / 2U;
        const MoveCandidate *candidate = &list->items[middle];
        if (candidate_order(candidate->root, candidate->leaf, root, leaf) < 0)
            low = middle + 1U;
        else
            high = middle;
    }
    return low;
}

int move_candidates_have_leaf(const MoveCandidates *list, size_t root,
                              const char *leaf)
{
    size_t at = candidates_lower_bound(list, root, leaf);
    return at < list->count && list->items[at].root == root &&
           strcmp(list->items[at].leaf, leaf) == 0;
}

static size_t children_matching(const MoveCandidate *candidate, int source_fd,
                                int nsec_exact)
{
    size_t matching = 0;
    for (size_t i = 0; i < candidate->child_count; i++)
    {
        const MoveChild *child = &candidate->children[i];
        struct stat st;
        if (fstatat(source_fd, child->name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            move_kind_of_mode(st.st_mode) != child->kind)
            continue;
        if (child->kind == MOVE_KIND_REGULAR &&
            (st.st_size != child->size ||
             (int64_t)st.st_mtim.tv_sec != child->mtime_sec ||
             (nsec_exact && st.st_mtim.tv_nsec != child->mtime_nsec)))
            continue;
        matching++;
    }
    return matching;
}

MoveCandidate *move_pick(MoveCandidates *list, size_t root, const char *leaf,
                         int source_fd, int nsec_exact)
{
    MoveCandidate *best = NULL;
    size_t best_score = 0, second_score = 0;
    for (size_t at = candidates_lower_bound(list, root, leaf);
         at < list->count && list->items[at].root == root &&
         strcmp(list->items[at].leaf, leaf) == 0;
         at++)
    {
        MoveCandidate *candidate = &list->items[at];
        if (candidate->used)
            continue;
        size_t score = children_matching(candidate, source_fd, nsec_exact);
        if (score > best_score)
        {
            second_score = best_score;
            best_score = score;
            best = candidate;
        }
        else if (score > second_score)
            second_score = score;
    }
    if (best == NULL || best_score == second_score ||
        best_score * 2U < best->child_count)
        return NULL;
    return best;
}

/* ------------------------------------------------------------------------- */
/* Source folders                                                            */
/* ------------------------------------------------------------------------- */

int move_open_source_dir(int parent_fd, const char *name)
{
    return openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_NOATIME | O_CLOEXEC);
}

// A DIR over its own descriptor for fd, which stays open.
static DIR *open_listing(int fd)
{
    int scan_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (dir == NULL && scan_fd >= 0)
        close(scan_fd);
    if (dir != NULL)
        rewinddir(dir);
    return dir;
}

static int is_dot(const char *name)
{
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

// The entry's kind, from the listing when it says, otherwise from fstatat.
static MoveKind entry_kind(int dir_fd, const struct dirent *entry)
{
    switch (entry->d_type)
    {
    case DT_DIR:
        return MOVE_KIND_DIRECTORY;
    case DT_REG:
        return MOVE_KIND_REGULAR;
    case DT_LNK:
        return MOVE_KIND_SYMLINK;
    case DT_UNKNOWN:
    {
        struct stat st;
        return fstatat(dir_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0
            ? move_kind_of_mode(st.st_mode) : MOVE_KIND_OTHER;
    }
    default:
        return MOVE_KIND_OTHER;
    }
}

off_t move_source_tree_bytes(int fd)
{
    DIR *dir = open_listing(fd);
    if (dir == NULL)
        return 0;
    off_t total = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (is_dot(entry->d_name))
            continue;
        MoveKind kind = entry_kind(fd, entry);
        if (kind == MOVE_KIND_REGULAR)
        {
            // Each name of a file with several counts its share, so a
            // hardlinked file inside the folder counts once.
            struct stat st;
            if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
                total += st.st_size / (off_t)(st.st_nlink > 1 ? st.st_nlink
                                                              : 1);
        }
        else if (kind == MOVE_KIND_DIRECTORY)
        {
            int child = move_open_source_dir(fd, entry->d_name);
            if (child >= 0)
            {
                total += move_source_tree_bytes(child);
                close(child);
            }
        }
    }
    closedir(dir);
    return total;
}

/* ------------------------------------------------------------------------- */
/* Native                                                                    */
/* ------------------------------------------------------------------------- */

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} NameList;

static int name_list_add(NameList *list, const char *name)
{
    if (list->count == list->capacity)
    {
        size_t capacity = list->capacity == 0 ? 16U : list->capacity * 2U;
        char **items = realloc(list->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        list->items = items;
        list->capacity = capacity;
    }
    list->items[list->count] = strdup(name);
    if (list->items[list->count] == NULL)
        return -1;
    list->count++;
    return 0;
}

static void name_list_free(NameList *list)
{
    for (size_t i = 0; i < list->count; i++)
        free(list->items[i]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static char *join_rel(const char *parent, const char *name)
{
    char *joined = NULL;
    if (asprintf(&joined, "%s%s%s", parent,
                 parent[0] != '\0' && name[0] != '\0' ? "/" : "", name) < 0)
        return NULL;
    return joined;
}

typedef struct {
    const NativeMoveRoot *roots;
    size_t root;
    int nsec_exact;
    const struct RecopyList *recopy;
    MoveCandidates gone;  /* Payload folders whose source is gone. */
    NameList fresh_paths; /* New source folders, and the root of each. */
    size_t *fresh_roots;
    size_t fresh_capacity;
} NativeScan;

static int scan_add_fresh(NativeScan *scan, const char *rel)
{
    if (scan->fresh_paths.count == scan->fresh_capacity)
    {
        size_t capacity = scan->fresh_capacity == 0
            ? 16U : scan->fresh_capacity * 2U;
        size_t *roots = realloc(scan->fresh_roots, capacity * sizeof(*roots));
        if (roots == NULL)
            return -1;
        scan->fresh_roots = roots;
        scan->fresh_capacity = capacity;
    }
    scan->fresh_roots[scan->fresh_paths.count] = scan->root;
    return name_list_add(&scan->fresh_paths, rel);
}

// Records a payload folder whose source is gone with its children, read
// from the payload: what a new source folder is compared with.
static int scan_add_gone(NativeScan *scan, int payload_fd, const char *name,
                         const char *rel)
{
    const char *payload = scan->roots[scan->root].payload_path;
    if (recopy_list_covers(scan->recopy, payload, rel))
        return 0;
    int fd = openat(payload_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_NOATIME | O_CLOEXEC);
    if (fd < 0)
        return 0;
    if (move_candidates_add(&scan->gone, scan->root, rel) != 0)
    {
        close(fd);
        return -1;
    }
    MoveCandidate *candidate = &scan->gone.items[scan->gone.count - 1];
    DIR *dir = open_listing(fd);
    int result = 0;
    struct dirent *entry;
    while (result == 0 && dir != NULL && (entry = readdir(dir)) != NULL)
    {
        struct stat st;
        if (is_dot(entry->d_name) ||
            fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        result = move_candidate_add_child(
            candidate, entry->d_name, move_kind_of_mode(st.st_mode),
            st.st_size, (int64_t)st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
    }
    if (dir != NULL)
        closedir(dir);
    close(fd);
    return result;
}

// Walks the payload and the source of one root side by side: a payload
// folder whose source is gone is a candidate and is not entered, a source
// folder the payload lacks is new and is not entered either.
static int scan_pair(NativeScan *scan, int source_fd, int payload_fd,
                     const char *rel)
{
    NameList shared = {0};
    int result = 0;
    DIR *dir = open_listing(payload_fd);
    struct dirent *entry;
    while (result == 0 && dir != NULL && (entry = readdir(dir)) != NULL)
    {
        if (is_dot(entry->d_name) ||
            entry_kind(payload_fd, entry) != MOVE_KIND_DIRECTORY)
            continue;
        char *child = join_rel(rel, entry->d_name);
        if (child == NULL)
        {
            result = -1;
            break;
        }
        struct stat st;
        if (fstatat(source_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        {
            if (errno == ENOENT)
                result = scan_add_gone(scan, payload_fd, entry->d_name, child);
        }
        else if (S_ISDIR(st.st_mode))
            result = name_list_add(&shared, entry->d_name);
        free(child);
    }
    if (dir != NULL)
        closedir(dir);

    const struct SelectionRoot *selection = scan->roots[scan->root].selection;
    dir = result == 0 ? open_listing(source_fd) : NULL;
    while (result == 0 && dir != NULL && (entry = readdir(dir)) != NULL)
    {
        struct stat st;
        if (is_dot(entry->d_name) ||
            entry_kind(source_fd, entry) != MOVE_KIND_DIRECTORY ||
            fstatat(payload_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT)
            continue;
        char *child = join_rel(rel, entry->d_name);
        if (child == NULL)
        {
            result = -1;
            break;
        }
        if (selection == NULL || selection_root_owns(selection, child) == 1)
            result = scan_add_fresh(scan, child);
        free(child);
    }
    if (dir != NULL)
        closedir(dir);

    for (size_t i = 0; result == 0 && i < shared.count; i++)
    {
        int source_child = move_open_source_dir(source_fd, shared.items[i]);
        int payload_child = openat(payload_fd, shared.items[i],
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_NOATIME | O_CLOEXEC);
        char *child = join_rel(rel, shared.items[i]);
        if (child == NULL)
            result = -1;
        else if (source_child >= 0 && payload_child >= 0)
            result = scan_pair(scan, source_child, payload_child, child);
        free(child);
        if (source_child >= 0)
            close(source_child);
        if (payload_child >= 0)
            close(payload_child);
    }
    name_list_free(&shared);
    return result;
}

// Matches the new source folder at fd, or else the folders inside it.
static int match_fresh(NativeScan *scan, size_t root, int fd, const char *rel,
                       MovePlan *plan)
{
    const char *slash = strrchr(rel, '/');
    const char *leaf = slash != NULL ? slash + 1 : rel;
    if (move_candidates_have_leaf(&scan->gone, root, leaf))
    {
        MoveCandidate *candidate = move_pick(&scan->gone, root, leaf, fd,
                                             scan->nsec_exact);
        if (candidate != NULL)
        {
            const NativeMoveRoot *native = &scan->roots[root];
            MoveItem *item = move_plan_add(plan, "", native->payload_path,
                                           candidate->path, "",
                                           native->payload_path, rel);
            if (item == NULL)
                return -1;
            item->from_shown = move_shown_path(native->capture_path,
                                               candidate->path);
            item->to_shown = move_shown_path(native->capture_path, rel);
            if (item->from_shown == NULL || item->to_shown == NULL)
                return -1;
            item->bytes = move_source_tree_bytes(fd);
            candidate->used = 1;
            return 0;
        }
    }

    const struct SelectionRoot *selection = scan->roots[root].selection;
    DIR *dir = open_listing(fd);
    int result = 0;
    struct dirent *entry;
    while (result == 0 && dir != NULL && (entry = readdir(dir)) != NULL)
    {
        if (is_dot(entry->d_name) ||
            entry_kind(fd, entry) != MOVE_KIND_DIRECTORY)
            continue;
        char *child = join_rel(rel, entry->d_name);
        if (child == NULL)
        {
            result = -1;
            break;
        }
        int child_fd = -1;
        if (selection == NULL || selection_root_owns(selection, child) == 1)
            child_fd = move_open_source_dir(fd, entry->d_name);
        if (child_fd >= 0)
        {
            result = match_fresh(scan, root, child_fd, child, plan);
            close(child_fd);
        }
        free(child);
    }
    if (dir != NULL)
        closedir(dir);
    return result;
}

int native_moves_plan(int data_fd, const NativeMoveRoot *roots, size_t count,
                      int nsec_exact, const struct RecopyList *recopy,
                      MovePlan *plan)
{
    NativeScan scan = {
        .roots = roots,
        .nsec_exact = nsec_exact,
        .recopy = recopy
    };
    int result = 0;
    for (size_t i = 0; result == 0 && i < count; i++)
    {
        scan.root = i;
        int source_fd = open(roots[i].capture_path,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                             O_CLOEXEC);
        int payload_fd = openat(data_fd, roots[i].payload_path,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                O_NOATIME | O_CLOEXEC);
        if (source_fd >= 0 && payload_fd >= 0)
            result = scan_pair(&scan, source_fd, payload_fd, "");
        if (source_fd >= 0)
            close(source_fd);
        if (payload_fd >= 0)
            close(payload_fd);
    }
    move_candidates_sort(&scan.gone);

    for (size_t i = 0; result == 0 && scan.gone.count != 0 &&
                       i < scan.fresh_paths.count; i++)
    {
        size_t root = scan.fresh_roots[i];
        int root_fd = open(roots[root].capture_path,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                           O_CLOEXEC);
        int fd = root_fd >= 0
            ? openat(root_fd, scan.fresh_paths.items[i],
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                     O_CLOEXEC)
            : -1;
        if (fd >= 0)
            result = match_fresh(&scan, root, fd, scan.fresh_paths.items[i],
                                 plan);
        if (fd >= 0)
            close(fd);
        if (root_fd >= 0)
            close(root_fd);
    }
    move_candidates_free(&scan.gone);
    name_list_free(&scan.fresh_paths);
    free(scan.fresh_roots);
    return result;
}

static char *payload_join(const char *payload, const char *path)
{
    return join_rel(payload, path);
}

int native_moves_apply(int data_fd, MovePlan *plan)
{
    for (size_t i = 0; i < plan->count; i++)
    {
        MoveItem *item = &plan->items[i];
        char *from = payload_join(item->from_payload, item->from_path);
        char *to = payload_join(item->to_payload, item->to_path);
        if (from == NULL || to == NULL)
        {
            free(from);
            free(to);
            errno = ENOMEM;
            return -1;
        }
        int result = 0;
        if (strcmp(from, to) == 0)
            item->moved = 1;
        else
        {
            int old_parent = -1, new_parent = -1;
            char old_leaf[NAME_MAX + 1], new_leaf[NAME_MAX + 1];
            struct stat st;
            if (open_existing_payload_parent(data_fd, from, &old_parent,
                                             old_leaf, sizeof(old_leaf)) == 0 &&
                fstatat(old_parent, old_leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                portable_open_relative_parent(data_fd, to, &new_parent,
                                              new_leaf, sizeof(new_leaf)) == 0)
            {
                if (renameat2(old_parent, old_leaf, new_parent, new_leaf,
                              RENAME_NOREPLACE) == 0)
                    item->moved = 1;
                else if (errno != EEXIST)
                    result = -1;
            }
            int saved = errno;
            if (old_parent >= 0)
                close(old_parent);
            if (new_parent >= 0)
                close(new_parent);
            errno = saved;
        }
        free(from);
        free(to);
        if (result != 0)
            return -1;
    }
    return 0;
}
