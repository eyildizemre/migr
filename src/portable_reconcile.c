#define _GNU_SOURCE

#include "portable_reconcile_internal.h"
#include "portable.h"
#include "portable_fsops_internal.h"
#include "portable_hashset_internal.h"
#include "sidecar.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    RECONCILE_REASON_STALE = 1,
    RECONCILE_REASON_RELOCATION = 2
} ReconcileReason;

typedef struct {
    char *logical_path;
    char *physical_leaf;
    SidecarObjectKind kind;
    PortableOwnerState state;
    ReconcileReason reason;
} ReconcileWorkItem;

typedef struct {
    ReconcileWorkItem *items;
    size_t count;
    size_t capacity;
} ReconcileWorkList;

static size_t logical_depth(const char *logical)
{
    if (logical == NULL || logical[0] == '\0')
        return 0;
    size_t depth = 1;
    for (const char *cursor = logical; *cursor != '\0'; cursor++)
        if (*cursor == '/')
            depth++;
    return depth;
}

static int logical_parent_copy(char *out, size_t out_size,
                               const char *logical)
{
    if (out == NULL || out_size == 0 || logical == NULL)
        return -1;
    const char *slash = strrchr(logical, '/');
    size_t length = slash == NULL ? 0U : (size_t)(slash - logical);
    if (length >= out_size)
        return -1;
    if (length != 0)
        memcpy(out, logical, length);
    out[length] = '\0';
    return 0;
}

static int owner_kind_matches(SidecarObjectKind kind, mode_t mode)
{
    if (kind == SIDECAR_KIND_DIRECTORY)
        return S_ISDIR(mode) != 0;
    if (kind == SIDECAR_KIND_SYMLINK)
        return S_ISREG(mode) != 0;
    if (kind == SIDECAR_KIND_REGULAR || kind == SIDECAR_KIND_HARDLINK)
        return S_ISREG(mode) != 0;
    if (kind == SIDECAR_KIND_FIFO)
        return S_ISFIFO(mode) != 0;
    return 0;
}

static void work_list_free(ReconcileWorkList *list)
{
    if (list == NULL)
        return;
    for (size_t index = 0; index < list->count; index++) {
        free(list->items[index].logical_path);
        free(list->items[index].physical_leaf);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int work_list_append(ReconcileWorkList *list,
                            const PortablePhysicalOwner *owner,
                            ReconcileReason reason)
{
    if (list == NULL || owner == NULL || owner->logical_path == NULL ||
        owner->physical_leaf == NULL ||
        list->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (list->count == list->capacity) {
        ReconcileWorkItem *items = array_reserve(
            list->items, &list->capacity, list->count, 1U, sizeof(*items),
            16U, SIDECAR_MAX_LIVE_ENTRIES);
        if (items == NULL)
            return -1;
        list->items = items;
    }
    ReconcileWorkItem item = {
        .kind = owner->kind,
        .state = owner->state,
        .reason = reason
    };
    item.logical_path = strdup(owner->logical_path);
    item.physical_leaf = strdup(owner->physical_leaf);
    if (item.logical_path == NULL || item.physical_leaf == NULL) {
        free(item.logical_path);
        free(item.physical_leaf);
        return -1;
    }
    list->items[list->count++] = item;
    return 0;
}

static int work_item_compare(const void *left, const void *right)
{
    const ReconcileWorkItem *a = left;
    const ReconcileWorkItem *b = right;
    size_t a_depth = logical_depth(a->logical_path);
    size_t b_depth = logical_depth(b->logical_path);
    if (a_depth != b_depth)
        return a_depth < b_depth ? 1 : -1;
    return strcmp(a->logical_path, b->logical_path);
}

static int remove_immediate_node(int parent_fd, const char *leaf)
{
    if (parent_fd < 0 || !safe_component(leaf))
        return -1;
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (unlinkat(parent_fd, leaf, S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0) == 0)
        return 0;
    return errno == ENOENT ? 0 : -1;
}

static int append_delete(PortableCaptureContext *context,
                         const PortableRootSpec *root,
                         const char *logical)
{
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)root->id, strlen(root->id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) }
    };
    return sidecar_log_append_delete(context->sidecar, &deletion) ==
                   SIDECAR_STATUS_OK
               ? 0
               : -1;
}

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static size_t reconcile_test_descend_call_count;
static size_t reconcile_test_descend_vanish_at;
static const char *reconcile_test_vanish_child_name;

void portable_reconcile_test_vanish_descend_at(size_t call_index)
{
    reconcile_test_descend_call_count = 0;
    reconcile_test_descend_vanish_at = call_index;
}

static void reconcile_test_descend_hook(int parent_fd, const char *leaf)
{
    reconcile_test_descend_call_count++;
    if (reconcile_test_descend_vanish_at != 0 &&
        reconcile_test_descend_call_count == reconcile_test_descend_vanish_at)
        unlinkat(parent_fd, leaf, AT_REMOVEDIR);
}

void portable_reconcile_test_vanish_child_named(const char *name)
{
    reconcile_test_vanish_child_name = name;
}

static void reconcile_test_child_stat_hook(int directory_fd, const char *name)
{
    if (reconcile_test_vanish_child_name != NULL &&
        strcmp(name, reconcile_test_vanish_child_name) == 0)
        unlinkat(directory_fd, name, 0);
}
#else
static void reconcile_test_descend_hook(int parent_fd, const char *leaf)
{
    (void)parent_fd;
    (void)leaf;
}

static void reconcile_test_child_stat_hook(int directory_fd, const char *name)
{
    (void)directory_fd;
    (void)name;
}
#endif

static int owner_for_child(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical_parent,
                           int directory_fd, const char *physical_leaf,
                           const struct stat *st, int tombstones_only,
                           const PortablePhysicalOwner **out)
{
    if (out != NULL)
        *out = NULL;
    if (context == NULL || root == NULL || logical_parent == NULL ||
        directory_fd < 0 || physical_leaf == NULL || st == NULL || out == NULL)
        return -1;

    const PortablePhysicalOwner *owner = NULL;
    if (!tombstones_only) {
        int active = portable_physical_owner_for_node(
            context, context->active_owners, root->id, logical_parent,
            directory_fd, physical_leaf, st, &owner);
        if (active < 0)
            return -1;
        if (active == 1) {
            *out = owner;
            return 1;
        }
    }

    int deleted = portable_physical_owner_for_node(
        context, context->tombstone_owners, root->id, logical_parent,
        directory_fd, physical_leaf, st, &owner);
    if (deleted < 0)
        return -1;
    if (deleted == 1) {
        *out = owner;
        return 1;
    }
    return 0;
}

static int validate_owned_node(PortableCaptureContext *context,
                               const PortableRootSpec *root,
                               const PortablePhysicalOwner *owner,
                               int parent_fd, const char *actual_leaf,
                               const struct stat *known_stat,
                               int tombstones_only);

static int validate_owned_children(PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const char *logical_parent,
                                   int directory_fd, int tombstones_only)
{
    int scan_fd = openat(directory_fd, ".",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        reconcile_test_child_stat_hook(directory_fd, entry->d_name);
        struct stat st;
        if (fstatat(directory_fd, entry->d_name, &st,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT)
                continue;
            failed = 1;
            break;
        }
        const PortablePhysicalOwner *owner = NULL;
        int found = owner_for_child(context, root, logical_parent,
                                    directory_fd, entry->d_name, &st,
                                    tombstones_only, &owner);
        if (found != 1) {
            failed = 1;
            break;
        }
        if (owner->state != PORTABLE_OWNER_TOMBSTONE) {
            int visited = visited_contains(context->visited, root->id,
                                           owner->logical_path);
            if (visited != 0) {
                failed = 1;
                break;
            }
        }
        if (validate_owned_node(context, root, owner, directory_fd,
                                entry->d_name, &st,
                                tombstones_only) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int validate_owned_node(PortableCaptureContext *context,
                               const PortableRootSpec *root,
                               const PortablePhysicalOwner *owner,
                               int parent_fd, const char *actual_leaf,
                               const struct stat *known_stat,
                               int tombstones_only)
{
    if (context == NULL || root == NULL || owner == NULL || parent_fd < 0 ||
        !safe_component(actual_leaf) || known_stat == NULL ||
        (tombstones_only && owner->state != PORTABLE_OWNER_TOMBSTONE) ||
        !owner_kind_matches(owner->kind, known_stat->st_mode))
        return -1;
    if (!S_ISDIR(known_stat->st_mode))
        return 0;

    reconcile_test_descend_hook(parent_fd, actual_leaf);
    int directory_fd = open_child_directory(parent_fd, actual_leaf);
    if (directory_fd < 0)
        return errno == ENOENT ? 0 : -1;
    int result = validate_owned_children(context, root, owner->logical_path,
                                         directory_fd, tombstones_only);
    if (close(directory_fd) != 0)
        result = -1;
    return result;
}

static int finalize_owner_state(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const PortablePhysicalOwner *owner,
                                ReconcileReason reason,
                                int parent_fd, const char *actual_leaf,
                                int node_present)
{
    if (owner->state == PORTABLE_OWNER_LIVE) {
        int deleted;
        if (reason == RECONCILE_REASON_RELOCATION)
            deleted = tombstone_if_live(context, root->id,
                                        owner->logical_path);
        else {
            deleted = append_delete(context, root, owner->logical_path);
            if (deleted == 0)
                portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_DELETE);
        }
        if (deleted != 0)
            return -1;

        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (node_present && remove_immediate_node(parent_fd, actual_leaf) != 0)
            return -1;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
        return 0;
    }

    if (owner->state == PORTABLE_OWNER_CLAIM) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (node_present && remove_immediate_node(parent_fd, actual_leaf) != 0)
            return -1;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
        return append_delete(context, root, owner->logical_path);
    }

    if (owner->state == PORTABLE_OWNER_TOMBSTONE) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (node_present && remove_immediate_node(parent_fd, actual_leaf) != 0)
            return -1;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
        return 0;
    }
    return -1;
}

static int mutate_owned_node(PortableCaptureContext *context,
                             const PortableRootSpec *root,
                             const PortablePhysicalOwner *owner,
                             int parent_fd, const char *actual_leaf,
                             ReconcileReason reason, int tombstones_only)
{
    if (context == NULL || root == NULL || owner == NULL || parent_fd < 0 ||
        !safe_component(actual_leaf) ||
        (tombstones_only && owner->state != PORTABLE_OWNER_TOMBSTONE))
        return -1;

    struct stat st;
    if (fstatat(parent_fd, actual_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT)
            return -1;
        return finalize_owner_state(context, root, owner, reason,
                                    parent_fd, actual_leaf, 0);
    }
    if (!owner_kind_matches(owner->kind, st.st_mode))
        return -1;

    if (S_ISDIR(st.st_mode)) {
        reconcile_test_descend_hook(parent_fd, actual_leaf);
        int directory_fd = open_child_directory(parent_fd, actual_leaf);
        if (directory_fd < 0) {
            if (errno != ENOENT)
                return -1;
            return finalize_owner_state(context, root, owner, reason,
                                        parent_fd, actual_leaf, 0);
        }

        int scan_fd = dup_cloexec(directory_fd);
        DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (directory == NULL) {
            if (scan_fd >= 0)
                close(scan_fd);
            close(directory_fd);
            return -1;
        }
        int failed = 0;
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(directory);
            if (entry == NULL) {
                if (errno != 0)
                    failed = 1;
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            struct stat child_stat;
            if (fstatat(directory_fd, entry->d_name, &child_stat,
                        AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT)
                    continue;
                failed = 1;
                break;
            }
            const PortablePhysicalOwner *child_owner = NULL;
            int found = owner_for_child(
                context, root, owner->logical_path, directory_fd,
                entry->d_name, &child_stat, tombstones_only, &child_owner);
            if (found != 1) {
                failed = 1;
                break;
            }
            if (child_owner->state != PORTABLE_OWNER_TOMBSTONE) {
                int visited = visited_contains(context->visited, root->id,
                                               child_owner->logical_path);
                if (visited != 0) {
                    failed = 1;
                    break;
                }
            }
            if (mutate_owned_node(context, root, child_owner, directory_fd,
                                  entry->d_name, reason,
                                  tombstones_only) != 0) {
                failed = 1;
                break;
            }
        }
        if (closedir(directory) != 0)
            failed = 1;
        if (close(directory_fd) != 0)
            failed = 1;
        if (failed)
            return -1;
    }

    return finalize_owner_state(context, root, owner, reason,
                                parent_fd, actual_leaf, 1);
}

static int validate_recorded_owner(PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const PortablePhysicalOwner *owner)
{
    int parent_fd = -1;
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    SidecarObjectKind kind;
    PortableOwnerState state;
    if (portable_recorded_parent_open(context, root, owner->logical_path, 0,
                                      &parent_fd, leaf, &kind, &state) != 0)
        return -1;
    if (state != owner->state || kind != owner->kind ||
        (owner->logical_path[0] != '\0' &&
         strcmp(leaf, owner->physical_leaf) != 0)) {
        close(parent_fd);
        return -1;
    }

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved = errno;
        close(parent_fd);
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }
    int result = validate_owned_node(context, root, owner, parent_fd, leaf,
                                     &st, 0);
    if (close(parent_fd) != 0)
        result = -1;
    return result;
}

static int cleanup_work_item(PortableCaptureContext *context,
                             const PortableRootSpec *root,
                             const ReconcileWorkItem *item)
{
    PortablePhysicalOwner owner = {
        .root_id = (char *)root->id,
        .logical_path = item->logical_path,
        .physical_leaf = item->physical_leaf,
        .kind = item->kind,
        .state = item->state
    };
    char parent[SIDECAR_MAX_PATH + 1U];
    if (logical_parent_copy(parent, sizeof(parent), item->logical_path) != 0)
        return -1;
    owner.logical_parent = parent;

    int parent_fd = -1;
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    SidecarObjectKind kind;
    PortableOwnerState state;
    int allow_tombstone = item->state == PORTABLE_OWNER_TOMBSTONE;
    if (portable_recorded_parent_open(context, root, item->logical_path,
                                      allow_tombstone,
                                      &parent_fd, leaf, &kind, &state) != 0)
        return -1;
    if (kind != item->kind || state != item->state ||
        (item->logical_path[0] != '\0' &&
         strcmp(leaf, item->physical_leaf) != 0)) {
        close(parent_fd);
        return -1;
    }
    int result = finalize_owner_state(context, root, &owner, item->reason,
                                      parent_fd, leaf, 1);
    if (result == 0) {
        struct stat st;
        if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
            result = -1;
        else if (errno != ENOENT)
            result = -1;
    }
    if (close(parent_fd) != 0)
        result = -1;
    return result;
}

static int work_list_validate_claims(PortableCaptureContext *context,
                                     const PortableRootSpec *root,
                                     const ReconcileWorkList *work)
{
    for (size_t index = 0; index < work->count; index++) {
        const ReconcileWorkItem *item = &work->items[index];
        if (item->state != PORTABLE_OWNER_CLAIM)
            continue;
        PortablePhysicalOwner owner = {
            .root_id = (char *)root->id,
            .logical_path = item->logical_path,
            .physical_leaf = item->physical_leaf,
            .kind = item->kind,
            .state = item->state
        };
        char parent[SIDECAR_MAX_PATH + 1U];
        if (logical_parent_copy(parent, sizeof(parent), item->logical_path) != 0)
            return -1;
        owner.logical_parent = parent;
        if (validate_recorded_owner(context, root, &owner) != 0)
            return -1;
    }
    return 0;
}

static int recorded_owner_payload_present(PortableCaptureContext *context,
                                          const PortableRootSpec *root,
                                          const PortablePhysicalOwner *owner)
{
    if (context == NULL || root == NULL || owner == NULL)
        return -1;
    int parent_fd = -1;
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    SidecarObjectKind kind;
    PortableOwnerState state;
    if (portable_recorded_parent_open(context, root, owner->logical_path, 0,
                                      &parent_fd, leaf, &kind, &state) != 0)
        return errno == ENOENT ? 0 : -1;
    int result = -1;
    if (kind == owner->kind && state == owner->state &&
        strcmp(leaf, owner->physical_leaf) == 0) {
        struct stat st;
        if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
            result = owner_kind_matches(owner->kind, st.st_mode) ? 1 : -1;
        else
            result = errno == ENOENT ? 0 : -1;
    }
    if (close(parent_fd) != 0)
        result = -1;
    return result;
}

static int active_state_exists_for_logical(PortableCaptureContext *context,
                                           const PortablePhysicalOwner *owner)
{
    if (context == NULL || context->sidecar == NULL || owner == NULL ||
        owner->root_id == NULL || owner->logical_path == NULL)
        return -1;

    SidecarBytes root_id = {
        (const unsigned char *)owner->root_id, strlen(owner->root_id) };
    SidecarBytes logical_path = {
        (const unsigned char *)owner->logical_path,
        strlen(owner->logical_path) };
    SidecarLiveView live = {0};
    SidecarClaimView claim = {0};
    int live_found = sidecar_log_find(context->sidecar, root_id, logical_path,
                                      &live);
    int claim_found = sidecar_log_find_claim(context->sidecar, root_id,
                                             logical_path, &claim);
    if (live_found < 0 || claim_found < 0 ||
        (live_found == 1 && claim_found == 1))
        return -1;
    return live_found == 1 || claim_found == 1;
}

int reconcile_stale_claim(PortableCaptureContext *context,
                          const PortableRootSpec *root, const char *logical,
                          const SidecarClaim *claim)
{
    if (context == NULL || root == NULL || logical == NULL || claim == NULL ||
        !sidecar_bytes_equal(
            claim->root_id,
            (SidecarBytes){ (const unsigned char *)root->id,
                            strlen(root->id) }) ||
        !sidecar_bytes_equal(
            claim->logical_path,
            (SidecarBytes){ (const unsigned char *)logical,
                            strlen(logical) }))
        return -1;
    if (portable_capture_owners_reload(context) != 0)
        return -1;

    char *physical_leaf = NULL;
    if (sidecar_bytes_to_text(claim->physical_leaf, &physical_leaf) != 0)
        return -1;
    char logical_parent[SIDECAR_MAX_PATH + 1U];
    if (logical_parent_copy(logical_parent, sizeof(logical_parent), logical) != 0) {
        free(physical_leaf);
        return -1;
    }
    const PortablePhysicalOwner *owner = NULL;
    int found = portable_physical_owners_find(
        context->active_owners, root->id, logical_parent, physical_leaf, &owner);
    free(physical_leaf);
    if (found != 1 || owner->state != PORTABLE_OWNER_CLAIM ||
        strcmp(owner->logical_path, logical) != 0 || owner->kind != claim->kind)
        return -1;
    if (validate_recorded_owner(context, root, owner) != 0)
        return -1;

    int parent_fd = -1;
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    SidecarObjectKind kind;
    PortableOwnerState state;
    if (portable_recorded_parent_open(context, root, logical, 0, &parent_fd,
                                      leaf, &kind, &state) != 0)
        return -1;
    int result = mutate_owned_node(context, root, owner, parent_fd, leaf,
                                   RECONCILE_REASON_STALE, 0);
    if (close(parent_fd) != 0)
        result = -1;
    if (result == 0)
        result = portable_capture_owners_reload(context);
    return result;
}

int reconcile_stale_live(PortableCaptureContext *context,
                         const PortableRootSpec *root, const char *logical)
{
    if (context == NULL || root == NULL || logical == NULL)
        return -1;
    if (portable_capture_owners_reload(context) != 0)
        return -1;

    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView live = {0};
    int found = sidecar_log_find(context->sidecar, root_key, logical_key,
                                 &live);
    if (found < 0)
        return -1;
    if (found == 0)
        return 0;
    if (live.entry == NULL)
        return -1;

    char *physical_leaf = NULL;
    if (sidecar_bytes_to_text(live.entry->physical_leaf, &physical_leaf) != 0)
        return -1;
    char logical_parent[SIDECAR_MAX_PATH + 1U];
    if (logical_parent_copy(logical_parent, sizeof(logical_parent), logical) !=
        0) {
        free(physical_leaf);
        return -1;
    }
    PortablePhysicalOwner owner = {
        .root_id = (char *)root->id,
        .logical_parent = logical_parent,
        .logical_path = (char *)logical,
        .physical_leaf = physical_leaf,
        .kind = live.entry->kind,
        .state = PORTABLE_OWNER_LIVE
    };

    int parent_fd = -1;
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    SidecarObjectKind kind;
    PortableOwnerState state;
    int result = portable_recorded_parent_open(
        context, root, logical, 0, &parent_fd, leaf, &kind, &state);
    if (result == 0 &&
        (kind != owner.kind || state != owner.state ||
         (logical[0] != '\0' && strcmp(leaf, physical_leaf) != 0)))
        result = -1;
    if (result == 0)
        result = mutate_owned_node(context, root, &owner, parent_fd, leaf,
                                   RECONCILE_REASON_STALE, 0);
    if (parent_fd >= 0 && close(parent_fd) != 0)
        result = -1;
    free(physical_leaf);
    if (result == 0)
        result = portable_capture_owners_reload(context);
    return result;
}

int reconcile_destination_children(PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const char *logical_parent,
                                   int parent_fd, const char *leaf)
{
    if (context == NULL || root == NULL || logical_parent == NULL ||
        parent_fd < 0 || !safe_component(leaf))
        return -1;
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return 0;

    reconcile_test_descend_hook(parent_fd, leaf);
    int directory_fd = open_child_directory(parent_fd, leaf);
    if (directory_fd < 0)
        return errno == ENOENT ? 0 : -1;
    int result = validate_owned_children(context, root, logical_parent,
                                         directory_fd, 0);
    if (result == 0) {
        int scan_fd = dup_cloexec(directory_fd);
        DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
        if (directory == NULL) {
            if (scan_fd >= 0)
                close(scan_fd);
            result = -1;
        } else {
            for (;;) {
                errno = 0;
                struct dirent *entry = readdir(directory);
                if (entry == NULL) {
                    if (errno != 0)
                        result = -1;
                    break;
                }
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0)
                    continue;
                struct stat child_stat;
                if (fstatat(directory_fd, entry->d_name, &child_stat,
                            AT_SYMLINK_NOFOLLOW) != 0) {
                    if (errno == ENOENT)
                        continue;
                    result = -1;
                    break;
                }
                const PortablePhysicalOwner *owner = NULL;
                int found = owner_for_child(
                    context, root, logical_parent, directory_fd,
                    entry->d_name, &child_stat, 0, &owner);
                if (found != 1 ||
                    (owner->state != PORTABLE_OWNER_TOMBSTONE &&
                     visited_contains(context->visited, root->id,
                                      owner->logical_path) != 0) ||
                    mutate_owned_node(context, root, owner, directory_fd,
                                      entry->d_name,
                                      RECONCILE_REASON_STALE, 0) != 0) {
                    result = -1;
                    break;
                }
            }
            if (closedir(directory) != 0)
                result = -1;
        }
    }
    if (close(directory_fd) != 0)
        result = -1;
    if (result == 0)
        result = portable_capture_owners_reload(context);
    return result;
}

int prepare_collision_relocations(PortableCaptureContext *context,
                                  const PortableRootSpec *root)
{
    if (context == NULL || root == NULL)
        return -1;
    if (!context->resume_mode)
        return 0;
    if (context->current_source == NULL || context->collision_plan == NULL ||
        portable_capture_owners_reload(context) != 0)
        return -1;

    PortablePhysicalOwners *active = context->active_owners;
    ReconcileWorkList work = {0};
    for (size_t index = 0; index < active->count; index++) {
        const PortablePhysicalOwner *owner = &active->items[index];
        if (strcmp(owner->root_id, root->id) != 0)
            continue;
        relocation_scan_count();
        int current = portable_current_source_contains(
            context->current_source, root->id, owner->logical_path);
        if (current < 0) {
            work_list_free(&work);
            return -1;
        }
        if (current == 0) {
            if (work_list_append(&work, owner,
                                 RECONCILE_REASON_STALE) != 0) {
                work_list_free(&work);
                return -1;
            }
            continue;
        }
        int same = portable_recorded_address_matches_current(
            context, root, owner->logical_path);
        if (same < 0) {
            work_list_free(&work);
            return -1;
        }
        if (same == 0 && owner->state == PORTABLE_OWNER_CLAIM) {
            char logical_parent[SIDECAR_MAX_PATH + 1U];
            if (logical_parent_copy(logical_parent, sizeof(logical_parent),
                                    owner->logical_path) != 0) {
                work_list_free(&work);
                return -1;
            }
            int parent_same = portable_recorded_address_matches_current(
                context, root, logical_parent);
            if (parent_same < 0) {
                work_list_free(&work);
                return -1;
            }
            if (parent_same == 1) {
                int present = recorded_owner_payload_present(context, root,
                                                              owner);
                if (present < 0) {
                    work_list_free(&work);
                    return -1;
                }
                if (present == 0)
                    continue;
            }
        }
        if (same == 0 &&
            work_list_append(&work, owner,
                             RECONCILE_REASON_RELOCATION) != 0) {
            work_list_free(&work);
            return -1;
        }
    }

    PortablePhysicalOwners *tombstones = context->tombstone_owners;
    for (size_t index = 0; index < tombstones->count; index++) {
        const PortablePhysicalOwner *owner = &tombstones->items[index];
        if (strcmp(owner->root_id, root->id) != 0)
            continue;
        int active = active_state_exists_for_logical(context, owner);
        if (active < 0) {
            work_list_free(&work);
            return -1;
        }
        if (active == 1)
            continue;
        int current = portable_current_source_contains(
            context->current_source, root->id, owner->logical_path);
        if (current < 0) {
            work_list_free(&work);
            return -1;
        }
        if (current == 0) {
            if (work_list_append(&work, owner,
                                 RECONCILE_REASON_STALE) != 0) {
                work_list_free(&work);
                return -1;
            }
            continue;
        }

        const PortablePhysicalOwner *exact = NULL;
        int exact_owner = portable_physical_owners_find(
            tombstones, root->id, owner->logical_parent,
            owner->physical_leaf, &exact);
        if (exact_owner != 1 || exact != owner) {
            work_list_free(&work);
            return -1;
        }

        int same = portable_tombstoned_address_matches_current(
            context, root, owner->logical_path);
        if (same < 0) {
            work_list_free(&work);
            return -1;
        }
        if (same == 0 &&
            work_list_append(&work, owner,
                             RECONCILE_REASON_RELOCATION) != 0) {
            work_list_free(&work);
            return -1;
        }
    }

    if (work_list_validate_claims(context, root, &work) != 0) {
        work_list_free(&work);
        return -1;
    }
    if (work.count > 1U)
        qsort(work.items, work.count, sizeof(*work.items), work_item_compare);
    int failed = 0;
    for (size_t index = 0; index < work.count; index++) {
        if (work.items[index].reason == RECONCILE_REASON_RELOCATION)
            relocation_remove_count();
        if (cleanup_work_item(context, root, &work.items[index]) != 0) {
            failed = 1;
            break;
        }
    }
    work_list_free(&work);
    if (failed)
        return -1;
    return portable_capture_owners_reload(context);
}

typedef struct {
    PortableCaptureContext *context;
    const PortableRootSpec *root;
    PortableVisited seen;
    int failed;
} InventoryState;

static int inventory_scan_live_node(InventoryState *inventory,
                                    const PortablePhysicalOwner *owner,
                                    int parent_fd, const char *actual_leaf,
                                    const struct stat *known_stat);

static int inventory_scan_children(InventoryState *inventory,
                                   const char *logical_parent,
                                   int directory_fd)
{
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        struct stat st;
        if (fstatat(directory_fd, entry->d_name, &st,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT)
                continue;
            failed = 1;
            break;
        }
        const PortablePhysicalOwner *owner = NULL;
        int active = portable_physical_owner_for_node(
            inventory->context, inventory->context->active_owners,
            inventory->root->id, logical_parent, directory_fd,
            entry->d_name, &st, &owner);
        if (active < 0) {
            failed = 1;
            break;
        }
        if (active == 1) {
            if (owner->state != PORTABLE_OWNER_LIVE ||
                inventory_scan_live_node(inventory, owner, directory_fd,
                                         entry->d_name, &st) != 0) {
                failed = 1;
                break;
            }
            continue;
        }

        int deleted = portable_physical_owner_for_node(
            inventory->context, inventory->context->tombstone_owners,
            inventory->root->id, logical_parent, directory_fd,
            entry->d_name, &st, &owner);
        if (deleted != 1 || owner->state != PORTABLE_OWNER_TOMBSTONE ||
            validate_owned_node(inventory->context, inventory->root, owner,
                                directory_fd, entry->d_name, &st, 1) != 0 ||
            mutate_owned_node(inventory->context, inventory->root, owner,
                              directory_fd, entry->d_name,
                              RECONCILE_REASON_STALE, 1) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int inventory_scan_live_node(InventoryState *inventory,
                                    const PortablePhysicalOwner *owner,
                                    int parent_fd, const char *actual_leaf,
                                    const struct stat *known_stat)
{
    if (owner == NULL || owner->state != PORTABLE_OWNER_LIVE ||
        !owner_kind_matches(owner->kind, known_stat->st_mode) ||
        visited_add(&inventory->seen, inventory->root->id,
                    owner->logical_path) != 0)
        return -1;
    if (!S_ISDIR(known_stat->st_mode))
        return 0;

    int directory_fd = open_child_directory(parent_fd, actual_leaf);
    if (directory_fd < 0)
        return -1;
    int result = inventory_scan_children(inventory, owner->logical_path,
                                         directory_fd);
    if (close(directory_fd) != 0)
        result = -1;
    return result;
}

static int inventory_all_live_seen(const PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const PortableVisited *seen)
{
    const PortablePhysicalOwners *active = context->active_owners;
    for (size_t index = 0; index < active->count; index++) {
        const PortablePhysicalOwner *owner = &active->items[index];
        if (strcmp(owner->root_id, root->id) != 0)
            continue;
        if (owner->state != PORTABLE_OWNER_LIVE)
            return -1;
        if (visited_contains(seen, root->id, owner->logical_path) != 1)
            return -1;
    }
    return 0;
}

static int reconcile_inventory(PortableCaptureContext *context,
                               const PortableRootSpec *root)
{
    if (portable_capture_owners_reload(context) != 0)
        return -1;
    InventoryState inventory = {
        .context = context,
        .root = root
    };
    inventory.seen.hash_salt = sidecar_process_salt();

    const PortablePhysicalOwner *root_owner = NULL;
    int active = portable_physical_owners_find(
        context->active_owners, root->id, "", "", &root_owner);
    if (active < 0)
        goto fail;
    const PortablePhysicalOwner *root_tombstone = NULL;
    int deleted = portable_physical_owners_find(
        context->tombstone_owners, root->id, "", "", &root_tombstone);
    if (deleted < 0)
        goto fail;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(context->data_fd, root->payload_path,
                                     &root_parent, root_leaf,
                                     sizeof(root_leaf)) != 0) {
        if (errno == ENOENT && active == 0) {
            visited_dispose(&inventory.seen);
            return 0;
        }
        goto fail;
    }

    struct stat root_stat;
    if (fstatat(root_parent, root_leaf, &root_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT && active == 0) {
            close(root_parent);
            visited_dispose(&inventory.seen);
            return 0;
        }
        goto close_fail;
    }

    int result = -1;
    if (active == 1) {
        if (root_owner->state != PORTABLE_OWNER_LIVE ||
            inventory_scan_live_node(&inventory, root_owner, root_parent,
                                     root_leaf, &root_stat) != 0)
            goto close_fail;
        result = 0;
    } else if (deleted == 1 && root_tombstone->state == PORTABLE_OWNER_TOMBSTONE) {
        if (validate_owned_node(context, root, root_tombstone, root_parent,
                                root_leaf, &root_stat, 1) != 0 ||
            mutate_owned_node(context, root, root_tombstone, root_parent,
                              root_leaf, RECONCILE_REASON_STALE, 1) != 0)
            goto close_fail;
        result = 0;
    } else {
        goto close_fail;
    }

    if (close(root_parent) != 0)
        goto fail;
    root_parent = -1;
    if (result != 0 || portable_capture_owners_reload(context) != 0 ||
        inventory_all_live_seen(context, root, &inventory.seen) != 0)
        goto fail;
    visited_dispose(&inventory.seen);
    return 0;

close_fail:
    {
        int saved = errno;
        close(root_parent);
        errno = saved;
    }
fail:
    visited_dispose(&inventory.seen);
    return -1;
}

static int stale_work_list_build(PortableCaptureContext *context,
                                 const PortableRootSpec *root,
                                 ReconcileWorkList *work)
{
    if (portable_capture_owners_reload(context) != 0)
        return -1;
    PortablePhysicalOwners *active = context->active_owners;
    for (size_t index = 0; index < active->count; index++) {
        const PortablePhysicalOwner *owner = &active->items[index];
        if (strcmp(owner->root_id, root->id) != 0)
            continue;
        int visited = visited_contains(context->visited, root->id,
                                       owner->logical_path);
        if (visited < 0)
            return -1;
        if (visited == 0 &&
            work_list_append(work, owner, RECONCILE_REASON_STALE) != 0)
            return -1;
    }
    return 0;
}

int reconcile_root(PortableCaptureContext *context,
                   const PortableRootSpec *root)
{
    if (context == NULL || root == NULL)
        return -1;
    ReconcileWorkList work = {0};
    if (stale_work_list_build(context, root, &work) != 0)
        goto fail;
    if (work_list_validate_claims(context, root, &work) != 0)
        goto fail;
    if (work.count > 1U)
        qsort(work.items, work.count, sizeof(*work.items), work_item_compare);
    for (size_t index = 0; index < work.count; index++)
        if (cleanup_work_item(context, root, &work.items[index]) != 0)
            goto fail;
    work_list_free(&work);

    if (portable_capture_owners_reload(context) != 0)
        return -1;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_FINAL_INVENTORY);
    return reconcile_inventory(context, root);

fail:
    work_list_free(&work);
    return -1;
}
