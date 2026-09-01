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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char *logical;
    char *physical;
} StaleKey;

typedef struct {
    StaleKey *items;
    size_t count;
    size_t capacity;
    int failed;
} StaleKeys;

typedef struct {
    char *logical;
    char *physical;
    SidecarObjectKind kind;
} StaleClaim;

typedef struct {
    StaleClaim *items;
    size_t count;
    size_t capacity;
    int failed;
} StaleClaims;

static void stale_keys_free(StaleKeys *keys)
{
    if (keys == NULL)
        return;
    for (size_t index = 0; index < keys->count; index++) {
        free(keys->items[index].logical);
        free(keys->items[index].physical);
    }
    free(keys->items);
    memset(keys, 0, sizeof(*keys));
}

static void stale_claims_free(StaleClaims *claims)
{
    if (claims == NULL)
        return;
    for (size_t index = 0; index < claims->count; index++) {
        free(claims->items[index].logical);
        free(claims->items[index].physical);
    }
    free(claims->items);
    memset(claims, 0, sizeof(*claims));
}

static int stale_claims_append(StaleClaims *claims, SidecarBytes logical,
                               SidecarBytes physical, SidecarObjectKind kind)
{
    if (claims == NULL || claims->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (claims->count == claims->capacity) {
        size_t capacity = claims->capacity == 0 ? 16U : claims->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < claims->capacity ||
            capacity > SIZE_MAX / sizeof(*claims->items))
            return -1;
        StaleClaim *items = realloc(claims->items,
                                    capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        claims->items = items;
        claims->capacity = capacity;
    }

    StaleClaim item = { .kind = kind };
    if (sidecar_bytes_to_text(logical, &item.logical) != 0 ||
        sidecar_bytes_to_text(physical, &item.physical) != 0) {
        free(item.logical);
        free(item.physical);
        return -1;
    }
    claims->items[claims->count++] = item;
    return 0;
}

static const PortableClaimedPath *portable_claimed_paths_owner(
    const PortableClaimedPaths *paths, const char *root_id,
    const char *physical_path)
{
    if (paths == NULL || !paths->sorted || root_id == NULL ||
        physical_path == NULL)
        return NULL;
    size_t low = 0;
    size_t high = paths->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        const PortableClaimedPath *item = &paths->items[middle];
        int result = strcmp(item->root_id, root_id);
        if (result == 0)
            result = strcmp(item->physical_path, physical_path);
        if (result < 0)
            low = middle + 1U;
        else
            high = middle;
    }
    if (low == paths->count)
        return NULL;
    const PortableClaimedPath *item = &paths->items[low];
    return strcmp(item->root_id, root_id) == 0 &&
                   strcmp(item->physical_path, physical_path) == 0
               ? item
               : NULL;
}

static int stale_keys_append(StaleKeys *keys, SidecarBytes logical,
                             SidecarBytes physical)
{
    if (keys == NULL)
        return -1;
    if (keys->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (keys->count == keys->capacity) {
        size_t capacity = keys->capacity == 0 ? 16U : keys->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < keys->capacity || capacity > SIZE_MAX / sizeof(*keys->items))
            return -1;
        StaleKey *items = realloc(keys->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        keys->items = items;
        keys->capacity = capacity;
    }

    StaleKey item = {0};
    if (sidecar_bytes_to_text(logical, &item.logical) != 0 ||
        sidecar_bytes_to_text(physical, &item.physical) != 0) {
        free(item.logical);
        free(item.physical);
        return -1;
    }
    keys->items[keys->count++] = item;
    return 0;
}

typedef struct {
    PortableCaptureContext *context;
    const char *root_id;
    StaleKeys *stale;
} StaleCollection;

static int collect_stale_key(const SidecarLiveView *view, void *argument)
{
    StaleCollection *collection = argument;
    if (collection == NULL || collection->context == NULL ||
        collection->root_id == NULL || collection->stale == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->entry->root_id,
            (SidecarBytes){ (const unsigned char *)collection->root_id,
                            strlen(collection->root_id) }))
        return 0;

    char *logical = NULL;
    if (sidecar_bytes_to_text(view->entry->logical_path, &logical) != 0) {
        collection->stale->failed = 1;
        return 1;
    }
    int present = visited_contains(collection->context->visited,
                                   collection->root_id, logical);
    free(logical);
    if (present < 0) {
        collection->stale->failed = 1;
        return 1;
    }
    if (present == 0) {
        if (stale_keys_append(collection->stale, view->entry->logical_path,
                              view->entry->physical_path) != 0)
            collection->stale->failed = 1;
    }
    return collection->stale->failed;
}

typedef struct {
    PortableCaptureContext *context;
    const char *root_id;
    StaleClaims *stale;
} StaleClaimCollection;

static int collect_stale_claim(const SidecarClaimView *view, void *argument)
{
    StaleClaimCollection *collection = argument;
    if (collection == NULL || collection->context == NULL ||
        collection->root_id == NULL || collection->stale == NULL ||
        view == NULL || view->claim == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->claim->root_id,
            (SidecarBytes){ (const unsigned char *)collection->root_id,
                            strlen(collection->root_id) }))
        return 0;

    char *logical = NULL;
    if (sidecar_bytes_to_text(view->claim->logical_path, &logical) != 0) {
        collection->stale->failed = 1;
        return 1;
    }
    int present = visited_contains(collection->context->visited,
                                   collection->root_id, logical);
    free(logical);
    if (present < 0) {
        collection->stale->failed = 1;
        return 1;
    }
    if (present == 0 && stale_claims_append(
                           collection->stale, view->claim->logical_path,
                           view->claim->physical_path, view->claim->kind) != 0)
        collection->stale->failed = 1;
    return collection->stale->failed;
}

/* Remove one owned payload entry without recursively touching its children.
 * The collision relocation pass removes descendants first; a non-empty
 * directory therefore fails closed instead of deleting an unowned entry. */
static int remove_owned_payload_relative(int data_fd, const char *payload_root,
                                         const char *physical)
{
    if (data_fd < 0 || payload_root == NULL || physical == NULL ||
        (physical[0] != '\0' && !safe_relative_path(physical)))
        return -1;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(data_fd, payload_root, &root_parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return errno == ENOENT ? 0 : -1;

    if (physical[0] == '\0') {
        struct stat st;
        int result = 0;
        if (fstatat(root_parent, root_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
            result = errno == ENOENT ? 0 : -1;
        else
            result = unlinkat(root_parent, root_leaf,
                              S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0) == 0
                         ? 0
                         : -1;
        int saved = errno;
        if (close(root_parent) != 0 && result == 0) {
            result = -1;
            saved = EIO;
        }
        errno = saved;
        return result;
    }

    int payload_fd = open_child_directory(root_parent, root_leaf);
    int saved = errno;
    if (close(root_parent) != 0) {
        if (payload_fd >= 0)
            close(payload_fd);
        return -1;
    }
    if (payload_fd < 0) {
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }

    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(payload_fd, physical, &parent_fd,
                                     leaf, sizeof(leaf)) != 0) {
        saved = errno;
        close(payload_fd);
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }

    struct stat st;
    int result = 0;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        result = errno == ENOENT ? 0 : -1;
    } else {
        result = unlinkat(parent_fd, leaf, S_ISDIR(st.st_mode)
                                      ? AT_REMOVEDIR : 0) == 0 ? 0 : -1;
    }
    saved = errno;
    if (close(parent_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    if (close(payload_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

typedef struct {
    const PortableOwnedPaths *owned;
    const PortableClaimedPaths *claimed;
} ClaimOwnershipPaths;

static int open_claim_node(int data_fd, const char *payload_root,
                           const char *physical, int *parent_out,
                           char *leaf, size_t leaf_size, struct stat *out_stat)
{
    if (data_fd < 0 || payload_root == NULL || physical == NULL ||
        parent_out == NULL || leaf == NULL || leaf_size == 0 ||
        out_stat == NULL ||
        (physical[0] != '\0' && !safe_relative_path(physical)))
        return -1;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(data_fd, payload_root, &root_parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return errno == ENOENT ? 1 : -1;

    int parent_fd = root_parent;
    if (physical[0] != '\0') {
        int payload_fd = open_child_directory(root_parent, root_leaf);
        int saved = errno;
        if (close(root_parent) != 0) {
            if (payload_fd >= 0)
                close(payload_fd);
            return -1;
        }
        if (payload_fd < 0) {
            errno = saved;
            return errno == ENOENT ? 1 : -1;
        }
        if (open_existing_payload_parent(payload_fd, physical, &parent_fd,
                                         leaf, leaf_size) != 0) {
            saved = errno;
            close(payload_fd);
            errno = saved;
            return errno == ENOENT ? 1 : -1;
        }
        if (close(payload_fd) != 0) {
            close(parent_fd);
            return -1;
        }
    } else if (copy_text(leaf, leaf_size, root_leaf) != 0) {
        close(parent_fd);
        return -1;
    }

    if (fstatat(parent_fd, leaf, out_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        int saved = errno;
        close(parent_fd);
        errno = saved;
        return errno == ENOENT ? 1 : -1;
    }
    *parent_out = parent_fd;
    return 0;
}

static int reconcile_claim_owner(const ClaimOwnershipPaths *paths,
                                 const char *root_id,
                                 const char *physical,
                                 const char **live_logical,
                                 const PortableClaimedPath **claim)
{
    if (paths == NULL || root_id == NULL || physical == NULL ||
        live_logical == NULL || claim == NULL)
        return -1;
    *live_logical = portable_owned_paths_owner(paths->owned, root_id,
                                               physical);
    *claim = portable_claimed_paths_owner(paths->claimed, root_id, physical);
    if ((*live_logical != NULL) == (*claim != NULL))
        return -1;
    return 0;
}

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
/* Both reconcile_claim_validate_node() and reconcile_mutate_known_node()
 * call open_child_directory(parent_fd, leaf) to descend into a node that
 * open_claim_node() just confirmed is a directory. A test arms this to
 * remove that directory out from under the Nth such call (1-based, across
 * both functions combined), simulating the node vanishing in the window
 * between the confirming stat and the descent. */
static size_t reconcile_test_descend_call_count;
static size_t reconcile_test_descend_vanish_at;

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

/* reconcile_claim_validate_node()'s directory-scan loop fstatat()s each
 * child by name. A test arms this to remove one specific child, by name,
 * immediately before that call, simulating the child vanishing between
 * readdir() and fstatat(). */
static const char *reconcile_test_vanish_child_name;

void portable_reconcile_test_vanish_child_named(const char *name)
{
    reconcile_test_vanish_child_name = name;
}

static void reconcile_test_child_stat_hook(int directory_fd,
                                           const char *name)
{
    if (reconcile_test_vanish_child_name != NULL &&
        strcmp(name, reconcile_test_vanish_child_name) == 0)
        unlinkat(directory_fd, name, 0);
}
#endif

static int reconcile_claim_validate_node(PortableCaptureContext *context,
                                         const PortableRootSpec *root,
                                         const char *physical,
                                         const ClaimOwnershipPaths *paths)
{
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    struct stat st;
    int present = open_claim_node(context->data_fd, root->payload_path,
                                  physical, &parent_fd, leaf, sizeof(leaf),
                                  &st);
    if (present != 0)
        return present < 0 ? -1 : 0;
    if (!S_ISDIR(st.st_mode)) {
        int result = close(parent_fd);
        return result == 0 ? 0 : -1;
    }

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
    reconcile_test_descend_hook(parent_fd, leaf);
#endif
    int directory_fd = open_child_directory(parent_fd, leaf);
    int saved = errno;
    if (close(parent_fd) != 0) {
        if (directory_fd >= 0)
            close(directory_fd);
        return -1;
    }
    if (directory_fd < 0) {
        errno = saved;
        return errno == ENOENT ? 0 : -1;
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

        char child_physical[SIDECAR_MAX_PATH + 1U];
        if (append_physical(child_physical, sizeof(child_physical), physical,
                            entry->d_name) != 0) {
            failed = 1;
            break;
        }
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
        reconcile_test_child_stat_hook(directory_fd, entry->d_name);
#endif
        struct stat child_stat;
        if (fstatat(directory_fd, entry->d_name, &child_stat,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT)
                continue;
            failed = 1;
            break;
        }
        const char *live_logical = NULL;
        const PortableClaimedPath *claim = NULL;
        if (reconcile_claim_owner(paths, root->id, child_physical,
                                   &live_logical, &claim) != 0) {
            failed = 1;
            break;
        }
        const char *owner_logical = claim != NULL ? claim->logical_path
                                                   : live_logical;
        int visited = visited_contains(context->visited, root->id,
                                       owner_logical);
        if (visited != 0) {
            failed = 1;
            break;
        }
        if (S_ISDIR(child_stat.st_mode) &&
            reconcile_claim_validate_node(context, root, child_physical,
                                          paths) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int append_claim_delete(PortableCaptureContext *context,
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

static int reconcile_mutate_known_node(PortableCaptureContext *context,
                                       const PortableRootSpec *root,
                                       const char *logical,
                                       const char *physical,
                                       int claim_owned,
                                       const ClaimOwnershipPaths *paths)
{
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    struct stat st;
    int present = open_claim_node(context->data_fd, root->payload_path,
                                  physical, &parent_fd, leaf, sizeof(leaf),
                                  &st);
    if (present < 0)
        return -1;
    if (present == 1)
        return claim_owned ? append_claim_delete(context, root, logical)
                           : tombstone_if_live(context, root->id, logical);

    if (S_ISDIR(st.st_mode)) {
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
        reconcile_test_descend_hook(parent_fd, leaf);
#endif
        int directory_fd = open_child_directory(parent_fd, leaf);
        int saved = errno;
        if (close(parent_fd) != 0) {
            if (directory_fd >= 0)
                close(directory_fd);
            return -1;
        }
        if (directory_fd < 0) {
            errno = saved;
            if (errno != ENOENT)
                return -1;
        } else {
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

                char child_physical[SIDECAR_MAX_PATH + 1U];
                if (append_physical(child_physical, sizeof(child_physical),
                                    physical, entry->d_name) != 0) {
                    failed = 1;
                    break;
                }
                struct stat child_stat;
                if (fstatat(directory_fd, entry->d_name, &child_stat,
                            AT_SYMLINK_NOFOLLOW) != 0) {
                    if (errno == ENOENT)
                        continue;
                    failed = 1;
                    break;
                }
                const char *live_logical = NULL;
                const PortableClaimedPath *claim = NULL;
                if (reconcile_claim_owner(paths, root->id, child_physical,
                                           &live_logical, &claim) != 0) {
                    failed = 1;
                    break;
                }
                const char *owner_logical = claim != NULL
                                                 ? claim->logical_path
                                                 : live_logical;
                if (visited_contains(context->visited, root->id,
                                     owner_logical) != 0) {
                    failed = 1;
                    break;
                }
                if (reconcile_mutate_known_node(
                        context, root, owner_logical, child_physical,
                        claim != NULL, paths) != 0) {
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
    } else if (close(parent_fd) != 0) {
        return -1;
    }

    if (claim_owned) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_owned_payload_relative(context->data_fd,
                                          root->payload_path, physical) != 0)
            return -1;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
        return append_claim_delete(context, root, logical);
    }
    if (tombstone_if_live(context, root->id, logical) != 0)
        return -1;
    return remove_owned_payload_relative(context->data_fd, root->payload_path,
                                         physical);
}

static int reconcile_stale_claim_with_paths(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, const char *physical, SidecarObjectKind kind,
    const ClaimOwnershipPaths *paths)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL || paths == NULL ||
        (physical[0] == '\0' && logical[0] != '\0') ||
        (kind != SIDECAR_KIND_REGULAR && kind != SIDECAR_KIND_DIRECTORY &&
         kind != SIDECAR_KIND_SYMLINK && kind != SIDECAR_KIND_HARDLINK))
        return -1;
    if (reconcile_claim_validate_node(context, root, physical, paths) != 0)
        return -1;
    return reconcile_mutate_known_node(context, root, logical, physical, 1,
                                       paths);
}

int reconcile_stale_claim(PortableCaptureContext *context,
                                 const PortableRootSpec *root,
                                 const char *logical,
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

    char *physical = NULL;
    if (sidecar_bytes_to_text(claim->physical_path, &physical) != 0)
        return -1;

    PortableOwnedPaths owned = {0};
    PortableClaimedPaths claimed = {0};
    int result = -1;
    if (portable_owned_paths_load(&owned, context->sidecar) == 0 &&
        portable_claimed_paths_load(&claimed, context->sidecar) == 0) {
        ClaimOwnershipPaths paths = {
            .owned = &owned,
            .claimed = &claimed
        };
        result = reconcile_stale_claim_with_paths(
            context, root, logical, physical, claim->kind, &paths);
    }
    portable_claimed_paths_free(&claimed);
    portable_owned_paths_free(&owned);
    free(physical);
    return result;
}

int prepare_collision_relocations(PortableCaptureContext *context,
                                          const PortableRootSpec *root)
{
    if (context == NULL || root == NULL)
        return -1;
    if (!context->resume_mode || context->collision_plan == NULL)
        return 0;
    if (context->owned_paths == NULL || context->claimed_paths == NULL)
        return -1;

    PortableOwnedPaths *owned = context->owned_paths;
    PortableClaimedPaths *claimed = context->claimed_paths;
    const PortableCollisionPlan *plan = context->collision_plan;
    for (size_t plan_index = 0; plan_index < plan->count; plan_index++) {
        const PortableCollisionPlanEntry *planned = &plan->entries[plan_index];
        if (strcmp(planned->root_id, root->id) != 0)
            continue;

        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)planned->logical_path,
            strlen(planned->logical_path)
        };
        SidecarLiveView previous = {0};
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0)
            return -1;
        SidecarClaimView previous_claim = {0};
        int claim_found = sidecar_log_find_claim(context->sidecar, root_key,
                                                 logical_key,
                                                 &previous_claim);
        if (claim_found < 0)
            return -1;
        if (live == 1 && claim_found == 1)
            return -1;
        if (!live && !claim_found)
            continue;

        SidecarBytes old_physical_bytes = live == 1
            ? previous.entry->physical_path
            : previous_claim.claim->physical_path;
        if (sidecar_bytes_equal(
                old_physical_bytes,
                (SidecarBytes){
                    (const unsigned char *)planned->physical_path,
                    strlen(planned->physical_path) }))
            continue;

        char *old_physical = NULL;
        if (sidecar_bytes_to_text(old_physical_bytes, &old_physical) != 0 ||
            old_physical[0] == '\0' ||
            !safe_relative_path(old_physical) ||
            !safe_relative_path(planned->physical_path)) {
            free(old_physical);
            return -1;
        }

        if (live == 1) {
            size_t candidate_count = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) != 0 ||
                    !relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    continue;
                if (!relative_path_prefix_match(
                        old_physical, candidate->physical_path, NULL) ||
                    !safe_relative_path(candidate->physical_path)) {
                    free(old_physical);
                    return -1;
                }
                candidate_count++;
            }
            if (candidate_count == 0) {
                free(old_physical);
                return -1;
            }

            unsigned char *selected = calloc(owned->count,
                                             sizeof(*selected));
            if (selected == NULL) {
                free(old_physical);
                return -1;
            }
            int failed = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) == 0 &&
                    relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL)) {
                    selected[index] = 1;
                    if (tombstone_if_live(context, root->id,
                                          candidate->logical_path) != 0) {
                        failed = 1;
                        break;
                    }
                }
            }

            for (size_t removed = 0; !failed && removed < candidate_count;
                 removed++) {
                size_t selected_index = SIZE_MAX;
                size_t selected_depth = 0;
                for (size_t index = 0; index < owned->count; index++) {
                    relocation_scan_count();
                    if (selected[index] != 1)
                        continue;
                    size_t depth = relative_path_depth(
                        owned->items[index].physical_path);
                    if (selected_index == SIZE_MAX || depth > selected_depth) {
                        selected_index = index;
                        selected_depth = depth;
                    }
                }
                if (selected_index == SIZE_MAX) {
                    failed = 1;
                    break;
                }
                relocation_remove_count();
                if (remove_owned_payload_relative(
                        context->data_fd, root->payload_path,
                        owned->items[selected_index].physical_path) != 0) {
                    failed = 1;
                    break;
                }
                selected[selected_index] = 2;
            }
            free(selected);
            if (failed) {
                free(old_physical);
                return -1;
            }
        }

        if (claim_found == 1) {
            /* A directory CLAIM owns only its node; known live and claimed
             * descendants must be removed deepest-first.  Unknown children
             * make the non-recursive removal fail closed. */
            size_t owned_candidate_count = 0;
            size_t claimed_candidate_count = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) != 0 ||
                    !relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    continue;
                if (!relative_path_prefix_match(
                        old_physical, candidate->physical_path, NULL) ||
                    !safe_relative_path(candidate->physical_path)) {
                    free(old_physical);
                    return -1;
                }
                owned_candidate_count++;
            }
            for (size_t index = 0; index < claimed->count; index++) {
                relocation_scan_count();
                PortableClaimedPath *candidate = &claimed->items[index];
                if (strcmp(candidate->root_id, root->id) != 0 ||
                    !relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    continue;
                if (!relative_path_prefix_match(
                        old_physical, candidate->physical_path, NULL) ||
                    !safe_relative_path(candidate->physical_path)) {
                    free(old_physical);
                    return -1;
                }
                claimed_candidate_count++;
            }
            if (claimed_candidate_count == 0) {
                free(old_physical);
                return -1;
            }

            unsigned char *selected_owned = owned->count == 0
                ? NULL : calloc(owned->count, sizeof(*selected_owned));
            unsigned char *selected_claimed = claimed->count == 0
                ? NULL : calloc(claimed->count, sizeof(*selected_claimed));
            if ((owned->count != 0 && selected_owned == NULL) ||
                (claimed->count != 0 && selected_claimed == NULL)) {
                free(selected_owned);
                free(selected_claimed);
                free(old_physical);
                return -1;
            }

            int failed = 0;
            for (size_t index = 0; index < owned->count; index++) {
                relocation_scan_count();
                PortableOwnedPath *candidate = &owned->items[index];
                if (strcmp(candidate->root_id, root->id) == 0 &&
                    relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL)) {
                    selected_owned[index] = 1;
                    if (tombstone_if_live(context, root->id,
                                          candidate->logical_path) != 0) {
                        failed = 1;
                        break;
                    }
                }
            }
            for (size_t index = 0; index < claimed->count; index++) {
                if (failed)
                    break;
                relocation_scan_count();
                PortableClaimedPath *candidate = &claimed->items[index];
                if (strcmp(candidate->root_id, root->id) == 0 &&
                    relative_path_prefix_match(
                        planned->logical_path, candidate->logical_path, NULL))
                    selected_claimed[index] = 1;
            }

            size_t remaining = owned_candidate_count + claimed_candidate_count;
            for (size_t removed = 0; !failed && removed < remaining; removed++) {
                int selected_is_owned = 0;
                size_t selected_index = SIZE_MAX;
                size_t selected_depth = 0;
                for (size_t index = 0; index < owned->count; index++) {
                    relocation_scan_count();
                    if (selected_owned[index] != 1)
                        continue;
                    size_t depth = relative_path_depth(
                        owned->items[index].physical_path);
                    if (selected_index == SIZE_MAX || depth > selected_depth) {
                        selected_index = index;
                        selected_depth = depth;
                        selected_is_owned = 1;
                    }
                }
                for (size_t index = 0; index < claimed->count; index++) {
                    relocation_scan_count();
                    if (selected_claimed[index] != 1)
                        continue;
                    size_t depth = relative_path_depth(
                        claimed->items[index].physical_path);
                    if (selected_index == SIZE_MAX || depth > selected_depth) {
                        selected_index = index;
                        selected_depth = depth;
                        selected_is_owned = 0;
                    }
                }
                if (selected_index == SIZE_MAX) {
                    failed = 1;
                    break;
                }
                relocation_remove_count();
                if (selected_is_owned) {
                    if (remove_owned_payload_relative(
                            context->data_fd, root->payload_path,
                            owned->items[selected_index].physical_path) != 0) {
                        failed = 1;
                        break;
                    }
                    selected_owned[selected_index] = 2;
                } else {
                    PortableClaimedPath *candidate =
                        &claimed->items[selected_index];
                    if (remove_owned_payload_relative(
                            context->data_fd, root->payload_path,
                            candidate->physical_path) != 0 ||
                        append_claim_delete(context, root,
                                            candidate->logical_path) != 0) {
                        failed = 1;
                        break;
                    }
                    selected_claimed[selected_index] = 2;
                }
            }
            free(selected_owned);
            free(selected_claimed);
            if (failed) {
                free(old_physical);
                return -1;
            }
        }

        free(old_physical);
    }
    return 0;
}

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} InventoryOrphans;

static void inventory_orphans_free(InventoryOrphans *orphans)
{
    if (orphans == NULL)
        return;
    for (size_t index = 0; index < orphans->count; index++)
        free(orphans->items[index]);
    free(orphans->items);
    memset(orphans, 0, sizeof(*orphans));
}

static int inventory_orphans_append(InventoryOrphans *orphans,
                                    const char *relative)
{
    if (orphans == NULL || relative == NULL)
        return -1;
    if (orphans->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (orphans->count == orphans->capacity) {
        size_t capacity = orphans->capacity == 0 ? 16U : orphans->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < orphans->capacity ||
            capacity > SIZE_MAX / sizeof(*orphans->items))
            return -1;
        char **items = realloc(orphans->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        orphans->items = items;
        orphans->capacity = capacity;
    }
    char *copy = strdup(relative);
    if (copy == NULL)
        return -1;
    orphans->items[orphans->count++] = copy;
    return 0;
}

typedef struct {
    PortableCaptureContext *context;
    const char *root_id;
    PortableVisited live_paths;
    PortableVisited physical_directories;
    PortableVisited seen_paths;
    InventoryOrphans orphans;
    int orphan_root;
    int failed;
    size_t live_count;
} InventoryState;

static int inventory_live_callback(const SidecarLiveView *view, void *argument)
{
    InventoryState *inventory = argument;
    if (inventory == NULL || inventory->root_id == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->entry->root_id,
            (SidecarBytes){ (const unsigned char *)inventory->root_id,
                            strlen(inventory->root_id) }))
        return 0;
    char *physical = NULL;
    if (sidecar_bytes_to_text(view->entry->physical_path, &physical) != 0) {
        inventory->failed = 1;
        return 1;
    }
    int inserted = visited_add(&inventory->live_paths, inventory->root_id,
                               physical);
    if (inserted != 0) {
        inventory->failed = 1;
        free(physical);
        return 1;
    }
    if (view->entry->kind == SIDECAR_KIND_DIRECTORY &&
        visited_add(&inventory->physical_directories, inventory->root_id,
                    physical) != 0) {
        inventory->failed = 1;
        free(physical);
        return 1;
    }
    inventory->live_count++;
    free(physical);
    return 0;
}

static int inventory_scan_node(InventoryState *inventory,
                               int parent_fd, const char *leaf,
                               const char *relative, int is_root)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    SidecarBytes key = {
        (const unsigned char *)relative, strlen(relative)
    };
    SidecarLiveView live_view;
    int live = sidecar_log_find(inventory->context->sidecar,
                                (SidecarBytes){
                                    (const unsigned char *)inventory->root_id,
                                    strlen(inventory->root_id)
                                }, key, &live_view);
    if (live < 0)
        return -1;
    SidecarObjectKind expected_kind = SIDECAR_KIND_REGULAR;
    if (live == 1 &&
        sidecar_bytes_equal(live_view.entry->physical_path, key))
        expected_kind = live_view.entry->kind;
    else {
        int physical_present = visited_contains(&inventory->live_paths,
                                                inventory->root_id, relative);
        if (physical_present < 0)
            return -1;
        if (physical_present == 1) {
            int is_directory = visited_contains(
                &inventory->physical_directories, inventory->root_id,
                relative);
            if (is_directory < 0)
                return -1;
            live = 1;
            expected_kind = is_directory == 1 ? SIDECAR_KIND_DIRECTORY :
                                                SIDECAR_KIND_REGULAR;
        } else if (live == 1) {
            live = 0;
        }
    }
    if (live == 0) {
        int deleted = sidecar_log_find_deleted(
            inventory->context->sidecar,
            (SidecarBytes){ (const unsigned char *)inventory->root_id,
                            strlen(inventory->root_id) },
            key, &live_view);
        if (deleted < 0)
            return -1;
        if (deleted == 1) {
            if (is_root)
                inventory->orphan_root = 1;
            else if (inventory_orphans_append(&inventory->orphans,
                                              relative) != 0)
                return -1;
            return 0;
        }
        inventory->failed = 1;
        return -1;
    }

    if (visited_add(&inventory->seen_paths, inventory->root_id, relative) != 0)
        return -1;
    if ((expected_kind == SIDECAR_KIND_DIRECTORY) !=
        (S_ISDIR(st.st_mode) != 0))
        return -1;
    if (!S_ISDIR(st.st_mode))
        return 0;

    int directory_fd = open_child_directory(parent_fd, leaf);
    if (directory_fd < 0)
        return -1;
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
        char child_relative[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_relative, sizeof(child_relative), relative,
                           entry->d_name) != 0 ||
            inventory_scan_node(inventory, directory_fd, entry->d_name,
                                child_relative, 0) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    if (close(directory_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int inventory_seen_callback(const SidecarLiveView *view,
                                   void *argument)
{
    InventoryState *inventory = argument;
    if (inventory == NULL || inventory->root_id == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
    if (!sidecar_bytes_equal(
            view->entry->root_id,
            (SidecarBytes){ (const unsigned char *)inventory->root_id,
                            strlen(inventory->root_id) }))
        return 0;
    char *physical = NULL;
    if (sidecar_bytes_to_text(view->entry->physical_path, &physical) != 0) {
        inventory->failed = 1;
        return 1;
    }
    int present = visited_contains(&inventory->seen_paths,
                                   inventory->root_id, physical);
    free(physical);
    if (present != 1) {
        inventory->failed = 1;
        return 1;
    }
    return 0;
}

static int reconcile_inventory(PortableCaptureContext *context,
                               const PortableRootSpec *root)
{
    InventoryState inventory;
    memset(&inventory, 0, sizeof(inventory));
    inventory.context = context;
    inventory.root_id = root->id;
    inventory.live_paths.hash_salt = sidecar_process_salt();
    inventory.physical_directories.hash_salt = inventory.live_paths.hash_salt;
    inventory.seen_paths.hash_salt = inventory.live_paths.hash_salt;

    SidecarStatus status = sidecar_log_foreach(context->sidecar,
                                               inventory_live_callback,
                                               &inventory);
    if (status != SIDECAR_STATUS_OK || inventory.failed)
        goto fail;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(context->data_fd, root->payload_path,
                                     &root_parent, root_leaf,
                                     sizeof(root_leaf)) != 0) {
        if (errno == ENOENT && inventory.live_count == 0) {
            inventory_orphans_free(&inventory.orphans);
            visited_dispose(&inventory.live_paths);
            visited_dispose(&inventory.physical_directories);
            visited_dispose(&inventory.seen_paths);
            return 0;
        }
        goto fail;
    }

    if (inventory_scan_node(&inventory, root_parent, root_leaf, "", 1) != 0)
        goto close_fail;
    if (close(root_parent) != 0)
        goto fail;
    root_parent = -1;

    if (inventory.orphan_root) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_payload_relative(context->data_fd, root->payload_path,
                                     "") != 0)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
    }
    for (size_t index = 0; index < inventory.orphans.count; index++) {
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_payload_relative(context->data_fd, root->payload_path,
                                     inventory.orphans.items[index]) != 0)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
    }

    status = sidecar_log_foreach(context->sidecar, inventory_seen_callback,
                                 &inventory);
    if (status != SIDECAR_STATUS_OK || inventory.failed)
        goto fail;

    inventory_orphans_free(&inventory.orphans);
    visited_dispose(&inventory.live_paths);
    visited_dispose(&inventory.physical_directories);
    visited_dispose(&inventory.seen_paths);
    return 0;

close_fail:
    {
        int saved = errno;
        close(root_parent);
        errno = saved;
    }
fail:
    inventory_orphans_free(&inventory.orphans);
    visited_dispose(&inventory.live_paths);
    visited_dispose(&inventory.physical_directories);
    visited_dispose(&inventory.seen_paths);
    return -1;
}

int reconcile_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    StaleKeys stale;
    StaleClaims stale_claims;
    PortableOwnedPaths owned;
    PortableClaimedPaths claimed;
    memset(&stale, 0, sizeof(stale));
    memset(&stale_claims, 0, sizeof(stale_claims));
    memset(&owned, 0, sizeof(owned));
    memset(&claimed, 0, sizeof(claimed));
    StaleCollection collection = {
        .context = context,
        .root_id = root->id,
        .stale = &stale
    };
    SidecarStatus status = sidecar_log_foreach(context->sidecar,
                                               collect_stale_key,
                                               &collection);
    if (status != SIDECAR_STATUS_OK || stale.failed)
        goto fail;

    for (size_t index = 0; index < stale.count; index++) {
        SidecarDelete deletion = {
            .root_id = { (const unsigned char *)root->id,
                        strlen(root->id) },
            .logical_path = { (const unsigned char *)stale.items[index].logical,
                              strlen(stale.items[index].logical) }
        };
        if (sidecar_log_append_delete(context->sidecar, &deletion) !=
            SIDECAR_STATUS_OK)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_DELETE);
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_STALE_UNLINK);
        if (remove_payload_relative(context->data_fd, root->payload_path,
                                    stale.items[index].physical) != 0)
            goto fail;
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_STALE_UNLINK);
    }

    stale_keys_free(&stale);
    StaleClaimCollection claim_collection = {
        .context = context,
        .root_id = root->id,
        .stale = &stale_claims
    };
    status = sidecar_log_claim_foreach(context->sidecar, collect_stale_claim,
                                       &claim_collection);
    if (status != SIDECAR_STATUS_OK || stale_claims.failed)
        goto fail;
    if (portable_owned_paths_load(&owned, context->sidecar) != 0 ||
        portable_claimed_paths_load(&claimed, context->sidecar) != 0)
        goto fail;

    ClaimOwnershipPaths paths = {
        .owned = &owned,
        .claimed = &claimed
    };
    for (size_t index = 0; index < stale_claims.count; index++) {
        StaleClaim *claim = &stale_claims.items[index];
        if (reconcile_stale_claim_with_paths(
                context, root, claim->logical, claim->physical, claim->kind,
                &paths) != 0)
            goto fail;
    }

    portable_claimed_paths_free(&claimed);
    portable_owned_paths_free(&owned);
    stale_claims_free(&stale_claims);
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_FINAL_INVENTORY);
    return reconcile_inventory(context, root);

fail:
    stale_keys_free(&stale);
    portable_claimed_paths_free(&claimed);
    portable_owned_paths_free(&owned);
    stale_claims_free(&stale_claims);
    return -1;
}
