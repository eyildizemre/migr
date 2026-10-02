#define _GNU_SOURCE

#include "live_state.h"
#include "portable_restore_internal.h"
#include "portable_restore_replay_internal.h"
#include "portable_restore.h"
#include "podman_state.h"
#include "backup.h"
#include "home_rewrite.h"
#include "manifest.h"
#include "metadata.h"
#include "portable.h"
#include "portable_fsops_internal.h"
#include "sidecar.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    const SidecarEntry *entry;
    const SidecarXattr *xattrs;
    size_t xattr_count;
    size_t root_index;
    size_t hardlink_ref_root_index;
    const SidecarEntry *hardlink_ref_entry;
    DestinationIdentityPlacement identity_placement;
    size_t destination_order;
    uint64_t content_digest;
    int content_digest_valid;
    /* The payload read from the backup did not match its capture digest. */
    int payload_differs;
    unsigned char directory_state;
    /* Live desktop state already present at the destination (D65). */
    int kept_live_state;
    /* REPLAY_DEFERRED_* (D66). */
    unsigned char deferral;
    /* The regular file as replay left it: identity, size, and mtime right
     * after its last metadata step (D67). */
    int written_valid;
    dev_t written_dev;
    ino_t written_ino;
    off_t written_size;
    struct timespec written_mtime;
} ReplayEntry;

enum {
    REPLAY_NOT_DEFERRED = 0,
    REPLAY_DEFERRED,
    REPLAY_DEFERRED_SKIPPED,
    REPLAY_LEFT_OUT /* Podman container state that would not work here (D94). */
};

enum {
    REPLAY_DIRECTORY_UNTOUCHED = 0,
    REPLAY_DIRECTORY_PREPARED,
    REPLAY_DIRECTORY_FINALIZED
};

/* ReplayEntry and RestoreAddressIndex share the same bounded allocation
 * budget. Keep per-entry replay state compact enough that the maximum live
 * entry count cannot consume more than half of that budget by itself. */
_Static_assert((uint64_t)sizeof(ReplayEntry) <=
                   SIDECAR_MAX_ALLOC_BUDGET /
                       (UINT64_C(2) * SIDECAR_MAX_LIVE_ENTRIES),
               "ReplayEntry exceeds its shared preflight-memory envelope");

/* One most-recent destination parent captures sibling locality without
 * retaining an fd per directory. */
typedef struct {
    int fd;
    int base_fd;
    char prefix[PATH_MAX];
} ReplayParentCache;

/* Payload locality is keyed by authenticated logical-parent identity rather
 * than by any reconstructed physical pathname. */
typedef struct {
    int fd;
    size_t parent_address_index;
} ReplayPayloadParentCache;

typedef struct {
    ReplayEntry *items;
    size_t count;
    size_t capacity;
    PreflightMemory memory;
    const Manifest *manifest;
    RootMap root_map;
    RestoreAddressIndex address_index;
    const SidecarLog *sidecar;
    int data_fd;
    int destination_home_fd;
    const char *destination_home_path;
    const char * const *destination_xdg_dirs;
    const HomeRewritePair *home_rewrite_pairs;
    size_t home_rewrite_pair_count;
    int xdg_anchor_fd[XDG_KEY_COUNT];
    char xdg_anchor_prefix[XDG_KEY_COUNT][PATH_MAX];
    ReplayParentCache parent_cache;
    ReplayParentCache verification_parent_cache;
    ReplayPayloadParentCache payload_cache;
    MetadataTimestampPolicy timestamp_policy;
    OwnerMap owner_map;
    PortableRestoreReplayReport *report;
    BackupCaptureReport *capture_report;
    MetadataXattrRequirements xattr_requirements;
    int skip_content_verification;
    void (*before_content_verification)(void *context);
    void *before_content_verification_context;
    int *dconf_database_fd_out;
    int dconf_loads_into_session;
    const PortableRestoreDeferredPath *deferred_paths;
    size_t deferred_path_count;
    int (*before_deferred)(void *context);
    void *before_deferred_context;
    PodmanContainers *left_out_containers;
} ReplayCollection;

typedef struct {
    size_t total_count;
    struct timespec started_at;
    struct timespec last_real_redraw;
    ProgressTicker ticker;
    int active;
    int ticker_started;
} ReplayVerificationProgress;

typedef struct {
    PortableRestoreReplayFailureStep step;
    int err;
} ReplayApplyFailure;

static int replay_hardlink_ref_relative(const ManifestRoot *ref_root,
                                        const SidecarEntry *ref_entry,
                                        const char * const *xdg_dirs,
                                        char *out, size_t out_size);

void replay_copy_bytes(char *destination, size_t destination_size,
                       SidecarBytes source)
{
    if (destination == NULL || destination_size == 0)
        return;
    if (source.length >= destination_size ||
        (source.length != 0 && source.data == NULL) ||
        (source.length != 0 &&
         memchr(source.data, '\0', source.length) != NULL))
    {
        destination[0] = '\0';
        return;
    }
    if (source.length != 0)
        memcpy(destination, source.data, source.length);
    destination[source.length] = '\0';
}

static void replay_report_failure(PortableRestoreReplayReport *report,
                                  const Manifest *manifest,
                                  size_t root_index,
                                  SidecarBytes logical)
{
    if (report == NULL)
        return;
    if (report->failed_count != SIZE_MAX)
        report->failed_count++;
    if (manifest != NULL && root_index < (size_t)manifest->root_count)
        snprintf(report->failed_root_id, sizeof(report->failed_root_id), "%s",
                 manifest->roots[root_index].id);
    replay_copy_bytes(report->failed_logical_path,
                      sizeof(report->failed_logical_path), logical);
}

static void replay_report_step_failure(
    PortableRestoreReplayReport *report, const Manifest *manifest,
    size_t root_index, const SidecarEntry *entry,
    PortableRestoreReplayFailureStep step, int err)
{
    replay_report_failure(report, manifest, root_index,
                          entry == NULL ? (SidecarBytes){0} :
                                          entry->logical_path);
    if (report == NULL || step == PORTABLE_RESTORE_REPLAY_FAILURE_NONE)
        return;
    if (entry != NULL && replay_failure_kind_text(entry->kind) != NULL)
    {
        report->failed_kind = entry->kind;
        report->failed_kind_valid = 1;
    }
    report->failure_step = step;
    report->failure_errno = err;
}

static void replay_apply_failure_record(
    ReplayApplyFailure *failure, PortableRestoreReplayFailureStep step, int err)
{
    if (failure == NULL || failure->step != PORTABLE_RESTORE_REPLAY_FAILURE_NONE ||
        step == PORTABLE_RESTORE_REPLAY_FAILURE_NONE)
        return;
    failure->step = step;
    failure->err = err != 0 ? err : EIO;
}

static void replay_report_apply_failure(
    PortableRestoreReplayReport *report, const Manifest *manifest,
    size_t root_index, const SidecarEntry *entry,
    const ReplayApplyFailure *failure)
{
    replay_report_step_failure(
        report, manifest, root_index, entry,
        failure == NULL ? PORTABLE_RESTORE_REPLAY_FAILURE_NONE : failure->step,
        failure == NULL ? 0 : failure->err);
}

const char *replay_failure_kind_text(SidecarObjectKind kind)
{
    switch (kind)
    {
        case SIDECAR_KIND_REGULAR: return "regular file";
        case SIDECAR_KIND_DIRECTORY: return "directory";
        case SIDECAR_KIND_FIFO: return "FIFO";
        case SIDECAR_KIND_SYMLINK: return "symlink";
        case SIDECAR_KIND_HARDLINK: return "hardlink";
    }
    return NULL;
}

const char *replay_failure_step_text(PortableRestoreReplayFailureStep step)
{
    switch (step)
    {
        case PORTABLE_RESTORE_REPLAY_FAILURE_FIND_ROOT:
            return "find manifest root";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_SIDECAR_PATH:
            return "validate sidecar path";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY:
            return "validate entry metadata";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ADDRESS_INDEX:
            return "validate restore address index";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_MANIFEST_OWNERSHIP:
            return "validate manifest ownership";
        case PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_HOME_REWRITE_TABLE:
            return "build HOME URI rewrite table";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_PLACEHOLDER:
            return "verify placeholder payload";
        case PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_ENTRY:
            return "resolve hardlink entry";
        case PORTABLE_RESTORE_REPLAY_FAILURE_FIND_HARDLINK_ROOT:
            return "find hardlink reference root";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_HARDLINK_OWNERSHIP:
            return "validate hardlink reference ownership";
        case PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_HARDLINK_DESTINATION:
            return "build hardlink reference destination";
        case PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_ENTRY_STAT:
            return "build entry metadata";
        case PORTABLE_RESTORE_REPLAY_FAILURE_RESERVE_ENTRY:
            return "reserve replay entry";
        case PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_DESTINATION_PATH:
            return "build destination path";
        case PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_ADDRESS_INDEX:
            return "build restore address index";
        case PORTABLE_RESTORE_REPLAY_FAILURE_REGISTER_DESTINATION_ANCHOR:
            return "register destination anchor";
        case PORTABLE_RESTORE_REPLAY_FAILURE_MAP_DESTINATION_IDENTITY:
            return "map destination identity";
        case PORTABLE_RESTORE_REPLAY_FAILURE_FINALIZE_DESTINATION_IDENTITY:
            return "finalize destination identity";
        case PORTABLE_RESTORE_REPLAY_FAILURE_ORDER_DESTINATION_IDENTITY:
            return "order destination identity";
        case PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_PAYLOAD:
            return "open backup payload";
        case PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT:
            return "resolve destination parent";
        case PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION:
            return "check destination";
        case PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_DESTINATION:
            return "open destination";
        case PORTABLE_RESTORE_REPLAY_FAILURE_COPY_CONTENT:
            return "copy content";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_PAYLOAD:
            return "verify backup payload";
        case PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_OWNERSHIP_MODE:
            return "apply ownership/mode";
        case PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_XATTRS:
            return "apply xattrs";
        case PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES:
            return "apply timestamps";
        case PORTABLE_RESTORE_REPLAY_FAILURE_CREATE_SYMLINK:
            return "create symlink";
        case PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_REFERENCE:
            return "resolve hardlink reference";
        case PORTABLE_RESTORE_REPLAY_FAILURE_CREATE_HARDLINK:
            return "create hardlink";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_HARDLINK:
            return "verify hardlink";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH:
            return "verify restored destination path";
        case PORTABLE_RESTORE_REPLAY_FAILURE_READ_DESTINATION_CONTENT:
            return "read restored content";
        case PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_DESTINATION_CONTENT:
            return "content differs from the backup";
        case PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_BACKUP_CONTENT:
            return "the backup's copy changed after it was captured";
        case PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK:
            return "verify restored hardlink";
        case PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR:
            return "close descriptor";
        case PORTABLE_RESTORE_REPLAY_FAILURE_NONE:
            break;
    }
    return NULL;
}

int replay_failure_reason_format(const PortableRestoreReplayReport *report,
                                 char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
        return -1;
    out[0] = '\0';
    if (report == NULL ||
        report->failure_step == PORTABLE_RESTORE_REPLAY_FAILURE_NONE)
        return 0;

    const char *step = replay_failure_step_text(report->failure_step);
    const char *kind = report->failed_kind_valid
        ? replay_failure_kind_text(report->failed_kind) : NULL;
    if (step == NULL || (report->failed_kind_valid && kind == NULL))
        return 0;
    // A comparison that fails has found a difference and records EIO; read
    // errors have their own steps, so it must not read like a disk failure.
    int failure_errno =
        report->failure_step ==
                PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_DESTINATION_CONTENT ||
        report->failure_step ==
                PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_BACKUP_CONTENT
            ? 0 : report->failure_errno;
    int length;
    if (kind != NULL && failure_errno != 0)
        length = snprintf(out, out_size, "%s, %s: %s", kind, step,
                          strerror(failure_errno));
    else if (kind != NULL)
        length = snprintf(out, out_size, "%s, %s", kind, step);
    else if (failure_errno != 0)
        length = snprintf(out, out_size, "%s: %s", step,
                          strerror(failure_errno));
    else
        length = snprintf(out, out_size, "%s", step);
    if (length < 0 || (size_t)length >= out_size)
    {
        out[0] = '\0';
        return -1;
    }
    return 1;
}

static void replay_report_security_skipped(
    PortableRestoreReplayReport *report, size_t count)
{
    if (report == NULL || count == 0 ||
        report->skipped_security_xattr_count == SIZE_MAX)
        return;
    if (count > SIZE_MAX - report->skipped_security_xattr_count)
        report->skipped_security_xattr_count = SIZE_MAX;
    else
        report->skipped_security_xattr_count += count;
}

// Names one entry in the log's full list of what the summary counts (D79).
static void replay_log_entry(const ReplayCollection *collection,
                             const ReplayEntry *replay, const char *what)
{
    char logical[PATH_MAX];
    replay_copy_bytes(logical, sizeof(logical), replay->entry->logical_path);
    run_log_printf("%s: %s:%s\n", what,
                   collection->manifest->roots[replay->root_index].id,
                   logical[0] != '\0' ? logical : ".");
}

static int replay_entries_reserve(ReplayCollection *collection, size_t extra)
{
    if (collection == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    ReplayEntry *items = preflight_array_reserve(
        &collection->memory, collection->items, &collection->capacity,
        collection->count, extra, sizeof(*items), 16U,
        SIDECAR_MAX_LIVE_ENTRIES, 1);
    if (items == NULL)
        return -1;
    collection->items = items;
    return 0;
}

static int replay_close_xdg_anchors(ReplayCollection *collection)
{
    int result = 0;
    int saved = errno;
    for (int index = 0; index < XDG_KEY_COUNT; index++)
    {
        if (collection->xdg_anchor_fd[index] < 0)
            continue;
        if (close(collection->xdg_anchor_fd[index]) != 0 && result == 0)
        {
            result = -1;
            saved = errno == 0 ? EIO : errno;
        }
        collection->xdg_anchor_fd[index] = -1;
    }
    errno = saved;
    return result;
}

static void replay_collection_free(ReplayCollection *collection)
{
    if (collection == NULL)
        return;
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        if (collection->xdg_anchor_fd[index] >= 0)
        {
            close(collection->xdg_anchor_fd[index]);
            collection->xdg_anchor_fd[index] = -1;
        }
    if (collection->parent_cache.fd >= 0)
    {
        (void)close(collection->parent_cache.fd);
        collection->parent_cache.fd = -1;
    }
    if (collection->verification_parent_cache.fd >= 0)
    {
        (void)close(collection->verification_parent_cache.fd);
        collection->verification_parent_cache.fd = -1;
    }
    if (collection->payload_cache.fd >= 0)
    {
        (void)close(collection->payload_cache.fd);
        collection->payload_cache.fd = -1;
    }
    preflight_free(&collection->memory, collection->items,
                   collection->capacity * sizeof(*collection->items));
    collection->items = NULL;
    collection->count = 0;
    collection->capacity = 0;
    restore_address_index_free(&collection->memory,
                               &collection->address_index);
    root_map_free(&collection->root_map);
}

static int replay_manifest_valid(const Manifest *manifest,
                                 const char * const *xdg_dirs,
                                 const char *destination_home)
{
    if (manifest == NULL || !manifest_selection_valid(manifest) ||
        manifest->representation != CLONE_PORTABLE_SIDECAR ||
        manifest->sidecar_version != SIDECAR_VERSION ||
        manifest->root_count < 0 || manifest->root_count > MANIFEST_MAX_ROOTS ||
        (manifest->root_count != 0 && manifest->roots == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    if (manifest->version == MANIFEST_SELECTION_VERSION &&
        (destination_home == NULL || destination_home[0] != '/'))
    {
        errno = EINVAL;
        return -1;
    }
    for (int index = 0; index < manifest->root_count; index++)
    {
        const ManifestRoot *root = &manifest->roots[index];
        if (!manifest_text_valid(root->id, sizeof(root->id), 1) ||
            !manifest_text_valid(root->payload_path,
                                 sizeof(root->payload_path), 1) ||
            !manifest_text_valid(root->source_path,
                                 sizeof(root->source_path), 0) ||
            !manifest_text_valid(root->restore_path,
                                 sizeof(root->restore_path), 0) ||
            !relative_path_valid(root->payload_path, 0) ||
            root->policy < ROOT_POLICY_XDG ||
            root->policy > ROOT_POLICY_MANUAL_NATIVE ||
            root->policy == ROOT_POLICY_MANUAL_NATIVE ||
            (root->policy == ROOT_POLICY_XDG &&
             !xdg_destination_valid(xdg_dirs, root)) ||
            (root->policy == ROOT_POLICY_HOME_RELATIVE &&
             (!root->has_restore_path ||
              !relative_path_valid(root->restore_path, 1))) ||
            (root->policy != ROOT_POLICY_HOME_RELATIVE &&
             root->has_restore_path))
        {
            errno = EINVAL;
            return -1;
        }
    }
    return 0;
}

int replay_entry_valid(const SidecarEntry *entry)
{
    if (entry == NULL ||
        (entry->kind != SIDECAR_KIND_REGULAR &&
         entry->kind != SIDECAR_KIND_DIRECTORY &&
         entry->kind != SIDECAR_KIND_SYMLINK &&
         entry->kind != SIDECAR_KIND_HARDLINK) ||
        (entry->kind != SIDECAR_KIND_REGULAR &&
         entry->kind != SIDECAR_KIND_DIRECTORY && entry->size != 0))
        return 0;
    if (entry->kind != SIDECAR_KIND_SYMLINK)
        return 1;
    return entry->symlink_target.data != NULL &&
           entry->symlink_target.length != 0 &&
           entry->symlink_target.length <= SIDECAR_MAX_SYMLINK_TARGET &&
           memchr(entry->symlink_target.data, '\0',
                  entry->symlink_target.length) == NULL;
}

int replay_stat_from_entry(const SidecarEntry *entry, struct stat *desired)
{
    if (entry == NULL || desired == NULL ||
        entry->mode > SIDECAR_MAX_MODE ||
        entry->atime_nsec > SIDECAR_MAX_NSEC ||
        entry->mtime_nsec > SIDECAR_MAX_NSEC ||
        entry->uid > SIDECAR_MAX_UID_GID ||
        entry->gid > SIDECAR_MAX_UID_GID)
    {
        errno = EINVAL;
        return -1;
    }

    memset(desired, 0, sizeof(*desired));
    mode_t type;
    if (sidecar_kind_to_type(entry->kind, &type) != 0)
        return -1;
    desired->st_mode = entry->mode | type;
    desired->st_uid = (uid_t)entry->uid;
    desired->st_gid = (gid_t)entry->gid;
    if ((uintmax_t)desired->st_uid != entry->uid ||
        (uintmax_t)desired->st_gid != entry->gid)
    {
        errno = EOVERFLOW;
        return -1;
    }
    desired->st_atim.tv_sec = (time_t)entry->atime_sec;
    desired->st_atim.tv_nsec = (long)entry->atime_nsec;
    desired->st_mtim.tv_sec = (time_t)entry->mtime_sec;
    desired->st_mtim.tv_nsec = (long)entry->mtime_nsec;
    if ((int64_t)desired->st_atim.tv_sec != entry->atime_sec ||
        (int64_t)desired->st_mtim.tv_sec != entry->mtime_sec)
    {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

// The entry's metadata as restored: the backup user's items go to the
// restoring user (D85).
static int replay_desired_stat(const ReplayCollection *collection,
                               const SidecarEntry *entry, struct stat *desired)
{
    if (replay_stat_from_entry(entry, desired) != 0)
        return -1;
    metadata_owner_map_apply(&collection->owner_map, desired);
    return 0;
}

static int replay_bytes_compare(SidecarBytes left, SidecarBytes right)
{
    size_t common = left.length < right.length ? left.length : right.length;
    int compare = common == 0 ? 0 : memcmp(left.data, right.data, common);
    if (compare != 0)
        return compare;
    if (left.length < right.length)
        return -1;
    if (left.length > right.length)
        return 1;
    return 0;
}

static SidecarBytes replay_logical_leaf(SidecarBytes logical)
{
    size_t start = 0;
    for (size_t i = 0; i < logical.length; i++)
        if (logical.data[i] == '/')
            start = i + 1U;
    return (SidecarBytes){
        .data = logical.length == 0 ? NULL : logical.data + start,
        .length = logical.length - start
    };
}

static int replay_entry_compare(const void *left, const void *right)
{
    const ReplayEntry *a = left;
    const ReplayEntry *b = right;
    if (a->destination_order < b->destination_order)
        return -1;
    if (a->destination_order > b->destination_order)
        return 1;

    SidecarBytes a_logical = a->entry->logical_path;
    SidecarBytes b_logical = b->entry->logical_path;
    int compare = replay_bytes_compare(replay_logical_leaf(a_logical),
                                       replay_logical_leaf(b_logical));
    if (compare != 0)
        return compare;
    compare = replay_bytes_compare(a->entry->root_id, b->entry->root_id);
    if (compare != 0)
        return compare;
    return replay_bytes_compare(a_logical, b_logical);
}

static int replay_open_payload(ReplayCollection *collection,
                               const ManifestRoot *root,
                               const SidecarEntry *entry, int *out_fd,
                               struct stat *out_stat);

/* Confirms the on-disk placeholder for a symlink or hardlink entry is
 * exactly the convention both kinds share: an empty regular file
 * (docs/DECISIONS.md D18, D22). Deliberately reused for SIDECAR_KIND_HARDLINK
 * as well as SIDECAR_KIND_SYMLINK -- both replay their real content from
 * elsewhere (the sidecar record's target string, or the referenced entry's
 * own payload), so the payload node itself only ever needs to prove it
 * was not tampered with. */
static int replay_symlink_placeholder_valid(ReplayCollection *collection,
                                            const ManifestRoot *root,
                                            const SidecarEntry *entry)
{
    if (collection == NULL || root == NULL || entry == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    int payload_fd = -1;
    struct stat payload_st;
    if (replay_open_payload(collection, root, entry, &payload_fd,
                            &payload_st) != 0)
        return -1;
    int result = S_ISREG(payload_st.st_mode) && payload_st.st_size == 0
        ? 0 : -1;
    int saved = errno;
    if (result != 0)
        saved = EIO;
    if (close(payload_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
    }
    errno = saved;
    return result;
}

/* Maps a sidecar entry kind to the MetadataXattrRequirements field (metadata.h)
 * its xattr namespaces accumulate into. SIDECAR_KIND_HARDLINK deliberately
 * maps to NULL: a hardlink alias carries no independent xattrs of its own
 * (docs/DECISIONS.md D22) -- its representative's REGULAR entry is what
 * accumulates them. If MetadataXattrRequirements ever grows a fourth field,
 * this is the other place that needs it. */
static unsigned int *replay_xattr_requirements_field(
    MetadataXattrRequirements *requirements, SidecarObjectKind kind)
{
    if (requirements == NULL)
        return NULL;
    switch (kind)
    {
    case SIDECAR_KIND_REGULAR:   return &requirements->regular_namespaces;
    case SIDECAR_KIND_DIRECTORY: return &requirements->directory_namespaces;
    case SIDECAR_KIND_SYMLINK:   return &requirements->symlink_namespaces;
    case SIDECAR_KIND_FIFO:
    case SIDECAR_KIND_HARDLINK:  return NULL;
    }
    return NULL;
}

static int replay_collect_entry(const SidecarLiveView *view, void *argument)
{
    ReplayCollection *collection = argument;
    if (collection == NULL || view == NULL || view->entry == NULL)
        return 1;

    const SidecarEntry *entry = view->entry;
    size_t root_index = root_map_find(&collection->root_map,
                                      collection->manifest,
                                      entry->root_id);
    if (root_index == SIZE_MAX)
    {
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_FIND_ROOT, 0);
        return 1;
    }
    if (!sidecar_path_valid(entry->logical_path, 1))
    {
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_SIDECAR_PATH, 0);
        return 1;
    }
    if (!replay_entry_valid(entry))
    {
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, 0);
        return 1;
    }
    size_t address_index = SIZE_MAX;
    errno = 0;
    int address_valid = restore_address_index_entry_valid(
        &collection->address_index, entry, &address_index);
    if (address_valid != 1)
    {
        int saved = address_valid < 0 ? errno : 0;
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ADDRESS_INDEX, saved);
        return 1;
    }
    (void)address_index;

    char logical[PATH_MAX];
    replay_copy_bytes(logical, sizeof(logical), entry->logical_path);
    int owned = entry->logical_path.length < sizeof(logical)
        ? manifest_entry_owned(collection->manifest, (int)root_index, logical)
        : -1;
    if (owned != 1)
    {
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_MANIFEST_OWNERSHIP, 0);
        return 1;
    }

    const ManifestRoot *root = &collection->manifest->roots[root_index];
    if ((entry->kind == SIDECAR_KIND_SYMLINK ||
         entry->kind == SIDECAR_KIND_HARDLINK) &&
        replay_symlink_placeholder_valid(collection, root, entry) != 0)
    {
        int saved = errno;
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_PLACEHOLDER, saved);
        return 1;
    }

    size_t hardlink_ref_root_index = SIZE_MAX;
    const SidecarEntry *hardlink_ref_entry = NULL;
    if (entry->kind == SIDECAR_KIND_HARDLINK)
    {
        SidecarLiveView referenced = {0};
        errno = 0;
        int referenced_found = collection->sidecar == NULL ? -1 :
            sidecar_log_find(collection->sidecar,
                             entry->hardlink_root_id,
                             entry->hardlink_logical_path, &referenced);
        if (referenced_found <= 0 ||
            referenced.entry == NULL ||
            referenced.entry->kind != SIDECAR_KIND_REGULAR ||
            !sidecar_path_valid(referenced.entry->logical_path, 1) ||
            referenced.entry->logical_path.length >= PATH_MAX)
        {
            replay_report_step_failure(
                collection->report, collection->manifest, root_index, entry,
                PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_ENTRY,
                referenced_found < 0 ? errno : 0);
            return 1;
        }
        hardlink_ref_root_index = root_map_find(&collection->root_map,
                                                collection->manifest,
                                                entry->hardlink_root_id);
        if (hardlink_ref_root_index == SIZE_MAX)
        {
            replay_report_step_failure(
                collection->report, collection->manifest, root_index, entry,
                PORTABLE_RESTORE_REPLAY_FAILURE_FIND_HARDLINK_ROOT, 0);
            return 1;
        }
        char reference_logical[PATH_MAX];
        replay_copy_bytes(reference_logical, sizeof(reference_logical),
                          referenced.entry->logical_path);
        if (referenced.entry->logical_path.length >=
                sizeof(reference_logical) ||
            manifest_entry_owned(collection->manifest,
                                 (int)hardlink_ref_root_index,
                                 reference_logical) != 1)
        {
            replay_report_step_failure(
                collection->report, collection->manifest, root_index, entry,
                PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_HARDLINK_OWNERSHIP,
                0);
            return 1;
        }
        char reference_relative[PATH_MAX];
        errno = 0;
        if (replay_hardlink_ref_relative(
                &collection->manifest->roots[hardlink_ref_root_index],
                referenced.entry, collection->destination_xdg_dirs,
                reference_relative, sizeof(reference_relative)) != 0)
        {
            int saved = errno;
            replay_report_step_failure(
                collection->report, collection->manifest, root_index, entry,
                PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_HARDLINK_DESTINATION,
                saved);
            return 1;
        }
        hardlink_ref_entry = referenced.entry;
    }

    struct stat desired;
    if (replay_desired_stat(collection, entry, &desired) != 0)
    {
        int saved = errno;
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_ENTRY_STAT, saved);
        return 1;
    }

    if (replay_entries_reserve(collection, 1) != 0)
    {
        int saved = errno;
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESERVE_ENTRY, saved);
        return 1;
    }
    ReplayEntry *replay = &collection->items[collection->count];
    memset(replay, 0, sizeof(*replay));
    char destination[PATH_MAX];
    errno = 0;
    if (destination_path_build(root, logical,
                               collection->destination_xdg_dirs,
                               destination, sizeof(destination)) != 0 ||
        (destination[0] == '\0' &&
         entry->kind != SIDECAR_KIND_DIRECTORY))
    {
        int saved = errno != 0 ? errno : ENAMETOOLONG;
        replay_report_step_failure(
            collection->report, collection->manifest, root_index, entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_DESTINATION_PATH, saved);
        return 1;
    }
    replay->entry = entry;
    replay->xattrs = view->xattrs;
    replay->xattr_count = view->xattr_count;
    replay->hardlink_ref_root_index = hardlink_ref_root_index;
    replay->hardlink_ref_entry = hardlink_ref_entry;
    /*
     * Accumulate the xattr namespace requirements for the pre-mutation
     * capability gate (D20 E-9). The sidecar's xattr names are not
     * NUL-terminated, so the length-aware classifier is required; and the
     * security.* bit is kept for the matrix but masked out by the probe
     * itself (METADATA_XATTR_NS_PROBED), so no branch is needed here.
     */
    if (view->xattr_count != 0)
    {
        unsigned int *kind_namespaces = replay_xattr_requirements_field(
            &collection->xattr_requirements, entry->kind);
        if (kind_namespaces != NULL)
            for (size_t xindex = 0; xindex < view->xattr_count; xindex++)
            {
                unsigned int namespaces = metadata_xattr_namespace_bytes(
                    view->xattrs[xindex].name.data,
                    view->xattrs[xindex].name.length);
                *kind_namespaces |= namespaces;
            }
    }
    replay->root_index = root_index;
    collection->count++;
    if (collection->report->live_count != SIZE_MAX)
        collection->report->live_count++;
    return 0;
}

static void replay_identity_entry(void *context, size_t index,
                                  DestinationIdentityEntryView *view)
{
    ReplayCollection *collection = context;
    ReplayEntry *entry = &collection->items[index];
    view->root_index = entry->root_index;
    view->logical = entry->entry->logical_path.data;
    view->logical_length = entry->entry->logical_path.length;
    view->claim = entry->entry->kind == SIDECAR_KIND_DIRECTORY
        ? DESTINATION_IDENTITY_DIRECTORY
        : DESTINATION_IDENTITY_NON_DIRECTORY;
    view->placement = &entry->identity_placement;
}

static void replay_identity_failure(void *context, size_t index)
{
    ReplayCollection *collection = context;
    ReplayEntry *entry = &collection->items[index];
    int saved = errno;
    replay_report_step_failure(
        collection->report, collection->manifest, entry->root_index,
        entry->entry, PORTABLE_RESTORE_REPLAY_FAILURE_MAP_DESTINATION_IDENTITY,
        saved);
}

static int replay_selection_destinations_valid(ReplayCollection *collection)
{
    DestinationIdentityGraph graph;
    destination_identity_graph_init(&graph, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    DestinationIdentityStatus anchor_status =
        destination_identity_graph_register_anchor(
            &graph, collection->destination_home_fd);
    if (anchor_status != DESTINATION_IDENTITY_OK)
    {
        int saved = errno;
        if (anchor_status == DESTINATION_IDENTITY_RESOURCE_ERROR &&
            errno == E2BIG)
            print_error("Error: Portable restore destination identity budget exceeded while registering destination HOME ancestry\n");
        else
            print_error("Error: Could not inspect destination HOME ancestry for portable restore\n");
        replay_report_step_failure(
            collection->report, collection->manifest, SIZE_MAX, NULL,
            PORTABLE_RESTORE_REPLAY_FAILURE_REGISTER_DESTINATION_ANCHOR,
            saved);
        destination_identity_graph_free(&graph);
        return -1;
    }
    if (destination_identity_graph_add_entries(
            &graph, collection->manifest, collection->count,
            collection->destination_home_fd,
            collection->destination_home_path,
            collection->destination_xdg_dirs, collection->xdg_anchor_fd,
            collection->xdg_anchor_prefix, replay_identity_entry,
            replay_identity_failure, NULL, collection,
            DESTINATION_IDENTITY_STOP_ON_COLLISION) != 0)
    {
        destination_identity_graph_free(&graph);
        return -1;
    }

    DestinationIdentityStatus status =
        destination_identity_graph_finalize(&graph);
    if (status != DESTINATION_IDENTITY_OK)
    {
        int saved = errno;
        if (status == DESTINATION_IDENTITY_RESOURCE_ERROR && errno == E2BIG)
            print_error("Error: Portable restore destination identity budget exceeded while ordering the destination namespace\n");
        else
            print_error("Error: Could not order the portable restore destination namespace\n");
        replay_report_step_failure(
            collection->report, collection->manifest, SIZE_MAX, NULL,
            PORTABLE_RESTORE_REPLAY_FAILURE_FINALIZE_DESTINATION_IDENTITY,
            saved);
        destination_identity_graph_free(&graph);
        return -1;
    }

    for (size_t index = 0; index < collection->count; index++)
        if (destination_identity_graph_order(
                &graph, &collection->items[index].identity_placement,
                &collection->items[index].destination_order) != 0)
        {
            int saved = errno;
            print_error("Error: Could not order portable restore destination for manifest root %s entry %.*s\n",
                        collection->manifest->roots[
                            collection->items[index].root_index].id,
                        (int)collection->items[index].entry->logical_path.length,
                        collection->items[index].entry->logical_path.data);
            replay_report_step_failure(
                collection->report, collection->manifest,
                collection->items[index].root_index,
                collection->items[index].entry,
                PORTABLE_RESTORE_REPLAY_FAILURE_ORDER_DESTINATION_IDENTITY,
                saved);
            destination_identity_graph_free(&graph);
            return -1;
        }

    destination_identity_graph_free(&graph);
    return 0;
}

static int replay_physical_leaf_text(const SidecarEntry *entry,
                                     char out[NAME_MAX + 1U])
{
    if (entry == NULL || out == NULL || entry->physical_leaf.length == 0 ||
        entry->physical_leaf.length > NAME_MAX ||
        entry->physical_leaf.data == NULL ||
        !portable_component_valid((const char *)entry->physical_leaf.data,
                                  entry->physical_leaf.length))
    {
        errno = EINVAL;
        return -1;
    }
    memcpy(out, entry->physical_leaf.data, entry->physical_leaf.length);
    out[entry->physical_leaf.length] = '\0';
    return 0;
}

static int replay_open_root_payload(const ReplayCollection *collection,
                                    const ManifestRoot *root, int flags,
                                    int *out_fd, struct stat *out_stat)
{
    if (collection == NULL || collection->data_fd < 0 || root == NULL ||
        out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    *out_fd = -1;

    int parent = -1;
    char leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(collection->data_fd, root->payload_path,
                                     &parent, leaf, sizeof(leaf)) != 0)
        return -1;

    int fd = openat(parent, leaf, flags | O_NOFOLLOW | O_CLOEXEC);
    int saved = errno;
    if (fd < 0)
    {
        close(parent);
        errno = saved;
        return -1;
    }
    if (out_stat != NULL && fstat(fd, out_stat) != 0)
    {
        saved = errno;
        close(fd);
        close(parent);
        errno = saved;
        return -1;
    }
    if (close(parent) != 0)
    {
        saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int replay_open_payload_parent_address(ReplayCollection *collection,
                                              const ManifestRoot *root,
                                              size_t parent_address_index,
                                              int *parent_out)
{
    if (collection == NULL || root == NULL || parent_out == NULL ||
        parent_address_index >= collection->address_index.count)
    {
        errno = EINVAL;
        return -1;
    }
    *parent_out = -1;

    const RestoreAddressEntry *parent_address =
        &collection->address_index.entries[parent_address_index];
    const SidecarEntry *parent_entry = parent_address->entry;
    if (parent_entry == NULL || parent_entry->kind != SIDECAR_KIND_DIRECTORY)
    {
        errno = EINVAL;
        return -1;
    }

    int current = -1;
    if (replay_open_root_payload(collection, root,
                                 O_RDONLY | O_DIRECTORY | O_NOATIME,
                                 &current, NULL) != 0)
        return -1;
    if (parent_entry->logical_path.length == 0)
    {
        *parent_out = current;
        return 0;
    }

    SidecarBytes root_id = parent_entry->root_id;
    SidecarBytes logical = parent_entry->logical_path;
    for (size_t length = 0; length <= logical.length; length++)
    {
        if (length != logical.length && logical.data[length] != '/')
            continue;
        SidecarBytes prefix = { .data = logical.data, .length = length };
        size_t address_index = SIZE_MAX;
        int found = restore_address_index_find_logical(
            &collection->address_index, root_id, prefix, &address_index);
        if (found != 1 || address_index >= collection->address_index.count)
        {
            int saved = found < 0 ? errno : EINVAL;
            close(current);
            errno = saved;
            return -1;
        }
        const SidecarEntry *ancestor =
            collection->address_index.entries[address_index].entry;
        char leaf[NAME_MAX + 1U];
        if (ancestor == NULL || ancestor->kind != SIDECAR_KIND_DIRECTORY ||
            replay_physical_leaf_text(ancestor, leaf) != 0)
        {
            int saved = errno == 0 ? EINVAL : errno;
            close(current);
            errno = saved;
            return -1;
        }
        int next = openat(current, leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_NOATIME | O_CLOEXEC);
        if (next < 0)
        {
            int saved = errno;
            close(current);
            errno = saved;
            return -1;
        }
        if (close(current) != 0)
        {
            int saved = errno;
            close(next);
            errno = saved;
            return -1;
        }
        current = next;
    }
    *parent_out = current;
    return 0;
}

static int replay_open_payload_parent_cached(ReplayCollection *collection,
                                             const ManifestRoot *root,
                                             size_t entry_address_index,
                                             int *parent_out)
{
    if (collection == NULL || root == NULL || parent_out == NULL ||
        entry_address_index >= collection->address_index.count)
    {
        errno = EINVAL;
        return -1;
    }
    const RestoreAddressEntry *address =
        &collection->address_index.entries[entry_address_index];
    const SidecarEntry *entry = address->entry;
    if (entry == NULL || entry->logical_path.length == 0)
    {
        errno = EINVAL;
        return -1;
    }

    size_t parent_address_index = SIZE_MAX;
    int found = restore_address_index_find_logical(
        &collection->address_index, entry->root_id, address->logical_parent,
        &parent_address_index);
    if (found != 1 || parent_address_index >= collection->address_index.count)
    {
        errno = found < 0 ? errno : EINVAL;
        return -1;
    }

    ReplayPayloadParentCache *cache = &collection->payload_cache;
    if (cache->fd >= 0 &&
        cache->parent_address_index == parent_address_index)
    {
        *parent_out = dup_cloexec(cache->fd);
        return *parent_out < 0 ? -1 : 0;
    }

    if (replay_open_payload_parent_address(collection, root,
                                           parent_address_index,
                                           parent_out) != 0)
        return -1;
    int cached = dup_cloexec(*parent_out);
    if (cached >= 0)
    {
        if (cache->fd >= 0)
            (void)close(cache->fd);
        cache->fd = cached;
        cache->parent_address_index = parent_address_index;
    }
    return 0;
}

static int replay_open_payload(ReplayCollection *collection,
                               const ManifestRoot *root,
                               const SidecarEntry *entry, int *out_fd,
                               struct stat *out_stat)
{
    if (collection == NULL || collection->data_fd < 0 || root == NULL ||
        entry == NULL || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    size_t entry_address_index = SIZE_MAX;
    size_t root_index = root_map_find(&collection->root_map,
                                      collection->manifest, entry->root_id);
    if (root_index == SIZE_MAX ||
        &collection->manifest->roots[root_index] != root ||
        restore_address_index_entry_valid(&collection->address_index, entry,
                                          &entry_address_index) != 1)
    {
        errno = EINVAL;
        return -1;
    }
    int flags = O_RDONLY | O_NOATIME;
    if (entry->kind == SIDECAR_KIND_DIRECTORY)
        flags |= O_DIRECTORY;
    int fd = -1;
    struct stat st;
    if (entry->logical_path.length == 0)
    {
        if (replay_open_root_payload(collection, root, flags, &fd, &st) != 0)
            return -1;
    }
    else
    {
        int parent = -1;
        char leaf[NAME_MAX + 1U];
        if (replay_open_payload_parent_cached(collection, root,
                                              entry_address_index,
                                              &parent) != 0 ||
            replay_physical_leaf_text(entry, leaf) != 0)
        {
            int saved = errno;
            if (parent >= 0)
                close(parent);
            errno = saved;
            return -1;
        }
        fd = openat(parent, leaf, flags | O_NOFOLLOW | O_CLOEXEC);
        int saved = errno;
        if (fd >= 0 && fstat(fd, &st) != 0)
        {
            saved = errno;
            close(fd);
            fd = -1;
        }
        if (close(parent) != 0 && fd >= 0)
        {
            saved = errno;
            close(fd);
            fd = -1;
        }
        if (fd < 0)
        {
            errno = saved;
            return -1;
        }
    }
    if ((entry->kind == SIDECAR_KIND_DIRECTORY && !S_ISDIR(st.st_mode)) ||
        (entry->kind == SIDECAR_KIND_REGULAR &&
         (!S_ISREG(st.st_mode) || st.st_size < 0 ||
          (uintmax_t)st.st_size != entry->size)))
    {
        int saved = EIO;
        close(fd);
        errno = saved;
        return -1;
    }
    if (out_stat != NULL)
        *out_stat = st;
    *out_fd = fd;
    return 0;
}

static int replay_open_destination_directory(int parent_fd, const char *leaf,
                                              int *out_fd)
{
    if (parent_fd < 0 || leaf == NULL || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (leaf[0] == '\0')
    {
        *out_fd = dup_cloexec(parent_fd);
        return *out_fd < 0 ? -1 : 0;
    }
    if (!text_component_valid(leaf, strlen(leaf)))
    {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            errno = ENOTDIR;
            return -1;
        }
    }
    else if (errno == ENOENT)
    {
        if (mkdirat(parent_fd, leaf, 0700) != 0 && errno != EEXIST)
            return -1;
        if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(st.st_mode))
        {
            errno = ENOTDIR;
            return -1;
        }
    }
    else
        return -1;
    *out_fd = openat(parent_fd, leaf,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return *out_fd < 0 ? -1 : 0;
}

static int replay_open_destination_regular(int parent_fd, const char *leaf,
                                            int *out_fd)
{
    if (parent_fd < 0 || leaf == NULL || leaf[0] == '\0' || out_fd == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (!S_ISREG(st.st_mode))
        {
            errno = EEXIST;
            return -1;
        }
        int fd = openat(parent_fd, leaf,
                        O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            return -1;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        {
            int saved = errno == 0 ? EIO : errno;
            close(fd);
            errno = saved;
            return -1;
        }
        *out_fd = fd;
        return 0;
    }
    if (errno != ENOENT)
        return -1;
    int fd = openat(parent_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                        O_NONBLOCK | O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        int saved = errno == 0 ? EIO : errno;
        close(fd);
        unlinkat(parent_fd, leaf, 0);
        errno = saved;
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int replay_open_relative_parent_cached(ReplayCollection *collection,
                                              int base_fd,
                                              const char *relative,
                                              int *parent_out, char *leaf,
                                              size_t leaf_size)
{
    if (collection == NULL || relative == NULL || parent_out == NULL ||
        leaf == NULL || leaf_size == 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (relative[0] == '\0')
        return portable_open_relative_parent(base_fd, relative, parent_out,
                                             leaf, leaf_size);
    if (!relative_path_valid(relative, 0))
    {
        errno = EINVAL;
        return -1;
    }

    const char *slash = strrchr(relative, '/');
    ReplayParentCache *cache = &collection->parent_cache;
    size_t prefix_length = 0;
    if (slash != NULL)
    {
        prefix_length = (size_t)(slash - relative);
        if (cache->fd >= 0 && cache->base_fd == base_fd &&
            strncmp(cache->prefix, relative, prefix_length) == 0 &&
            cache->prefix[prefix_length] == '\0')
        {
            int length = snprintf(leaf, leaf_size, "%s", slash + 1U);
            if (length < 0 || (size_t)length >= leaf_size)
            {
                errno = ENAMETOOLONG;
                return -1;
            }
            int fd = dup_cloexec(cache->fd);
            if (fd < 0)
                return -1;
            *parent_out = fd;
            return 0;
        }
    }

    if (portable_open_relative_parent(base_fd, relative, parent_out, leaf,
                                      leaf_size) != 0)
        return -1;

    if (slash == NULL)
        return 0;
    int cached = dup_cloexec(*parent_out);
    if (cached >= 0)
    {
        if (cache->fd >= 0)
            (void)close(cache->fd);
        cache->fd = cached;
        cache->base_fd = base_fd;
        memcpy(cache->prefix, relative, prefix_length);
        cache->prefix[prefix_length] = '\0';
    }
    return 0;
}

static int replay_destination_parent_for_root(
    ReplayCollection *collection, size_t root_index,
    const char *relative, int *parent_out, char *leaf, size_t leaf_size)
{
    if (collection == NULL || collection->manifest == NULL ||
        relative == NULL || parent_out == NULL || leaf == NULL ||
        root_index >= (size_t)collection->manifest->root_count)
    {
        errno = EINVAL;
        return -1;
    }

    const ManifestRoot *root = &collection->manifest->roots[root_index];
    if (root->policy != ROOT_POLICY_XDG)
        return replay_open_relative_parent_cached(
            collection, collection->destination_home_fd, relative,
            parent_out, leaf, leaf_size);

    if (!xdg_destination_valid(collection->destination_xdg_dirs, root))
    {
        errno = EINVAL;
        return -1;
    }
    int index = xdg_key_index(root->id);
    if (index < 0 || index >= XDG_KEY_COUNT)
    {
        errno = EINVAL;
        return -1;
    }
    if (collection->xdg_anchor_fd[index] < 0)
    {
        int xdg_fd = -1;
        char prefix[NAME_MAX + 1U];
        if (open_xdg_destination_anchor(
                collection->destination_xdg_dirs[index], &xdg_fd,
                prefix, sizeof(prefix)) != 0)
            return -1;
        collection->xdg_anchor_fd[index] = xdg_fd;
        memcpy(collection->xdg_anchor_prefix[index], prefix, sizeof(prefix));
    }

    char destination[PATH_MAX];
    if (destination_relative_path_build(collection->xdg_anchor_prefix[index],
                                        relative, destination,
                                        sizeof(destination)) != 0)
        return -1;

    return replay_open_relative_parent_cached(
        collection, collection->xdg_anchor_fd[index], destination,
        parent_out, leaf, leaf_size);
}

/* Rebuilds the relative destination path from the borrowed sidecar entry.
 * Collection already validates the same mapping, so replay does not retain a
 * PATH_MAX-sized copy for every live entry. */
static int replay_destination_relative(const ReplayCollection *collection,
                                       const ReplayEntry *replay,
                                       char *out, size_t out_size)
{
    if (collection == NULL || collection->manifest == NULL || replay == NULL ||
        replay->entry == NULL ||
        replay->root_index >= (size_t)collection->manifest->root_count ||
        out == NULL || out_size == 0)
    {
        errno = EINVAL;
        return -1;
    }
    const ManifestRoot *root = &collection->manifest->roots[replay->root_index];
    char logical[PATH_MAX];
    replay_copy_bytes(logical, sizeof(logical), replay->entry->logical_path);
    if (replay->entry->logical_path.length >= sizeof(logical))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (root->policy == ROOT_POLICY_XDG)
    {
        int length = snprintf(out, out_size, "%s", logical);
        return (length < 0 || (size_t)length >= out_size) ? -1 : 0;
    }
    return destination_path_build(root, logical,
                                  collection->destination_xdg_dirs,
                                  out, out_size);
}

/* Rebuilds the validated hardlink reference path from the borrowed sidecar
 * entry instead of retaining another PATH_MAX buffer in every ReplayEntry. */
static int replay_hardlink_ref_relative(const ManifestRoot *ref_root,
                                        const SidecarEntry *ref_entry,
                                        const char * const *xdg_dirs,
                                        char *out, size_t out_size)
{
    if (ref_root == NULL || ref_entry == NULL || out == NULL || out_size == 0)
    {
        errno = EINVAL;
        return -1;
    }
    char reference_logical[PATH_MAX];
    replay_copy_bytes(reference_logical, sizeof(reference_logical),
                      ref_entry->logical_path);
    if (ref_root->policy == ROOT_POLICY_XDG)
    {
        if (!xdg_destination_valid(xdg_dirs, ref_root))
        {
            errno = EINVAL;
            return -1;
        }
        int length = snprintf(out, out_size, "%s", reference_logical);
        return (length < 0 || (size_t)length >= out_size) ? -1 : 0;
    }
    char destination[PATH_MAX];
    if (destination_path_build(ref_root, reference_logical, xdg_dirs,
                               destination, sizeof(destination)) != 0)
        return -1;
    int length = snprintf(out, out_size, "%s", destination);
    return (length < 0 || (size_t)length >= out_size) ? -1 : 0;
}

static int replay_destination_parent(ReplayCollection *collection,
                                     const ReplayEntry *replay,
                                     int *parent_out, char *leaf,
                                     size_t leaf_size)
{
    if (collection == NULL || collection->manifest == NULL ||
        replay == NULL || parent_out == NULL || leaf == NULL ||
        replay->root_index >= (size_t)collection->manifest->root_count)
    {
        errno = EINVAL;
        return -1;
    }
    char relative[PATH_MAX];
    if (replay_destination_relative(collection, replay, relative,
                                    sizeof(relative)) != 0)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    return replay_destination_parent_for_root(collection, replay->root_index,
                                              relative, parent_out, leaf,
                                              leaf_size);
}

static int replay_entry_source_path(const ReplayCollection *collection,
                                    const ReplayEntry *replay,
                                    char out[PATH_MAX])
{
    if (collection == NULL || collection->manifest == NULL || replay == NULL ||
        replay->entry == NULL || out == NULL ||
        replay->root_index >= (size_t)collection->manifest->root_count ||
        collection->manifest->source_home[0] == '\0')
    {
        errno = EINVAL;
        return -1;
    }

    char logical[PATH_MAX];
    replay_copy_bytes(logical, sizeof(logical), replay->entry->logical_path);
    if (replay->entry->logical_path.length >= sizeof(logical))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    char source_root[PATH_MAX];
    if (manifest_root_source_path(collection->manifest,
                                  (int)replay->root_index,
                                  source_root) != 0)
        return -1;
    if (logical[0] == '\0')
    {
        int length = snprintf(out, PATH_MAX, "%s", source_root);
        return length >= 0 && (size_t)length < PATH_MAX ? 0 : -1;
    }
    return path_join(out, PATH_MAX, source_root, logical);
}

static int replay_regular_rewrites_home(const ReplayCollection *collection,
                                        const ReplayEntry *replay)
{
    if (collection == NULL || collection->manifest == NULL || replay == NULL ||
        replay->entry == NULL || collection->home_rewrite_pair_count == 0)
        return 0;

    char source_path[PATH_MAX];
    if (replay_entry_source_path(collection, replay, source_path) != 0)
        return 0;

    for (size_t index = 0; index < HOME_REWRITE_FILE_COUNT; index++)
    {
        char known_path[PATH_MAX];
        if (path_join(known_path, sizeof(known_path),
                      collection->manifest->source_home,
                      home_rewrite_files[index]) == 0 &&
            strcmp(source_path, known_path) == 0)
            return 1;
    }
    return 0;
}

// Whether replay's regular file is the one at home_relative below the source
// HOME the manifest records.
static int replay_regular_is_home_file(const ReplayCollection *collection,
                                       const ReplayEntry *replay,
                                       const char *home_relative)
{
    if (collection == NULL || collection->manifest == NULL || replay == NULL ||
        replay->entry == NULL || replay->entry->kind != SIDECAR_KIND_REGULAR)
        return 0;

    char source_path[PATH_MAX], known_path[PATH_MAX];
    if (replay_entry_source_path(collection, replay, source_path) != 0 ||
        path_join(known_path, sizeof(known_path),
                  collection->manifest->source_home, home_relative) != 0)
        return 0;
    return strcmp(source_path, known_path) == 0;
}

static int replay_regular_is_locally_authoritative(
    const ReplayCollection *collection, const ReplayEntry *replay)
{
    return replay_regular_is_home_file(collection, replay,
                                       ".config/user-dirs.dirs");
}

static int replay_regular_content_verification_excluded(
    const SidecarEntry *entry);

static int replay_regular_is_dconf_database(const ReplayCollection *collection,
                                            const ReplayEntry *replay)
{
    return replay_regular_is_home_file(collection, replay,
                                       ".config/dconf/user");
}

// Fill, don't fight (D65): confirmed live desktop state that a running
// service has already written at the destination is left as it is; it is
// restored only where nothing is there yet. Returns 1 when present.
static int replay_live_state_present(ReplayCollection *collection,
                                     const ReplayEntry *replay)
{
    if (!replay_regular_content_verification_excluded(replay->entry))
        return 0;
    // The dconf database holds the user's settings, not state a service
    // regenerates: an existing one is left only to the load into the
    // running session that follows replay (D80).
    if (!collection->dconf_loads_into_session &&
        replay_regular_is_dconf_database(collection, replay))
        return 0;
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    if (replay_destination_parent(collection, replay, &parent_fd, leaf,
                                  sizeof(leaf)) != 0)
        return 0;
    struct stat st;
    int present = fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0;
    close(parent_fd);
    return present;
}

// Hands the applied dconf database's payload to the caller (see
// PortableRestoreRequest). Best-effort: without it the restored file is still
// in place and only the running-session load is skipped.
static void replay_capture_dconf_database(ReplayCollection *collection,
                                          ReplayEntry *replay)
{
    if (collection->dconf_database_fd_out == NULL ||
        *collection->dconf_database_fd_out >= 0 ||
        !replay_regular_is_dconf_database(collection, replay))
        return;
    int saved = errno;
    int fd = -1;
    struct stat st;
    if (replay_open_payload(collection,
                            &collection->manifest->roots[replay->root_index],
                            replay->entry, &fd, &st) == 0)
        *collection->dconf_database_fd_out = fd;
    errno = saved;
}

static int replay_apply_regular(ReplayCollection *collection,
                                ReplayEntry *replay,
                                ReplayApplyFailure *failure)
{
    if (failure != NULL)
        *failure = (ReplayApplyFailure){0};
    const ManifestRoot *root = &collection->manifest->roots[
        replay->root_index];
    const SidecarEntry *entry = replay->entry;
    if (replay_regular_is_locally_authoritative(collection, replay))
        return 0;
    if (replay_live_state_present(collection, replay))
    {
        replay->kept_live_state = 1;
        return 0;
    }
    if (entry->size > (uint64_t)INTMAX_MAX)
    {
        errno = EOVERFLOW;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }
    struct stat desired;
    if (replay_desired_stat(collection, entry, &desired) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }

    int source_fd = -1;
    struct stat source_before;
    if (replay_open_payload(collection, root, entry, &source_fd,
                            &source_before) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_PAYLOAD, errno);
        return -1;
    }
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    int destination_fd = -1;
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result != 0)
        replay_apply_failure_record(
            failure,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT,
            errno);
    if (result == 0)
    {
        result = replay_open_destination_regular(parent_fd, leaf,
                                                 &destination_fd);
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_DESTINATION,
                errno);
    }
    if (result == 0 && collection->capture_report != NULL)
    {
        char relative[PATH_MAX];
        if (replay_destination_relative(collection, replay, relative,
                                        sizeof(relative)) == 0)
            snprintf(collection->capture_report->current_path,
                     sizeof(collection->capture_report->current_path), "%s",
                     relative);
    }
    if (result == 0)
    {
        // The written bytes differ from the read ones only when HOME paths
        // are rewritten; the read ones are what the capture digest covers.
        uint64_t source_digest = 0;
        if (replay_regular_rewrites_home(collection, replay))
            result = home_rewrite_copy(
                source_fd, destination_fd, (off_t)entry->size,
                collection->home_rewrite_pairs,
                collection->home_rewrite_pair_count,
                collection->capture_report, &replay->content_digest,
                &source_digest);
        else
        {
            result = portable_copy_regular_digest(
                source_fd, destination_fd, (off_t)entry->size,
                collection->capture_report, &replay->content_digest);
            source_digest = replay->content_digest;
        }
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_COPY_CONTENT, errno);
        else
        {
            replay->content_digest_valid = 1;
            replay->payload_differs = source_digest != entry->content_digest;
        }
    }
    if (result == 0)
    {
        struct stat source_after;
        if (fstat(source_fd, &source_after) != 0 ||
            !metadata_source_unchanged(&source_before, &source_after))
        {
            errno = EIO;
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_PAYLOAD,
                errno);
        }
    }
    if (result == 0)
    {
        result = metadata_apply_ownership_and_mode_fd(destination_fd,
                                                      &desired);
        if (result != 0)
            replay_apply_failure_record(
                failure,
                PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_OWNERSHIP_MODE,
                errno);
    }
    if (result == 0)
    {
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_fd_report(
            destination_fd, replay->xattrs, replay->xattr_count,
            &skipped_security);
        replay_report_security_skipped(collection->report, skipped_security);
        if (xattr_result != 0)
        {
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_XATTRS,
                errno);
        }
    }
    if (result == 0)
    {
        result = metadata_apply_times_fd(destination_fd, &desired,
                                         collection->timestamp_policy);
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES, errno);
    }
    struct stat written;
    if (result == 0 && fstat(destination_fd, &written) == 0)
    {
        replay->written_valid = 1;
        replay->written_dev = written.st_dev;
        replay->written_ino = written.st_ino;
        replay->written_size = written.st_size;
        replay->written_mtime = written.st_mtim;
    }

    int saved = errno;
    if (destination_fd >= 0 && close(destination_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (close(source_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static int replay_apply_symlink(ReplayCollection *collection,
                                ReplayEntry *replay,
                                ReplayApplyFailure *failure)
{
    if (failure != NULL)
        *failure = (ReplayApplyFailure){0};
    if (collection == NULL || replay == NULL || replay->entry == NULL ||
        replay->entry->kind != SIDECAR_KIND_SYMLINK ||
        !replay_entry_valid(replay->entry))
    {
        errno = EINVAL;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }

    const SidecarEntry *entry = replay->entry;
    struct stat desired;
    if (replay_desired_stat(collection, entry, &desired) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }

    size_t target_length = entry->symlink_target.length;
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    memcpy(target, entry->symlink_target.data, target_length);
    target[target_length] = '\0';

    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result != 0)
        replay_apply_failure_record(
            failure,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT,
            errno);
    int already_present = 0;
    if (result == 0)
    {
        struct stat existing;
        if (fstatat(parent_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
        {
            // A symlink with the recorded target is this entry from an
            // earlier run; its metadata is still applied below.
            int matches = S_ISLNK(existing.st_mode)
                ? destination_symlink_target_matches(parent_fd, leaf,
                                                     entry->symlink_target)
                : 0;
            if (matches == 1)
                already_present = 1;
            else
            {
                if (matches == 0)
                    errno = EEXIST;
                result = -1;
                replay_apply_failure_record(
                    failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                    errno);
            }
        }
        else if (errno != ENOENT)
        {
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                errno);
        }
    }
    if (result == 0 && !already_present &&
        symlinkat(target, parent_fd, leaf) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CREATE_SYMLINK, errno);
    }
    if (result == 0)
    {
        result = metadata_apply_symlink_ownership_at(parent_fd, leaf,
                                                     &desired);
        if (result != 0)
            replay_apply_failure_record(
                failure,
                PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_OWNERSHIP_MODE,
                errno);
    }
    if (result == 0)
    {
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_symlink_at_report(
            parent_fd, leaf, replay->xattrs, replay->xattr_count,
            &skipped_security);
        replay_report_security_skipped(collection->report, skipped_security);
        if (xattr_result != 0)
        {
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_XATTRS,
                errno);
        }
    }
    if (result == 0)
    {
        result = metadata_apply_symlink_times_at(parent_fd, leaf, &desired,
                                                 collection->timestamp_policy);
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES, errno);
    }

    int saved = errno;
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

int replay_hardlink_identity_matches(const struct stat *linked,
                                     const struct stat *reference)
{
    return linked != NULL && reference != NULL &&
           linked->st_dev == reference->st_dev &&
           linked->st_ino == reference->st_ino;
}

#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
static void (*hardlink_race_hook)(void);
static void (*before_content_verification_hook)(void);
static void (*after_apply_hook)(void);
static int verification_progress_enabled;
static size_t verification_regular_read_count;

void portable_restore_replay_test_set_hardlink_race_hook(void (*hook)(void))
{
    hardlink_race_hook = hook;
}

void portable_restore_replay_test_set_before_content_verification_hook(
    void (*hook)(void))
{
    before_content_verification_hook = hook;
}

void portable_restore_replay_test_set_after_apply_hook(void (*hook)(void))
{
    after_apply_hook = hook;
}

void portable_restore_replay_test_set_verification_progress_enabled(int enabled)
{
    verification_progress_enabled = enabled != 0;
}

void portable_restore_replay_test_reset_verification_regular_read_count(void)
{
    verification_regular_read_count = 0;
}

size_t portable_restore_replay_test_verification_regular_read_count(void)
{
    return verification_regular_read_count;
}
#endif

static int replay_apply_hardlink(ReplayCollection *collection,
                                 ReplayEntry *replay,
                                 ReplayApplyFailure *failure)
{
    if (failure != NULL)
        *failure = (ReplayApplyFailure){0};
    if (collection == NULL || replay == NULL || replay->entry == NULL ||
        replay->entry->kind != SIDECAR_KIND_HARDLINK ||
        !replay_entry_valid(replay->entry) ||
        replay->hardlink_ref_root_index >=
            (size_t)collection->manifest->root_count ||
        replay->hardlink_ref_entry == NULL)
    {
        errno = EINVAL;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }

    char ref_relative[PATH_MAX];
    if (replay_hardlink_ref_relative(
            &collection->manifest->roots[replay->hardlink_ref_root_index],
            replay->hardlink_ref_entry, collection->destination_xdg_dirs,
            ref_relative, sizeof(ref_relative)) != 0 ||
        ref_relative[0] == '\0' || !relative_path_valid(ref_relative, 0))
    {
        errno = EINVAL;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }

    int parent_fd = -1;
    int ref_parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    char ref_leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result != 0)
        replay_apply_failure_record(
            failure,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT,
            errno);
    if (result == 0)
    {
        result = replay_destination_parent_for_root(
            collection, replay->hardlink_ref_root_index,
            ref_relative, &ref_parent_fd, ref_leaf, sizeof(ref_leaf));
        if (result != 0)
            replay_apply_failure_record(
                failure,
                PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_REFERENCE,
                errno);
    }

    struct stat reference_before;
    if (result == 0 &&
        (ref_leaf[0] == '\0' ||
         fstatat(ref_parent_fd, ref_leaf, &reference_before,
                 AT_SYMLINK_NOFOLLOW) != 0 ||
         !S_ISREG(reference_before.st_mode)))
    {
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_HARDLINK_REFERENCE,
            errno);
    }
    int already_linked = 0;
    if (result == 0)
    {
        struct stat existing;
        if (fstatat(parent_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
        {
            // A name already on the reference's inode is this entry from an
            // earlier run.
            if (S_ISREG(existing.st_mode) &&
                replay_hardlink_identity_matches(&existing, &reference_before))
                already_linked = 1;
            else
            {
                errno = EEXIST;
                result = -1;
                replay_apply_failure_record(
                    failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                    errno);
            }
        }
        else if (errno != ENOENT)
        {
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                errno);
        }
    }
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (result == 0 && !already_linked && hardlink_race_hook != NULL)
        hardlink_race_hook();
#endif
    if (result == 0 && !already_linked &&
        linkat(ref_parent_fd, ref_leaf, parent_fd, leaf, 0) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CREATE_HARDLINK, errno);
    }
    if (result == 0)
    {
        struct stat linked;
        if (fstatat(parent_fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
            !replay_hardlink_identity_matches(&linked, &reference_before))
        {
            errno = EIO;
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_HARDLINK,
                errno);
        }
    }

    int saved = errno;
    if (ref_parent_fd >= 0 && close(ref_parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static int replay_prepare_directory(ReplayCollection *collection,
                                     ReplayEntry *replay,
                                     ReplayApplyFailure *failure)
{
    if (failure != NULL)
        *failure = (ReplayApplyFailure){0};
    const ManifestRoot *root = &collection->manifest->roots[
        replay->root_index];
    const SidecarEntry *entry = replay->entry;
    int source_fd = -1;
    struct stat source_st;
    if (replay_open_payload(collection, root, entry, &source_fd,
                            &source_st) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_PAYLOAD, errno);
        return -1;
    }

    int parent_fd = -1;
    int destination_fd = -1;
    char leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result != 0)
        replay_apply_failure_record(
            failure,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT,
            errno);
    if (result == 0)
    {
        result = replay_open_destination_directory(parent_fd, leaf,
                                                   &destination_fd);
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_DESTINATION,
                errno);
    }

    int saved = errno;
    if (destination_fd >= 0 && close(destination_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (close(source_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static int replay_apply_directory_metadata(ReplayCollection *collection,
                                            ReplayEntry *replay,
                                            ReplayApplyFailure *failure)
{
    if (failure != NULL)
        *failure = (ReplayApplyFailure){0};
    const SidecarEntry *entry = replay->entry;
    struct stat desired;
    if (replay_desired_stat(collection, entry, &desired) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }
    int parent_fd = -1;
    int destination_fd = -1;
    char leaf[NAME_MAX + 1U];
    int result = replay_destination_parent(collection, replay, &parent_fd,
                                           leaf, sizeof(leaf));
    if (result != 0)
        replay_apply_failure_record(
            failure,
            PORTABLE_RESTORE_REPLAY_FAILURE_RESOLVE_DESTINATION_PARENT,
            errno);
    if (result == 0)
    {
        struct stat existing;
        if (leaf[0] == '\0')
            destination_fd = dup_cloexec(parent_fd);
        else if (fstatat(parent_fd, leaf, &existing,
                         AT_SYMLINK_NOFOLLOW) == 0 &&
                 S_ISDIR(existing.st_mode))
            destination_fd = openat(parent_fd, leaf,
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                        O_CLOEXEC);
        else
        {
            errno = ENOTDIR;
            result = -1;
        }
        if (destination_fd < 0 && result == 0)
            result = -1;
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_OPEN_DESTINATION,
                errno);
    }
    if (result == 0)
    {
        result = metadata_apply_ownership_and_mode_fd(destination_fd,
                                                      &desired);
        if (result != 0)
            replay_apply_failure_record(
                failure,
                PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_OWNERSHIP_MODE,
                errno);
    }
    if (result == 0)
    {
        size_t skipped_security = 0;
        int xattr_result = metadata_apply_xattrs_fd_report(
            destination_fd, replay->xattrs, replay->xattr_count,
            &skipped_security);
        replay_report_security_skipped(collection->report, skipped_security);
        if (xattr_result != 0)
        {
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_XATTRS,
                errno);
        }
    }
    if (result == 0)
    {
        result = metadata_apply_times_fd(destination_fd, &desired,
                                         collection->timestamp_policy);
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES, errno);
    }

    int saved = errno;
    if (destination_fd >= 0 && close(destination_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        result = -1;
        saved = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static void replay_print_verbose_root(const ReplayCollection *collection,
                                      size_t root_index,
                                      unsigned char *printed_roots)
{
    if (!verbose || collection == NULL || collection->manifest == NULL ||
        printed_roots == NULL || root_index >= MANIFEST_MAX_ROOTS ||
        root_index >= (size_t)collection->manifest->root_count ||
        printed_roots[root_index])
        return;

    printf("  Restoring: %s\n",
           collection->manifest->roots[root_index].id);
    printed_roots[root_index] = 1;
}

static int replay_verification_progress_should_install(void)
{
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (verification_progress_enabled)
        return 1;
#endif
    return isatty(STDOUT_FILENO);
}

static long replay_verification_elapsed_seconds(
    const struct timespec *started_at, const struct timespec *now)
{
    double elapsed = timespec_elapsed_seconds(started_at, now);
    if (elapsed <= 0.0)
        return 0;
    if (elapsed >= (double)LONG_MAX)
        return LONG_MAX;
    return (long)elapsed;
}

static void replay_verification_progress_render(
    const ReplayVerificationProgress *display, size_t checked_count,
    const struct timespec *now)
{
    if (display == NULL || now == NULL)
        return;
    char elapsed_text[32];
    format_duration(
        replay_verification_elapsed_seconds(&display->started_at, now),
        elapsed_text, sizeof(elapsed_text));
    char line[192];
    (void)snprintf(line, sizeof(line),
                   "Verifying restored content: %zu/%zu checked, elapsed %s",
                   checked_count, display->total_count, elapsed_text);
    progress_line_fit(line, sizeof(line));
    printf("\r%s\033[K", line);
    fflush(stdout);
}

static void replay_verification_ticker_redraw(
    const ProgressTickerSnapshot *snapshot, const struct timespec *now,
    void *context)
{
    ReplayVerificationProgress *display = context;
    if (snapshot == NULL || snapshot->bytes < 0)
        return;
    replay_verification_progress_render(display, (size_t)snapshot->bytes, now);
}

static void replay_verification_progress_stop_ticker(
    ReplayVerificationProgress *display)
{
    if (display == NULL || !display->ticker_started)
        return;
    if (progress_ticker_stop(&display->ticker) == 0)
    {
        display->ticker_started = 0;
        return;
    }
    print_error("Error: Could not stop the restore verification progress thread: %s\n",
                strerror(errno));
    abort();
}

static int replay_verification_size_to_off_t(size_t value, off_t *out)
{
    if (out == NULL)
        return -1;
    off_t converted = (off_t)value;
    if (converted < 0 || (size_t)converted != value)
        return -1;
    *out = converted;
    return 0;
}

static int replay_verification_snapshot(ReplayVerificationProgress *display,
                                        size_t checked_count,
                                        const struct timespec *now)
{
    if (display == NULL || now == NULL || !display->ticker_started)
        return 0;
    off_t checked = 0;
    if (replay_verification_size_to_off_t(checked_count, &checked) != 0)
    {
        replay_verification_progress_stop_ticker(display);
        return 0;
    }
    return progress_ticker_snapshot(&display->ticker, checked, 0, 0, 0,
                                    "verification", now);
}

static void replay_verification_progress_start(
    ReplayVerificationProgress *display, size_t total_count)
{
    if (display == NULL)
        return;
    memset(display, 0, sizeof(*display));
    if (!replay_verification_progress_should_install())
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    {
        printf("Verifying restored content...\n");
        fflush(stdout);
        return;
    }
    display->total_count = total_count;
    display->started_at = now;
    display->last_real_redraw = now;
    display->active = 1;
    if (progress_ticker_start(&display->ticker,
                              replay_verification_ticker_redraw,
                              display) == 0)
        display->ticker_started = 1;
    else
        print_warning("  Warning: restore verification stall redraw is unavailable: %s\n",
                      strerror(errno));
    replay_verification_progress_render(display, 0, &now);
    if (replay_verification_snapshot(display, 0, &now) != 0)
    {
        replay_verification_progress_stop_ticker(display);
        putchar('\n');
        display->active = 0;
    }
}

static void replay_verification_progress_note(
    ReplayVerificationProgress *display, size_t checked_count, int force)
{
    if (display == NULL || !display->active)
        return;
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (verification_progress_enabled)
        force = 1;
#endif
    if (!backup_progress_should_fire(&display->last_real_redraw, force))
        return;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    display->last_real_redraw = now;
    if (replay_verification_snapshot(display, checked_count, &now) != 0)
    {
        replay_verification_progress_stop_ticker(display);
        putchar('\n');
        display->active = 0;
        return;
    }
    replay_verification_progress_render(display, checked_count, &now);
}

static void replay_verification_progress_finish(
    ReplayVerificationProgress *display, size_t checked_count)
{
    if (display == NULL || !display->active)
        return;
    replay_verification_progress_stop_ticker(display);
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        replay_verification_progress_render(display, checked_count, &now);
    putchar('\n');
    fflush(stdout);
    display->active = 0;
}

static int replay_open_existing_relative_parent_cached(
    ReplayCollection *collection, int base_fd, const char *relative,
    int *parent_out, char *leaf, size_t leaf_size)
{
    if (collection == NULL || base_fd < 0 || relative == NULL ||
        relative[0] == '\0' || parent_out == NULL || leaf == NULL ||
        leaf_size == 0 || !relative_path_valid(relative, 0))
    {
        errno = EINVAL;
        return -1;
    }

    const char *slash = strrchr(relative, '/');
    ReplayParentCache *cache = &collection->verification_parent_cache;
    size_t prefix_length = slash == NULL ? 0U : (size_t)(slash - relative);
    if (slash != NULL && cache->fd >= 0 && cache->base_fd == base_fd &&
        strncmp(cache->prefix, relative, prefix_length) == 0 &&
        cache->prefix[prefix_length] == '\0')
    {
        int length = snprintf(leaf, leaf_size, "%s", slash + 1U);
        if (length < 0 || (size_t)length >= leaf_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        int fd = dup_cloexec(cache->fd);
        if (fd < 0)
            return -1;
        *parent_out = fd;
        return 0;
    }

    if (open_existing_payload_parent(base_fd, relative, parent_out, leaf,
                                     leaf_size) != 0)
        return -1;
    if (slash == NULL)
        return 0;

    int cached = dup_cloexec(*parent_out);
    if (cached >= 0)
    {
        if (cache->fd >= 0)
            (void)close(cache->fd);
        cache->fd = cached;
        cache->base_fd = base_fd;
        memcpy(cache->prefix, relative, prefix_length);
        cache->prefix[prefix_length] = '\0';
    }
    return 0;
}

static int replay_verification_destination_parent_for_root(
    ReplayCollection *collection, size_t root_index, const char *relative,
    int *parent_out, char *leaf, size_t leaf_size)
{
    if (collection == NULL || collection->manifest == NULL ||
        relative == NULL || parent_out == NULL || leaf == NULL ||
        root_index >= (size_t)collection->manifest->root_count)
    {
        errno = EINVAL;
        return -1;
    }
    const ManifestRoot *root = &collection->manifest->roots[root_index];
    if (root->policy != ROOT_POLICY_XDG)
        return replay_open_existing_relative_parent_cached(
            collection, collection->destination_home_fd, relative,
            parent_out, leaf, leaf_size);

    if (!xdg_destination_valid(collection->destination_xdg_dirs, root))
    {
        errno = EINVAL;
        return -1;
    }
    int index = xdg_key_index(root->id);
    if (index < 0 || index >= XDG_KEY_COUNT)
    {
        errno = EINVAL;
        return -1;
    }
    if (collection->xdg_anchor_fd[index] < 0)
    {
        int xdg_fd = -1;
        char prefix[NAME_MAX + 1U];
        if (open_xdg_destination_anchor(
                collection->destination_xdg_dirs[index], &xdg_fd,
                prefix, sizeof(prefix)) != 0)
            return -1;
        collection->xdg_anchor_fd[index] = xdg_fd;
        memcpy(collection->xdg_anchor_prefix[index], prefix, sizeof(prefix));
    }

    char destination[PATH_MAX];
    if (destination_relative_path_build(collection->xdg_anchor_prefix[index],
                                        relative, destination,
                                        sizeof(destination)) != 0)
        return -1;
    return replay_open_existing_relative_parent_cached(
        collection, collection->xdg_anchor_fd[index], destination,
        parent_out, leaf, leaf_size);
}

static int replay_verification_destination_parent(
    ReplayCollection *collection, const ReplayEntry *replay,
    int *parent_out, char *leaf, size_t leaf_size)
{
    char relative[PATH_MAX];
    if (collection == NULL || replay == NULL ||
        replay_destination_relative(collection, replay, relative,
                                    sizeof(relative)) != 0 ||
        relative[0] == '\0')
    {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    return replay_verification_destination_parent_for_root(
        collection, replay->root_index, relative, parent_out, leaf, leaf_size);
}

static int replay_destination_regular_digest(
    int parent_fd, const char *leaf, uint64_t *digest,
    ReplayApplyFailure *failure)
{
    if (parent_fd < 0 || leaf == NULL || leaf[0] == '\0' || digest == NULL)
    {
        errno = EINVAL;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
        return -1;
    }

    struct stat path_before;
    if (fstatat(parent_fd, leaf, &path_before, AT_SYMLINK_NOFOLLOW) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
        return -1;
    }
    if (!S_ISREG(path_before.st_mode))
    {
        errno = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
        return -1;
    }
    int fd = openat(parent_fd, leaf,
                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (fd < 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_READ_DESTINATION_CONTENT,
            errno);
        return -1;
    }

    int result = 0;
    int saved = 0;
    struct stat opened;
    if (fstat(fd, &opened) != 0)
    {
        saved = errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            saved);
    }
    else if (!S_ISREG(opened.st_mode) ||
             !replay_hardlink_identity_matches(&opened, &path_before))
    {
        saved = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            saved);
    }

    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    unsigned char buffer[65536];
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (result == 0)
        verification_regular_read_count++;
#endif
    while (result == 0)
    {
        ssize_t received = read(fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
        {
            saved = errno;
            result = -1;
            replay_apply_failure_record(
                failure,
                PORTABLE_RESTORE_REPLAY_FAILURE_READ_DESTINATION_CONTENT,
                saved);
            break;
        }
        if (received == 0)
            break;
        hash = hash_fnv1a_bytes(hash, buffer, (size_t)received);
    }
    if (result == 0)
        *digest = hash;

    struct stat path_after;
    if (result == 0 &&
        fstatat(parent_fd, leaf, &path_after, AT_SYMLINK_NOFOLLOW) != 0)
    {
        saved = errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            saved);
    }
    else if (result == 0 &&
             (!S_ISREG(path_after.st_mode) ||
              !replay_hardlink_identity_matches(&opened, &path_after)))
    {
        saved = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            saved);
    }
    if (close(fd) != 0 && result == 0)
    {
        saved = errno == 0 ? EIO : errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

// Whether the file at leaf is no longer the one replay left: removed,
// replaced by another regular file, or rewritten (its size or mtime moved;
// replay set mtime to the backup's, and a writer sets it to now). Content
// that differs while all of these match is corruption, not a later write,
// and anything but a regular file in its place stays a failure.
static int replay_changed_after_restore(const ReplayEntry *replay,
                                        int parent_fd, const char *leaf)
{
    struct stat now;
    if (fstatat(parent_fd, leaf, &now, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT;
    if (!S_ISREG(now.st_mode))
        return 0;
    return now.st_dev != replay->written_dev ||
           now.st_ino != replay->written_ino ||
           now.st_size != replay->written_size ||
           now.st_mtim.tv_sec != replay->written_mtime.tv_sec ||
           now.st_mtim.tv_nsec != replay->written_mtime.tv_nsec;
}

// Returns 0 when the restored file matches, 1 when another program changed
// it after it was restored (D67), and -1 on a mismatch or error.
static int replay_verify_regular(ReplayCollection *collection,
                                 ReplayEntry *replay,
                                 ReplayApplyFailure *failure)
{
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    if (replay == NULL || replay->entry == NULL ||
        replay->entry->kind != SIDECAR_KIND_REGULAR ||
        !replay->content_digest_valid)
    {
        errno = EIO;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_DESTINATION_CONTENT,
            errno);
        return -1;
    }
    if (replay_verification_destination_parent(collection, replay, &parent_fd,
                                               leaf, sizeof(leaf)) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
        return -1;
    }

    uint64_t digest = 0;
    int result = 0;
    if (replay->payload_differs)
    {
        // The restored file matches what was read, but the backup's copy no
        // longer matches what was captured: the backup itself is damaged.
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_BACKUP_CONTENT,
            errno);
    }
    if (result == 0)
        result = replay_destination_regular_digest(parent_fd, leaf, &digest,
                                                   failure);
    int differs = result == 0 && digest != replay->content_digest;
    if (!replay->payload_differs && replay->written_valid &&
        (result != 0 || differs) &&
        replay_changed_after_restore(replay, parent_fd, leaf))
    {
        // Another program wrote, replaced, or removed it after replay left
        // it; the restore itself was right (D67).
        if (failure != NULL)
            *failure = (ReplayApplyFailure){0};
        errno = 0;
        result = 1;
    }
    else if (differs)
    {
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_DESTINATION_CONTENT,
            errno);
    }
    int saved = errno;
    if (close(parent_fd) != 0 && result == 0)
    {
        saved = errno == 0 ? EIO : errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static int replay_verify_symlink(ReplayCollection *collection,
                                 ReplayEntry *replay,
                                 ReplayApplyFailure *failure)
{
    int parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    const SidecarEntry *entry = replay == NULL ? NULL : replay->entry;
    if (entry == NULL || entry->kind != SIDECAR_KIND_SYMLINK ||
        replay_verification_destination_parent(collection, replay, &parent_fd,
                                               leaf, sizeof(leaf)) != 0)
    {
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno == 0 ? EIO : errno);
        return -1;
    }

    int result = 0;
    struct stat before;
    if (fstatat(parent_fd, leaf, &before, AT_SYMLINK_NOFOLLOW) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
    }
    else if (!S_ISLNK(before.st_mode))
    {
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
    }

    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    ssize_t length = -1;
    if (result == 0)
    {
        length = readlinkat(parent_fd, leaf, target, sizeof(target));
        if (length < 0)
        {
            result = -1;
            replay_apply_failure_record(
                failure,
                PORTABLE_RESTORE_REPLAY_FAILURE_READ_DESTINATION_CONTENT,
                errno);
        }
    }
    if (result == 0 &&
        ((size_t)length != entry->symlink_target.length ||
         (length != 0 &&
          memcmp(target, entry->symlink_target.data, (size_t)length) != 0)))
    {
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_COMPARE_DESTINATION_CONTENT,
            errno);
    }

    struct stat desired;
    if (result == 0 && replay_desired_stat(collection, entry, &desired) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES, errno);
    }
    if (result == 0 &&
        metadata_apply_symlink_times_at(parent_fd, leaf, &desired,
                                        collection->timestamp_policy) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_APPLY_TIMES, errno);
    }

    struct stat after;
    if (result == 0 &&
        fstatat(parent_fd, leaf, &after, AT_SYMLINK_NOFOLLOW) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
    }
    else if (result == 0 &&
             (!S_ISLNK(after.st_mode) ||
              !replay_hardlink_identity_matches(&before, &after)))
    {
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);
    }

    int saved = errno;
    if (close(parent_fd) != 0 && result == 0)
    {
        saved = errno == 0 ? EIO : errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static int replay_verify_hardlink(ReplayCollection *collection,
                                  ReplayEntry *replay,
                                  ReplayApplyFailure *failure)
{
    if (collection == NULL || replay == NULL || replay->entry == NULL ||
        replay->entry->kind != SIDECAR_KIND_HARDLINK ||
        replay->hardlink_ref_entry == NULL ||
        replay->hardlink_ref_root_index >=
            (size_t)collection->manifest->root_count)
    {
        errno = EINVAL;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK,
            errno);
        return -1;
    }

    int parent_fd = -1;
    int ref_parent_fd = -1;
    char leaf[NAME_MAX + 1U];
    char ref_leaf[NAME_MAX + 1U];
    int result = replay_verification_destination_parent(
        collection, replay, &parent_fd, leaf, sizeof(leaf));
    if (result == 0)
    {
        char ref_relative[PATH_MAX];
        result = replay_hardlink_ref_relative(
            &collection->manifest->roots[replay->hardlink_ref_root_index],
            replay->hardlink_ref_entry, collection->destination_xdg_dirs,
            ref_relative, sizeof(ref_relative));
        if (result == 0)
            result = replay_verification_destination_parent_for_root(
                collection, replay->hardlink_ref_root_index, ref_relative,
                &ref_parent_fd, ref_leaf, sizeof(ref_leaf));
    }
    if (result != 0)
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
            errno);

    struct stat linked;
    struct stat reference;
    if (result == 0 &&
        fstatat(parent_fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK,
            errno);
    }
    if (result == 0 &&
        fstatat(ref_parent_fd, ref_leaf, &reference, AT_SYMLINK_NOFOLLOW) != 0)
    {
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK,
            errno);
    }
    if (result == 0 &&
        (!S_ISREG(linked.st_mode) || !S_ISREG(reference.st_mode) ||
         !replay_hardlink_identity_matches(&linked, &reference)))
    {
        errno = EIO;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_HARDLINK,
            errno);
    }

    int saved = errno;
    if (ref_parent_fd >= 0 && close(ref_parent_fd) != 0 && result == 0)
    {
        saved = errno == 0 ? EIO : errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    if (parent_fd >= 0 && close(parent_fd) != 0 && result == 0)
    {
        saved = errno == 0 ? EIO : errno;
        result = -1;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_CLOSE_DESCRIPTOR, saved);
    }
    errno = saved;
    return result;
}

static int replay_regular_content_verification_excluded(
    const SidecarEntry *entry)
{
    if (entry == NULL || entry->kind != SIDECAR_KIND_REGULAR ||
        entry->root_id.data == NULL || entry->logical_path.data == NULL)
        return 0;
    return live_state_path((const char *)entry->root_id.data,
                           entry->root_id.length,
                           (const char *)entry->logical_path.data,
                           entry->logical_path.length);
}

static int replay_content_verification_excluded(
    const ReplayCollection *collection, const ReplayEntry *replay)
{
    return replay != NULL &&
           (replay->deferral == REPLAY_DEFERRED_SKIPPED ||
            replay->deferral == REPLAY_LEFT_OUT ||
            replay_regular_content_verification_excluded(replay->entry) ||
            replay_regular_is_locally_authoritative(collection, replay));
}

static int replay_verify_content(ReplayCollection *collection)
{
    if (collection == NULL || collection->report == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    size_t total_count = 0;
    for (size_t index = 0; index < collection->count; index++)
    {
        const ReplayEntry *replay = &collection->items[index];
        const SidecarEntry *entry = replay->entry;
        if (replay_content_verification_excluded(collection, replay))
            continue;
        SidecarObjectKind kind = entry->kind;
        if ((kind == SIDECAR_KIND_REGULAR || kind == SIDECAR_KIND_SYMLINK ||
             kind == SIDECAR_KIND_HARDLINK) &&
            total_count != SIZE_MAX)
            total_count++;
    }

    if (collection->before_content_verification != NULL)
        collection->before_content_verification(
            collection->before_content_verification_context);
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (before_content_verification_hook != NULL)
        before_content_verification_hook();
#endif

    // Both are counted in the report as well; these keep examples.
    ExampleList failed = {0};
    ExampleList changed = {0};
    ReplayVerificationProgress progress;
    replay_verification_progress_start(&progress, total_count);
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        if (replay_content_verification_excluded(collection, replay))
            continue;
        ReplayApplyFailure failure = {0};
        int result = 0;
        switch (replay->entry->kind)
        {
            case SIDECAR_KIND_REGULAR:
                result = replay_verify_regular(collection, replay, &failure);
                break;
            case SIDECAR_KIND_SYMLINK:
                result = replay_verify_symlink(collection, replay, &failure);
                break;
            case SIDECAR_KIND_HARDLINK:
                result = replay_verify_hardlink(collection, replay, &failure);
                break;
            case SIDECAR_KIND_DIRECTORY:
                continue;
            case SIDECAR_KIND_FIFO:
                errno = EINVAL;
                result = -1;
                replay_apply_failure_record(
                    &failure,
                    PORTABLE_RESTORE_REPLAY_FAILURE_VERIFY_DESTINATION_PATH,
                    errno);
                break;
        }

        if (collection->report->verification_checked_count != SIZE_MAX)
            collection->report->verification_checked_count++;
        replay_verification_progress_note(
            &progress, collection->report->verification_checked_count, 0);
        if (result > 0)
        {
            if (collection->report->verification_changed_count != SIZE_MAX)
                collection->report->verification_changed_count++;
            replay_log_entry(collection, replay,
                             "Changed by another program after restore");
            char *text = example_list_next(&changed);
            if (text != NULL)
            {
                char logical[PATH_MAX];
                replay_copy_bytes(logical, sizeof(logical),
                                  replay->entry->logical_path);
                snprintf(text, EXAMPLE_TEXT_MAX, "%s:%s",
                         collection->manifest->roots[replay->root_index].id,
                         logical[0] != '\0' ? logical : ".");
            }
        }
        else if (result != 0)
        {
            // Every item is already applied, so keep checking: one mismatch
            // must not hide the rest. The first one stays the reported one.
            if (collection->report->verification_failed_count != SIZE_MAX)
                collection->report->verification_failed_count++;
            if (collection->report->verification_failed_count == 1)
                replay_report_apply_failure(
                    collection->report, collection->manifest,
                    replay->root_index, replay->entry, &failure);
            else if (collection->report->failed_count != SIZE_MAX)
                collection->report->failed_count++;
            char *text = example_list_next(&failed);
            if (text != NULL)
            {
                PortableRestoreReplayReport scratch;
                portable_restore_replay_report_init(&scratch);
                replay_report_apply_failure(
                    &scratch, collection->manifest, replay->root_index,
                    replay->entry, &failure);
                char reason[256];
                if (replay_failure_reason_format(&scratch, reason,
                                                 sizeof(reason)) != 1)
                    reason[0] = '\0';
                snprintf(text, EXAMPLE_TEXT_MAX, "%s:%s%s%s%s",
                         scratch.failed_root_id,
                         scratch.failed_logical_path[0] != '\0'
                             ? scratch.failed_logical_path : ".",
                         reason[0] != '\0' ? " (" : "", reason,
                         reason[0] != '\0' ? ")" : "");
            }
        }
    }
    replay_verification_progress_finish(
        &progress, collection->report->verification_checked_count);
    if (changed.count != 0)
    {
        printf("%zu restored item%s changed by other programs after "
               "%s restored; not errors:\n", changed.count,
               changed.count == 1 ? " was" : "s were",
               changed.count == 1 ? "it was" : "they were");
        example_list_print(&changed, "  ");
    }
    if (failed.count == 0)
        return 0;
    printf("Verification found %zu restored item%s that differ%s from the "
           "backup:\n", failed.count, failed.count == 1 ? "" : "s",
           failed.count == 1 ? "s" : "");
    example_list_print(&failed, "  ");
    return -1;
}

/* Replay creates directories 0700 (owned by the restoring user) and applies
 * their recorded metadata only after their children. When replay stops early,
 * every directory this run prepared still gets that metadata, in the same
 * reverse order, so a failed restore does not leave e.g. a root-owned 0700
 * tree under HOME. Best-effort: the original failure stays the reported one. */
static void replay_finalize_prepared_directories(ReplayCollection *collection)
{
    int saved = errno;
    for (size_t index = collection->count; index != 0; index--)
    {
        ReplayEntry *replay = &collection->items[index - 1U];
        if (replay->entry->kind != SIDECAR_KIND_DIRECTORY ||
            replay->directory_state != REPLAY_DIRECTORY_PREPARED)
            continue;
        ReplayApplyFailure ignored = {0};
        if (replay_apply_directory_metadata(collection, replay, &ignored) == 0)
            replay->directory_state = REPLAY_DIRECTORY_FINALIZED;
    }
    errno = saved;
}

// Applies one entry of any kind but a directory's final metadata, with the
// accounting the apply passes share. On failure the report names the entry
// and prepared directories are finalized.
static int replay_apply_entry(ReplayCollection *collection,
                              ReplayEntry *replay,
                              unsigned char *printed_roots)
{
    ReplayApplyFailure failure = {0};
    int result;
    replay_print_verbose_root(collection, replay->root_index, printed_roots);
    if (replay->entry->kind == SIDECAR_KIND_HARDLINK)
        result = replay_apply_hardlink(collection, replay, &failure);
    else if (replay->entry->kind == SIDECAR_KIND_SYMLINK)
        result = replay_apply_symlink(collection, replay, &failure);
    else if (replay->entry->kind == SIDECAR_KIND_DIRECTORY)
        result = replay_prepare_directory(collection, replay, &failure);
    else
        result = replay_apply_regular(collection, replay, &failure);
    if (result != 0)
    {
        replay_report_apply_failure(
            collection->report, collection->manifest, replay->root_index,
            replay->entry, &failure);
        replay_finalize_prepared_directories(collection);
        return -1;
    }
    if (replay->entry->kind == SIDECAR_KIND_DIRECTORY)
        replay->directory_state = REPLAY_DIRECTORY_PREPARED;
    else if (replay->entry->kind == SIDECAR_KIND_REGULAR)
        replay_capture_dconf_database(collection, replay);
    if (replay->entry->kind == SIDECAR_KIND_REGULAR &&
        replay_regular_is_locally_authoritative(collection, replay))
    {
        if (collection->report->preserved_local_state_count != SIZE_MAX)
            collection->report->preserved_local_state_count++;
        replay_log_entry(collection, replay,
                         "Left as the destination had it");
    }
    else if (replay->kept_live_state)
    {
        if (collection->report->live_state_kept_count != SIZE_MAX)
            collection->report->live_state_kept_count++;
        replay_log_entry(collection, replay,
                         "Left as a running service wrote it");
    }
    else if (replay->entry->kind != SIDECAR_KIND_DIRECTORY)
    {
        if (collection->report->applied_count != SIZE_MAX)
            collection->report->applied_count++;
    }
    return 0;
}

static int replay_path_is_below(const char *path, const char *prefix)
{
    size_t length = strlen(prefix);
    return length != 0 && strncmp(path, prefix, length) == 0 &&
           (path[length] == '\0' || path[length] == '/');
}

static int replay_relative_is_deferred(const ReplayCollection *collection,
                                       const char *relative)
{
    for (size_t index = 0; index < collection->deferred_path_count; index++)
        if (collection->deferred_paths[index].home_relative != NULL &&
            replay_path_is_below(relative,
                                 collection->deferred_paths[index].home_relative))
            return 1;
    return 0;
}

// Marks what an open application owns (D66): regular files and symlinks
// below a deferred path of a home-relative root, and hardlinks whose own
// name or representative is there, so a link never precedes its target.
static void replay_mark_deferred(ReplayCollection *collection)
{
    if (collection->deferred_path_count == 0)
        return;
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        const ManifestRoot *root =
            &collection->manifest->roots[replay->root_index];
        if (replay->entry->kind == SIDECAR_KIND_DIRECTORY ||
            root->policy != ROOT_POLICY_HOME_RELATIVE ||
            replay->deferral != REPLAY_NOT_DEFERRED)
            continue;
        char relative[PATH_MAX];
        int deferred =
            replay_destination_relative(collection, replay, relative,
                                        sizeof(relative)) == 0 &&
            replay_relative_is_deferred(collection, relative);
        if (!deferred && replay->entry->kind == SIDECAR_KIND_HARDLINK &&
            replay->hardlink_ref_entry != NULL &&
            replay->hardlink_ref_root_index <
                (size_t)collection->manifest->root_count)
        {
            const ManifestRoot *ref_root =
                &collection->manifest->roots[replay->hardlink_ref_root_index];
            deferred = ref_root->policy == ROOT_POLICY_HOME_RELATIVE &&
                       replay_hardlink_ref_relative(
                           ref_root, replay->hardlink_ref_entry,
                           collection->destination_xdg_dirs, relative,
                           sizeof(relative)) == 0 &&
                       replay_relative_is_deferred(collection, relative);
        }
        if (!deferred)
            continue;
        replay->deferral = REPLAY_DEFERRED;
        if (collection->report->deferred_count != SIZE_MAX)
            collection->report->deferred_count++;
    }
}

// Reads the backup's containers.json from its payload, at most 16 MiB.
static int replay_read_containers_json(ReplayCollection *collection,
                                       const ReplayEntry *replay,
                                       PodmanContainers *out)
{
    int fd = -1;
    struct stat st;
    if (replay_open_payload(collection,
                            &collection->manifest->roots[replay->root_index],
                            replay->entry, &fd, &st) != 0)
        return -1;
    int result = -1;
    char *text = NULL;
    if (st.st_size > 16 * 1024 * 1024 ||
        (text = malloc((size_t)st.st_size + 1U)) == NULL)
        goto done;
    size_t length = 0;
    while (length < (size_t)st.st_size)
    {
        ssize_t count = read(fd, text + length, (size_t)st.st_size - length);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        length += (size_t)count;
    }
    result = podman_containers_parse(text, length, out);
done:
    free(text);
    close(fd);
    return result;
}

// Leaves out the backup's podman container state, which would not work on
// this system (D94): the containers its containers.json names, their
// writable layers and links, and podman's database. The containers' names
// go to the caller.
static int replay_mark_left_out_containers(ReplayCollection *collection)
{
    PodmanContainers *containers = collection->left_out_containers;
    char storage[PATH_MAX];
    if (containers == NULL ||
        path_join(storage, sizeof(storage),
                  collection->manifest->source_home, PODMAN_STORAGE) != 0)
        return 0;
    for (size_t index = 0; index < collection->count; index++)
        if (replay_regular_is_home_file(collection, &collection->items[index],
                                        PODMAN_STORAGE "/"
                                        PODMAN_CONTAINERS_JSON))
        {
            if (replay_read_containers_json(collection,
                                            &collection->items[index],
                                            containers) != 0)
            {
                print_error("Error: Could not read the backup's podman "
                            "containers.json\n");
                return -1;
            }
            break;
        }

    size_t storage_length = strlen(storage);
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        char source_path[PATH_MAX], target[PATH_MAX];
        if (replay_entry_source_path(collection, replay, source_path) != 0 ||
            strncmp(source_path, storage, storage_length) != 0 ||
            source_path[storage_length] != '/')
            continue;
        const char *link_target = NULL;
        const SidecarBytes *link = &replay->entry->symlink_target;
        if (replay->entry->kind == SIDECAR_KIND_SYMLINK &&
            link->length < sizeof(target) &&
            memchr(link->data, '\0', link->length) == NULL)
        {
            memcpy(target, link->data, link->length);
            target[link->length] = '\0';
            link_target = target;
        }
        if (podman_state_left_out(containers, source_path + storage_length + 1,
                                  link_target))
            replay->deferral = REPLAY_LEFT_OUT;
    }
    return 0;
}

// Restores what was deferred, now that everything else is in place, unless
// before_deferred says to leave it out (D66).
static int replay_apply_deferred(ReplayCollection *collection,
                                 unsigned char *printed_roots)
{
    if (collection->report->deferred_count == 0)
        return 0;
    int restore = collection->before_deferred == NULL ||
                  collection->before_deferred(
                      collection->before_deferred_context) != 0;
    for (int hardlinks = 0; hardlinks < 2; hardlinks++)
        for (size_t index = 0; index < collection->count; index++)
        {
            ReplayEntry *replay = &collection->items[index];
            if (replay->deferral != REPLAY_DEFERRED ||
                (replay->entry->kind == SIDECAR_KIND_HARDLINK) != hardlinks)
                continue;
            if (!restore)
            {
                replay->deferral = REPLAY_DEFERRED_SKIPPED;
                if (collection->report->deferred_skipped_count != SIZE_MAX)
                    collection->report->deferred_skipped_count++;
                replay_log_entry(collection, replay,
                                 "Left out, its application stayed open");
                continue;
            }
            if (replay_apply_entry(collection, replay, printed_roots) != 0)
                return -1;
        }
    return 0;
}

static int replay_run(ReplayCollection *collection)
{
    if (collection == NULL || collection->report == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    unsigned char printed_roots[MANIFEST_MAX_ROOTS] = { 0 };
    qsort(collection->items, collection->count, sizeof(*collection->items),
          replay_entry_compare);

    /* Three passes over the same sorted set, not one:
     * 1. Every non-HARDLINK entry, in resolved namespace order.
     * 2. HARDLINK entries only, in a second pass over the same set --
     *    deferred because neither the sidecar's hash-bucket iteration order
     *    nor this sort gives any representative-before-alias guarantee a
     *    single combined pass could rely on (D22 As-built, Phase G).
     * 3. Directory metadata, applied in reverse sorted order so every child
     *    is already on disk before its parent's own metadata (mtime
     *    especially) is set (D17, "directories: children first, then exact
     *    post-order metadata"). */
    if (replay_mark_left_out_containers(collection) != 0)
        return -1;
    replay_mark_deferred(collection);
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        if (replay->entry->kind == SIDECAR_KIND_HARDLINK ||
            replay->deferral != REPLAY_NOT_DEFERRED)
            continue;
        if (replay_apply_entry(collection, replay, printed_roots) != 0)
            return -1;
    }

    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        if (replay->entry->kind != SIDECAR_KIND_HARDLINK ||
            replay->deferral != REPLAY_NOT_DEFERRED)
            continue;
        if (replay_apply_entry(collection, replay, printed_roots) != 0)
            return -1;
    }

    if (replay_apply_deferred(collection, printed_roots) != 0)
        return -1;

    for (size_t index = collection->count; index != 0; index--)
    {
        ReplayEntry *replay = &collection->items[index - 1U];
        if (replay->entry->kind != SIDECAR_KIND_DIRECTORY ||
            replay->deferral == REPLAY_LEFT_OUT)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        ReplayApplyFailure failure = {0};
        if (replay_apply_directory_metadata(collection, replay, &failure) != 0)
        {
            replay_report_apply_failure(
                collection->report, collection->manifest, replay->root_index,
                replay->entry, &failure);
            replay_finalize_prepared_directories(collection);
            return -1;
        }
        replay->directory_state = REPLAY_DIRECTORY_FINALIZED;
        if (collection->report->applied_count != SIZE_MAX)
            collection->report->applied_count++;
    }
#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
    if (after_apply_hook != NULL)
        after_apply_hook();
#endif
    if (!collection->skip_content_verification &&
        replay_verify_content(collection) != 0)
        return -1;
    return 0;
}

void portable_restore_replay_report_init(PortableRestoreReplayReport *report)
{
    if (report == NULL)
        return;
    memset(report, 0, sizeof(*report));
}

int replay_timestamp_policy(const PortableRestoreRequest *request,
                            MetadataTimestampPolicy *out)
{
    if (request == NULL || out == NULL ||
        !request->destination_timestamp_policy.configured ||
        (request->destination_timestamp_policy.nsec_exact != 0 &&
         request->destination_timestamp_policy.nsec_exact != 1))
    {
        errno = EINVAL;
        return -1;
    }
    *out = request->destination_timestamp_policy;
    return 0;
}

int portable_restore_replay_at(const PortableRestoreRequest *request,
                               PortableRestoreReplayReport *report)
{
    if (request == NULL || report == NULL || request->source_container_fd < 0 ||
        request->destination_home_fd < 0 || request->manifest == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    MetadataTimestampPolicy timestamp_policy;
    if (replay_timestamp_policy(request, &timestamp_policy) != 0 ||
        replay_manifest_valid(request->manifest,
                              request->destination_xdg_dirs,
                              request->destination_home_path) != 0)
    {
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
        return -1;
    }

    HomeRewritePair home_rewrite_pairs[HOME_REWRITE_MAX_PAIRS] = {0};
    size_t home_rewrite_pair_count = 0;
    if (home_rewrite_pairs_build(
            request->manifest, request->destination_xdg_dirs,
            request->destination_home_path, home_rewrite_pairs,
            &home_rewrite_pair_count) != 0)
    {
        int saved = errno;
        replay_report_step_failure(
            report, request->manifest, SIZE_MAX, NULL,
            PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_HOME_REWRITE_TABLE, saved);
        return -1;
    }

    ReplayCollection collection = {
        .manifest = request->manifest,
        .data_fd = -1,
        .destination_home_fd = request->destination_home_fd,
        .destination_home_path = request->destination_home_path,
        .destination_xdg_dirs = request->destination_xdg_dirs,
        .home_rewrite_pairs = home_rewrite_pairs,
        .home_rewrite_pair_count = home_rewrite_pair_count,
        .timestamp_policy = timestamp_policy,
        .owner_map = request->owner_map,
        .report = report,
        .capture_report = request->capture_report,
        .skip_content_verification = request->skip_content_verification,
        .before_content_verification = request->before_content_verification,
        .before_content_verification_context =
            request->before_content_verification_context,
        .dconf_database_fd_out = request->dconf_database_fd_out,
        .dconf_loads_into_session = request->dconf_loads_into_session,
        .deferred_paths = request->deferred_paths,
        .deferred_path_count = request->deferred_path_count,
        .before_deferred = request->before_deferred,
        .before_deferred_context = request->before_deferred_context,
        .left_out_containers = request->left_out_containers
    };
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        collection.xdg_anchor_fd[index] = -1;
    collection.parent_cache.fd = -1;
    collection.verification_parent_cache.fd = -1;
    collection.payload_cache.fd = -1;
    if (root_map_build(&collection.root_map, request->manifest) != 0)
        goto fail;

    struct stat home_st;
    if (fstat(request->destination_home_fd, &home_st) != 0 ||
        !S_ISDIR(home_st.st_mode))
    {
        errno = ENOTDIR;
        goto fail;
    }
    if (sidecar_is_complete_readonly(request->source_container_fd) != 0)
        goto fail;
    collection.data_fd = openat(request->source_container_fd, "data",
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                    O_NOATIME | O_CLOEXEC);
    if (collection.data_fd < 0)
        goto fail;

    SidecarLog sidecar = {0};
    if (sidecar_log_open_readonly_at(request->source_container_fd, &sidecar) !=
        SIDECAR_OPEN_RESUMABLE)
    {
        close(collection.data_fd);
        collection.data_fd = -1;
        goto fail;
    }
    if (sidecar_log_claim_count(&sidecar) != 0)
    {
        sidecar_log_close(&sidecar);
        close(collection.data_fd);
        collection.data_fd = -1;
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
        goto fail;
    }
    collection.sidecar = &sidecar;
    const SidecarEntry *address_failure_entry = NULL;
    errno = 0;
    if (restore_address_index_build(&collection.address_index,
                                    &collection.memory, &sidecar,
                                    &address_failure_entry) != 0)
    {
        int saved = errno;
        size_t root_index = SIZE_MAX;
        if (address_failure_entry != NULL)
            root_index = root_map_find(&collection.root_map,
                                       request->manifest,
                                       address_failure_entry->root_id);
        replay_report_step_failure(
            report, request->manifest, root_index, address_failure_entry,
            PORTABLE_RESTORE_REPLAY_FAILURE_BUILD_ADDRESS_INDEX, saved);
        sidecar_log_close(&sidecar);
        close(collection.data_fd);
        collection.data_fd = -1;
        goto fail;
    }
    SidecarStatus status = sidecar_log_foreach(&sidecar,
                                               replay_collect_entry,
                                               &collection);
    /* Past this point the failure carrier is a plain 0/-1, not a
     * SidecarStatus: neither the capability gate below nor replay_run
     * reports a sidecar-log condition, so neither has an honest
     * SidecarStatus to return. */
    int result = status == SIDECAR_STATUS_OK ? 0 : -1;
    if (result == 0 && replay_selection_destinations_valid(&collection) != 0)
        result = -1;
    /*
     * Pre-mutation xattr capability gate (D20 E-9). A single probe at the
     * destination home cannot observe a subtree on a different mount with
     * different xattr support (e.g. ~/usb on vfat under an ext4 home);
     * such a failure surfaces later through E-3's fail-closed partial
     * result, exactly the class D20 E-9's closing paragraph assigns to
     * post-gate failures.
     */
    if (result == 0 &&
        metadata_xattr_capability_probe(collection.destination_home_fd,
                                        &collection.xattr_requirements) != 0)
        result = -1;
    if (result == 0)
        result = replay_run(&collection);
    int saved_errno = errno;
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
    {
        if (result == 0)
            saved_errno = errno == 0 ? EIO : errno;
        result = -1;
    }
    if (close(collection.data_fd) != 0)
    {
        if (result == 0)
            saved_errno = errno == 0 ? EIO : errno;
        result = -1;
    }
    collection.data_fd = -1;
    if (replay_close_xdg_anchors(&collection) != 0)
    {
        if (result == 0)
            saved_errno = errno == 0 ? EIO : errno;
        result = -1;
    }
    errno = saved_errno;
    if (result == 0)
    {
        replay_collection_free(&collection);
        return 0;
    }
    if (report->failed_count == 0)
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
    replay_collection_free(&collection);
    return -1;

fail:
    if (collection.data_fd >= 0)
        close(collection.data_fd);
    if (report->failed_count == 0)
        replay_report_failure(report, request->manifest, SIZE_MAX,
                              (SidecarBytes){0});
    replay_collection_free(&collection);
    return -1;
}
