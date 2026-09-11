#define _GNU_SOURCE

#include "portable_restore_internal.h"
#include "portable_restore_replay_internal.h"
#include "portable_restore.h"
#include "backup.h"
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
} ReplayEntry;

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
    int xdg_anchor_fd[XDG_KEY_COUNT];
    char xdg_anchor_prefix[XDG_KEY_COUNT][PATH_MAX];
    ReplayParentCache parent_cache;
    ReplayParentCache verification_parent_cache;
    ReplayPayloadParentCache payload_cache;
    MetadataTimestampPolicy timestamp_policy;
    PortableRestoreReplayReport *report;
    BackupCaptureReport *capture_report;
    MetadataXattrRequirements xattr_requirements;
    int skip_content_verification;
    void (*before_content_verification)(void *context);
    void *before_content_verification_context;
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
            return "compare restored content";
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
    int length;
    if (kind != NULL && report->failure_errno != 0)
        length = snprintf(out, out_size, "%s, %s: %s", kind, step,
                          strerror(report->failure_errno));
    else if (kind != NULL)
        length = snprintf(out, out_size, "%s, %s", kind, step);
    else if (report->failure_errno != 0)
        length = snprintf(out, out_size, "%s: %s", step,
                          strerror(report->failure_errno));
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
    if (replay_stat_from_entry(entry, &desired) != 0)
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

static int replay_regular_rewrites_home(const ReplayCollection *collection,
                                        const ReplayEntry *replay)
{
    if (collection == NULL || collection->manifest == NULL || replay == NULL ||
        replay->entry == NULL ||
        replay->root_index >= (size_t)collection->manifest->root_count ||
        collection->manifest->version != MANIFEST_SELECTION_VERSION ||
        collection->manifest->source_home[0] == '\0' ||
        collection->destination_home_path == NULL ||
        strcmp(collection->manifest->source_home,
               collection->destination_home_path) == 0)
        return 0;

    char logical[PATH_MAX];
    replay_copy_bytes(logical, sizeof(logical), replay->entry->logical_path);
    if (replay->entry->logical_path.length >= sizeof(logical))
        return 0;

    char source_root[PATH_MAX];
    if (manifest_root_source_path(collection->manifest,
                                  (int)replay->root_index,
                                  source_root) != 0)
        return 0;

    char source_path[PATH_MAX];
    if (logical[0] == '\0')
        memcpy(source_path, source_root, strlen(source_root) + 1U);
    else if (path_join(source_path, sizeof(source_path), source_root,
                       logical) != 0)
        return 0;

    static const char *const known_home_relative_paths[] = {
        ".config/gtk-3.0/bookmarks",
        ".local/share/recently-used.xbel"
    };
    for (size_t index = 0;
         index < sizeof(known_home_relative_paths) /
                     sizeof(known_home_relative_paths[0]);
         index++)
    {
        char known_path[PATH_MAX];
        if (path_join(known_path, sizeof(known_path),
                      collection->manifest->source_home,
                      known_home_relative_paths[index]) == 0 &&
            strcmp(source_path, known_path) == 0)
            return 1;
    }
    return 0;
}

static int replay_write_all(int fd, const unsigned char *data, size_t length,
                            uint64_t *hash)
{
    size_t offset = 0;
    while (offset < length)
    {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
        {
            if (written == 0)
                errno = EIO;
            return -1;
        }
        if (hash != NULL)
            *hash = hash_fnv1a_bytes(*hash, data + offset, (size_t)written);
        offset += (size_t)written;
    }
    return 0;
}

static size_t replay_bytes_find(const unsigned char *haystack,
                                size_t haystack_length,
                                const unsigned char *needle,
                                size_t needle_length)
{
    if (needle_length == 0 || haystack_length < needle_length)
        return SIZE_MAX;
    size_t limit = haystack_length - needle_length;
    for (size_t index = 0; index <= limit; index++)
        if (haystack[index] == needle[0] &&
            memcmp(haystack + index, needle, needle_length) == 0)
            return index;
    return SIZE_MAX;
}

/* Flushes every replacement whose trailing path-component boundary is already
 * known. On non-final chunks, at most one source-home length remains buffered
 * so a match and its following boundary may straddle the next read. */
static int replay_home_uri_boundary(unsigned char byte)
{
    return byte == '/' || byte == ' ' || byte == '\t' || byte == '\r' ||
           byte == '\n' || byte == '"' || byte == '\'';
}

static int replay_home_rewrite_flush(int destination_fd,
                                     const unsigned char *buffer,
                                     size_t length,
                                     const unsigned char *source_uri,
                                     size_t source_uri_length,
                                     const unsigned char *destination_uri,
                                     size_t destination_uri_length,
                                     int final, size_t *consumed_out,
                                     uint64_t *hash)
{
    if (destination_fd < 0 || buffer == NULL || source_uri == NULL ||
        source_uri_length == 0 || destination_uri == NULL ||
        consumed_out == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    size_t safe_start = final ? length :
        (length > source_uri_length ? length - source_uri_length : 0U);
    size_t cursor = 0;
    while (cursor < length)
    {
        size_t relative = replay_bytes_find(
            buffer + cursor, length - cursor,
            source_uri, source_uri_length);
        if (relative == SIZE_MAX)
            break;
        size_t match = cursor + relative;
        if (!final && match >= safe_start)
            break;

        size_t after = match + source_uri_length;
        int component_boundary =
            after < length ? replay_home_uri_boundary(buffer[after]) : final;
        if (component_boundary)
        {
            if (replay_write_all(destination_fd, buffer + cursor,
                                 match - cursor, hash) != 0 ||
                replay_write_all(destination_fd, destination_uri,
                                 destination_uri_length, hash) != 0)
                return -1;
            cursor = after;
        }
        else
        {
            /* Emit one byte, not the whole rejected candidate: a canonical
             * path can contain a later suffix that is also its own prefix. */
            if (replay_write_all(destination_fd, buffer + cursor,
                                 match + 1U - cursor, hash) != 0)
                return -1;
            cursor = match + 1U;
        }
    }

    size_t flush_to = final ? length : safe_start;
    if (cursor < flush_to)
    {
        if (replay_write_all(destination_fd, buffer + cursor,
                             flush_to - cursor, hash) != 0)
            return -1;
        cursor = flush_to;
    }
    *consumed_out = cursor;
    return 0;
}

static int replay_copy_regular_rewriting_home(
    int source_fd, int destination_fd, off_t expected_size,
    const char *source_home, const char *destination_home,
    BackupCaptureReport *report, uint64_t *digest)
{
    if (source_fd < 0 || destination_fd < 0 || expected_size < 0 ||
        source_home == NULL || source_home[0] == '\0' ||
        destination_home == NULL || destination_home[0] == '\0' ||
        digest == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (ftruncate(destination_fd, 0) != 0)
        return -1;

    enum { FILE_URI_PREFIX_LENGTH = 7, REWRITE_READ_SIZE = 65536 };
    size_t old_length = strnlen(source_home, PATH_MAX);
    size_t new_length = strnlen(destination_home, PATH_MAX);
    if (old_length == PATH_MAX || new_length == PATH_MAX)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    unsigned char source_uri[PATH_MAX + FILE_URI_PREFIX_LENGTH + 1U];
    unsigned char destination_uri[PATH_MAX + FILE_URI_PREFIX_LENGTH + 1U];
    memcpy(source_uri, "file://", FILE_URI_PREFIX_LENGTH);
    memcpy(source_uri + FILE_URI_PREFIX_LENGTH, source_home, old_length);
    size_t source_uri_length = FILE_URI_PREFIX_LENGTH + old_length;
    memcpy(destination_uri, "file://", FILE_URI_PREFIX_LENGTH);
    memcpy(destination_uri + FILE_URI_PREFIX_LENGTH, destination_home,
           new_length);
    size_t destination_uri_length = FILE_URI_PREFIX_LENGTH + new_length;

    unsigned char buffer[REWRITE_READ_SIZE + PATH_MAX +
                         FILE_URI_PREFIX_LENGTH + 1U];
    size_t carried = 0;
    uint64_t copied = 0;
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;

    for (;;)
    {
        ssize_t received = read(source_fd, buffer + carried,
                                REWRITE_READ_SIZE);
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            return -1;
        if (received == 0)
        {
            size_t consumed = 0;
            if (replay_home_rewrite_flush(
                    destination_fd, buffer, carried,
                    source_uri, source_uri_length,
                    destination_uri, destination_uri_length,
                    1, &consumed, &hash) != 0)
                return -1;
            if (consumed != carried)
            {
                errno = EIO;
                return -1;
            }
            break;
        }

        if ((uint64_t)received > UINT64_MAX - copied)
        {
            errno = EOVERFLOW;
            return -1;
        }
        copied += (uint64_t)received;
        size_t total = carried + (size_t)received;
        size_t consumed = 0;
        if (replay_home_rewrite_flush(
                destination_fd, buffer, total,
                source_uri, source_uri_length,
                destination_uri, destination_uri_length,
                0, &consumed, &hash) != 0)
            return -1;
        carried = total - consumed;
        if (carried > source_uri_length)
        {
            errno = EIO;
            return -1;
        }
        if (carried != 0)
            memmove(buffer, buffer + consumed, carried);
        if (backup_capture_report_tick(report, received, destination_fd) != 0)
            return -1;
    }

    if (copied != (uint64_t)expected_size)
    {
        errno = EIO;
        return -1;
    }
    *digest = hash;
    return 0;
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
    if (entry->size > (uint64_t)INTMAX_MAX)
    {
        errno = EOVERFLOW;
        replay_apply_failure_record(
            failure, PORTABLE_RESTORE_REPLAY_FAILURE_VALIDATE_ENTRY, errno);
        return -1;
    }
    struct stat desired;
    if (replay_stat_from_entry(entry, &desired) != 0)
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
        if (replay_regular_rewrites_home(collection, replay))
            result = replay_copy_regular_rewriting_home(
                source_fd, destination_fd, (off_t)entry->size,
                collection->manifest->source_home,
                collection->destination_home_path,
                collection->capture_report, &replay->content_digest);
        else
            result = portable_copy_regular_digest(
                source_fd, destination_fd, (off_t)entry->size,
                collection->capture_report, &replay->content_digest);
        if (result != 0)
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_COPY_CONTENT, errno);
        else
            replay->content_digest_valid = 1;
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
    if (replay_stat_from_entry(entry, &desired) != 0)
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
    if (result == 0)
    {
        struct stat existing;
        if (fstatat(parent_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
        {
            errno = EEXIST;
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                errno);
        }
        else if (errno != ENOENT)
        {
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                errno);
        }
    }
    if (result == 0 && symlinkat(target, parent_fd, leaf) != 0)
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
    if (result == 0)
    {
        struct stat existing;
        if (fstatat(parent_fd, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0)
        {
            errno = EEXIST;
            result = -1;
            replay_apply_failure_record(
                failure, PORTABLE_RESTORE_REPLAY_FAILURE_CHECK_DESTINATION,
                errno);
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
    if (result == 0 && hardlink_race_hook != NULL)
        hardlink_race_hook();
#endif
    if (result == 0 && linkat(ref_parent_fd, ref_leaf, parent_fd, leaf, 0) != 0)
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
    if (replay_stat_from_entry(entry, &desired) != 0)
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
    return isatty(fileno(stdout));
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

static void replay_verification_progress_cancel(
    ReplayVerificationProgress *display)
{
    if (display == NULL || !display->active)
        return;
    replay_verification_progress_stop_ticker(display);
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
    int result = replay_destination_regular_digest(parent_fd, leaf, &digest,
                                                   failure);
    if (result == 0 && digest != replay->content_digest)
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
    if (result == 0 && replay_stat_from_entry(entry, &desired) != 0)
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
    static const char root_id[] = "BUILTIN_LOCAL_SHARE";
    static const char logical_prefix[] = "gvfs-metadata";
    const size_t root_id_length = sizeof(root_id) - 1U;
    const size_t logical_prefix_length = sizeof(logical_prefix) - 1U;

    if (entry == NULL || entry->kind != SIDECAR_KIND_REGULAR ||
        entry->root_id.data == NULL ||
        entry->root_id.length != root_id_length ||
        memcmp(entry->root_id.data, root_id, root_id_length) != 0 ||
        entry->logical_path.data == NULL ||
        entry->logical_path.length < logical_prefix_length ||
        memcmp(entry->logical_path.data, logical_prefix,
               logical_prefix_length) != 0)
        return 0;

    return entry->logical_path.length == logical_prefix_length ||
           entry->logical_path.data[logical_prefix_length] == '/';
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
        const SidecarEntry *entry = collection->items[index].entry;
        if (replay_regular_content_verification_excluded(entry))
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

    ReplayVerificationProgress progress;
    replay_verification_progress_start(&progress, total_count);
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        if (replay_regular_content_verification_excluded(replay->entry))
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
        if (result != 0)
        {
            if (collection->report->verification_failed_count != SIZE_MAX)
                collection->report->verification_failed_count++;
            replay_verification_progress_cancel(&progress);
            replay_report_apply_failure(
                collection->report, collection->manifest, replay->root_index,
                replay->entry, &failure);
            return -1;
        }
    }
    replay_verification_progress_finish(
        &progress, collection->report->verification_checked_count);
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
    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        ReplayApplyFailure failure = {0};
        int result;
        if (replay->entry->kind == SIDECAR_KIND_HARDLINK)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        if (replay->entry->kind == SIDECAR_KIND_SYMLINK)
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
            return -1;
        }
        if (replay->entry->kind == SIDECAR_KIND_REGULAR ||
            replay->entry->kind == SIDECAR_KIND_SYMLINK)
        {
            if (collection->report->applied_count != SIZE_MAX)
                collection->report->applied_count++;
        }
    }

    for (size_t index = 0; index < collection->count; index++)
    {
        ReplayEntry *replay = &collection->items[index];
        if (replay->entry->kind != SIDECAR_KIND_HARDLINK)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        ReplayApplyFailure failure = {0};
        if (replay_apply_hardlink(collection, replay, &failure) != 0)
        {
            replay_report_apply_failure(
                collection->report, collection->manifest, replay->root_index,
                replay->entry, &failure);
            return -1;
        }
        if (collection->report->applied_count != SIZE_MAX)
            collection->report->applied_count++;
    }

    for (size_t index = collection->count; index != 0; index--)
    {
        ReplayEntry *replay = &collection->items[index - 1U];
        if (replay->entry->kind != SIDECAR_KIND_DIRECTORY)
            continue;
        replay_print_verbose_root(collection, replay->root_index,
                                  printed_roots);
        ReplayApplyFailure failure = {0};
        if (replay_apply_directory_metadata(collection, replay, &failure) != 0)
        {
            replay_report_apply_failure(
                collection->report, collection->manifest, replay->root_index,
                replay->entry, &failure);
            return -1;
        }
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

    ReplayCollection collection = {
        .manifest = request->manifest,
        .data_fd = -1,
        .destination_home_fd = request->destination_home_fd,
        .destination_home_path = request->destination_home_path,
        .destination_xdg_dirs = request->destination_xdg_dirs,
        .timestamp_policy = timestamp_policy,
        .report = report,
        .capture_report = request->capture_report,
        .skip_content_verification = request->skip_content_verification,
        .before_content_verification = request->before_content_verification,
        .before_content_verification_context =
            request->before_content_verification_context
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
    if (sidecar_log_adopt_at(request->source_container_fd, &sidecar) !=
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
