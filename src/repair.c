#define _GNU_SOURCE
#include "repair.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h> /* flock */
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "container.h"
#include "hash.h"
#include "manifest.h"
#include "portable_fsops_internal.h"
#include "portable_name.h"
#include "portable_restore_internal.h"
#include "sidecar.h"
#include "utils.h"
#include "verify.h"

#define REPAIR_REPORT_EXAMPLES 20

typedef struct {
    char *root;
    char *path;
} RepairPath;

typedef struct {
    RepairPath *items;
    size_t count;
    size_t capacity;
} RepairPathList;

typedef struct {
    const Manifest *manifest;
    int data_fd;
    SidecarLog *log;

    /* Deep copy of the ENTRY group being read; the parser's copy is freed
     * before its ENTRY_COMMIT reaches the new log. */
    SidecarEntry pending;
    SidecarXattr *xattrs;
    size_t xattr_count;
    int has_pending;

    RepairPathList rejected;
    RepairPathList recreated;
    RepairPathList dropped;
    size_t damaged_regions;
    uint64_t damaged_bytes;
    uint64_t first_damage;
    SidecarStatus fatal;
} RepairSalvage;

static void pending_clear(RepairSalvage *salvage)
{
    if (salvage->has_pending)
        sidecar_entry_dup_free(&salvage->pending);
    sidecar_xattrs_dup_free(salvage->xattrs, salvage->xattr_count);
    salvage->xattrs = NULL;
    salvage->xattr_count = 0;
    salvage->has_pending = 0;
}

static int path_list_add(RepairPathList *list, SidecarBytes root,
                         SidecarBytes path)
{
    if (list->count == list->capacity)
    {
        size_t capacity = list->capacity == 0 ? 16U : list->capacity * 2U;
        RepairPath *items = realloc(list->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        list->items = items;
        list->capacity = capacity;
    }
    SidecarBytes root_copy = sidecar_bytes_dup(root);
    SidecarBytes path_copy = sidecar_bytes_dup(path);
    if (root_copy.data == NULL || path_copy.data == NULL)
    {
        sidecar_bytes_dup_free(&root_copy);
        sidecar_bytes_dup_free(&path_copy);
        return -1;
    }
    list->items[list->count].root = (char *)root_copy.data;
    list->items[list->count].path = (char *)path_copy.data;
    list->count++;
    return 0;
}

static void path_list_free(RepairPathList *list)
{
    for (size_t index = 0; index < list->count; index++)
    {
        free(list->items[index].root);
        free(list->items[index].path);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int repair_path_compare(const void *left_pointer,
                               const void *right_pointer)
{
    const RepairPath *left = left_pointer;
    const RepairPath *right = right_pointer;
    int order = strcmp(left->root, right->root);
    return order != 0 ? order : strcmp(left->path, right->path);
}

static SidecarBytes text_bytes(const char *text)
{
    return (SidecarBytes){ (const unsigned char *)text, strlen(text) };
}

// A rejected record is an item the state layer refused as inconsistent with
// what came before it. Those checks run before anything is written, so the new
// log is still sound and replay continues; a log that did fail mid-write is
// poisoned and answers every later append with SIDECAR_STATUS_IO_ERROR, which
// is fatal here.
static int salvage_result(RepairSalvage *salvage, SidecarStatus status,
                          SidecarBytes root, SidecarBytes path)
{
    if (status == SIDECAR_STATUS_OK)
        return 0;
    int rejected = status == SIDECAR_STATUS_INVALID_ARGUMENT ||
                   status == SIDECAR_STATUS_CORRUPT;
    if (rejected && path_list_add(&salvage->rejected, root, path) == 0)
        return 0;
    salvage->fatal = rejected ? SIDECAR_STATUS_ALLOCATION : status;
    return -1;
}

static int salvage_record(const SidecarRecord *record, void *context)
{
    RepairSalvage *salvage = context;
    switch (record->type)
    {
        case SIDECAR_RECORD_CLAIM:
            return salvage_result(
                salvage, sidecar_log_append_claim(salvage->log,
                                                  &record->value.claim),
                record->value.claim.root_id,
                record->value.claim.logical_path);
        case SIDECAR_RECORD_DELETE:
            return salvage_result(
                salvage, sidecar_log_append_delete(salvage->log,
                                                   &record->value.deletion),
                record->value.deletion.root_id,
                record->value.deletion.logical_path);
        case SIDECAR_RECORD_ENTRY:
            pending_clear(salvage);
            if (sidecar_entry_dup(&record->value.entry, &salvage->pending) != 0)
            {
                salvage->fatal = SIDECAR_STATUS_ALLOCATION;
                return -1;
            }
            salvage->has_pending = 1;
            return 0;
        case SIDECAR_RECORD_XATTR:
        {
            SidecarXattr *xattrs = realloc(
                salvage->xattrs,
                (salvage->xattr_count + 1U) * sizeof(*xattrs));
            if (xattrs == NULL)
            {
                salvage->fatal = SIDECAR_STATUS_ALLOCATION;
                return -1;
            }
            salvage->xattrs = xattrs;
            SidecarXattr *copy = &xattrs[salvage->xattr_count];
            copy->name = sidecar_bytes_dup(record->value.xattr.name);
            copy->value = sidecar_bytes_dup(record->value.xattr.value);
            salvage->xattr_count++;
            if (copy->name.data == NULL || copy->value.data == NULL)
            {
                salvage->fatal = SIDECAR_STATUS_ALLOCATION;
                return -1;
            }
            return 0;
        }
        case SIDECAR_RECORD_ENTRY_COMMIT:
        {
            if (!salvage->has_pending)
                return 0;
            int result = salvage_result(
                salvage,
                sidecar_log_append_group(salvage->log, &salvage->pending,
                                         salvage->xattr_count != 0
                                             ? salvage->xattrs : NULL),
                salvage->pending.root_id, salvage->pending.logical_path);
            pending_clear(salvage);
            return result;
        }
    }
    return 0;
}

// Record starts are recognizable in the text: every record begins with its
// tag field right after the NUL that ends the previous field. ENTRY_COMMIT and
// XATTR are never resumed at, since they only continue an open group.
static size_t next_record_start(const unsigned char *data, size_t length,
                                size_t from)
{
    static const char *const tags[] = { "CLAIM", "ENTRY", "DELETE" };
    const unsigned char *end = data + length;
    const unsigned char *nul = from < length
                                   ? memchr(data + from, '\0', length - from)
                                   : NULL;
    for (; nul != NULL; nul = memchr(nul + 1, '\0', (size_t)(end - nul - 1)))
    {
        size_t start = (size_t)(nul - data) + 1U;
        for (size_t index = 0; index < sizeof(tags) / sizeof(tags[0]); index++)
        {
            size_t tag_length = strlen(tags[index]) + 1U;
            if (length - start >= tag_length &&
                memcmp(data + start, tags[index], tag_length) == 0)
                return start;
        }
    }
    return SIZE_MAX;
}

static void salvage_note_damage(RepairSalvage *salvage, uint64_t start,
                                uint64_t end)
{
    if (salvage->damaged_regions == 0)
        salvage->first_damage = start;
    salvage->damaged_regions++;
    salvage->damaged_bytes += end - start;
}

// Replays the journal into salvage->log, skipping each damaged region up to
// the next record start. Each segment is parsed in place, after the header.
static int salvage_journal(RepairSalvage *salvage, const unsigned char *data,
                           size_t length)
{
    size_t header_length = strlen(SIDECAR_MAGIC) + 1U;
    const unsigned char *version = memchr(data + header_length, '\0',
                                          length > header_length
                                              ? length - header_length : 0);
    if (length <= header_length ||
        memcmp(data, SIDECAR_MAGIC, header_length) != 0 || version == NULL)
    {
        print_error("Error: the backup journal's header is damaged; it cannot "
                    "be repaired.\n");
        return -1;
    }
    header_length = (size_t)(version - data) + 1U;

    int scratch = memfd_create("migr-repair", MFD_CLOEXEC);
    if (scratch < 0)
    {
        print_error("Error: Could not create a scratch file: %s\n",
                    strerror(errno));
        return -1;
    }
    if (write_all(scratch, data, length) != 0)
    {
        print_error("Error: Could not write a scratch file: %s\n",
                    strerror(errno));
        close(scratch);
        return -1;
    }
    int result = -1;
    size_t start = header_length;
    for (;;)
    {
        pending_clear(salvage);
        SidecarParseResult parsed;
        SidecarStatus status = sidecar_parse_fd_from(scratch, start,
                                                     salvage_record, salvage,
                                                     &parsed);
        pending_clear(salvage);
        if (salvage->fatal != SIDECAR_STATUS_OK ||
            status == SIDECAR_STATUS_CALLBACK ||
            status == SIDECAR_STATUS_IO_ERROR ||
            status == SIDECAR_STATUS_ALLOCATION ||
            status == SIDECAR_STATUS_INVALID_ARGUMENT)
        {
            print_error("Error: Could not write the rebuilt journal: %s\n",
                        salvage->fatal == SIDECAR_STATUS_ALLOCATION ||
                                status == SIDECAR_STATUS_ALLOCATION
                            ? strerror(ENOMEM)
                            : strerror(errno != 0 ? errno : EIO));
            break;
        }
        // The header is the same in every segment, so it fails on the first.
        // A version this build does not write is never reinterpreted.
        if (parsed.last_valid_boundary == 0)
        {
            const char *field = (const char *)data + strlen(SIDECAR_MAGIC) + 1U;
            if (status == SIDECAR_STATUS_UNKNOWN_VERSION)
                print_error("Error: the backup journal's header names version "
                            "%s, but its manifest and this build use version "
                            "%d; it cannot be repaired.\n", field,
                            SIDECAR_VERSION);
            else
                print_error("Error: the backup journal's header is damaged; it "
                            "cannot be repaired.\n");
            break;
        }
        uint64_t boundary = parsed.last_valid_boundary;
        if (status == SIDECAR_STATUS_OK)
        {
            result = 0;
            break;
        }
        size_t next = status == SIDECAR_STATUS_TRUNCATED_TAIL
                          ? SIZE_MAX
                          : next_record_start(data, length, (size_t)boundary);
        if (next == SIZE_MAX)
        {
            salvage_note_damage(salvage, boundary, length);
            result = 0;
            break;
        }
        salvage_note_damage(salvage, boundary, next);
        start = next;
    }
    close(scratch);
    return result;
}

#ifdef REPAIR_TEST_HOOKS
int repair_test_salvage(SidecarLog *log, const unsigned char *data,
                        size_t length, size_t *damaged_regions,
                        size_t *rejected)
{
    RepairSalvage salvage;
    memset(&salvage, 0, sizeof(salvage));
    salvage.log = log;
    salvage.fatal = SIDECAR_STATUS_OK;
    salvage.data_fd = -1;
    int result = salvage_journal(&salvage, data, length);
    *damaged_regions = salvage.damaged_regions;
    *rejected = salvage.rejected.count;
    path_list_free(&salvage.rejected);
    return result;
}
#endif

typedef struct {
    SidecarClaim *items;
    size_t count;
    size_t capacity;
} RepairClaims;

static int collect_claim(const SidecarClaimView *view, void *context)
{
    RepairClaims *claims = context;
    if (claims->count == claims->capacity)
    {
        size_t capacity = claims->capacity == 0 ? 16U : claims->capacity * 2U;
        SidecarClaim *items = realloc(claims->items,
                                      capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        claims->items = items;
        claims->capacity = capacity;
    }
    SidecarClaim *copy = &claims->items[claims->count];
    copy->kind = view->claim->kind;
    copy->root_id = sidecar_bytes_dup(view->claim->root_id);
    copy->logical_path = sidecar_bytes_dup(view->claim->logical_path);
    copy->physical_leaf = sidecar_bytes_dup(view->claim->physical_leaf);
    claims->count++;
    return copy->root_id.data == NULL || copy->logical_path.data == NULL ||
                   copy->physical_leaf.data == NULL
               ? -1 : 0;
}

// Folders first, shallower first, so an item's folder is recorded again
// before the item is settled.
static int claim_order(const void *left_pointer, const void *right_pointer)
{
    const SidecarClaim *left = left_pointer, *right = right_pointer;
    int left_folder = left->kind == SIDECAR_KIND_DIRECTORY;
    int right_folder = right->kind == SIDECAR_KIND_DIRECTORY;
    if (left_folder != right_folder)
        return left_folder ? -1 : 1;
    size_t left_depth = left->logical_path.length != 0;
    size_t right_depth = right->logical_path.length != 0;
    for (size_t index = 0; index < left->logical_path.length; index++)
        left_depth += left->logical_path.data[index] == '/';
    for (size_t index = 0; index < right->logical_path.length; index++)
        right_depth += right->logical_path.data[index] == '/';
    return left_depth < right_depth ? -1 : left_depth > right_depth;
}

static void claims_free(RepairClaims *claims)
{
    for (size_t index = 0; index < claims->count; index++)
    {
        sidecar_bytes_dup_free(&claims->items[index].root_id);
        sidecar_bytes_dup_free(&claims->items[index].logical_path);
        sidecar_bytes_dup_free(&claims->items[index].physical_leaf);
    }
    free(claims->items);
    memset(claims, 0, sizeof(*claims));
}

// The collision suffix is not part of a claim; it is the tail of the physical
// leaf that makes the entry authenticate against its logical name.
static int synthesize_collision_suffix(SidecarEntry *entry)
{
    size_t leaf_length = entry->physical_leaf.length;
    for (size_t length = 0;
         length <= leaf_length && length <= SIDECAR_MAX_COLLISION_SUFFIX;
         length++)
    {
        entry->collision_suffix = (SidecarBytes){
            entry->physical_leaf.data + leaf_length - length, length
        };
        if (restore_entry_physical_leaf_authentic(entry))
            return 0;
    }
    entry->collision_suffix = (SidecarBytes){ (const unsigned char *)"", 0 };
    return -1;
}

static const ManifestRoot *find_root(const RepairSalvage *salvage,
                                    SidecarBytes id)
{
    for (int index = 0; index < salvage->manifest->root_count; index++)
        if (strlen(salvage->manifest->roots[index].id) == id.length &&
            memcmp(salvage->manifest->roots[index].id, id.data, id.length) == 0)
            return &salvage->manifest->roots[index];
    return NULL;
}

// Metadata for an item whose ENTRY was lost: the nearest recorded ancestor
// directory's, or for a root the payload directory's own.
static int ancestor_metadata(RepairSalvage *salvage, SidecarBytes root_id,
                             SidecarBytes logical_path, SidecarEntry *entry,
                             SidecarXattr **xattrs_out)
{
    *xattrs_out = NULL;
    size_t length = logical_path.length;
    while (length != 0)
    {
        while (length != 0 && logical_path.data[length - 1U] != '/')
            length--;
        if (length != 0)
            length--;
        SidecarLiveView view;
        SidecarBytes prefix = { logical_path.data, length };
        if (sidecar_log_find(salvage->log, root_id, prefix, &view) == 1 &&
            view.entry->kind == SIDECAR_KIND_DIRECTORY)
        {
            entry->mode = view.entry->mode;
            entry->uid = view.entry->uid;
            entry->gid = view.entry->gid;
            entry->atime_sec = view.entry->atime_sec;
            entry->atime_nsec = view.entry->atime_nsec;
            entry->mtime_sec = view.entry->mtime_sec;
            entry->mtime_nsec = view.entry->mtime_nsec;
            entry->xattr_count = (uint32_t)view.xattr_count;
            if (view.xattr_count == 0)
                return 0;
            SidecarXattr *xattrs = sidecar_xattrs_dup(view.xattrs,
                                                      view.xattr_count);
            if (xattrs == NULL)
                return -1;
            *xattrs_out = xattrs;
            return 0;
        }
    }

    const ManifestRoot *root = find_root(salvage, root_id);
    struct stat st;
    if (root == NULL ||
        fstatat(salvage->data_fd, root->payload_path, &st,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(st.st_mode))
        return -1;
    entry->mode = (uint32_t)(st.st_mode & 07777);
    entry->uid = (uint32_t)st.st_uid;
    entry->gid = (uint32_t)st.st_gid;
    entry->atime_sec = st.st_atim.tv_sec;
    entry->atime_nsec = (uint32_t)st.st_atim.tv_nsec;
    entry->mtime_sec = st.st_mtim.tv_sec;
    entry->mtime_nsec = (uint32_t)st.st_mtim.tv_nsec;
    entry->xattr_count = 0;
    return 0;
}

static void note_sidecar_failure(FailedStep *failed, const char *step,
                                 SidecarStatus status)
{
    if (status == SIDECAR_STATUS_IO_ERROR)
        failed_step_note(failed, step, errno);
    else
        failed_step_note_reason(failed, step, sidecar_status_reason(status));
}

#define DIRECTORY_FLAGS (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)

static int bytes_text(SidecarBytes bytes, char *out, size_t size)
{
    if (bytes.length >= size)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (bytes.length != 0)
        memcpy(out, bytes.data, bytes.length);
    out[bytes.length] = '\0';
    return 0;
}

// Opens the payload folder of logical, a directory of root or the root
// itself when empty, by following each recorded ancestor's physical leaf,
// as restore does: no path is joined (D39 R-7).
static int open_recorded_folder(const RepairSalvage *salvage,
                                const ManifestRoot *root, SidecarBytes logical)
{
    int parent = -1;
    char leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(salvage->data_fd, root->payload_path,
                                     &parent, leaf, sizeof(leaf)) != 0)
    {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    int current = openat(parent, leaf, DIRECTORY_FLAGS);
    int saved = errno;
    close(parent);
    errno = saved;
    for (size_t end = 1; current >= 0 && end <= logical.length; end++)
    {
        if (end != logical.length && logical.data[end] != '/')
            continue;
        SidecarLiveView view;
        SidecarBytes prefix = { logical.data, end };
        int next = -1;
        if (sidecar_log_find(salvage->log, text_bytes(root->id), prefix,
                             &view) == 1 &&
            view.entry->kind == SIDECAR_KIND_DIRECTORY &&
            bytes_text(view.entry->physical_leaf, leaf, sizeof(leaf)) == 0)
            next = openat(current, leaf, DIRECTORY_FLAGS);
        else if (errno != ENAMETOOLONG)
            errno = ENOENT;
        saved = errno;
        close(current);
        errno = saved;
        current = next;
    }
    return current;
}

static SidecarBytes logical_parent_of(SidecarBytes logical)
{
    size_t length = logical.length;
    while (length != 0 && logical.data[length - 1U] != '/')
        length--;
    return (SidecarBytes){ logical.data, length != 0 ? length - 1U : 0 };
}

// The size and content digest (D59) of a payload file whose record was lost.
static int payload_measure(int parent_fd, const char *leaf,
                           SidecarEntry *entry)
{
    int fd = openat(parent_fd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    int stated = fstat(fd, &st) == 0;
    if (!stated || !S_ISREG(st.st_mode))
    {
        int saved = stated ? EINVAL : errno;
        close(fd);
        errno = saved;
        return -1;
    }
    unsigned char buffer[65536];
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    uint64_t total = 0;
    ssize_t got;
    for (;;)
    {
        got = read(fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        hash = hash_fnv1a_bytes(hash, buffer, (size_t)got);
        total += (uint64_t)got;
    }
    int saved = errno;
    close(fd);
    if (got < 0)
    {
        errno = saved;
        return -1;
    }
    if (total != (uint64_t)st.st_size)
    {
        errno = EIO;
        return -1;
    }
    entry->size = total;
    entry->content_digest = hash;
    return 0;
}

// Claims an item no record is left for and commits its group, as capture
// writes one (D25).
static SidecarStatus append_unclaimed(RepairSalvage *salvage,
                                      const SidecarEntry *entry,
                                      const SidecarXattr *xattrs)
{
    SidecarClaim claim = {
        .kind = entry->kind,
        .root_id = entry->root_id,
        .logical_path = entry->logical_path,
        .physical_leaf = entry->physical_leaf
    };
    SidecarStatus status = sidecar_log_append_claim(salvage->log, &claim);
    return status == SIDECAR_STATUS_OK
        ? sidecar_log_append_group(salvage->log, entry, xattrs) : status;
}

// Records a regular file whose record was lost from its payload, with the
// metadata of the folder above it, less the execute and special bits, under
// its claim when it has one. Returns 0, or the state layer's status.
static SidecarStatus record_regular(RepairSalvage *salvage, int parent_fd,
                                    const char *leaf, SidecarEntry *entry,
                                    int claimed)
{
    SidecarXattr *xattrs = NULL;
    if (ancestor_metadata(salvage, entry->root_id, entry->logical_path, entry,
                          &xattrs) != 0)
    {
        sidecar_xattrs_dup_free(xattrs, entry->xattr_count);
        errno = ENOENT;
        return SIDECAR_STATUS_IO_ERROR;
    }
    sidecar_xattrs_dup_free(xattrs, entry->xattr_count);
    entry->xattr_count = 0;
    entry->mode &= 0666;
    if (payload_measure(parent_fd, leaf, entry) != 0)
        return SIDECAR_STATUS_IO_ERROR;
    return claimed ? sidecar_log_append_group(salvage->log, entry, NULL)
                   : append_unclaimed(salvage, entry, NULL);
}

// A claimed regular file in a finished backup had its ENTRY written, so its
// payload is whole: it is re-created under the claim's own name. Returns 1
// when it was, 0 when it cannot be (no payload, or refused), -1 on an error.
static int recreate_claimed_file(RepairSalvage *salvage,
                                 const SidecarClaim *claim, FailedStep *failed)
{
    const ManifestRoot *root = find_root(salvage, claim->root_id);
    char leaf[NAME_MAX + 1U];
    if (root == NULL ||
        bytes_text(claim->physical_leaf, leaf, sizeof(leaf)) != 0)
        return 0;
    int folder = open_recorded_folder(salvage, root,
                                      logical_parent_of(claim->logical_path));
    struct stat st;
    if (folder < 0 || fstatat(folder, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode))
    {
        if (folder >= 0)
            close(folder);
        return 0;
    }
    SidecarEntry entry = {
        .root_id = claim->root_id,
        .logical_path = claim->logical_path,
        .physical_leaf = claim->physical_leaf,
        .kind = SIDECAR_KIND_REGULAR
    };
    SidecarStatus status = synthesize_collision_suffix(&entry) == 0
        ? record_regular(salvage, folder, leaf, &entry, 1)
        : SIDECAR_STATUS_INVALID_ARGUMENT;
    int saved = errno;
    close(folder);
    errno = saved;
    if (status == SIDECAR_STATUS_INVALID_ARGUMENT ||
        status == SIDECAR_STATUS_CORRUPT)
        return 0;
    if (status != SIDECAR_STATUS_OK)
    {
        note_sidecar_failure(failed, "record a re-created file", status);
        return -1;
    }
    if (path_list_add(&salvage->recreated, claim->root_id,
                      claim->logical_path) != 0)
    {
        failed_step_note(failed, "note a re-created file", errno);
        return -1;
    }
    return 1;
}

// The placeholder of a symlink or hardlink whose ENTRY, and so its target,
// was lost is an empty file that holds nothing to keep.
static int remove_claimed_placeholder(RepairSalvage *salvage,
                                      const SidecarClaim *claim)
{
    const ManifestRoot *root = find_root(salvage, claim->root_id);
    char leaf[NAME_MAX + 1U];
    if (root == NULL ||
        bytes_text(claim->physical_leaf, leaf, sizeof(leaf)) != 0)
        return 0;
    int folder = open_recorded_folder(salvage, root,
                                      logical_parent_of(claim->logical_path));
    if (folder < 0)
        return 0;
    struct stat st;
    int result = 0;
    if (fstatat(folder, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(st.st_mode) && st.st_size == 0 &&
        unlinkat(folder, leaf, 0) != 0)
        result = -1;
    int saved = errno;
    close(folder);
    errno = saved;
    return result;
}

// Every item whose capture began but whose ENTRY was lost is re-created from
// its payload (a directory, so its recorded children stay reachable, or a
// file) or left out.
static int close_open_claims(RepairSalvage *salvage, FailedStep *failed)
{
    RepairClaims claims = {0};
    SidecarStatus listed = sidecar_log_claim_foreach(salvage->log,
                                                     collect_claim, &claims);
    if (listed != SIDECAR_STATUS_OK)
    {
        note_sidecar_failure(failed, "list them", listed);
        claims_free(&claims);
        return -1;
    }
    if (claims.count > 1)
        qsort(claims.items, claims.count, sizeof(*claims.items), claim_order);
    int result = 0;
    for (size_t index = 0; index < claims.count && result == 0; index++)
    {
        const SidecarClaim *claim = &claims.items[index];
        if (claim->kind == SIDECAR_KIND_DIRECTORY)
        {
            SidecarEntry entry = {
                .root_id = claim->root_id,
                .logical_path = claim->logical_path,
                .physical_leaf = claim->physical_leaf,
                .kind = SIDECAR_KIND_DIRECTORY
            };
            SidecarXattr *xattrs = NULL;
            if (ancestor_metadata(salvage, claim->root_id,
                                  claim->logical_path, &entry, &xattrs) == 0 &&
                synthesize_collision_suffix(&entry) == 0)
            {
                SidecarStatus status = sidecar_log_append_group(
                    salvage->log, &entry, xattrs);
                sidecar_xattrs_dup_free(xattrs, entry.xattr_count);
                if (status == SIDECAR_STATUS_OK)
                {
                    if (path_list_add(&salvage->recreated, claim->root_id,
                                      claim->logical_path) != 0)
                    {
                        failed_step_note(failed, "note a re-created folder",
                                         errno);
                        result = -1;
                    }
                    continue;
                }
                if (status != SIDECAR_STATUS_INVALID_ARGUMENT &&
                    status != SIDECAR_STATUS_CORRUPT)
                {
                    note_sidecar_failure(failed, "record a re-created folder",
                                         status);
                    result = -1;
                    break;
                }
            }
            else
                sidecar_xattrs_dup_free(xattrs, entry.xattr_count);
        }
        else if (claim->kind == SIDECAR_KIND_REGULAR)
        {
            int recreated = recreate_claimed_file(salvage, claim, failed);
            if (recreated < 0)
            {
                result = -1;
                break;
            }
            if (recreated)
                continue;
        }
        else if (remove_claimed_placeholder(salvage, claim) != 0)
        {
            failed_step_note(failed, "remove an empty placeholder", errno);
            result = -1;
            break;
        }
        SidecarDelete deletion = {
            .root_id = claim->root_id,
            .logical_path = claim->logical_path
        };
        SidecarStatus deleted = sidecar_log_append_delete(salvage->log,
                                                          &deletion);
        if (deleted != SIDECAR_STATUS_OK)
        {
            note_sidecar_failure(failed, "record an item left out", deleted);
            result = -1;
        }
        else if (path_list_add(&salvage->dropped, claim->root_id,
                               claim->logical_path) != 0)
        {
            failed_step_note(failed, "note an item left out", errno);
            result = -1;
        }
    }
    claims_free(&claims);
    if (result == 0 && sidecar_log_claim_count(salvage->log) != 0)
    {
        failed_step_note_reason(failed, "settle every one",
                                "some are still unfinished");
        result = -1;
    }
    return result;
}

// An item left out whose item is live in the end (a stale DELETE followed by
// a fresh capture, or one re-created from its payload) lost nothing; only the
// rest are reported.
static void keep_lost_only(RepairSalvage *salvage, RepairPathList *list)
{
    if (list->count > 1)
        qsort(list->items, list->count, sizeof(*list->items),
              repair_path_compare);
    size_t kept = 0;
    for (size_t index = 0; index < list->count; index++)
    {
        RepairPath *item = &list->items[index];
        SidecarLiveView view;
        int duplicate = kept != 0 &&
                        repair_path_compare(&list->items[kept - 1U], item) ==
                            0;
        if (duplicate ||
            sidecar_log_find(salvage->log, text_bytes(item->root),
                             text_bytes(item->path), &view) == 1)
        {
            free(item->root);
            free(item->path);
            continue;
        }
        list->items[kept++] = *item;
    }
    list->count = kept;
}

static void print_path_list(const char *heading, const RepairPathList *list)
{
    if (list->count == 0)
        return;
    printf("%s (%zu):\n", heading, list->count);
    for (size_t index = 0;
         index < list->count && index < REPAIR_REPORT_EXAMPLES; index++)
    {
        char line[EXAMPLE_TEXT_MAX];
        (void)snprintf(line, sizeof(line), "%s:%s", list->items[index].root,
                       list->items[index].path[0] != '\0'
                           ? list->items[index].path : ".");
        text_make_printable(line);
        printf("  %s\n", line);
    }
    if (list->count > REPAIR_REPORT_EXAMPLES)
        printf("  ... and %zu more\n", list->count - REPAIR_REPORT_EXAMPLES);
}

// A payload node no record is left for, under a root: the recorded folder
// holding it (empty for a root's own node) and its name there.
typedef struct {
    const ManifestRoot *root;
    SidecarBytes parent;
    int is_root;
    char name[NAME_MAX + 1U];
} RepairFound;

typedef struct {
    RepairFound *items;
    size_t count;
    size_t capacity;
    /* Nodes that lie in no root, which a restore has nowhere to put. */
    size_t strays;
    char stray[PATH_MAX];
} RepairFoundList;

static int found_add(void *context, int parent_fd, const char *name,
                     const char *path, const ManifestRoot *root,
                     const SidecarEntry *parent)
{
    (void)parent_fd;
    RepairFoundList *found = context;
    if (root == NULL)
    {
        if (found->strays++ == 0)
            (void)snprintf(found->stray, sizeof(found->stray), "%s", path);
        return 0;
    }
    if (found->count == found->capacity)
    {
        size_t capacity = found->capacity == 0 ? 16U : found->capacity * 2U;
        RepairFound *items = realloc(found->items, capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        found->items = items;
        found->capacity = capacity;
    }
    RepairFound *item = &found->items[found->count];
    memset(item, 0, sizeof(*item));
    item->root = root;
    item->is_root = parent == NULL;
    if (parent != NULL && parent->logical_path.length != 0)
    {
        item->parent = sidecar_bytes_dup(parent->logical_path);
        if (item->parent.data == NULL)
            return -1;
    }
    (void)snprintf(item->name, sizeof(item->name), "%s", name);
    found->count++;
    return 0;
}

static void found_free(RepairFoundList *found)
{
    for (size_t index = 0; index < found->count; index++)
        sidecar_bytes_dup_free(&found->items[index].parent);
    free(found->items);
    memset(found, 0, sizeof(*found));
}

static int join_logical(SidecarBytes parent, const char *leaf, char *out,
                        size_t size)
{
    int length = parent.length != 0
        ? snprintf(out, size, "%.*s/%s", (int)parent.length,
                   (const char *)parent.data, leaf)
        : snprintf(out, size, "%s", leaf);
    if (length < 0 || (size_t)length >= size)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int logical_live(const RepairSalvage *salvage, SidecarBytes root_id,
                        const char *logical)
{
    SidecarLiveView view;
    return sidecar_log_find(salvage->log, root_id, text_bytes(logical),
                            &view) == 1;
}

// The name an unrecorded node goes back under: its own, when its physical
// leaf authenticates as a name not in use (a collision suffix included);
// otherwise the name on disk, made unique, with the node renamed to that
// name's physical form. Fills entry's logical path, leaf, and suffix from
// logical and physical.
static int adopted_name(RepairSalvage *salvage, int parent_fd,
                        const char *leaf, SidecarBytes parent,
                        SidecarEntry *entry, char *logical,
                        PortablePhysicalName *physical)
{
    size_t leaf_length = strlen(leaf);
    for (size_t suffix = 0;
         suffix < leaf_length && suffix <= SIDECAR_MAX_COLLISION_SUFFIX;
         suffix++)
    {
        char own[NAME_MAX + 1U];
        (void)snprintf(own, sizeof(own), "%.*s",
                       (int)(leaf_length - suffix), leaf);
        if (join_logical(parent, own, logical, SIDECAR_MAX_PATH + 1U) != 0)
            continue;
        entry->logical_path = text_bytes(logical);
        entry->physical_leaf = (SidecarBytes){
            (const unsigned char *)leaf, leaf_length };
        entry->collision_suffix = (SidecarBytes){
            (const unsigned char *)leaf + leaf_length - suffix, suffix };
        if (restore_entry_physical_leaf_authentic(entry) &&
            !logical_live(salvage, entry->root_id, logical))
        {
            (void)snprintf(physical->physical_leaf,
                           sizeof(physical->physical_leaf), "%s", leaf);
            (void)snprintf(physical->collision_suffix,
                           sizeof(physical->collision_suffix), "%s",
                           leaf + leaf_length - suffix);
            entry->physical_leaf = text_bytes(physical->physical_leaf);
            entry->collision_suffix = text_bytes(physical->collision_suffix);
            return 0;
        }
    }

    // A name that was encoded or shortened on the way to the payload.
    for (unsigned attempt = 1; attempt <= 100; attempt++)
    {
        char name[NAME_MAX + 1U];
        int length = attempt == 1
            ? snprintf(name, sizeof(name), "%s", leaf)
            : snprintf(name, sizeof(name), "%s-%u", leaf, attempt);
        if (length < 0 || (size_t)length >= sizeof(name) ||
            join_logical(parent, name, logical, SIDECAR_MAX_PATH + 1U) != 0)
            break;
        if (logical_live(salvage, entry->root_id, logical))
            continue;
        for (uint64_t collision = 0; collision < 100; collision++)
        {
            if (portable_physical_name_map(name, collision, physical) != 0)
                break;
            struct stat st;
            if (strcmp(physical->physical_leaf, leaf) != 0)
            {
                if (fstatat(parent_fd, physical->physical_leaf, &st,
                            AT_SYMLINK_NOFOLLOW) == 0)
                    continue;
                if (errno != ENOENT ||
                    renameat(parent_fd, leaf, parent_fd,
                             physical->physical_leaf) != 0)
                    return -1;
            }
            entry->logical_path = text_bytes(logical);
            entry->physical_leaf = text_bytes(physical->physical_leaf);
            entry->collision_suffix = text_bytes(physical->collision_suffix);
            return 0;
        }
    }
    errno = EEXIST;
    return -1;
}

static int list_names(int directory_fd, char ***names_out, size_t *count_out)
{
    *names_out = NULL;
    *count_out = 0;
    int scan_fd = dup_cloexec(directory_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL)
    {
        int saved = errno;
        if (scan_fd >= 0)
            close(scan_fd);
        errno = saved;
        return -1;
    }
    char **names = NULL;
    size_t count = 0, capacity = 0;
    int result = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *item = readdir(directory);
        if (item == NULL)
        {
            if (errno != 0)
                result = -1;
            break;
        }
        if (strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0)
            continue;
        if (count == capacity)
        {
            capacity = capacity == 0 ? 16U : capacity * 2U;
            char **grown = realloc(names, capacity * sizeof(*grown));
            if (grown == NULL)
            {
                result = -1;
                break;
            }
            names = grown;
        }
        if ((names[count] = strdup(item->d_name)) == NULL)
        {
            result = -1;
            break;
        }
        count++;
    }
    int saved = errno;
    closedir(directory);
    if (result != 0)
    {
        for (size_t index = 0; index < count; index++)
            free(names[index]);
        free(names);
        errno = saved;
        return -1;
    }
    *names_out = names;
    *count_out = count;
    return 0;
}

// Re-creates the record of a payload node no record is left for, and for a
// folder of everything below it: metadata from the recorded folder above
// them (D61 rule 3), and for a root's own node from the node itself. The
// names are listed first, as a rename while reading a folder could show a
// node twice.
static int adopt_node(RepairSalvage *salvage, const ManifestRoot *root,
                      int parent_fd, const char *leaf, SidecarBytes parent,
                      int is_root, FailedStep *failed)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
    {
        failed_step_note(failed, "read it", errno);
        return -1;
    }
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
    {
        failed_step_note_reason(failed, "re-create it",
                                "it is neither a file nor a folder");
        return -1;
    }
    char *logical = malloc(SIDECAR_MAX_PATH + 1U);
    if (logical == NULL)
    {
        failed_step_note(failed, "re-create it", errno);
        return -1;
    }
    logical[0] = '\0';
    PortablePhysicalName physical = {0};
    SidecarEntry entry = {
        .root_id = text_bytes(root->id),
        .logical_path = text_bytes(logical),
        .physical_leaf = text_bytes(logical),
        .collision_suffix = text_bytes(logical),
        .kind = S_ISDIR(st.st_mode) ? SIDECAR_KIND_DIRECTORY
                                    : SIDECAR_KIND_REGULAR
    };
    const char *final_leaf = leaf;
    SidecarStatus status = SIDECAR_STATUS_OK;
    int result = -1;
    if (is_root)
    {
        entry.mode = (uint32_t)(st.st_mode & 07777);
        entry.uid = (uint32_t)st.st_uid;
        entry.gid = (uint32_t)st.st_gid;
        entry.atime_sec = st.st_atim.tv_sec;
        entry.atime_nsec = (uint32_t)st.st_atim.tv_nsec;
        entry.mtime_sec = st.st_mtim.tv_sec;
        entry.mtime_nsec = (uint32_t)st.st_mtim.tv_nsec;
        status = S_ISREG(st.st_mode) &&
                         payload_measure(parent_fd, leaf, &entry) != 0
            ? SIDECAR_STATUS_IO_ERROR
            : append_unclaimed(salvage, &entry, NULL);
    }
    else if (adopted_name(salvage, parent_fd, leaf, parent, &entry, logical,
                          &physical) != 0)
    {
        failed_step_note(failed, "give it a name", errno);
        goto done;
    }
    else
    {
        final_leaf = physical.physical_leaf;
        if (S_ISREG(st.st_mode))
            status = record_regular(salvage, parent_fd, final_leaf, &entry,
                                    0);
        else
        {
            SidecarXattr *xattrs = NULL;
            status = ancestor_metadata(salvage, entry.root_id,
                                       entry.logical_path, &entry,
                                       &xattrs) == 0
                ? append_unclaimed(salvage, &entry, xattrs)
                : SIDECAR_STATUS_INVALID_ARGUMENT;
            sidecar_xattrs_dup_free(xattrs, entry.xattr_count);
        }
    }
    if (status != SIDECAR_STATUS_OK)
    {
        note_sidecar_failure(failed, "record it", status);
        goto done;
    }
    if (path_list_add(&salvage->recreated, entry.root_id,
                      entry.logical_path) != 0)
    {
        failed_step_note(failed, "note it", errno);
        goto done;
    }
    result = 0;
    if (!S_ISDIR(st.st_mode))
        goto done;

    int folder = openat(parent_fd, final_leaf, DIRECTORY_FLAGS);
    char **names = NULL;
    size_t count = 0;
    if (folder < 0 || list_names(folder, &names, &count) != 0)
    {
        failed_step_note(failed, "list what it holds", errno);
        result = -1;
    }
    for (size_t index = 0; result == 0 && index < count; index++)
        result = adopt_node(salvage, root, folder, names[index],
                            entry.logical_path, 0, failed);
    for (size_t index = 0; index < count; index++)
        free(names[index]);
    free(names);
    if (folder >= 0)
        close(folder);

done:
    free(logical);
    return result;
}

// Re-creates every item whose records were all lost from what the payload
// holds of it. A node that lies in no root is refused before anything
// changes: a restore would have nowhere to put it.
static int adopt_unrecorded(RepairSalvage *salvage)
{
    RestoreAddressIndex index = {0};
    PreflightMemory memory = {0};
    RepairFoundList found = {0};
    if (restore_address_index_build(&index, &memory, salvage->log, NULL) != 0)
    {
        restore_address_index_free(&memory, &index);
        print_error("Error: the rebuilt journal's paths are still "
                    "inconsistent; the backup cannot be repaired.\n");
        return -1;
    }
    int scanned = payload_unrecorded_scan(salvage->data_fd, salvage->manifest,
                                          &index, found_add, &found);
    int saved = errno;
    restore_address_index_free(&memory, &index);
    if (scanned != 0)
    {
        print_error("Error: Could not list the backup's payload: %s\n",
                    strerror(saved));
        found_free(&found);
        return -1;
    }
    if (found.strays != 0)
    {
        text_make_printable(found.stray);
        print_error("Error: data/%s%s belongs to none of the backup's folders, "
                    "so a restore has nowhere to put it. Move it out of data/ "
                    "and run repair again; nothing was changed.\n",
                    found.stray, found.strays > 1 ? " (and others)" : "");
        found_free(&found);
        return -1;
    }
    int result = 0;
    for (size_t at = 0; result == 0 && at < found.count; at++)
    {
        const RepairFound *item = &found.items[at];
        int folder = -1;
        char leaf[NAME_MAX + 1U];
        if (item->is_root)
        {
            if (open_existing_payload_parent(salvage->data_fd,
                                             item->root->payload_path,
                                             &folder, leaf,
                                             sizeof(leaf)) != 0)
                folder = -1;
        }
        else
            folder = open_recorded_folder(salvage, item->root, item->parent);
        FailedStep failed = {0};
        if (folder < 0)
            failed_step_note(&failed, "open the folder holding it",
                             errno != 0 ? errno : EINVAL);
        else
            result = adopt_node(salvage, item->root, folder, item->name,
                                item->parent, item->is_root, &failed);
        if (folder < 0 || result != 0)
        {
            char name[NAME_MAX + 1U];
            (void)snprintf(name, sizeof(name), "%s", item->name);
            text_make_printable(name);
            print_step_failure(&failed, "Error: Could not re-create %s, whose "
                                        "record was lost, in %s",
                               name, item->root->id);
            result = -1;
        }
        if (folder >= 0)
            close(folder);
    }
    found_free(&found);
    return result;
}

static int read_journal(int container_fd, unsigned char **data_out,
                        size_t *length_out)
{
    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        print_error("Error: Could not read the backup journal (%s): %s\n",
                    SIDECAR_SLOT_NAME, strerror(errno != 0 ? errno : EINVAL));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if ((uint64_t)st.st_size > SIDECAR_MAX_TOTAL_BYTES)
    {
        print_error("Error: the backup journal is larger than any journal "
                    "migr writes; it cannot be repaired.\n");
        close(fd);
        return -1;
    }
    size_t length = (size_t)st.st_size;
    unsigned char *data = malloc(length != 0 ? length : 1U);
    size_t done = 0;
    while (data != NULL && done < length)
    {
        ssize_t got = pread(fd, data + done, length - done, (off_t)done);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
        {
            print_error("Error: Could not read the backup journal: %s\n",
                        strerror(got < 0 ? errno : EIO));
            free(data);
            data = NULL;
            break;
        }
        done += (size_t)got;
    }
    close(fd);
    if (data == NULL)
        return -1;
    *data_out = data;
    *length_out = length;
    return 0;
}

// Puts the journal rebuilt in staging/ in place of the old one: the drive
// must give it back whole first (D51), and the rename is the one step that
// replaces the old journal, so an interruption leaves one or the other.
// Returns 0, -1 with the old journal in place, or -2 when the drive did not
// confirm the rename.
static int install_journal(int container_fd, int staging_fd)
{
    uint64_t valid_bytes = 0, file_bytes = 0;
    if (syncfs(container_fd) != 0)
        return -1;
    SidecarStatus readback = sidecar_check_complete_readonly(
        staging_fd, &valid_bytes, &file_bytes);
    if (readback != SIDECAR_STATUS_OK)
    {
        if (readback != SIDECAR_STATUS_IO_ERROR)
            errno = EIO;
        return -1;
    }
    if (renameat(staging_fd, SIDECAR_SLOT_NAME, container_fd,
                 SIDECAR_SLOT_NAME) != 0)
        return -1;
    return fsync(container_fd) == 0 ? 0 : -2;
}

int repair_backup(const char *source)
{
    if (source == NULL)
        return 1;
    Manifest manifest;
    int container_fd = -1;
    if (portable_container_open(source, &manifest, &container_fd) != 0)
        return 1;

    int result = 1;
    unsigned char *journal = NULL;
    size_t journal_length = 0;
    int staging_fd = -1;
    SidecarLog log = {0};
    int log_open = 0;
    RepairSalvage salvage;
    memset(&salvage, 0, sizeof(salvage));
    salvage.manifest = &manifest;
    salvage.log = &log;
    salvage.fatal = SIDECAR_STATUS_OK;
    salvage.data_fd = -1;

    // An update or another repair of this backup holds the same lock.
    if (flock(container_fd, LOCK_EX | LOCK_NB) != 0)
    {
        if (errno == EWOULDBLOCK)
            print_error("Error: another migr is using %s; repair it once that "
                        "has finished.\n", source);
        else
            print_error("Error: Could not lock %s: %s\n", source,
                        strerror(errno));
        goto done;
    }
    salvage.data_fd = openat(container_fd, "data",
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (salvage.data_fd < 0)
    {
        print_error("Error: Could not open data/ in the backup: %s\n",
                    strerror(errno));
        goto done;
    }
    if (read_journal(container_fd, &journal, &journal_length) != 0)
        goto done;
    // The journal is rebuilt beside the payload, in staging/ (D110): no
    // room is needed but the journal's own.
    if (container_staging_remove(container_fd) != 0 ||
        (staging_fd = container_staging_open(container_fd)) < 0 ||
        sidecar_log_create_at(staging_fd, &log) != SIDECAR_OPEN_FRESH)
    {
        print_error("Error: Could not start a new journal in %s/%s: %s\n",
                    source, CONTAINER_STAGING_NAME, strerror(errno));
        goto done;
    }
    log_open = 1;

    printf("Rebuilding the backup journal of %s\n", source);
    fflush(stdout);
    if (salvage_journal(&salvage, journal, journal_length) != 0)
        goto done;
    FailedStep settle_failure = {0};
    if (close_open_claims(&salvage, &settle_failure) != 0)
    {
        print_step_failure(&settle_failure, "Error: Could not settle the "
                                            "journal's unfinished items");
        goto done;
    }
    if (adopt_unrecorded(&salvage) != 0)
        goto done;
    keep_lost_only(&salvage, &salvage.rejected);
    keep_lost_only(&salvage, &salvage.dropped);

    RestoreAddressIndex address_index = {0};
    PreflightMemory memory = {0};
    int consistent = restore_address_index_build(&address_index, &memory,
                                                 &log, NULL) == 0;
    restore_address_index_free(&memory, &address_index);
    if (!consistent)
    {
        print_error("Error: the rebuilt journal's paths are still "
                    "inconsistent; the backup cannot be repaired.\n");
        goto done;
    }

    if (salvage.damaged_regions == 0 && salvage.rejected.count == 0 &&
        salvage.recreated.count == 0 && salvage.dropped.count == 0)
    {
        fflush(stdout);
        print_success("The backup journal is intact; nothing to repair. Run "
                      "'migr verify' to check the backed-up files.\n");
        result = 0;
        goto done;
    }

    if (salvage.damaged_regions != 0)
        printf("Skipped %zu damaged region%s of the journal (%ju bytes, the "
               "first at byte %ju)\n", salvage.damaged_regions,
               salvage.damaged_regions == 1 ? "" : "s",
               (uintmax_t)salvage.damaged_bytes,
               (uintmax_t)salvage.first_damage);
    print_path_list("Left out: their records conflict with the rest of the "
                    "journal", &salvage.rejected);
    print_path_list("Left out: their records were lost", &salvage.dropped);
    print_path_list("Re-created from the payload, their own records lost "
                    "(metadata taken from the folder above them)",
                    &salvage.recreated);
    printf("Recovered %zu item%s\n", sidecar_log_live_count(&log),
           sidecar_log_live_count(&log) == 1 ? "" : "s");

    SidecarStatus closed = sidecar_log_close(&log);
    log_open = 0;
    int installed = closed == SIDECAR_STATUS_OK
        ? install_journal(container_fd, staging_fd) : -1;
    if (installed != 0)
    {
        print_error("Error: Could not write the rebuilt journal: %s\n",
                    strerror(errno));
        printf(installed == -1
                   ? "The backup keeps its old journal.\n"
                   : "The rebuilt journal is in place, but the drive did not "
                     "confirm it; run repair again.\n");
        goto done;
    }
    fflush(stdout);
    print_success("Repaired the backup: %s\n", source);
    printf("Check it with 'migr verify', then restore from it.\n");
    result = 0;

done:
    if (log_open)
        sidecar_log_close(&log);
    if (staging_fd >= 0)
    {
        close(staging_fd);
        if (container_staging_remove(container_fd) != 0)
            print_warning("Warning: could not remove %s/%s: %s; the next "
                          "update or repair removes it.\n", source,
                          CONTAINER_STAGING_NAME, strerror(errno));
    }
    pending_clear(&salvage);
    path_list_free(&salvage.rejected);
    path_list_free(&salvage.recreated);
    path_list_free(&salvage.dropped);
    if (salvage.data_fd >= 0)
        close(salvage.data_fd);
    free(journal);
    manifest_free(&manifest);
    close(container_fd);
    return result;
}
