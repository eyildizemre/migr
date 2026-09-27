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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#include "container.h"
#include "manifest.h"
#include "portable_fsops_internal.h"
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
    int source_data_fd;
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

static SidecarBytes bytes_copy(SidecarBytes bytes)
{
    unsigned char *copy = malloc(bytes.length + 1U);
    if (copy == NULL)
        return (SidecarBytes){ NULL, 0 };
    if (bytes.length != 0)
        memcpy(copy, bytes.data, bytes.length);
    copy[bytes.length] = '\0';
    return (SidecarBytes){ copy, bytes.length };
}

static void bytes_release(SidecarBytes *bytes)
{
    free((void *)bytes->data);
    bytes->data = NULL;
    bytes->length = 0;
}

static void entry_release(SidecarEntry *entry)
{
    bytes_release(&entry->root_id);
    bytes_release(&entry->logical_path);
    bytes_release(&entry->physical_leaf);
    bytes_release(&entry->collision_suffix);
    bytes_release(&entry->symlink_target);
    bytes_release(&entry->hardlink_root_id);
    bytes_release(&entry->hardlink_logical_path);
}

static int entry_copy(const SidecarEntry *source, SidecarEntry *out)
{
    *out = *source;
    out->root_id = bytes_copy(source->root_id);
    out->logical_path = bytes_copy(source->logical_path);
    out->physical_leaf = bytes_copy(source->physical_leaf);
    out->collision_suffix = bytes_copy(source->collision_suffix);
    out->symlink_target = bytes_copy(source->symlink_target);
    out->hardlink_root_id = bytes_copy(source->hardlink_root_id);
    out->hardlink_logical_path = bytes_copy(source->hardlink_logical_path);
    if (out->root_id.data == NULL || out->logical_path.data == NULL ||
        out->physical_leaf.data == NULL || out->collision_suffix.data == NULL ||
        out->symlink_target.data == NULL ||
        out->hardlink_root_id.data == NULL ||
        out->hardlink_logical_path.data == NULL)
    {
        entry_release(out);
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

static void xattrs_release(SidecarXattr *xattrs, size_t count)
{
    for (size_t index = 0; index < count; index++)
    {
        bytes_release(&xattrs[index].name);
        bytes_release(&xattrs[index].value);
    }
    free(xattrs);
}

static void pending_clear(RepairSalvage *salvage)
{
    if (salvage->has_pending)
        entry_release(&salvage->pending);
    xattrs_release(salvage->xattrs, salvage->xattr_count);
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
    SidecarBytes root_copy = bytes_copy(root);
    SidecarBytes path_copy = bytes_copy(path);
    if (root_copy.data == NULL || path_copy.data == NULL)
    {
        bytes_release(&root_copy);
        bytes_release(&path_copy);
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
            if (entry_copy(&record->value.entry, &salvage->pending) != 0)
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
            copy->name = bytes_copy(record->value.xattr.name);
            copy->value = bytes_copy(record->value.xattr.value);
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

static int pwrite_all(int fd, const unsigned char *data, size_t length,
                      off_t offset)
{
    while (length != 0)
    {
        ssize_t written = pwrite(fd, data, length, offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
        {
            if (written == 0)
                errno = EIO;
            return -1;
        }
        data += written;
        length -= (size_t)written;
        offset += written;
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
    size_t best = SIZE_MAX;
    for (size_t index = 0; index < sizeof(tags) / sizeof(tags[0]); index++)
    {
        char needle[16];
        size_t tag_length = strlen(tags[index]);
        needle[0] = '\0';
        memcpy(needle + 1, tags[index], tag_length);
        needle[tag_length + 1U] = '\0';
        if (from >= length)
            break;
        const unsigned char *found = memmem(data + from, length - from,
                                            needle, tag_length + 2U);
        if (found != NULL && (size_t)(found - data) + 1U < best)
            best = (size_t)(found - data) + 1U;
    }
    return best;
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
// the next record start. Each segment is parsed behind a copy of the header.
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
    int result = -1;
    size_t start = header_length;
    for (;;)
    {
        pending_clear(salvage);
        if (ftruncate(scratch, 0) != 0 ||
            pwrite_all(scratch, data, header_length, 0) != 0 ||
            pwrite_all(scratch, data + start, length - start,
                       (off_t)header_length) != 0)
        {
            print_error("Error: Could not write a scratch file: %s\n",
                        strerror(errno));
            break;
        }
        SidecarParseResult parsed;
        SidecarStatus status = sidecar_parse_fd(scratch, salvage_record,
                                                salvage, &parsed);
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
        uint64_t boundary = parsed.last_valid_boundary >= header_length
                                ? start + (parsed.last_valid_boundary -
                                           header_length)
                                : start;
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
    copy->root_id = bytes_copy(view->claim->root_id);
    copy->logical_path = bytes_copy(view->claim->logical_path);
    copy->physical_leaf = bytes_copy(view->claim->physical_leaf);
    claims->count++;
    return copy->root_id.data == NULL || copy->logical_path.data == NULL ||
                   copy->physical_leaf.data == NULL
               ? -1 : 0;
}

static void claims_free(RepairClaims *claims)
{
    for (size_t index = 0; index < claims->count; index++)
    {
        bytes_release(&claims->items[index].root_id);
        bytes_release(&claims->items[index].logical_path);
        bytes_release(&claims->items[index].physical_leaf);
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

// Metadata for a directory whose ENTRY was lost: the nearest recorded ancestor
// directory's, or for a root the payload directory's own.
static int synthesize_directory_metadata(RepairSalvage *salvage,
                                         const SidecarClaim *claim,
                                         SidecarEntry *entry,
                                         SidecarXattr **xattrs_out)
{
    *xattrs_out = NULL;
    size_t length = claim->logical_path.length;
    while (length != 0)
    {
        while (length != 0 && claim->logical_path.data[length - 1U] != '/')
            length--;
        if (length != 0)
            length--;
        SidecarLiveView view;
        SidecarBytes prefix = { claim->logical_path.data, length };
        if (sidecar_log_find(salvage->log, claim->root_id, prefix, &view) ==
                1 &&
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
            SidecarXattr *xattrs = calloc(view.xattr_count, sizeof(*xattrs));
            if (xattrs == NULL)
                return -1;
            for (size_t index = 0; index < view.xattr_count; index++)
            {
                xattrs[index].name = bytes_copy(view.xattrs[index].name);
                xattrs[index].value = bytes_copy(view.xattrs[index].value);
                if (xattrs[index].name.data == NULL ||
                    xattrs[index].value.data == NULL)
                {
                    xattrs_release(xattrs, index + 1U);
                    return -1;
                }
            }
            *xattrs_out = xattrs;
            return 0;
        }
    }

    const ManifestRoot *root = NULL;
    for (int index = 0; index < salvage->manifest->root_count; index++)
        if (strlen(salvage->manifest->roots[index].id) ==
                claim->root_id.length &&
            memcmp(salvage->manifest->roots[index].id, claim->root_id.data,
                   claim->root_id.length) == 0)
            root = &salvage->manifest->roots[index];
    struct stat st;
    if (root == NULL ||
        fstatat(salvage->source_data_fd, root->payload_path, &st,
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

// Every item whose capture began but whose ENTRY was lost is either re-created
// (a directory, so its recorded children stay reachable) or left out.
static int close_open_claims(RepairSalvage *salvage)
{
    RepairClaims claims = {0};
    if (sidecar_log_claim_foreach(salvage->log, collect_claim, &claims) !=
        SIDECAR_STATUS_OK)
    {
        claims_free(&claims);
        return -1;
    }
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
            if (synthesize_directory_metadata(salvage, claim, &entry,
                                              &xattrs) == 0 &&
                synthesize_collision_suffix(&entry) == 0)
            {
                SidecarStatus status = sidecar_log_append_group(
                    salvage->log, &entry, xattrs);
                xattrs_release(xattrs, entry.xattr_count);
                if (status == SIDECAR_STATUS_OK)
                {
                    if (path_list_add(&salvage->recreated, claim->root_id,
                                      claim->logical_path) != 0)
                        result = -1;
                    continue;
                }
                if (status != SIDECAR_STATUS_INVALID_ARGUMENT &&
                    status != SIDECAR_STATUS_CORRUPT)
                {
                    result = -1;
                    break;
                }
            }
            else
                xattrs_release(xattrs, entry.xattr_count);
        }
        SidecarDelete deletion = {
            .root_id = claim->root_id,
            .logical_path = claim->logical_path
        };
        if (sidecar_log_append_delete(salvage->log, &deletion) !=
                SIDECAR_STATUS_OK ||
            path_list_add(&salvage->dropped, claim->root_id,
                          claim->logical_path) != 0)
            result = -1;
    }
    claims_free(&claims);
    if (result == 0 && sidecar_log_claim_count(salvage->log) != 0)
        result = -1;
    return result;
}

// A rejected record whose item is live in the end (for example a stale DELETE
// followed by a fresh capture) lost nothing; only the rest are reported.
static void keep_lost_only(RepairSalvage *salvage)
{
    RepairPathList *list = &salvage->rejected;
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
        printf("  %s:%s\n", list->items[index].root,
               list->items[index].path[0] != '\0' ? list->items[index].path
                                                   : ".");
    if (list->count > REPAIR_REPORT_EXAMPLES)
        printf("  ... and %zu more\n", list->count - REPAIR_REPORT_EXAMPLES);
}

typedef struct {
    uint64_t copied;
    uint64_t total;
    int progress;
    struct timespec last_redraw;
} RepairCopy;

static void copy_progress(RepairCopy *copy, int force)
{
    if (!copy->progress ||
        !backup_progress_should_fire(&copy->last_redraw, force))
        return;
    char done[32], total[32];
    format_size((off_t)(copy->copied > INT64_MAX ? INT64_MAX : copy->copied),
                done, sizeof(done));
    format_size((off_t)(copy->total > INT64_MAX ? INT64_MAX : copy->total),
                total, sizeof(total));
    char line[128];
    (void)snprintf(line, sizeof(line), "Copying the backup: %s of %s", done,
                   total);
    progress_line_fit(line, sizeof(line));
    printf("\r%s\033[K", line);
    fflush(stdout);
}

static int copy_file_at(int source_dir, const char *name, int dest_dir,
                        mode_t mode, RepairCopy *copy)
{
    int source = openat(source_dir, name,
                        O_RDONLY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (source < 0 && errno == EPERM)
        source = openat(source_dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0)
        return -1;
    int dest = openat(dest_dir, name,
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      mode);
    if (dest < 0)
    {
        int saved = errno;
        close(source);
        errno = saved;
        return -1;
    }
    int result = 0;
    int kernel_copy = 1;
    unsigned char buffer[65536];
    for (;;)
    {
        ssize_t moved;
        if (kernel_copy)
        {
            moved = copy_file_range(source, NULL, dest, NULL, 1U << 24, 0);
            if (moved < 0 && (errno == EXDEV || errno == EINVAL ||
                              errno == ENOSYS || errno == EOPNOTSUPP))
            {
                kernel_copy = 0;
                continue;
            }
        }
        else
        {
            moved = read(source, buffer, sizeof(buffer));
            for (ssize_t done = 0; moved > 0 && done < moved;)
            {
                ssize_t written = write(dest, buffer + done,
                                        (size_t)(moved - done));
                if (written < 0 && errno == EINTR)
                    continue;
                if (written <= 0)
                {
                    if (written == 0)
                        errno = EIO;
                    moved = -1;
                    break;
                }
                done += written;
            }
        }
        if (moved < 0 && errno == EINTR)
            continue;
        if (moved <= 0)
        {
            result = moved < 0 ? -1 : 0;
            break;
        }
        copy->copied += (uint64_t)moved;
        copy_progress(copy, 0);
    }
    int saved = errno;
    if (close(dest) != 0 && result == 0)
    {
        result = -1;
        saved = errno;
    }
    close(source);
    errno = saved;
    return result;
}

static int copy_tree_at(int source_dir, int dest_dir, RepairCopy *copy,
                        char *failed, size_t failed_size);

static int copy_node_at(int source_dir, const char *name, int dest_dir,
                        RepairCopy *copy, char *failed, size_t failed_size)
{
    struct stat st;
    if (fstatat(source_dir, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        goto fail;
    if (S_ISREG(st.st_mode))
    {
        if (copy_file_at(source_dir, name, dest_dir, st.st_mode & 0777,
                         copy) != 0)
            goto fail;
        return 0;
    }
    if (!S_ISDIR(st.st_mode))
    {
        errno = EINVAL;
        goto fail;
    }
    if (mkdirat(dest_dir, name, 0700) != 0)
        goto fail;
    int source_child = openat(source_dir, name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dest_child = source_child < 0
        ? -1
        : openat(dest_dir, name,
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source_child < 0 || dest_child < 0)
    {
        int saved = errno;
        if (source_child >= 0)
            close(source_child);
        errno = saved;
        goto fail;
    }
    int result = copy_tree_at(source_child, dest_child, copy, failed,
                              failed_size);
    if (result == 0 && fchmod(dest_child, st.st_mode & 0777) != 0)
        result = -1;
    int saved = errno;
    close(dest_child);
    errno = saved;
    if (result != 0 && failed[0] == '\0')
        snprintf(failed, failed_size, "%s", name);
    return result;

fail:
    snprintf(failed, failed_size, "%s", name);
    return -1;
}

// Takes ownership of source_dir.
static int copy_tree_at(int source_dir, int dest_dir, RepairCopy *copy,
                        char *failed, size_t failed_size)
{
    DIR *directory = fdopendir(source_dir);
    if (directory == NULL)
    {
        int saved = errno;
        close(source_dir);
        errno = saved;
        return -1;
    }
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
        if (copy_node_at(dirfd(directory), item->d_name, dest_dir, copy,
                         failed, failed_size) != 0)
        {
            result = -1;
            break;
        }
    }
    int saved = errno;
    closedir(directory);
    errno = saved;
    return result;
}

// Copies everything in the container except the journal, which was rebuilt.
static int copy_container(int source_fd, int dest_fd, RepairCopy *copy)
{
    DIR *directory = fdopendir(dup(source_fd));
    if (directory == NULL)
        return -1;
    int result = 0;
    char failed[NAME_MAX + 1U] = "";
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
        if (strcmp(item->d_name, ".") == 0 ||
            strcmp(item->d_name, "..") == 0 ||
            strcmp(item->d_name, SIDECAR_SLOT_NAME) == 0 ||
            strcmp(item->d_name, SIDECAR_REWRITE_NAME) == 0)
            continue;
        if (copy_node_at(source_fd, item->d_name, dest_fd, copy, failed,
                         sizeof(failed)) != 0)
        {
            result = -1;
            break;
        }
    }
    int saved = errno;
    closedir(directory);
    if (copy->progress)
    {
        copy_progress(copy, 1);
        putchar('\n');
    }
    if (result != 0)
        print_error("Error: Could not copy %s into the repaired backup: %s\n",
                    failed[0] != '\0' ? failed : "the backup",
                    strerror(saved));
    return result;
}

static int sum_regular_bytes(const SidecarLiveView *view, void *context)
{
    uint64_t *total = context;
    if (view->entry->kind == SIDECAR_KIND_REGULAR &&
        view->entry->size <= UINT64_MAX - *total)
        *total += view->entry->size;
    return 0;
}

static int destination_inside_source(const char *source, const char *dest)
{
    char source_real[PATH_MAX], dest_real[PATH_MAX];
    if (realpath(source, source_real) == NULL ||
        realpath(dest, dest_real) == NULL)
        return 0;
    size_t length = strlen(source_real);
    return strncmp(source_real, dest_real, length) == 0 &&
           (dest_real[length] == '\0' || dest_real[length] == '/');
}

// A copy next to the backup it repairs would make the next backup to that
// folder find two of this install's backups and refuse to choose (D72).
static int destination_holds_source(const char *source, const char *dest)
{
    char source_real[PATH_MAX], dest_real[PATH_MAX];
    if (realpath(source, source_real) == NULL ||
        realpath(dest, dest_real) == NULL)
        return 0;
    char *slash = strrchr(source_real, '/');
    if (slash == NULL)
        return 0;
    if (slash == source_real)
        slash++;
    *slash = '\0';
    return strcmp(source_real, dest_real) == 0;
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

static void remove_unpublished(BackupContainer *container, int dest_root_fd)
{
    int fd = container_root_fd(container);
    char name[CONTAINER_NAME_MAX];
    snprintf(name, sizeof(name), "%s", container_current_name(container));
    if (fd >= 0)
        (void)unlinkat(fd, SIDECAR_SLOT_NAME, 0);
    container_close(container);
    (void)unlinkat(dest_root_fd, name, AT_REMOVEDIR);
}

int repair_backup(const char *source, const char *dest_root)
{
    if (source == NULL || dest_root == NULL)
        return 1;
    if (destination_inside_source(source, dest_root))
    {
        print_error("Error: the repaired copy cannot be written inside the "
                    "backup it repairs.\n");
        return 1;
    }
    if (destination_holds_source(source, dest_root))
    {
        print_error("Error: the repaired copy cannot go in the folder that "
                    "holds the backup it repairs: the next backup there would "
                    "find two backups of this install. Choose another folder "
                    "or drive.\n");
        return 1;
    }
    Manifest manifest;
    int source_fd = -1;
    if (portable_container_open(source, &manifest, &source_fd) != 0)
        return 1;

    int result = 1;
    unsigned char *journal = NULL;
    size_t journal_length = 0;
    int dest_root_fd = -1;
    BackupContainer container = {0};
    int container_reserved = 0;
    int copy_started = 0;
    SidecarLog log = {0};
    int log_open = 0;
    RepairSalvage salvage;
    memset(&salvage, 0, sizeof(salvage));
    salvage.manifest = &manifest;
    salvage.log = &log;
    salvage.fatal = SIDECAR_STATUS_OK;
    salvage.source_data_fd = openat(source_fd, "data",
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                        O_CLOEXEC);

    if (salvage.source_data_fd < 0)
    {
        print_error("Error: Could not open data/ in the backup: %s\n",
                    strerror(errno));
        goto done;
    }
    if (read_journal(source_fd, &journal, &journal_length) != 0)
        goto done;
    dest_root_fd = open(dest_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dest_root_fd < 0)
    {
        print_error("Error: Could not open %s: %s\n", dest_root,
                    strerror(errno));
        goto done;
    }
    if (container_reserve_fd(dest_root_fd, invoker_name(), time(NULL),
                             &container) !=
        CONTAINER_OK)
    {
        print_error("Error: Could not create a backup container under %s.\n",
                    dest_root);
        goto done;
    }
    container_reserved = 1;
    int container_fd = container_root_fd(&container);
    if (sidecar_log_create_at(container_fd, &log) != SIDECAR_OPEN_FRESH)
    {
        print_error("Error: Could not start the repaired backup under %s: "
                    "%s\n", dest_root, strerror(errno));
        goto done;
    }
    log_open = 1;

    printf("Rebuilding the backup journal of %s\n", source);
    fflush(stdout);
    if (salvage_journal(&salvage, journal, journal_length) != 0)
        goto done;
    if (close_open_claims(&salvage) != 0)
    {
        print_error("Error: Could not settle the journal's unfinished "
                    "items.\n");
        goto done;
    }
    keep_lost_only(&salvage);

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
        sidecar_log_close(&log);
        log_open = 0;
        remove_unpublished(&container, dest_root_fd);
        container_reserved = 0;
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
    print_path_list("Re-created directories, their own records lost "
                    "(metadata taken from the directory above them)",
                    &salvage.recreated);
    printf("Recovered %zu item%s\n", sidecar_log_live_count(&log),
           sidecar_log_live_count(&log) == 1 ? "" : "s");

    RepairCopy copy = {0};
    if (sidecar_log_foreach(&log, sum_regular_bytes, &copy.total) !=
        SIDECAR_STATUS_OK)
        goto done;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
    {
        log_open = 0;
        print_error("Error: Could not write the rebuilt journal: %s\n",
                    strerror(errno));
        goto done;
    }
    log_open = 0;
    struct statvfs space;
    if (fstatvfs(container_fd, &space) == 0 &&
        (uint64_t)space.f_bavail * space.f_frsize < copy.total)
    {
        char need[32], have[32];
        format_size((off_t)(copy.total > INT64_MAX ? INT64_MAX : copy.total),
                    need, sizeof(need));
        format_size((off_t)((uint64_t)space.f_bavail * space.f_frsize >
                                    INT64_MAX
                                ? INT64_MAX
                                : (uint64_t)space.f_bavail * space.f_frsize),
                    have, sizeof(have));
        print_error("Error: the repaired copy needs %s, but %s has only %s "
                    "free.\n", need, dest_root, have);
        goto done;
    }

    copy.progress = isatty(STDOUT_FILENO);
    copy_started = 1;
    if (copy_container(source_fd, container_fd, &copy) != 0)
        goto done;
    if (syncfs(container_fd) != 0 ||
        container_finalize(&container) != CONTAINER_OK)
    {
        print_error("Error: Could not publish the repaired backup under %s: "
                    "%s\n", dest_root, strerror(errno));
        goto done;
    }
    fflush(stdout);
    print_success("Repaired backup: %s/%s\n", dest_root,
                  container_current_name(&container));
    printf("Check it with 'migr verify', then restore from it.\n");
    result = 0;

done:
    if (log_open)
        sidecar_log_close(&log);
    if (container_reserved && result != 0 && !copy_started)
        remove_unpublished(&container, dest_root_fd);
    else if (container_reserved && result != 0)
        printf("The unfinished copy is left at %s/%s; delete it before "
               "trying again.\n", dest_root,
               container_current_name(&container));
    container_close(&container);
    pending_clear(&salvage);
    path_list_free(&salvage.rejected);
    path_list_free(&salvage.recreated);
    path_list_free(&salvage.dropped);
    if (salvage.source_data_fd >= 0)
        close(salvage.source_data_fd);
    if (dest_root_fd >= 0)
        close(dest_root_fd);
    free(journal);
    manifest_free(&manifest);
    close(source_fd);
    return result;
}
