#define _GNU_SOURCE

#include "portable.h"
#include "container.h"
#include "live_state.h"
#include "portable_reconcile_internal.h"
#include "portable_fsops_internal.h"
#include "portable_hashset_internal.h"
#include "portable_prescan_internal.h"
#include "portable_name.h"
#include "repair.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <signal.h>
#include <unistd.h>

#include "encoding.h"
#include "metadata.h"
#include "selection.h"
#include "utils.h"

#define PORTABLE_MAX_READBACK_NAMES SIDECAR_MAX_LIVE_ENTRIES

void portable_prescan_report_init(PortablePrescanReport *report)
{
    if (report != NULL)
        memset(report, 0, sizeof(*report));
}

void portable_prescan_report_free(PortablePrescanReport *report)
{
    if (report == NULL)
        return;
    free(report->examples);
    portable_collision_plan_free(&report->collision_plan);
    for (size_t index = 0; index < report->current_source.count; index++)
        free(report->current_source.entries[index].logical_path);
    free(report->current_source.entries);
    for (size_t index = 0; index < report->unreadable.count; index++)
        free(report->unreadable.entries[index].logical_path);
    free(report->unreadable.entries);
    if (report->inode_seen != NULL)
    {
        prescan_inode_set_free(report->inode_seen);
        report->inode_seen = NULL;
    }
    memset(report, 0, sizeof(*report));
}


#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static uint64_t portable_test_probe_count;
static uint64_t portable_test_readback_scan_count;
static uint64_t portable_test_case_probe_count;
static uint64_t portable_test_case_fs_probe_count;
static uint64_t portable_test_relocation_scan_count;
static uint64_t portable_test_relocation_remove_count;
static uint64_t portable_test_inode_map_probe_count;
static uint64_t portable_test_prescan_inode_probe_count;
static uint64_t portable_test_sticky_seed_lstat_count;

void visited_count_probe(void)
{
    if (portable_test_probe_count != UINT64_MAX)
        portable_test_probe_count++;
}

uint64_t portable_capture_test_probe_count(void)
{
    return portable_test_probe_count;
}

void portable_capture_test_reset_probe_count(void)
{
    portable_test_probe_count = 0;
}

uint64_t portable_capture_test_readback_scan_count(void)
{
    return portable_test_readback_scan_count;
}

void portable_capture_test_reset_readback_scan_count(void)
{
    portable_test_readback_scan_count = 0;
}

uint64_t portable_capture_test_case_probe_count(void)
{
    return portable_test_case_probe_count;
}

void portable_capture_test_reset_case_probe_count(void)
{
    portable_test_case_probe_count = 0;
}

uint64_t portable_capture_test_case_fs_probe_count(void)
{
    return portable_test_case_fs_probe_count;
}

void portable_capture_test_reset_case_fs_probe_count(void)
{
    portable_test_case_fs_probe_count = 0;
}

uint64_t portable_capture_test_inode_map_probe_count(void)
{
    return portable_test_inode_map_probe_count;
}

void portable_capture_test_reset_inode_map_probe_count(void)
{
    portable_test_inode_map_probe_count = 0;
}

uint64_t portable_capture_test_prescan_inode_probe_count(void)
{
    return portable_test_prescan_inode_probe_count;
}

void portable_capture_test_reset_prescan_inode_probe_count(void)
{
    portable_test_prescan_inode_probe_count = 0;
}

uint64_t portable_capture_test_sticky_seed_lstat_count(void)
{
    return portable_test_sticky_seed_lstat_count;
}

void portable_capture_test_reset_sticky_seed_lstat_count(void)
{
    portable_test_sticky_seed_lstat_count = 0;
}

uint64_t portable_capture_test_relocation_scan_count(void)
{
    return portable_test_relocation_scan_count;
}

void portable_capture_test_reset_relocation_scan_count(void)
{
    portable_test_relocation_scan_count = 0;
    portable_test_relocation_remove_count = 0;
}

uint64_t portable_capture_test_relocation_remove_count(void)
{
    return portable_test_relocation_remove_count;
}

void case_probe_count(void)
{
    if (portable_test_case_probe_count != UINT64_MAX)
        portable_test_case_probe_count++;
}

void case_fs_probe_count(void)
{
    if (portable_test_case_fs_probe_count != UINT64_MAX)
        portable_test_case_fs_probe_count++;
}

void inode_map_count_probe(void)
{
    if (portable_test_inode_map_probe_count != UINT64_MAX)
        portable_test_inode_map_probe_count++;
}

void prescan_inode_count_probe(void)
{
    if (portable_test_prescan_inode_probe_count != UINT64_MAX)
        portable_test_prescan_inode_probe_count++;
}

static void sticky_seed_count_lstat(void)
{
    if (portable_test_sticky_seed_lstat_count != UINT64_MAX)
        portable_test_sticky_seed_lstat_count++;
}

void relocation_scan_count(void)
{
    if (portable_test_relocation_scan_count != UINT64_MAX)
        portable_test_relocation_scan_count++;
}

void relocation_remove_count(void)
{
    if (portable_test_relocation_remove_count != UINT64_MAX)
        portable_test_relocation_remove_count++;
}
#else
void visited_count_probe(void)
{
}

void case_probe_count(void)
{
}

void case_fs_probe_count(void)
{
}

void inode_map_count_probe(void)
{
}

void prescan_inode_count_probe(void)
{
}

static void sticky_seed_count_lstat(void)
{
}

void relocation_scan_count(void)
{
}

void relocation_remove_count(void)
{
}
#endif

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static void portable_readback_scan_count(void)
{
    if (portable_test_readback_scan_count != UINT64_MAX)
        portable_test_readback_scan_count++;
}
#else
static void portable_readback_scan_count(void)
{
}
#endif

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static volatile sig_atomic_t portable_test_interrupt_point =
    PORTABLE_TEST_INTERRUPT_NONE;
static PortableCaptureTestHook portable_test_after_payload_write_hook;
static void *portable_test_after_payload_write_context;

void portable_capture_test_set_interrupt(PortableTestInterruptPoint point)
{
    portable_test_interrupt_point = point;
}

void portable_capture_test_set_after_payload_write_hook(
    PortableCaptureTestHook hook, void *userdata)
{
    portable_test_after_payload_write_hook = hook;
    portable_test_after_payload_write_context = userdata;
}

static void portable_test_after_payload_write(void)
{
    PortableCaptureTestHook hook = portable_test_after_payload_write_hook;
    void *userdata = portable_test_after_payload_write_context;
    portable_test_after_payload_write_hook = NULL;
    portable_test_after_payload_write_context = NULL;
    if (hook != NULL)
        hook(userdata);
}

void portable_test_interrupt_if(PortableTestInterruptPoint point)
{
    if (portable_test_interrupt_point == (sig_atomic_t)point)
        (void)kill(getpid(), SIGKILL);
}
#else
void portable_test_interrupt_if(int point)
{
    (void)point;
}

static void portable_test_after_payload_write(void)
{
}
#endif

size_t bounded_strlen(const char *value, size_t maximum)
{
    if (value == NULL)
        return 0;
    return strnlen(value, maximum + 1U);
}

int copy_text(char *destination, size_t destination_size,
                     const char *source)
{
    if (destination == NULL || destination_size == 0 || source == NULL)
        return -1;
    size_t length = bounded_strlen(source, destination_size - 1U);
    if (length >= destination_size)
        return -1;
    memcpy(destination, source, length + 1U);
    return 0;
}


static int safe_id(const char *id)
{
    if (id == NULL || id[0] == '\0' || strlen(id) >= MANIFEST_ID_MAX)
        return 0;
    for (size_t index = 0; id[index] != '\0'; index++)
        if (!(id[index] >= 'a' && id[index] <= 'z') &&
            !(id[index] >= 'A' && id[index] <= 'Z') &&
            !(id[index] >= '0' && id[index] <= '9') &&
            id[index] != '_' && id[index] != '-')
            return 0;
    return 1;
}

int portable_component_valid(const char *component, size_t length)
{
    return component != NULL && length != 0 && length <= NAME_MAX &&
           memchr(component, '/', length) == NULL &&
           memchr(component, '\0', length) == NULL &&
           !(length == 1 && component[0] == '.') &&
           !(length == 2 && component[0] == '.' && component[1] == '.');
}

int portable_relative_bytes_valid(const char *data, size_t length,
                                  int allow_empty)
{
    if (length >= PATH_MAX || (length != 0 && data == NULL))
        return 0;
    if (length == 0)
        return allow_empty;
    if (data[0] == '/' || data[length - 1U] == '/')
        return 0;

    size_t component_start = 0;
    for (size_t index = 0; index <= length; index++)
    {
        if (index != length && data[index] != '/')
            continue;
        if (!portable_component_valid(data + component_start,
                                      index - component_start))
            return 0;
        component_start = index + 1U;
    }
    return 1;
}

int safe_component(const char *component)
{
    return component != NULL &&
           portable_component_valid(component, strlen(component));
}

int safe_relative_path(const char *path)
{
    if (path == NULL || path[0] == '\0' || path[0] == '/')
        return 0;
    size_t length = bounded_strlen(path, PATH_MAX);
    return portable_relative_bytes_valid(path, length, 0);
}

int portable_collision_suffix_parse(const char *data, size_t length,
                                    uint64_t *out_value)
{
    if (data == NULL || out_value == NULL || length < 4U ||
        length > SIDECAR_MAX_COLLISION_SUFFIX || data[0] != '%' ||
        data[1] != '7' || data[2] != 'E' || data[3] < '1' ||
        data[3] > '9')
        return 0;

    uint64_t value = (uint64_t)(data[3] - '0');
    for (size_t index = 4U; index < length; index++)
    {
        if (data[index] < '0' || data[index] > '9' ||
            value > (UINT64_MAX - (uint64_t)(data[index] - '0')) /
                UINT64_C(10))
            return 0;
        value = value * UINT64_C(10) +
                (uint64_t)(data[index] - '0');
    }
    *out_value = value;
    return value != 0;
}

void xattrs_free(PortableXattrs *xattrs)
{
    if (xattrs == NULL)
        return;
    for (size_t index = 0; index < xattrs->count; index++) {
        free((void *)xattrs->items[index].name.data);
        free((void *)xattrs->items[index].value.data);
    }
    free(xattrs->items);
    memset(xattrs, 0, sizeof(*xattrs));
}

static int xattrs_reserve(PortableXattrs *xattrs, size_t extra)
{
    SidecarXattr *items = array_reserve(xattrs->items, &xattrs->capacity,
                                        xattrs->count, extra,
                                        sizeof(*items), 4U,
                                        SIDECAR_MAX_XATTRS_PER_ENTRY);
    if (items == NULL)
        return -1;
    xattrs->items = items;
    return 0;
}

typedef struct {
    char **names;
    size_t count;
    size_t capacity;
} PendingReadbackNames;

static void pending_readback_names_free(PendingReadbackNames *pending)
{
    for (size_t index = 0; index < pending->count; index++)
        free(pending->names[index]);
    free(pending->names);
    memset(pending, 0, sizeof(*pending));
}

static int pending_readback_names_reserve(PendingReadbackNames *pending,
                                          size_t extra)
{
    char **names = array_reserve(pending->names, &pending->capacity,
                                 pending->count, extra, sizeof(*names), 16U,
                                 PORTABLE_MAX_READBACK_NAMES);
    if (names == NULL)
        return -1;
    pending->names = names;
    return 0;
}

static int pending_readback_names_add(PendingReadbackNames *pending,
                                      const char *name)
{
    if (pending_readback_names_reserve(pending, 1) != 0)
        return -1;
    size_t length = strlen(name);
    char *copy = malloc(length + 1U);
    if (copy == NULL)
        return -1;
    memcpy(copy, name, length + 1U);
    pending->names[pending->count++] = copy;
    return 0;
}

static void pending_readback_names_remove_last(PendingReadbackNames *pending)
{
    pending->count--;
    free(pending->names[pending->count]);
    pending->names[pending->count] = NULL;
}

static int encoded_name_has_raw_high_byte(const char *encoded)
{
    for (size_t index = 0; encoded[index] != '\0'; index++)
        if ((unsigned char)encoded[index] >= 0x80U)
            return 1;
    return 0;
}

typedef struct {
    const char *name;
    size_t original_index;
} PendingReadbackNameRef;

static int pending_readback_name_ref_compare(const void *left,
                                             const void *right)
{
    const PendingReadbackNameRef *left_ref = left;
    const PendingReadbackNameRef *right_ref = right;
    return strcmp(left_ref->name, right_ref->name);
}

static int verify_pending_readback_names(int destination_fd,
                                         const PendingReadbackNames *pending)
{
    if (pending->count == 0)
        return 0;

    unsigned char *found = calloc(pending->count, sizeof(*found));
    if (found == NULL)
        return -1;
    PendingReadbackNameRef *sorted =
        malloc(pending->count * sizeof(*sorted));
    if (sorted == NULL) {
        free(found);
        return -1;
    }
    for (size_t index = 0; index < pending->count; index++) {
        sorted[index].name = pending->names[index];
        sorted[index].original_index = index;
    }
    qsort(sorted, pending->count, sizeof(*sorted),
          pending_readback_name_ref_compare);

    int scan_fd = dup_cloexec(destination_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        free(sorted);
        free(found);
        return -1;
    }
    /* Rewound: through an fd opened earlier, btrfs lists only the entries
     * that existed then, and this folder has been written since. */
    rewinddir(directory);
    portable_readback_scan_count();

    int scan_error = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                scan_error = 1;
            break;
        }
        size_t low = 0;
        size_t high = pending->count;
        while (low < high) {
            size_t middle = low + (high - low) / 2U;
            if (strcmp(sorted[middle].name, entry->d_name) < 0)
                low = middle + 1U;
            else
                high = middle;
        }
        if (low < pending->count &&
            strcmp(sorted[low].name, entry->d_name) == 0)
            found[sorted[low].original_index] = 1;
    }
    int close_failed = closedir(directory) != 0;
    free(sorted);
    int all_found = 1;
    for (size_t index = 0; index < pending->count; index++)
        if (!found[index]) {
            all_found = 0;
            break;
        }
    free(found);
    return (!scan_error && !close_failed && all_found) ? 0 : -1;
}

static ssize_t xattr_list(int fd, const char *path, char *names, size_t size)
{
    return path != NULL ? llistxattr(path, names, size)
                        : flistxattr(fd, names, size);
}

static ssize_t xattr_get(int fd, const char *path, const char *name,
                         void *value, size_t size)
{
    return path != NULL ? lgetxattr(path, name, value, size)
                        : fgetxattr(fd, name, value, size);
}

// Reads the xattrs of fd, or of path itself when path is set.
static int collect_xattrs_from(int fd, const char *path, PortableXattrs *out)
{
    memset(out, 0, sizeof(*out));

    errno = 0;
    ssize_t length = xattr_list(fd, path, NULL, 0);
    if (length < 0)
        return errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENODATA
                   ? 0
                   : -1;
    if ((uint64_t)length > SIDECAR_MAX_XATTRS_PER_ENTRY *
                           (uint64_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (length == 0)
        return 0;

    char *names = malloc((size_t)length);
    if (names == NULL)
        return -1;
    /* Shorter than asked is fine, as in metadata_xattr_names_read(). */
    ssize_t received = xattr_list(fd, path, names, (size_t)length);
    if (received < 0 || received > length)
        goto fail;

    size_t offset = 0;
    while (offset < (size_t)received) {
        const char *name = names + offset;
        size_t name_length = strnlen(name, (size_t)received - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == (size_t)received - offset)
            goto fail;
        offset += name_length + 1U;
        if (metadata_xattr_is_selinux_label((const unsigned char *)name,
                                            name_length))
            continue;
        if (xattrs_reserve(out, 1) != 0)
            goto fail;

        errno = 0;
        ssize_t value_length = xattr_get(fd, path, name, NULL, 0);
        if (value_length < 0 || (uint64_t)value_length > SIDECAR_MAX_XATTR_VALUE)
            goto fail;
        unsigned char *name_copy = malloc(name_length);
        unsigned char *value_copy =
            value_length > 0 ? malloc((size_t)value_length) : NULL;
        if (name_copy == NULL || (value_length > 0 && value_copy == NULL) ||
            (value_length > 0 &&
             xattr_get(fd, path, name, value_copy, (size_t)value_length) !=
                 value_length)) {
            free(name_copy);
            free(value_copy);
            goto fail;
        }
        memcpy(name_copy, name, name_length);
        out->items[out->count++] = (SidecarXattr){
            .name = { name_copy, name_length },
            .value = { value_copy, (size_t)value_length }
        };
    }
    free(names);
    return 0;

fail:
    free(names);
    xattrs_free(out);
    return -1;
}

int collect_xattrs(int fd, PortableXattrs *out)
{
    if (fd < 0 || out == NULL)
        return -1;
    return collect_xattrs_from(fd, NULL, out);
}

int collect_symlink_xattrs(const char *path, PortableXattrs *out)
{
    if (path == NULL || out == NULL)
        return -1;
    return collect_xattrs_from(-1, path, out);
}

// The sidecar's fixed-width fields hold every value these types can take.
_Static_assert(sizeof(time_t) <= sizeof(int64_t),
               "a timestamp fits the sidecar's 64-bit seconds");
_Static_assert(sizeof(uid_t) <= sizeof(uint32_t) &&
                   sizeof(gid_t) <= sizeof(uint32_t),
               "an owner fits the sidecar's 32-bit ids");
_Static_assert(SIDECAR_MAX_MODE == 07777U,
               "the sidecar records the permission bits whole");
_Static_assert(NAME_MAX <= SIDECAR_MAX_PHYSICAL_LEAF,
               "a payload root's own name fits a recorded leaf");

int entry_from_stat(const char *root_id, const char *logical,
                    const char *physical_leaf, const char *collision_suffix,
                    const struct stat *st,
                    PortableXattrs *xattrs, SidecarEntry *out,
                    const SidecarBytes *symlink_target,
                    const SidecarBytes *hardlink_root_id,
                    const SidecarBytes *hardlink_logical_path)
{
    int hardlink_requested = hardlink_root_id != NULL ||
                             hardlink_logical_path != NULL;
    if (root_id == NULL || logical == NULL || physical_leaf == NULL ||
        collision_suffix == NULL || st == NULL || out == NULL ||
        st->st_size < 0)
        return -1;
    if (st->st_atim.tv_nsec < 0 || st->st_atim.tv_nsec > SIDECAR_MAX_NSEC ||
        st->st_mtim.tv_nsec < 0 || st->st_mtim.tv_nsec > SIDECAR_MAX_NSEC)
        return -1;
    if (hardlink_requested &&
        (hardlink_root_id == NULL || hardlink_logical_path == NULL ||
         !S_ISREG(st->st_mode) || symlink_target != NULL ||
         (xattrs != NULL && xattrs->count != 0) ||
         hardlink_root_id->data == NULL || hardlink_root_id->length == 0 ||
         hardlink_root_id->length > SIDECAR_MAX_ROOT_ID ||
         memchr(hardlink_root_id->data, '\0', hardlink_root_id->length) != NULL ||
         hardlink_logical_path->data == NULL ||
         hardlink_logical_path->length > SIDECAR_MAX_PATH ||
         memchr(hardlink_logical_path->data, '\0',
                hardlink_logical_path->length) != NULL))
        return -1;

    memset(out, 0, sizeof(*out));
    if ((logical[0] == '\0' && physical_leaf[0] != '\0') ||
        (logical[0] != '\0' && !safe_component(physical_leaf)))
        return -1;

    out->root_id = (SidecarBytes){ (const unsigned char *)root_id,
                                   strlen(root_id) };
    out->logical_path = (SidecarBytes){ (const unsigned char *)logical,
                                        strlen(logical) };
    out->physical_leaf = (SidecarBytes){
        (const unsigned char *)physical_leaf, strlen(physical_leaf) };
    out->collision_suffix = (SidecarBytes){
        (const unsigned char *)collision_suffix, strlen(collision_suffix) };
    if (hardlink_requested)
        out->kind = SIDECAR_KIND_HARDLINK;
    else if (S_ISLNK(st->st_mode))
        out->kind = SIDECAR_KIND_SYMLINK;
    else if (S_ISREG(st->st_mode))
        out->kind = SIDECAR_KIND_REGULAR;
    else
        out->kind = SIDECAR_KIND_DIRECTORY;
    out->mode = (uint32_t)(st->st_mode & 07777);
    out->uid = (uint32_t)st->st_uid;
    out->gid = (uint32_t)st->st_gid;
    out->atime_sec = st->st_atim.tv_sec;
    out->mtime_sec = st->st_mtim.tv_sec;
    out->atime_nsec = (uint32_t)st->st_atim.tv_nsec;
    out->mtime_nsec = (uint32_t)st->st_mtim.tv_nsec;
    out->size = out->kind == SIDECAR_KIND_HARDLINK
                    ? 0U
                    : ((S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))
                           ? (uint64_t)st->st_size : 0U);
    out->xattr_count = out->kind == SIDECAR_KIND_HARDLINK
                           ? 0U
                           : (xattrs == NULL ? 0U : (uint32_t)xattrs->count);
    if (out->kind == SIDECAR_KIND_HARDLINK) {
        out->hardlink_root_id = *hardlink_root_id;
        out->hardlink_logical_path = *hardlink_logical_path;
    } else if (out->kind == SIDECAR_KIND_SYMLINK) {
        if (symlink_target == NULL || symlink_target->data == NULL ||
            symlink_target->length == 0)
            return -1;
        out->symlink_target = *symlink_target;
    }
    return 0;
}

int sidecar_bytes_equal(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 ||
            (left.data != NULL && right.data != NULL &&
             memcmp(left.data, right.data, left.length) == 0));
}

static int xattrs_equal(const PortableXattrs *current,
                        const SidecarLiveView *previous)
{
    if (current == NULL || current->count != previous->xattr_count)
        return 0;
    unsigned char matched[SIDECAR_MAX_XATTRS_PER_ENTRY] = {0};
    for (size_t index = 0; index < current->count; index++) {
        SidecarBytes name = current->items[index].name;
        SidecarBytes value = current->items[index].value;
        int found = 0;
        for (size_t candidate = 0; candidate < previous->xattr_count;
             candidate++) {
            if (matched[candidate])
                continue;
            if (sidecar_bytes_equal(name, previous->xattrs[candidate].name) &&
                sidecar_bytes_equal(value,
                                    previous->xattrs[candidate].value)) {
                matched[candidate] = 1;
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    return 1;
}

int entries_equal(const SidecarEntry *current,
                  const SidecarLiveView *previous,
                  const PortableXattrs *xattrs)
{
    if (current == NULL || previous == NULL || previous->entry == NULL)
        return 0;
    const SidecarEntry *entry = previous->entry;
    /* Reading a symlink target may update its source atime; D18 does not
     * promise source-symlink atime preservation, so atime is not a resume key. */
    return sidecar_bytes_equal(current->root_id, entry->root_id) &&
           sidecar_bytes_equal(current->logical_path, entry->logical_path) &&
           sidecar_bytes_equal(current->physical_leaf, entry->physical_leaf) &&
           sidecar_bytes_equal(current->collision_suffix,
                               entry->collision_suffix) &&
           current->kind == entry->kind && current->mode == entry->mode &&
           current->uid == entry->uid && current->gid == entry->gid &&
           (current->kind == SIDECAR_KIND_SYMLINK ||
            (current->atime_sec == entry->atime_sec &&
             current->atime_nsec == entry->atime_nsec)) &&
           current->mtime_sec == entry->mtime_sec &&
           current->mtime_nsec == entry->mtime_nsec &&
           (current->kind != SIDECAR_KIND_REGULAR ||
            current->size == entry->size) &&
           sidecar_bytes_equal(current->symlink_target, entry->symlink_target) &&
           sidecar_bytes_equal(current->hardlink_root_id,
                               entry->hardlink_root_id) &&
           sidecar_bytes_equal(current->hardlink_logical_path,
                               entry->hardlink_logical_path) &&
           xattrs_equal(xattrs, previous);
}

/* Whether a regular file differs from its record at most in metadata (mode,
 * owner, atime, xattrs): the same address, and the size and mtime that resume
 * and native updates already trust to tell content apart. */
static int entry_content_equal(const SidecarEntry *current,
                               const SidecarEntry *entry)
{
    return current->kind == SIDECAR_KIND_REGULAR &&
           entry->kind == SIDECAR_KIND_REGULAR &&
           sidecar_bytes_equal(current->root_id, entry->root_id) &&
           sidecar_bytes_equal(current->logical_path, entry->logical_path) &&
           sidecar_bytes_equal(current->physical_leaf, entry->physical_leaf) &&
           sidecar_bytes_equal(current->collision_suffix,
                               entry->collision_suffix) &&
           sidecar_bytes_equal(current->hardlink_root_id,
                               entry->hardlink_root_id) &&
           sidecar_bytes_equal(current->hardlink_logical_path,
                               entry->hardlink_logical_path) &&
           current->size == entry->size &&
           current->mtime_sec == entry->mtime_sec &&
           current->mtime_nsec == entry->mtime_nsec;
}

static int existing_payload_matches(int data_fd, const char *payload_path,
                                    int destination_parent,
                                    const char *destination_leaf,
                                    int destination_is_root,
                                    uint64_t expected_size)
{
    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (open_existing_payload_parent(data_fd, payload_path, &parent_fd,
                                         root_leaf, sizeof(root_leaf)) != 0)
            return errno == ENOENT ? 0 : -1;
        destination_leaf = root_leaf;
    }

    struct stat st;
    int result = fstatat(parent_fd, destination_leaf, &st,
                         AT_SYMLINK_NOFOLLOW);
    int saved = errno;
    if (destination_is_root && close(parent_fd) != 0 && result == 0) {
        result = -1;
        saved = EIO;
    }
    if (result != 0) {
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size != expected_size)
        return 0;
    return 1;
}

int sidecar_bytes_to_text(SidecarBytes bytes, char **out)
{
    if (out == NULL || bytes.length >= PATH_MAX ||
        (bytes.length != 0 && bytes.data == NULL) ||
        (bytes.length != 0 && memchr(bytes.data, '\0', bytes.length) != NULL))
        return -1;
    char *copy = malloc(bytes.length + 1U);
    if (copy == NULL)
        return -1;
    if (bytes.length != 0)
        memcpy(copy, bytes.data, bytes.length);
    copy[bytes.length] = '\0';
    *out = copy;
    return 0;
}

typedef struct {
    PortableInodeMap *inode_map;
    const PortableCaptureRequest *request;
    int failed;
} StickySeedState;

static int sticky_seed_callback(const SidecarLiveView *view, void *argument)
{
    StickySeedState *state = argument;
    if (view->entry->kind != SIDECAR_KIND_REGULAR)
        return 0;

    char *root_id = NULL;
    char *logical = NULL;
    if (sidecar_bytes_to_text(view->entry->root_id, &root_id) != 0 ||
        sidecar_bytes_to_text(view->entry->logical_path, &logical) != 0) {
        free(root_id);
        free(logical);
        state->failed = 1;
        return 1;
    }

    const PortableRootSpec *root = portable_collision_plan_root(state->request,
                                                                root_id);
    char source_path[PATH_MAX];
    int source_path_ready = 0;
    if (root != NULL) {
        if (logical[0] == '\0') {
            int length = snprintf(source_path, sizeof(source_path), "%s",
                                  root->capture_path);
            source_path_ready = length >= 0 &&
                                 (size_t)length < sizeof(source_path);
        } else {
            source_path_ready = path_join(source_path, sizeof(source_path),
                                          root->capture_path, logical) == 0;
        }
    }

    struct stat source_stat;
    int source_exists = 0;
    if (source_path_ready) {
        sticky_seed_count_lstat();
        source_exists = lstat(source_path, &source_stat) == 0;
    }
    if (source_exists && S_ISREG(source_stat.st_mode)) {
        const PortableInodeSlot *slot = NULL;
        if (inode_map_find_or_insert(state->inode_map, source_stat.st_dev,
                                     source_stat.st_ino, root_id, logical,
                                     &slot) < 0) {
            state->failed = 1;
            free(root_id);
            free(logical);
            return 1;
        }
    }

    free(root_id);
    free(logical);
    return 0;
}

static int sticky_seed_inode_map(PortableInodeMap *inode_map,
                                 const PortableCaptureRequest *request,
                                 SidecarLog *sidecar)
{
    StickySeedState state = {
        .inode_map = inode_map,
        .request = request,
        .failed = 0
    };
    SidecarStatus status = sidecar_log_foreach(sidecar, sticky_seed_callback,
                                               &state);
    return status == SIDECAR_STATUS_OK && state.failed == 0 ? 0 : -1;
}

void portable_physical_owners_free(PortablePhysicalOwners *owners)
{
    if (owners == NULL)
        return;
    for (size_t index = 0; index < owners->count; index++) {
        PortablePhysicalOwner *item = &owners->items[index];
        free(item->root_id);
        free(item->logical_parent);
        free(item->physical_leaf);
        free(item->logical_path);
    }
    free(owners->items);
    memset(owners, 0, sizeof(*owners));
}

static int logical_parent_dup(const char *logical, char **out)
{
    *out = NULL;
    const char *slash = strrchr(logical, '/');
    size_t length = slash == NULL ? 0U : (size_t)(slash - logical);
    char *parent = malloc(length + 1U);
    if (parent == NULL)
        return -1;
    if (length != 0)
        memcpy(parent, logical, length);
    parent[length] = '\0';
    *out = parent;
    return 0;
}

static int portable_physical_owner_append(
    PortablePhysicalOwners *owners, SidecarBytes root_id,
    SidecarBytes logical_path, SidecarBytes physical_leaf,
    SidecarObjectKind kind, PortableOwnerState state)
{
    if (owners->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (owners->count == owners->capacity) {
        PortablePhysicalOwner *items = array_reserve(
            owners->items, &owners->capacity, owners->count, 1U,
            sizeof(*items), 16U, SIDECAR_MAX_LIVE_ENTRIES);
        if (items == NULL)
            return -1;
        owners->items = items;
    }

    PortablePhysicalOwner item = { .kind = kind, .state = state };
    if (sidecar_bytes_to_text(root_id, &item.root_id) != 0 ||
        sidecar_bytes_to_text(logical_path, &item.logical_path) != 0 ||
        sidecar_bytes_to_text(physical_leaf, &item.physical_leaf) != 0 ||
        logical_parent_dup(item.logical_path, &item.logical_parent) != 0) {
        free(item.root_id);
        free(item.logical_parent);
        free(item.physical_leaf);
        free(item.logical_path);
        return -1;
    }
    owners->items[owners->count++] = item;
    owners->sorted = 0;
    return 0;
}

static int portable_active_live_callback(const SidecarLiveView *view,
                                         void *argument)
{
    PortablePhysicalOwners *owners = argument;
    return portable_physical_owner_append(
               owners, view->entry->root_id, view->entry->logical_path,
               view->entry->physical_leaf, view->entry->kind,
               PORTABLE_OWNER_LIVE) == 0
               ? 0
               : 1;
}

static int portable_active_claim_callback(const SidecarClaimView *view,
                                          void *argument)
{
    PortablePhysicalOwners *owners = argument;
    return portable_physical_owner_append(
               owners, view->claim->root_id, view->claim->logical_path,
               view->claim->physical_leaf, view->claim->kind,
               PORTABLE_OWNER_CLAIM) == 0
               ? 0
               : 1;
}

static int portable_tombstone_callback(const SidecarLiveView *view,
                                       void *argument)
{
    PortablePhysicalOwners *owners = argument;
    return portable_physical_owner_append(
               owners, view->entry->root_id, view->entry->logical_path,
               view->entry->physical_leaf, view->entry->kind,
               PORTABLE_OWNER_TOMBSTONE) == 0
               ? 0
               : 1;
}

static int portable_physical_owner_compare(const void *left,
                                           const void *right)
{
    const PortablePhysicalOwner *a = left;
    const PortablePhysicalOwner *b = right;
    int result = strcmp(a->root_id, b->root_id);
    if (result == 0)
        result = strcmp(a->logical_parent, b->logical_parent);
    if (result == 0)
        result = strcmp(a->physical_leaf, b->physical_leaf);
    if (result == 0)
        result = strcmp(a->logical_path, b->logical_path);
    return result;
}

static int portable_physical_owners_sort(PortablePhysicalOwners *owners,
                                         int reject_ambiguous)
{
    if (owners->count > 1U)
        qsort(owners->items, owners->count, sizeof(*owners->items),
              portable_physical_owner_compare);
    if (reject_ambiguous) {
        for (size_t index = 1; index < owners->count; index++) {
            PortablePhysicalOwner *previous = &owners->items[index - 1U];
            PortablePhysicalOwner *current = &owners->items[index];
            if (strcmp(previous->root_id, current->root_id) == 0 &&
                strcmp(previous->logical_parent, current->logical_parent) == 0 &&
                strcmp(previous->physical_leaf, current->physical_leaf) == 0)
                return -1;
        }
    }
    owners->sorted = 1;
    owners->allow_ambiguous = !reject_ambiguous;
    return 0;
}

int portable_active_owners_load(PortablePhysicalOwners *owners,
                                SidecarLog *sidecar)
{
    if (owners == NULL || sidecar == NULL)
        return -1;
    portable_physical_owners_free(owners);
    SidecarStatus live_status = sidecar_log_foreach(
        sidecar, portable_active_live_callback, owners);
    SidecarStatus claim_status = live_status == SIDECAR_STATUS_OK
        ? sidecar_log_claim_foreach(sidecar, portable_active_claim_callback,
                                    owners)
        : live_status;
    if (live_status != SIDECAR_STATUS_OK || claim_status != SIDECAR_STATUS_OK ||
        portable_physical_owners_sort(owners, 1) != 0) {
        portable_physical_owners_free(owners);
        return -1;
    }
    return 0;
}

int portable_tombstone_owners_load(PortablePhysicalOwners *owners,
                                   SidecarLog *sidecar)
{
    if (owners == NULL || sidecar == NULL)
        return -1;
    portable_physical_owners_free(owners);
    SidecarStatus status = sidecar_log_deleted_foreach(
        sidecar, portable_tombstone_callback, owners);
    if (status != SIDECAR_STATUS_OK ||
        portable_physical_owners_sort(owners, 0) != 0) {
        portable_physical_owners_free(owners);
        return -1;
    }
    return 0;
}

static int portable_owner_key_compare(const PortablePhysicalOwner *item,
                                      const char *root_id,
                                      const char *logical_parent,
                                      const char *physical_leaf)
{
    int result = strcmp(item->root_id, root_id);
    if (result == 0)
        result = strcmp(item->logical_parent, logical_parent);
    if (result == 0)
        result = strcmp(item->physical_leaf, physical_leaf);
    return result;
}

int portable_physical_owners_find(const PortablePhysicalOwners *owners,
                                  const char *root_id,
                                  const char *logical_parent,
                                  const char *physical_leaf,
                                  const PortablePhysicalOwner **out)
{
    if (out != NULL)
        *out = NULL;
    if (owners == NULL || !owners->sorted || root_id == NULL ||
        logical_parent == NULL || physical_leaf == NULL || out == NULL)
        return -1;

    size_t low = 0;
    size_t high = owners->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        int result = portable_owner_key_compare(&owners->items[middle],
                                                root_id, logical_parent,
                                                physical_leaf);
        if (result < 0)
            low = middle + 1U;
        else
            high = middle;
    }
    if (low == owners->count ||
        portable_owner_key_compare(&owners->items[low], root_id,
                                   logical_parent, physical_leaf) != 0)
        return 0;
    if (low + 1U < owners->count &&
        portable_owner_key_compare(&owners->items[low + 1U], root_id,
                                   logical_parent, physical_leaf) == 0)
        return -1;
    *out = &owners->items[low];
    return 1;
}

int portable_capture_owners_reload(PortableCaptureContext *context)
{
    if (context == NULL || context->sidecar == NULL ||
        context->active_owners == NULL || context->tombstone_owners == NULL)
        return -1;
    PortablePhysicalOwners *active = context->active_owners;
    PortablePhysicalOwners *tombstones = context->tombstone_owners;
    return portable_active_owners_load(active, context->sidecar) == 0 &&
                   portable_tombstone_owners_load(tombstones,
                                                  context->sidecar) == 0
               ? 0
               : -1;
}

// Both callers capture logical, at most SIDECAR_MAX_PATH long.
static void logical_parent_copy(char out[SIDECAR_MAX_PATH + 1U],
                                const char *logical)
{
    const char *slash = strrchr(logical, '/');
    size_t length = slash == NULL ? 0U : (size_t)(slash - logical);
    if (length != 0)
        memcpy(out, logical, length);
    out[length] = '\0';
}

int portable_assignment_for(
    const PortableCollisionPlan *plan, const PortableCurrentSourceSet *source,
    const char *root_id, const char *logical,
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U],
    char collision_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U])
{
    if (plan == NULL || source == NULL || root_id == NULL ||
        logical == NULL || physical_leaf == NULL || collision_suffix == NULL)
        return -1;
    physical_leaf[0] = '\0';
    collision_suffix[0] = '\0';

    int present = portable_current_source_contains(source, root_id, logical);
    if (present != 1)
        return -1;
    if (logical[0] == '\0')
        return 0;

    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(plan, root_id, logical);
    if (planned != NULL) {
        if (!safe_component(planned->physical_leaf) ||
            copy_text(physical_leaf, SIDECAR_MAX_PHYSICAL_LEAF + 1U,
                      planned->physical_leaf) != 0 ||
            copy_text(collision_suffix,
                      SIDECAR_MAX_COLLISION_SUFFIX + 1U,
                      planned->collision_suffix) != 0)
            return -1;
        return 0;
    }

    const char *raw_component = strrchr(logical, '/');
    raw_component = raw_component == NULL ? logical : raw_component + 1U;
    PortablePhysicalName mapped;
    if (portable_physical_name_map(raw_component, 0, &mapped) != 0 ||
        mapped.shortened || mapped.collision_suffix[0] != '\0' ||
        !safe_component(mapped.physical_leaf) ||
        copy_text(physical_leaf, SIDECAR_MAX_PHYSICAL_LEAF + 1U,
                  mapped.physical_leaf) != 0)
        return -1;
    return 0;
}

int portable_current_assignment(
    const PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical,
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U],
    char collision_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U])
{
    if (context == NULL || root == NULL)
        return -1;
    return portable_assignment_for(context->collision_plan,
                                   context->current_source, root->id, logical,
                                   physical_leaf, collision_suffix);
}

// Copies a recorded physical leaf, which names the root itself only for
// the empty logical path; the journal holds no other kind (sidecar.c,
// sidecar_physical_leaf_valid()).
static void recorded_leaf_copy(SidecarBytes leaf,
                               char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U])
{
    if (leaf.length != 0)
        memcpy(physical_leaf, leaf.data, leaf.length);
    physical_leaf[leaf.length] = '\0';
}

static int recorded_state_copy(
    PortableCaptureContext *context, const char *root_id,
    const char *logical, int allow_tombstone,
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U],
    SidecarObjectKind *kind_out, PortableOwnerState *state_out)
{
    SidecarBytes root_key = {
        (const unsigned char *)root_id, strlen(root_id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView live = {0};
    SidecarClaimView claim = {0};
    int live_found = sidecar_log_find(context->sidecar, root_key,
                                      logical_key, &live);
    int claim_found = sidecar_log_find_claim(context->sidecar, root_key,
                                             logical_key, &claim);
    if (live_found < 0 || claim_found < 0 ||
        (live_found == 1 && claim_found == 1))
        return -1;

    SidecarBytes leaf = {0};
    if (live_found == 1) {
        leaf = live.entry->physical_leaf;
        *kind_out = live.entry->kind;
        *state_out = PORTABLE_OWNER_LIVE;
    } else if (claim_found == 1) {
        leaf = claim.claim->physical_leaf;
        *kind_out = claim.claim->kind;
        *state_out = PORTABLE_OWNER_CLAIM;
    } else if (allow_tombstone) {
        SidecarLiveView deleted = {0};
        int deleted_found = sidecar_log_find_deleted(
            context->sidecar, root_key, logical_key, &deleted);
        if (deleted_found != 1)
            return -1;
        leaf = deleted.entry->physical_leaf;
        *kind_out = deleted.entry->kind;
        *state_out = PORTABLE_OWNER_TOMBSTONE;
    } else {
        return -1;
    }
    recorded_leaf_copy(leaf, physical_leaf);
    return 0;
}

// The physical leaf of the folder logical names, for a path below it. A
// deleted item's folder may have been deleted with it, or replaced by an
// item of another kind: until that item's entry commits, which consumes the
// folder's tombstone, the tombstone still names where the folder is (D25).
// Sets *deleted when the folder is known only by its tombstone; fails with
// ENOENT when it is gone.
static int recorded_folder_copy(
    PortableCaptureContext *context, const char *root_id,
    const char *logical, int allow_tombstone,
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U], int *deleted)
{
    SidecarObjectKind kind;
    PortableOwnerState state;
    if (recorded_state_copy(context, root_id, logical, allow_tombstone,
                            physical_leaf, &kind, &state) != 0) {
        errno = EINVAL;
        return -1;
    }
    *deleted = state == PORTABLE_OWNER_TOMBSTONE;
    if (kind == SIDECAR_KIND_DIRECTORY)
        return 0;
    if (!allow_tombstone) {
        errno = EINVAL;
        return -1;
    }

    SidecarBytes root_key = {
        (const unsigned char *)root_id, strlen(root_id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView folder = {0};
    int found = *deleted ? 0
                         : sidecar_log_find_deleted(context->sidecar, root_key,
                                                    logical_key, &folder);
    if (found < 0) {
        errno = EINVAL;
        return -1;
    }
    if (found == 0 || folder.entry->kind != SIDECAR_KIND_DIRECTORY) {
        errno = ENOENT;
        return -1;
    }
    recorded_leaf_copy(folder.entry->physical_leaf, physical_leaf);
    *deleted = 1;
    return 0;
}

int portable_recorded_parent_open(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, int allow_tombstone, int *parent_out,
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U],
    SidecarObjectKind *kind_out, PortableOwnerState *state_out)
{
    if (context == NULL || root == NULL || logical == NULL ||
        parent_out == NULL || leaf == NULL || kind_out == NULL ||
        state_out == NULL)
        return -1;
    *parent_out = -1;
    leaf[0] = '\0';

    char target_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    if (recorded_state_copy(context, root->id, logical, allow_tombstone,
                            target_leaf, kind_out, state_out) != 0) {
        errno = EINVAL;
        return -1;
    }

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(context->data_fd, root->payload_path,
                                     &root_parent, root_leaf,
                                     sizeof(root_leaf)) != 0)
        return -1;
    if (logical[0] == '\0') {
        memcpy(leaf, root_leaf, strlen(root_leaf) + 1U);
        *parent_out = root_parent;
        return 0;
    }

    int current_fd = open_child_directory(root_parent, root_leaf);
    int saved = errno;
    if (close(root_parent) != 0 && current_fd >= 0) {
        close(current_fd);
        return -1;
    }
    if (current_fd < 0) {
        errno = saved;
        return -1;
    }

    const char *last_slash = strrchr(logical, '/');
    if (last_slash != NULL) {
        size_t parent_length = (size_t)(last_slash - logical);
        size_t prefix_end = 0;
        while (prefix_end < parent_length) {
            while (prefix_end < parent_length && logical[prefix_end] != '/')
                prefix_end++;
            // A recorded logical path is a journal key, at most
            // SIDECAR_MAX_PATH long.
            char prefix[SIDECAR_MAX_PATH + 1U];
            memcpy(prefix, logical, prefix_end);
            prefix[prefix_end] = '\0';

            char ancestor_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
            int deleted = 0;
            if (recorded_folder_copy(context, root->id, prefix,
                                     allow_tombstone, ancestor_leaf,
                                     &deleted) != 0) {
                saved = errno;
                close(current_fd);
                errno = saved;
                return -1;
            }
            int child_fd = open_child_directory(current_fd, ancestor_leaf);
            saved = errno;
            // A deleted folder's place may hold what replaced it.
            if (child_fd < 0 && deleted && saved == ENOTDIR)
                saved = ENOENT;
            if (close(current_fd) != 0 && child_fd >= 0) {
                close(child_fd);
                return -1;
            }
            if (child_fd < 0) {
                errno = saved;
                return -1;
            }
            current_fd = child_fd;
            if (prefix_end < parent_length)
                prefix_end++;
        }
    }

    memcpy(leaf, target_leaf, strlen(target_leaf) + 1U);
    *parent_out = current_fd;
    return 0;
}

static int owner_parent_matches(const PortablePhysicalOwner *owner,
                                const char *root_id,
                                const char *logical_parent)
{
    return strcmp(owner->root_id, root_id) == 0 &&
           strcmp(owner->logical_parent, logical_parent) == 0;
}

int portable_physical_owner_for_node(
    const PortableCaptureContext *context,
    const PortablePhysicalOwners *owners, const char *root_id,
    const char *logical_parent, int parent_fd, const char *requested_leaf,
    const struct stat *requested_stat, const PortablePhysicalOwner **out)
{
    if (out != NULL)
        *out = NULL;
    if (context == NULL || owners == NULL || root_id == NULL ||
        logical_parent == NULL || parent_fd < 0 ||
        !safe_component(requested_leaf) || requested_stat == NULL ||
        out == NULL)
        return -1;

    const PortablePhysicalOwner *exact = NULL;
    int found = portable_physical_owners_find(
        owners, root_id, logical_parent, requested_leaf, &exact);
    if (found < 0)
        return found;
    if (found == 1) {
        *out = exact;
        return 1;
    }
    if (context->case_sensitive)
        return 0;

    size_t low = 0;
    size_t high = owners->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        PortablePhysicalOwner *candidate = &owners->items[middle];
        int result = strcmp(candidate->root_id, root_id);
        if (result == 0)
            result = strcmp(candidate->logical_parent, logical_parent);
        if (result < 0)
            low = middle + 1U;
        else
            high = middle;
    }

    const PortablePhysicalOwner *identity_owner = NULL;
    for (size_t index = low; index < owners->count; index++) {
        const PortablePhysicalOwner *candidate = &owners->items[index];
        if (!owner_parent_matches(candidate, root_id, logical_parent))
            break;
        struct stat candidate_stat;
        if (fstatat(parent_fd, candidate->physical_leaf, &candidate_stat,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT)
                continue;
            return -1;
        }
        if (candidate_stat.st_dev != requested_stat->st_dev ||
            candidate_stat.st_ino != requested_stat->st_ino)
            continue;
        if (identity_owner != NULL &&
            strcmp(identity_owner->logical_path,
                   candidate->logical_path) != 0)
            return -1;
        identity_owner = candidate;
    }
    if (identity_owner == NULL)
        return 0;
    *out = identity_owner;
    return 1;
}

// With allow_tombstone, logical and its folders may be deleted items, whose
// recorded leaves give the address they had.
static int portable_recorded_address_matches_current_internal(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, int allow_tombstone)
{
    if (context == NULL || root == NULL || logical == NULL)
        return -1;
    if (logical[0] == '\0')
        return portable_current_source_contains(context->current_source,
                                                root->id, logical) == 1
                   ? 1
                   : -1;

    char prefix[SIDECAR_MAX_PATH + 1U];
    size_t logical_length = strlen(logical);
    size_t end = 0;
    while (end < logical_length) {
        while (end < logical_length && logical[end] != '/')
            end++;
        if (end >= sizeof(prefix))
            return -1;
        memcpy(prefix, logical, end);
        prefix[end] = '\0';

        char old_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
        char current_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
        char current_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
        SidecarObjectKind old_kind;
        PortableOwnerState old_state;
        if (recorded_state_copy(context, root->id, prefix, allow_tombstone,
                                old_leaf, &old_kind, &old_state) != 0 ||
            portable_current_assignment(context, root, prefix, current_leaf,
                                        current_suffix) != 0)
            return -1;
        if (strcmp(old_leaf, current_leaf) != 0)
            return 0;
        if (end < logical_length)
            end++;
    }
    return 1;
}

int portable_recorded_address_matches_current(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical)
{
    return portable_recorded_address_matches_current_internal(
        context, root, logical, 0);
}

int portable_tombstoned_address_matches_current(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical)
{
    return portable_recorded_address_matches_current_internal(
        context, root, logical, 1);
}

// Returns 0 when the node at leaf in parent_fd may be replaced by logical's
// capture: there is none, or logical owns it, live, claimed, or deleted.
// Returns 1 when no record or claim owns it and -1 when another item does, or
// on an error.
static int capture_destination_is_safe(const PortableCaptureContext *context,
                                       const PortableRootSpec *root,
                                       const char *logical,
                                       int parent_fd, const char *leaf)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    if (logical[0] == '\0') {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView live = {0};
        SidecarClaimView claim = {0};
        int live_found = sidecar_log_find(context->sidecar, root_key,
                                          logical_key, &live);
        int claim_found = sidecar_log_find_claim(context->sidecar, root_key,
                                                 logical_key, &claim);
        if (live_found < 0 || claim_found < 0 ||
            (live_found == 1 && claim_found == 1))
            return -1;
        if (live_found == 1 || claim_found == 1)
            return 0;
        SidecarLiveView deleted = {0};
        int deleted_found = sidecar_log_find_deleted(
            context->sidecar, root_key, logical_key, &deleted);
        return deleted_found < 0 ? -1 : !deleted_found;
    }

    char logical_parent[SIDECAR_MAX_PATH + 1U];
    logical_parent_copy(logical_parent, logical);
    const PortablePhysicalOwner *owner = NULL;
    int owner_found = portable_physical_owner_for_node(
        context, context->active_owners, root->id, logical_parent, parent_fd,
        leaf, &st, &owner);
    if (owner_found < 0)
        return -1;
    if (owner_found == 1)
        return strcmp(owner->logical_path, logical) == 0 ? 0 : -1;

    owner_found = portable_physical_owner_for_node(
        context, context->tombstone_owners, root->id, logical_parent,
        parent_fd, leaf, &st, &owner);
    if (owner_found < 0)
        return -1;
    if (owner_found == 1)
        return strcmp(owner->logical_path, logical) == 0 ? 0 : -1;
    return 1;
}

/* During resume, an interrupted claim is also ownership proof for the
 * payload that was created after the claim and before its ENTRY_COMMIT.
 * Keep the existing owned-path and tombstone checks intact.  A same-key,
 * same-physical claim remains ownership proof even when the source kind has
 * changed; append_capture_claim() then reconciles that old kind before
 * publishing the replacement claim. */
static int capture_destination_is_safe_or_claimed(
    const PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, int parent_fd, const char *leaf)
{
    return capture_destination_is_safe(context, root, logical, parent_fd,
                                       leaf);
}

/* A live view borrows sidecar storage and remains valid only until the next
 * log mutation or close. */
typedef struct {
    int resolved;
    int live;
    SidecarLiveView view;
} CapturePreviousEntry;

static int replace_live_capture(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical,
                                const CapturePreviousEntry *previous_hint)
{

    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView previous;
    int live;
    if (previous_hint != NULL && previous_hint->resolved) {
        live = previous_hint->live;
        if (live == 1)
            previous = previous_hint->view;
    } else {
        live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                &previous);
    }
    if (live < 0)
        return -1;
    if (!live)
        return 0;

    // The record is at its current address: prepare_collision_relocations()
    // deleted every live record whose address changed before the capture.
    SidecarDelete deletion = {
        .root_id = root_key,
        .logical_path = logical_key
    };
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE);
    if (sidecar_log_append_delete(context->sidecar, &deletion) !=
        SIDECAR_STATUS_OK)
        return -1;
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_REPLACEMENT_DELETE);
    return 0;
}

static int tombstone_destination_children(PortableCaptureContext *context,
                                          const PortableRootSpec *root,
                                          const char *logical,
                                          int parent_fd,
                                          const char *leaf)
{
    return reconcile_destination_children(context, root, logical, parent_fd,
                                          leaf);
}

static int append_group(PortableCaptureContext *context,
                        const SidecarEntry *entry,
                        const PortableXattrs *xattrs)
{
    SidecarStatus status = sidecar_log_append_group(
        context->sidecar, entry, xattrs != NULL ? xattrs->items : NULL);
    return status == SIDECAR_STATUS_OK ? 0 : -1;
}

static int append_capture_claim(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical,
                                const char *physical_leaf,
                                SidecarObjectKind kind)
{
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)root->id, strlen(root->id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) },
        .physical_leaf = {
            (const unsigned char *)physical_leaf, strlen(physical_leaf) },
        .kind = kind
    };
    SidecarClaimView existing = {0};
    int found = sidecar_log_find_claim(context->sidecar, claim.root_id,
                                       claim.logical_path, &existing);
    if (found < 0)
        return -1;
    if (found == 1) {
        if (existing.claim != NULL &&
            sidecar_bytes_equal(existing.claim->root_id, claim.root_id) &&
            sidecar_bytes_equal(existing.claim->logical_path,
                                claim.logical_path) &&
            sidecar_bytes_equal(existing.claim->physical_leaf,
                                claim.physical_leaf) &&
            existing.claim->kind == claim.kind)
            return 0;
        if (reconcile_stale_claim(context, root, logical, existing.claim) != 0)
            return -1;
    }
    return sidecar_log_append_claim(context->sidecar, &claim) ==
                   SIDECAR_STATUS_OK
               ? 0
               : -1;
}

int read_source_stat(int source_parent, const char *source_name,
                            const char *root_path, struct stat *out)
{
    if (out == NULL)
        return -1;
    if (source_parent >= 0)
        return fstatat(source_parent, source_name, out, AT_SYMLINK_NOFOLLOW);
    return lstat(root_path, out);
}

static int source_symlink_target(int source_parent, const char *source_name,
                                 const char *root_path, char *target,
                                 size_t target_size)
{
    ssize_t length;
    if (source_parent >= 0)
        length = readlinkat(source_parent, source_name, target, target_size);
    else
        length = readlink(root_path, target, target_size);
    if (length < 0)
        return -1;
    if (length == 0 || (size_t)length >= target_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    target[length] = '\0';
    return (int)length;
}

/* Symlinks have no fd of their own for llistxattr/lgetxattr; Linux provides no
 * *at()-style no-follow xattr syscall (docs/DECISIONS.md D18 C-8). This is the
 * one place that must re-derive /proc/self/fd/<parent>/<name> instead of using
 * the fd-relative (source_parent, source_name) addressing every other source
 * operation uses. If how those arguments are formed ever changes, this
 * reconstruction must change with it; nothing enforces that at compile time. */
static int source_symlink_xattr_path(int source_parent,
                                     const char *source_name,
                                     const char *root_path, char *path,
                                     size_t path_size)
{
    if (source_parent < 0)
        return copy_text(path, path_size, root_path);
    int length = snprintf(path, path_size, "/proc/self/fd/%d/%s",
                          source_parent, source_name);
    return length < 0 || (size_t)length >= path_size ? -1 : 0;
}

int open_source_node(int source_parent, const char *source_name,
                            const char *root_path, const struct stat *st)
{
    int flags = O_RDONLY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC;
    if (S_ISDIR(st->st_mode))
        flags |= O_DIRECTORY;
    if (source_parent >= 0)
        return openat(source_parent, source_name, flags);
    return open(root_path, flags);
}

// expected_size < 0 accepts whatever length the source has when read and
// reports it through copied_out; otherwise a different length is EIO.
// *read_failed, when given, is set when reading the source failed.
static int portable_copy_regular_impl(
    int source_fd, int destination_fd, off_t expected_size,
    BackupCaptureReport *report, uint64_t *digest, uint64_t *copied_out,
    int *read_failed)
{
    if (source_fd < 0 || destination_fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (ftruncate(destination_fd, 0) != 0 ||
        lseek(destination_fd, 0, SEEK_SET) != 0)
        return -1;

    unsigned char buffer[65536];
    uint64_t copied = 0;
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    for (;;) {
        ssize_t received = read(source_fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0) {
            if (read_failed != NULL)
                *read_failed = 1;
            return -1;
        }
        if (received == 0)
            break;

        if (write_all(destination_fd, buffer, (size_t)received) != 0)
            return -1;
        copied += (uint64_t)received;
        if (digest != NULL)
            hash = hash_fnv1a_bytes(hash, buffer, (size_t)received);
        if (backup_capture_report_tick(report, received, destination_fd) != 0)
            return -1;
    }
    if (copied_out == NULL &&
        (expected_size < 0 || copied != (uint64_t)expected_size))
    {
        errno = EIO;
        return -1;
    }
    if (copied_out != NULL)
        *copied_out = copied;
    if (digest != NULL)
        *digest = hash;
    return 0;
}

int portable_copy_regular(int source_fd, int destination_fd, off_t expected_size,
                          BackupCaptureReport *report)
{
    return portable_copy_regular_impl(source_fd, destination_fd, expected_size,
                                      report, NULL, NULL, NULL);
}

int portable_copy_regular_digest(
    int source_fd, int destination_fd, off_t expected_size,
    BackupCaptureReport *report, uint64_t *digest)
{
    if (digest == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    return portable_copy_regular_impl(source_fd, destination_fd, expected_size,
                                      report, digest, NULL, NULL);
}

// Reads a source that may be changing: rewinds it, copies whatever it holds
// now, and reports the length copied (D63).
static int portable_copy_regular_as_is(int source_fd, int destination_fd,
                                       BackupCaptureReport *report,
                                       uint64_t *digest, uint64_t *copied,
                                       int *read_failed)
{
    if (lseek(source_fd, 0, SEEK_SET) != 0) {
        *read_failed = 1;
        return -1;
    }
    return portable_copy_regular_impl(source_fd, destination_fd, -1, report,
                                      digest, copied, read_failed);
}


typedef struct {
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
    char collision_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    char unsuffixed_candidate[SIDECAR_MAX_PHYSICAL_LEAF + 1U];
} PortableCaptureAssignment;

static int capture_assignment_resolve(
    const PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, const char *raw_component,
    PortableCaptureAssignment *out)
{
    memset(out, 0, sizeof(*out));

    // Each name below has a buffer of the same size as out's.
    PortablePhysicalName unsuffixed;
    if (portable_physical_name_map(raw_component, 0, &unsuffixed) != 0)
        return -1;
    strcpy(out->unsuffixed_candidate, unsuffixed.physical_leaf);

    // The pre-scan planned the name from a name it mapped the same way.
    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(context->collision_plan, root->id,
                                     logical);
    if (planned != NULL) {
        strcpy(out->physical_leaf, planned->physical_leaf);
        strcpy(out->collision_suffix, planned->collision_suffix);
        return 0;
    }

    if (unsuffixed.shortened || unsuffixed.collision_suffix[0] != '\0')
        return -1;
    strcpy(out->physical_leaf, unsuffixed.physical_leaf);
    return 0;
}

static void portable_capture_failure_reset(BackupCaptureReport *report)
{
    if (report == NULL)
        return;
    report->failed_source_path[0] = '\0';
    report->failure_kind = BACKUP_CAPTURE_FAILURE_NONE;
    report->failure_errno = 0;
    report->failed_operation = NULL;
}

// Keeps the first failure: the item, as a source path (the root's own when
// logical is empty or NULL, none without a root), what was being done, and
// errno for an operational one or an item that could not be read. A failure
// of the backup replaces an item failure not listed yet (D109).
static void portable_capture_failure_record(
    BackupCaptureReport *report, BackupCaptureFailureKind kind, int err,
    const char *operation, const PortableRootSpec *root, const char *logical)
{
    if (report == NULL || kind == BACKUP_CAPTURE_FAILURE_NONE ||
        (report->failure_kind != BACKUP_CAPTURE_FAILURE_NONE &&
         (kind == BACKUP_CAPTURE_FAILURE_ITEM ||
          report->failure_kind != BACKUP_CAPTURE_FAILURE_ITEM)))
        return;

    report->failure_kind = kind;
    report->failure_errno = kind == BACKUP_CAPTURE_FAILURE_OPERATIONAL
        ? (err != 0 ? err : EIO)
        : kind == BACKUP_CAPTURE_FAILURE_ITEM ? err : 0;
    report->failed_operation = operation;

    report->failed_source_path[0] = '\0';
    // A path too long to hold is named by its root alone.
    if (root != NULL && root->capture_path != NULL &&
        (logical == NULL || logical[0] == '\0' ||
         path_join(report->failed_source_path,
                   sizeof(report->failed_source_path), root->capture_path,
                   logical) != 0))
        (void)snprintf(report->failed_source_path,
                       sizeof(report->failed_source_path), "%s",
                       root->capture_path);
}

static void portable_capture_context_failure_record(
    const PortableCaptureContext *context, BackupCaptureFailureKind kind,
    int err, const char *operation, const PortableRootSpec *root,
    const char *logical)
{
    if (context == NULL)
        return;
    portable_capture_failure_record(
        context->progress_report, kind, err, operation, root, logical);
}

// A step that stops on the journal names the error that stopped it, as a
// failed write to the backup does; the capture's own refusals carry none.
static void journal_failure_record(const PortableCaptureContext *context,
                                   const char *operation,
                                   const PortableRootSpec *root,
                                   const char *logical)
{
    int err = sidecar_log_failure_errno(context->sidecar);
    portable_capture_context_failure_record(
        context, err != 0 ? BACKUP_CAPTURE_FAILURE_OPERATIONAL
                          : BACKUP_CAPTURE_FAILURE_INTERNAL,
        err, operation, root, logical);
}

// A source that changes under a running backup is expected, not an error
// (D63): the entry is kept as read or left out, and the change is reported.
// Confirmed live desktop state (D55) changes constantly and is only counted.
// BACKUP_SOURCE_CHANGE_KINDS is not reported: used where a planned member is
// skipped, since the membership check after the root reports every planned
// member that was not captured as vanished, once.
static void capture_note_change(const PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical,
                                BackupSourceChangeKind kind)
{
    BackupCaptureReport *report = context->progress_report;
    if (live_state_path(root->id, strlen(root->id), logical, strlen(logical)))
    {
        if (report != NULL && report->live_state_changes != SIZE_MAX)
            report->live_state_changes++;
        return;
    }
    if (kind == BACKUP_SOURCE_CHANGE_KINDS)
        return;
    const char *base = root->source_path != NULL && root->source_path[0] == '/'
        ? root->source_path : root->capture_path;
    char location[PATH_MAX];
    if (logical[0] == '\0')
        snprintf(location, sizeof(location), "%s", base != NULL ? base : "");
    else
        snprintf(location, sizeof(location), "%s/%s",
                 base != NULL ? base : "", logical);
    backup_capture_report_note_change(report, kind, location);
}

// An entry that vanished, appeared after the pre-scan, or was replaced
// before it could be opened is left out of this backup.
static int capture_leave_out(const PortableCaptureContext *context,
                             const PortableRootSpec *root,
                             const char *logical, BackupSourceChangeKind kind,
                             int *no_destination_object)
{
    capture_note_change(context, root, logical, kind);
    if (no_destination_object != NULL)
        *no_destination_object = 1;
    return 0;
}

// An item the source would not give up (D109): listed, and the backup keeps
// what it holds for it, with everything below it.
static int capture_item_failed(PortableCaptureContext *context,
                               const PortableRootSpec *root,
                               const char *logical, const char *operation,
                               int err, int *no_destination_object)
{
    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView held;
    int kept = sidecar_log_find(context->sidecar, root_key, logical_key,
                                &held);
    if (kept < 0 || visited_add(context->failed, root->id, logical) < 0) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "record it as not backed up", root, logical);
        return -1;
    }
    portable_capture_context_failure_record(
        context, BACKUP_CAPTURE_FAILURE_ITEM, err, operation, root, logical);
    backup_capture_report_note_failure(context->progress_report, kept);
    if (no_destination_object != NULL)
        *no_destination_object = 1;
    return 0;
}

// What the pre-scan could not read is kept as the backup holds it from the
// start, before an update moves or removes anything (D109).
static int capture_failed_seed(PortableCaptureContext *context,
                               const PortableCurrentSourceSet *unreadable)
{
    for (size_t index = 0; index < unreadable->count; index++)
        if (visited_add(context->failed, unreadable->entries[index].root_id,
                        unreadable->entries[index].logical_path) < 0)
            return -1;
    return 0;
}

int portable_failed_covers(const PortableCaptureContext *context,
                           const char *root_id, const char *logical)
{
    const PortableVisited *failed = context->failed;
    if (failed == NULL || failed->count == 0)
        return 0;
    // Every caller passes a journal key or a scanned path, both at most
    // SIDECAR_MAX_PATH long.
    char path[SIDECAR_MAX_PATH + 1U];
    memcpy(path, logical, strlen(logical) + 1U);
    for (;;) {
        int found = visited_contains(failed, root_id, path);
        if (found != 0 || path[0] == '\0')
            return found;
        char *slash = strrchr(path, '/');
        *(slash != NULL ? slash : path) = '\0';
    }
}

static int capture_current_source_seen(const PortableCaptureContext *context,
                                       const PortableRootSpec *root)
{
    const PortableCurrentSourceSet *set = context->current_source;
    for (size_t index = 0; index < set->count; index++) {
        const PortableCurrentSourceEntry *entry = &set->entries[index];
        if (strcmp(entry->root_id, root->id) != 0)
            continue;
        int present = visited_contains(context->visited, root->id,
                                       entry->logical_path);
        if (present == 0)
            present = portable_failed_covers(context, root->id,
                                             entry->logical_path);
        if (present == 0) {
            capture_note_change(context, root, entry->logical_path,
                                BACKUP_SOURCE_VANISHED);
            continue;
        }
        if (present != 1) {
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "look it up among the items the source was scanned with", root,
                entry->logical_path);
            return -1;
        }
    }
    return 0;
}

static int source_kind_is_address_bearing(mode_t mode)
{
    return S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode);
}

static BackupCaptureFailureKind source_lookup_failure_kind(int err)
{
    return err == ENOENT || err == ENOTDIR || err == ELOOP
        ? BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED
        : BACKUP_CAPTURE_FAILURE_OPERATIONAL;
}

// logical is a path the pre-scan listed: relative, at most SIDECAR_MAX_PATH
// long, made of names a folder held.
static int prepared_source_member_stat(int root_fd, const char *logical,
                                       struct stat *out)
{
    size_t length = strlen(logical);
    char copy[SIDECAR_MAX_PATH + 1U];
    memcpy(copy, logical, length + 1U);

    int current = dup_cloexec(root_fd);
    if (current < 0)
        return -1;
    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash == NULL)
            break;
        *slash = '\0';
        int next = open_child_directory(current, cursor);
        int saved = errno;
        if (close(current) != 0 && next >= 0) {
            close(next);
            errno = EIO;
            return -1;
        }
        if (next < 0) {
            errno = saved;
            return -1;
        }
        current = next;
        cursor = slash + 1U;
    }

    int result = fstatat(current, cursor, out, AT_SYMLINK_NOFOLLOW);
    int saved = errno;
    if (close(current) != 0 && result == 0) {
        errno = EIO;
        return -1;
    }
    errno = saved;
    return result;
}

static int prepared_source_validate_root(
    PortableCaptureContext *context, const PortableRootSpec *root)
{
    int root_member = portable_current_source_contains(
        context->current_source, root->id, "");

    // What cannot be read is left to capture, which lists it (D109).
    struct stat root_stat;
    if (lstat(root->capture_path, &root_stat) != 0) {
        int saved_errno = errno;
        if (source_lookup_failure_kind(saved_errno) ==
            BACKUP_CAPTURE_FAILURE_OPERATIONAL)
            return 0;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED, saved_errno,
            "inspect it", root, NULL);
        return -1;
    }
    int root_address_bearing = source_kind_is_address_bearing(root_stat.st_mode);
    if ((root_address_bearing && root_member != 1) ||
        (!root_address_bearing && root_member == 1)) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED, 0,
            "it changed kind since the source was scanned", root, NULL);
        return -1;
    }

    int root_fd = -1;
    if (S_ISDIR(root_stat.st_mode)) {
        root_fd = open(root->capture_path,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root_fd < 0) {
            int saved_errno = errno;
            if (source_lookup_failure_kind(saved_errno) ==
                BACKUP_CAPTURE_FAILURE_OPERATIONAL)
                return 0;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED, saved_errno,
                "open the folder", root, NULL);
            return -1;
        }
    }

    int failed = 0;
    for (size_t index = 0; index < context->current_source->count; index++) {
        const PortableCurrentSourceEntry *entry =
            &context->current_source->entries[index];
        if (strcmp(entry->root_id, root->id) != 0 ||
            entry->logical_path[0] == '\0')
            continue;
        struct stat member_stat;
        if (root_fd < 0) {
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED, 0,
                "it changed since the source was scanned", root,
                entry->logical_path);
            failed = 1;
            break;
        }
        if (prepared_source_member_stat(root_fd, entry->logical_path,
                                        &member_stat) != 0) {
            int saved_errno = errno;
            if (source_lookup_failure_kind(saved_errno) ==
                BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED)
                capture_note_change(context, root, entry->logical_path,
                                    BACKUP_SOURCE_CHANGE_KINDS);
            continue;
        }
        if (!source_kind_is_address_bearing(member_stat.st_mode))
            capture_note_change(context, root, entry->logical_path,
                                BACKUP_SOURCE_CHANGE_KINDS);
    }
    if (root_fd >= 0 && close(root_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close the folder", root, NULL);
        failed = 1;
    }
    return failed ? -1 : 0;
}

static int capture_node(PortableCaptureContext *context,
                        const PortableRootSpec *root,
                        const char *logical, const char *physical_leaf,
                        const char *collision_suffix,
                        int source_parent,
                        const char *source_name, const char *root_path,
                        int destination_parent, const char *destination_leaf,
                        int *no_destination_object);

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
/* Forces capture_directory()'s fdopendir() to fail with a genuine EBADF, by
 * closing its scan_fd one call early -- self-clearing so a test only needs
 * to arm, not disarm. */
static int capture_directory_test_close_scan_fd_early;

void portable_test_close_capture_directory_scan_fd_early(void)
{
    capture_directory_test_close_scan_fd_early = 1;
}
#endif

static int capture_directory(PortableCaptureContext *context,
                             const PortableRootSpec *root,
                             const char *logical, const char *physical_leaf,
                             int source_fd,
                             const struct stat *before, int destination_fd,
                             PortableXattrs *xattrs,
                             const char *collision_suffix)
{
    PendingReadbackNames pending = {0};
    int scan_fd = dup_cloexec(source_fd);
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
    if (scan_fd >= 0 && capture_directory_test_close_scan_fd_early) {
        capture_directory_test_close_scan_fd_early = 0;
        close(scan_fd);
    }
#endif
    // A folder that cannot be listed to its end is an item that failed
    // (D109): it is recorded as read, and the backup keeps what it held below.
    int listing_errno = 0;
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        listing_errno = errno;
        if (scan_fd >= 0)
            close(scan_fd);
    }
    int failed = 0;
    PortableCaseFoldSet observed_skeletons = {0};
    PortableCaseFoldSet observed_ascii = {0};
    if (!context->case_sensitive)
        observed_skeletons.hash_salt = sidecar_process_salt();
    if (!context->case_sensitive)
        observed_ascii.hash_salt = sidecar_process_salt();
    while (directory != NULL) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            listing_errno = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0) {
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED, 0,
                "its path is longer than the journal can record", root,
                logical);
            failed = 1;
            break;
        }
        if (root->selection != NULL) {
            int owned = selection_root_owns(root->selection, child_logical);
            if (owned < 0) {
                portable_capture_context_failure_record(
                    context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                    "match it against the selection", root, child_logical);
                failed = 1;
                break;
            }
            if (owned == 0)
                continue;
        }

        PortableCaptureAssignment assignment;
        if (capture_assignment_resolve(context, root, child_logical,
                                       entry->d_name, &assignment) != 0) {
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "choose its name in the backup", root, child_logical);
            failed = 1;
            break;
        }

        if (!context->case_sensitive) {
            char skeleton[NAME_MAX + 1U];
            char ascii_skeleton[NAME_MAX + 1U];
            skeleton_copy(skeleton, sizeof(skeleton),
                          assignment.unsuffixed_candidate);
            ascii_fold_copy(ascii_skeleton, sizeof(ascii_skeleton),
                            assignment.unsuffixed_candidate);
            char *existing_logical = NULL;
            int duplicate = case_fold_set_find_or_insert(
                &observed_skeletons, skeleton, child_logical,
                &existing_logical);
            char *existing_ascii_logical = NULL;
            int ascii_duplicate = case_fold_set_find_or_insert(
                &observed_ascii, ascii_skeleton, child_logical,
                &existing_ascii_logical);
            const PortableCollisionPlanEntry *current_plan =
                portable_collision_plan_find(context->collision_plan,
                                              root->id, child_logical);
            const PortableCollisionPlanEntry *existing_plan =
                duplicate == 1
                    ? portable_collision_plan_find(context->collision_plan,
                                                   root->id, existing_logical)
                    : NULL;
            const PortableCollisionPlanEntry *existing_ascii_plan =
                ascii_duplicate == 1
                    ? portable_collision_plan_find(
                          context->collision_plan, root->id,
                          existing_ascii_logical)
                    : NULL;
            /* A case-folded sibling group is valid only when the pre-scan
             * planned both members.  ASCII folding is authoritative for the
             * deterministic collision class; the broader skeleton catches a
             * newly added non-ASCII twin only when the pre-scan had planned
             * that candidate group, avoiding false refusals for distinct
             * names that the destination probe kept separate (D21, F-8). */
            if (duplicate < 0 || ascii_duplicate < 0 ||
                (ascii_duplicate == 1 &&
                 (current_plan == NULL || existing_ascii_plan == NULL)) ||
                (duplicate == 1 &&
                 (current_plan != NULL || existing_plan != NULL) &&
                 (current_plan == NULL || existing_plan == NULL))) {
                portable_capture_context_failure_record(
                    context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                    "choose its name in the backup", root, child_logical);
                failed = 1;
                break;
            }
        }

        int added_pending = 0;
        if (encoded_name_has_raw_high_byte(assignment.physical_leaf)) {
            if (pending_readback_names_add(&pending,
                                           assignment.physical_leaf) != 0) {
                portable_capture_context_failure_record(
                    context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                    "note its name for reading back", root, child_logical);
                failed = 1;
                break;
            }
            added_pending = 1;
        }

        int no_destination_object = 0;
        if (capture_node(context, root, child_logical,
                         assignment.physical_leaf,
                         assignment.collision_suffix,
                         source_fd, entry->d_name, NULL, destination_fd,
                         assignment.physical_leaf,
                         &no_destination_object) != 0) {
            failed = 1;
            break;
        }
        if (added_pending && no_destination_object)
            pending_readback_names_remove_last(&pending);
    }
    if (directory != NULL && closedir(directory) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "list the folder", root, logical);
        failed = 1;
    }

    case_fold_set_free(&observed_skeletons);
    case_fold_set_free(&observed_ascii);

    struct stat after;
    if (!failed && fstat(source_fd, &after) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "inspect the folder again after reading", root, logical);
        failed = 1;
    } else if (!failed && !metadata_source_unchanged(before, &after)) {
        capture_note_change(context, root, logical, BACKUP_SOURCE_CHANGED);
    }

    if (!failed && verify_pending_readback_names(destination_fd, &pending) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "read back the names written in the backup", root, logical);
        failed = 1;
    }
    if (close(source_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close the folder", root, logical);
        failed = 1;
    }
    if (failed) {
        pending_readback_names_free(&pending);
        xattrs_free(xattrs);
        close(destination_fd);
        return -1;
    }

    SidecarEntry sidecar_entry;
    if (entry_from_stat(root->id, logical, physical_leaf, collision_suffix,
                        before, xattrs, &sidecar_entry, NULL, NULL,
                        NULL) != 0 ||
        append_group(context, &sidecar_entry, xattrs) != 0) {
        journal_failure_record(
            context, "record the folder in the journal", root, logical);
        pending_readback_names_free(&pending);
        xattrs_free(xattrs);
        close(destination_fd);
        return -1;
    }
    pending_readback_names_free(&pending);
    xattrs_free(xattrs);
    if (close(destination_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close the folder in the backup", root, logical);
        return -1;
    }
    if (listing_errno != 0)
        return capture_item_failed(context, root, logical, "list the folder",
                                   listing_errno, NULL);
    return 0;
}

// Ends the previous entry of a regular file's key and claims its address for
// the new copy (D25).
static int capture_regular_claim(PortableCaptureContext *context,
                                 const PortableRootSpec *root,
                                 const char *logical,
                                 const char *physical_leaf, int parent_fd,
                                 const char *destination_leaf,
                                 const CapturePreviousEntry *previous_hint)
{
    return replace_live_capture(context, root, logical, previous_hint) == 0 &&
                   append_capture_claim(context, root, logical, physical_leaf,
                                        SIDECAR_KIND_REGULAR) == 0 &&
                   tombstone_destination_children(context, root, logical,
                                                  parent_fd,
                                                  destination_leaf) == 0
               ? 0 : -1;
}

// Copies the source into destination_fd and closes destination_fd. A file
// written while it is read is read again, up to BACKUP_CAPTURE_READ_ATTEMPTS
// times; one still changing after that is kept as last read, with that
// read's length, and *changed set (D63). Live desktop state is kept as read
// at once. 0, with *captured as copied; or -1 with *step and *err, errno 0
// when the step says why, and *source_failed set when the source could not
// be read.
static int capture_regular_content(const PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const char *logical, int source_fd,
                                   int destination_fd, struct stat *captured,
                                   uint64_t *digest, int *changed,
                                   const char **step, int *err,
                                   int *source_failed)
{
    uint64_t copied = 0;
    *step = NULL;
    *source_failed = 0;
    for (unsigned int attempt = 1;; attempt++) {
        backup_capture_report_reread(context->progress_report, (off_t)copied);
        copied = 0;
        int source_side = 0;
        struct stat after;
        if (portable_copy_regular_as_is(source_fd, destination_fd,
                                        context->progress_report, digest,
                                        &copied, &source_side) != 0) {
            *step = source_side ? "read the content" : "copy its content";
            *err = errno;
        } else {
            portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_WRITE);
            portable_test_after_payload_write();
            source_side = 1;
            if (fstat(source_fd, &after) != 0) {
                *step = "inspect it again after reading";
                *err = errno;
            }
        }
        // Unchanged metadata with a different length read is not a writer
        // but a read that failed.
        int unchanged = *step == NULL &&
                        metadata_source_unchanged(captured, &after);
        if (unchanged && copied != (uint64_t)after.st_size) {
            *step = "fewer or more bytes were read than its size";
            *err = 0;
        }
        if (*step != NULL) {
            *source_failed = source_side;
            break;
        }
        if (unchanged) {
            *captured = after;
            break;
        }
        if (attempt >= BACKUP_CAPTURE_READ_ATTEMPTS ||
            live_state_path(root->id, strlen(root->id), logical,
                            strlen(logical))) {
            // Recorded with the times from before this read, not the newer
            // ones it may have missed, so the next update reads it again.
            captured->st_size = (off_t)copied;
            *changed = 1;
            break;
        }
        *captured = after;
        backup_capture_reread_pause(attempt);
    }
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE);
    if (close(destination_fd) != 0 && *step == NULL) {
        *step = "finish writing its copy in the backup";
        *err = errno;
        *source_failed = 0;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_CLOSE);
    return *step == NULL ? 0 : -1;
}

static int capture_regular(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical_leaf,
                           const char *collision_suffix,
                           int source_fd,
                           const struct stat *before,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           PortableXattrs *xattrs,
                           const CapturePreviousEntry *previous_hint,
                           int *no_destination_object)
{
    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            int saved_errno = errno;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
                "open its place in the backup", root, logical);
            xattrs_free(xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    int staging_fd = -1;
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, parent_fd, destination_leaf) != 0)
        goto journal_failed;

    // The copy the backup holds stays until the new one is whole: that is
    // written to staging/ with no record, then its key is claimed and the
    // copy renamed over the old one (D110). One with no copy to keep, or no
    // room to stage, is claimed and written in place.
    // Staging is a resume's, where capture_node has looked the key up.
    int staged = context->staging != NULL && previous_hint->live == 1 &&
                 previous_hint->view.entry->kind == SIDECAR_KIND_REGULAR;

    if (context->progress_report != NULL)
        snprintf(context->progress_report->current_path,
                 sizeof(context->progress_report->current_path), "%s",
                 logical[0] == '\0' ? root->capture_path : logical);
    uint64_t content_digest = 0;
    struct stat captured = *before;
    off_t counted = context->progress_report != NULL
        ? context->progress_report->bytes_copied : 0;
    const char *step = NULL;
    int err = 0;
    int source_failed = 0;
    int changed = 0;
    int result;
    for (;;) {
        int destination_fd = -1;
        if (staged) {
            staging_fd = container_staging_open(
                context->staging->container_fd);
            if (staging_fd >= 0)
                destination_fd = openat(staging_fd, CONTAINER_STAGED_NAME,
                                        O_WRONLY | O_CREAT | O_TRUNC |
                                            O_NOFOLLOW | O_CLOEXEC,
                                        0600);
        } else {
            if (capture_regular_claim(context, root, logical, physical_leaf,
                                      parent_fd, destination_leaf,
                                      previous_hint) != 0)
                goto journal_failed;
            portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
            if (ensure_regular_leaf(parent_fd, destination_leaf,
                                    &destination_fd) != 0)
                destination_fd = -1;
            else
                portable_test_interrupt_if(
                    PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);
        }
        if (destination_fd < 0) {
            step = staged ? "stage its copy in the backup"
                          : "create its copy in the backup";
            err = errno;
            source_failed = 0;
            result = -1;
        } else {
            portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_WRITE);
            result = capture_regular_content(context, root, logical,
                                             source_fd, destination_fd,
                                             &captured, &content_digest,
                                             &changed, &step, &err,
                                             &source_failed);
        }
        if (result == 0 || !staged || source_failed || err != ENOSPC)
            break;
        if (verbose) {
            progress_line_end();
            printf("  No room to stage a new copy of %s%s%s; writing it "
                   "over the old one.\n", root->capture_path,
                   logical[0] != '\0' ? "/" : "", logical);
        }
        if (staging_fd >= 0) {
            (void)unlinkat(staging_fd, CONTAINER_STAGED_NAME, 0);
            close(staging_fd);
            staging_fd = -1;
        }
        staged = 0;
        captured = *before;
        changed = 0;
        if (context->progress_report != NULL)
            context->progress_report->bytes_copied = counted;
    }
    if (result == 0 && staged) {
        if (capture_regular_claim(context, root, logical, physical_leaf,
                                  parent_fd, destination_leaf,
                                  previous_hint) != 0)
            goto journal_failed;
        portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
        if (place_regular_leaf(staging_fd, CONTAINER_STAGED_NAME, parent_fd,
                               destination_leaf) != 0) {
            step = "put its copy in place in the backup";
            err = errno;
            result = -1;
        } else {
            portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);
        }
    }
    if (staging_fd >= 0) {
        if (result != 0)
            (void)unlinkat(staging_fd, CONTAINER_STAGED_NAME, 0);
        close(staging_fd);
    }

    // A read that fails leaves the copy cut short. It is removed, with its
    // claim when written in place, and the file listed (D109); a staged one
    // leaves the copy and the entry the backup holds. A file with other
    // names stops the backup: they are recorded against it in this run.
    int failed = 0;
    if (result != 0 && (!source_failed || before->st_nlink != 1)) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL,
            err != 0 ? err : EIO, step, root, logical);
        failed = 1;
    }
    if (close(source_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close it", root, logical);
        failed = 1;
    }
    if (destination_is_root)
        close(parent_fd);
    if (failed || result != 0)
        xattrs_free(xattrs);
    if (failed)
        return -1;
    if (result != 0) {
        SidecarClaim claim = {
            .root_id = { (const unsigned char *)root->id, strlen(root->id) },
            .logical_path = { (const unsigned char *)logical, strlen(logical) },
            .physical_leaf = {
                (const unsigned char *)physical_leaf, strlen(physical_leaf) },
            .kind = SIDECAR_KIND_REGULAR
        };
        if (!staged &&
            reconcile_stale_claim(context, root, logical, &claim) != 0) {
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "remove its cut-short copy from the backup", root, logical);
            return -1;
        }
        return capture_item_failed(context, root, logical, step, err,
                                   no_destination_object);
    }
    if (changed)
        capture_note_change(context, root, logical, BACKUP_SOURCE_CHANGED);

    SidecarEntry sidecar_entry;
    failed = entry_from_stat(root->id, logical, physical_leaf,
                             collision_suffix, &captured, xattrs,
                             &sidecar_entry, NULL, NULL, NULL) != 0;
    if (!failed) {
        sidecar_entry.content_digest = content_digest;
        failed = append_group(context, &sidecar_entry, xattrs) != 0;
    }
    xattrs_free(xattrs);
    return failed ? -1 : 0;

journal_failed:
    if (staging_fd >= 0) {
        (void)unlinkat(staging_fd, CONTAINER_STAGED_NAME, 0);
        close(staging_fd);
    }
    if (destination_is_root)
        close(parent_fd);
    xattrs_free(xattrs);
    close(source_fd);
    return -1;
}

/* Records a regular file whose metadata alone changed with its recorded
 * content digest, and leaves its payload as it is (D88). A run interrupted
 * in between leaves a claim, which the next one reconciles by copying the
 * file again. */
static int capture_metadata_change(PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const char *logical,
                                   const char *physical_leaf,
                                   const SidecarEntry *entry,
                                   const PortableXattrs *xattrs,
                                   const CapturePreviousEntry *previous_hint)
{
    return replace_live_capture(context, root, logical, previous_hint) == 0 &&
                   append_capture_claim(context, root, logical, physical_leaf,
                                        SIDECAR_KIND_REGULAR) == 0 &&
                   append_group(context, entry, xattrs) == 0
               ? 0 : -1;
}

static int capture_special(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root, const struct stat *st)
{
    if (visited_add(context->visited, root->id, logical) != 0)
        return -1;
    // A claim on this path was stale, since the scan never lists a special
    // file: prepare_collision_relocations() removed it before the capture.

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            int saved_errno = errno;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
                "open its place in the backup", root, logical);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe(context, root, logical,
                                    parent_fd, destination_leaf) != 0 ||
        reconcile_stale_live(context, root, logical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (remove_leaf(parent_fd, destination_leaf) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "remove an old copy from the backup", root, logical);
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (destination_is_root)
        close(parent_fd);

    const char *kind = S_ISSOCK(st->st_mode) ? "socket" : "device";
    print_warning("Warning: skipping unsupported %s %s\n", kind,
           logical[0] == '\0' ? root->capture_path : logical);
    return 0;
}

static int capture_symlink(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical_leaf,
                           const char *collision_suffix,
                           int source_parent,
                           const char *source_name, const char *root_path,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           const struct stat *before,
                           int *no_destination_object)
{
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    int target_length = source_symlink_target(source_parent, source_name,
                                              root_path, target,
                                              sizeof(target));
    if (target_length < 0)
        return capture_item_failed(context, root, logical, "read the link",
                                   errno, no_destination_object);

    char source_path[PATH_MAX];
    if (source_symlink_xattr_path(source_parent, source_name, root_path,
                                  source_path, sizeof(source_path)) != 0) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "find its extended attributes", root, logical);
        return -1;
    }
    PortableXattrs xattrs;
    if (collect_symlink_xattrs(source_path, &xattrs) != 0)
        return capture_item_failed(context, root, logical,
                                   "read its extended attributes", errno,
                                   no_destination_object);

    // The final consistency check runs after every path-based read (target,
    // then xattrs) rather than right after the target read: symlinks have no
    // usable fd (open_source_node's O_NOFOLLOW would hit ELOOP), so each read
    // above re-resolves the path independently and nothing pins them to one
    // inode the way capture_regular's single fd does. One check positioned
    // last covers the read window for both.
    struct stat after;
    if (read_source_stat(source_parent, source_name, root_path, &after) != 0) {
        int saved_errno = errno;
        xattrs_free(&xattrs);
        if (source_lookup_failure_kind(saved_errno) ==
            BACKUP_CAPTURE_FAILURE_OPERATIONAL)
            return capture_item_failed(context, root, logical,
                                       "inspect it again after reading",
                                       saved_errno, no_destination_object);
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED, saved_errno,
            "inspect it again after reading", root, logical);
        return -1;
    }
    if (!metadata_symlink_unchanged(before, &after))
        capture_note_change(context, root, logical, BACKUP_SOURCE_CHANGED);

    if (visited_add(context->visited, root->id, logical) != 0) {
        xattrs_free(&xattrs);
        return -1;
    }

    SidecarBytes target_bytes = {
        (const unsigned char *)target, (size_t)target_length
    };
    SidecarEntry entry;
    if (entry_from_stat(root->id, logical, physical_leaf, collision_suffix,
                        before, &xattrs, &entry, &target_bytes, NULL,
                        NULL) != 0) {
        xattrs_free(&xattrs);
        return -1;
    }

    if (context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView previous;
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0) {
            xattrs_free(&xattrs);
            return -1;
        }
        if (live == 1 && entries_equal(&entry, &previous, &xattrs)) {
            int payload = existing_payload_matches(
                context->data_fd, root->payload_path, destination_parent,
                destination_leaf, destination_is_root, 0);
            if (payload < 0) {
                xattrs_free(&xattrs);
                return -1;
            }
            if (payload == 1) {
                xattrs_free(&xattrs);
                return 0;
            }
        }
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            int saved_errno = errno;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
                "open its place in the backup", root, logical);
            xattrs_free(&xattrs);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, NULL) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }

    if (append_capture_claim(context, root, logical, physical_leaf,
                             SIDECAR_KIND_SYMLINK) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }
    if (tombstone_destination_children(context, root, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf,
                            &destination_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "create its copy in the backup", root, logical);
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);
    int failed = close(destination_fd) != 0;
    if (destination_is_root && close(parent_fd) != 0)
        failed = 1;
    if (failed) {
        xattrs_free(&xattrs);
        return -1;
    }

    failed = append_group(context, &entry, &xattrs) != 0;
    xattrs_free(&xattrs);
    return failed ? -1 : 0;
}

static int capture_hardlink(PortableCaptureContext *context,
                            const PortableRootSpec *root,
                            const char *logical, const char *physical_leaf,
                            const char *collision_suffix,
                            int source_fd, const struct stat *before,
                            int destination_parent,
                            const char *destination_leaf,
                            int destination_is_root,
                            const PortableInodeSlot *representative)
{
    SidecarBytes hardlink_root_id = {
        (const unsigned char *)representative->root_id,
        representative->root_length
    };
    SidecarBytes hardlink_logical_path = {
        (const unsigned char *)representative->logical_path,
        representative->logical_length
    };
    SidecarEntry entry;
    PortableXattrs empty_xattrs = {0};
    if (entry_from_stat(root->id, logical, physical_leaf, collision_suffix,
                        before, &empty_xattrs, &entry, NULL,
                        &hardlink_root_id, &hardlink_logical_path) != 0) {
        close(source_fd);
        return -1;
    }

    if (context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView previous;
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0) {
            close(source_fd);
            return -1;
        }
        if (live == 1 && entries_equal(&entry, &previous, &empty_xattrs)) {
            int payload = existing_payload_matches(
                context->data_fd, root->payload_path, destination_parent,
                destination_leaf, destination_is_root, 0);
            if (payload < 0) {
                close(source_fd);
                return -1;
            }
            if (payload == 1)
                return close(source_fd) == 0 ? 0 : -1;
        }
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            int saved_errno = errno;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
                "open its place in the backup", root, logical);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, NULL) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    if (append_capture_claim(context, root, logical, physical_leaf,
                             SIDECAR_KIND_HARDLINK) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "create its copy in the backup", root, logical);
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);

    struct stat after;
    int failed = 0;
    if (fstat(source_fd, &after) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "inspect it again after reading", root, logical);
        failed = 1;
    } else if (!metadata_source_unchanged(before, &after)) {
        // A changed file keeps the bytes read; its entry records the pre-scan
        // metadata that portable_copy_regular() copied against.
        capture_note_change(context, root, logical, BACKUP_SOURCE_CHANGED);
    }
    if (close(destination_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "finish writing its copy in the backup", root, logical);
        failed = 1;
    }
    if (destination_is_root && close(parent_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close its place in the backup", root, logical);
        failed = 1;
    }
    if (close(source_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close it", root, logical);
        failed = 1;
    }
    if (failed)
        return -1;

    return append_group(context, &entry, NULL) == 0 ? 0 : -1;
}

// A node at logical's address in the backup that no record or claim owns is
// migr's own copy whose record was lost: it is recorded from the payload as
// repair records one (D25, D111), so the capture replaces it as any copy it
// holds, and what is below it and no longer in the source is removed with
// the root's stale items.
static int adopt_unowned_destination(PortableCaptureContext *context,
                                     const PortableRootSpec *root,
                                     const char *logical,
                                     const char *physical_leaf,
                                     const char *collision_suffix,
                                     int parent_fd, const char *leaf,
                                     int is_root)
{
    // Most items are recorded under the leaf they are captured to, which
    // needs no look at the backup.
    char logical_parent[SIDECAR_MAX_PATH + 1U];
    const PortablePhysicalOwner *owner = NULL;
    if (!is_root)
        logical_parent_copy(logical_parent, logical);
    if (!is_root &&
        portable_physical_owners_find(context->active_owners, root->id,
                                      logical_parent, physical_leaf,
                                      &owner) == 1 &&
        strcmp(owner->logical_path, logical) == 0)
        return 0;
    char root_leaf[NAME_MAX + 1U];
    if (is_root) {
        if (open_existing_payload_parent(context->data_fd, root->payload_path,
                                         &parent_fd, root_leaf,
                                         sizeof(root_leaf)) != 0) {
            if (errno == ENOENT)
                return 0;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, errno,
                "open its place in the backup", root, logical);
            return -1;
        }
        leaf = root_leaf;
    }
    // A node another item owns, or one that cannot be looked at, is left to
    // the check before the capture writes.
    int result = capture_destination_is_safe(context, root, logical,
                                             parent_fd, leaf);
    if (result == 1) {
        SidecarEntry address = {
            .root_id = { (const unsigned char *)root->id, strlen(root->id) },
            .logical_path = { (const unsigned char *)logical,
                              strlen(logical) },
            .physical_leaf = { (const unsigned char *)physical_leaf,
                               strlen(physical_leaf) },
            .collision_suffix = { (const unsigned char *)collision_suffix,
                                  strlen(collision_suffix) }
        };
        FailedStep failed = {0};
        result = repair_adopt_payload(context->sidecar, context->data_fd,
                                      root->payload_path, parent_fd, leaf,
                                      &address, &failed) == 0 &&
                         portable_capture_owners_reload(context) == 0
                     ? 0 : -1;
        if (result != 0)
            portable_capture_context_failure_record(
                context,
                failed.err != 0 ? BACKUP_CAPTURE_FAILURE_OPERATIONAL
                                : BACKUP_CAPTURE_FAILURE_INTERNAL,
                failed.err, "record the copy the backup holds without a record",
                root, logical);
    } else {
        result = 0;
    }
    if (is_root)
        close(parent_fd);
    return result;
}

static int capture_node(PortableCaptureContext *context,
                        const PortableRootSpec *root,
                        const char *logical, const char *physical_leaf,
                        const char *collision_suffix,
                        int source_parent,
                        const char *source_name, const char *root_path,
                        int destination_parent, const char *destination_leaf,
                        int *no_destination_object)
{
    struct stat before;
    if (read_source_stat(source_parent, source_name, root_path, &before) != 0) {
        int saved_errno = errno;
        if (source_lookup_failure_kind(saved_errno) ==
            BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED)
            return capture_leave_out(context, root, logical,
                                     BACKUP_SOURCE_CHANGE_KINDS,
                                     no_destination_object);
        return capture_item_failed(context, root, logical, "inspect it",
                                   saved_errno, no_destination_object);
    }

    int prepared_member = portable_current_source_contains(
        context->current_source, root->id, logical);
    int address_bearing = S_ISDIR(before.st_mode) || S_ISREG(before.st_mode) ||
                          S_ISLNK(before.st_mode);
    if ((address_bearing && prepared_member != 1) ||
        (!address_bearing && prepared_member == 1)) {
        // Appeared (or changed kind) after the pre-scan planned its name.
        return capture_leave_out(context, root, logical,
                                 prepared_member != 1
                                     ? BACKUP_SOURCE_APPEARED
                                     : BACKUP_SOURCE_CHANGE_KINDS,
                                 no_destination_object);
    }

    int is_root = source_parent < 0;
    if (context->resume_mode &&
        adopt_unowned_destination(context, root, logical, physical_leaf,
                                  collision_suffix, destination_parent,
                                  destination_leaf, is_root) != 0)
        return -1;
    if (S_ISSOCK(before.st_mode) || S_ISCHR(before.st_mode) ||
        S_ISBLK(before.st_mode)) {
        if (no_destination_object != NULL)
            *no_destination_object = 1;
        return capture_special(context, root, logical,
                               destination_parent, destination_leaf, is_root,
                               &before);
    }
    if (S_ISFIFO(before.st_mode)) {
        errno = EOPNOTSUPP;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, EOPNOTSUPP,
            "keep a FIFO in a portable backup", root, logical);
        return -1;
    }
    if (S_ISLNK(before.st_mode)) {
        int result = capture_symlink(context, root, logical, physical_leaf,
                                     collision_suffix, source_parent,
                                     source_name, root_path,
                                     destination_parent, destination_leaf,
                                     is_root, &before, no_destination_object);
        if (result != 0)
            journal_failure_record(
                context, "record the link in the journal", root, logical);
        return result;
    }

    int source_fd = open_source_node(source_parent, source_name, root_path,
                                     &before);
    if (source_fd < 0) {
        int saved_errno = errno;
        if (source_lookup_failure_kind(saved_errno) ==
            BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED)
            return capture_leave_out(context, root, logical,
                                     BACKUP_SOURCE_CHANGE_KINDS,
                                     no_destination_object);
        // Refused with O_NOATIME: never read without it (D17).
        int folder = S_ISDIR(before.st_mode);
        const char *step =
            saved_errno == EPERM
                ? (folder ? "open the folder without changing its access time"
                          : "open it without changing its access time")
                : (folder ? "open the folder" : "open it");
        return capture_item_failed(context, root, logical, step, saved_errno,
                                   no_destination_object);
    }
    struct stat opened;
    if (fstat(source_fd, &opened) != 0) {
        int saved_errno = errno;
        close(source_fd);
        return capture_item_failed(context, root, logical, "inspect it",
                                   saved_errno, no_destination_object);
    }
    if (!metadata_source_unchanged(&before, &opened)) {
        // Changed between the stat and the open. The same kind of object is
        // simply captured as it is now, from the open fd; a different kind
        // (replaced by a directory, say) no longer matches what was planned.
        if ((opened.st_mode & S_IFMT) == (before.st_mode & S_IFMT)) {
            before = opened;
        } else {
            close(source_fd);
            return capture_leave_out(context, root, logical,
                                     BACKUP_SOURCE_CHANGE_KINDS,
                                     no_destination_object);
        }
    }

    if (visited_add(context->visited, root->id, logical) != 0) {
        close(source_fd);
        return -1;
    }

    const PortableInodeSlot *representative = NULL;
    if (S_ISREG(before.st_mode)) {
        int inode_state = inode_map_find_or_insert(
            context->inode_map, opened.st_dev, opened.st_ino, root->id,
            logical, &representative);
        if (inode_state < 0) {
            close(source_fd);
            return -1;
        }
        int same_logical_entry = inode_state == 1 &&
                                 strcmp(representative->root_id, root->id) == 0 &&
                                 strcmp(representative->logical_path, logical) == 0;
        if (inode_state == 1 && !same_logical_entry) {
            int result = capture_hardlink(
                context, root, logical, physical_leaf, collision_suffix,
                source_fd, &before, destination_parent, destination_leaf,
                is_root, representative);
            if (result != 0)
                journal_failure_record(
                    context,
                    "record it as another name of a file already backed up",
                    root, logical);
            return result;
        }
    }

    // A file with other names is their representative by now, so it cannot
    // be left out alone: the backup stops.
    PortableXattrs xattrs;
    if (collect_xattrs(source_fd, &xattrs) != 0) {
        int saved_errno = errno;
        close(source_fd);
        if (S_ISREG(before.st_mode) && before.st_nlink > 1) {
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
                "read its extended attributes", root, logical);
            return -1;
        }
        return capture_item_failed(context, root, logical,
                                   "read its extended attributes",
                                   saved_errno, no_destination_object);
    }

    CapturePreviousEntry previous_hint = {0};
    if (S_ISREG(before.st_mode) && context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarLiveView previous;
        int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                    &previous);
        if (live < 0) {
            xattrs_free(&xattrs);
            close(source_fd);
            return -1;
        }
        previous_hint.resolved = 1;
        previous_hint.live = live;
        if (live == 1)
            previous_hint.view = previous;
        if (live == 1) {
            SidecarEntry current;
            int built = entry_from_stat(root->id, logical, physical_leaf,
                                        collision_suffix, &before, &xattrs,
                                        &current, NULL, NULL, NULL) == 0;
            int matches = built && entries_equal(&current, &previous, &xattrs);
            int same_content = built && !matches && previous.entry != NULL &&
                               entry_content_equal(&current, previous.entry);
            // A copy verify found damaged is written again (D107).
            int recopy = recopy_list_contains(context->recopy, root->id,
                                              logical);
            if (!recopy && (matches || same_content)) {
                int payload = existing_payload_matches(
                    context->data_fd, root->payload_path, destination_parent,
                    destination_leaf, is_root, current.size);
                if (payload < 0) {
                    xattrs_free(&xattrs);
                    close(source_fd);
                    return -1;
                }
                if (payload == 1)
                    backup_capture_report_unchanged(
                        context->progress_report, (off_t)current.size,
                        logical[0] == '\0' ? root->capture_path : logical);
                if (payload == 1 && matches) {
                    xattrs_free(&xattrs);
                    return close(source_fd) == 0 ? 0 : -1;
                }
                if (payload == 1) {
                    current.content_digest = previous.entry->content_digest;
                    int result = capture_metadata_change(
                        context, root, logical, physical_leaf, &current,
                        &xattrs, &previous_hint);
                    xattrs_free(&xattrs);
                    if (close(source_fd) != 0)
                        result = -1;
                    if (result != 0)
                        journal_failure_record(
                            context, "record it in the journal", root, logical);
                    return result;
                }
            }
        }
    }

    if (S_ISREG(before.st_mode)) {
        int result = capture_regular(context, root, logical, physical_leaf,
                                     collision_suffix, source_fd, &before,
                                     destination_parent, destination_leaf,
                                     is_root, &xattrs, &previous_hint,
                                     no_destination_object);
        if (result != 0)
            journal_failure_record(
                context, "record it in the journal", root, logical);
        return result;
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            int saved_errno = errno;
            portable_capture_context_failure_record(
                context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
                "open its place in the backup", root, logical);
            xattrs_free(&xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }

    if (capture_destination_is_safe_or_claimed(
            context, root, logical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, NULL) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    if (append_capture_claim(context, root, logical, physical_leaf,
                             SIDECAR_KIND_DIRECTORY) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    if (ensure_directory_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        int saved_errno = errno;
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "create the folder in the backup", root, logical);
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }
    if (capture_directory(context, root, logical, physical_leaf,
                          source_fd, &before, destination_fd, &xattrs,
                          collision_suffix) != 0) {
        if (is_root)
            close(parent_fd);
        journal_failure_record(
            context, "record the folder in the journal", root, logical);
        return -1;
    }
    if (is_root)
        close(parent_fd);
    return 0;
}

int root_spec_valid(const PortableRootSpec *root)
{
    if (root == NULL || !safe_id(root->id) || root->capture_path == NULL ||
        root->capture_path[0] != '/' || !safe_relative_path(root->payload_path) ||
        root->source_path == NULL)
        return 0;
    if (root->policy != ROOT_POLICY_XDG &&
        root->policy != ROOT_POLICY_HOME_RELATIVE)
        return 0;
    if (root->policy == ROOT_POLICY_HOME_RELATIVE) {
        if (!root->has_restore_path || root->restore_path == NULL)
            return 0;
    } else if (root->has_restore_path) {
        return 0;
    }
    if (root->has_restore_path && root->restore_path[0] != '\0' &&
        !safe_relative_path(root->restore_path))
        return 0;
    if (root->selection != NULL) {
        const BackupPlanRoot *selected = &root->selection->root;
        const ManifestRoot *mapped = &selected->manifest_root;
        if (strcmp(root->id, mapped->id) != 0 ||
            root->policy != mapped->policy ||
            strcmp(root->capture_path, selected->capture_path) != 0 ||
            strcmp(root->payload_path, mapped->payload_path) != 0 ||
            strcmp(root->source_path, mapped->source_path) != 0 ||
            root->has_restore_path != mapped->has_restore_path ||
            (root->has_restore_path &&
             strcmp(root->restore_path, mapped->restore_path) != 0))
            return 0;
    }
    return strlen(root->capture_path) < PATH_MAX &&
           strlen(root->source_path) < PATH_MAX;
}

int portable_capture_request_set_selection(
    PortableCaptureRequest *request, const SelectionPlan *plan,
    PortableRootSpec *roots, size_t root_capacity)
{
    if (request == NULL || selection_plan_validate(plan) < 0 ||
        root_capacity < plan->root_count ||
        (plan->root_count != 0 && roots == NULL))
        return -1;
    for (size_t index = 0; index < plan->root_count; index++) {
        const SelectionRoot *selection = &plan->roots[index];
        const BackupPlanRoot *root = &selection->root;
        const ManifestRoot *mapped = &root->manifest_root;
        roots[index] = (PortableRootSpec){
            .id = mapped->id,
            .policy = mapped->policy,
            .capture_path = root->capture_path,
            .payload_path = mapped->payload_path,
            .source_path = mapped->source_path,
            .restore_path = mapped->restore_path,
            .has_restore_path = mapped->has_restore_path,
            .selection = selection,
            .comprehensive_only = root->comprehensive_only
        };
    }
    request->scope = plan->scope;
    request->roots = roots;
    request->root_count = plan->root_count;
    request->selection_plan = plan;
    return 0;
}

static int request_selection_valid(const PortableCaptureRequest *request)
{
    if (request->selection_plan == NULL) {
        for (size_t index = 0; index < request->root_count; index++)
            if (request->roots[index].selection != NULL)
                return 0;
        return 1;
    }
    /* selection_plan_validate() holds the structural checks (parent indices,
     * delegated/excluded consistency, root ordering, payload-path
     * disjointness) the native entry points require. Every portable entry
     * point routes through this function, so this is the single place for
     * them. */
    const SelectionPlan *plan = request->selection_plan;
    if (selection_plan_validate(plan) < 0 || request->scope != plan->scope ||
        request->root_count != plan->root_count)
        return 0;
    for (size_t index = 0; index < request->root_count; index++)
        if (request->roots[index].selection != &plan->roots[index] ||
            !root_spec_valid(&request->roots[index]))
            return 0;
    return 1;
}

// What every portable entry point requires of its request.
static int request_valid(const PortableCaptureRequest *request)
{
    return request != NULL &&
           request->scope >= MANIFEST_SCOPE_CRITICAL &&
           request->scope <= MANIFEST_SCOPE_EXPLICIT &&
           request->root_count <= MANIFEST_MAX_ROOTS &&
           (request->root_count == 0 || request->roots != NULL) &&
           request_selection_valid(request);
}

static int build_manifest(const PortableCaptureRequest *request,
                          Manifest *manifest)
{
    if (request->selection_plan != NULL) {
        if (selection_plan_manifest(request->selection_plan, manifest) != 0)
            return -1;
        manifest->representation = CLONE_PORTABLE_SIDECAR;
        manifest->sidecar_version = SIDECAR_VERSION;
        manifest->has_source_identity = request->has_source_identity != 0;
        if (manifest->has_source_identity) {
            if (request->machine_id == NULL ||
                copy_text(manifest->machine_id, sizeof(manifest->machine_id),
                          request->machine_id) != 0) {
                manifest_free(manifest);
                return -1;
            }
            manifest->source_uid = request->source_uid;
            manifest->source_gid = request->source_gid;
            manifest->has_source_gid = 1;
        }
        if (!manifest_selection_valid(manifest)) {
            manifest_free(manifest);
            return -1;
        }
        return 0;
    }
    memset(manifest, 0, sizeof(*manifest));
    manifest->version = MANIFEST_CURRENT_VERSION;
    manifest->representation = CLONE_PORTABLE_SIDECAR;
    manifest->scope = request->scope;
    manifest->sidecar_version = SIDECAR_VERSION;
    manifest->has_source_identity = request->has_source_identity != 0;
    if (manifest->has_source_identity) {
        if (request->machine_id == NULL ||
            copy_text(manifest->machine_id, sizeof(manifest->machine_id),
                      request->machine_id) != 0)
            return -1;
        manifest->source_uid = request->source_uid;
        manifest->source_gid = request->source_gid;
        manifest->has_source_gid = 1;
    }

    manifest->root_count = (int)request->root_count;
    if (request->root_count == 0)
        return 0;
    manifest->roots = calloc(request->root_count, sizeof(*manifest->roots));
    if (manifest->roots == NULL)
        return -1;

    for (size_t index = 0; index < request->root_count; index++) {
        const PortableRootSpec *source = &request->roots[index];
        ManifestRoot *destination = &manifest->roots[index];
        if (!root_spec_valid(source))
            goto fail;
        for (size_t previous = 0; previous < index; previous++) {
            if (strcmp(request->roots[previous].id, source->id) == 0 ||
                relative_paths_overlap(request->roots[previous].payload_path,
                                       source->payload_path))
                goto fail;
        }
        // root_spec_valid() bounds every field by its manifest buffer.
        strcpy(destination->id, source->id);
        strcpy(destination->payload_path, source->payload_path);
        strcpy(destination->source_path, source->source_path);
        destination->policy = source->policy;
        destination->has_restore_path = source->has_restore_path;
        if (source->has_restore_path)
            strcpy(destination->restore_path, source->restore_path);
    }
    return 0;

fail:
    manifest_free(manifest);
    return -1;
}

/* Keep the request identity independent from the manifest that the caller may
 * annotate with bundled self/network metadata before publication. */
static int manifest_clone(const Manifest *source, Manifest *destination)
{
    *destination = *source;
    destination->roots = NULL;
    destination->excludes = NULL;

    if (source->root_count > 0) {
        size_t root_count = (size_t)source->root_count;
        destination->roots = calloc(root_count, sizeof(*destination->roots));
        if (destination->roots == NULL)
            goto fail;
        memcpy(destination->roots, source->roots,
               root_count * sizeof(*destination->roots));
    }

    if (source->exclude_count > 0) {
        destination->excludes = calloc(source->exclude_count,
                                       sizeof(*destination->excludes));
        if (destination->excludes == NULL)
            goto fail;
        for (size_t index = 0; index < source->exclude_count; index++) {
            destination->excludes[index] = strdup(source->excludes[index]);
            if (destination->excludes[index] == NULL)
                goto fail;
        }
    }
    return 0;

fail:
    manifest_free(destination);
    return -1;
}

typedef enum {
    PORTABLE_PREPARED_REQUEST_MATCH,
    PORTABLE_PREPARED_REQUEST_MISMATCH,
    PORTABLE_PREPARED_REQUEST_ERROR
} PortablePreparedRequestStatus;

static ManifestIdentityComparison portable_request_identity_compare(
    const Manifest *prepared_identity, const Manifest *candidate)
{
    if (prepared_identity->has_source_identity != candidate->has_source_identity)
        return MANIFEST_IDENTITY_DIFFERENT;

    if (prepared_identity->has_source_identity)
        return manifest_resume_identity_compare(prepared_identity, candidate);

    /* D15 deliberately treats a missing source identity as non-adoptable. For
     * this in-memory binding, two requests that both omit the optional
     * identity are equivalent; normalize only that field before reusing the
     * full comparator. A present/absent transition remains a mismatch. */
    Manifest normalized_prepared = *prepared_identity;
    Manifest normalized_candidate = *candidate;
    normalized_prepared.has_source_identity = 1;
    normalized_candidate.has_source_identity = 1;
    strcpy(normalized_prepared.machine_id, "0");
    strcpy(normalized_candidate.machine_id, "0");
    normalized_prepared.source_uid = 0;
    normalized_candidate.source_uid = 0;
    return manifest_resume_identity_compare(&normalized_prepared,
                                            &normalized_candidate);
}

static PortablePreparedRequestStatus portable_prepared_request_status(
    const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared)
{
    Manifest candidate = {0};
    if (build_manifest(request, &candidate) != 0)
        return PORTABLE_PREPARED_REQUEST_ERROR;

    ManifestIdentityComparison identity = portable_request_identity_compare(
        &prepared->request_identity, &candidate);
    manifest_free(&candidate);
    if (identity == MANIFEST_IDENTITY_ERROR)
        return PORTABLE_PREPARED_REQUEST_ERROR;
    return identity == MANIFEST_IDENTITY_EQUAL
        ? PORTABLE_PREPARED_REQUEST_MATCH
        : PORTABLE_PREPARED_REQUEST_MISMATCH;
}

int portable_capture_prepare(int scratch_fd,
                             const PortableCaptureRequest *request,
                             PortablePreparedCapture *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    if (scratch_fd < 0 || !request_valid(request))
        return -1;

    portable_prescan_report_init(&out->report);
    if (prescan_request(scratch_fd, request, &out->report) != 0)
        return -1;
    if (build_manifest(request, &out->manifest) != 0)
        return -1;
    if (manifest_clone(&out->manifest, &out->request_identity) != 0)
        return -1;
    out->ready = 1;
    return 0;
}

void portable_prepared_capture_free(PortablePreparedCapture *prepared)
{
    if (prepared == NULL)
        return;
    manifest_free(&prepared->manifest);
    manifest_free(&prepared->request_identity);
    portable_prescan_report_free(&prepared->report);
    memset(prepared, 0, sizeof(*prepared));
}

// data_fd is a folder its callers opened with O_DIRECTORY.
static int data_namespace_is_empty(int data_fd)
{
    int empty = 1;
    int scan_fd = dup_cloexec(data_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    /* Rewound: through an fd opened earlier, btrfs lists only the entries
     * that existed then, and this folder has been written since. */
    rewinddir(directory);
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                empty = 0;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = 0;
            break;
        }
    }
    if (closedir(directory) != 0)
        empty = 0;
    return empty ? 0 : -1;
}

static int fresh_namespace_is_empty(int container_fd)
{
    struct stat st;
    if (fstatat(container_fd, "manifest.txt", &st, AT_SYMLINK_NOFOLLOW) == 0)
        return -1;
    if (errno != ENOENT)
        return -1;
    if (fstatat(container_fd, SIDECAR_SLOT_NAME, &st,
                AT_SYMLINK_NOFOLLOW) == 0)
        return -1;
    if (errno != ENOENT)
        return -1;
    if (fstatat(container_fd, "data", &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return -1;
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0)
        return -1;
    int result = data_namespace_is_empty(data_fd);
    if (close(data_fd) != 0)
        result = -1;
    return result;
}

int portable_capture_context_init(PortableCaptureContext *context,
                                  int data_fd, SidecarLog *sidecar,
                                  int case_sensitive)
{
    if (context == NULL || data_fd < 0 || sidecar == NULL ||
        sidecar->implementation == NULL)
        return -1;
    struct stat st;
    if (fstat(data_fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    memset(context, 0, sizeof(*context));
    PortableVisited *visited = calloc(1, sizeof(*visited));
    if (visited == NULL)
        return -1;
    PortablePhysicalOwners *active_owners = calloc(1, sizeof(*active_owners));
    if (active_owners == NULL) {
        free(visited);
        return -1;
    }
    PortablePhysicalOwners *tombstone_owners = calloc(1,
                                                       sizeof(*tombstone_owners));
    if (tombstone_owners == NULL) {
        free(active_owners);
        free(visited);
        return -1;
    }
    PortableInodeMap *inode_map = calloc(1, sizeof(*inode_map));
    PortableVisited *failed = calloc(1, sizeof(*failed));
    if (inode_map == NULL || failed == NULL) {
        free(failed);
        free(inode_map);
        free(tombstone_owners);
        free(active_owners);
        free(visited);
        return -1;
    }
    context->data_fd = data_fd;
    context->sidecar = sidecar;
    context->case_sensitive = case_sensitive != 0;
    visited->hash_salt = sidecar_process_salt();
    inode_map->hash_salt = sidecar_process_salt();
    failed->hash_salt = sidecar_process_salt();
    context->visited = visited;
    context->failed = failed;
    context->inode_map = inode_map;
    context->active_owners = active_owners;
    context->tombstone_owners = tombstone_owners;
    return 0;
}

void portable_capture_context_close(PortableCaptureContext *context)
{
    if (context == NULL)
        return;
    visited_free(context->visited);
    visited_free(context->failed);
    inode_map_free(context->inode_map);
    portable_physical_owners_free(context->active_owners);
    free(context->active_owners);
    portable_physical_owners_free(context->tombstone_owners);
    free(context->tombstone_owners);
    memset(context, 0, sizeof(*context));
}

int portable_capture_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    if (context == NULL || context->visited == NULL ||
        context->inode_map == NULL ||
        context->data_fd < 0 || context->sidecar == NULL ||
        !root_spec_valid(root)) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "it was given to the capture wrongly", root, NULL);
        return -1;
    }
    /* visited is root-local; inode_map spans every root in this context. */
    PortableVisited *visited = context->visited;
    if (visited_reset(visited) != 0) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "reset the list of items backed up", root, NULL);
        return -1;
    }
    if (prepared_source_validate_root(context, root) != 0)
        return -1;
    if (prepare_collision_relocations(context, root) != 0) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "plan the names that collide", root, NULL);
        return -1;
    }
    if (portable_capture_owners_reload(context) != 0) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "load the owners already recorded", root, NULL);
        return -1;
    }
    if (fileops_make_parents_at(context->data_fd, root->payload_path) != 0) {
        portable_capture_context_failure_record(
            context, BACKUP_CAPTURE_FAILURE_OPERATIONAL, errno,
            "create the folders above it in the backup", root, NULL);
        return -1;
    }
    int result = capture_node(context, root, "", "", "", -1, NULL,
                              root->capture_path, -1, NULL, NULL);
    if (result != 0)
        return result;
    return capture_current_source_seen(context, root);
}

// Captures and reconciles every root: the critical ones first, then those
// only --comprehensive takes, and the deferred ones last (D84, D97).
// Returns 0, or -1 once one fails.
static int capture_roots(PortableCaptureContext *context,
                         const PortableCaptureRequest *request)
{
    for (int deferred = 0; deferred <= 1; deferred++) {
        int asked = 0;
        for (int later = 0; later <= 1; later++) {
            for (size_t index = 0; index < request->root_count; index++) {
                const PortableRootSpec *root = &request->roots[index];
                int root_deferred = request->deferred != NULL &&
                                    request->deferred[index] != 0;
                if (root_deferred != deferred ||
                    root->comprehensive_only != later)
                    continue;
                if (deferred && !asked && request->before_deferred != NULL)
                    request->before_deferred(request->before_deferred_context);
                asked = 1;
                if (verbose)
                    printf("  Capturing: %s -> data/%s\n", root->capture_path,
                           root->payload_path);
                if (portable_capture_root(context, root) != 0)
                    return -1;
                if (reconcile_root(context, root) != 0) {
                    portable_capture_context_failure_record(
                        context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                        "remove the items no longer in the source", root, NULL);
                    return -1;
                }
            }
        }
    }
    return 0;
}

int portable_capture_fresh_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report)
{
    portable_capture_failure_reset(progress_report);
    if (live_count != NULL)
        *live_count = 0;
    if (container_fd < 0 || !request_valid(request) ||
        prepared == NULL || !prepared->ready) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "it was given to the capture wrongly", NULL, NULL);
        return -1;
    }

    PortablePreparedRequestStatus request_status =
        portable_prepared_request_status(request, prepared);
    if (request_status == PORTABLE_PREPARED_REQUEST_ERROR ||
        request_status == PORTABLE_PREPARED_REQUEST_MISMATCH) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "the scan does not match this backup", NULL, NULL);
        return -1;
    }
    if (fresh_namespace_is_empty(container_fd) != 0) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "the new backup is not empty", NULL, NULL);
        return -1;
    }

    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = -1;
    int sidecar_ready = 0;
    int context_ready = 0;
    int result = -1;

    if (manifest_write_v1_at(container_fd, &prepared->manifest) != 0) {
        int saved_errno = errno;
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "write manifest.txt", NULL, NULL);
        goto done;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_MANIFEST);

    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST) {
        int saved_errno = errno;
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "create data/", NULL, NULL);
        goto done;
    }
    data_fd = openat(container_fd, "data",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0) {
        int saved_errno = errno;
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "open data/", NULL, NULL);
        goto done;
    }

    if (sidecar_log_create_at(container_fd, &sidecar) != SIDECAR_OPEN_FRESH) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "create the journal", NULL, NULL);
        goto done;
    }
    sidecar_ready = 1;

    int failed = portable_capture_context_init(&context, data_fd, &sidecar,
                                               request->case_sensitive) != 0;
    if (failed)
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "set up the capture", NULL, NULL);
    if (!failed) {
        context_ready = 1;
        context.progress_report = progress_report;
        context.collision_plan = &prepared->report.collision_plan;
        context.current_source = &prepared->report.current_source;
        if (portable_capture_owners_reload(&context) != 0 ||
            sticky_seed_inode_map(context.inode_map, request, &sidecar) != 0 ||
            capture_failed_seed(&context, &prepared->report.unreadable) != 0) {
            portable_capture_context_failure_record(
                &context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "load the owners and hardlinks already recorded", NULL, NULL);
            failed = 1;
        }
    }
    if (!failed && capture_roots(&context, request) != 0)
        failed = 1;
    if (!failed && sidecar_log_claim_count(&sidecar) != 0) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "some items are still unfinished in the journal", NULL, NULL);
        failed = 1;
    }
    result = failed ? -1 : 0;

done:
    if (sidecar_ready && live_count != NULL)
        *live_count = sidecar_log_live_count(&sidecar);
    if (context_ready)
        portable_capture_context_close(&context);
    if (sidecar_ready && sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "close the journal", NULL, NULL);
        result = -1;
    }
    if (data_fd >= 0 && close(data_fd) != 0) {
        int saved_errno = errno;
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close data/", NULL, NULL);
        result = -1;
    }
    if (result != 0)
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "finish the backup", NULL, NULL);
    return result;
}

int portable_capture_fresh_at(int container_fd,
                              const PortableCaptureRequest *request,
                              PortablePrescanReport *report)
{
    if (container_fd < 0 || !request_valid(request) ||
        fresh_namespace_is_empty(container_fd) != 0)
        return -1;

    PortablePreparedCapture prepared;
    if (portable_capture_prepare(container_fd, request, &prepared) != 0) {
        if (report != NULL) {
            *report = prepared.report;
            memset(&prepared.report, 0, sizeof(prepared.report));
        }
        portable_prepared_capture_free(&prepared);
        return -1;
    }

    int result = portable_capture_fresh_prepared_at(container_fd, request,
                                                    &prepared, NULL, NULL);
    if (report != NULL) {
        *report = prepared.report;
        memset(&prepared.report, 0, sizeof(prepared.report));
    }
    portable_prepared_capture_free(&prepared);
    return result;
}

/* Returns 0 with an open data directory, 1 when data is absent, -1 otherwise. */
static int open_existing_data(int container_fd, int *out_fd)
{
    *out_fd = -1;
    struct stat st;
    if (fstatat(container_fd, "data", &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 1 : -1;
    if (!S_ISDIR(st.st_mode))
        return -1;
    int fd = openat(container_fd, "data",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    *out_fd = fd;
    return 0;
}

static int create_resume_data(int container_fd, int *out_fd)
{
    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST)
        return -1;
    int state = open_existing_data(container_fd, out_fd);
    return state == 0 ? 0 : -1;
}

int portable_capture_resume_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report)
{
    portable_capture_failure_reset(progress_report);
    BackupStaging staging = { container_fd };
    if (live_count != NULL)
        *live_count = 0;
    if (container_fd < 0 || !request_valid(request) ||
        prepared == NULL || !prepared->ready) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "it was given to the capture wrongly", NULL, NULL);
        return -1;
    }

    PortablePreparedRequestStatus request_status =
        portable_prepared_request_status(request, prepared);
    if (request_status == PORTABLE_PREPARED_REQUEST_ERROR ||
        request_status == PORTABLE_PREPARED_REQUEST_MISMATCH) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "the scan does not match this backup", NULL, NULL);
        return -1;
    }

    Manifest existing = {0};
    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = -1;
    int context_ready = 0;
    int result = -1;

    ManifestStatus manifest_status = manifest_read_v1_at(container_fd,
                                                         &existing);
    if (manifest_status != MANIFEST_STATUS_VALID) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "read the backup's manifest.txt", NULL, NULL);
        goto done;
    }
    ManifestIdentityComparison identity =
        manifest_resume_identity_compare(&existing, &prepared->manifest);
    if (identity == MANIFEST_IDENTITY_ERROR)
    {
        /* An allocation failure while comparing is an operational fault, not
         * proof this container is a different job (docs/DECISIONS.md D15;
         * manifest.h's MANIFEST_IDENTITY_ERROR contract). Both branches still
         * refuse resume today; keeping them separate prevents this distinction
         * from disappearing if a future change handles them differently. */
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "the backup's manifest names another backup", NULL, NULL);
        goto done;
    }
    if (identity != MANIFEST_IDENTITY_EQUAL) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "the backup's manifest names another backup", NULL, NULL);
        goto done;
    }

    int data_state = open_existing_data(container_fd, &data_fd);
    if (data_state < 0) {
        int saved_errno = errno;
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "open data/", NULL, NULL);
        goto done;
    }
    int data_missing = data_state == 1;

    SidecarOpenStatus sidecar_status = sidecar_log_adopt_at(container_fd,
                                                            &sidecar);
    int failed = 0;
    if (sidecar_status == SIDECAR_OPEN_MISSING) {
        if (data_missing) {
            if (create_resume_data(container_fd, &data_fd) != 0) {
                int saved_errno = errno;
                portable_capture_failure_record(
                    progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL,
                    saved_errno, "create data/", NULL, NULL);
                failed = 1;
            }
        }
        if (!failed && data_namespace_is_empty(data_fd) != 0) {
            portable_capture_failure_record(
                progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "data/ is not empty", NULL, NULL);
            failed = 1;
        }
        if (!failed &&
            sidecar_log_create_at(container_fd, &sidecar) !=
                SIDECAR_OPEN_FRESH) {
            portable_capture_failure_record(
                progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "create the journal", NULL, NULL);
            failed = 1;
        }
    } else if (sidecar_status != SIDECAR_OPEN_RESUMABLE || data_missing) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "the journal and data/ do not match", NULL, NULL);
        failed = 1;
    }

    if (!failed && portable_capture_context_init(&context, data_fd, &sidecar,
                                                request->case_sensitive) != 0) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "set up the capture", NULL, NULL);
        failed = 1;
    }
    if (!failed) {
        context_ready = 1;
        context.progress_report = progress_report;
        context.resume_mode = 1;
        context.payload_matches_journal = request->payload_matches_journal;
        context.recopy = request->recopy;
        context.staging = &staging;
        context.collision_plan = &prepared->report.collision_plan;
        context.current_source = &prepared->report.current_source;
        if (portable_capture_owners_reload(&context) != 0 ||
            sticky_seed_inode_map(context.inode_map, request, &sidecar) != 0 ||
            capture_failed_seed(&context, &prepared->report.unreadable) != 0) {
            portable_capture_context_failure_record(
                &context, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
                "load the owners and hardlinks already recorded", NULL, NULL);
            failed = 1;
        }
        if (!failed && capture_roots(&context, request) != 0) {
            failed = 1;
            // An update writes moved files before it removes their old
            // copies; when that fills the destination, it removes them
            // first, and the caller runs it again (D98).
            if (progress_report != NULL &&
                progress_report->failure_errno == ENOSPC)
                for (size_t index = 0; index < request->root_count; index++)
                    if (reconcile_vanished(
                            &context, &request->roots[index],
                            &progress_report->vanished_removed) != 0) {
                        progress_report->vanished_removed = 0;
                        break;
                    }
        }
    }
    if (!failed && sidecar_log_claim_count(&sidecar) != 0) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "some items are still unfinished in the journal", NULL, NULL);
        failed = 1;
    }
    result = failed ? -1 : 0;

done:
    if (sidecar.implementation != NULL && live_count != NULL)
        *live_count = sidecar_log_live_count(&sidecar);
    if (context_ready)
        portable_capture_context_close(&context);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK) {
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "close the journal", NULL, NULL);
        result = -1;
    }
    if (data_fd >= 0 && close(data_fd) != 0) {
        int saved_errno = errno;
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_OPERATIONAL, saved_errno,
            "close data/", NULL, NULL);
        result = -1;
    }
    manifest_free(&existing);
    if (result != 0)
        portable_capture_failure_record(
            progress_report, BACKUP_CAPTURE_FAILURE_INTERNAL, 0,
            "finish the backup", NULL, NULL);
    return result;
}

int portable_capture_resume_at(int container_fd,
                               const PortableCaptureRequest *request,
                               PortablePrescanReport *report)
{
    if (container_fd < 0 || !request_valid(request))
        return -1;

    PortablePreparedCapture prepared;
    if (portable_capture_prepare(container_fd, request, &prepared) != 0) {
        if (report != NULL) {
            *report = prepared.report;
            memset(&prepared.report, 0, sizeof(prepared.report));
        }
        portable_prepared_capture_free(&prepared);
        return -1;
    }

    int result = portable_capture_resume_prepared_at(container_fd, request,
                                                     &prepared, NULL, NULL);
    if (report != NULL) {
        *report = prepared.report;
        memset(&prepared.report, 0, sizeof(prepared.report));
    }
    portable_prepared_capture_free(&prepared);
    return result;
}
