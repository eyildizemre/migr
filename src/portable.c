#define _GNU_SOURCE

#include "portable.h"
#include "portable_reconcile_internal.h"
#include "portable_fsops_internal.h"
#include "portable_hashset_internal.h"
#include "portable_prescan_internal.h"

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

void portable_capture_test_set_interrupt(PortableTestInterruptPoint point)
{
    portable_test_interrupt_point = point;
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

int portable_payload_path_fits(size_t root_length, size_t physical_length,
                               size_t capacity)
{
    if (root_length == 0 || root_length >= capacity)
        return 0;
    size_t remaining = capacity - root_length - 1U;
    if (physical_length == 0)
        return 1;
    return remaining >= 1U && physical_length <= remaining - 1U;
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
    if (extra > SIDECAR_MAX_XATTRS_PER_ENTRY - xattrs->count)
        return -1;
    size_t needed = xattrs->count + extra;
    if (needed <= xattrs->capacity)
        return 0;
    size_t capacity = xattrs->capacity == 0 ? 4U : xattrs->capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > SIDECAR_MAX_XATTRS_PER_ENTRY)
        capacity = SIDECAR_MAX_XATTRS_PER_ENTRY;
    SidecarXattr *items = realloc(xattrs->items, capacity * sizeof(*items));
    if (items == NULL)
        return -1;
    memset(items + xattrs->capacity, 0,
           (capacity - xattrs->capacity) * sizeof(*items));
    xattrs->items = items;
    xattrs->capacity = capacity;
    return 0;
}

typedef struct {
    char **names;
    size_t count;
    size_t capacity;
} PendingReadbackNames;

static void pending_readback_names_free(PendingReadbackNames *pending)
{
    if (pending == NULL)
        return;
    for (size_t index = 0; index < pending->count; index++)
        free(pending->names[index]);
    free(pending->names);
    memset(pending, 0, sizeof(*pending));
}

static int pending_readback_names_reserve(PendingReadbackNames *pending,
                                          size_t extra)
{
    if (pending == NULL ||
        extra > PORTABLE_MAX_READBACK_NAMES - pending->count)
        return -1;
    size_t needed = pending->count + extra;
    if (needed <= pending->capacity)
        return 0;

    size_t capacity = pending->capacity == 0 ? 16U : pending->capacity * 2U;
    if (capacity < needed)
        capacity = needed;
    if (capacity > PORTABLE_MAX_READBACK_NAMES)
        capacity = PORTABLE_MAX_READBACK_NAMES;
    if (capacity > SIZE_MAX / sizeof(*pending->names))
        return -1;

    char **names = realloc(pending->names, capacity * sizeof(*names));
    if (names == NULL)
        return -1;
    memset(names + pending->capacity, 0,
           (capacity - pending->capacity) * sizeof(*names));
    pending->names = names;
    pending->capacity = capacity;
    return 0;
}

static int pending_readback_names_add(PendingReadbackNames *pending,
                                      const char *name)
{
    if (pending == NULL || name == NULL ||
        pending_readback_names_reserve(pending, 1) != 0)
        return -1;
    size_t length = strlen(name);
    char *copy = malloc(length + 1U);
    if (copy == NULL)
        return -1;
    memcpy(copy, name, length + 1U);
    pending->names[pending->count++] = copy;
    return 0;
}

static int encoded_name_has_raw_high_byte(const char *encoded)
{
    if (encoded == NULL)
        return 0;
    for (size_t index = 0; encoded[index] != '\0'; index++)
        if ((unsigned char)encoded[index] >= 0x80U)
            return 1;
    return 0;
}

static int verify_pending_readback_names(int destination_fd,
                                         const PendingReadbackNames *pending)
{
    if (destination_fd < 0 || pending == NULL)
        return -1;
    if (pending->count == 0)
        return 0;

    unsigned char *found = calloc(pending->count, sizeof(*found));
    if (found == NULL)
        return -1;
    int scan_fd = dup_cloexec(destination_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        free(found);
        return -1;
    }
    portable_readback_scan_count();

    int failed = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                failed = 1;
            break;
        }
        for (size_t index = 0; index < pending->count; index++) {
            if (!found[index] &&
                strcmp(entry->d_name, pending->names[index]) == 0) {
                found[index] = 1;
                break;
            }
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    for (size_t index = 0; index < pending->count; index++)
        if (!found[index]) {
            failed = 1;
        }
    free(found);
    return failed ? -1 : 0;
}

int collect_xattrs(int fd, PortableXattrs *out)
{
    if (fd < 0 || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    errno = 0;
    ssize_t length = flistxattr(fd, NULL, 0);
    if (length < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENODATA)
            return 0;
        return -1;
    }
    if ((uint64_t)length > SIDECAR_MAX_XATTRS_PER_ENTRY *
                           (uint64_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (length == 0)
        return 0;

    char *names = malloc((size_t)length);
    if (names == NULL)
        return -1;
    ssize_t received = flistxattr(fd, names, (size_t)length);
    if (received != length) {
        free(names);
        return -1;
    }

    size_t offset = 0;
    while (offset < (size_t)received) {
        size_t name_length = strnlen(names + offset,
                                    (size_t)received - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == (size_t)received - offset) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        if (xattrs_reserve(out, 1) != 0) {
            free(names);
            xattrs_free(out);
            return -1;
        }

        unsigned char *name_copy = malloc(name_length);
        if (name_copy == NULL) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        memcpy(name_copy, names + offset, name_length);

        errno = 0;
        ssize_t value_length = fgetxattr(fd, names + offset, NULL, 0);
        if (value_length < 0 || (uint64_t)value_length > SIDECAR_MAX_XATTR_VALUE) {
            free(name_copy);
            free(names);
            xattrs_free(out);
            return -1;
        }
        unsigned char *value_copy = NULL;
        if (value_length > 0) {
            value_copy = malloc((size_t)value_length);
            if (value_copy == NULL) {
                free(name_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
            ssize_t reread = fgetxattr(fd, names + offset, value_copy,
                                       (size_t)value_length);
            if (reread != value_length) {
                free(name_copy);
                free(value_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
        }
        out->items[out->count++] = (SidecarXattr){
            .name = { name_copy, name_length },
            .value = { value_copy, (size_t)value_length }
        };
        offset += name_length + 1U;
    }
    free(names);
    return 0;
}

int collect_symlink_xattrs(const char *path, PortableXattrs *out)
{
    if (path == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    errno = 0;
    ssize_t length = llistxattr(path, NULL, 0);
    if (length < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENODATA)
            return 0;
        return -1;
    }
    if ((uint64_t)length > SIDECAR_MAX_XATTRS_PER_ENTRY *
                           (uint64_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (length == 0)
        return 0;

    char *names = malloc((size_t)length);
    if (names == NULL)
        return -1;
    ssize_t received = llistxattr(path, names, (size_t)length);
    if (received != length) {
        free(names);
        return -1;
    }

    size_t offset = 0;
    while (offset < (size_t)received) {
        size_t name_length = strnlen(names + offset,
                                    (size_t)received - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == (size_t)received - offset) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        if (xattrs_reserve(out, 1) != 0) {
            free(names);
            xattrs_free(out);
            return -1;
        }

        unsigned char *name_copy = malloc(name_length);
        if (name_copy == NULL) {
            free(names);
            xattrs_free(out);
            return -1;
        }
        memcpy(name_copy, names + offset, name_length);

        errno = 0;
        ssize_t value_length = lgetxattr(path, names + offset, NULL, 0);
        if (value_length < 0 ||
            (uint64_t)value_length > SIDECAR_MAX_XATTR_VALUE) {
            free(name_copy);
            free(names);
            xattrs_free(out);
            return -1;
        }
        unsigned char *value_copy = NULL;
        if (value_length > 0) {
            value_copy = malloc((size_t)value_length);
            if (value_copy == NULL) {
                free(name_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
            ssize_t reread = lgetxattr(path, names + offset, value_copy,
                                       (size_t)value_length);
            if (reread != value_length) {
                free(name_copy);
                free(value_copy);
                free(names);
                xattrs_free(out);
                return -1;
            }
        }
        out->items[out->count++] = (SidecarXattr){
            .name = { name_copy, name_length },
            .value = { value_copy, (size_t)value_length }
        };
        offset += name_length + 1U;
    }
    free(names);
    return 0;
}

static int time_to_i64(time_t value, int64_t *out)
{
    if (out == NULL)
        return -1;
    intmax_t converted = (intmax_t)value;
    if ((time_t)converted != value || converted < INT64_MIN ||
        converted > INT64_MAX)
        return -1;
    *out = (int64_t)converted;
    return 0;
}

int entry_from_stat(const char *root_id, const char *logical,
                    const char *physical, const char *collision_suffix,
                    const struct stat *st, int nsec_exact,
                    PortableXattrs *xattrs, SidecarEntry *out,
                    const SidecarBytes *symlink_target,
                    const SidecarBytes *hardlink_root_id,
                    const SidecarBytes *hardlink_logical_path)
{
    int64_t atime_sec;
    int64_t mtime_sec;
    int hardlink_requested = hardlink_root_id != NULL ||
                             hardlink_logical_path != NULL;
    if (root_id == NULL || logical == NULL || physical == NULL ||
        collision_suffix == NULL ||
        st == NULL || out == NULL ||
        (st->st_mode & 07777) > SIDECAR_MAX_MODE || st->st_uid > UINT32_MAX ||
        st->st_gid > UINT32_MAX || st->st_size < 0 ||
        (uintmax_t)st->st_size > UINT64_MAX ||
        time_to_i64(st->st_atim.tv_sec, &atime_sec) != 0 ||
        time_to_i64(st->st_mtim.tv_sec, &mtime_sec) != 0)
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
    out->root_id = (SidecarBytes){ (const unsigned char *)root_id,
                                   strlen(root_id) };
    out->logical_path = (SidecarBytes){ (const unsigned char *)logical,
                                        strlen(logical) };
    out->physical_path = (SidecarBytes){ (const unsigned char *)physical,
                                         strlen(physical) };
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
    out->atime_sec = atime_sec;
    out->mtime_sec = mtime_sec;
    out->atime_nsec = nsec_exact ? (uint32_t)st->st_atim.tv_nsec : 0;
    out->mtime_nsec = nsec_exact ? (uint32_t)st->st_mtim.tv_nsec : 0;
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
    if (current == NULL || previous == NULL ||
        current->count != previous->xattr_count)
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
           sidecar_bytes_equal(current->physical_path, entry->physical_path) &&
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
    if (state == NULL || state->inode_map == NULL || state->request == NULL ||
        view == NULL || view->entry == NULL)
        return 1;
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
    if (inode_map == NULL || request == NULL || sidecar == NULL)
        return -1;
    StickySeedState state = {
        .inode_map = inode_map,
        .request = request,
        .failed = 0
    };
    SidecarStatus status = sidecar_log_foreach(sidecar, sticky_seed_callback,
                                               &state);
    return status == SIDECAR_STATUS_OK && state.failed == 0 ? 0 : -1;
}

void portable_owned_paths_free(PortableOwnedPaths *paths)
{
    if (paths == NULL)
        return;
    for (size_t index = 0; index < paths->count; index++) {
        free(paths->items[index].root_id);
        free(paths->items[index].physical_path);
        free(paths->items[index].logical_path);
    }
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static int portable_owned_paths_append(PortableOwnedPaths *paths,
                                       const SidecarLiveView *view)
{
    if (paths == NULL || view == NULL || view->entry == NULL ||
        paths->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (paths->count == paths->capacity) {
        size_t capacity = paths->capacity == 0 ? 16U : paths->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < paths->capacity ||
            capacity > SIZE_MAX / sizeof(*paths->items))
            return -1;
        PortableOwnedPath *items = realloc(paths->items,
                                           capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        paths->items = items;
        paths->capacity = capacity;
    }

    PortableOwnedPath item = {0};
    if (sidecar_bytes_to_text(view->entry->root_id, &item.root_id) != 0 ||
        sidecar_bytes_to_text(view->entry->physical_path,
                              &item.physical_path) != 0 ||
        sidecar_bytes_to_text(view->entry->logical_path,
                              &item.logical_path) != 0) {
        free(item.root_id);
        free(item.physical_path);
        free(item.logical_path);
        return -1;
    }
    paths->items[paths->count++] = item;
    return 0;
}

static int portable_owned_paths_callback(const SidecarLiveView *view,
                                         void *argument)
{
    PortableOwnedPaths *paths = argument;
    return portable_owned_paths_append(paths, view) == 0 ? 0 : 1;
}

static int portable_owned_path_compare(const void *left, const void *right)
{
    const PortableOwnedPath *left_path = left;
    const PortableOwnedPath *right_path = right;
    int result = strcmp(left_path->root_id, right_path->root_id);
    if (result != 0)
        return result;
    return strcmp(left_path->physical_path, right_path->physical_path);
}

int portable_owned_paths_load(PortableOwnedPaths *paths,
                                     SidecarLog *sidecar)
{
    if (paths == NULL || sidecar == NULL)
        return -1;
    SidecarStatus status = sidecar_log_foreach(
        sidecar, portable_owned_paths_callback, paths);
    if (status != SIDECAR_STATUS_OK)
        return -1;
    if (paths->count > 1U)
        qsort(paths->items, paths->count, sizeof(*paths->items),
              portable_owned_path_compare);
    for (size_t index = 1; index < paths->count; index++) {
        PortableOwnedPath *previous = &paths->items[index - 1U];
        PortableOwnedPath *current = &paths->items[index];
        if (strcmp(previous->root_id, current->root_id) == 0 &&
            strcmp(previous->physical_path, current->physical_path) == 0)
            return -1;
    }
    paths->sorted = 1;
    return 0;
}

const char *portable_owned_paths_owner(
    const PortableOwnedPaths *paths, const char *root_id,
    const char *physical_path)
{
    if (paths == NULL || !paths->sorted || root_id == NULL ||
        physical_path == NULL)
        return NULL;
    size_t low = 0;
    size_t high = paths->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        const PortableOwnedPath *item = &paths->items[middle];
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
    const PortableOwnedPath *item = &paths->items[low];
    return strcmp(item->root_id, root_id) == 0 &&
                   strcmp(item->physical_path, physical_path) == 0
               ? item->logical_path
               : NULL;
}

void portable_claimed_paths_free(PortableClaimedPaths *paths)
{
    if (paths == NULL)
        return;
    for (size_t index = 0; index < paths->count; index++) {
        free(paths->items[index].root_id);
        free(paths->items[index].physical_path);
        free(paths->items[index].logical_path);
    }
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static int portable_claimed_paths_append(PortableClaimedPaths *paths,
                                         const SidecarClaimView *view)
{
    if (paths == NULL || view == NULL || view->claim == NULL ||
        paths->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;
    if (paths->count == paths->capacity) {
        size_t capacity = paths->capacity == 0 ? 16U : paths->capacity * 2U;
        if (capacity > SIDECAR_MAX_LIVE_ENTRIES)
            capacity = SIDECAR_MAX_LIVE_ENTRIES;
        if (capacity < paths->capacity ||
            capacity > SIZE_MAX / sizeof(*paths->items))
            return -1;
        PortableClaimedPath *items = realloc(paths->items,
                                             capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        paths->items = items;
        paths->capacity = capacity;
    }

    PortableClaimedPath item = {0};
    if (sidecar_bytes_to_text(view->claim->root_id, &item.root_id) != 0 ||
        sidecar_bytes_to_text(view->claim->physical_path,
                              &item.physical_path) != 0 ||
        sidecar_bytes_to_text(view->claim->logical_path,
                              &item.logical_path) != 0) {
        free(item.root_id);
        free(item.physical_path);
        free(item.logical_path);
        return -1;
    }
    paths->items[paths->count++] = item;
    return 0;
}

static int portable_claimed_paths_callback(const SidecarClaimView *view,
                                           void *argument)
{
    PortableClaimedPaths *paths = argument;
    return portable_claimed_paths_append(paths, view) == 0 ? 0 : 1;
}

static int portable_claimed_path_compare(const void *left, const void *right)
{
    const PortableClaimedPath *left_path = left;
    const PortableClaimedPath *right_path = right;
    int result = strcmp(left_path->root_id, right_path->root_id);
    if (result != 0)
        return result;
    return strcmp(left_path->physical_path, right_path->physical_path);
}

int portable_claimed_paths_load(PortableClaimedPaths *paths,
                                       SidecarLog *sidecar)
{
    if (paths == NULL || sidecar == NULL)
        return -1;
    SidecarStatus status = sidecar_log_claim_foreach(
        sidecar, portable_claimed_paths_callback, paths);
    if (status != SIDECAR_STATUS_OK)
        return -1;
    if (paths->count > 1U)
        qsort(paths->items, paths->count, sizeof(*paths->items),
              portable_claimed_path_compare);
    for (size_t index = 1; index < paths->count; index++) {
        PortableClaimedPath *previous = &paths->items[index - 1U];
        PortableClaimedPath *current = &paths->items[index];
        if (strcmp(previous->root_id, current->root_id) == 0 &&
            strcmp(previous->physical_path, current->physical_path) == 0)
            return -1;
    }
    paths->sorted = 1;
    return 0;
}

int relative_path_prefix_match(const char *prefix, const char *path,
                               const char **relative_out)
{
    if (prefix == NULL || path == NULL)
        return 0;
    size_t prefix_length = strlen(prefix);
    if (strcmp(prefix, path) == 0)
    {
        if (relative_out != NULL)
            *relative_out = path + prefix_length;
        return 1;
    }
    if (strncmp(prefix, path, prefix_length) == 0 &&
        path[prefix_length] == '/')
    {
        if (relative_out != NULL)
            *relative_out = path + prefix_length + 1U;
        return 1;
    }
    return 0;
}


static int key_is_live(PortableCaptureContext *context,
                       const char *root_id, const char *logical)
{
    SidecarLiveView view;
    SidecarBytes root = { (const unsigned char *)root_id, strlen(root_id) };
    SidecarBytes path = { (const unsigned char *)logical, strlen(logical) };
    int found = sidecar_log_find(context->sidecar, root, path, &view);
    return found < 0 ? -1 : found;
}

int remove_payload_relative(int data_fd, const char *payload_root,
                                   const char *physical);

static int capture_destination_is_safe(const PortableCaptureContext *context,
                                       const PortableRootSpec *root,
                                       const char *logical,
                                       const char *physical,
                                       int parent_fd, const char *leaf)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL || parent_fd < 0 || !safe_component(leaf))
        return -1;
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    if (!context->resume_mode)
        return 0;
    if (context->owned_paths == NULL)
        return -1;
    const PortableOwnedPaths *owned = context->owned_paths;
    const char *owner = portable_owned_paths_owner(owned, root->id,
                                                   physical);
    if (owner != NULL && strcmp(owner, logical) == 0)
        return 0;

    /* A resume may have been interrupted after its DELETE record was
     * committed but before the replacement payload was published.  The
     * matching tombstone is still this container's ownership proof for the
     * old physical name; a missing or mismatching tombstone remains foreign. */
    SidecarLiveView deleted;
    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    int found = sidecar_log_find_deleted(context->sidecar, root_key,
                                         logical_key, &deleted);
    if (found < 0)
        return -1;
    return found == 1 &&
                   sidecar_bytes_equal(
                       deleted.entry->physical_path,
                       (SidecarBytes){
                           (const unsigned char *)physical,
                           strlen(physical) })
               ? 0
               : -1;
}

/* During resume, an interrupted claim is also ownership proof for the
 * payload that was created after the claim and before its ENTRY_COMMIT.
 * Keep the existing owned-path and tombstone checks intact.  A same-key,
 * same-physical claim remains ownership proof even when the source kind has
 * changed; append_capture_claim() then reconciles that old kind before
 * publishing the replacement claim. */
static int capture_destination_is_safe_or_claimed(
    const PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, const char *physical, int parent_fd,
    const char *leaf)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL)
        return -1;

    int result = capture_destination_is_safe(context, root, logical, physical,
                                             parent_fd, leaf);
    if (result == 0 || !context->resume_mode)
        return result;

    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarBytes physical_key = {
        (const unsigned char *)physical, strlen(physical)
    };
    SidecarClaimView claim_view = {0};
    int found = sidecar_log_find_claim(context->sidecar, root_key,
                                       logical_key, &claim_view);
    if (found < 0)
        return -1;
    if (found == 1 && claim_view.claim != NULL &&
        sidecar_bytes_equal(claim_view.claim->root_id, root_key) &&
        sidecar_bytes_equal(claim_view.claim->logical_path, logical_key) &&
        sidecar_bytes_equal(claim_view.claim->physical_path, physical_key))
        return 0;
    return result;
}

int tombstone_if_live(PortableCaptureContext *context,
                             const char *root_id, const char *logical)
{
    int live = key_is_live(context, root_id, logical);
    if (live < 0)
        return -1;
    if (!live)
        return 0;
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)root_id, strlen(root_id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) }
    };
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE);
    int result = sidecar_log_append_delete(context->sidecar, &deletion) ==
                         SIDECAR_STATUS_OK ? 0 : -1;
    if (result == 0)
        portable_test_interrupt_if(PORTABLE_TEST_AFTER_REPLACEMENT_DELETE);
    return result;
}

static int replace_live_capture(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical,
                                const char *physical)
{
    if (context == NULL || root == NULL || logical == NULL ||
        root->payload_path == NULL)
        return -1;

    SidecarBytes root_key = {
        (const unsigned char *)root->id, strlen(root->id)
    };
    SidecarBytes logical_key = {
        (const unsigned char *)logical, strlen(logical)
    };
    SidecarLiveView previous;
    int live = sidecar_log_find(context->sidecar, root_key, logical_key,
                                &previous);
    if (live < 0)
        return -1;
    if (!live)
        return 0;

    int remove_old = physical != NULL &&
        !sidecar_bytes_equal(previous.entry->physical_path,
                             (SidecarBytes){
                                 (const unsigned char *)physical,
                                 strlen(physical) });
    char *old_physical = NULL;
    if (remove_old &&
        sidecar_bytes_to_text(previous.entry->physical_path, &old_physical) != 0)
        return -1;

    SidecarDelete deletion = {
        .root_id = root_key,
        .logical_path = logical_key
    };
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE);
    if (sidecar_log_append_delete(context->sidecar, &deletion) !=
        SIDECAR_STATUS_OK) {
        free(old_physical);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_REPLACEMENT_DELETE);

    if (remove_old) {
        int result = remove_payload_relative(context->data_fd,
                                             root->payload_path,
                                             old_physical);
        free(old_physical);
        if (result != 0)
            return -1;
    }
    return 0;
}

static int tombstone_destination_children(PortableCaptureContext *context,
                                          const char *root_id,
                                          const char *logical,
                                          int parent_fd,
                                          const char *leaf)
{
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
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

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0 ||
            tombstone_if_live(context, root_id, child_logical) != 0 ||
            tombstone_destination_children(context, root_id, child_logical,
                                           directory_fd, entry->d_name) != 0) {
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

static int append_group(PortableCaptureContext *context,
                        const SidecarEntry *entry,
                        const PortableXattrs *xattrs)
{
    SidecarStatus status = sidecar_log_append_entry(context->sidecar, entry);
    if (status != SIDECAR_STATUS_OK)
        return -1;
    for (size_t index = 0; xattrs != NULL && index < xattrs->count; index++)
        if (sidecar_log_append_xattr(context->sidecar, &xattrs->items[index]) !=
            SIDECAR_STATUS_OK)
            return -1;
    status = sidecar_log_append_entry_commit(context->sidecar);
    return status == SIDECAR_STATUS_OK ? 0 : -1;
}

static int append_capture_claim(PortableCaptureContext *context,
                                const PortableRootSpec *root,
                                const char *logical, const char *physical,
                                SidecarObjectKind kind)
{
    if (context == NULL || root == NULL || root->id == NULL ||
        logical == NULL || physical == NULL)
        return -1;
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)root->id, strlen(root->id) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) },
        .physical_path = { (const unsigned char *)physical, strlen(physical) },
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
            sidecar_bytes_equal(existing.claim->physical_path,
                                claim.physical_path) &&
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

int remove_payload_relative(int data_fd, const char *payload_root,
                                   const char *physical)
{
    if (data_fd < 0 || payload_root == NULL || physical == NULL)
        return -1;

    int root_parent = -1;
    char root_leaf[NAME_MAX + 1U];
    if (open_existing_payload_parent(data_fd, payload_root, &root_parent,
                                     root_leaf, sizeof(root_leaf)) != 0)
        return errno == ENOENT ? 0 : -1;

    if (physical[0] == '\0') {
        int result = remove_leaf(root_parent, root_leaf);
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
    if (payload_fd >= 0) {
        if (close(root_parent) != 0) {
            saved = errno;
            close(payload_fd);
            errno = saved;
            return -1;
        }
    } else if (close(root_parent) != 0) {
        saved = errno;
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
        if (close(payload_fd) != 0)
            return -1;
        errno = saved;
        return errno == ENOENT ? 0 : -1;
    }
    int result = remove_leaf(parent_fd, leaf);
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
    if (target == NULL || target_size == 0)
        return -1;
    ssize_t length;
    if (source_parent >= 0) {
        if (source_name == NULL)
            return -1;
        length = readlinkat(source_parent, source_name, target, target_size);
    } else {
        if (root_path == NULL)
            return -1;
        length = readlink(root_path, target, target_size);
    }
    if (length <= 0 || (size_t)length >= target_size)
        return -1;
    target[length] = '\0';
    return (int)length;
}

static int source_symlink_xattr_path(int source_parent,
                                     const char *source_name,
                                     const char *root_path, char *path,
                                     size_t path_size)
{
    if (path == NULL || path_size == 0)
        return -1;
    if (source_parent < 0)
        return copy_text(path, path_size, root_path);
    if (source_name == NULL || !safe_component(source_name))
        return -1;
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

int portable_copy_regular(int source_fd, int destination_fd, off_t expected_size,
                          BackupCaptureReport *report)
{
    if (source_fd < 0 || destination_fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (ftruncate(destination_fd, 0) != 0)
        return -1;

    unsigned char buffer[65536];
    uint64_t copied = 0;
    for (;;) {
        ssize_t received = read(source_fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            return -1;
        if (received == 0)
            break;
        if ((uint64_t)received > UINT64_MAX - copied)
        {
            errno = EOVERFLOW;
            return -1;
        }

        size_t offset = 0;
        while (offset < (size_t)received) {
            ssize_t written = write(destination_fd, buffer + offset,
                                     (size_t)received - offset);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0)
                return -1;
            offset += (size_t)written;
        }
        copied += (uint64_t)received;
        if (backup_capture_report_tick(report, received, destination_fd) != 0)
            return -1;
    }
    if (expected_size < 0 || copied != (uint64_t)expected_size)
    {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int physical_path_parent_matches(const char *physical,
                                        const char *parent)
{
    if (physical == NULL || parent == NULL)
        return 0;
    const char *slash = strrchr(physical, '/');
    if (slash == NULL)
        return parent[0] == '\0';
    size_t parent_length = (size_t)(slash - physical);
    return strlen(parent) == parent_length &&
           memcmp(physical, parent, parent_length) == 0;
}

static int physical_path_leaf(const char *physical, char *leaf,
                              size_t leaf_size)
{
    if (physical == NULL || leaf == NULL || leaf_size == 0 ||
        physical[0] == '\0')
        return -1;
    const char *slash = strrchr(physical, '/');
    const char *name = slash == NULL ? physical : slash + 1;
    if (!safe_component(name))
        return -1;
    return copy_text(leaf, leaf_size, name);
}

static int capture_plan_child(const PortableCaptureContext *context,
                              const PortableRootSpec *root,
                              const char *logical, const char *parent_physical,
                              const char *encoded_leaf,
                              char *physical, size_t physical_size,
                              char *leaf, size_t leaf_size)
{
    if (context == NULL || root == NULL || logical == NULL ||
        parent_physical == NULL || encoded_leaf == NULL || physical == NULL ||
        leaf == NULL)
        return -1;

    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(context->collision_plan, root->id,
                                     logical);
    if (planned == NULL) {
        if (append_physical(physical, physical_size, parent_physical,
                            encoded_leaf) != 0 ||
            copy_text(leaf, leaf_size, encoded_leaf) != 0)
            return -1;
        return 0;
    }

    if (!physical_path_parent_matches(planned->physical_path,
                                      parent_physical) ||
        copy_text(physical, physical_size, planned->physical_path) != 0 ||
        physical_path_leaf(planned->physical_path, leaf, leaf_size) != 0)
        return -1;
    return 0;
}

static int capture_plan_entries_seen(const PortableCaptureContext *context,
                                    const PortableRootSpec *root)
{
    if (context == NULL || root == NULL)
        return -1;
    const PortableCollisionPlan *plan = context->collision_plan;
    if (plan == NULL)
        return 0;
    for (size_t index = 0; index < plan->count; index++) {
        const PortableCollisionPlanEntry *entry = &plan->entries[index];
        if (strcmp(entry->root_id, root->id) != 0)
            continue;
        int present = visited_contains(context->visited, root->id,
                                       entry->logical_path);
        if (present != 1)
            return -1;
    }
    return 0;
}

static int capture_node(PortableCaptureContext *context,
                        const PortableRootSpec *root,
                        const char *logical, const char *physical,
                        int source_parent,
                        const char *source_name, const char *root_path,
                        int destination_parent, const char *destination_leaf);

static int capture_directory(PortableCaptureContext *context,
                             const PortableRootSpec *root,
                             const char *logical, const char *physical,
                             int source_fd,
                             const struct stat *before, int destination_fd,
                             PortableXattrs *xattrs,
                             const char *collision_suffix)
{
    PendingReadbackNames pending = {0};
    int scan_fd = dup_cloexec(source_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
    int failed = 0;
    PortableCaseFoldSet observed_skeletons = {0};
    PortableCaseFoldSet observed_ascii = {0};
    if (!context->case_sensitive)
        observed_skeletons.hash_salt = sidecar_process_salt();
    if (!context->case_sensitive)
        observed_ascii.hash_salt = sidecar_process_salt();
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

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0) {
            failed = 1;
            break;
        }

        char encoded_leaf[NAME_MAX + 1U];
        if (encoding_percent_encode(ENCODING_MODE_COMPONENT, entry->d_name,
                                    encoded_leaf, sizeof(encoded_leaf)) != 0) {
            failed = 1;
            break;
        }

        if (!context->case_sensitive) {
            char skeleton[NAME_MAX + 1U];
            char ascii_skeleton[NAME_MAX + 1U];
            skeleton_copy(skeleton, sizeof(skeleton), encoded_leaf);
            ascii_fold_copy(ascii_skeleton, sizeof(ascii_skeleton),
                            encoded_leaf);
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
                failed = 1;
                break;
            }
        }

        char child_physical[SIDECAR_MAX_PATH + 1U];
        char child_leaf[NAME_MAX + 1U];
        if (capture_plan_child(context, root, child_logical, physical,
                               encoded_leaf, child_physical,
                               sizeof(child_physical), child_leaf,
                               sizeof(child_leaf)) != 0) {
            failed = 1;
            break;
        }

        size_t payload_root_length = strlen(root->payload_path);
        size_t physical_length = strlen(child_physical);
        if (!portable_payload_path_fits(payload_root_length, physical_length,
                                        PATH_MAX)) {
            failed = 1;
            break;
        }

        if (encoded_name_has_raw_high_byte(child_leaf) &&
            pending_readback_names_add(&pending, child_leaf) != 0) {
            failed = 1;
            break;
        }

        if (capture_node(context, root, child_logical, child_physical,
                         source_fd, entry->d_name, NULL, destination_fd,
                         child_leaf) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;

    case_fold_set_free(&observed_skeletons);
    case_fold_set_free(&observed_ascii);

    struct stat after;
    if (!failed && (fstat(source_fd, &after) != 0 ||
                    !metadata_source_unchanged(before, &after)))
        failed = 1;

    if (!failed && verify_pending_readback_names(destination_fd, &pending) != 0)
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    if (failed) {
        pending_readback_names_free(&pending);
        xattrs_free(xattrs);
        close(destination_fd);
        return -1;
    }

    SidecarEntry sidecar_entry;
    if (entry_from_stat(root->id, logical, physical, collision_suffix, before,
                        context->nsec_exact,
                        xattrs, &sidecar_entry, NULL, NULL, NULL) != 0 ||
        append_group(context, &sidecar_entry, xattrs) != 0) {
        pending_readback_names_free(&pending);
        xattrs_free(xattrs);
        close(destination_fd);
        return -1;
    }
    pending_readback_names_free(&pending);
    xattrs_free(xattrs);
    return close(destination_fd) == 0 ? 0 : -1;
}

static int capture_regular(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical,
                           const char *collision_suffix,
                           int source_fd,
                           const struct stat *before,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           PortableXattrs *xattrs)
{
    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_REGULAR) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_WRITE);
    if (context->progress_report != NULL)
        snprintf(context->progress_report->current_path,
                 sizeof(context->progress_report->current_path), "%s", physical);
    if (portable_copy_regular(source_fd, destination_fd, before->st_size,
                              context->progress_report) != 0) {
        close(destination_fd);
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_WRITE);

    struct stat after;
    int failed = fstat(source_fd, &after) != 0 ||
                 !metadata_source_unchanged(before, &after);
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE);
    if (close(destination_fd) != 0)
        failed = 1;
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_CLOSE);
    if (close(source_fd) != 0)
        failed = 1;
    if (destination_is_root)
        close(parent_fd);
    if (failed) {
        xattrs_free(xattrs);
        return -1;
    }

    SidecarEntry sidecar_entry;
    failed = entry_from_stat(root->id, logical, physical, collision_suffix,
                             before,
                             context->nsec_exact,
                             xattrs, &sidecar_entry, NULL, NULL, NULL) != 0 ||
             append_group(context, &sidecar_entry, xattrs) != 0;
    xattrs_free(xattrs);
    return failed ? -1 : 0;
}

static int capture_special(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root, const struct stat *st)
{
    if (visited_add(context->visited, root->id, logical) != 0)
        return -1;

    if (context->resume_mode) {
        SidecarBytes root_key = {
            (const unsigned char *)root->id, strlen(root->id)
        };
        SidecarBytes logical_key = {
            (const unsigned char *)logical, strlen(logical)
        };
        SidecarClaimView existing = {0};
        int found = sidecar_log_find_claim(context->sidecar, root_key,
                                           logical_key, &existing);
        if (found < 0 ||
            (found == 1 &&
             (existing.claim == NULL ||
              reconcile_stale_claim(context, root, logical,
                                    existing.claim) != 0)))
            return -1;
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0)
            return -1;
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe(context, root, logical, physical,
                                    parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        return -1;
    }
    if (remove_leaf(parent_fd, destination_leaf) != 0) {
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
                           const char *logical, const char *physical,
                           const char *collision_suffix,
                           int source_parent,
                           const char *source_name, const char *root_path,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           const struct stat *before)
{
    char target[SIDECAR_MAX_SYMLINK_TARGET + 1U];
    int target_length = source_symlink_target(source_parent, source_name,
                                              root_path, target,
                                              sizeof(target));
    if (target_length < 0)
        return -1;

    char source_path[PATH_MAX];
    if (source_symlink_xattr_path(source_parent, source_name, root_path,
                                  source_path, sizeof(source_path)) != 0)
        return -1;
    PortableXattrs xattrs;
    if (collect_symlink_xattrs(source_path, &xattrs) != 0)
        return -1;

    // The final consistency check runs after every path-based read (target,
    // then xattrs) rather than right after the target read: symlinks have no
    // usable fd (open_source_node's O_NOFOLLOW would hit ELOOP), so each read
    // above re-resolves the path independently and nothing pins them to one
    // inode the way capture_regular's single fd does. One check positioned
    // last covers the read window for both.
    struct stat after;
    if (read_source_stat(source_parent, source_name, root_path, &after) != 0 ||
        !metadata_symlink_unchanged(before, &after)) {
        xattrs_free(&xattrs);
        return -1;
    }

    if (visited_add(context->visited, root->id, logical) != 0) {
        xattrs_free(&xattrs);
        return -1;
    }

    SidecarBytes target_bytes = {
        (const unsigned char *)target, (size_t)target_length
    };
    SidecarEntry entry;
    if (entry_from_stat(root->id, logical, physical, collision_suffix, before,
                        context->nsec_exact,
                        &xattrs, &entry, &target_bytes, NULL, NULL) != 0) {
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
            xattrs_free(&xattrs);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }

    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_SYMLINK) != 0) {
        if (destination_is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
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
                            const char *logical, const char *physical,
                            const char *collision_suffix,
                            int source_fd, const struct stat *before,
                            int destination_parent,
                            const char *destination_leaf,
                            int destination_is_root,
                            const PortableInodeSlot *representative)
{
    if (context == NULL || root == NULL || logical == NULL ||
        physical == NULL || collision_suffix == NULL || source_fd < 0 ||
        before == NULL || representative == NULL)
        return -1;

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
    if (entry_from_stat(root->id, logical, physical, collision_suffix, before,
                        context->nsec_exact, &empty_xattrs, &entry, NULL,
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
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }
    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_HARDLINK) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    if (tombstone_destination_children(context, root->id, logical, parent_fd,
                                       destination_leaf) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE);
    if (ensure_regular_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        if (destination_is_root)
            close(parent_fd);
        close(source_fd);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_PAYLOAD_REPLACE);

    struct stat after;
    int failed = fstat(source_fd, &after) != 0 ||
                 !metadata_source_unchanged(before, &after);
    if (close(destination_fd) != 0)
        failed = 1;
    if (destination_is_root && close(parent_fd) != 0)
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    if (failed)
        return -1;

    return append_group(context, &entry, NULL) == 0 ? 0 : -1;
}

static int capture_node(PortableCaptureContext *context,
                        const PortableRootSpec *root,
                        const char *logical, const char *physical,
                        int source_parent,
                        const char *source_name, const char *root_path,
                        int destination_parent, const char *destination_leaf)
{
    struct stat before;
    if (read_source_stat(source_parent, source_name, root_path, &before) != 0)
        return -1;

    const char *collision_suffix = "";
    const PortableCollisionPlanEntry *planned =
        portable_collision_plan_find(context->collision_plan, root->id,
                                     logical);
    if (planned != NULL) {
        if (strcmp(planned->physical_path, physical) != 0)
            return -1;
        collision_suffix = planned->collision_suffix;
    }

    int is_root = source_parent < 0;
    if (S_ISSOCK(before.st_mode) || S_ISCHR(before.st_mode) ||
        S_ISBLK(before.st_mode))
        return capture_special(context, root, logical, physical,
                               destination_parent, destination_leaf, is_root,
                               &before);
    if (S_ISFIFO(before.st_mode)) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (S_ISLNK(before.st_mode))
        return capture_symlink(context, root, logical, physical,
                               collision_suffix, source_parent,
                               source_name, root_path, destination_parent,
                               destination_leaf, is_root, &before);
    if (!S_ISREG(before.st_mode) && !S_ISDIR(before.st_mode)) {
        errno = EOPNOTSUPP;
        return -1;
    }

    int source_fd = open_source_node(source_parent, source_name, root_path,
                                     &before);
    if (source_fd < 0)
        return -1;
    struct stat opened;
    if (fstat(source_fd, &opened) != 0 ||
        !metadata_source_unchanged(&before, &opened)) {
        close(source_fd);
        return -1;
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
        int same_logical_entry = inode_state == 1 && representative != NULL &&
                                 strcmp(representative->root_id, root->id) == 0 &&
                                 strcmp(representative->logical_path, logical) == 0;
        if (inode_state == 1 && !same_logical_entry) {
            return capture_hardlink(context, root, logical, physical,
                                    collision_suffix, source_fd, &before,
                                    destination_parent, destination_leaf,
                                    is_root, representative);
        }
    }

    PortableXattrs xattrs;
    if (collect_xattrs(source_fd, &xattrs) != 0) {
        close(source_fd);
        return -1;
    }

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
        if (live == 1) {
            SidecarEntry current;
            int matches = entry_from_stat(root->id, logical, physical,
                                          collision_suffix, &before,
                                          context->nsec_exact, &xattrs,
                                          &current, NULL, NULL, NULL) == 0 &&
                          entries_equal(&current, &previous, &xattrs);
            if (matches) {
                int payload = existing_payload_matches(
                    context->data_fd, root->payload_path, destination_parent,
                    destination_leaf, is_root, current.size);
                if (payload < 0) {
                    xattrs_free(&xattrs);
                    close(source_fd);
                    return -1;
                }
                if (payload == 1) {
                    xattrs_free(&xattrs);
                    return close(source_fd) == 0 ? 0 : -1;
                }
            }
        }
    }

    if (S_ISREG(before.st_mode))
        return capture_regular(context, root, logical, physical,
                               collision_suffix, source_fd,
                               &before,
                               destination_parent, destination_leaf, is_root,
                               &xattrs);

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (is_root) {
        if (portable_open_relative_parent(context->data_fd,
                                          root->payload_path, &parent_fd,
                                          root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(&xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
    }

    if (capture_destination_is_safe_or_claimed(
            context, root, logical, physical, parent_fd, destination_leaf) != 0 ||
        replace_live_capture(context, root, logical, physical) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    if (append_capture_claim(context, root, logical, physical,
                             SIDECAR_KIND_DIRECTORY) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    int destination_fd;
    if (ensure_directory_leaf(parent_fd, destination_leaf, &destination_fd) != 0) {
        if (is_root)
            close(parent_fd);
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }
    if (capture_directory(context, root, logical, physical, source_fd, &before,
                          destination_fd, &xattrs, collision_suffix) != 0) {
        if (is_root)
            close(parent_fd);
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
    if (root->policy < ROOT_POLICY_XDG ||
        root->policy > ROOT_POLICY_MANUAL_NATIVE)
        return 0;
    if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
        return 0;
    if (root->policy == ROOT_POLICY_HOME_RELATIVE) {
        if (!root->has_restore_path || root->restore_path == NULL)
            return 0;
    } else if (root->has_restore_path) {
        return 0;
    }
    if (root->has_restore_path && root->restore_path == NULL)
        return 0;
    if (root->has_restore_path && root->restore_path[0] != '\0' &&
        !safe_relative_path(root->restore_path))
        return 0;
    return strlen(root->capture_path) < PATH_MAX &&
           strlen(root->source_path) < PATH_MAX &&
           (!root->has_restore_path || strlen(root->restore_path) < PATH_MAX);
}


static int build_manifest(const PortableCaptureRequest *request,
                          Manifest *manifest)
{
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
    }

    if (request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
        return -1;
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
        if (copy_text(destination->id, sizeof(destination->id), source->id) != 0 ||
            copy_text(destination->payload_path, sizeof(destination->payload_path),
                      source->payload_path) != 0 ||
            copy_text(destination->source_path, sizeof(destination->source_path),
                      source->source_path) != 0)
            goto fail;
        destination->policy = source->policy;
        destination->has_restore_path = source->has_restore_path;
        if (source->has_restore_path &&
            copy_text(destination->restore_path, sizeof(destination->restore_path),
                      source->restore_path) != 0)
            goto fail;
    }
    return 0;

fail:
    manifest_free(manifest);
    return -1;
}

int portable_capture_prepare(int scratch_fd,
                             const PortableCaptureRequest *request,
                             PortablePreparedCapture *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    if (scratch_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
        return -1;

    portable_prescan_report_init(&out->report);
    if (prescan_request(scratch_fd, request, &out->report) != 0)
        return -1;
    if (build_manifest(request, &out->manifest) != 0)
        return -1;
    out->ready = 1;
    return 0;
}

void portable_prepared_capture_free(PortablePreparedCapture *prepared)
{
    if (prepared == NULL)
        return;
    manifest_free(&prepared->manifest);
    portable_prescan_report_free(&prepared->report);
    memset(prepared, 0, sizeof(*prepared));
}

static int data_namespace_is_empty(int data_fd)
{
    if (data_fd < 0)
        return -1;
    struct stat st;
    if (fstat(data_fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    int empty = 1;
    int scan_fd = dup_cloexec(data_fd);
    DIR *directory = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (directory == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return -1;
    }
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
                                  int nsec_exact, int case_sensitive)
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
    PortableOwnedPaths *owned_paths = calloc(1, sizeof(*owned_paths));
    if (owned_paths == NULL) {
        free(visited);
        return -1;
    }
    PortableClaimedPaths *claimed_paths = calloc(1, sizeof(*claimed_paths));
    if (claimed_paths == NULL) {
        free(owned_paths);
        free(visited);
        return -1;
    }
    PortableInodeMap *inode_map = calloc(1, sizeof(*inode_map));
    if (inode_map == NULL) {
        free(claimed_paths);
        free(owned_paths);
        free(visited);
        return -1;
    }
    context->data_fd = data_fd;
    context->sidecar = sidecar;
    context->nsec_exact = nsec_exact != 0;
    context->case_sensitive = case_sensitive != 0;
    visited->hash_salt = sidecar_process_salt();
    inode_map->hash_salt = sidecar_process_salt();
    context->visited = visited;
    context->inode_map = inode_map;
    context->owned_paths = owned_paths;
    context->claimed_paths = claimed_paths;
    return 0;
}

void portable_capture_context_close(PortableCaptureContext *context)
{
    if (context == NULL)
        return;
    visited_free(context->visited);
    inode_map_free(context->inode_map);
    portable_owned_paths_free(context->owned_paths);
    free(context->owned_paths);
    portable_claimed_paths_free(context->claimed_paths);
    free(context->claimed_paths);
    memset(context, 0, sizeof(*context));
}

int portable_capture_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    if (context == NULL || context->visited == NULL ||
        context->inode_map == NULL ||
        context->data_fd < 0 || context->sidecar == NULL ||
        !root_spec_valid(root))
        return -1;
    /* visited is root-local; inode_map spans every root in this context. */
    PortableVisited *visited = context->visited;
    if (visited_reset(visited) != 0)
        return -1;
    if (prepare_collision_relocations(context, root) != 0)
        return -1;
    int result = capture_node(context, root, "", "", -1, NULL,
                              root->capture_path, -1, NULL);
    if (result != 0)
        return result;
    return capture_plan_entries_seen(context, root);
}

int portable_capture_fresh_prepared_at(
    int container_fd, const PortableCaptureRequest *request,
    const PortablePreparedCapture *prepared, size_t *live_count,
    BackupCaptureReport *progress_report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL) ||
        prepared == NULL || !prepared->ready ||
        fresh_namespace_is_empty(container_fd) != 0)
        return -1;

    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = -1;
    int sidecar_ready = 0;
    int context_ready = 0;
    int result = -1;

    if (manifest_write_v1_at(container_fd, &prepared->manifest) != 0)
        goto done;
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_MANIFEST);

    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST) {
        goto done;
    }
    data_fd = openat(container_fd, "data",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0) {
        goto done;
    }

    if (sidecar_log_create_at(container_fd, &sidecar) != SIDECAR_OPEN_FRESH) {
        goto done;
    }
    sidecar_ready = 1;

    int failed = portable_capture_context_init(&context, data_fd, &sidecar,
                                               request->nsec_exact,
                                               request->case_sensitive) != 0;
    if (!failed) {
        context_ready = 1;
        context.progress_report = progress_report;
        context.collision_plan = &prepared->report.collision_plan;
        if (portable_owned_paths_load(context.owned_paths, &sidecar) != 0 ||
            portable_claimed_paths_load(context.claimed_paths, &sidecar) != 0 ||
            sticky_seed_inode_map(context.inode_map, request, &sidecar) != 0)
            failed = 1;
    }
    for (size_t index = 0; !failed && index < request->root_count; index++)
    {
        if (verbose)
            printf("  Capturing: %s -> data/%s\n",
                   request->roots[index].capture_path,
                   request->roots[index].payload_path);
        if (portable_capture_root(&context, &request->roots[index]) != 0 ||
            reconcile_root(&context, &request->roots[index]) != 0)
            failed = 1;
    }
    if (!failed && sidecar_log_claim_count(&sidecar) != 0)
        failed = 1;
    if (!failed && live_count != NULL)
        *live_count = sidecar_log_live_count(&sidecar);
    result = failed ? -1 : 0;

done:
    if (context_ready)
        portable_capture_context_close(&context);
    if (sidecar_ready && sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (data_fd >= 0 && close(data_fd) != 0)
        result = -1;
    return result;
}

int portable_capture_fresh_at(int container_fd,
                              const PortableCaptureRequest *request,
                              PortablePrescanReport *report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL) ||
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
    if (container_fd < 0 || out_fd == NULL)
        return -1;
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
    if (container_fd < 0 || out_fd == NULL)
        return -1;
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
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL) ||
        prepared == NULL || !prepared->ready)
        return -1;

    Manifest existing = {0};
    SidecarLog sidecar = {0};
    PortableCaptureContext context = {0};
    int data_fd = -1;
    int context_ready = 0;
    int result = -1;

    ManifestStatus manifest_status = manifest_read_v1_at(container_fd,
                                                         &existing);
    if (manifest_status != MANIFEST_STATUS_VALID) {
        goto done;
    }
    ManifestIdentityComparison identity =
        manifest_resume_identity_compare(&existing, &prepared->manifest);
    if (identity != MANIFEST_IDENTITY_EQUAL) {
        goto done;
    }

    int data_state = open_existing_data(container_fd, &data_fd);
    if (data_state < 0)
        goto done;
    int data_missing = data_state == 1;

    SidecarOpenStatus sidecar_status = sidecar_log_adopt_at(container_fd,
                                                            &sidecar);
    int failed = 0;
    if (sidecar_status == SIDECAR_OPEN_MISSING) {
        if (data_missing) {
            if (create_resume_data(container_fd, &data_fd) != 0)
                failed = 1;
        }
        if (!failed && data_namespace_is_empty(data_fd) != 0)
            failed = 1;
        if (!failed &&
            sidecar_log_create_at(container_fd, &sidecar) !=
                SIDECAR_OPEN_FRESH)
            failed = 1;
    } else if (sidecar_status != SIDECAR_OPEN_RESUMABLE || data_missing) {
        failed = 1;
    }

    if (!failed && portable_capture_context_init(&context, data_fd, &sidecar,
                                                request->nsec_exact,
                                                request->case_sensitive) != 0)
        failed = 1;
    if (!failed) {
        context_ready = 1;
        context.progress_report = progress_report;
        context.resume_mode = 1;
        context.collision_plan = &prepared->report.collision_plan;
        if (portable_owned_paths_load(context.owned_paths, &sidecar) != 0 ||
            portable_claimed_paths_load(context.claimed_paths, &sidecar) != 0 ||
            sticky_seed_inode_map(context.inode_map, request, &sidecar) != 0)
            failed = 1;
        for (size_t index = 0; !failed && index < request->root_count;
             index++) {
            if (verbose)
                printf("  Capturing: %s -> data/%s\n",
                       request->roots[index].capture_path,
                       request->roots[index].payload_path);
            if (portable_capture_root(&context, &request->roots[index]) != 0 ||
                reconcile_root(&context, &request->roots[index]) != 0) {
                failed = 1;
                break;
            }
        }
    }
    if (!failed && sidecar_log_claim_count(&sidecar) != 0)
        failed = 1;
    if (!failed && live_count != NULL)
        *live_count = sidecar_log_live_count(&sidecar);
    result = failed ? -1 : 0;

done:
    if (context_ready)
        portable_capture_context_close(&context);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        result = -1;
    if (data_fd >= 0 && close(data_fd) != 0)
        result = -1;
    manifest_free(&existing);
    return result;
}

int portable_capture_resume_at(int container_fd,
                               const PortableCaptureRequest *request,
                               PortablePrescanReport *report)
{
    if (container_fd < 0 || request == NULL ||
        request->scope < MANIFEST_SCOPE_CRITICAL ||
        request->scope > MANIFEST_SCOPE_EXPLICIT ||
        request->root_count > MANIFEST_MAX_ROOTS ||
        (request->root_count != 0 && request->roots == NULL))
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
