#define _GNU_SOURCE

#include "portable.h"

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

typedef struct {
    char *root_id;
    char *logical_path;
    size_t root_length;
    size_t logical_length;
    uint64_t hash;
} PortableVisitedSlot;

typedef struct {
    PortableVisitedSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} PortableVisited;

#define VISITED_INITIAL_CAPACITY 16U
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
    memset(report, 0, sizeof(*report));
}

int prescan_report_add(PortablePrescanReport *report,
                       const PortablePrescanViolation *violation)
{
    if (report == NULL || violation == NULL)
        return -1;
    if (report->total_count != SIZE_MAX)
        report->total_count++;
    if (report->example_count >= PORTABLE_PRESCAN_MAX_EXAMPLES)
        return 0;

    if (report->example_count == report->example_capacity) {
        size_t capacity = report->example_capacity == 0
            ? 8U : report->example_capacity * 2U;
        if (capacity > PORTABLE_PRESCAN_MAX_EXAMPLES)
            capacity = PORTABLE_PRESCAN_MAX_EXAMPLES;
        PortablePrescanViolation *examples = realloc(
            report->examples, capacity * sizeof(*examples));
        if (examples == NULL)
            return -1;
        report->examples = examples;
        report->example_capacity = capacity;
    }
    report->examples[report->example_count++] = *violation;
    return 0;
}

#ifdef PORTABLE_CAPTURE_TEST_HOOKS
static uint64_t portable_test_probe_count;
static uint64_t portable_test_readback_scan_count;

static void visited_count_probe(void)
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
#else
static void visited_count_probe(void)
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

static void portable_test_interrupt_if(PortableTestInterruptPoint point)
{
    if (portable_test_interrupt_point == (sig_atomic_t)point)
        (void)kill(getpid(), SIGKILL);
}
#else
static void portable_test_interrupt_if(int point)
{
    (void)point;
}
#endif

static size_t bounded_strlen(const char *value, size_t maximum)
{
    if (value == NULL)
        return 0;
    return strnlen(value, maximum + 1U);
}

static int copy_text(char *destination, size_t destination_size,
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

static int safe_component(const char *component)
{
    if (component == NULL || component[0] == '\0' ||
        strcmp(component, ".") == 0 || strcmp(component, "..") == 0 ||
        strchr(component, '/') != NULL || strlen(component) > NAME_MAX)
        return 0;
    return 1;
}

static int safe_relative_path(const char *path)
{
    if (path == NULL || path[0] == '\0' || path[0] == '/')
        return 0;
    size_t length = bounded_strlen(path, PATH_MAX);
    if (length == 0 || length >= PATH_MAX || path[length - 1U] == '/')
        return 0;

    char copy[PATH_MAX];
    memcpy(copy, path, length + 1U);
    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (!safe_component(cursor))
            return 0;
        if (slash == NULL)
            return 1;
        cursor = slash + 1;
    }
}

static int append_logical(char *destination, size_t destination_size,
                          const char *parent, const char *name)
{
    if (destination == NULL || parent == NULL || !safe_component(name))
        return -1;
    size_t parent_length = bounded_strlen(parent, destination_size);
    size_t name_length = strlen(name);
    if (parent_length >= destination_size ||
        name_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0) {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, name, name_length + 1U);
    return 0;
}

int append_physical(char *destination, size_t destination_size,
                    const char *parent, const char *encoded_leaf)
{
    if (destination == NULL || parent == NULL || encoded_leaf == NULL)
        return -1;
    size_t parent_length = bounded_strlen(parent, destination_size);
    size_t leaf_length = strlen(encoded_leaf);
    if (parent_length >= destination_size ||
        leaf_length > destination_size - parent_length - 1U)
        return -1;

    size_t offset = 0;
    if (parent_length != 0) {
        memcpy(destination, parent, parent_length);
        offset = parent_length;
        destination[offset++] = '/';
    }
    memcpy(destination + offset, encoded_leaf, leaf_length + 1U);
    return 0;
}

static int duplicate_fd(int fd)
{
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

static int open_child_directory(int parent_fd, const char *name)
{
    return openat(parent_fd, name,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int remove_leaf(int parent_fd, const char *name);

static int remove_directory_tree(int parent_fd, const char *name)
{
    int directory_fd = openat(parent_fd, name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    int scan_fd = duplicate_fd(directory_fd);
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
        if (remove_leaf(directory_fd, entry->d_name) != 0) {
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
    return unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 ? 0 : -1;
}

static int remove_leaf(int parent_fd, const char *name)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (S_ISDIR(st.st_mode))
        return remove_directory_tree(parent_fd, name);
    return unlinkat(parent_fd, name, 0) == 0 ? 0 : -1;
}

static int open_payload_parent(int data_fd, const char *relative,
                               int *parent_out, char *leaf, size_t leaf_size)
{
    if (data_fd < 0 || parent_out == NULL || leaf == NULL ||
        !safe_relative_path(relative) || leaf_size == 0)
        return -1;

    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);
    int current = duplicate_fd(data_fd);
    if (current < 0)
        return -1;

    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL) {
            int result = copy_text(leaf, leaf_size, cursor);
            if (result == 0) {
                *parent_out = current;
                return 0;
            }
            close(current);
            return -1;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0 && errno == ENOENT) {
            if (mkdirat(current, cursor, 0700) != 0 && errno != EEXIST) {
                close(current);
                return -1;
            }
            next = open_child_directory(current, cursor);
        }
        if (next < 0) {
            close(current);
            return -1;
        }
        close(current);
        current = next;
        cursor = slash + 1;
    }
}

/* Opens an existing payload parent without creating any component. */
static int open_existing_payload_parent(int data_fd, const char *relative,
                                        int *parent_out, char *leaf,
                                        size_t leaf_size)
{
    if (data_fd < 0 || parent_out == NULL || leaf == NULL ||
        !safe_relative_path(relative) || leaf_size == 0)
        return -1;

    size_t length = strlen(relative);
    char copy[PATH_MAX];
    memcpy(copy, relative, length + 1U);
    int current = duplicate_fd(data_fd);
    if (current < 0)
        return -1;

    char *cursor = copy;
    for (;;) {
        char *slash = strchr(cursor, '/');
        if (slash != NULL)
            *slash = '\0';
        if (slash == NULL) {
            int result = copy_text(leaf, leaf_size, cursor);
            if (result == 0) {
                *parent_out = current;
                return 0;
            }
            close(current);
            return -1;
        }

        int next = open_child_directory(current, cursor);
        if (next < 0) {
            int saved = errno;
            close(current);
            errno = saved;
            return -1;
        }
        close(current);
        current = next;
        cursor = slash + 1;
    }
}

static int ensure_directory_leaf(int parent_fd, const char *leaf, int *out_fd)
{
    if (parent_fd < 0 || !safe_component(leaf) || out_fd == NULL)
        return -1;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISDIR(st.st_mode)) {
            *out_fd = open_child_directory(parent_fd, leaf);
            return *out_fd < 0 ? -1 : 0;
        }
        if (remove_leaf(parent_fd, leaf) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    if (mkdirat(parent_fd, leaf, 0700) != 0 && errno != EEXIST)
        return -1;
    *out_fd = open_child_directory(parent_fd, leaf);
    return *out_fd < 0 ? -1 : 0;
}

static int ensure_regular_leaf(int parent_fd, const char *leaf, int *out_fd)
{
    if (parent_fd < 0 || !safe_component(leaf) || out_fd == NULL)
        return -1;

    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (remove_leaf(parent_fd, leaf) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    int fd = openat(parent_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK |
                        O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int saved = errno == 0 ? EIO : errno;
        close(fd);
        unlinkat(parent_fd, leaf, 0);
        errno = saved;
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static void xattrs_free(PortableXattrs *xattrs)
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
    int scan_fd = duplicate_fd(destination_fd);
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

static int collect_xattrs(int fd, PortableXattrs *out)
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

static int collect_symlink_xattrs(const char *path, PortableXattrs *out)
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
                    const char *physical,
                    const struct stat *st, int nsec_exact,
                    PortableXattrs *xattrs, SidecarEntry *out,
                    const SidecarBytes *symlink_target)
{
    int64_t atime_sec;
    int64_t mtime_sec;
    if (root_id == NULL || logical == NULL || physical == NULL ||
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

    memset(out, 0, sizeof(*out));
    out->root_id = (SidecarBytes){ (const unsigned char *)root_id,
                                   strlen(root_id) };
    out->logical_path = (SidecarBytes){ (const unsigned char *)logical,
                                        strlen(logical) };
    out->physical_path = (SidecarBytes){ (const unsigned char *)physical,
                                         strlen(physical) };
    if (S_ISLNK(st->st_mode))
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
    out->size = S_ISREG(st->st_mode) ? (uint64_t)st->st_size : 0;
    out->xattr_count = xattrs == NULL ? 0U : (uint32_t)xattrs->count;
    if (out->kind == SIDECAR_KIND_SYMLINK) {
        if (symlink_target == NULL || symlink_target->data == NULL ||
            symlink_target->length == 0)
            return -1;
        out->symlink_target = *symlink_target;
    }
    return 0;
}

static int sidecar_bytes_equal(SidecarBytes left, SidecarBytes right)
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
           current->kind == entry->kind && current->mode == entry->mode &&
           current->uid == entry->uid && current->gid == entry->gid &&
           (current->kind == SIDECAR_KIND_SYMLINK ||
            (current->atime_sec == entry->atime_sec &&
             current->atime_nsec == entry->atime_nsec)) &&
           current->mtime_sec == entry->mtime_sec &&
           current->mtime_nsec == entry->mtime_nsec &&
           current->size == entry->size &&
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

static uint64_t visited_fnv1a_bytes(uint64_t hash,
                                    const unsigned char *data,
                                    size_t length)
{
    for (size_t index = 0; index < length; index++)
    {
        hash ^= data[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t visited_fnv1a_uint64(uint64_t hash, uint64_t value)
{
    for (size_t index = 0; index < sizeof(value); index++)
    {
        hash ^= (unsigned char)(value >> (index * 8U));
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t visited_hash(const PortableVisited *visited,
                             const char *root_id, size_t root_length,
                             const char *logical, size_t logical_length)
{
    uint64_t hash = UINT64_C(1469598103934665603) ^ visited->hash_salt;
    hash = visited_fnv1a_uint64(hash, (uint64_t)root_length);
    hash = visited_fnv1a_bytes(hash, (const unsigned char *)root_id,
                               root_length);
    hash = visited_fnv1a_uint64(hash, (uint64_t)logical_length);
    return visited_fnv1a_bytes(hash, (const unsigned char *)logical,
                               logical_length);
}

static size_t visited_max_capacity(void)
{
    if (SIDECAR_MAX_LIVE_ENTRIES > SIZE_MAX / 2U)
        return SIZE_MAX & ~(SIZE_MAX >> 1);
    return (size_t)SIDECAR_MAX_LIVE_ENTRIES * 2U;
}

static int visited_capacity_valid(size_t capacity)
{
    return capacity >= VISITED_INITIAL_CAPACITY &&
           (capacity & (capacity - 1U)) == 0;
}

static int visited_rehash(PortableVisited *visited, size_t new_capacity)
{
    if (visited == NULL || !visited_capacity_valid(new_capacity) ||
        new_capacity > visited_max_capacity() ||
        new_capacity > SIZE_MAX / sizeof(*visited->slots))
        return -1;

    PortableVisitedSlot *new_slots = calloc(new_capacity,
                                            sizeof(*new_slots));
    if (new_slots == NULL)
        return -1;

    for (size_t old_index = 0; old_index < visited->capacity; old_index++)
    {
        PortableVisitedSlot *old_slot = &visited->slots[old_index];
        if (old_slot->root_id == NULL)
            continue;
        size_t index = (size_t)old_slot->hash & (new_capacity - 1U);
        while (new_slots[index].root_id != NULL)
            index = (index + 1U) & (new_capacity - 1U);
        new_slots[index] = *old_slot;
    }

    free(visited->slots);
    visited->slots = new_slots;
    visited->capacity = new_capacity;
    return 0;
}

/* Returns 1 for a matching slot, 0 for an empty insertion slot, -1 if full. */
static int visited_locate(const PortableVisited *visited,
                          const char *root_id, size_t root_length,
                          const char *logical, size_t logical_length,
                          uint64_t hash, size_t *out_index)
{
    if (visited == NULL || out_index == NULL)
        return -1;
    if (visited->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t index = (size_t)hash & (visited->capacity - 1U);
    for (size_t probes = 0; probes < visited->capacity; probes++)
    {
        visited_count_probe();
        const PortableVisitedSlot *slot = &visited->slots[index];
        if (slot->root_id == NULL)
        {
            *out_index = index;
            return 0;
        }
        if (slot->hash == hash && slot->root_length == root_length &&
            slot->logical_length == logical_length &&
            memcmp(slot->root_id, root_id, root_length) == 0 &&
            memcmp(slot->logical_path, logical, logical_length) == 0)
        {
            *out_index = index;
            return 1;
        }
        index = (index + 1U) & (visited->capacity - 1U);
    }

    *out_index = SIZE_MAX;
    return -1;
}

static void visited_slot_free(PortableVisitedSlot *slot)
{
    if (slot == NULL)
        return;
    free(slot->root_id);
    free(slot->logical_path);
    memset(slot, 0, sizeof(*slot));
}

static int visited_reset(PortableVisited *visited)
{
    if (visited == NULL)
        return -1;
    for (size_t index = 0; index < visited->capacity; index++)
        visited_slot_free(&visited->slots[index]);
    visited->count = 0;
    return 0;
}

static void visited_free(PortableVisited *visited)
{
    if (visited == NULL)
        return;
    visited_reset(visited);
    free(visited->slots);
    free(visited);
}

static void visited_dispose(PortableVisited *visited)
{
    if (visited == NULL)
        return;
    visited_reset(visited);
    free(visited->slots);
    memset(visited, 0, sizeof(*visited));
}

static int visited_add(PortableVisited *visited, const char *root_id,
                       const char *logical)
{
    if (visited == NULL || root_id == NULL || logical == NULL)
        return -1;
    size_t root_length = strlen(root_id);
    size_t logical_length = strlen(logical);
    if (root_length == SIZE_MAX || logical_length == SIZE_MAX)
        return -1;

    uint64_t hash = visited_hash(visited, root_id, root_length, logical,
                                 logical_length);
    if (visited->capacity == 0 &&
        visited_rehash(visited, VISITED_INITIAL_CAPACITY) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = visited_locate(visited, root_id, root_length, logical,
                                  logical_length, hash, &index);
    if (location == 1)
        return 1;
    if (location < 0)
        return -1;
    if (visited->count >= SIDECAR_MAX_LIVE_ENTRIES)
        return -1;

    if (visited->count + 1U > visited->capacity / 2U)
    {
        if (visited->capacity > visited_max_capacity() / 2U ||
            visited_rehash(visited, visited->capacity * 2U) != 0)
            return -1;
        location = visited_locate(visited, root_id, root_length, logical,
                                  logical_length, hash, &index);
        if (location != 0)
            return -1;
    }

    char *root_copy = malloc(root_length + 1U);
    if (root_copy == NULL)
        return -1;
    char *logical_copy = malloc(logical_length + 1U);
    if (logical_copy == NULL)
    {
        free(root_copy);
        return -1;
    }
    memcpy(root_copy, root_id, root_length + 1U);
    memcpy(logical_copy, logical, logical_length + 1U);

    PortableVisitedSlot *slot = &visited->slots[index];
    slot->root_id = root_copy;
    slot->logical_path = logical_copy;
    slot->root_length = root_length;
    slot->logical_length = logical_length;
    slot->hash = hash;
    visited->count++;
    return 0;
}

static int visited_contains(const PortableVisited *visited,
                            const char *root_id, const char *logical)
{
    if (visited == NULL || root_id == NULL || logical == NULL)
        return -1;
    if (visited->capacity == 0)
        return 0;

    size_t root_length = strlen(root_id);
    size_t logical_length = strlen(logical);
    uint64_t hash = visited_hash(visited, root_id, root_length, logical,
                                 logical_length);
    size_t index = SIZE_MAX;
    int location = visited_locate(visited, root_id, root_length, logical,
                                  logical_length, hash, &index);
    if (location < 0)
        return -1;
    return location == 1 ? 1 : 0;
}

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

static int sidecar_bytes_to_text(SidecarBytes bytes, char **out)
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
        if (!sidecar_bytes_equal(view->entry->logical_path,
                                 view->entry->physical_path) ||
            stale_keys_append(collection->stale, view->entry->logical_path,
                              view->entry->physical_path) != 0)
            collection->stale->failed = 1;
    }
    return collection->stale->failed;
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

static int tombstone_if_live(PortableCaptureContext *context,
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
    int scan_fd = duplicate_fd(directory_fd);
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

static int remove_payload_relative(int data_fd, const char *payload_root,
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
    int scan_fd = duplicate_fd(directory_fd);
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

static int reconcile_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    StaleKeys stale;
    memset(&stale, 0, sizeof(stale));
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
    portable_test_interrupt_if(PORTABLE_TEST_BEFORE_FINAL_INVENTORY);
    return reconcile_inventory(context, root);

fail:
    stale_keys_free(&stale);
    return -1;
}

static int read_source_stat(int source_parent, const char *source_name,
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

static int open_source_node(int source_parent, const char *source_name,
                            const char *root_path, const struct stat *st)
{
    int flags = O_RDONLY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC;
    if (S_ISDIR(st->st_mode))
        flags |= O_DIRECTORY;
    if (source_parent >= 0)
        return openat(source_parent, source_name, flags);
    return open(root_path, flags);
}

static int copy_regular(int source_fd, int destination_fd, off_t expected_size)
{
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
            return -1;
        copied += (uint64_t)received;

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
    }
    return expected_size >= 0 && copied == (uint64_t)expected_size ? 0 : -1;
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
                             PortableXattrs *xattrs)
{
    PendingReadbackNames pending = {0};
    int scan_fd = duplicate_fd(source_fd);
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

        char child_physical[SIDECAR_MAX_PATH + 1U];
        if (append_physical(child_physical, sizeof(child_physical), physical,
                            encoded_leaf) != 0) {
            failed = 1;
            break;
        }

        size_t payload_root_length = strlen(root->payload_path);
        size_t physical_length = strlen(child_physical);
        /* Keep this arithmetic in sync with replay_payload_path_build(). */
        if (payload_root_length == 0 || payload_root_length >= PATH_MAX ||
            physical_length > PATH_MAX - payload_root_length - 1U) {
            failed = 1;
            break;
        }

        if (encoded_name_has_raw_high_byte(encoded_leaf) &&
            pending_readback_names_add(&pending, encoded_leaf) != 0) {
            failed = 1;
            break;
        }

        if (capture_node(context, root, child_logical, child_physical,
                         source_fd, entry->d_name, NULL, destination_fd,
                         encoded_leaf) != 0) {
            failed = 1;
            break;
        }
    }
    if (closedir(directory) != 0)
        failed = 1;

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
    if (entry_from_stat(root->id, logical, physical, before,
                        context->nsec_exact,
                        xattrs, &sidecar_entry, NULL) != 0 ||
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
                           int source_fd,
                           const struct stat *before,
                           int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root,
                           PortableXattrs *xattrs)
{
    if (tombstone_if_live(context, root->id, logical) != 0) {
        xattrs_free(xattrs);
        close(source_fd);
        return -1;
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (open_payload_parent(context->data_fd, root->payload_path,
                                &parent_fd, root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
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
    if (copy_regular(source_fd, destination_fd, before->st_size) != 0) {
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
    failed = entry_from_stat(root->id, logical, physical, before,
                             context->nsec_exact,
                             xattrs, &sidecar_entry, NULL) != 0 ||
             append_group(context, &sidecar_entry, xattrs) != 0;
    xattrs_free(xattrs);
    return failed ? -1 : 0;
}

static int capture_special(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, int destination_parent,
                           const char *destination_leaf,
                           int destination_is_root, const struct stat *st)
{
    if (visited_add(context->visited, root->id, logical) != 0)
        return -1;
    if (tombstone_if_live(context, root->id, logical) != 0)
        return -1;

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (open_payload_parent(context->data_fd, root->payload_path,
                                &parent_fd, root_leaf, sizeof(root_leaf)) != 0)
            return -1;
        destination_leaf = root_leaf;
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
    printf("Warning: skipping unsupported %s %s\n", kind,
           logical[0] == '\0' ? root->capture_path : logical);
    return 0;
}

static int capture_symlink(PortableCaptureContext *context,
                           const PortableRootSpec *root,
                           const char *logical, const char *physical,
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
    if (entry_from_stat(root->id, logical, physical, before,
                        context->nsec_exact,
                        &xattrs, &entry, &target_bytes) != 0) {
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

    if (tombstone_if_live(context, root->id, logical) != 0) {
        xattrs_free(&xattrs);
        return -1;
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (destination_is_root) {
        if (open_payload_parent(context->data_fd, root->payload_path,
                                &parent_fd, root_leaf,
                                sizeof(root_leaf)) != 0) {
            xattrs_free(&xattrs);
            return -1;
        }
        destination_leaf = root_leaf;
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

    int is_root = source_parent < 0;
    if (S_ISSOCK(before.st_mode) || S_ISCHR(before.st_mode) ||
        S_ISBLK(before.st_mode))
        return capture_special(context, root, logical, destination_parent,
                               destination_leaf, is_root, &before);
    if (S_ISFIFO(before.st_mode)) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (S_ISLNK(before.st_mode))
        return capture_symlink(context, root, logical, physical, source_parent,
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

    PortableXattrs xattrs;
    if (collect_xattrs(source_fd, &xattrs) != 0) {
        close(source_fd);
        return -1;
    }
    if (visited_add(context->visited, root->id, logical) != 0) {
        xattrs_free(&xattrs);
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
            int matches = entry_from_stat(root->id, logical, physical, &before,
                                          context->nsec_exact, &xattrs,
                                          &current, NULL) == 0 &&
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
        return capture_regular(context, root, logical, physical, source_fd,
                               &before,
                               destination_parent, destination_leaf, is_root,
                               &xattrs);

    if (tombstone_if_live(context, root->id, logical) != 0) {
        xattrs_free(&xattrs);
        close(source_fd);
        return -1;
    }

    int parent_fd = destination_parent;
    char root_leaf[NAME_MAX + 1U];
    if (is_root) {
        if (open_payload_parent(context->data_fd, root->payload_path,
                                &parent_fd, root_leaf, sizeof(root_leaf)) != 0) {
            xattrs_free(&xattrs);
            close(source_fd);
            return -1;
        }
        destination_leaf = root_leaf;
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
                          destination_fd, &xattrs) != 0) {
        if (is_root)
            close(parent_fd);
        return -1;
    }
    if (is_root)
        close(parent_fd);
    return 0;
}

static int root_spec_valid(const PortableRootSpec *root)
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

static int prescan_record_violation(PortablePrescanReport *report,
                                    const char *root_id,
                                    const char *logical_path,
                                    PortablePrescanViolationKind kind,
                                    size_t limit, size_t actual)
{
    PortablePrescanViolation violation = {
        .kind = kind,
        .limit = limit,
        .actual = actual
    };
    if (copy_text(violation.root_id, sizeof(violation.root_id), root_id) != 0 ||
        copy_text(violation.logical_path, sizeof(violation.logical_path),
                  logical_path) != 0)
        return -1;
    return prescan_report_add(report, &violation);
}

static int prescan_directory(int source_fd, const char *logical,
                             const char *physical, const char *root_id,
                             const char *payload_path,
                             PortablePrescanReport *report)
{
    if (source_fd < 0 || logical == NULL || physical == NULL ||
        root_id == NULL || payload_path == NULL || report == NULL)
        return -1;

    int scan_fd = duplicate_fd(source_fd);
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

        char child_logical[SIDECAR_MAX_PATH + 1U];
        if (append_logical(child_logical, sizeof(child_logical), logical,
                           entry->d_name) != 0) {
            failed = 1;
            break;
        }

        char scratch[3U * NAME_MAX + 4U];
        if (encoding_percent_encode(ENCODING_MODE_COMPONENT, entry->d_name,
                                    scratch, sizeof(scratch)) != 0) {
            failed = 1;
            break;
        }

        size_t encoded_length = strlen(scratch);
        if (encoded_length > NAME_MAX) {
            if (prescan_record_violation(
                    report, root_id, child_logical,
                    PORTABLE_PRESCAN_NAME_TOO_LONG, NAME_MAX,
                    encoded_length) != 0)
                failed = 1;
            if (failed)
                break;
            continue;
        }

        char child_physical[SIDECAR_MAX_PATH + 1U];
        if (append_physical(child_physical, sizeof(child_physical), physical,
                            scratch) != 0) {
            failed = 1;
            break;
        }

        size_t payload_root_length = strlen(payload_path);
        size_t physical_length = strlen(child_physical);
        /* Keep this arithmetic in sync with replay_payload_path_build() and
         * capture_directory(). */
        if (payload_root_length == 0 || payload_root_length >= PATH_MAX ||
            physical_length > PATH_MAX - payload_root_length - 1U) {
            if (payload_root_length > SIZE_MAX - 1U ||
                physical_length > SIZE_MAX - payload_root_length - 1U)
                failed = 1;
            else if (prescan_record_violation(
                         report, root_id, child_logical,
                         PORTABLE_PRESCAN_PATH_TOO_LONG, PATH_MAX,
                         payload_root_length + 1U + physical_length) != 0)
                failed = 1;
            if (failed)
                break;
            continue;
        }

        struct stat child_stat;
        if (read_source_stat(source_fd, entry->d_name, NULL, &child_stat) != 0) {
            failed = 1;
            break;
        }
        if (S_ISDIR(child_stat.st_mode)) {
            int child_fd = open_source_node(source_fd, entry->d_name, NULL,
                                            &child_stat);
            if (child_fd < 0) {
                failed = 1;
                break;
            }
            int child_result = prescan_directory(
                child_fd, child_logical, child_physical, root_id,
                payload_path, report);
            if (close(child_fd) != 0)
                child_result = -1;
            if (child_result != 0) {
                failed = 1;
                break;
            }
        }
    }
    if (closedir(directory) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int prescan_root(const PortableRootSpec *root,
                        PortablePrescanReport *report)
{
    if (!root_spec_valid(root) || report == NULL)
        return -1;

    struct stat st;
    if (read_source_stat(-1, NULL, root->capture_path, &st) != 0)
        return -1;
    if (!S_ISDIR(st.st_mode))
        return 0;

    int root_fd = open_source_node(-1, NULL, root->capture_path, &st);
    if (root_fd < 0)
        return -1;
    int result = prescan_directory(root_fd, "", "", root->id,
                                   root->payload_path, report);
    if (close(root_fd) != 0)
        result = -1;
    return result;
}

static int prescan_request(const PortableCaptureRequest *request,
                           PortablePrescanReport *report)
{
    if (request == NULL || report == NULL)
        return -1;
    int failed = 0;
    for (size_t index = 0; index < request->root_count; index++)
        if (prescan_root(&request->roots[index], report) != 0)
            failed = 1;
    return failed || report->total_count != 0 ? -1 : 0;
}

static int relative_paths_overlap(const char *left, const char *right)
{
    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    if (left_length <= right_length &&
        strncmp(left, right, left_length) == 0 &&
        (left_length == right_length || right[left_length] == '/'))
        return 1;
    if (right_length < left_length &&
        strncmp(left, right, right_length) == 0 &&
        left[right_length] == '/')
        return 1;
    return 0;
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

static int data_namespace_is_empty(int data_fd)
{
    if (data_fd < 0)
        return -1;
    struct stat st;
    if (fstat(data_fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    int empty = 1;
    int scan_fd = duplicate_fd(data_fd);
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
    context->data_fd = data_fd;
    context->sidecar = sidecar;
    context->nsec_exact = nsec_exact != 0;
    context->case_sensitive = case_sensitive != 0;
    visited->hash_salt = sidecar_process_salt();
    context->visited = visited;
    return 0;
}

void portable_capture_context_close(PortableCaptureContext *context)
{
    if (context == NULL)
        return;
    visited_free(context->visited);
    memset(context, 0, sizeof(*context));
}

int portable_capture_root(PortableCaptureContext *context,
                          const PortableRootSpec *root)
{
    if (context == NULL || context->visited == NULL ||
        context->data_fd < 0 || context->sidecar == NULL ||
        !root_spec_valid(root))
        return -1;
    PortableVisited *visited = context->visited;
    if (visited_reset(visited) != 0)
        return -1;
    return capture_node(context, root, "", "", -1, NULL, root->capture_path,
                        -1, NULL);
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

    PortablePrescanReport local_report;
    int owns_report = report == NULL;
    PortablePrescanReport *active_report = report;
    if (owns_report) {
        portable_prescan_report_init(&local_report);
        active_report = &local_report;
    }
    if (prescan_request(request, active_report) != 0) {
        if (owns_report)
            portable_prescan_report_free(&local_report);
        return -1;
    }
    if (owns_report)
        portable_prescan_report_free(&local_report);

    Manifest manifest;
    if (build_manifest(request, &manifest) != 0)
        return -1;
    if (manifest_write_v1_at(container_fd, &manifest) != 0) {
        manifest_free(&manifest);
        return -1;
    }
    portable_test_interrupt_if(PORTABLE_TEST_AFTER_MANIFEST);

    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST) {
        manifest_free(&manifest);
        return -1;
    }
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0) {
        manifest_free(&manifest);
        return -1;
    }

    SidecarLog sidecar = {0};
    if (sidecar_log_create_at(container_fd, &sidecar) != SIDECAR_OPEN_FRESH) {
        close(data_fd);
        manifest_free(&manifest);
        return -1;
    }

    PortableCaptureContext context = {0};
    int failed = portable_capture_context_init(&context, data_fd, &sidecar,
                                               request->nsec_exact,
                                               request->case_sensitive) != 0;
    for (size_t index = 0; !failed && index < request->root_count; index++)
        if (portable_capture_root(&context, &request->roots[index]) != 0 ||
            reconcile_root(&context, &request->roots[index]) != 0)
            failed = 1;
    portable_capture_context_close(&context);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        failed = 1;
    if (close(data_fd) != 0)
        failed = 1;
    manifest_free(&manifest);
    return failed ? -1 : 0;
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

    PortablePrescanReport local_report;
    int owns_report = report == NULL;
    PortablePrescanReport *active_report = report;
    if (owns_report) {
        portable_prescan_report_init(&local_report);
        active_report = &local_report;
    }
    if (prescan_request(request, active_report) != 0) {
        if (owns_report)
            portable_prescan_report_free(&local_report);
        return -1;
    }
    if (owns_report)
        portable_prescan_report_free(&local_report);

    Manifest expected;
    if (build_manifest(request, &expected) != 0)
        return -1;

    Manifest existing;
    ManifestStatus manifest_status = manifest_read_v1_at(container_fd,
                                                         &existing);
    if (manifest_status != MANIFEST_STATUS_VALID) {
        manifest_free(&expected);
        return -1;
    }
    ManifestIdentityComparison identity =
        manifest_resume_identity_compare(&existing, &expected);
    if (identity != MANIFEST_IDENTITY_EQUAL) {
        manifest_free(&existing);
        manifest_free(&expected);
        return -1;
    }

    int data_fd = -1;
    int data_state = open_existing_data(container_fd, &data_fd);
    if (data_state < 0) {
        manifest_free(&existing);
        manifest_free(&expected);
        return -1;
    }
    int data_missing = data_state == 1;

    SidecarLog sidecar = {0};
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

    PortableCaptureContext context = {0};
    if (!failed && portable_capture_context_init(&context, data_fd, &sidecar,
                                                request->nsec_exact,
                                                request->case_sensitive) != 0)
        failed = 1;
    if (!failed) {
        context.resume_mode = 1;
        for (size_t index = 0; index < request->root_count; index++) {
            if (portable_capture_root(&context, &request->roots[index]) != 0 ||
                reconcile_root(&context, &request->roots[index]) != 0) {
                failed = 1;
                break;
            }
        }
    }
    portable_capture_context_close(&context);
    if (sidecar_log_close(&sidecar) != SIDECAR_STATUS_OK)
        failed = 1;
    if (data_fd >= 0 && close(data_fd) != 0)
        failed = 1;
    manifest_free(&existing);
    manifest_free(&expected);
    return failed ? -1 : 0;
}
