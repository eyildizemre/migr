#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#include "fileops.h"
#include "metadata.h"

#ifdef METADATA_TEST_HOOKS
static uint64_t metadata_probe_calls;
static MetadataTestProbeHook metadata_probe_hook;
static void *metadata_probe_hook_context;

uint64_t metadata_test_probe_count(void)
{
    return metadata_probe_calls;
}

void metadata_test_reset_probe_count(void)
{
    metadata_probe_calls = 0;
}

void metadata_test_set_probe_hook(MetadataTestProbeHook hook, void *context)
{
    metadata_probe_hook = hook;
    metadata_probe_hook_context = context;
}
#endif

static int same_timespec(struct timespec left, struct timespec right)
{
    return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static int gid_is_allowed(gid_t desired)
{
    if (desired == getegid())
        return 1;

    int count = getgroups(0, NULL);
    if (count < 0)
        return 0;

    gid_t *groups = NULL;
    if (count > 0)
    {
        groups = malloc((size_t)count * sizeof(*groups));
        if (groups == NULL)
            return 0;
        int actual = getgroups(count, groups);
        if (actual < 0)
        {
            free(groups);
            return 0;
        }
        count = actual;
    }

    int allowed = 0;
    for (int i = 0; i < count; i++)
        if (groups[i] == desired)
        {
            allowed = 1;
            break;
        }
    free(groups);
    return allowed;
}

static int owner_is_foreign(const struct stat *st)
{
    return st != NULL &&
           (st->st_uid != geteuid() || !gid_is_allowed(st->st_gid));
}

static int mount_identity_for_fd(int fd, uint64_t *out)
{
    if (fd < 0 || out == NULL)
        return -1;

    struct statfs fs;
    if (fstatfs(fd, &fs) != 0)
        return -1;

    uint64_t identity = 0;
    size_t bytes = sizeof(fs.f_fsid) < sizeof(identity)
        ? sizeof(fs.f_fsid) : sizeof(identity);
    memcpy(&identity, &fs.f_fsid, bytes);
    *out = identity;
    return 0;
}

static int profile_same(const MetadataProfile *profile,
                        dev_t anchor_device, ino_t anchor_inode,
                        uint64_t mount_identity, const struct stat *desired,
                        const struct stat *existing)
{
    if (profile->anchor_device != anchor_device ||
        profile->anchor_inode != anchor_inode ||
        profile->mount_identity != mount_identity ||
        profile->desired_uid != desired->st_uid ||
        profile->desired_gid != desired->st_gid ||
        profile->desired_mode != (desired->st_mode & 07777) ||
        profile->has_initial_owner != (existing != NULL))
        return 0;
    return existing == NULL ||
           (profile->initial_uid == existing->st_uid &&
            profile->initial_gid == existing->st_gid);
}

void metadata_profiles_init(MetadataProfiles *profiles)
{
    if (profiles == NULL)
        return;
    memset(profiles, 0, sizeof(*profiles));
}

void metadata_profiles_free(MetadataProfiles *profiles)
{
    if (profiles == NULL)
        return;
    for (size_t i = 0; i < profiles->count; i++)
        close(profiles->items[i].anchor_fd);
    free(profiles->items);
    memset(profiles, 0, sizeof(*profiles));
}

int metadata_profiles_add(MetadataProfiles *profiles, int anchor_fd,
                          const struct stat *desired,
                          const struct stat *existing,
                          const char *path)
{
    if (profiles == NULL || anchor_fd < 0 || desired == NULL)
        return -1;

    int privilege_relevant = desired->st_uid != geteuid() ||
                             !gid_is_allowed(desired->st_gid) ||
                             (desired->st_mode & (S_ISUID | S_ISGID)) != 0 ||
                             owner_is_foreign(existing);
    if (!privilege_relevant)
        return 0;

    struct stat anchor_st;
    if (fstat(anchor_fd, &anchor_st) != 0 || !S_ISDIR(anchor_st.st_mode))
        return -1;
    uint64_t mount_identity;
    if (mount_identity_for_fd(anchor_fd, &mount_identity) != 0)
        return -1;

    for (size_t i = 0; i < profiles->count; i++)
    {
        if (profile_same(&profiles->items[i], anchor_st.st_dev,
                         anchor_st.st_ino, mount_identity, desired,
                         existing))
        {
            profiles->affected_objects++;
            if (path != NULL && profiles->example_count < METADATA_MAX_PREFLIGHT_EXAMPLES)
            {
                int n = snprintf(profiles->examples[profiles->example_count],
                                 sizeof(profiles->examples[0]), "%s", path);
                if (n >= 0 && (size_t)n < sizeof(profiles->examples[0]))
                    profiles->example_count++;
            }
            return 0;
        }
    }

    if (profiles->count >= METADATA_MAX_PROFILES)
    {
        errno = E2BIG;
        return -1;
    }
    if (profiles->count == profiles->capacity)
    {
        size_t capacity = profiles->capacity == 0 ? 16 : profiles->capacity * 2;
        if (capacity > METADATA_MAX_PROFILES)
            capacity = METADATA_MAX_PROFILES;
        MetadataProfile *items = realloc(profiles->items,
                                         capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        profiles->items = items;
        profiles->capacity = capacity;
    }

    MetadataProfile *profile = &profiles->items[profiles->count];
    memset(profile, 0, sizeof(*profile));
    profile->anchor_device = anchor_st.st_dev;
    profile->anchor_inode = anchor_st.st_ino;
    profile->mount_identity = mount_identity;
    profile->desired_uid = desired->st_uid;
    profile->desired_gid = desired->st_gid;
    profile->desired_mode = desired->st_mode & 07777;
    profile->has_initial_owner = existing != NULL;
    if (existing != NULL)
    {
        profile->initial_uid = existing->st_uid;
        profile->initial_gid = existing->st_gid;
    }
    profile->anchor_fd = fcntl(anchor_fd, F_DUPFD_CLOEXEC, 0);
    if (profile->anchor_fd < 0)
        return -1;
    profiles->count++;
    profiles->affected_objects++;
    if (path != NULL && profiles->example_count < METADATA_MAX_PREFLIGHT_EXAMPLES)
    {
        int n = snprintf(profiles->examples[profiles->example_count],
                         sizeof(profiles->examples[0]), "%s", path);
        if (n >= 0 && (size_t)n < sizeof(profiles->examples[0]))
            profiles->example_count++;
    }
    return 0;
}

static int set_probe_times(int fd, MetadataTimestampPolicy policy,
                           struct timespec out[2])
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        return -1;
    out[0].tv_sec = now.tv_sec + 17;
    out[0].tv_nsec = policy.nsec_exact ? 123456789 : 0;
    out[1].tv_sec = now.tv_sec + 19;
    out[1].tv_nsec = policy.nsec_exact ? 987654321 : 0;
    return futimens(fd, out);
}

static int probe_one_profile(const MetadataProfile *profile,
                             MetadataTimestampPolicy policy)
{
    int fd = openat(profile->anchor_fd, ".",
                    O_TMPFILE | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    int failed = 0;
    struct stat st;
    if (fstat(fd, &st) != 0)
        failed = 1;
    if (!failed && profile->has_initial_owner &&
        fchown(fd, profile->initial_uid, profile->initial_gid) != 0)
        failed = 1;
    if (!failed && fchown(fd, profile->desired_uid, profile->desired_gid) != 0)
        failed = 1;
    if (!failed && fchmod(fd, profile->desired_mode) != 0)
        failed = 1;

    struct timespec times[2];
    if (!failed && set_probe_times(fd, policy, times) != 0)
        failed = 1;
    if (!failed && fstat(fd, &st) != 0)
        failed = 1;
    if (!failed && (st.st_uid != profile->desired_uid ||
                    st.st_gid != profile->desired_gid ||
                    (st.st_mode & 07777) != profile->desired_mode ||
                    !same_timespec(st.st_atim, times[0]) ||
                    !same_timespec(st.st_mtim, times[1])))
    {
        errno = EIO;
        failed = 1;
    }

    if (close(fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

int metadata_profiles_probe(const MetadataProfiles *profiles,
                            MetadataTimestampPolicy policy)
{
#ifdef METADATA_TEST_HOOKS
    metadata_probe_calls++;
    if (metadata_probe_hook != NULL)
        metadata_probe_hook(metadata_probe_hook_context);
#endif
    if (profiles == NULL)
        return -1;
    for (size_t i = 0; i < profiles->count; i++)
        if (probe_one_profile(&profiles->items[i], policy) != 0)
            return -1;
    return 0;
}

void metadata_profiles_report(const MetadataProfiles *profiles)
{
    if (profiles == NULL || profiles->affected_objects == 0)
        return;

    printf("Metadata preflight: %zu object(s), %zu privilege-relevant profile(s)\n",
           profiles->affected_objects, profiles->count);
    for (size_t i = 0; i < profiles->example_count; i++)
        printf("  metadata example: %s\n", profiles->examples[i]);
    if (profiles->affected_objects > profiles->example_count)
        printf("  ... additional affected objects omitted\n");
}

void metadata_snapshots_init(MetadataSnapshots *snapshots)
{
    if (snapshots == NULL)
        return;
    memset(snapshots, 0, sizeof(*snapshots));
}

void metadata_snapshots_free(MetadataSnapshots *snapshots)
{
    if (snapshots == NULL)
        return;
    free(snapshots->items);
    memset(snapshots, 0, sizeof(*snapshots));
}

int metadata_snapshot_from_stat(const struct stat *st, MetadataSnapshot *out)
{
    if (st == NULL || out == NULL)
        return -1;
    out->device = st->st_dev;
    out->inode = st->st_ino;
    out->type_and_mode = st->st_mode;
    out->size = st->st_size;
    out->uid = st->st_uid;
    out->gid = st->st_gid;
    out->atime = st->st_atim;
    out->mtime = st->st_mtim;
    out->ctime = st->st_ctim;
    return 0;
}

int metadata_snapshot_to_stat(const MetadataSnapshot *snapshot,
                              struct stat *out)
{
    if (snapshot == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    out->st_dev = snapshot->device;
    out->st_ino = snapshot->inode;
    out->st_mode = snapshot->type_and_mode;
    out->st_size = snapshot->size;
    out->st_uid = snapshot->uid;
    out->st_gid = snapshot->gid;
    out->st_atim = snapshot->atime;
    out->st_mtim = snapshot->mtime;
    out->st_ctim = snapshot->ctime;
    return 0;
}

static int snapshot_same_object(const MetadataSnapshot *left,
                                const struct stat *right)
{
    return left->device == right->st_dev && left->inode == right->st_ino;
}

int metadata_snapshot_record(MetadataSnapshots *snapshots,
                             const struct stat *st)
{
    if (snapshots == NULL || st == NULL)
        return -1;
    for (size_t i = 0; i < snapshots->count; i++)
        if (snapshot_same_object(&snapshots->items[i], st))
            return 0;

    if (snapshots->count == snapshots->capacity)
    {
        size_t capacity = snapshots->capacity == 0 ? 32 : snapshots->capacity * 2;
        MetadataSnapshot *items = realloc(snapshots->items,
                                          capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        snapshots->items = items;
        snapshots->capacity = capacity;
    }
    if (metadata_snapshot_from_stat(st, &snapshots->items[snapshots->count]) != 0)
        return -1;
    snapshots->count++;
    return 0;
}

const MetadataSnapshot *metadata_snapshot_find(const MetadataSnapshots *snapshots,
                                               const struct stat *st)
{
    if (snapshots == NULL || st == NULL)
        return NULL;
    for (size_t i = 0; i < snapshots->count; i++)
        if (snapshot_same_object(&snapshots->items[i], st))
            return &snapshots->items[i];
    return NULL;
}

MetadataTimestampPolicy metadata_policy_from_context(const CloneContext *ctx)
{
    MetadataTimestampPolicy policy = { .nsec_exact = 1, .configured = 0 };
    if (ctx != NULL && ctx->timestamp_policy_configured)
    {
        policy.nsec_exact = ctx->nsec_exact != 0;
        policy.configured = 1;
    }
    return policy;
}

struct timespec metadata_canonical_time(struct timespec value,
                                        MetadataTimestampPolicy policy)
{
    if (!policy.nsec_exact)
        value.tv_nsec = 0;
    return value;
}

static int metadata_stat_core_matches(const struct stat *actual,
                                      const struct stat *desired,
                                      MetadataTimestampPolicy policy)
{
    struct timespec atime = metadata_canonical_time(desired->st_atim, policy);
    struct timespec mtime = metadata_canonical_time(desired->st_mtim, policy);
    return (actual->st_mode & S_IFMT) == (desired->st_mode & S_IFMT) &&
           actual->st_uid == desired->st_uid &&
           actual->st_gid == desired->st_gid &&
           (actual->st_mode & 07777) == (desired->st_mode & 07777) &&
           same_timespec(actual->st_atim, atime) &&
           same_timespec(actual->st_mtim, mtime);
}

int metadata_apply_ownership_and_mode_fd(int fd, const struct stat *desired)
{
    if (fd < 0 || desired == NULL)
        return -1;
    if (fchown(fd, desired->st_uid, desired->st_gid) != 0)
        return -1;
    if (fchmod(fd, desired->st_mode & 07777) != 0)
        return -1;
    return 0;
}

int metadata_apply_times_fd(int fd, const struct stat *desired,
                            MetadataTimestampPolicy policy)
{
    if (fd < 0 || desired == NULL)
        return -1;
    struct timespec times[2] = {
        metadata_canonical_time(desired->st_atim, policy),
        metadata_canonical_time(desired->st_mtim, policy)
    };
    if (futimens(fd, times) != 0)
        return -1;

    struct stat actual;
    if (fstat(fd, &actual) != 0)
        return -1;
    if (!metadata_stat_core_matches(&actual, desired, policy))
    {
        errno = EIO;
        return -1;
    }
    return 0;
}

int metadata_apply_fd(int fd, const struct stat *desired,
                      MetadataTimestampPolicy policy)
{
    if (metadata_apply_ownership_and_mode_fd(fd, desired) != 0)
        return -1;
    return metadata_apply_times_fd(fd, desired, policy);
}

int metadata_apply_symlink_ownership_at(int dir_fd, const char *leaf,
                                        const struct stat *desired)
{
    if (dir_fd < 0 || leaf == NULL || desired == NULL)
        return -1;
    if (fchownat(dir_fd, leaf, desired->st_uid, desired->st_gid,
                 AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    return 0;
}

int metadata_apply_symlink_times_at(int dir_fd, const char *leaf,
                                    const struct stat *desired,
                                    MetadataTimestampPolicy policy)
{
    if (dir_fd < 0 || leaf == NULL || desired == NULL)
        return -1;

    struct timespec times[2] = {
        metadata_canonical_time(desired->st_atim, policy),
        metadata_canonical_time(desired->st_mtim, policy)
    };
    if (utimensat(dir_fd, leaf, times, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;

    struct stat actual;
    if (fstatat(dir_fd, leaf, &actual, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (!S_ISLNK(actual.st_mode) ||
        actual.st_uid != desired->st_uid || actual.st_gid != desired->st_gid ||
        !same_timespec(actual.st_atim, times[0]) ||
        !same_timespec(actual.st_mtim, times[1]))
    {
        errno = EIO;
        return -1;
    }
    return 0;
}

int metadata_apply_symlink_at(int dir_fd, const char *leaf,
                              const struct stat *desired,
                              MetadataTimestampPolicy policy)
{
    if (metadata_apply_symlink_ownership_at(dir_fd, leaf, desired) != 0)
        return -1;
    return metadata_apply_symlink_times_at(dir_fd, leaf, desired, policy);
}

typedef struct {
    int fd;
    const char *path;
} MetadataXattrTarget;

static int metadata_xattr_unsupported_errno(int value)
{
    return value == ENOTSUP || value == EOPNOTSUPP || value == ENODATA;
}

static ssize_t metadata_xattr_list(const MetadataXattrTarget *target,
                                   char *names, size_t size)
{
    if (target == NULL)
        return -1;
    if (target->fd >= 0)
        return flistxattr(target->fd, names, size);
    if (target->path != NULL)
        return llistxattr(target->path, names, size);
    errno = EINVAL;
    return -1;
}

static int metadata_xattr_remove(const MetadataXattrTarget *target,
                                 const char *name)
{
    if (target == NULL || name == NULL)
        return -1;
    if (target->fd >= 0)
        return fremovexattr(target->fd, name);
    if (target->path != NULL)
        return lremovexattr(target->path, name);
    errno = EINVAL;
    return -1;
}

static int metadata_xattr_set(const MetadataXattrTarget *target,
                              const char *name, const void *value,
                              size_t value_length)
{
    if (target == NULL || name == NULL || (value == NULL && value_length != 0))
        return -1;
    if (target->fd >= 0)
        return fsetxattr(target->fd, name, value, value_length, 0);
    if (target->path != NULL)
        return lsetxattr(target->path, name, value, value_length, 0);
    errno = EINVAL;
    return -1;
}

static int metadata_xattr_input_valid(const SidecarXattr *xattrs, size_t count)
{
    if (count > SIDECAR_MAX_XATTRS_PER_ENTRY ||
        (count != 0 && xattrs == NULL))
        return -1;

    for (size_t index = 0; index < count; index++)
    {
        const SidecarXattr *current = &xattrs[index];
        if (current->name.data == NULL || current->name.length == 0 ||
            current->name.length > SIDECAR_MAX_XATTR_NAME ||
            memchr(current->name.data, '\0', current->name.length) != NULL ||
            current->value.length > SIDECAR_MAX_XATTR_VALUE ||
            (current->value.length != 0 && current->value.data == NULL))
            return -1;
        for (size_t previous = 0; previous < index; previous++)
            if (xattrs[previous].name.length == current->name.length &&
                memcmp(xattrs[previous].name.data, current->name.data,
                       current->name.length) == 0)
                return -1;
    }
    return 0;
}

static int metadata_xattr_names_valid(const char *names, size_t length,
                                      size_t *count)
{
    if ((length != 0 && names == NULL) || count == NULL)
        return -1;

    size_t found = 0;
    size_t offset = 0;
    while (offset < length)
    {
        size_t name_length = strnlen(names + offset, length - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == length - offset ||
            found == SIDECAR_MAX_XATTRS_PER_ENTRY)
            return -1;
        found++;
        offset += name_length + 1U;
    }
    *count = found;
    return 0;
}

static int metadata_xattr_names_read(const MetadataXattrTarget *target,
                                     char **out_names, size_t *out_count)
{
    if (target == NULL || out_names == NULL || out_count == NULL)
        return -1;
    *out_names = NULL;
    *out_count = 0;

    errno = 0;
    ssize_t required = metadata_xattr_list(target, NULL, 0);
    if (required < 0)
    {
        if (metadata_xattr_unsupported_errno(errno))
            return 0;
        return -1;
    }
    if ((uintmax_t)required >
        (uintmax_t)SIDECAR_MAX_XATTRS_PER_ENTRY *
            (uintmax_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (required == 0)
        return 0;

    char *names = malloc((size_t)required);
    if (names == NULL)
        return -1;
    ssize_t received = metadata_xattr_list(target, names, (size_t)required);
    if (received != required || metadata_xattr_names_valid(
                                    names, (size_t)received, out_count) != 0)
    {
        free(names);
        return -1;
    }
    *out_names = names;
    return 0;
}

static unsigned int metadata_xattr_namespace(const char *name)
{
    if (strncmp(name, "user.", 5) == 0)
        return METADATA_XATTR_NS_USER;
    if (strncmp(name, "security.", 9) == 0)
        return METADATA_XATTR_NS_SECURITY;
    if (strncmp(name, "system.", 7) == 0)
        return METADATA_XATTR_NS_SYSTEM;
    if (strncmp(name, "trusted.", 8) == 0)
        return METADATA_XATTR_NS_TRUSTED;
    return 0;
}

static int metadata_xattr_namespaces_target(const MetadataXattrTarget *target,
                                            unsigned int *out)
{
    if (target == NULL || out == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    *out = 0;
    char *names = NULL;
    size_t count = 0;
    if (metadata_xattr_names_read(target, &names, &count) != 0)
        return -1;

    size_t offset = 0;
    for (size_t index = 0; index < count; index++)
    {
        const char *name = names + offset;
        *out |= metadata_xattr_namespace(name);
        offset += strlen(name) + 1U;
    }
    free(names);
    return 0;
}

int metadata_xattr_namespaces_fd(int fd, unsigned int *out)
{
    if (fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    MetadataXattrTarget target = { .fd = fd, .path = NULL };
    return metadata_xattr_namespaces_target(&target, out);
}

int metadata_xattr_namespaces_path(const char *path, unsigned int *out)
{
    if (path == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    MetadataXattrTarget target = { .fd = -1, .path = path };
    return metadata_xattr_namespaces_target(&target, out);
}

static int metadata_xattr_input_contains(const SidecarXattr *xattrs,
                                         size_t count, const char *name)
{
    size_t name_length = strlen(name);
    for (size_t index = 0; index < count; index++)
        if (xattrs[index].name.length == name_length &&
            memcmp(xattrs[index].name.data, name, name_length) == 0)
            return 1;
    return 0;
}

static int metadata_apply_xattrs_target(const MetadataXattrTarget *target,
                                        const SidecarXattr *xattrs,
                                        size_t count)
{
    if (target == NULL ||
        metadata_xattr_input_valid(xattrs, count) != 0)
        return -1;

    char *existing_names = NULL;
    size_t existing_count = 0;
    if (metadata_xattr_names_read(target, &existing_names,
                                  &existing_count) != 0)
        return -1;

    size_t offset = 0;
    for (size_t index = 0; index < existing_count; index++)
    {
        char *name = existing_names + offset;
        size_t name_length = strlen(name);
        if (!metadata_xattr_input_contains(xattrs, count, name))
        {
            if (metadata_xattr_remove(target, name) != 0 && errno != ENODATA)
            {
                free(existing_names);
                return -1;
            }
        }
        offset += name_length + 1U;
    }

    for (size_t index = 0; index < count; index++)
    {
        const SidecarXattr *current = &xattrs[index];
        char *name = malloc(current->name.length + 1U);
        if (name == NULL)
        {
            free(existing_names);
            return -1;
        }
        memcpy(name, current->name.data, current->name.length);
        name[current->name.length] = '\0';

        static const unsigned char empty_value;
        const void *value = current->value.length == 0 ? &empty_value :
                                                         current->value.data;
        int failed = metadata_xattr_set(target, name, value,
                                        current->value.length);
        free(name);
        if (failed != 0)
        {
            free(existing_names);
            return -1;
        }
    }
    free(existing_names);
    return 0;
}

static int metadata_safe_xattr_component(const char *component)
{
    if (component == NULL || component[0] == '\0' ||
        strcmp(component, ".") == 0 || strcmp(component, "..") == 0 ||
        strchr(component, '/') != NULL || strlen(component) > NAME_MAX)
        return 0;
    return 1;
}

int metadata_symlink_xattr_path(int dir_fd, const char *leaf,
                                char *path, size_t path_size)
{
    if (dir_fd < 0 || path == NULL || path_size == 0 ||
        !metadata_safe_xattr_component(leaf))
        return -1;
    int length = snprintf(path, path_size, "/proc/self/fd/%d/%s", dir_fd,
                          leaf);
    return length < 0 || (size_t)length >= path_size ? -1 : 0;
}

int metadata_apply_xattrs_fd(int fd, const SidecarXattr *xattrs, size_t count)
{
    MetadataXattrTarget target = { .fd = fd, .path = NULL };
    return metadata_apply_xattrs_target(&target, xattrs, count);
}

int metadata_apply_xattrs_symlink_at(int dir_fd, const char *leaf,
                                     const SidecarXattr *xattrs, size_t count)
{
    char path[PATH_MAX];
    if (metadata_symlink_xattr_path(dir_fd, leaf, path, sizeof(path)) != 0)
        return -1;

    struct stat st;
    if (fstatat(dir_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(st.st_mode))
        return -1;

    MetadataXattrTarget target = { .fd = -1, .path = path };
    return metadata_apply_xattrs_target(&target, xattrs, count);
}

typedef enum {
    METADATA_XATTR_PROBE_DIRECTORY,
    METADATA_XATTR_PROBE_SYMLINK
} MetadataXattrProbeKind;

typedef struct {
    unsigned int namespace_bit;
    const char *name;
    const unsigned char *value;
    size_t value_length;
} MetadataXattrProbeAttribute;

static const unsigned char metadata_system_acl_probe[44] = {
    0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x04, 0x00, 0xfe, 0xff, 0x00, 0x00,
    0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x20, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff
};

static const MetadataXattrProbeAttribute metadata_probe_attributes[] = {
    { METADATA_XATTR_NS_USER, "user.migr_probe",
      (const unsigned char *)"probe", 5 },
    { METADATA_XATTR_NS_SYSTEM, "system.posix_acl_access",
      metadata_system_acl_probe,
      sizeof(metadata_system_acl_probe) },
    { METADATA_XATTR_NS_TRUSTED, "trusted.migr_probe",
      (const unsigned char *)"probe", 5 }
};

#define METADATA_XATTR_NS_ALL \
    (METADATA_XATTR_NS_USER | METADATA_XATTR_NS_SECURITY | \
     METADATA_XATTR_NS_SYSTEM | METADATA_XATTR_NS_TRUSTED)

#define METADATA_XATTR_NS_PROBED \
    (METADATA_XATTR_NS_USER | METADATA_XATTR_NS_SYSTEM | \
     METADATA_XATTR_NS_TRUSTED)

static unsigned long metadata_probe_serial;

static int metadata_create_named_probe(int anchor_fd,
                                       MetadataXattrProbeKind kind,
                                       char *name, size_t name_size)
{
    if (anchor_fd < 0 || name == NULL || name_size == 0)
    {
        errno = EINVAL;
        return -1;
    }

    for (unsigned int attempt = 0; attempt < 1000U; attempt++)
    {
        unsigned long serial = metadata_probe_serial++;
        int length = snprintf(name, name_size, ".migr-xattr-probe-%ld-%lu-%u",
                              (long)getpid(), serial, attempt);
        if (length < 0 || (size_t)length >= name_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }

        int result;
        if (kind == METADATA_XATTR_PROBE_DIRECTORY)
            result = mkdirat(anchor_fd, name, 0700);
        else
            result = symlinkat("migr-xattr-probe-target", anchor_fd, name);
        if (result == 0)
            return 0;
        if (errno != EEXIST)
            return -1;
    }

    errno = EEXIST;
    return -1;
}

static int metadata_probe_attribute_target(const MetadataXattrTarget *target,
                                           const MetadataXattrProbeAttribute *attribute)
{
    /* Deliberately calls metadata_xattr_set/metadata_xattr_remove directly
     * rather than metadata_apply_xattrs_fd/_symlink_at: those do exact-set
     * reconciliation against whatever the probe object already carries, and
     * a freshly-created object already carries an LSM-assigned
     * security.selinux attribute on an SELinux-enabled filesystem.
     * Reconciliation would try to remove that unrelated attribute as
     * "not in the target set," which fails with EACCES for a non-root
     * process -- a failure that has nothing to do with whether the probed
     * namespace itself is usable. The probe only needs "can I set and
     * remove this one name," so it must not touch anything else already on
     * the object. */
    int failed = metadata_xattr_set(target, attribute->name, attribute->value,
                                    attribute->value_length);
    int saved_errno = failed != 0 ? errno : 0;
    if (metadata_xattr_remove(target, attribute->name) != 0)
    {
        if (saved_errno == 0)
            saved_errno = errno;
        failed = 1;
    }
    if (failed && saved_errno != 0)
        errno = saved_errno;
    return failed ? -1 : 0;
}

static int metadata_probe_attribute_fd(int fd,
                                       const MetadataXattrProbeAttribute *attribute)
{
    MetadataXattrTarget target = { .fd = fd, .path = NULL };
    return metadata_probe_attribute_target(&target, attribute);
}

static int metadata_probe_attribute_symlink(int anchor_fd, const char *name,
                                            const MetadataXattrProbeAttribute *attribute)
{
    char path[PATH_MAX];
    if (metadata_symlink_xattr_path(anchor_fd, name, path, sizeof(path)) != 0)
        return -1;
    MetadataXattrTarget target = { .fd = -1, .path = path };
    return metadata_probe_attribute_target(&target, attribute);
}

static int metadata_probe_regular_xattrs(int anchor_fd,
                                         unsigned int namespaces)
{
    if (namespaces == 0)
        return 0;

    int fd = openat(anchor_fd, ".",
                    O_TMPFILE | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    int failed = 0;
    int saved_errno = 0;
    for (size_t i = 0;
         i < sizeof(metadata_probe_attributes) /
                 sizeof(metadata_probe_attributes[0]);
         i++)
    {
        if ((namespaces & metadata_probe_attributes[i].namespace_bit) == 0)
            continue;
        if (metadata_probe_attribute_fd(fd, &metadata_probe_attributes[i]) != 0)
        {
            failed = 1;
            saved_errno = errno;
            break;
        }
    }
    if (close(fd) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    if (failed && saved_errno != 0)
        errno = saved_errno;
    return failed ? -1 : 0;
}

static int metadata_probe_named_xattrs(int anchor_fd,
                                       MetadataXattrProbeKind kind,
                                       unsigned int namespaces)
{
    if (namespaces == 0)
        return 0;

    char name[NAME_MAX + 1];
    if (metadata_create_named_probe(anchor_fd, kind, name, sizeof(name)) != 0)
        return -1;

    int object_fd = -1;
    int failed = 0;
    int saved_errno = 0;
    if (kind == METADATA_XATTR_PROBE_DIRECTORY)
    {
        object_fd = openat(anchor_fd, name,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (object_fd < 0)
        {
            failed = 1;
            saved_errno = errno;
        }
    }

    if (!failed)
    {
        for (size_t i = 0;
             i < sizeof(metadata_probe_attributes) /
                     sizeof(metadata_probe_attributes[0]);
         i++)
        {
            if ((namespaces & metadata_probe_attributes[i].namespace_bit) == 0)
                continue;
            int result = kind == METADATA_XATTR_PROBE_DIRECTORY
                ? metadata_probe_attribute_fd(object_fd,
                                               &metadata_probe_attributes[i])
                : metadata_probe_attribute_symlink(anchor_fd, name,
                                                   &metadata_probe_attributes[i]);
            if (result != 0)
            {
                failed = 1;
                saved_errno = errno;
                break;
            }
        }
    }

    if (object_fd >= 0 && close(object_fd) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    int unlink_flags = kind == METADATA_XATTR_PROBE_DIRECTORY ? AT_REMOVEDIR : 0;
    if (unlinkat(anchor_fd, name, unlink_flags) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    if (failed && saved_errno != 0)
        errno = saved_errno;
    return failed ? -1 : 0;
}

int metadata_xattr_capability_probe(
    int anchor_fd, const MetadataXattrRequirements *required)
{
    if (anchor_fd < 0 || required == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if ((required->regular_namespaces & ~METADATA_XATTR_NS_ALL) != 0 ||
        (required->directory_namespaces & ~METADATA_XATTR_NS_ALL) != 0 ||
        (required->symlink_namespaces & ~METADATA_XATTR_NS_ALL) != 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (required->regular_namespaces == 0 &&
        required->directory_namespaces == 0 &&
        required->symlink_namespaces == 0)
        return 0;

    unsigned int regular_namespaces =
        required->regular_namespaces & METADATA_XATTR_NS_PROBED;
    unsigned int directory_namespaces =
        required->directory_namespaces & METADATA_XATTR_NS_PROBED;
    unsigned int symlink_namespaces =
        required->symlink_namespaces & METADATA_XATTR_NS_PROBED;
    if (regular_namespaces == 0 && directory_namespaces == 0 &&
        symlink_namespaces == 0)
        return 0;

    if (metadata_probe_regular_xattrs(anchor_fd, regular_namespaces) != 0)
        return -1;
    if (metadata_probe_named_xattrs(anchor_fd,
                                    METADATA_XATTR_PROBE_DIRECTORY,
                                    directory_namespaces) != 0)
        return -1;
    if (metadata_probe_named_xattrs(anchor_fd,
                                    METADATA_XATTR_PROBE_SYMLINK,
                                    symlink_namespaces) != 0)
        return -1;
    return 0;
}

int metadata_snapshot_matches(const MetadataSnapshot *snapshot,
                              const struct stat *st)
{
    if (snapshot == NULL || st == NULL)
        return 0;
    if (S_ISLNK(snapshot->type_and_mode))
    {
        struct stat saved;
        if (metadata_snapshot_to_stat(snapshot, &saved) != 0)
            return 0;
        return metadata_symlink_unchanged(&saved, st);
    }
    return snapshot->device == st->st_dev &&
           snapshot->inode == st->st_ino &&
           snapshot->type_and_mode == st->st_mode &&
           snapshot->size == st->st_size &&
           snapshot->uid == st->st_uid &&
           snapshot->gid == st->st_gid &&
           same_timespec(snapshot->atime, st->st_atim) &&
           same_timespec(snapshot->mtime, st->st_mtim) &&
           same_timespec(snapshot->ctime, st->st_ctim);
}

int metadata_source_unchanged(const struct stat *before,
                              const struct stat *after)
{
    if (before == NULL || after == NULL)
        return 0;
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           (before->st_mode & (S_IFMT | 07777 | S_ISUID | S_ISGID | S_ISVTX)) ==
           (after->st_mode & (S_IFMT | 07777 | S_ISUID | S_ISGID | S_ISVTX)) &&
           before->st_size == after->st_size &&
           before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid &&
           same_timespec(before->st_atim, after->st_atim) &&
           same_timespec(before->st_mtim, after->st_mtim) &&
           same_timespec(before->st_ctim, after->st_ctim);
}

int metadata_symlink_unchanged(const struct stat *before,
                               const struct stat *after)
{
    if (before == NULL || after == NULL)
        return 0;
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           (before->st_mode & (S_IFMT | 07777 | S_ISUID | S_ISGID | S_ISVTX)) ==
           (after->st_mode & (S_IFMT | 07777 | S_ISUID | S_ISGID | S_ISVTX)) &&
           before->st_size == after->st_size &&
           before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid &&
           same_timespec(before->st_mtim, after->st_mtim) &&
           same_timespec(before->st_ctim, after->st_ctim);
}
