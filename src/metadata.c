#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#include "fileops.h"
#include "metadata.h"

#ifdef METADATA_TEST_HOOKS
static uint64_t metadata_ownership_probe_calls;
static MetadataTestProbeHook metadata_ownership_probe_hook;
static void *metadata_ownership_probe_hook_context;

uint64_t metadata_test_probe_count(void)
{
    return metadata_ownership_probe_calls;
}

void metadata_test_reset_probe_count(void)
{
    metadata_ownership_probe_calls = 0;
}

void metadata_test_set_probe_hook(MetadataTestProbeHook hook, void *context)
{
    metadata_ownership_probe_hook = hook;
    metadata_ownership_probe_hook_context = context;
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

static void metadata_profiles_record_example(MetadataProfiles *profiles,
                                              const char *path)
{
    if (path != NULL && profiles->example_count < METADATA_MAX_PREFLIGHT_EXAMPLES)
    {
        int n = snprintf(profiles->examples[profiles->example_count],
                         sizeof(profiles->examples[0]), "%s", path);
        if (n >= 0 && (size_t)n < sizeof(profiles->examples[0]))
            profiles->example_count++;
    }
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
            metadata_profiles_record_example(profiles, path);
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
    metadata_profiles_record_example(profiles, path);
    return 0;
}

void metadata_profiles_note_security_xattr(MetadataProfiles *profiles)
{
    if (profiles != NULL && profiles->security_xattr_entry_count != SIZE_MAX)
        profiles->security_xattr_entry_count++;
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
    metadata_ownership_probe_calls++;
    if (metadata_ownership_probe_hook != NULL)
        metadata_ownership_probe_hook(metadata_ownership_probe_hook_context);
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

static int metadata_snapshot_from_stat(const struct stat *st,
                                       MetadataSnapshot *out)
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

static struct timespec metadata_canonical_time(
    struct timespec value, MetadataTimestampPolicy policy)
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

static int metadata_stat_fields_unchanged(const struct stat *before,
                                          const struct stat *after,
                                          int compare_atime)
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
           (!compare_atime || same_timespec(before->st_atim, after->st_atim)) &&
           same_timespec(before->st_mtim, after->st_mtim) &&
           same_timespec(before->st_ctim, after->st_ctim);
}

int metadata_snapshot_matches(const MetadataSnapshot *snapshot,
                              const struct stat *st)
{
    if (snapshot == NULL || st == NULL)
        return 0;

    struct stat saved;
    if (metadata_snapshot_to_stat(snapshot, &saved) != 0)
        return 0;
    return S_ISLNK(snapshot->type_and_mode)
        ? metadata_symlink_unchanged(&saved, st)
        : metadata_source_unchanged(&saved, st);
}

int metadata_source_unchanged(const struct stat *before,
                              const struct stat *after)
{
    return metadata_stat_fields_unchanged(before, after, 1);
}

int metadata_symlink_unchanged(const struct stat *before,
                               const struct stat *after)
{
    return metadata_stat_fields_unchanged(before, after, 0);
}
