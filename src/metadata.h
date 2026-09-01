#ifndef METADATA_H
#define METADATA_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sidecar.h"

typedef struct CloneContext CloneContext;

#define METADATA_MAX_PROFILES 65536U
#define METADATA_MAX_PREFLIGHT_EXAMPLES 16U

typedef struct {
    int nsec_exact;
    int configured;
} MetadataTimestampPolicy;

typedef struct {
    dev_t device;
    ino_t inode;
    mode_t type_and_mode;
    off_t size;
    uid_t uid;
    gid_t gid;
    struct timespec atime;
    struct timespec mtime;
    struct timespec ctime;
} MetadataSnapshot;

typedef struct {
    dev_t anchor_device;
    ino_t anchor_inode;
    uint64_t mount_identity;
    uid_t initial_uid;
    gid_t initial_gid;
    uid_t desired_uid;
    gid_t desired_gid;
    mode_t desired_mode;
    int has_initial_owner;
    int anchor_fd;
} MetadataProfile;

typedef struct MetadataProfiles {
    MetadataProfile *items;
    size_t count;
    size_t capacity;
    size_t affected_objects;
    size_t security_xattr_entry_count;
    size_t example_count;
    char examples[METADATA_MAX_PREFLIGHT_EXAMPLES][PATH_MAX];
} MetadataProfiles;

typedef struct MetadataSnapshots {
    MetadataSnapshot *items;
    size_t count;
    size_t capacity;
    void *dev_ino_index;    // private: MetadataSnapshotIndexSlot[], see metadata.c
    size_t index_capacity;
    uint64_t index_hash_salt;
} MetadataSnapshots;

enum {
    METADATA_XATTR_NS_USER     = 1u << 0,
    METADATA_XATTR_NS_SECURITY = 1u << 1,
    METADATA_XATTR_NS_SYSTEM   = 1u << 2,
    METADATA_XATTR_NS_TRUSTED  = 1u << 3
};

typedef struct {
    unsigned int regular_namespaces;
    unsigned int directory_namespaces;
    unsigned int symlink_namespaces;
} MetadataXattrRequirements;

void metadata_profiles_init(MetadataProfiles *profiles);
void metadata_profiles_free(MetadataProfiles *profiles);
int metadata_profiles_add(MetadataProfiles *profiles, int anchor_fd,
                          const struct stat *desired,
                          const struct stat *existing,
                          const char *path);
int metadata_profiles_probe(const MetadataProfiles *profiles,
                            MetadataTimestampPolicy policy);
void metadata_profiles_report(const MetadataProfiles *profiles);
void metadata_profiles_note_security_xattr(MetadataProfiles *profiles);
int metadata_xattr_capability_probe(
    int anchor_fd, const MetadataXattrRequirements *required);
int metadata_xattr_namespaces_fd(int fd, unsigned int *out);
int metadata_xattr_namespaces_path(const char *path, unsigned int *out);

/*
 * Length-aware xattr namespace classifier for non-NUL-terminated names
 * (sidecar SidecarBytes). The four namespace prefixes live only here;
 * metadata.c's NUL-terminated wrapper shares this implementation.
 */
unsigned int metadata_xattr_namespace_bytes(const unsigned char *name,
                                            size_t length);

#ifdef METADATA_TEST_HOOKS
typedef void (*MetadataTestProbeHook)(void *context);

uint64_t metadata_test_probe_count(void);
void metadata_test_reset_probe_count(void);
void metadata_test_set_probe_hook(MetadataTestProbeHook hook, void *context);
#endif

void metadata_snapshots_init(MetadataSnapshots *snapshots);
void metadata_snapshots_free(MetadataSnapshots *snapshots);
int metadata_snapshot_record(MetadataSnapshots *snapshots,
                             const struct stat *st);
const MetadataSnapshot *metadata_snapshot_find(const MetadataSnapshots *snapshots,
                                               const struct stat *st);

MetadataTimestampPolicy metadata_policy_from_context(const CloneContext *ctx);
int metadata_snapshot_to_stat(const MetadataSnapshot *snapshot,
                              struct stat *out);
int metadata_snapshot_matches(const MetadataSnapshot *snapshot,
                              const struct stat *st);
int metadata_source_unchanged(const struct stat *before,
                              const struct stat *after);
int metadata_symlink_unchanged(const struct stat *before,
                               const struct stat *after);

int metadata_apply_fd(int fd, const struct stat *desired,
                      MetadataTimestampPolicy policy);
int metadata_apply_ownership_and_mode_fd(int fd,
                                         const struct stat *desired);
int metadata_apply_times_fd(int fd, const struct stat *desired,
                            MetadataTimestampPolicy policy);
int metadata_apply_symlink_at(int dir_fd, const char *leaf,
                              const struct stat *desired,
                              MetadataTimestampPolicy policy);
int metadata_apply_symlink_ownership_at(int dir_fd, const char *leaf,
                                        const struct stat *desired);
int metadata_apply_symlink_times_at(int dir_fd, const char *leaf,
                                    const struct stat *desired,
                                    MetadataTimestampPolicy policy);
int metadata_apply_xattrs_fd(int fd, const SidecarXattr *xattrs,
                             size_t count);
int metadata_apply_xattrs_fd_report(int fd, const SidecarXattr *xattrs,
                                    size_t count,
                                    size_t *skipped_security_count);
int metadata_symlink_xattr_path(int dir_fd, const char *leaf,
                                char *path, size_t path_size);
int metadata_apply_xattrs_symlink_at(int dir_fd, const char *leaf,
                                     const SidecarXattr *xattrs, size_t count);
int metadata_apply_xattrs_symlink_at_report(
    int dir_fd, const char *leaf, const SidecarXattr *xattrs, size_t count,
    size_t *skipped_security_count);

#ifdef METADATA_XATTR_TEST_HOOKS
/*
 * Fires once, inside metadata_apply_xattrs_symlink_at_report(), between its
 * pre-check fstatat() and the xattr syscalls -- lets a test replace dir_fd's
 * leaf with a different object right in the TOCTOU window the syscalls'
 * fresh /proc/self/fd re-resolution opens up.
 */
typedef void (*MetadataXattrTestSymlinkRaceHook)(int dir_fd, const char *leaf);
void metadata_xattr_test_set_symlink_race_hook(
    MetadataXattrTestSymlinkRaceHook hook);
#endif

#endif
