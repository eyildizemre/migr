#ifndef METADATA_H
#define METADATA_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

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
    size_t example_count;
    char examples[METADATA_MAX_PREFLIGHT_EXAMPLES][PATH_MAX];
} MetadataProfiles;

typedef struct MetadataSnapshots {
    MetadataSnapshot *items;
    size_t count;
    size_t capacity;
} MetadataSnapshots;

void metadata_profiles_init(MetadataProfiles *profiles);
void metadata_profiles_free(MetadataProfiles *profiles);
int metadata_profiles_add(MetadataProfiles *profiles, int anchor_fd,
                          const struct stat *desired,
                          const struct stat *existing,
                          const char *path);
int metadata_profiles_probe(const MetadataProfiles *profiles,
                            MetadataTimestampPolicy policy);
void metadata_profiles_report(const MetadataProfiles *profiles);

#ifdef METADATA_TEST_HOOKS
uint64_t metadata_test_probe_count(void);
void metadata_test_reset_probe_count(void);
#endif

void metadata_snapshots_init(MetadataSnapshots *snapshots);
void metadata_snapshots_free(MetadataSnapshots *snapshots);
int metadata_snapshot_record(MetadataSnapshots *snapshots,
                             const struct stat *st);
const MetadataSnapshot *metadata_snapshot_find(const MetadataSnapshots *snapshots,
                                               const struct stat *st);

MetadataTimestampPolicy metadata_policy_from_context(const CloneContext *ctx);
struct timespec metadata_canonical_time(struct timespec value,
                                        MetadataTimestampPolicy policy);
int metadata_snapshot_from_stat(const struct stat *st, MetadataSnapshot *out);
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
int metadata_apply_symlink_at(int dir_fd, const char *leaf,
                              const struct stat *desired,
                              MetadataTimestampPolicy policy);

#endif
