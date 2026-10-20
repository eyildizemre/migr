#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#include "backup.h"
#include "backup_plan.h"
#include "selection.h"
#include "source_snapshot.h"
#include "container.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "metadata.h"
#include "move.h"
#include "packages.h"
#include "groups.h"
#include "flatpak.h"
#include "portable.h"
#include "repair.h"
#include "selfcopy.h"
#include "sidecar.h"
#include "utils.h"
#include "writer_apps.h"
#include "xdg.h"

typedef struct {
    const char *name;
    const char *source_dir;
    const char *container_subdir;
    int may_contain_secrets;
    const char *filename_suffix;
} NetworkConfigBackend;

static const NetworkConfigBackend NETWORK_CONFIG_BACKENDS[] = {
    { "NetworkManager", "/etc/NetworkManager/system-connections",
      "networkmanager", 1, NULL },
    { "netplan", "/etc/netplan", "netplan", 1, NULL },
    { "systemd-networkd", "/etc/systemd/network", "systemd-networkd", 1, NULL },
    { "wpa_supplicant", "/etc/wpa_supplicant", "wpa_supplicant", 1, ".conf" },
    { "netctl", "/etc/netctl", "netctl", 1, NULL },
};

#define NETWORK_CONFIG_BACKEND_COUNT \
    (sizeof(NETWORK_CONFIG_BACKENDS) / sizeof(NETWORK_CONFIG_BACKENDS[0]))

#ifdef BACKUP_TEST_HOOKS
static BackupTestInventoryHook backup_test_inventory_hook;
static void *backup_test_inventory_context;
static BackupTestFreeSpaceHook backup_test_free_space_hook;
static void *backup_test_free_space_context;
static BackupTestBlockSizeHook backup_test_block_size_hook;
static void *backup_test_block_size_context;
static BackupTestProgressHook backup_test_progress_hook;
static void *backup_test_progress_context;
static const char *backup_test_network_config_source_dirs[
    NETWORK_CONFIG_BACKEND_COUNT];
static int backup_test_portable_representation_forced;
static int backup_test_case_insensitive_destination_forced;
static int backup_test_restore_privilege_bypass;
static int backup_test_invoker_set;
static uid_t backup_test_invoker_uid;
static gid_t backup_test_invoker_gid;
static const char *backup_test_machine_id;
static BackupTestSidecarReadbackHook backup_test_sidecar_readback_hook;
static void *backup_test_sidecar_readback_context;

void backup_test_set_sidecar_readback_hook(BackupTestSidecarReadbackHook hook,
                                           void *context)
{
    backup_test_sidecar_readback_hook = hook;
    backup_test_sidecar_readback_context = context;
}

void backup_test_set_inventory_hook(BackupTestInventoryHook hook,
                                    void *context)
{
    backup_test_inventory_hook = hook;
    backup_test_inventory_context = context;
}

void backup_test_set_free_space_hook(BackupTestFreeSpaceHook hook,
                                     void *context)
{
    backup_test_free_space_hook = hook;
    backup_test_free_space_context = context;
}

void backup_test_set_block_size_hook(BackupTestBlockSizeHook hook,
                                     void *context)
{
    backup_test_block_size_hook = hook;
    backup_test_block_size_context = context;
}

void backup_test_set_progress_hook(BackupTestProgressHook hook,
                                   void *context)
{
    backup_test_progress_hook = hook;
    backup_test_progress_context = context;
}

void backup_test_set_network_config_source_dir(const char *backend_name,
                                               const char *source_dir)
{
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        if (strcmp(NETWORK_CONFIG_BACKENDS[i].name, backend_name) == 0)
        {
            backup_test_network_config_source_dirs[i] = source_dir;
            return;
        }
    }
}

void backup_test_force_portable_representation(int enabled)
{
    backup_test_portable_representation_forced = enabled != 0;
}

void backup_test_force_case_insensitive_destination(int enabled)
{
    backup_test_case_insensitive_destination_forced = enabled != 0;
}

void backup_test_set_restore_privilege_bypass(int enabled)
{
    backup_test_restore_privilege_bypass = enabled != 0;
}

void backup_test_set_machine_id(const char *machine_id)
{
    backup_test_machine_id = machine_id;
}

void backup_test_set_invoker(int enabled, uid_t uid, gid_t gid)
{
    backup_test_invoker_set = enabled != 0;
    backup_test_invoker_uid = uid;
    backup_test_invoker_gid = gid;
}

static void backup_test_before_source_open(const char *source_path)
{
    if (backup_test_inventory_hook != NULL)
        backup_test_inventory_hook(source_path, backup_test_inventory_context);
}
#endif

int destination_block_size(int dest_fd, off_t *block_size)
{
    if (dest_fd < 0 || block_size == NULL)
    {
        errno = EINVAL;
        return -1;
    }

#ifdef BACKUP_TEST_HOOKS
    if (backup_test_block_size_hook != NULL)
    {
        *block_size = 0;
        backup_test_block_size_hook(block_size,
                                    backup_test_block_size_context);
        return 0;
    }
#endif

    struct statfs fs;
    if (fstatfs(dest_fd, &fs) != 0)
        return -1;

    uintmax_t selected = (uintmax_t)(fs.f_frsize != 0
                                         ? fs.f_frsize : fs.f_bsize);
    if (selected == 0 || selected > (uintmax_t)INTMAX_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    *block_size = (off_t)selected;
    return 0;
}

// Returns 1 when the destination has at least `needed` bytes available, 0
// when it clearly does not, and -1 with errno when the filesystem space
// cannot be read.
// f_bavail is the space this unprivileged process can actually consume;
// f_bfree also includes blocks reserved for root.
int destination_has_space(int dest_fd, off_t needed, off_t *free_bytes)
{
    if (dest_fd < 0 || needed < 0 || free_bytes == NULL)
    {
        errno = EINVAL;
        return -1;
    }

#ifdef BACKUP_TEST_HOOKS
    if (backup_test_free_space_hook != NULL)
    {
        *free_bytes = 0;
        backup_test_free_space_hook(needed, free_bytes,
                                    backup_test_free_space_context);
        if (*free_bytes < 0)
        {
            errno = EIO;
            return -1;
        }
        return needed <= *free_bytes;
    }
#endif

    off_t block_size = 0;
    if (destination_block_size(dest_fd, &block_size) != 0)
        return -1;
    if (block_size <= 0)
    {
        errno = EINVAL;
        return -1;
    }

    struct statfs fs;
    if (fstatfs(dest_fd, &fs) != 0)
        return -1;

    uintmax_t blocks = (uintmax_t)fs.f_bavail;
    uintmax_t allocation_size = (uintmax_t)block_size;
    if (blocks > UINTMAX_MAX / allocation_size)
    {
        errno = EOVERFLOW;
        return -1;
    }

    uintmax_t available = blocks * allocation_size;
    *free_bytes = available > (uintmax_t)INTMAX_MAX
        ? (off_t)INTMAX_MAX
        : (off_t)available;
    return needed <= *free_bytes;
}

/* Reads only the destination's current free space -- the progress display's
 * use case, which has no "needed" amount to compare against.
 */
static int destination_free_bytes(int dest_fd, off_t *free_bytes)
{
    return destination_has_space(dest_fd, 0, free_bytes) < 0 ? -1 : 0;
}

int restore_space_preflight(int destination_fd, const char *home,
                            off_t estimated_bytes, int estimate_had_error)
{
    if (estimate_had_error)
    {
        print_warning("Warning: could not fully estimate restore size: out "
                      "of memory, or a total too large to count; skipping "
                      "the free-space preflight check.\n");
        return 0;
    }

    off_t block_size = 0;
    int block_failed = destination_block_size(destination_fd,
                                              &block_size) != 0;
    if (block_failed || block_size <= 0)
    {
        print_warning("Warning: could not determine destination free space: "
                      "%s; skipping the free-space preflight check.\n",
                      block_failed ? strerror(errno)
                                   : "it reports no block size");
        return 0;
    }

    off_t free_bytes = 0;
    int has_space = destination_has_space(destination_fd, estimated_bytes,
                                          &free_bytes);
    if (has_space < 0)
    {
        print_warning("Warning: could not determine destination free space: "
                      "%s; skipping the free-space preflight check.\n",
                      strerror(errno));
        return 0;
    }

    char estimated_text[32];
    char free_text[32];
    format_size(estimated_bytes, estimated_text, sizeof(estimated_text));
    format_size(free_bytes, free_text, sizeof(free_text));
    printf("Estimated restore size: %s\n", estimated_text);
    printf("Destination free space: %s\n", free_text);
    if (!has_space)
    {
        off_t shortfall = estimated_bytes - free_bytes;
        char shortfall_text[32];
        format_size(shortfall, shortfall_text, sizeof(shortfall_text));
        fflush(stdout);
        print_error("Error: not enough free space at %s (need %s more)\n",
                    home, shortfall_text);
        return -1;
    }
    return 0;
}

int restore_privilege_preflight(size_t foreign_owner_count,
                                int network_config_needs_privilege)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_restore_privilege_bypass)
        return 0;
#endif

    // Root can chown to any recorded owner, so a root-invoked restore never
    // needs this refusal regardless of what the manifest/sidecar records
    // (docs/DECISIONS.md D38).
    if (geteuid() == 0)
        return 0;

    if (foreign_owner_count == 0 && !network_config_needs_privilege)
        return 0;

    // No count: a native inventory that stopped at an unreadable file of
    // another user knows of at least one, not how many.
    if (foreign_owner_count != 0 && network_config_needs_privilege)
        print_error("Error: This restore needs root: it would restore items "
                    "owned by a different user and apply saved network "
                    "configuration. Rerun the same migr command with "
                    "sudo.\n");
    else if (foreign_owner_count != 0)
        print_error("Error: This restore needs root: it would restore items "
                    "owned by a different user. Rerun the same migr command "
                    "with sudo.\n");
    else
        print_error("Error: This restore needs root: it would apply saved "
                    "network configuration. Rerun the same migr command "
                    "with sudo.\n");
    return -1;
}

void restore_privilege_dry_run_note(void)
{
    if (geteuid() != 0)
        printf("Note: the real restore needs root. Run it with sudo.\n");
}

// The user a sudo backup runs for (D38). Returns 0 with their ids, or -1
// when the backup does not run through sudo.
static int backup_invoker_identity(uid_t *uid, gid_t *gid)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_invoker_set)
    {
        *uid = backup_test_invoker_uid;
        *gid = backup_test_invoker_gid;
        return 0;
    }
#endif
    return sudo_invoker(uid, gid, NULL) == 1 ? 0 : -1;
}

// Whose data a backup holds, as recorded in its source identity (D15): the
// sudo invoker when run through sudo (D62), otherwise the caller.
static uid_t backup_source_uid(void)
{
    uid_t uid;
    gid_t gid;
    return backup_invoker_identity(&uid, &gid) == 0 ? uid : getuid();
}

// That user's primary group, recorded beside the uid (D85).
static gid_t backup_source_gid(void)
{
    uid_t uid;
    gid_t gid;
    return backup_invoker_identity(&uid, &gid) == 0 ? gid : getgid();
}

// A sudo backup on a destination that records ownership belongs to the user
// who ran it (D70), so they can look at, preview, and delete it without
// sudo. Only migr's own entries change hands: the destination folder when
// migr created it, the container, data/, and the files at the container's
// top. Payload entries keep the owners they were captured with, and
// network/ stays root's, since it can hold Wi-Fi secrets.
static void backup_give_to_invoker(int container_fd, int target_created)
{
    uid_t uid;
    gid_t gid;
    if (container_fd < 0 || backup_invoker_identity(&uid, &gid) != 0)
        return;
    int error = 0; /* The first failure's errno. */
    if (fchown(container_fd, uid, gid) != 0)
        error = errno;
    if (target_created)
    {
        int parent_fd = openat(container_fd, "..",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if ((parent_fd < 0 || fchown(parent_fd, uid, gid) != 0) && error == 0)
            error = errno;
        if (parent_fd >= 0)
            close(parent_fd);
    }
    int scan_fd = openat(container_fd, ".",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        if (error == 0)
            error = errno;
        if (scan_fd >= 0)
            close(scan_fd);
    }
    struct dirent *entry;
    while (dir != NULL && (entry = readdir(dir)) != NULL)
    {
        struct stat st;
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            fstatat(container_fd, entry->d_name, &st,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !(S_ISREG(st.st_mode) ||
              (S_ISDIR(st.st_mode) && strcmp(entry->d_name, "data") == 0)))
            continue;
        if (fchownat(container_fd, entry->d_name, uid, gid,
                     AT_SYMLINK_NOFOLLOW) != 0 && error == 0)
            error = errno;
    }
    if (dir != NULL)
        closedir(dir);
    // The folder the capture made for non-user roots is migr's too (D82).
    // data/ is opened first: a path through it would follow a data/ that
    // is a link.
    int data_fd = openat(container_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat settings_st;
    if (data_fd >= 0 &&
        fstatat(data_fd, BACKUP_PLAN_SETTINGS_DIR, &settings_st,
                AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(settings_st.st_mode) &&
        fchownat(data_fd, BACKUP_PLAN_SETTINGS_DIR, uid, gid,
                 AT_SYMLINK_NOFOLLOW) != 0 && error == 0)
        error = errno;
    if (data_fd >= 0)
        close(data_fd);
    if (error != 0)
        print_warning("Warning: could not give every part of the backup "
                      "container to the user who ran sudo: %s\n",
                      strerror(error));
}

/* Returns 0 to proceed (space is adequate, or an earlier probe/estimate
 * step failed and already printed its own warning), or -1 if the
 * destination does not have enough free space (having already printed the
 * shortfall error). reused_size is the space the backup being updated
 * already holds there (D98). The caller is responsible for its own cleanup
 * and return value in that case.
 */
static int backup_space_preflight(int dest_fd, off_t estimated_size,
                                  off_t raw_estimated_size,
                                  int estimate_had_error,
                                  int raw_estimate_had_error,
                                  const FailedItem *estimate_failure,
                                  off_t reused_size, const char *target)
{
    if (estimate_had_error || raw_estimate_had_error)
    {
        print_step_warning(&estimate_failure->step,
                           "Warning: could not fully estimate backup size at "
                           "%s", estimate_failure->path);
        print_warning("  The free-space check is skipped.\n");
        return 0;
    }

    off_t needed = estimated_size > reused_size
        ? estimated_size - reused_size : 0;
    off_t free_bytes = 0;
    int has_space = destination_has_space(dest_fd, needed, &free_bytes);
    if (has_space < 0)
    {
        print_warning("Warning: could not determine destination free space: "
                      "%s; skipping the free-space preflight check.\n",
                      strerror(errno));
        return 0;
    }

    char estimated_text[32];
    char free_text[32];
    format_size(raw_estimated_size, estimated_text, sizeof(estimated_text));
    format_size(free_bytes, free_text, sizeof(free_text));
    printf("Estimated backup size: %s\n", estimated_text);
    if (reused_size > 0)
    {
        char reused_text[32];
        format_size(reused_size, reused_text, sizeof(reused_text));
        printf("Size of the backup being updated: %s\n", reused_text);
    }
    printf("Destination free space: %s\n", free_text);
    printf("\n");

    if (!has_space)
    {
        off_t shortfall = needed - free_bytes;
        char shortfall_text[32];
        format_size(shortfall, shortfall_text, sizeof(shortfall_text));
        print_error("Error: not enough free space at %s (need %s more)\n",
                    target, shortfall_text);
        return -1;
    }
    return 0;
}

typedef enum {
    UPDATE_NONE = 0, /* a new backup */
    UPDATE_OWN,      /* this install's backup */
    UPDATE_OTHER     /* the one finished backup of another install (D88) */
} UpdateTarget;

/* The backup a run would update under dest_fd, as adoption will find it:
 * this install's, or with take_other the one finished backup of another
 * install it offers to update instead. Its name goes to name, and to
 * reused_size the space it already holds, most of which the update keeps
 * (D98): 0 when unrecorded or a first backup still unfinished.
 */
static UpdateTarget backup_update_target(int dest_fd, const Manifest *wanted,
                                         int take_other,
                                         char name[CONTAINER_NAME_MAX],
                                         off_t *reused_size)
{
    name[0] = '\0';
    *reused_size = 0;
    ContainerSurvey survey;
    if (container_survey_fd(dest_fd, invoker_name(), wanted, &survey) != 0)
        return UPDATE_NONE;
    if (survey.own == 1)
    {
        memcpy(name, survey.own_name, CONTAINER_NAME_MAX);
        *reused_size = survey.own_size;
        return UPDATE_OWN;
    }
    if (survey.own == 0 && survey.other == 1 && take_other)
    {
        memcpy(name, survey.other_name, CONTAINER_NAME_MAX);
        *reused_size = survey.other_size;
        return UPDATE_OTHER;
    }
    return UPDATE_NONE;
}

/* Returns 0 to proceed (*out_profile and *out_repr are set), or -1 if the
 * destination could not be probed or is not usable for backup (having already
 * printed the refusal error). The caller is responsible for its own cleanup
 * and return value in that case.
 */
static int backup_representation_preflight(int dest_fd, const char *target,
                                           FsCapabilityProfile *out_profile,
                                           CloneRepresentation *out_repr)
{
    if (fsprobe_fd(dest_fd, out_profile) != 0)
    {
        int error = errno;
        print_error("Error: could not probe the destination filesystem at "
                    "%s: %s\n", target, strerror(error));
        if (error == ENOSPC)
            print_error("  The destination is full; free some space on it "
                        "and run the backup again.\n");
        return -1;
    }
    if (select_representation(out_profile, out_repr) != 0)
    {
        print_error("Error: could not measure what the destination "
                    "filesystem at %s can keep, so the backup's format "
                    "would be a guess\n", target);
        return -1;
    }
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_portable_representation_forced)
        *out_repr = CLONE_PORTABLE_SIDECAR;
    if (backup_test_case_insensitive_destination_forced)
        out_profile->capabilities[FS_CAP_CASE_SENSITIVE] =
            (FsCapabilityResult){ .status = FS_CAP_UNAVAILABLE };
#endif
    return 0;
}

static int probe_self_binary(int *out_fd, char *arch, size_t arch_size)
{
    MigrStaticStatus status = migr_static_probe(out_fd, arch, arch_size);
    switch (status)
    {
        case MIGR_STATIC_OK:
            return 0;
        case MIGR_STATIC_NOT_FOUND:
        {
            char path[PATH_MAX];
            if (migr_static_path(path) == 0)
                print_error("Error: --include-self needs %s, which does not "
                            "exist.\n", path);
            else
                print_error("Error: --include-self could not find migr-static "
                            "beside the running executable.\n");
            print_error("  Install the static migr there under that name, as "
                        "the README's Install section shows.\n");
            break;
        }
        case MIGR_STATIC_NOT_ELF:
            print_error("Error: migr-static beside the running executable is not "
                        "a usable 64-bit little-endian ELF binary.\n");
            break;
        case MIGR_STATIC_NOT_STATIC:
            print_error("Error: migr-static was found but is dynamically linked; "
                        "it would not be portable to another system.\n");
            break;
        case MIGR_STATIC_UNKNOWN_ARCH:
            print_error("Error: migr-static has an unsupported architecture and "
                        "cannot be included in the backup.\n");
            break;
        case MIGR_STATIC_IO_ERROR:
            print_error("Error: could not inspect migr-static for --include-self: %s\n",
                        strerror(errno));
            break;
    }
    return -1;
}

static void manifest_set_self_binary(Manifest *manifest, const char *arch)
{
    manifest->has_self_binary = 1;
    memcpy(manifest->arch, arch, strlen(arch) + 1);
}

static const char *network_config_source_dir(size_t backend_index)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_network_config_source_dirs[backend_index] != NULL)
        return backup_test_network_config_source_dirs[backend_index];
#endif
    return NETWORK_CONFIG_BACKENDS[backend_index].source_dir;
}

static int network_config_name_matches_suffix(const char *name,
                                              const char *filename_suffix)
{
    if (filename_suffix == NULL)
        return 1;
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(filename_suffix);
    return name_len >= suffix_len &&
           strcmp(name + name_len - suffix_len, filename_suffix) == 0;
}

static int network_config_preflight_error(size_t backend_index,
                                          const char *source_dir,
                                          const char *entry_name, int err)
{
    const char *backend_name = NETWORK_CONFIG_BACKENDS[backend_index].name;
    if (err == EACCES || err == EPERM)
    {
        if (entry_name != NULL)
            print_error("Error: --include-network-config: cannot read %s configuration file at %s/%s (%s). "
                        "Rerun the same migr command with sudo.\n",
                        backend_name, source_dir, entry_name, strerror(err));
        else
            print_error("Error: --include-network-config: cannot read %s backend at %s (%s). "
                        "Rerun the same migr command with sudo.\n",
                        backend_name, source_dir, strerror(err));
    }
    else
    {
        if (entry_name != NULL)
            print_error("Error: --include-network-config: cannot read %s configuration file at %s/%s (%s).\n",
                        backend_name, source_dir, entry_name, strerror(err));
        else
            print_error("Error: --include-network-config: cannot read %s backend at %s (%s).\n",
                        backend_name, source_dir, strerror(err));
    }
    errno = err;
    return -1;
}

static int check_network_config_readable(unsigned int *present_mask)
{
    *present_mask = 0;
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        const char *source_dir = network_config_source_dir(i);
        int source_fd = open(source_dir,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (source_fd < 0)
        {
            int saved_errno = errno;
            if (saved_errno == ENOENT)
                continue;
            return network_config_preflight_error(i, source_dir, NULL,
                                                  saved_errno);
        }

        DIR *directory = fdopendir(source_fd);
        if (directory == NULL)
        {
            int saved_errno = errno;
            close(source_fd);
            return network_config_preflight_error(i, source_dir, NULL,
                                                  saved_errno);
        }

        for (;;)
        {
            errno = 0;
            struct dirent *entry = readdir(directory);
            if (entry == NULL)
            {
                int saved_errno = errno;
                if (saved_errno != 0)
                {
                    (void)closedir(directory);
                    return network_config_preflight_error(
                        i, source_dir, NULL, saved_errno);
                }
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            struct stat entry_st;
            if (fstatat(dirfd(directory), entry->d_name, &entry_st,
                        AT_SYMLINK_NOFOLLOW) != 0)
            {
                int saved_errno = errno;
                network_config_preflight_error(i, source_dir, entry->d_name,
                                               saved_errno);
                (void)closedir(directory);
                errno = saved_errno;
                return -1;
            }
            if (!S_ISREG(entry_st.st_mode) ||
                !network_config_name_matches_suffix(
                    entry->d_name,
                    NETWORK_CONFIG_BACKENDS[i].filename_suffix))
                continue;

            int candidate_fd = openat(
                dirfd(directory), entry->d_name,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
            if (candidate_fd < 0)
            {
                int saved_errno = errno;
                if (saved_errno == ELOOP)
                    continue;
                network_config_preflight_error(i, source_dir, entry->d_name,
                                               saved_errno);
                (void)closedir(directory);
                errno = saved_errno;
                return -1;
            }

            struct stat candidate_st;
            if (fstat(candidate_fd, &candidate_st) != 0)
            {
                int saved_errno = errno;
                close(candidate_fd);
                network_config_preflight_error(i, source_dir, entry->d_name,
                                               saved_errno);
                (void)closedir(directory);
                errno = saved_errno;
                return -1;
            }
            if (close(candidate_fd) != 0)
            {
                int saved_errno = errno;
                network_config_preflight_error(i, source_dir, entry->d_name,
                                               saved_errno);
                (void)closedir(directory);
                errno = saved_errno;
                return -1;
            }

            /* The entry may have changed between fstatat() and openat().
             * The copy path performs the same regular-file check again. */
            if (!S_ISREG(candidate_st.st_mode))
                continue;
        }

        if (closedir(directory) != 0)
        {
            int saved_errno = errno;
            return network_config_preflight_error(i, source_dir, NULL,
                                                  saved_errno);
        }
        *present_mask |= 1u << i;
    }
    return 0;
}

static int portable_prescan_example_is_unresolved(
    const PortablePrescanViolation *violation)
{
    return !violation->resolved;
}

static void print_portable_prescan_failure(const PortablePrescanReport *report,
                                           const char *target, int preview)
{
    const char *outcome = preview
        ? "nothing would be created"
        : "no container was created";

    if (report != NULL && report->operational_failure)
    {
        const char *path = report->operational_failure_path[0] != '\0'
            ? report->operational_failure_path : "(selected root)";
        print_error("Error: could not scan %s while preparing the portable capture at %s (%s); %s\n",
                    path, target,
                    strerror(report->operational_failure_errno), outcome);
        return;
    }

    if (report != NULL && report->unresolved_count > 0)
    {
        print_error("Error: portable pre-scan found %zu unresolved issue(s) at %s; %s:\n",
                    report->unresolved_count, target, outcome);
        enum { DISPLAY_LIMIT = 10 };
        size_t shown = 0;
        for (size_t i = 0;
             i < report->example_count && shown < DISPLAY_LIMIT; i++)
        {
            const PortablePrescanViolation *violation = &report->examples[i];
            if (!portable_prescan_example_is_unresolved(violation))
                continue;

            const char *path = violation->logical_path[0] != '\0'
                ? violation->logical_path : "(selected root)";
            switch (violation->kind)
            {
                case PORTABLE_PRESCAN_NAME_TOO_LONG:
                    print_error("  - name too long at %s (%zu bytes; limit %zu)\n",
                                path, violation->actual, violation->limit);
                    break;
                case PORTABLE_PRESCAN_PATH_TOO_LONG:
                    print_error("  - path too long at %s (%zu bytes; limit %zu)\n",
                                path, violation->actual, violation->limit);
                    break;
                case PORTABLE_PRESCAN_CASE_COLLISION:
                {
                    const char *other =
                        violation->collides_with_logical_path[0] != '\0'
                            ? violation->collides_with_logical_path
                            : "(selected root)";
                    print_error("  - %s collides with %s on this case-insensitive destination\n",
                                path, other);
                    break;
                }
                case PORTABLE_PRESCAN_UNSUPPORTED_KIND:
                    print_error("  - unsupported file kind for portable capture at %s\n",
                                path);
                    break;
            }
            shown++;
        }
        if (report->unresolved_count > shown)
            print_error("  ... %zu more unresolved issue(s) not shown\n",
                        report->unresolved_count - shown);
        return;
    }

    print_error("Error: portable pre-scan failed or found an unresolvable conflict at %s; %s\n",
                target, outcome);
}

static void begin_source_snapshot(SourceSnapshot *snapshot,
                                  const BackupPlan *plan, const char *target)
{
    const char *paths[MANIFEST_MAX_ROOTS];
    size_t count = 0;
    for (int index = 0; index < plan->root_count &&
                        count < sizeof(paths) / sizeof(paths[0]); index++)
        paths[count++] = plan->roots[index].capture_path;
    char note[PATH_MAX + 128];
    size_t snapshotted = source_snapshot_begin(snapshot, paths, count, target,
                                               note, sizeof(note));
    for (size_t index = 0; index < snapshotted; index++)
        printf("Backing up %s from a read-only snapshot.\n",
               snapshot->entries[index].subvolume_path);
    if (note[0] != '\0')
        printf("Note: %s.\n", note);
}

static void print_source_change_list(const ExampleList *list,
                                     const char *singular,
                                     const char *plural)
{
    if (list->count == 0)
        return;
    printf("  %zu %s:\n", list->count, list->count == 1 ? singular : plural);
    example_list_print(list, "    ");
}

// Lists what changed under the backup (D63); returns whether anything did.
static int print_source_changes(const BackupCaptureReport *report)
{
    if (!backup_capture_report_has_changes(report))
        return 0;
    printf("\n");
    fflush(stdout);
    print_warning("Some files changed while they were being backed up:\n");
    print_source_change_list(
        &report->source_changes[BACKUP_SOURCE_CHANGED],
        "file kept as last read; it was still being written",
        "files kept as last read; they were still being written");
    print_source_change_list(
        &report->source_changes[BACKUP_SOURCE_VANISHED],
        "item removed before it could be read; not in this backup",
        "items removed before they could be read; not in this backup");
    print_source_change_list(
        &report->source_changes[BACKUP_SOURCE_APPEARED],
        "item created after its folder was scanned; not in this backup",
        "items created after their folder was scanned; not in this backup");
    return 1;
}

// Lists the items the backup could not read (D109); returns whether any.
static int print_failed_items(const BackupCaptureReport *report)
{
    const ExampleList *list = &report->failed_items;
    if (list->count == 0)
        return 0;
    printf("\n");
    fflush(stdout);
    if (list->count == 1)
        print_warning("Could not read 1 item; it was not backed up this "
                      "time:\n");
    else
        print_warning("Could not read %zu items; they were not backed up "
                      "this time:\n", list->count);
    example_list_print(list, "  ");
    return 1;
}

static void print_portable_capture_failure(const BackupCaptureReport *report)
{
    const char *path = report != NULL && report->failed_source_path[0] != '\0'
        ? report->failed_source_path : NULL;
    const char *operation = report != NULL ? report->failed_operation : NULL;

    if (report != NULL &&
        report->failure_kind == BACKUP_CAPTURE_FAILURE_SOURCE_CHANGED)
    {
        if (path != NULL)
            print_error("Error: portable capture stopped because the source changed after pre-scan at %s. Rerun the backup.\n",
                        path);
        else
            print_error("Error: portable capture stopped because the source changed after pre-scan. Rerun the backup.\n");
        return;
    }

    // An internal failure carries no errno: the operation says what the
    // capture's own state refused.
    int err = report != NULL &&
              report->failure_kind == BACKUP_CAPTURE_FAILURE_OPERATIONAL
        ? (report->failure_errno != 0 ? report->failure_errno : EIO)
        : 0;
    if (path != NULL)
        print_item_failure("back up", path, operation, err);
    else
    {
        FailedStep failed = { .step = operation, .err = err };
        print_step_failure(&failed, "Error: the portable backup stopped");
    }
}

static int self_binary_clear_at(int container_fd)
{
    if (unlinkat(container_fd, "migr", 0) == 0 || errno == ENOENT)
        return 0;
    if ((errno == EISDIR || errno == EPERM) &&
        unlinkat(container_fd, "migr", AT_REMOVEDIR) == 0)
        return 0;
    return -1;
}

static int copy_self_binary_at(int container_fd, int source_fd,
                               CloneRepresentation repr)
{
    if (container_fd < 0 || source_fd < 0)
        return -1;
    if (self_binary_clear_at(container_fd) != 0)
        return -1;
    if (lseek(source_fd, 0, SEEK_SET) != 0)
        return -1;

    int dest_fd = openat(container_fd, "migr",
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         0755);
    if (dest_fd < 0)
        return -1;

    int failed = 0;
    struct stat st;
    if (fstat(dest_fd, &st) != 0 || !S_ISREG(st.st_mode))
        failed = 1;

    unsigned char buffer[64 * 1024];
    while (!failed)
    {
        ssize_t n = read(source_fd, buffer, sizeof(buffer));
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            failed = 1;
            break;
        }
        if (n == 0)
            break;

        if (write_all(dest_fd, buffer, (size_t)n) != 0)
            failed = 1;
    }

    if (!failed && fchmod(dest_fd, 0755) != 0 &&
        repr == CLONE_NATIVE_TREE)
        failed = 1;
    if (close(dest_fd) != 0)
        failed = 1;

    if (failed)
    {
        int saved_errno = errno;
        (void)self_binary_clear_at(container_fd);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int network_config_clear_flat_dir_at(int parent_fd, const char *name)
{
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    if (!S_ISDIR(st.st_mode))
    {
        if (unlinkat(parent_fd, name, 0) == 0 || errno == ENOENT)
            return 0;
        return -1;
    }

    int dir_fd = openat(parent_fd, name,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir_fd < 0)
        return errno == ENOENT ? 0 : -1;

    DIR *dir = fdopendir(dir_fd);
    if (dir == NULL)
    {
        close(dir_fd);
        return -1;
    }

    int failed = 0;
    int saved_errno = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                saved_errno = errno;
                failed = 1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (unlinkat(dirfd(dir), entry->d_name, 0) == 0 || errno == ENOENT)
            continue;
        if ((errno == EISDIR || errno == EPERM) &&
            (unlinkat(dirfd(dir), entry->d_name, AT_REMOVEDIR) == 0 ||
             errno == ENOENT))
            continue;
        saved_errno = errno;
        failed = 1;
        break;
    }

    if (closedir(dir) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    if (failed)
    {
        errno = saved_errno != 0 ? saved_errno : EIO;
        return -1;
    }

    if (unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 || errno == ENOENT)
        return 0;
    return -1;
}

static int network_config_clear_at(int container_fd)
{
    struct stat st;
    if (fstatat(container_fd, "network", &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;

    if (!S_ISDIR(st.st_mode))
    {
        if (unlinkat(container_fd, "network", 0) == 0 || errno == ENOENT)
            return 0;
        return -1;
    }

    int network_fd = openat(container_fd, "network",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (network_fd < 0)
        return errno == ENOENT ? 0 : -1;

    DIR *dir = fdopendir(network_fd);
    if (dir == NULL)
    {
        close(network_fd);
        return -1;
    }

    int failed = 0;
    int saved_errno = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                saved_errno = errno;
                failed = 1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (unlinkat(dirfd(dir), entry->d_name, 0) == 0 || errno == ENOENT)
            continue;
        if (errno == EISDIR || errno == EPERM)
        {
            if (network_config_clear_flat_dir_at(dirfd(dir),
                                                 entry->d_name) == 0)
                continue;
        }
        saved_errno = errno;
        failed = 1;
        break;
    }

    if (closedir(dir) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    if (failed)
    {
        errno = saved_errno != 0 ? saved_errno : EIO;
        return -1;
    }

    if (unlinkat(container_fd, "network", AT_REMOVEDIR) == 0 ||
        errno == ENOENT)
        return 0;
    return -1;
}

static int copy_network_config_file_at(int source_dir_fd, int network_fd,
                                       const char *name, const char *filename_suffix,
                                       CloneRepresentation repr)
{
    struct stat entry_st;
    if (fstatat(source_dir_fd, name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (S_ISLNK(entry_st.st_mode))
    {
        printf("  Note: skipping symbolic link in network configuration: %s\n",
               name);
        return 0;
    }
    if (!S_ISREG(entry_st.st_mode))
    {
        printf("  Note: skipping non-regular network configuration entry: %s\n",
               name);
        return 0;
    }

    if (!network_config_name_matches_suffix(name, filename_suffix))
    {
        printf("  Note: skipping non-configuration file in network configuration: %s\n",
               name);
        return 0;
    }

    int source_fd = openat(source_dir_fd, name,
                           O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (source_fd < 0)
    {
        if (errno == ELOOP)
        {
            printf("  Note: skipping symbolic link in network configuration: %s\n",
                   name);
            return 0;
        }
        return -1;
    }

    struct stat source_st;
    if (fstat(source_fd, &source_st) != 0)
    {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(source_st.st_mode))
    {
        printf("  Note: skipping non-regular network configuration entry: %s\n",
               name);
        close(source_fd);
        return 0;
    }

    int dest_fd = openat(network_fd, name,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         0600);
    if (dest_fd < 0)
    {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }

    int failed = 0;
    int saved_errno = 0;
    unsigned char buffer[64 * 1024];
    while (!failed)
    {
        ssize_t n = read(source_fd, buffer, sizeof(buffer));
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            failed = 1;
            break;
        }
        if (n == 0)
            break;

        if (write_all(dest_fd, buffer, (size_t)n) != 0)
        {
            saved_errno = errno;
            failed = 1;
        }
    }

    mode_t source_mode = source_st.st_mode & 0777;
    if (!failed && fchmod(dest_fd, source_mode) != 0 &&
        repr == CLONE_NATIVE_TREE)
    {
        saved_errno = errno;
        failed = 1;
    }
    if (close(dest_fd) != 0 && !failed)
    {
        saved_errno = errno;
        failed = 1;
    }
    if (close(source_fd) != 0 && !failed)
    {
        saved_errno = errno;
        failed = 1;
    }

    if (failed)
    {
        if (saved_errno == 0)
            saved_errno = EIO;
        (void)unlinkat(network_fd, name, 0);
        errno = saved_errno;
        return -1;
    }

    return 0;
}

static int copy_network_config_backend_at(
    int network_fd, size_t backend_index, CloneRepresentation repr)
{
    const NetworkConfigBackend *backend = &NETWORK_CONFIG_BACKENDS[backend_index];
    const char *source_dir = network_config_source_dir(backend_index);
    int source_fd = open(source_dir,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source_fd < 0)
        return -1;

    if (mkdirat(network_fd, backend->container_subdir, 0700) != 0 &&
        errno != EEXIST)
    {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }

    int backend_fd = openat(network_fd, backend->container_subdir,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (backend_fd < 0)
    {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }

    DIR *dir = fdopendir(source_fd);
    if (dir == NULL)
    {
        int saved_errno = errno;
        close(source_fd);
        close(backend_fd);
        errno = saved_errno;
        return -1;
    }

    int failed = 0;
    int saved_errno = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                saved_errno = errno;
                failed = 1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (copy_network_config_file_at(dirfd(dir), backend_fd,
                                        entry->d_name, backend->filename_suffix,
                                        repr) != 0)
        {
            saved_errno = errno;
            print_error("Error: --include-network-config: could not copy %s/%s: %s\n",
                        source_dir, entry->d_name, strerror(saved_errno));
            failed = 1;
            break;
        }
    }

    if (closedir(dir) != 0 && !failed)
    {
        saved_errno = errno;
        failed = 1;
    }
    if (close(backend_fd) != 0 && !failed)
    {
        saved_errno = errno;
        failed = 1;
    }

    if (failed)
    {
        if (saved_errno == 0)
            saved_errno = EIO;
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static const char *crypto_policy_source = "/etc/crypto-policies/config";

#ifdef BACKUP_TEST_HOOKS
void backup_test_set_crypto_policy_source(const char *path)
{
    crypto_policy_source = path != NULL ? path : "/etc/crypto-policies/config";
}
#endif

// Saved connections can depend on the system crypto policy (for example
// 802.1X networks that need TLS 1.0 under DEFAULT:SHA1). Restore only
// suggests it, so a missing or unreadable policy is simply not recorded.
static int record_crypto_policy_at(int network_fd)
{
    char policy[CRYPTO_POLICY_MAX];
    if (crypto_policy_read_at(AT_FDCWD, crypto_policy_source, policy) != 0)
        return 0;
    char line[CRYPTO_POLICY_MAX + 1];
    snprintf(line, sizeof(line), "%s\n", policy);
    return write_container_text_file_at(network_fd, "crypto-policy", line) == 0
        ? 0 : -1;
}

static int copy_network_config_at(int container_fd, CloneRepresentation repr,
                                  unsigned int present_mask,
                                  unsigned int *processed_mask)
{
    *processed_mask = 0;
    if (network_config_clear_at(container_fd) != 0)
        return -1;
    if (present_mask == 0)
        return 0;

    if (mkdirat(container_fd, "network", 0700) != 0 && errno != EEXIST)
        return -1;

    int network_fd = openat(container_fd, "network",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (network_fd < 0)
    {
        int saved_errno = errno;
        (void)network_config_clear_at(container_fd);
        errno = saved_errno;
        return -1;
    }

    int failed = 0;
    int saved_errno = 0;
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        if ((present_mask & (1u << i)) == 0)
            continue;

        if (copy_network_config_backend_at(network_fd, i, repr) != 0)
        {
            saved_errno = errno;
            print_error("Error: --include-network-config: could not copy %s "
                        "configuration from %s: %s\n",
                        NETWORK_CONFIG_BACKENDS[i].name,
                        network_config_source_dir(i), strerror(saved_errno));
            failed = 1;
            break;
        }
        *processed_mask |= 1u << i;
    }
    if (!failed && record_crypto_policy_at(network_fd) != 0)
    {
        saved_errno = errno;
        print_error("Error: --include-network-config: could not record the "
                    "system crypto policy: %s\n", strerror(saved_errno));
        failed = 1;
    }

    if (close(network_fd) != 0 && !failed)
    {
        saved_errno = errno;
        failed = 1;
    }
    if (failed)
    {
        if (saved_errno == 0)
            saved_errno = EIO;
        (void)network_config_clear_at(container_fd);
        *processed_mask = 0;
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static size_t network_config_backend_count_in_mask(unsigned int mask)
{
    size_t count = 0;
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
        if ((mask & (1u << i)) != 0)
            count++;
    return count;
}

static void print_network_config_backend_names(unsigned int mask)
{
    size_t total = network_config_backend_count_in_mask(mask);
    size_t printed = 0;
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        if ((mask & (1u << i)) == 0)
            continue;
        if (printed > 0)
            printf(printed + 1 == total ? " and " : ", ");
        printf("%s", NETWORK_CONFIG_BACKENDS[i].name);
        printed++;
    }
}

static int network_config_mask_may_contain_secrets(unsigned int mask)
{
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
        if ((mask & (1u << i)) != 0 &&
            NETWORK_CONFIG_BACKENDS[i].may_contain_secrets)
            return 1;
    return 0;
}

static void print_network_config_none_found(void)
{
    printf("  Note: --include-network-config found no network configuration "
           "to back up (checked ");
    print_network_config_backend_names((1u << NETWORK_CONFIG_BACKEND_COUNT) - 1u);
    printf(").\n");
}

static void print_network_config_dry_run(unsigned int present_mask)
{
    if (present_mask == 0)
    {
        print_network_config_none_found();
        return;
    }

    printf("  Would capture network configuration from ");
    print_network_config_backend_names(present_mask);
    printf(" under network/.\n");
    if (network_config_mask_may_contain_secrets(present_mask))
    {
        printf("  Note: these files may include secrets such as WiFi "
               "passwords, PSKs, or VPN keys, stored as plain text.\n");
    }
}

static void print_network_config_completion(unsigned int processed_mask,
                                            const char *target,
                                            const char *container_name)
{
    if (processed_mask == 0)
    {
        printf("\n");
        print_network_config_none_found();
        return;
    }

    printf("\nNetwork configuration\n");
    printf("  Captured ");
    print_network_config_backend_names(processed_mask);
    printf(" under %s/%s/network/.\n", target, container_name);
    if (network_config_mask_may_contain_secrets(processed_mask))
    {
        printf("  This may include secrets such as WiFi passwords, PSKs, "
               "or VPN keys, stored as plain text. Anyone with access to "
               "this backup can read them.\n");
    }
}

typedef struct {
    off_t estimated_total_bytes;
    int updating; /* an existing backup: unchanged files are checked, not copied */
    int data_fd;
    int printed_anything;
    int finished; /* the last draw: totals, without the current path */
    struct timespec started_at;
    ProgressTicker ticker;
} BackupProgressDisplay;

// Cumulative average since started_at, not the rate since the last callback:
// a syncfs() stall followed by a buffered-write burst would otherwise show
// near-zero speed during the stall and a wildly inflated spike right after
// it, neither of which reflects the actual sustained throughput.
static off_t progress_speed(off_t total_bytes, const struct timespec *started_at,
                            const struct timespec *now)
{
    double elapsed_seconds = timespec_elapsed_seconds(started_at, now);
    if (!isfinite(elapsed_seconds) || elapsed_seconds <= 0.0 ||
        total_bytes <= 0)
        return 0;

    double speed = (double)total_bytes / elapsed_seconds;
    if (!isfinite(speed) || speed <= 0.0)
        return 0;
    if (speed >= (double)INTMAX_MAX)
        return (off_t)INTMAX_MAX;
    return (off_t)speed;
}

#ifdef BACKUP_TEST_HOOKS
// Drives the cumulative-average formula directly with synthetic timestamps,
// so a test can simulate a long stall followed by a burst without actually
// sleeping.
off_t backup_test_progress_speed(off_t total_bytes,
                                 const struct timespec *started_at,
                                 const struct timespec *now)
{
    return progress_speed(total_bytes, started_at, now);
}
#endif

static long progress_elapsed_whole_seconds(double elapsed_seconds)
{
    if (!isfinite(elapsed_seconds) || elapsed_seconds <= 0.0)
        return 0;
    if (elapsed_seconds >= (double)LONG_MAX)
        return LONG_MAX;
    return (long)elapsed_seconds;
}

static void backup_render_progress(BackupProgressDisplay *display,
                                   off_t bytes_copied,
                                   off_t bytes_unchanged,
                                   off_t speed_bytes,
                                   off_t free_bytes,
                                   int free_bytes_known,
                                   const char *current_path,
                                   const struct timespec *now)
{
    double elapsed_seconds = timespec_elapsed_seconds(&display->started_at,
                                                      now);
    char copied_text[32];
    char checked_text[32];
    char estimated_text[32];
    char free_text[32];
    char elapsed_text[32];
    char speed_text[32];
    format_size(bytes_copied, copied_text, sizeof(copied_text));
    format_size(bytes_copied + bytes_unchanged, checked_text,
                sizeof(checked_text));

    if (free_bytes_known)
        format_size(free_bytes, free_text, sizeof(free_text));
    else
        snprintf(free_text, sizeof(free_text), "unknown");
    format_duration(progress_elapsed_whole_seconds(elapsed_seconds),
                    elapsed_text, sizeof(elapsed_text));
    format_size(speed_bytes, speed_text, sizeof(speed_text));
    const char *path_text = current_path != NULL && current_path[0] != '\0'
        ? current_path : "unknown";

    char of_estimate[40] = "";
    if (display->estimated_total_bytes > 0)
    {
        format_size(display->estimated_total_bytes, estimated_text,
                    sizeof(estimated_text));
        snprintf(of_estimate, sizeof(of_estimate), "/%s", estimated_text);
    }

    char line[PATH_MAX + 256U];
    int length;
    if (display->updating)
        length = snprintf(line, sizeof(line),
                          "Checked %s%s, copied %s in %s, %s/s, %s free",
                          checked_text, of_estimate, copied_text,
                          elapsed_text, speed_text, free_text);
    else
        length = snprintf(line, sizeof(line), "Copied %s%s in %s, %s/s, %s free",
                          copied_text, of_estimate, elapsed_text, speed_text,
                          free_text);
    if (!display->finished && length > 0 && (size_t)length < sizeof(line))
        snprintf(line + length, sizeof(line) - (size_t)length,
                 ", current: %s", path_text);
    progress_line_draw(line, sizeof(line));
}

static void backup_ticker_redraw(const ProgressTickerSnapshot *snapshot,
                                 const struct timespec *now, void *context)
{
    BackupProgressDisplay *display = context;
    backup_render_progress(display, snapshot->bytes, snapshot->unchanged_bytes,
                           snapshot->speed_bytes, snapshot->free_bytes,
                           snapshot->free_bytes_known, snapshot->path, now);
}

static void backup_progress_stop_ticker(BackupProgressDisplay *display)
{
    if (progress_ticker_stop(&display->ticker) == 0)
        return;

    print_error("Error: Could not stop the progress display thread: %s\n",
                strerror(errno));
    // Returning would let a live thread retain pointers into this stack frame.
    abort();
}

static void backup_report_progress(off_t bytes_copied,
                                   off_t bytes_unchanged,
                                   const char *current_path,
                                   void *userdata)
{
    BackupProgressDisplay *display = userdata;
    if (display == NULL)
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    if (!display->printed_anything)
        display->started_at = now;

    off_t speed_bytes = progress_speed(bytes_copied, &display->started_at,
                                       &now);

    off_t free_bytes = 0;
    int free_bytes_known =
        destination_free_bytes(display->data_fd, &free_bytes) == 0;

    if (progress_ticker_snapshot(&display->ticker, bytes_copied,
                                 bytes_unchanged, speed_bytes, free_bytes,
                                 free_bytes_known, current_path, &now) != 0)
    {
        int saved_errno = errno;
        backup_progress_stop_ticker(display);
        print_warning("  Warning: progress stall redraw disabled after a "
                      "snapshot failure: %s\n", strerror(saved_errno));
    }

    backup_render_progress(display, bytes_copied, bytes_unchanged, speed_bytes,
                           free_bytes, free_bytes_known, current_path, &now);

#ifdef BACKUP_TEST_HOOKS
    if (backup_test_progress_hook != NULL)
        backup_test_progress_hook(bytes_copied, bytes_unchanged,
                                  display->estimated_total_bytes,
                                  current_path,
                                  backup_test_progress_context);
#endif
    display->printed_anything = 1;
}

// Validate and, if needed, create the top-level backup destination.
// Sets *created only when THIS call made the directory, so a later refusal can
// roll back exactly what we created — never a pre-existing directory, and never
// one a racing process slipped in between our check and mkdir.
static int ensure_target_root(const char *path, int *created)
{
    *created = 0;

    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            print_error("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    if (errno != ENOENT)
    {
        // A real access failure (e.g. EACCES) must not masquerade as "absent";
        // otherwise dry-run would promise to create something it cannot reach.
        print_error("Error: Could not access %s: %s\n", path,
                    strerror(errno));
        return 1;
    }

    if (dry_run)
    {
        printf("[dry-run] Would create directory: %s\n", path);
        return 0;
    }

    if (mkdir(path, 0755) == 0)
    {
        *created = 1;
        return 0;
    }
    if (errno == EEXIST)
    {
        // Lost a race: someone created the path between our stat and mkdir.
        // Accept it only if it is a directory, and never claim we made it.
        if (stat(path, &st) != 0)
        {
            print_error("Error: Could not access %s: %s\n", path,
                        strerror(errno));
            return 1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            print_error("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    print_error("Error: Could not create directory %s: %s\n", path,
                strerror(errno));
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Source identity (docs/DECISIONS.md D15).                                  */
/* ------------------------------------------------------------------------- */

// Machine id plus uid is what proves two invocations are the same job, so an
// unreadable or malformed machine id is not fatal: the backup still runs, it
// just cannot adopt an existing partial, because a timestamp or scope label
// alone never proves identity. Anything the manifest writer would reject is
// treated as unavailable rather than written out and turned into a fatal
// manifest failure later.
static int read_machine_id(char *out, size_t out_size)
{
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_machine_id != NULL)
    {
        int n = snprintf(out, out_size, "%s", backup_test_machine_id);
        return n > 0 && (size_t)n < out_size ? 0 : -1;
    }
#endif
    static const char *const sources[] = {
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        NULL
    };

    for (int i = 0; sources[i] != NULL; i++)
    {
        FILE *f = fopen(sources[i], "r");
        if (f == NULL)
            continue;

        char line[MANIFEST_MACHINE_ID_MAX];
        char *read = fgets(line, sizeof(line), f);
        fclose(f);
        if (read == NULL)
            continue;

        line[strcspn(line, "\r\n")] = '\0';
        size_t len = strlen(line);
        if (len == 0 || len >= out_size)
            continue;

        int hex = 1;
        for (size_t c = 0; c < len; c++)
            if (!isxdigit((unsigned char)line[c]))
                hex = 0;
        if (!hex)
            continue;

        memcpy(out, line, len + 1);
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------------- */
/* Plan to manifest.                                                          */
/* ------------------------------------------------------------------------- */

// selection_plan_manifest() has no machine/uid of its own to stamp, so both
// the unfiltered and the selection-derived manifest paths need this same
// stamp applied after the fact; kept in one place instead of two copies.
static void manifest_set_source_identity(Manifest *out)
{
    char machine_id[MANIFEST_MACHINE_ID_MAX];
    if (read_machine_id(machine_id, sizeof(machine_id)) == 0)
    {
        memcpy(out->machine_id, machine_id, strlen(machine_id) + 1);
        out->source_uid = backup_source_uid();
        out->source_gid = backup_source_gid();
        out->has_source_gid = 1;
        out->has_source_identity = 1;
        // Rootless containers' files belong to the user's subordinate IDs,
        // which restore moves to the new system's (D93).
        struct passwd *user = getpwuid(out->source_uid);
        const char *name = user != NULL ? user->pw_name : NULL;
        if (subid_ranges_read("/etc/subuid", name, out->source_uid,
                              &out->source_subuids) != 0 ||
            subid_ranges_read("/etc/subgid", name, out->source_uid,
                              &out->source_subgids) != 0)
            print_warning("Warning: Could not read /etc/subuid or "
                          "/etc/subgid: %s; files of rootless containers "
                          "will keep their owners as they are.\n",
                          strerror(errno));
    }
}

// The manifest is production's resume identity, not a byproduct of it: this is
// the model container_adopt() matches against and the model that is written
// into the container. The root table is copied entry by entry into its own
// array — a BackupPlanRoot embeds a ManifestRoot but is larger, so the plan's
// roots are not a ManifestRoot[] and must never be handed to the manifest API
// as one.
static int manifest_from_plan(const BackupPlan *plan, Manifest *out)
{
    memset(out, 0, sizeof(*out));
    out->version = MANIFEST_CURRENT_VERSION;
    out->representation = CLONE_NATIVE_TREE; // replaced by the probe's verdict
    out->scope = plan->scope;
    out->sidecar_version = 0;
    out->root_count = plan->root_count;

    if (plan->root_count > 0)
    {
        out->roots = calloc((size_t)plan->root_count, sizeof(*out->roots));
        if (out->roots == NULL)
        {
            print_error("Error: out of memory building the backup manifest\n");
            return -1;
        }
        for (int i = 0; i < plan->root_count; i++)
            out->roots[i] = plan->roots[i].manifest_root;
    }

    manifest_set_source_identity(out);
    char home[PATH_MAX];
    if (resolve_target_home(home) == 0)
        manifest_set_source_home(out, home);

    return 0;
}

static int backup_plan_from_selection(const SelectionPlan *selection,
                                      BackupPlan *out)
{
    *out = (BackupPlan){0};
    if (selection_plan_validate(selection) < 0 ||
        selection->root_count > (size_t)INT_MAX)
        return -1;

    out->scope = selection->scope;
    out->root_count = (int)selection->root_count;
    if (selection->root_count == 0)
        return 0;

    out->roots = calloc(selection->root_count, sizeof(*out->roots));
    if (out->roots == NULL)
    {
        print_error("Error: out of memory building the backup execution plan\n");
        return -1;
    }
    for (size_t i = 0; i < selection->root_count; i++)
        out->roots[i] = selection->roots[i].root;
    return 0;
}

static void backup_execution_estimate(const BackupPlan *plan,
                                      const SelectionPlan *selection,
                                      off_t block_size, off_t *total,
                                      int *had_error, FailedItem *failed)
{
    backup_estimate_size_report(plan, selection, block_size, total, had_error,
                                failed);
}

/* ------------------------------------------------------------------------- */
/* Plan to portable capture request (docs/DECISIONS.md D24).                 */
/* ------------------------------------------------------------------------- */

// Mechanical field-by-field conversion: PortableRootSpec covers exactly what
// a BackupPlanRoot/ManifestRoot pair already carries. The returned entries
// borrow their strings from plan and remain valid while plan is unchanged.
static void portable_root_specs_from_plan(const BackupPlan *plan,
                                          PortableRootSpec *roots_out)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        roots_out[i] = (PortableRootSpec){
            .id = root->manifest_root.id,
            .policy = root->manifest_root.policy,
            .capture_path = root->capture_path,
            .payload_path = root->manifest_root.payload_path,
            .source_path = root->manifest_root.source_path,
            .restore_path = root->manifest_root.restore_path,
            .has_restore_path = root->manifest_root.has_restore_path,
            .comprehensive_only = root->comprehensive_only
        };
    }
}

// The portable request mirrors manifest_from_plan()'s identity fields. All
// strings are borrowed from plan or machine_id and must outlive the request.
static int portable_capture_request_from_plan(
    const BackupPlan *plan, const char *machine_id, int has_machine_id,
    int case_sensitive, PortableRootSpec *roots_storage,
    PortableCaptureRequest *out)
{
    if (plan == NULL || out == NULL ||
        (plan->root_count > 0 && roots_storage == NULL))
        return -1;

    if (plan->root_count > 0)
        portable_root_specs_from_plan(plan, roots_storage);
    *out = (PortableCaptureRequest){
        .scope = plan->scope,
        .has_source_identity = has_machine_id,
        .machine_id = has_machine_id ? machine_id : NULL,
        .source_uid = backup_source_uid(),
        .source_gid = backup_source_gid(),
        .roots = plan->root_count > 0 ? roots_storage : NULL,
        .root_count = (size_t)plan->root_count,
        .case_sensitive = case_sensitive
    };
    return 0;
}

static int portable_capture_request_for_execution(
    const BackupPlan *plan, const SelectionPlan *selection,
    const char *machine_id, int has_machine_id, int case_sensitive,
    PortableRootSpec *roots_storage,
    PortableCaptureRequest *out)
{
    if (portable_capture_request_from_plan(
            plan, machine_id, has_machine_id, case_sensitive,
            roots_storage, out) != 0)
        return -1;
    if (selection != NULL &&
        portable_capture_request_set_selection(
            out, selection, roots_storage, selection->root_count) != 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Container payload namespace.                                              */
/* ------------------------------------------------------------------------- */

// Every user-derived object lives below data/ (docs/DECISIONS.md D15), so the
// container root stays reserved for migr's own control artifacts. Opened with
/* ------------------------------------------------------------------------- */
/* Updating a backup in place (docs/DECISIONS.md D72).                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *root_id;
    char *logical_path;
} DroppedPath;

// Journal records of roots the new selection left out, collected before any
// of them is deleted: live views are only valid until the next mutation.
typedef struct {
    const Manifest *previous;
    const unsigned char *dropped; /* per root of previous */
    const MovePlan *keep; /* Records planned to move are left; optional. */
    int keep_moved; /* Records moved to their new place are left. */
    DroppedPath *paths;
    size_t count;
    size_t capacity;
    int failed;
} DroppedPaths;

static int root_is_dropped(const DroppedPaths *dropped, SidecarBytes root_id)
{
    for (int i = 0; i < dropped->previous->root_count; i++)
        if (dropped->dropped[i] &&
            strlen(dropped->previous->roots[i].id) == root_id.length &&
            memcmp(dropped->previous->roots[i].id, root_id.data,
                   root_id.length) == 0)
            return 1;
    return 0;
}

// Whether root_id's logical_path is at or below a folder the plan moves,
// or with moved, at or below the place a moved folder took.
static int kept_by_move(const MovePlan *plan, int moved, SidecarBytes root_id,
                        SidecarBytes logical_path)
{
    for (size_t i = 0; plan != NULL && i < plan->count; i++)
    {
        const MoveItem *item = &plan->items[i];
        const char *id = moved ? item->to_id : item->from_id;
        const char *path = moved ? item->to_path : item->from_path;
        size_t length = strlen(path);
        if ((!moved || item->moved) && strlen(id) == root_id.length &&
            memcmp(id, root_id.data, root_id.length) == 0 &&
            (length == 0 ||
             (logical_path.length >= length &&
              memcmp(logical_path.data, path, length) == 0 &&
              (logical_path.length == length ||
               logical_path.data[length] == '/'))))
            return 1;
    }
    return 0;
}

static int dropped_paths_add(DroppedPaths *dropped, SidecarBytes root_id,
                             SidecarBytes logical_path)
{
    if (!root_is_dropped(dropped, root_id) ||
        kept_by_move(dropped->keep, dropped->keep_moved, root_id,
                     logical_path))
        return 0;
    if (dropped->count == dropped->capacity)
    {
        size_t capacity = dropped->capacity == 0 ? 64U
                                                 : dropped->capacity * 2U;
        DroppedPath *paths = realloc(dropped->paths,
                                     capacity * sizeof(*paths));
        if (paths == NULL)
        {
            dropped->failed = 1;
            return -1;
        }
        dropped->paths = paths;
        dropped->capacity = capacity;
    }
    DroppedPath *path = &dropped->paths[dropped->count];
    path->root_id = strndup((const char *)root_id.data, root_id.length);
    // A root's own entry has an empty logical path, which may carry no data.
    path->logical_path = logical_path.length != 0
        ? strndup((const char *)logical_path.data, logical_path.length)
        : strdup("");
    if (path->root_id == NULL || path->logical_path == NULL)
    {
        free(path->root_id);
        free(path->logical_path);
        dropped->failed = 1;
        return -1;
    }
    dropped->count++;
    return 0;
}

static void dropped_paths_free(DroppedPaths *dropped)
{
    for (size_t i = 0; i < dropped->count; i++)
    {
        free(dropped->paths[i].root_id);
        free(dropped->paths[i].logical_path);
    }
    free(dropped->paths);
}

static int collect_dropped_live(const SidecarLiveView *view, void *context)
{
    return dropped_paths_add(context, view->entry->root_id,
                             view->entry->logical_path);
}

static int collect_dropped_claim(const SidecarClaimView *view, void *context)
{
    return dropped_paths_add(context, view->claim->root_id,
                             view->claim->logical_path);
}

// Deletes the journal records of dropped roots, live and claimed alike, and
// makes the deletions durable before the caller writes the new manifest.
static int forget_dropped_journal_paths(SidecarLog *log, int container_fd,
                                        DroppedPaths *dropped)
{
    int failed =
        sidecar_log_foreach(log, collect_dropped_live, dropped) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_claim_foreach(log, collect_dropped_claim, dropped) !=
            SIDECAR_STATUS_OK ||
        dropped->failed;
    for (size_t i = 0; !failed && i < dropped->count; i++)
    {
        SidecarDelete deletion = {
            .root_id = { (const unsigned char *)dropped->paths[i].root_id,
                         strlen(dropped->paths[i].root_id) },
            .logical_path = {
                (const unsigned char *)dropped->paths[i].logical_path,
                strlen(dropped->paths[i].logical_path) }
        };
        failed = sidecar_log_append_delete(log, &deletion) !=
                 SIDECAR_STATUS_OK;
    }
    int journal_fd = openat(container_fd, SIDECAR_SLOT_NAME,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (journal_fd < 0 || fsync(journal_fd) != 0)
        failed = 1;
    if (journal_fd >= 0)
        close(journal_fd);
    return failed ? -1 : 0;
}

// Sets errno for a journal that could not be opened, as the state layer sets
// it only on a read error: EBADMSG stands for one that cannot be read as it
// is.
static void journal_open_errno(SidecarOpenStatus status)
{
    if (status == SIDECAR_OPEN_ALLOCATION)
        errno = ENOMEM;
    else if (status != SIDECAR_OPEN_IO_ERROR)
        errno = EBADMSG;
}

static const char *journal_error_text(int err)
{
    return err == EBADMSG ? "its journal cannot be read as it is"
                          : strerror(err);
}

// Removes what an adopted backup holds for roots the current selection no
// longer has: their journal records (portable) and their payload. What a
// root of the current selection still selects is moved to it first
// (D108). The new manifest is written only afterwards, so an interrupted
// run leaves them listed for the next one to finish. report is the
// pre-scan of a portable run.
static int drop_left_out_roots(int container_fd, const Manifest *current,
                               const PortablePrescanReport *report,
                               MovePlan *moves, int *changed)
{
    Manifest previous;
    if (manifest_read_v1_at(container_fd, &previous) != MANIFEST_STATUS_VALID)
        return -1;
    unsigned char *flags = calloc((size_t)previous.root_count + 1U, 1U);
    if (flags == NULL)
    {
        manifest_free(&previous);
        return -1;
    }
    int any = 0;
    for (int i = 0; i < previous.root_count; i++)
    {
        int kept = 0;
        for (int j = 0; j < current->root_count && !kept; j++)
            kept = manifest_root_equal(&previous.roots[i], &current->roots[j]);
        flags[i] = !kept;
        any |= !kept;
    }

    *changed = any;
    int portable = previous.representation == CLONE_PORTABLE_SIDECAR;
    // Files verify found damaged are copied again, never moved (D107); an
    // unreadable list moves nothing.
    RecopyList recopy = {0};
    int movable = any && recopy_list_read(container_fd, &recopy) == 0;
    int failed = movable &&
                 move_plan_roots(&previous, flags, current, &recopy, portable,
                                 moves) != 0;
    int data_fd = any && !failed
        ? openat(container_fd, "data",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        : -1;
    if (any && !failed && data_fd < 0 && errno != ENOENT)
        failed = 1;
    if (data_fd < 0)
        movable = 0;

    // The records nothing moves go first: a moved root may take the id of
    // a dropped one, its own included.
    DroppedPaths first = { .previous = &previous, .dropped = flags,
                           .keep = moves };
    DroppedPaths dropped = { .previous = &previous, .dropped = flags,
                             .keep = moves, .keep_moved = 1 };
    if (any && !failed && portable)
    {
        SidecarLog log = {0};
        SidecarOpenStatus status = sidecar_log_adopt_at(container_fd, &log);
        if (status == SIDECAR_OPEN_RESUMABLE)
        {
            failed = forget_dropped_journal_paths(&log, container_fd,
                                                  &first) != 0 ||
                     (movable && report != NULL &&
                      portable_moves_apply(&log, container_fd, data_fd, report,
                                           moves) != 0) ||
                     forget_dropped_journal_paths(&log, container_fd,
                                                  &dropped) != 0;
            if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
                failed = 1;
        }
        else if (status != SIDECAR_OPEN_MISSING)
        {
            journal_open_errno(status);
            failed = 1;
        }
    }
    else if (any && !failed && movable)
        failed = native_moves_apply(data_fd, moves) != 0;

    for (int i = 0; data_fd >= 0 && !failed && i < previous.root_count; i++)
        if (flags[i] && !move_plan_moves_root(moves, previous.roots[i].id) &&
            fileops_remove_tree_at(data_fd, previous.roots[i].payload_path) != 0)
            failed = 1;
    if (data_fd >= 0)
        close(data_fd);

    dropped_paths_free(&first);
    dropped_paths_free(&dropped);
    recopy_list_free(&recopy);
    free(flags);
    manifest_free(&previous);
    return failed ? -1 : 0;
}

// Plans, and unless dry_run makes, the moves of folders that moved inside a
// root of the backup in container_fd since it was taken, before a capture
// would copy them again and remove their old copies (D108). A portable
// backup is planned from its journal and request's pre-scan report.
static int move_folders(int container_fd, const BackupPlan *plan,
                        const SelectionPlan *selection,
                        CloneRepresentation repr, int nsec_exact,
                        const PortableCaptureRequest *request,
                        const PortablePrescanReport *report,
                        const RecopyList *recopy, int dry_run,
                        MovePlan *moves)
{
    int data_fd = openat(container_fd, "data", O_RDONLY | O_DIRECTORY |
                                               O_NOFOLLOW | O_CLOEXEC);
    if (data_fd < 0)
        return errno == ENOENT ? 0 : -1;
    MovePlan found = {0};
    int result = 0;
    if (repr == CLONE_NATIVE_TREE)
    {
        NativeMoveRoot *roots = calloc((size_t)plan->root_count + 1U,
                                       sizeof(*roots));
        if (roots == NULL)
            result = -1;
        for (int i = 0; roots != NULL && i < plan->root_count; i++)
            roots[i] = (NativeMoveRoot){
                .capture_path = plan->roots[i].capture_path,
                .payload_path = plan->roots[i].manifest_root.payload_path,
                .selection = selection != NULL ? &selection->roots[i] : NULL
            };
        if (roots != NULL)
            result = native_moves_plan(data_fd, roots,
                                       (size_t)plan->root_count, nsec_exact,
                                       recopy, &found);
        if (result == 0 && !dry_run)
            result = native_moves_apply(data_fd, &found);
        free(roots);
    }
    else if (request != NULL && report != NULL)
    {
        SidecarLog log = {0};
        SidecarOpenStatus status =
            dry_run ? sidecar_log_open_readonly_at(container_fd, &log)
                    : sidecar_log_adopt_at(container_fd, &log);
        if (status == SIDECAR_OPEN_RESUMABLE)
        {
            result = portable_moves_plan(&log, request, report, recopy,
                                         &found);
            if (result == 0 && !dry_run)
                result = portable_moves_apply(&log, container_fd, data_fd,
                                              report, &found);
            if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
                result = -1;
        }
        else if (status != SIDECAR_OPEN_MISSING)
        {
            journal_open_errno(status);
            result = -1;
        }
    }
    int saved = errno;
    close(data_fd);
    if (result == 0 && move_plan_append(moves, &found) != 0)
        result = -1;
    move_plan_free(&found);
    errno = saved;
    return result;
}

// Every update appends to the journal; once records no longer live outweigh
// those that do, it is rewritten to its live state (D73). A failure leaves
// the old journal in place, which is still complete.
static void compact_journal(int container_fd)
{
    uint64_t before = 0, after = 0;
    SidecarStatus status = sidecar_compact_at(container_fd, &before, &after);
    if (status != SIDECAR_STATUS_OK)
    {
        print_warning("Warning: could not rewrite the backup journal without "
                      "its old records: %s; it stays as it was.\n",
                      status == SIDECAR_STATUS_IO_ERROR
                          ? strerror(errno) : sidecar_status_reason(status));
        return;
    }
    if (after < before)
    {
        char before_text[32], after_text[32];
        format_size((off_t)before, before_text, sizeof(before_text));
        format_size((off_t)after, after_text, sizeof(after_text));
        printf("Rewrote the backup journal without its old records: %s to "
               "%s.\n", before_text, after_text);
    }
}

// The bytes of the regular files at or below dir_fd/name, whose links are not
// followed; 0 when it is missing. Only shown, so a tree it cannot read or
// deeper than 256 levels counts as far as it got. It leaves the recorded
// access times as they are; a folder another user owns refuses O_NOATIME.
static off_t payload_size_at(int dir_fd, const char *name, int depth)
{
    struct stat st;
    if (depth > 256 || fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return 0;
    if (!S_ISDIR(st.st_mode))
        return S_ISREG(st.st_mode) ? st.st_size : 0;
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    int fd = openat(dir_fd, name, flags | O_NOATIME);
    if (fd < 0 && errno == EPERM)
        fd = openat(dir_fd, name, flags);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (dir == NULL)
    {
        if (fd >= 0)
            close(fd);
        return 0;
    }
    off_t total = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            total += payload_size_at(dirfd(dir), entry->d_name, depth + 1);
    closedir(dir);
    return total;
}

// Starts a line of what an update removes, with its size unless negative,
// under a heading before the first.
static void print_removal(int *listed, const char *target, const char *name,
                          const char *what, off_t size)
{
    if ((*listed)++ == 0)
        printf("\nUpdating %s/%s would also remove what this run does not "
               "select:\n", target, name);
    printf("  %s", what);
    if (size < 0)
        return;
    char size_text[32];
    format_size(size, size_text, sizeof(size_text));
    printf(" (%s)", size_text);
}

// Lists what updating the backup dest_fd/name with plan removes from it
// beyond what left the source (D72): the roots this run does not select, the
// bundled migr, network configuration, and the lists an explicit-path backup
// keeps none of. A root this run selects folders of loses the rest, and the
// folders move to their own roots; a root inside one this run selects moves
// into it and is not listed (D108). Returns 1 when it listed something, 0
// when nothing is removed, and -1, reported, when the backup could not be
// read.
static int print_update_removals(int dest_fd, const char *target,
                                 const char *name, const BackupPlan *plan,
                                 int include_self, int include_network_config,
                                 unsigned int network_config_present_mask)
{
    int container_fd = openat(dest_fd, name, O_RDONLY | O_DIRECTORY |
                                             O_NOFOLLOW | O_CLOEXEC);
    Manifest previous;
    if (container_fd < 0 ||
        manifest_read_v1_at(container_fd, &previous) != MANIFEST_STATUS_VALID)
    {
        print_error("Error: could not read the backup %s/%s: %s\n", target,
                    name, container_fd < 0 ? strerror(errno)
                                           : "its manifest is not valid");
        if (container_fd >= 0)
            close(container_fd);
        return -1;
    }
    char (*selected)[PATH_MAX + 2] =
        calloc((size_t)plan->root_count + 1U, sizeof(*selected));
    if (selected == NULL)
    {
        print_error("Error: out of memory listing what the update removes\n");
        close(container_fd);
        manifest_free(&previous);
        return -1;
    }
    char home[PATH_MAX];
    if (resolve_target_home(home) != 0)
        home[0] = '\0';
    for (int j = 0; j < plan->root_count; j++)
        manifest_root_user_path(home, &plan->roots[j].manifest_root,
                                selected[j], sizeof(selected[j]));
    int data_fd = openat(container_fd, "data", O_RDONLY | O_DIRECTORY |
                                               O_NOFOLLOW | O_CLOEXEC);

    int listed = 0;
    for (int i = 0; i < previous.root_count; i++)
    {
        const ManifestRoot *root = &previous.roots[i];
        char path[PATH_MAX + 2];
        manifest_root_user_path(previous.source_home, root, path,
                                sizeof(path));
        int kept = 0;
        for (int j = 0; j < plan->root_count && !kept; j++)
            kept = path_covers(selected[j], path);
        if (kept)
            continue;
        off_t size = data_fd >= 0
            ? payload_size_at(data_fd, root->payload_path, 0) : 0;
        for (int j = 0; j < plan->root_count; j++)
            if (path_covers(path, selected[j]))
            {
                char payload[PATH_MAX * 2 + 2];
                snprintf(payload, sizeof(payload), "%s%s", root->payload_path,
                         selected[j] + strlen(path));
                off_t kept = data_fd >= 0
                    ? payload_size_at(data_fd, payload, 0) : 0;
                size -= kept < size ? kept : size;
            }
        print_removal(&listed, target, name, path, size);
        for (int j = 0, shown = 0; j < plan->root_count; j++)
            if (path_covers(path, selected[j]))
                printf("%s%s", shown++ == 0 ? ", except " : ", ",
                       selected[j]);
        printf("\n");
    }
    if (previous.has_self_binary && !include_self)
    {
        print_removal(&listed, target, name, "the bundled migr",
                      payload_size_at(container_fd, "migr", 0));
        printf("\n");
    }
    if (previous.has_network_config &&
        !(include_network_config && network_config_present_mask != 0))
    {
        print_removal(&listed, target, name, "network configuration",
                      payload_size_at(container_fd, "network", 0));
        printf("\n");
    }
    int paths_only = plan->scope == MANIFEST_SCOPE_EXPLICIT &&
                     previous.scope != MANIFEST_SCOPE_EXPLICIT;
    if (paths_only)
    {
        print_removal(&listed, target, name, "the package, VS Code "
                      "extension, group, and Flatpak lists", -1);
        printf("\n");
    }

    char options[96] = "";
    if (previous.scope == MANIFEST_SCOPE_COMPREHENSIVE &&
        plan->scope != MANIFEST_SCOPE_COMPREHENSIVE)
        strcat(options, " --comprehensive");
    if (previous.has_self_binary && !include_self)
        strcat(options, " --include-self");
    if (previous.has_network_config && !include_network_config)
        strcat(options, " --include-network-config");
    if (paths_only)
        printf("  To keep them, run the backup without paths%s%s.\n",
               options[0] != '\0' ? ", with" : "", options);
    else if (listed && options[0] != '\0')
        printf("  To keep them, add%s.\n", options);

    if (data_fd >= 0)
        close(data_fd);
    close(container_fd);
    free(selected);
    manifest_free(&previous);
    return listed > 0;
}

// Says what updating the backup dest_fd/name with plan moves inside it
// instead of copying it again (D108), as a dry run: the roots a root of plan
// keeps, then the folders that moved inside roots. request and report are a
// portable run's pre-scan. Payload folders are only read with O_NOATIME.
static int print_update_moves(int dest_fd, const char *name,
                              const BackupPlan *plan,
                              const SelectionPlan *selection,
                              CloneRepresentation repr, int nsec_exact,
                              const PortableCaptureRequest *request,
                              const PortablePrescanReport *report)
{
    int container_fd = openat(dest_fd, name, O_RDONLY | O_DIRECTORY |
                                             O_NOFOLLOW | O_CLOEXEC);
    Manifest previous, current;
    if (container_fd < 0)
        return -1;
    if (manifest_read_v1_at(container_fd, &previous) != MANIFEST_STATUS_VALID)
    {
        close(container_fd);
        return -1;
    }
    unsigned char *flags = calloc((size_t)previous.root_count + 1U, 1U);
    RecopyList recopy = {0};
    MovePlan moves = {0};
    int result = flags != NULL && manifest_from_plan(plan, &current) == 0
        ? 0 : -1;
    if (result == 0)
    {
        for (int i = 0; i < previous.root_count; i++)
        {
            int kept = 0;
            for (int j = 0; j < current.root_count && !kept; j++)
                kept = manifest_root_equal(&previous.roots[i],
                                           &current.roots[j]);
            flags[i] = !kept;
        }
        if (recopy_list_read(container_fd, &recopy) == 0 &&
            (move_plan_roots(&previous, flags, &current, &recopy,
                             repr == CLONE_PORTABLE_SIDECAR, &moves) != 0 ||
             move_folders(container_fd, plan, selection, repr, nsec_exact,
                          request, report, &recopy, 1, &moves) != 0))
            result = -1;
        manifest_free(&current);
    }
    if (result == 0)
        move_plan_print(&moves, 1);
    move_plan_free(&moves);
    recopy_list_free(&recopy);
    free(flags);
    manifest_free(&previous);
    close(container_fd);
    return result;
}

// O_NOFOLLOW | O_DIRECTORY: in an adopted container this entry may already
// exist, and only a genuine directory is acceptable — a symlink there would
// otherwise place the whole payload outside the container.
static int open_data_dir(int container_fd)
{
    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST)
        return -1;
    return openat(container_fd, "data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

/* ------------------------------------------------------------------------- */
/* Presentation.                                                              */
/* ------------------------------------------------------------------------- */

// Grouping is presentation only: it selects which heading a root prints under,
// never where its payload goes. That address is the manifest's payload_path.
static const struct {
    BackupRootGroup group;
    const char *heading;
} root_sections[] = {
    { BACKUP_ROOT_MAIN,     "Main Directories" },
    { BACKUP_ROOT_DOTFILE,  "Dotfiles" },
    { BACKUP_ROOT_BROWSER,  "Browser Profiles" },
    { BACKUP_ROOT_EXPLICIT, "Explicit Paths" },
};
enum { ROOT_SECTION_COUNT = sizeof(root_sections) / sizeof(root_sections[0]) };

static void preview_roots(const BackupPlan *plan, int *count)
{
    for (int s = 0; s < ROOT_SECTION_COUNT; s++)
    {
        int printed_heading = 0;
        for (int i = 0; i < plan->root_count; i++)
        {
            const BackupPlanRoot *root = &plan->roots[i];
            if (root->group != root_sections[s].group)
                continue;

            if (!printed_heading)
            {
                printf("\n%s\n", root_sections[s].heading);
                printed_heading = 1;
            }
            printf("  Would capture: %s -> data/%s\n",
                   root->capture_path, root->manifest_root.payload_path);
            (*count)++;
        }
    }
}

// 1 when HOME/name exists and the selection backs it up, 0 when it does not,
// -1 after a message when it cannot be inspected.
static int backup_selects_home_file(const SelectionPlan *selection,
                                    const char *name)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), selection->home, name) != 0)
    {
        print_error("Error: %s/%s is too long to inspect safely\n",
                    selection->home, name);
        return -1;
    }

    struct stat st;
    if (lstat(path, &st) != 0)
    {
        if (errno == ENOENT || errno == ENOTDIR)
            return 0;
        print_error("Error: could not inspect %s before backup: %s\n", path,
                    strerror(errno));
        return -1;
    }

    for (size_t root = 0; root < selection->root_count; root++)
        if (selection_source_owns(&selection->roots[root], path) == 1)
            return 1;
    return 0;
}

typedef struct {
    unsigned int mask;
    size_t count;
} ShellHistorySelection;

enum {
    SHELL_HISTORY_BASH = 1U << 0,
    SHELL_HISTORY_ZSH  = 1U << 1,
};

static int backup_shell_history_selection(const SelectionPlan *selection,
                                          ShellHistorySelection *owned)
{
    static const struct {
        const char *name;
        unsigned int bit;
    } candidates[] = {
        { ".bash_history", SHELL_HISTORY_BASH },
        { ".zsh_history",  SHELL_HISTORY_ZSH },
    };

    if (owned == NULL)
        return -1;
    *owned = (ShellHistorySelection){0};
    if (selection == NULL)
        return 0;

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
    {
        int selected = backup_selects_home_file(selection, candidates[i].name);
        if (selected < 0)
            return -1;
        if (selected)
        {
            owned->mask |= candidates[i].bit;
            owned->count++;
        }
    }
    return 0;
}

static const char *backup_shell_history_names(const ShellHistorySelection *owned)
{
    if (owned->mask == (SHELL_HISTORY_BASH | SHELL_HISTORY_ZSH))
        return ".bash_history, .zsh_history";
    if (owned->mask == SHELL_HISTORY_BASH)
        return ".bash_history";
    if (owned->mask == SHELL_HISTORY_ZSH)
        return ".zsh_history";
    return "";
}

static void backup_shell_history_dry_run_notice(
    const ShellHistorySelection *owned)
{
    if (owned->count == 0)
        return;
    printf("Security notice: this backup would include %zu item(s) that can "
           "carry secrets typed at a shell prompt (%s). Make sure the "
           "destination is trustworthy before a live run.\n",
           owned->count, backup_shell_history_names(owned));
}

static int backup_shell_history_confirm(const ShellHistorySelection *owned)
{
    if (owned->count == 0)
        return 1;

    char message[512];
    int length = snprintf(
        message, sizeof(message),
        "This backup includes %zu item(s) that can carry secrets typed at a "
        "shell prompt (%s). Make sure the destination is trustworthy before "
        "continuing. Continue?",
        owned->count, backup_shell_history_names(owned));
    if (length < 0 || (size_t)length >= sizeof(message))
    {
        print_error("Error: could not build the shell history consent "
                    "prompt: the names it lists are too long\n");
        return -1;
    }
    return confirm_action_default_yes(message) ? 1 : 0;
}

// Saved passwords and sign-ins, encrypted with the login password (D87).
static const char login_keyring[] = ".local/share/keyrings/login.keyring";

static void print_login_keyring_note(void)
{
    printf("\nUse the same password for your user on the new system. Your "
           "saved passwords and sign-ins (the login keyring) open with this "
           "system's password; with a different one, the first app that needs "
           "them asks for this system's password once.\n");
}

// When no backup under target is this install's and exactly one finished
// backup of another install could be updated instead, asks whether to update
// it, with no as the default and when nobody answers (D88). On yes, its name
// goes to other_name; otherwise other_name is empty.
static void backup_offer_other_install(int target_fd, const char *target,
                                       const Manifest *wanted,
                                       char other_name[CONTAINER_NAME_MAX])
{
    other_name[0] = '\0';
    ContainerSurvey survey;
    if (container_survey_fd(target_fd, invoker_name(), wanted, &survey) != 0 ||
        survey.own != 0 || survey.other != 1)
        return;

    char when[48] = "";
    struct tm local;
    if (survey.other_updated > 0 &&
        localtime_r(&survey.other_updated, &local) != NULL)
        strftime(when, sizeof(when), " (last updated %Y-%m-%d %H:%M)", &local);
    char message[PATH_MAX + CONTAINER_NAME_MAX + 192];
    int length = snprintf(message, sizeof(message),
                          "%s/%s was taken on another install%s. Update it "
                          "from this system? Files that are not here will be "
                          "removed from it.",
                          target, survey.other_name, when);
    if (length < 0 || (size_t)length >= sizeof(message))
        return;
    if (confirm_action(message))
        memcpy(other_name, survey.other_name, CONTAINER_NAME_MAX);
}

/* ------------------------------------------------------------------------- */
/* Applications open on a live source (docs/DECISIONS.md D84).               */
/* ------------------------------------------------------------------------- */

// The roots that hold the settings of applications running when capture
// starts, read live and so captured last, and what asking about them needs.
typedef struct {
    unsigned char roots[MANIFEST_MAX_ROOTS]; /* 1: captured last */
    size_t root_count;
    RunningWriter writers[WRITER_APPS_MAX]; /* those that defer a root */
    size_t writer_count;
    const char *labels[WRITER_APPS_MAX]; /* their applications, distinct */
    size_t label_count;
    uid_t uid;
    BackupProgressDisplay *progress; /* NULL when no progress line is shown */
    const char *unanswered[WRITER_APPS_MAX]; /* still open, nobody answered */
    size_t unanswered_count;
} BackupDeferral;

// Defers every root that holds, or lies inside, the settings of a writer
// application running now, unless those settings are read from a snapshot,
// which already sees them at one point in time (D64).
static void backup_defer_open_writers(BackupDeferral *deferral,
                                      const BackupPlan *plan)
{
    char home[PATH_MAX];
    if (writer_apps_session_uid(&deferral->uid) != 0 ||
        resolve_target_home(home) != 0)
        return;
    RunningWriter running[WRITER_APPS_MAX];
    size_t count = writer_apps_running(deferral->uid, running,
                                       WRITER_APPS_MAX);
    for (size_t index = 0; index < count; index++)
    {
        char settings[PATH_MAX];
        struct stat st;
        if (running[index].settings[0] == '\0' ||
            path_join(settings, sizeof(settings), home,
                      running[index].settings) != 0 ||
            lstat(settings, &st) != 0 || source_snapshot_covers(settings))
            continue;
        int defers = 0;
        for (int root = 0; root < plan->root_count; root++)
        {
            const char *capture = plan->roots[root].capture_path;
            if (!path_covers(capture, settings) &&
                !path_covers(settings, capture))
                continue;
            defers = 1;
            if (!deferral->roots[root])
                deferral->root_count++;
            deferral->roots[root] = 1;
        }
        if (defers)
            deferral->writers[deferral->writer_count++] = running[index];
    }
    deferral->label_count = writer_apps_labels(
        deferral->writers, deferral->writer_count, deferral->labels);
}

static void backup_print_deferral(const BackupDeferral *deferral,
                                  const BackupPlan *plan)
{
    if (deferral->root_count == 0)
        return;
    writer_apps_print_labels(deferral->labels, deferral->label_count);
    printf(" %s open, so ", deferral->label_count == 1 ? "is" : "are");
    size_t shown = 0;
    for (int root = 0; root < plan->root_count; root++)
    {
        if (!deferral->roots[root])
            continue;
        shown++;
        printf("%s%s", shown == 1 ? ""
                       : shown == deferral->root_count ? " and " : ", ",
               plan->roots[root].capture_path);
    }
    printf(" %s backed up last, after everything else; close %s before "
           "then.\n", deferral->root_count == 1 ? "is" : "are",
           deferral->label_count == 1 ? "it" : "them");
}

// Which of the deferring applications are still running, into open.
static size_t backup_deferral_still_open(const BackupDeferral *deferral,
                                         const char **open)
{
    RunningWriter writers[WRITER_APPS_MAX];
    size_t count = writer_apps_running(deferral->uid, writers,
                                       WRITER_APPS_MAX);
    size_t open_count = 0;
    for (size_t label = 0; label < deferral->label_count; label++)
        for (size_t index = 0; index < count; index++)
            if (strcmp(writers[index].label, deferral->labels[label]) == 0)
            {
                open[open_count++] = deferral->labels[label];
                break;
            }
    return open_count;
}

// Runs once every other root is captured (D84). Waiting here costs nothing:
// the rest of the backup is done. The roots are captured whatever the
// answer; a backup that left them out would lose more than it protects.
static void backup_before_deferred(void *context)
{
    BackupDeferral *deferral = context;
    const char *open[WRITER_APPS_MAX];
    size_t open_count = backup_deferral_still_open(deferral, open);
    if (open_count == 0)
        return;
    BackupProgressDisplay *progress = deferral->progress;
    int ticking = progress != NULL && progress->ticker.running;
    if (ticking)
        backup_progress_stop_ticker(progress);
    progress_line_end();
    while (open_count != 0)
    {
        printf("\n");
        writer_apps_print_labels(open, open_count);
        printf(" %s still open. Close %s and press Enter to back up %s "
               "settings, or type c to back them up as they are: ",
               open_count == 1 ? "is" : "are", open_count == 1 ? "it" : "them",
               open_count == 1 ? "its" : "their");
        fflush(stdout);
        char answer[32];
        if (fgets(answer, sizeof(answer), stdin) == NULL)
        {
            printf("\nNo answer; backing them up as they are.\n");
            memcpy(deferral->unanswered, open, open_count * sizeof(*open));
            deferral->unanswered_count = open_count;
            break;
        }
        if (answer[0] == 'c' || answer[0] == 'C')
            break;
        open_count = backup_deferral_still_open(deferral, open);
    }
    fflush(stdout);
    if (ticking &&
        progress_ticker_start(&progress->ticker, backup_ticker_redraw,
                              progress) != 0)
        print_warning("  Warning: progress stall redraw is unavailable: %s\n",
                      strerror(errno));
}

static void print_root_capture_failure(const BackupPlanRoot *root,
                                       const BackupCaptureReport *report)
{
    const char *failed_source = report->failed_source_path[0] != '\0'
        ? report->failed_source_path : root->capture_path;
    print_item_failure("back up", failed_source, report->failed_operation,
                       report->failure_errno);
    size_t root_length = strlen(root->capture_path);
    const char *below =
        strncmp(failed_source, root->capture_path, root_length) == 0
            ? failed_source + root_length : "";
    run_log_printf("  Its place in the backup: data/%s%s\n",
                   root->manifest_root.payload_path, below);
}

// With full_root not NULL, a root that fills the destination is not reported
// as an error: full_root receives its index, for the caller to make room.
static void capture_plan_root(const CloneContext *ctx, const BackupPlan *plan,
                              const SelectionPlan *selection, int index,
                              int data_fd, int *had_error,
                              BackupCaptureReport *capture_report,
                              int *full_root)
{
    const BackupPlanRoot *root = &plan->roots[index];
    if (verbose)
        printf("  Capturing: %s -> data/%s\n",
               root->capture_path, root->manifest_root.payload_path);

    CloneContext root_ctx = *ctx;
    root_ctx.selection = selection ? &selection->roots[(size_t)index] : NULL;

    capture_report->failed_source_path[0] = '\0';
    capture_report->failure_kind = BACKUP_CAPTURE_FAILURE_NONE;
    capture_report->failure_errno = 0;
    capture_report->failed_operation = NULL;
    BackupCaptureStatus capture_status = backup_capture_at_report_continue(
        &root_ctx, root->capture_path, data_fd,
        root->manifest_root.payload_path, capture_report);
    if (capture_status == BACKUP_CAPTURE_OK)
        return;
    if (full_root != NULL && capture_status == BACKUP_CAPTURE_ERROR &&
        capture_report->failure_errno == ENOSPC)
    {
        *full_root = index;
        return;
    }
    print_root_capture_failure(root, capture_report);
    *had_error = 1;
}

// selection is the optional compiled plan (docs/DECISIONS.md D34) backing
// *plan's roots one-for-one by index (backup_plan_from_selection() builds
// plan that way); NULL means an unfiltered explicit-path backup, which needs
// no per-entry filter. Each root gets its own CloneContext copy so the
// borrowed SelectionRoot pointer never leaks across roots, while inode_map
// and visited stay the single shared instances the caller created. Critical
// roots go first (D97) and deferred roots last (D84); a backup that already
// failed has no one to ask.
static void capture_roots(const CloneContext *ctx, const BackupPlan *plan,
                          const SelectionPlan *selection, int data_fd,
                          BackupDeferral *deferral, int *had_error,
                          BackupCaptureReport *capture_report, int *full_root)
{
    // A mismatched pair would index selection->roots past its end with no
    // error, silently capturing a root under the wrong filter -- this is a
    // caller bug, not something to recover from at runtime.
    assert(!selection || (size_t)plan->root_count == selection->root_count);
    for (int deferred = 0; deferred <= 1; deferred++)
    {
        if (deferred && deferral->root_count != 0 && !*had_error)
            backup_before_deferred(deferral);
        for (int later = 0; later <= 1; later++)
        {
            for (int s = 0; s < ROOT_SECTION_COUNT; s++)
            {
                int printed_heading = 0;
                for (int i = 0; i < plan->root_count; i++)
                {
                    if (plan->roots[i].group != root_sections[s].group ||
                        plan->roots[i].comprehensive_only != later ||
                        deferral->roots[i] != deferred)
                        continue;
                    if (*had_error || (full_root != NULL && *full_root >= 0))
                        return;
                    // Headings only group the verbose lines under them.
                    if (verbose && !printed_heading)
                    {
                        printf("\n%s\n", root_sections[s].heading);
                        printed_heading = 1;
                    }
                    capture_plan_root(ctx, plan, selection, i, data_fd,
                                      had_error, capture_report, full_root);
                }
            }
        }
    }
}

// A partial native capture may already contain one member of a hardlink group.
// Seed every existing, resume-matching destination before the live walk so the
// current root/readdir order cannot replace that earlier representative.
// selection follows the same index-aligned, optional convention as
// capture_roots() above.
static int seed_native_hardlink_map(const CloneContext *ctx, const BackupPlan *plan,
                                    const SelectionPlan *selection, int data_fd,
                                    FailedItem *failed)
{
    // See capture_roots(): the same one-for-one index alignment with
    // selection->roots is assumed here and must hold, not just be documented.
    assert(!selection || (size_t)plan->root_count == selection->root_count);
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        CloneContext root_ctx = *ctx;
        root_ctx.selection = selection ? &selection->roots[(size_t)i] : NULL;
        if (native_inode_map_seed_existing(&root_ctx, root->capture_path, data_fd,
                                           root->manifest_root.payload_path,
                                           failed) != 0)
            return -1;
    }
    return 0;
}

static void reconcile_roots(const void *visited, const BackupPlan *plan,
                            int data_fd, int *had_error)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        NativeReconcileReport report;
        if (native_reconcile_stale_at(
                visited, root->manifest_root.payload_path, data_fd,
                &report) != NATIVE_RECONCILE_OK)
        {
            char path[PATH_MAX * 2 + 8];
            snprintf(path, sizeof(path), "data/%s%s%s",
                     root->manifest_root.payload_path,
                     report.failed_relative_path[0] != '\0' ? "/" : "",
                     report.failed_relative_path);
            print_item_failure("clean up", path,
                               report.failed_operation, report.failure_errno);
            *had_error = 1;
        }
    }
}

// One native capture of every root, then the removal of what it did not
// visit, with hardlink and visited tracking of its own. An adopted backup's
// hardlinks are found first. full_root as for capture_plan_root(); a root
// that filled the destination leaves reconciliation undone.
static void native_capture_pass(CloneContext *ctx, const BackupPlan *plan,
                                const SelectionPlan *selection, int data_fd,
                                int adopted, BackupDeferral *deferral,
                                int *had_error, BackupCaptureReport *report,
                                int *full_root)
{
    ctx->inode_map = native_inode_map_create();
    ctx->visited = native_visited_create();
    if (ctx->inode_map == NULL || ctx->visited == NULL)
    {
        print_error("Error: Could not initialize native hardlink/resume "
                    "tracking: %s\n", strerror(errno));
        *had_error = 1;
    }
    FailedItem seed_failure = {0};
    if (!*had_error && adopted &&
        seed_native_hardlink_map(ctx, plan, selection, data_fd,
                                 &seed_failure) != 0)
    {
        print_step_failure(&seed_failure.step,
                           "Error: Could not find the hardlinks the backup "
                           "already holds, at %s", seed_failure.path);
        *had_error = 1;
    }
    if (!*had_error)
        capture_roots(ctx, plan, selection, data_fd, deferral, had_error,
                      report, full_root);
    if (!*had_error && (full_root == NULL || *full_root < 0))
        reconcile_roots(ctx->visited, plan, data_fd, had_error);
    native_inode_map_free(ctx->inode_map);
    ctx->inode_map = NULL;
    native_visited_free(ctx->visited);
    ctx->visited = NULL;
}

// An update writes moved files to their new paths before it removes their
// old copies (D23), so a destination with room for the result can fill up
// on the way. Says that the copies of what left the source are removed
// first and the capture runs again (D98), and readies the progress counts
// for that second pass: what the first copied, the second finds in place.
static void begin_second_capture(BackupProgressDisplay *progress,
                                 BackupCaptureReport *report,
                                 off_t *copied_before)
{
    int ticking = progress != NULL && progress->ticker.running;
    if (ticking)
        backup_progress_stop_ticker(progress);
    progress_line_end();
    printf("The backup drive is full. Removing the copies of files no longer "
           "on this system, then going on.\n");
    fflush(stdout);
    if (ticking &&
        progress_ticker_start(&progress->ticker, backup_ticker_redraw,
                              progress) != 0)
        print_warning("  Warning: progress stall redraw is unavailable: %s\n",
                      strerror(errno));
    *copied_before = report->bytes_copied;
    report->bytes_copied = 0;
    report->bytes_unchanged = 0;
    report->items = 0;
    // The second pass meets them again.
    memset(&report->failed_items, 0, sizeof(report->failed_items));
}

// After the second pass: the bytes the first copied count as copied once.
static void end_second_capture(BackupCaptureReport *report,
                               off_t copied_before)
{
    off_t found = report->bytes_unchanged < copied_before
        ? report->bytes_unchanged : copied_before;
    report->bytes_unchanged -= found;
    report->bytes_copied += copied_before;
}

static int metadata_existing_at(int root_fd, const char *rel,
                                struct stat *out, int *exists)
{
    *exists = 0;
    if (root_fd < 0)
        return 0;

    char copy[PATH_MAX];
    int n = snprintf(copy, sizeof(copy), "%s", rel);
    if (n < 0 || (size_t)n >= sizeof(copy))
        return -1;

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    char *component = copy;
    for (;;)
    {
        char *slash = strchr(component, '/');
        if (slash != NULL)
            *slash = '\0';
        if (component[0] == '\0' || strcmp(component, ".") == 0 ||
            strcmp(component, "..") == 0)
        {
            close(current);
            return -1;
        }

        int next = openat(current, component, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
        {
            int saved_errno = errno;
            close(current);
            // ENOTDIR: an older copy of another kind is on the way, and
            // capture replaces it with a folder.
            if (saved_errno == ENOENT || saved_errno == ENOTDIR)
                return 0;
            errno = saved_errno;
            return -1;
        }
        close(current);
        if (slash == NULL)
        {
            int rc = fstat(next, out);
            int saved_errno = errno;
            close(next);
            if (rc != 0)
            {
                errno = saved_errno;
                return -1;
            }
            *exists = 1;
            return 0;
        }
        current = next;
        component = slash + 1;
    }
}

// Notes a source item the preflight could not read. Capture lists it and
// goes on (D109), so only a dry run shows these.
static void unreadable_note(ExampleList *unreadable, const char *source_path,
                            const char *step, int err)
{
    char *text = unreadable != NULL ? example_list_next(unreadable) : NULL;
    if (text != NULL)
        snprintf(text, EXAMPLE_TEXT_MAX, "%s: %s: %s", source_path, step,
                 strerror(err));
}

// Opening an item listed a moment ago failed because it is gone, or was
// replaced by something else (a symlink, a file where a folder was).
static int source_vanished(int error)
{
    return error == ENOENT || error == ENOTDIR || error == ELOOP;
}

static int backup_metadata_inventory(const char *source_path, int anchor_fd,
                                     int destination_root_fd,
                                     const char *destination_rel,
                                     MetadataProfiles *profiles,
                                     ExampleList *unreadable,
                                     const SelectionRoot *selection,
                                     FailedItem *failure)
{
    if (selection)
    {
        int owned = selection_source_owns(selection, source_path);
        if (owned < 0)
            failed_item_note(failure, source_path,
                             "it lies outside its root in the selection", 0);
        if (owned <= 0) return owned;
    }
    // The source may change while it is walked (D63): an item gone since it
    // was listed is left to capture, which leaves it out and says so, and
    // one that changed is profiled as first seen. One that cannot be read
    // is left to capture too, which lists it (D109).
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
    {
        if (errno != ENOENT)
            unreadable_note(unreadable, source_path, "inspect it", errno);
        return 0;
    }

    struct stat existing_st;
    int destination_exists = 0;
    if (metadata_existing_at(destination_root_fd, destination_rel,
                             &existing_st, &destination_exists) != 0)
    {
        failed_item_note(failure, source_path,
                         "inspect what the backup holds there", errno);
        return -1;
    }

    // Another kind of item there is an older copy, which capture replaces.
    if (destination_exists &&
        (source_st.st_mode & S_IFMT) != (existing_st.st_mode & S_IFMT))
        destination_exists = 0;

    // Only what can be read is captured, so only that must keep its owner,
    // permissions, and times.
    int source_fd = -1;
    if (S_ISREG(source_st.st_mode) || S_ISDIR(source_st.st_mode))
    {
        int folder = S_ISDIR(source_st.st_mode);
#ifdef BACKUP_TEST_HOOKS
        backup_test_before_source_open(source_path);
#endif
        source_fd = open(source_path, O_RDONLY | O_NOFOLLOW | O_NOATIME |
                                          O_CLOEXEC |
                                          (folder ? O_DIRECTORY : 0));
        if (source_fd < 0)
        {
            if (!source_vanished(errno))
                unreadable_note(
                    unreadable, source_path,
                    errno == EPERM
                        ? (folder
                               ? "open the folder without changing its access time"
                               : "open it without changing its access time")
                        : (folder ? "open the folder" : "open it"),
                    errno);
            return 0;
        }
    }

    if (!S_ISSOCK(source_st.st_mode) && !S_ISCHR(source_st.st_mode) &&
        !S_ISBLK(source_st.st_mode) &&
        metadata_profiles_add(profiles, anchor_fd, &source_st,
                              destination_exists ? &existing_st : NULL,
                              source_path) != 0)
    {
        failed_item_note(failure, source_path,
                         "note its owner and permissions for the check", errno);
        if (source_fd >= 0)
            close(source_fd);
        return -1;
    }

    if (!S_ISDIR(source_st.st_mode))
    {
        if (source_fd < 0 || close(source_fd) == 0)
            return 0;
        failed_item_note(failure, source_path, "close it", errno);
        return -1;
    }

    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        unreadable_note(unreadable, source_path, "list the folder", errno);
        if (scan_fd >= 0)
            close(scan_fd);
        return close(source_fd) == 0 ? 0 : -1;
    }

    int failed = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
                unreadable_note(unreadable, source_path, "list the folder",
                                errno);
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_source[PATH_MAX];
        char child_destination[PATH_MAX];
        if (path_join(child_source, sizeof(child_source), source_path,
                      entry->d_name) != 0 ||
            path_join(child_destination, sizeof(child_destination),
                      destination_rel, entry->d_name) != 0)
        {
            unreadable_note(unreadable, source_path,
                            "name an item in the folder", ENAMETOOLONG);
            continue;
        }
        if (backup_metadata_inventory(child_source, anchor_fd,
                                      destination_root_fd, child_destination,
                                      profiles, unreadable, selection,
                                      failure) != 0)
        {
            failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
    {
        failed_item_note(failure, source_path, "list the folder", errno);
        failed = 1;
    }
    if (close(source_fd) != 0)
    {
        failed_item_note(failure, source_path, "close the folder", errno);
        failed = 1;
    }
    return failed ? -1 : 0;
}

// A backup given as the destination would get a new one inside it, as large
// as the whole selection; the folder holding it is the destination that
// updates it.
static int backup_target_is_container(int target_fd, const char *target)
{
    Manifest manifest;
    if (manifest_read_v1_at(target_fd, &manifest) != MANIFEST_STATUS_VALID)
        return 0;
    manifest_free(&manifest);
    char *resolved = realpath(target, NULL);
    print_error("Error: %s is a migr backup itself; to update it, give the "
                "folder that holds it%s%s.\n", target,
                resolved != NULL ? ": " : "",
                resolved != NULL ? dirname(resolved) : "");
    free(resolved);
    return 1;
}

// backup_dry_run()'s advisory probes only need an fd on the filesystem
// `target` would land on -- exactly what a live run's mkdir(target) requires
// its parent to already provide. So when target doesn't exist yet (the
// common first-time-use case), fall back to opening its parent instead of
// leaving the whole preview silently skipped; *out_used_parent tells the
// caller which one it got, for an accurate preview note.
static int open_advisory_probe_fd(const char *target, int *out_used_parent)
{
    *out_used_parent = 0;
    int fd = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0 || errno != ENOENT)
        return fd;

    char *copy = strdup(target);
    if (copy == NULL)
        return -1;
    size_t len = strlen(copy);
    while (len > 1 && copy[len - 1] == '/')
        copy[--len] = '\0';
    char *slash = strrchr(copy, '/');
    const char *parent;
    if (slash == NULL)
        parent = ".";
    else if (slash == copy)
    {
        slash[1] = '\0';
        parent = copy;
    }
    else
    {
        *slash = '\0';
        parent = copy;
    }

    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(copy);
    if (fd >= 0)
        *out_used_parent = 1;
    return fd;
}

// selection follows the same index-aligned, optional convention as
// capture_roots() and seed_native_hardlink_map(). unreadable, when not NULL,
// collects the source items that could not be read (D109).
static int backup_metadata_preflight(const BackupPlan *plan, const SelectionPlan *selection,
                                     int anchor_fd, int destination_root_fd,
                                     MetadataProfiles *profiles,
                                     ExampleList *unreadable,
                                     FailedItem *failure)
{
    // See capture_roots(): the same one-for-one index alignment with
    // selection->roots is assumed here and must hold, not just be documented.
    assert(!selection || (size_t)plan->root_count == selection->root_count);
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        const SelectionRoot *sel_root = selection ? &selection->roots[(size_t)i] : NULL;
        if (backup_metadata_inventory(root->capture_path, anchor_fd,
                                      destination_root_fd,
                                      root->manifest_root.payload_path,
                                      profiles, unreadable, sel_root,
                                      failure) != 0)
            return -1;
    }
    return 0;
}

static int backup_execution_metadata_preflight(
    const BackupPlan *plan, const SelectionPlan *selection, int anchor_fd,
    int destination_root_fd, MetadataProfiles *profiles,
    ExampleList *unreadable, FailedItem *failure)
{
    return backup_metadata_preflight(plan, selection, anchor_fd, destination_root_fd,
                                     profiles, unreadable, failure);
}

// The live run's native metadata preflight: the destination able to keep
// the source's owner, permissions, and times. An item that cannot be read is
// left to capture, which lists it (D109). On a refusal, says why, then
// unchanged.
static int backup_metadata_check(const BackupPlan *plan,
                                 const SelectionPlan *selection, int anchor_fd,
                                 int destination_root_fd,
                                 MetadataProfiles *profiles,
                                 const char *unchanged)
{
    FailedItem failure = {0};
    int failed = backup_execution_metadata_preflight(
        plan, selection, anchor_fd, destination_root_fd, profiles, NULL,
        &failure) != 0;
    if (failed)
    {
        print_item_failure("back up", failure.path, failure.step.step,
                           failure.step.err);
        print_error("  %s\n", unchanged);
        return -1;
    }
    metadata_profiles_report(profiles);
    MetadataProbeFailure probe_failure;
    if (metadata_profiles_probe(profiles,
                                (MetadataTimestampPolicy){ .nsec_exact = 0,
                                                            .configured = 1 },
                                &probe_failure) != 0)
    {
        metadata_probe_failure_print(&probe_failure, 0, unchanged);
        return -1;
    }
    return 0;
}

static int backup_dry_run(const char *target, BackupMode mode,
                          BackupPlan *plan, const SelectionPlan *selection,
                          int include_self,
                          const char *self_arch, int include_network_config,
                          unsigned int network_config_present_mask)
{
    off_t estimated_size = 0;
    int estimate_had_error = 0;
    off_t raw_estimated_size = 0;
    int raw_estimate_had_error = 0;
    int count = 0;
    ShellHistorySelection shell_history = {0};
    if (backup_shell_history_selection(selection, &shell_history) != 0)
    {
        backup_plan_free(plan);
        return MIGR_EXIT_FAILURE;
    }

    // The destination is inspected exactly as a live run would inspect
    // it, including the real capability probe and portable pre-scan
    // (D24 I-6) -- but nothing beyond that: no container, no manifest,
    // no data/, no package export.
    int target_created = 0;
    if (ensure_target_root(target, &target_created) != 0)
    {
        backup_plan_free(plan);
        return MIGR_EXIT_FAILURE;
    }

    CloneRepresentation advisory_repr = CLONE_NATIVE_TREE;
    FsCapabilityProfile advisory_profile;
    MetadataProfiles advisory_profiles;
    metadata_profiles_init(&advisory_profiles);
    ExampleList advisory_unreadable = {0};
    int advisory_used_parent = 0;
    int advisory_fd = open_advisory_probe_fd(target, &advisory_used_parent);
    if (advisory_fd < 0)
        print_warning("Warning: could not preview destination-dependent checks "
               "(size estimate, free space, filesystem capabilities) for %s: "
               "%s; the live backup will check these before writing.\n",
               target, strerror(errno));
    else if (advisory_used_parent)
        printf("Note: %s does not exist yet; the preview below reflects its "
               "parent directory's filesystem instead.\n\n", target);
    int advisory_probe_failed = 0;
    if (advisory_fd >= 0)
        advisory_probe_failed =
            (!advisory_used_parent &&
             backup_target_is_container(advisory_fd, target)) ||
            backup_representation_preflight(
                advisory_fd, target, &advisory_profile, &advisory_repr) != 0;
    // The backup a live run would update, which it offers to when it
    // belongs to another install (D88, D98).
    UpdateTarget update = UPDATE_NONE;
    char update_name[CONTAINER_NAME_MAX] = "";
    if (advisory_fd >= 0 && !advisory_probe_failed)
    {
        off_t reused_size = 0;
        if (!advisory_used_parent)
        {
            Manifest wanted = {
                .representation = advisory_repr,
                .sidecar_version = advisory_repr == CLONE_PORTABLE_SIDECAR
                    ? SIDECAR_VERSION : 0,
                .source_uid = backup_source_uid()
            };
            wanted.has_source_identity =
                read_machine_id(wanted.machine_id,
                                sizeof(wanted.machine_id)) == 0;
            update = backup_update_target(advisory_fd, &wanted, 1,
                                          update_name, &reused_size);
        }
        off_t advisory_block_size = 0;
        (void)destination_block_size(advisory_fd, &advisory_block_size);
        FailedItem estimate_failure = {0};
        backup_execution_estimate(plan, selection, advisory_block_size,
                                  &estimated_size, &estimate_had_error,
                                  &estimate_failure);
        backup_execution_estimate(plan, selection, 1, &raw_estimated_size,
                                  &raw_estimate_had_error, &estimate_failure);
        if (backup_space_preflight(advisory_fd, estimated_size,
                                   raw_estimated_size, estimate_had_error,
                                   raw_estimate_had_error, &estimate_failure,
                                   reused_size, target) != 0)
        {
            close(advisory_fd);
            if (target_created)
                rmdir(target);
            metadata_profiles_free(&advisory_profiles);
            backup_plan_free(plan);
            return MIGR_EXIT_FAILURE;
        }
    }
    if (advisory_probe_failed)
    {
        close(advisory_fd);
        if (target_created)
            rmdir(target);
        backup_plan_free(plan);
        return MIGR_EXIT_FAILURE;
    }

    if (advisory_fd >= 0)
    {
        FailedItem advisory_failure = {0};
        int advisory_failed = backup_execution_metadata_preflight(
            plan, selection, advisory_fd, -1, &advisory_profiles,
            &advisory_unreadable, &advisory_failure) != 0;
        if (advisory_unreadable.count > 0)
        {
            print_warning("Warning: %zu item%s could not be read; the backup "
                          "would go on without %s:\n",
                          advisory_unreadable.count,
                          advisory_unreadable.count == 1 ? "" : "s",
                          advisory_unreadable.count == 1 ? "it" : "them");
            example_list_print(&advisory_unreadable, "  ");
        }
        if (advisory_failed)
        {
            print_step_warning(&advisory_failure.step,
                               "Warning: could not complete the read-only "
                               "metadata preview at %s",
                               advisory_failure.path);
            print_warning("  The live backup will check it again before "
                          "writing.\n");
        }
        else
        {
            metadata_profiles_report(&advisory_profiles);
            // The ownership probe is privilege-relevant and native-only;
            // portable capture has no analogous native ownership step.
            MetadataProbeFailure probe_failure;
            if (advisory_repr == CLONE_NATIVE_TREE &&
                metadata_profiles_probe(
                    &advisory_profiles,
                    (MetadataTimestampPolicy){ .nsec_exact = 0,
                                                .configured = 1 },
                    &probe_failure) != 0)
                metadata_probe_failure_print(
                    &probe_failure, 1,
                    "The live backup will check it again before writing.");
        }
    }

    PortablePrescanReport advisory_prescan = {0};
    int has_advisory_prescan = 0;
    PortableRootSpec *advisory_roots = NULL;
    PortableCaptureRequest advisory_request = {0};
    if (advisory_fd >= 0 && advisory_repr == CLONE_PORTABLE_SIDECAR)
    {
        advisory_roots = plan->root_count > 0
            ? calloc((size_t)plan->root_count, sizeof(*advisory_roots))
            : NULL;
        if (plan->root_count > 0 && advisory_roots == NULL)
        {
            print_error("Error: out of memory building the portable capture preview\n");
            close(advisory_fd);
            metadata_profiles_free(&advisory_profiles);
            backup_plan_free(plan);
            return MIGR_EXIT_FAILURE;
        }
        char advisory_machine_id[MANIFEST_MACHINE_ID_MAX];
        int advisory_has_machine_id = read_machine_id(
            advisory_machine_id, sizeof(advisory_machine_id)) == 0;
        int request_result = portable_capture_request_for_execution(
            plan, selection, advisory_machine_id, advisory_has_machine_id,
            advisory_profile.capabilities[FS_CAP_CASE_SENSITIVE].status ==
                FS_CAP_SUPPORTED,
            advisory_roots, &advisory_request);
        PortablePreparedCapture advisory_prepared = {0};
        int prepare_result = request_result == 0
            ? portable_capture_prepare(advisory_fd, &advisory_request,
                                        &advisory_prepared)
            : -1;
        if (prepare_result != 0)
        {
            free(advisory_roots);
            int has_manual_native = 0;
            for (int i = 0; i < plan->root_count; i++)
                if (plan->roots[i].manifest_root.policy ==
                    ROOT_POLICY_MANUAL_NATIVE)
                    has_manual_native = 1;
            if (has_manual_native)
                print_error("Error: %s cannot hold Linux metadata natively, and portable "
                       "capture cannot carry an external (manual-native) root's "
                       "restore address; move or drop the external path(s) to "
                       "back up here.\n", target);
            else
                print_portable_prescan_failure(&advisory_prepared.report,
                                               target, 1);
            portable_prepared_capture_free(&advisory_prepared);
            close(advisory_fd);
            metadata_profiles_free(&advisory_profiles);
            backup_plan_free(plan);
            return MIGR_EXIT_FAILURE;
        }
        advisory_prescan = advisory_prepared.report;
        memset(&advisory_prepared.report, 0,
               sizeof(advisory_prepared.report));
        has_advisory_prescan = 1;
        portable_prepared_capture_free(&advisory_prepared);
    }
    metadata_profiles_free(&advisory_profiles);

    printf("Dry run mode enabled. No changes will be made.\n\n");
    if (update == UPDATE_OWN)
        printf("Would update the backup %s/%s in place.\n", target,
               update_name);
    else if (update == UPDATE_OTHER)
        printf("Would ask whether to update %s/%s, taken on another "
               "install,\n  and create a new backup container next to it "
               "otherwise.\n", target, update_name);
    else
    {
        printf("Would create a versioned backup container under: %s\n", target);
        printf("  Its name, migr-<user> or a dated one when that is taken, is chosen when the backup actually runs.\n");
    }

    preview_roots(plan, &count);

    if (selection != NULL)
    {
        printf("\nSelection policy\n");
        if (selection->excludes.count == 0)
            printf("  No active exclusions for this scope.\n");
        else
            for (size_t i = 0; i < selection->excludes.count; i++)
                printf("  Excludes: %s\n", selection->excludes.paths[i]);
        for (size_t i = 0; i < selection->root_count; i++)
        {
            uint32_t aliases = selection->roots[i].xdg_aliases;
            if (aliases == 0 || (aliases & (aliases - 1U)) == 0)
                continue;
            printf("  XDG aliases for %s:", selection->roots[i].root.capture_path);
            for (int key = 0; key < XDG_KEY_COUNT; key++)
                if ((aliases & (UINT32_C(1) << key)) != 0)
                    printf(" %s", xdg_keys[key]);
            printf("\n");
        }
    }

    backup_shell_history_dry_run_notice(&shell_history);

    if (has_advisory_prescan)
    {
        printf("\nDestination cannot hold Linux metadata natively; a portable "
               "sidecar representation would be used.\n");
        if (advisory_prescan.unresolved_count > 0)
            printf("  %zu naming conflict(s) found; the live run would refuse.\n",
                   advisory_prescan.unresolved_count);
    }

    printf("\nControls\n");
    printf("  Would write manifest.txt\n");
    if (mode != BACKUP_EXPLICIT_PATHS)
    {
        printf("  Would export package list to packages.txt\n");
        printf("  Would save group memberships to groups.txt\n");
        printf("  Would list system-wide Flatpak applications in "
               "flatpak-apps.txt\n");
    }
    if (include_self)
        printf("  Would copy migr-static (%s) to the container root as migr\n",
               self_arch);
    if (include_network_config)
        print_network_config_dry_run(network_config_present_mask);

    int removes = update != UPDATE_NONE
        ? print_update_removals(advisory_fd, target, update_name, plan,
                                include_self, include_network_config,
                                network_config_present_mask)
        : 0;
    if (removes >= 0 && update != UPDATE_NONE &&
        print_update_moves(advisory_fd, update_name, plan, selection,
                           advisory_repr, advisory_profile.nsec_exact,
                           has_advisory_prescan ? &advisory_request : NULL,
                           has_advisory_prescan ? &advisory_prescan : NULL) !=
            0)
        print_warning("Warning: could not tell which folders the update "
                      "would move inside %s/%s: %s\n", target, update_name,
                      journal_error_text(errno));
    if (advisory_fd >= 0)
        close(advisory_fd);
    portable_prescan_report_free(&advisory_prescan);
    free(advisory_roots);
    if (removes < 0)
    {
        backup_plan_free(plan);
        return MIGR_EXIT_FAILURE;
    }

    // The paths listed above; their files are counted when the backup runs.
    printf("\nDry run complete: %d path%s would be backed up\n", count,
           count == 1 ? "" : "s");

    backup_plan_free(plan);
    return 0;
}

/* ------------------------------------------------------------------------- */

static char *collect_vscode_extensions(void)
{
    static char *const vscode_extensions_cmd[] = {
        "code", "--list-extensions", "--show-versions", NULL
    };

    size_t buf_size = 5 * 1024 * 1024;
    char *buffer = malloc(buf_size);
    if (buffer == NULL)
        return NULL;

    buffer[0] = '\0';
    int capture_status;
    uid_t uid;
    gid_t gid;
    char home[PATH_MAX];
    if (sudo_invoker(&uid, &gid, home) == 1)
    {
        capture_status = run_command_capture_as_identity(
            vscode_extensions_cmd, buffer, buf_size, uid, gid, home);
    }
    else
    {
        capture_status = run_command_capture(vscode_extensions_cmd,
                                             buffer, buf_size);
    }
    if (capture_status != 0)
    {
        free(buffer);
        return NULL;
    }

    for (const unsigned char *p = (const unsigned char *)buffer; *p; p++)
    {
        if (!isspace(*p))
            return buffer;
    }

    free(buffer);
    return NULL;
}

#ifdef BACKUP_TEST_HOOKS
char *backup_test_collect_vscode_extensions(void)
{
    return collect_vscode_extensions();
}
#endif

// The supplementary groups of the user whose data the backup holds (D74).
static char *backup_collect_groups(void)
{
    char user[ACCOUNT_NAME_MAX];
    return local_account_name(backup_source_uid(), user) == 0
        ? groups_collect(user) : NULL;
}

// Saves a list restore acts on at the container root, consuming contents;
// NULL leaves the slot empty, which is what an explicit-paths backup, which
// records no system state, asks for. Either way a stale list in an adopted
// container never survives. Returns 0 with its line count when written, 1
// when the slot was left empty, and -1, reported, when the list could not be
// written or the slot made safe.
static int backup_save_list_at(int container_fd, const char *leaf,
                               char *contents, size_t *lines)
{
    *lines = 0;
    for (const char *p = contents; p != NULL && *p != '\0'; p++)
        *lines += *p == '\n';
    int written = write_container_text_file_at(container_fd, leaf, contents);
    int saved = errno;
    free(contents);
    if (written < 0)
        print_error("Error: could not write %s into the backup container: "
                    "%s\n", leaf, strerror(saved));
    return written;
}

/* Every read during capture is served from the page cache, so a journal the
 * device stored differently (e.g. a cluster the filesystem also handed to
 * another file) still parses there. After syncing, drop the journal's clean
 * pages and parse it again from the device before publishing. Returns 0 when
 * it parses completely, 1 when it is damaged (valid_bytes is the last valid
 * record boundary), and -1 with errno when it cannot be read. */
static int backup_sidecar_readback(int container_fd, uint64_t *valid_bytes,
                                   uint64_t *file_bytes)
{
    *valid_bytes = 0;
    *file_bytes = 0;
    if (container_fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (syncfs(container_fd) != 0)
        return -1;
#ifdef BACKUP_TEST_HOOKS
    if (backup_test_sidecar_readback_hook != NULL)
        backup_test_sidecar_readback_hook(container_fd,
                                          backup_test_sidecar_readback_context);
#endif
    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    (void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    SidecarParseResult parse;
    memset(&parse, 0, sizeof(parse));
    SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &parse);
    int saved = errno;
    close(fd);
    *file_bytes = (uint64_t)st.st_size;
    *valid_bytes = parse.last_valid_boundary;
    if (status == SIDECAR_STATUS_IO_ERROR)
    {
        errno = saved != 0 ? saved : EIO;
        return -1;
    }
    return status == SIDECAR_STATUS_OK &&
                   parse.bytes_read == (uint64_t)st.st_size
               ? 0 : 1;
}

static int backup_run(const char *target_arg, BackupMode mode,
                      BackupPlan plan, const SelectionPlan *selection,
                      int include_self, int include_network_config)
{
    // A path too long to trim is refused below like any unusable one.
    char trimmed[PATH_MAX];
    const char *target =
        path_trim_trailing_slashes(trimmed, sizeof(trimmed), target_arg) == 0
            ? trimmed : target_arg;
    // Asked before the destination is created, probed or previewed, so a
    // destination inside a selected root is refused identically in a live run
    // and a dry run, with nothing written either way.
    int destination_conflicts = selection != NULL
        ? selection_destination_conflicts(selection, target)
        : backup_plan_destination_conflicts(&plan, target);
    if (destination_conflicts)
    {
        backup_plan_free(&plan);
        return MIGR_EXIT_FAILURE;
    }

    int self_fd = -1;
    char self_arch[MIGR_ARCH_MAX] = {0};
    if (include_self &&
        probe_self_binary(&self_fd, self_arch, sizeof(self_arch)) != 0)
    {
        backup_plan_free(&plan);
        return MIGR_EXIT_FAILURE;
    }
    unsigned int network_config_present_mask = 0;
    if (include_network_config &&
        check_network_config_readable(&network_config_present_mask) != 0)
    {
        if (self_fd >= 0)
            close(self_fd);
        backup_plan_free(&plan);
        return MIGR_EXIT_FAILURE;
    }

    off_t estimated_size = 0;
    int estimate_had_error = 0;
    off_t raw_estimated_size = 0;
    int raw_estimate_had_error = 0;

    // Items backed up: every file, folder, link, and FIFO.
    size_t count = 0;

    if (dry_run)
    {
        if (self_fd >= 0)
            close(self_fd);
        return backup_dry_run(target, mode, &plan, selection, include_self, self_arch,
                              include_network_config,
                              network_config_present_mask);
    }

    Manifest manifest = {0};
    int manifest_result = selection != NULL
        ? selection_plan_manifest(selection, &manifest)
        : manifest_from_plan(&plan, &manifest);
    if (manifest_result != 0)
    {
        if (self_fd >= 0)
            close(self_fd);
        backup_plan_free(&plan);
        return MIGR_EXIT_FAILURE;
    }
    if (selection != NULL)
        manifest_set_source_identity(&manifest);
    if (include_self)
        manifest_set_self_binary(&manifest, self_arch);
    if (include_network_config && network_config_present_mask != 0)
        manifest.has_network_config = 1;
    // Containers created where SELinux runs carry its labels (D94).
    manifest.selinux = selinux_runs();
    manifest.updated = time(NULL);

    // Hoisted so both cleanup epilogues can release every resource
    // unconditionally: each handle is inert until its corresponding operation
    // populates it.
    int target_fd = -1;
    int target_created = 0;
    BackupContainer container = {0};
    PortablePreparedCapture prepared = {0};
    PortableRootSpec *portable_roots = NULL;
    MetadataProfiles metadata_profiles;
    metadata_profiles_init(&metadata_profiles);
    SourceSnapshot source_snapshot;
    source_snapshot_init(&source_snapshot);
    BackupDeferral deferral = {0};
    int finish_result = MIGR_EXIT_FAILURE;
    int adopted_changed = 0;
    RecopyList recopy = {0};
    int recopy_unread = 0;
    MovePlan moves = {0};

    if (ensure_target_root(target, &target_created) != 0)
        goto fail_pre_container;

    target_fd = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (target_fd < 0)
    {
        print_error("Error: Could not open backup destination %s: %s\n",
                    target, strerror(errno));
        goto fail_pre_container;
    }
    if (backup_target_is_container(target_fd, target))
        goto fail_pre_container;

    // Probe the destination and choose a representation before any container
    // exists. An unreliable probe is fatal, never a silent fall-through. If we
    // created the destination root this run and then refuse, roll it back so a
    // rejected attempt leaves nothing behind.
    CloneRepresentation repr = CLONE_NATIVE_TREE;
    FsCapabilityProfile profile;
    if (backup_representation_preflight(target_fd, target, &profile, &repr) != 0)
        goto fail_pre_container;

    // The representation is part of the resume identity, so it must be settled
    // before the manifest is matched against an existing partial.
    manifest.representation = repr;
    manifest.sidecar_version =
        repr == CLONE_PORTABLE_SIDECAR ? SIDECAR_VERSION : 0;

    // Asked before anything is read, so an unattended run is not held up
    // later (D88).
    char other_install[CONTAINER_NAME_MAX];
    backup_offer_other_install(target_fd, target, &manifest, other_install);
    char update_name[CONTAINER_NAME_MAX];
    off_t reused_size = 0;
    if (backup_update_target(target_fd, &manifest, other_install[0] != '\0',
                             update_name, &reused_size) != UPDATE_NONE)
    {
        // An update removes what this run does not select from the backup,
        // which only the user can decide, so it asks here as well (D72).
        int removes = print_update_removals(
            target_fd, target, update_name, &plan, include_self,
            include_network_config, network_config_present_mask);
        if (removes < 0)
            goto fail_pre_container;
        if (removes > 0 &&
            !confirm_action("Remove them and update the backup?"))
        {
            printf("Backup cancelled; nothing was changed.\n");
            goto cancel_pre_container;
        }
        if (removes > 0)
            printf("\n");
    }

    // A copy an interrupted update left in staging/ takes room this run
    // needs (D110).
    if (update_name[0] != '\0' &&
        container_staging_remove_at(target_fd, update_name) != 0)
        print_warning("Warning: could not remove %s/%s/%s: %s\n", target,
                      update_name, CONTAINER_STAGING_NAME, strerror(errno));

    off_t target_block_size = 0;
    (void)destination_block_size(target_fd, &target_block_size);
    FailedItem estimate_failure = {0};
    backup_execution_estimate(&plan, selection, target_block_size,
                              &estimated_size, &estimate_had_error,
                              &estimate_failure);
    backup_execution_estimate(&plan, selection, 1, &raw_estimated_size,
                              &raw_estimate_had_error, &estimate_failure);
    if (!estimate_had_error)
        manifest.size = estimated_size;

    if (backup_space_preflight(target_fd, estimated_size, raw_estimated_size,
                               estimate_had_error, raw_estimate_had_error,
                               &estimate_failure, reused_size,
                               target) != 0)
        goto fail_pre_container;
    selection_plan_print_notes(selection);
    if (selection != NULL && selection_plan_print_uncovered(selection))
        printf("\n");

    ShellHistorySelection shell_history = {0};
    if (backup_shell_history_selection(selection, &shell_history) != 0)
        goto fail_pre_container;
    int consent = backup_shell_history_confirm(&shell_history);
    if (consent < 0)
        goto fail_pre_container;
    if (consent == 0)
    {
        printf("Backup cancelled; no container was created.\n");
        goto cancel_pre_container;
    }
    int keyring_selected =
        selection != NULL ? backup_selects_home_file(selection, login_keyring)
                          : 0;
    if (keyring_selected < 0)
        goto fail_pre_container;

    // From here until capture ends, sources on btrfs are read from a
    // read-only snapshot (D64): the pre-scan and the capture see one point
    // in time.
    begin_source_snapshot(&source_snapshot, &plan, target);
    backup_defer_open_writers(&deferral, &plan);

    PortableCaptureRequest portable_request = {0};
    char portable_machine_id[MANIFEST_MACHINE_ID_MAX];
    if (repr == CLONE_PORTABLE_SIDECAR)
    {
        if (plan.root_count > 0)
        {
            portable_roots = calloc((size_t)plan.root_count,
                                    sizeof(*portable_roots));
            if (portable_roots == NULL)
            {
                print_error("Error: out of memory building the portable capture request\n");
                goto fail_pre_container;
            }
        }
        int has_machine_id = read_machine_id(portable_machine_id,
                                             sizeof(portable_machine_id)) == 0;
        if (portable_capture_request_for_execution(
                &plan, selection, portable_machine_id, has_machine_id,
                profile.capabilities[FS_CAP_CASE_SENSITIVE].status ==
                    FS_CAP_SUPPORTED,
                portable_roots, &portable_request) != 0 ||
            portable_capture_prepare(target_fd, &portable_request,
                                     &prepared) != 0)
        {
            int has_manual_native = 0;
            for (int i = 0; i < plan.root_count; i++)
                if (plan.roots[i].manifest_root.policy ==
                    ROOT_POLICY_MANUAL_NATIVE)
                    has_manual_native = 1;
            if (has_manual_native)
                print_error("Error: %s cannot hold Linux metadata natively, and portable "
                       "capture cannot carry an external (manual-native) root's "
                       "restore address; move or drop the external path(s) to "
                       "back up here.\n", target);
            else
                print_portable_prescan_failure(&prepared.report, target, 0);
            goto fail_pre_container;
        }
        if (include_self)
            manifest_set_self_binary(&prepared.manifest, self_arch);
        if (include_network_config && network_config_present_mask != 0)
            prepared.manifest.has_network_config = 1;
        prepared.manifest.updated = manifest.updated;
        prepared.manifest.size = manifest.size;
        manifest_set_source_home(&prepared.manifest, manifest.source_home);
        prepared.manifest.selinux = manifest.selinux;
        prepared.manifest.source_subuids = manifest.source_subuids;
        prepared.manifest.source_subgids = manifest.source_subgids;
    }
    const Manifest *identity_manifest = repr == CLONE_PORTABLE_SIDECAR
        ? &prepared.manifest : &manifest;

    int adopted = 0;
    ContainerStatus adopt_status =
        other_install[0] != '\0'
            ? container_adopt_other_fd(target_fd, invoker_name(),
                                       identity_manifest, other_install,
                                       &container)
            : container_adopt_fd(target_fd, invoker_name(), identity_manifest,
                                 &container);
    if (adopt_status == CONTAINER_OK)
    {
        adopted = 1;
        char adopted_label[PATH_MAX + NAME_MAX + 2];
        (void)snprintf(adopted_label, sizeof(adopted_label), "%s/%s", target,
                       container_current_name(&container));
        // A damaged journal is rebuilt before anything reads it (D111).
        if (repr == CLONE_PORTABLE_SIDECAR &&
            repair_damaged_journal_at(container_root_fd(&container),
                                      adopted_label) != 0)
            goto fail_pre_container;
        // An adopted backup may have been taken with another selection: roots
        // it no longer has are removed first, so the checks below see only
        // payload this run keeps, and before its manifest is replaced (D72).
        if (drop_left_out_roots(container_root_fd(&container),
                                identity_manifest,
                                repr == CLONE_PORTABLE_SIDECAR
                                    ? &prepared.report : NULL,
                                &moves, &adopted_changed) != 0)
        {
            print_error("Error: Could not remove the parts of the backup that "
                        "are no longer selected: %s\n",
                        journal_error_text(errno));
            adopted_changed = 1;
            goto fail_pre_container;
        }
        // Until this run writes into it, an interrupt puts the backup back
        // under its finished name, as a run that stops by itself does.
        if (!adopted_changed)
            container_guard_finished_name(&container);
        int adopted_data_fd = openat(container_root_fd(&container), "data",
                                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_CLOEXEC);
        if (repr == CLONE_NATIVE_TREE)
        {
            // A run stopped before it made data/ leaves none, and this one
            // makes it; a finished backup without it is damaged.
            if (adopted_data_fd < 0 &&
                (errno != ENOENT || container.from_finished))
            {
                print_error("Error: Could not open data/ in the backup: %s\n",
                            strerror(errno));
                goto fail_pre_container;
            }
            if (backup_metadata_check(&plan, selection,
                                      adopted_data_fd >= 0
                                          ? adopted_data_fd
                                          : container_root_fd(&container),
                                      adopted_data_fd, &metadata_profiles,
                                      "No payload was changed.") != 0)
            {
                close(adopted_data_fd);
                goto fail_pre_container;
            }
        }
        if (adopted_data_fd >= 0)
            close(adopted_data_fd);
    }
    else if (adopt_status == CONTAINER_ERR_NO_MATCH)
    {
        if (repr == CLONE_NATIVE_TREE &&
            backup_metadata_check(&plan, selection, target_fd, -1,
                                  &metadata_profiles,
                                  "No container was created.") != 0)
            goto fail_pre_container;
        if (container_reserve_fd(target_fd, invoker_name(), manifest.updated,
                                 &container) != CONTAINER_OK)
        {
            print_error("Error: Could not create a backup container under %s: %s\n",
                        target, strerror(errno));
            goto fail_pre_container;
        }
        if (container.suffix != 0)
            printf("Note: a backup under %s already has this user's name but "
                   "belongs to another install (or is in use); it is left "
                   "alone, and this one is %s.\n\n",
                   target, container.final_name);
    }
    else
    {
        if (adopt_status == CONTAINER_ERR_AMBIGUOUS)
            print_error("Error: more than one backup under %s belongs to this "
                        "install; choosing one would be a guess. Remove or move "
                        "the ones you do not want.\n", target);
        else if (adopt_status == CONTAINER_ERR_NOREPLACE)
            print_error("Error: %s does not support the atomic rename migr "
                        "needs to update a backup in place\n", target);
        else
            print_error("Error: could not examine existing backups under %s: %s\n",
                        target, strerror(errno));
        goto fail_pre_container;
    }
    close(target_fd);
    target_fd = -1;
    container_unguard_finished_name();

    int container_fd = container_root_fd(&container);
    int had_error = 0;
    unsigned int network_config_processed_mask = 0;

    // The run's log goes into the backup it describes (D79); in a native one
    // it belongs to the user who ran sudo, like migr's other entries (D70).
    uid_t log_uid = (uid_t)-1;
    gid_t log_gid = (gid_t)-1;
    if (repr == CLONE_NATIVE_TREE)
        (void)backup_invoker_identity(&log_uid, &log_gid);
    (void)run_log_attach(container_fd, "logs", "backup", log_uid, log_gid);
    // A partial is only worth resuming if its manifest proves which job it
    // belongs to. A fresh container whose manifest never got written can never
    // be adopted, so it must not be reported as resumable.
    int resumable = 1;

    // A native container gets its manifest before any payload: it is the
    // format discriminator, the representation record and the root table, so
    // a container without one is not a v1 container at all. An adopted one
    // gets this run's, atomically: its selection and time may have changed.
    // A fresh portable container is written by its capture.
    if (!had_error && (adopted || repr == CLONE_NATIVE_TREE) &&
        manifest_write_v1_at(container_fd, identity_manifest) != 0)
    {
        print_error("Error: Could not write manifest.txt into the backup container: %s\n",
                    strerror(errno));
        had_error = 1;
        resumable = adopted;
    }

    int data_fd = -1;
    if (!had_error)
    {
        data_fd = open_data_dir(container_fd);
        if (data_fd < 0)
        {
            print_error("Error: Could not open the container's data/ directory: %s\n",
                        strerror(errno));
            had_error = 1;
        }
    }

    BackupCaptureReport capture_report;
    backup_capture_report_init(&capture_report);
    if (!had_error)
    {
        printf("Backing up to: %s/%s\n", target, container_current_name(&container));
        if (container.updating && other_install[0] != '\0')
            printf("Updating the other install's backup in place; from now "
                   "on it is this install's.\n");
        else if (container.updating)
            printf("Updating this install's backup in place.\n");
        else if (adopted)
            printf("Resuming an interrupted backup of this install.\n");
        backup_print_deferral(&deferral, &plan);
        // The files verify found damaged are copied again (D107).
        if (recopy_list_read(container_root_fd(&container), &recopy) != 0)
        {
            print_warning("Warning: could not read the list of damaged "
                          "files (%s) in the backup: %s; they are not "
                          "copied again.\n", CONTAINER_RECOPY_NAME,
                          strerror(errno));
            recopy_unread = 1;
        }
        // Folders that moved in the source move inside the backup first; a
        // list of damaged files that cannot be read leaves them to be
        // copied again (D108).
        if (adopted && !recopy_unread &&
            move_folders(container_root_fd(&container), &plan, selection, repr,
                         profile.nsec_exact, &portable_request,
                         &prepared.report, &recopy, 0, &moves) != 0)
        {
            print_error("Error: Could not move folders inside the backup: "
                        "%s\n", journal_error_text(errno));
            had_error = 1;
        }
        move_plan_print(&moves, 0);

        capture_report.sync_interval_bytes = BACKUP_SYNC_INTERVAL_BYTES;
        BackupProgressDisplay progress_display = {
            .estimated_total_bytes = estimate_had_error || raw_estimate_had_error
                ? 0 : raw_estimated_size,
            .updating = adopted,
            .data_fd = data_fd
        };
        int progress_installed = 0;
        int progress_force = 0;
#ifdef BACKUP_TEST_HOOKS
        progress_force = backup_test_progress_hook != NULL;
#endif
        if (!estimate_had_error && !raw_estimate_had_error &&
            (isatty(STDOUT_FILENO) || progress_force))
        {
            capture_report.progress_cb = backup_report_progress;
            capture_report.progress_userdata = &progress_display;
            capture_report.progress_unthrottled = progress_force;
            if (progress_ticker_start(&progress_display.ticker,
                                      backup_ticker_redraw,
                                      &progress_display) != 0)
                print_warning("  Warning: progress stall redraw is unavailable: %s\n",
                              strerror(errno));
            progress_installed = 1;
            deferral.progress = &progress_display;
        }

        if (!had_error && repr == CLONE_NATIVE_TREE)
        {
            BackupStaging staging = { container_fd };
            CloneContext ctx = {
                .operation = CLONE_BACKUP,
                .representation = repr,
                .timestamp_policy_configured = 1,
                .nsec_exact = profile.nsec_exact,
                .metadata_preflight_done = 1,
                .recopy = &recopy,
                .staging = &staging
            };
            int full_root = -1;
            native_capture_pass(&ctx, &plan, selection, data_fd, adopted,
                                &deferral, &had_error, &capture_report,
                                adopted ? &full_root : NULL);
            // Another failure already ends the run; the full destination
            // is then reported with it.
            int make_room = full_root >= 0 && !had_error;
            size_t removed = 0;
            for (int i = 0; make_room && i < plan.root_count; i++)
                make_room = native_remove_vanished_at(
                    plan.roots[i].capture_path, data_fd,
                    plan.roots[i].manifest_root.payload_path, &removed) == 0;
            if (make_room && removed > 0)
            {
                off_t copied_before = 0;
                begin_second_capture(progress_installed ? &progress_display
                                                        : NULL,
                                     &capture_report, &copied_before);
                native_capture_pass(&ctx, &plan, selection, data_fd, adopted,
                                    &deferral, &had_error, &capture_report,
                                    NULL);
                end_second_capture(&capture_report, copied_before);
            }
            else if (full_root >= 0)
            {
                print_root_capture_failure(&plan.roots[full_root],
                                           &capture_report);
                had_error = 1;
            }
            count = capture_report.items;
        }
        else if (!had_error)
        {
            size_t live_count = 0;
            portable_request.payload_matches_journal = container.from_finished;
            portable_request.recopy = &recopy;
            if (deferral.root_count != 0)
            {
                portable_request.deferred = deferral.roots;
                portable_request.before_deferred = backup_before_deferred;
                portable_request.before_deferred_context = &deferral;
            }
            int capture_result = adopted
                ? portable_capture_resume_prepared_at(
                      container_fd, &portable_request, &prepared, &live_count,
                      &capture_report)
                : portable_capture_fresh_prepared_at(
                      container_fd, &portable_request, &prepared, &live_count,
                      &capture_report);
            if (capture_result != 0 && capture_report.vanished_removed > 0)
            {
                off_t copied_before = 0;
                begin_second_capture(progress_installed ? &progress_display
                                                        : NULL,
                                     &capture_report, &copied_before);
                // The first pass stopped part way, so the payload is checked
                // item by item again.
                portable_request.payload_matches_journal = 0;
                capture_result = portable_capture_resume_prepared_at(
                    container_fd, &portable_request, &prepared, &live_count,
                    &capture_report);
                end_second_capture(&capture_report, copied_before);
            }
            count = live_count;
            if (capture_result != 0)
            {
                print_portable_capture_failure(&capture_report);
                had_error = 1;
            }
            else
                compact_journal(container_fd);
        }

        if (progress_installed)
            backup_progress_stop_ticker(&progress_display);
        if (progress_installed && progress_display.printed_anything)
        {
            progress_display.finished = 1;
            capture_report.progress_cb(capture_report.bytes_copied,
                                       capture_report.bytes_unchanged,
                                       capture_report.current_path,
                                       capture_report.progress_userdata);
            progress_line_end();
        }
        source_snapshot_end(&source_snapshot);
        if (capture_report.live_state_changes != 0)
            printf("Note: live desktop state (such as GNOME's file metadata) "
                   "changed %zu time%s during the backup; it was saved as read, "
                   "and files that appeared or disappeared meanwhile were left "
                   "out.\n",
                   capture_report.live_state_changes,
                   capture_report.live_state_changes == 1 ? "" : "s");
        if (deferral.unanswered_count != 0)
        {
            size_t open_count = deferral.unanswered_count;
            printf("Note: ");
            writer_apps_print_labels(deferral.unanswered, open_count);
            printf(" %s open while %s settings were backed up, so they are "
                   "as %s last saved them.\n",
                   open_count == 1 ? "was" : "were",
                   open_count == 1 ? "its" : "their",
                   open_count == 1 ? "it" : "they");
        }
        close(data_fd);
        // A finished backup holds no staging folder (D110).
        if (container_staging_remove(container_fd) != 0)
            print_warning("Warning: could not remove %s/ from the backup: "
                          "%s\n", CONTAINER_STAGING_NAME, strerror(errno));

        // packages.txt is a migr-owned control artifact, not a payload root, so
        // it stays at the container root. Restore acts on whichever one it
        // finds without re-deriving the backup's scope, so this slot must
        // always end up matching this invocation: a fresh list for a scope that
        // exports one, and demonstrably empty for a scope that does not.
        // Anything else -- a stale list inside an adopted container, or one
        // planted there -- would otherwise be published and later replayed.
        if (mode == BACKUP_EXPLICIT_PATHS)
        {
            if (packages_clear_at(container_fd, "packages.txt") != 0)
            {
                print_error("Error: could not clear packages.txt from the backup container: %s\n",
                            strerror(errno));
                had_error = 1;
            }
        }
        else
        {
            printf("\nPackages\n");
            // A system without a package list is a warning; a list the
            // destination could not store, or a slot that could not be made
            // safe, is an error.
            int pkg = packages_at(container_fd, "packages.txt");
            if (pkg < 0)
            {
                print_error("Error: could not write packages.txt into the "
                            "backup container: %s\n", strerror(errno));
                had_error = 1;
            }
            else if (pkg > 0)
            {
                print_warning("  Warning: no package list was written for this backup.\n");
            }
        }

        // The VS Code snapshot follows the same scoped-vs-explicit ownership
        // rule for container controls: explicit backups make no inventory
        // assumptions, and an adopted partial must not publish a stale list.
        if (mode == BACKUP_EXPLICIT_PATHS)
        {
            if (packages_clear_at(container_fd, "vs-code-extensions.txt") != 0)
            {
                print_error("Error: could not clear vs-code-extensions.txt from "
                            "the backup container: %s\n", strerror(errno));
                had_error = 1;
            }
        }
        else
        {
            printf("\nVS Code Extensions\n");
            char *extensions = collect_vscode_extensions();
            int vscode = write_container_text_file_at(
                container_fd, "vs-code-extensions.txt", extensions);
            free(extensions);

            if (vscode < 0)
            {
                print_error("Error: could not write vs-code-extensions.txt "
                            "into the backup container: %s\n",
                            strerror(errno));
                had_error = 1;
            }
            else if (vscode > 0)
            {
                printf("  Note: no VS Code extension list was captured for this backup.\n");
            }
            else
            {
                printf("Saved VS Code extension list to vs-code-extensions.txt\n");
            }
        }

        // Group memberships and Flatpak applications follow the same rule:
        // restore acts on whatever groups.txt and flatpak-apps.txt list.
        size_t lines = 0;
        if (mode == BACKUP_EXPLICIT_PATHS)
        {
            if (backup_save_list_at(container_fd, "groups.txt", NULL,
                                    &lines) < 0 ||
                backup_save_list_at(container_fd, "flatpak-apps.txt", NULL,
                                    &lines) < 0)
                had_error = 1;
        }
        else
        {
            printf("\nGroups\n");
            errno = 0;
            char *groups = backup_collect_groups();
            int groups_errno = errno;
            int saved = backup_save_list_at(container_fd, "groups.txt",
                                            groups, &lines);
            if (saved < 0)
                had_error = 1;
            else if (saved > 0)
                print_warning("  Warning: group memberships were not saved "
                              "for this backup: %s.\n",
                              groups_errno != 0
                                  ? strerror(groups_errno)
                                  : "the user is not in the local account "
                                    "or group files");
            else
                printf("Saved %zu group membership%s to groups.txt\n",
                       lines, lines == 1 ? "" : "s");

            printf("\nFlatpak Applications\n");
            saved = backup_save_list_at(container_fd, "flatpak-apps.txt",
                                        flatpak_apps_collect(), &lines);
            if (saved < 0)
                had_error = 1;
            else if (saved > 0)
                printf("  Note: no system-wide Flatpak applications were "
                       "found.\n");
            else
                printf("Saved %zu Flatpak application%s to "
                       "flatpak-apps.txt\n", lines, lines == 1 ? "" : "s");
        }

        if (!had_error)
        {
            if (include_self)
            {
                if (copy_self_binary_at(container_fd, self_fd, repr) != 0)
                {
                    print_error("Error: could not copy the bundled migr binary into "
                                "the backup container: %s\n", strerror(errno));
                    had_error = 1;
                }
                else
                {
                    close(self_fd);
                    self_fd = -1;
                }
            }
            else if (self_binary_clear_at(container_fd) != 0)
            {
                print_error("Error: could not clear a stale bundled migr binary "
                            "from the backup container: %s\n", strerror(errno));
                had_error = 1;
            }
        }

        if (!had_error)
        {
            if (include_network_config)
            {
                if (copy_network_config_at(container_fd, repr,
                                           network_config_present_mask,
                                           &network_config_processed_mask) != 0)
                {
                    print_error("Error: could not copy network configuration "
                                "into the backup container: %s\n", strerror(errno));
                    had_error = 1;
                }
            }
            else if (network_config_clear_at(container_fd) != 0)
            {
                print_error("Error: could not clear stale network configuration "
                            "from the backup container: %s\n", strerror(errno));
                had_error = 1;
            }
        }
    }

    printf("\n");

    if (had_error)
    {
        // Nothing is published: an incomplete container must never look
        // complete.
        char item_phrase[64];
        format_item_count_phrase(item_phrase, sizeof(item_phrase), count,
                                 "backed up");
        printf("Backup finished with errors: %s, some items failed\n",
               item_phrase);
        if (resumable)
            printf("Incomplete backup kept for resume: %s/%s\n",
                   target, container_current_name(&container));
        else
            printf("Unusable container left behind; it cannot be resumed, remove it: %s/%s\n",
                   target, container_current_name(&container));
        finish_result = MIGR_EXIT_FAILURE;
        goto finish;
    }

    printf("Finalizing (syncing to disk)...\n");
    // Every damaged file on the list was copied again.
    if (!recopy_unread && recopy_list_remove(container_root_fd(&container)) != 0)
        print_warning("Warning: could not remove the list of damaged files "
                      "(%s) from the backup: %s; the next update copies them "
                      "again.\n", CONTAINER_RECOPY_NAME, strerror(errno));
    if (repr == CLONE_PORTABLE_SIDECAR)
    {
        uint64_t valid_bytes = 0;
        uint64_t file_bytes = 0;
        int readback = backup_sidecar_readback(container_root_fd(&container),
                                               &valid_bytes, &file_bytes);
        if (readback != 0)
        {
            if (readback > 0)
                print_error("Error: the backup journal (%s) read back from %s "
                            "is damaged at byte %ju of %ju: the drive did not "
                            "keep what was written\n",
                            SIDECAR_SLOT_NAME, target, (uintmax_t)valid_bytes,
                            (uintmax_t)file_bytes);
            else
                print_error("Error: could not read the backup journal (%s) "
                            "back from %s: %s\n",
                            SIDECAR_SLOT_NAME, target, strerror(errno));
            printf("The backup was not published and cannot be restored or "
                   "resumed. Remove %s/%s and back up again, preferably to a "
                   "different drive.\n",
                   target, container_current_name(&container));
            finish_result = MIGR_EXIT_FAILURE;
            goto finish;
        }
    }
    ContainerStatus final_status = container_finalize(&container);
    if (final_status != CONTAINER_OK)
    {
        if (final_status == CONTAINER_ERR_FINAL_EXISTS)
            print_error("Error: a completed backup already occupies this container's final name\n");
        else if (final_status == CONTAINER_ERR_NOREPLACE)
            print_error("Error: %s does not support the atomic rename migr publishes backups with\n", target);
        else
            print_error("Error: Could not publish the completed backup container: %s\n",
                        strerror(errno));

        printf("Incomplete backup kept for resume: %s/%s\n",
               target, container_current_name(&container));
        finish_result = MIGR_EXIT_FAILURE;
        goto finish;
    }

    char item_phrase[64];
    // An update copies only what changed; the count is the whole backup.
    format_item_count_phrase(item_phrase, sizeof(item_phrase), count,
                             "in the backup");
    print_success("Backup complete: %s\n", item_phrase);
    printf("Location: %s/%s\n", target, container_current_name(&container));
    if (include_self && repr == CLONE_PORTABLE_SIDECAR)
    {
        printf("\nThis backup includes a copy of migr (%s). The destination "
               "filesystem does not record permissions.\n"
               "The copy may not run directly from the drive. On the new "
               "system, enter the backup directory and run:\n\n"
               "  cp migr ~/migr && chmod +x ~/migr\n", self_arch);
    }
    if (include_network_config)
        print_network_config_completion(network_config_processed_mask, target,
                                        container_current_name(&container));
    // A source that changed under the backup does not fail it, nor does an
    // item it could not read, but the run ends with the lists and a warning
    // status (D63, D109).
    int listed = print_source_changes(&capture_report);
    listed |= print_failed_items(&capture_report);
    finish_result = listed ? MIGR_EXIT_CHANGED : MIGR_EXIT_OK;
    if (keyring_selected)
        print_login_keyring_note();

finish:
    source_snapshot_end(&source_snapshot);
    if (repr == CLONE_NATIVE_TREE)
        backup_give_to_invoker(container_root_fd(&container), target_created);
    if (self_fd >= 0)
        close(self_fd);
    container_close(&container);
    metadata_profiles_free(&metadata_profiles);
    portable_prepared_capture_free(&prepared);
    free(portable_roots);
    recopy_list_free(&recopy);
    move_plan_free(&moves);
    manifest_free(&manifest);
    backup_plan_free(&plan);
    return finish_result;

cancel_pre_container:
    finish_result = MIGR_EXIT_OK;
fail_pre_container:
    container_unguard_finished_name();
    source_snapshot_end(&source_snapshot);
    // A finished backup taken over for an update and left unchanged is
    // published again as it was, rather than left looking unfinished.
    if (container.from_finished && !adopted_changed &&
        container_restore_finished_name(&container) != CONTAINER_OK)
        print_warning("Warning: %s/%s could not get its name back: %s; the "
                      "next backup finishes it.\n", target,
                      container_current_name(&container), strerror(errno));
    if (self_fd >= 0)
        close(self_fd);
    container_close(&container);
    metadata_profiles_free(&metadata_profiles);
    portable_prepared_capture_free(&prepared);
    free(portable_roots);
    recopy_list_free(&recopy);
    move_plan_free(&moves);
    if (target_fd >= 0)
        close(target_fd);
    if (target_created)
        rmdir(target);
    manifest_free(&manifest);
    backup_plan_free(&plan);
    return finish_result;
}

int backup(const char *target, BackupMode mode, char **paths, int include_self,
           int include_network_config)
{
    char home[PATH_MAX];
    if (resolve_target_home(home) != 0)
        return MIGR_EXIT_FAILURE;

    BackupPlan plan;
    if (backup_plan_build(home, mode, (const char *const *)paths, &plan) != 0)
        return MIGR_EXIT_FAILURE;
    return backup_run(target, mode, plan, NULL, include_self,
                      include_network_config);
}

int backup_selection(const char *target, BackupMode mode,
                     const SelectionPlan *selection, int include_self,
                     int include_network_config)
{
    ManifestScope expected = mode == BACKUP_CRITICAL
        ? MANIFEST_SCOPE_CRITICAL : MANIFEST_SCOPE_COMPREHENSIVE;
    if (selection == NULL || mode == BACKUP_EXPLICIT_PATHS ||
        selection->scope != expected)
    {
        print_error("Error: invalid scoped backup selection\n");
        return MIGR_EXIT_FAILURE;
    }

    BackupPlan plan;
    if (backup_plan_from_selection(selection, &plan) != 0)
        return MIGR_EXIT_FAILURE;
    return backup_run(target, mode, plan, selection, include_self,
                      include_network_config);
}

// Thin wrapper kept for tests/test_native_selection.c and
// tests/test_portable_selection.c: production (backup_run()) calls
// backup_metadata_preflight() directly with both the BackupPlan and the
// SelectionPlan it was derived from, since it already holds both. This
// entry point only has the SelectionPlan, so it derives the matching
// BackupPlan first -- backup_plan_from_selection() copies each root
// index-for-index, which is exactly the alignment backup_metadata_preflight()
// requires between plan and selection.
int backup_selection_inventory(const SelectionPlan *plan, int anchor_fd,
                                int data_fd, MetadataProfiles *profiles)
{
    if (selection_plan_validate(plan) < 0 || anchor_fd < 0 || !profiles) return -1;

    BackupPlan backup_plan;
    if (backup_plan_from_selection(plan, &backup_plan) != 0) return -1;

    FailedItem failure = {0};
    int result = backup_metadata_preflight(&backup_plan, plan, anchor_fd, data_fd,
                                           profiles, NULL, &failure);
    if (result != 0)
        print_item_failure("back up", failure.path, failure.step.step,
                           failure.step.err);
    backup_plan_free(&backup_plan);
    return result;
}

// Thin wrapper kept for the same two test entry points; see
// backup_selection_inventory() above for why it derives its own BackupPlan.
// Unlike backup_run(), which only seeds the hardlink map for an adopted
// (resumed) container, this entry point has no adopted/fresh distinction in
// its contract and always seeds -- harmless, since seeding a missing
// destination is a no-op, and required by callers (including
// tests/test_native_selection.c) that drive repeated captures into the same
// data_fd without going through backup_run()'s resume detection.
BackupCaptureStatus backup_selection_capture(const CloneContext *ctx,
                                             const SelectionPlan *plan,
                                             int data_fd, BackupCaptureReport *report)
{
    if (!ctx || ctx->operation != CLONE_BACKUP || ctx->representation != CLONE_NATIVE_TREE ||
        !ctx->metadata_preflight_done || data_fd < 0 || selection_plan_validate(plan) < 0)
        return BACKUP_CAPTURE_ERROR;

    BackupPlan backup_plan;
    if (backup_plan_from_selection(plan, &backup_plan) != 0)
        return BACKUP_CAPTURE_ERROR;

    CloneContext run = *ctx;
    run.inode_map = native_inode_map_create();
    run.visited = native_visited_create();
    BackupCaptureStatus status = BACKUP_CAPTURE_ERROR;
    if (run.inode_map && run.visited)
    {
        int had_error = 0;
        BackupDeferral none = {0};
        if (seed_native_hardlink_map(&run, &backup_plan, plan, data_fd,
                                     NULL) != 0)
            had_error = 1;
        if (!had_error)
            capture_roots(&run, &backup_plan, plan, data_fd, &none,
                          &had_error, report, NULL);
        if (!had_error)
            reconcile_roots(run.visited, &backup_plan, data_fd, &had_error);
        status = had_error ? BACKUP_CAPTURE_ERROR : BACKUP_CAPTURE_OK;
    }
    native_inode_map_free(run.inode_map);
    native_visited_free(run.visited);
    backup_plan_free(&backup_plan);
    return status;
}
