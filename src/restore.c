#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include "restore.h"
#include "backup.h"
#include "container.h"
#include "detect.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "metadata.h"
#include "packages.h"
#include "portable.h"
#include "portable_restore.h"
#include "portable_restore_internal.h"
#include "utils.h"
#include "xdg.h"

typedef enum {
    NETWORK_CONFIG_APPLY_RELOAD,
    NETWORK_CONFIG_APPLY_MANUAL,
} NetworkConfigApplyMode;

typedef struct {
    const char *name;
    const char *container_subdir;
    const char *dest_dir;
    NetworkConfigApplyMode apply_mode;
    const char *manual_apply_hint;
} RestoreNetworkConfigBackend;

static const RestoreNetworkConfigBackend RESTORE_NETWORK_CONFIG_BACKENDS[] = {
    { "NetworkManager", "networkmanager",
      "/etc/NetworkManager/system-connections",
      NETWORK_CONFIG_APPLY_RELOAD, NULL },
    { "netplan", "netplan", "/etc/netplan",
      NETWORK_CONFIG_APPLY_MANUAL, "sudo netplan apply" },
    { "systemd-networkd", "systemd-networkd", "/etc/systemd/network",
      NETWORK_CONFIG_APPLY_MANUAL, "sudo networkctl reload" },
    { "wpa_supplicant", "wpa_supplicant", "/etc/wpa_supplicant",
      NETWORK_CONFIG_APPLY_MANUAL,
      "sudo systemctl restart wpa_supplicant@<interface> "
      "(replace <interface> with your interface name)" },
    { "netctl", "netctl", "/etc/netctl",
      NETWORK_CONFIG_APPLY_MANUAL,
      "sudo netctl restart <profile> (replace <profile> with your profile name)" },
};

#define NETWORK_CONFIG_BACKEND_COUNT \
    (sizeof(RESTORE_NETWORK_CONFIG_BACKENDS) / \
     sizeof(RESTORE_NETWORK_CONFIG_BACKENDS[0]))

#ifdef RESTORE_TEST_HOOKS
static const char *restore_test_network_config_dest_dirs[NETWORK_CONFIG_BACKEND_COUNT];
static RestoreTestNetworkReloadHook restore_test_network_reload_hook;
static void *restore_test_network_reload_context;

void restore_test_set_network_config_dest_dir(const char *backend_name,
                                              const char *dest_dir)
{
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        if (strcmp(RESTORE_NETWORK_CONFIG_BACKENDS[i].name, backend_name) == 0)
        {
            restore_test_network_config_dest_dirs[i] = dest_dir;
            return;
        }
    }
}

void restore_test_set_network_reload_hook(RestoreTestNetworkReloadHook hook,
                                          void *context)
{
    restore_test_network_reload_hook = hook;
    restore_test_network_reload_context = context;
}
#endif

// The canonical XDG key/fallback table (xdg.h) is shared by both restore
// paths: legacy records them as "KEY=value" lines in an unversioned
// manifest.txt; a v1 manifest records them as root-table entries whose id is
// one of these same keys (docs/DECISIONS.md D16).
#define XDG_RESTORE_COUNT XDG_KEY_COUNT

static void free_xdg_dirs(char **dirs)
{
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(dirs[i]);
}

static const char *network_config_dest_dir(size_t backend_index)
{
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_network_config_dest_dirs[backend_index] != NULL)
        return restore_test_network_config_dest_dirs[backend_index];
#endif
    return RESTORE_NETWORK_CONFIG_BACKENDS[backend_index].dest_dir;
}

static int run_network_config_reload(void)
{
    char *const reload_argv[] = {
        "sudo", "nmcli", "connection", "reload", NULL
    };
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_network_reload_hook != NULL)
        return restore_test_network_reload_hook(
            reload_argv, restore_test_network_reload_context);
#endif
    return run_command(reload_argv);
}

static int network_config_regular_count(DIR *dir, size_t *count)
{
    *count = 0;
    int failed = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                print_error("Error: Could not enumerate network/ in the backup\n");
                failed = 1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        struct stat st;
        if (fstatat(dirfd(dir), entry->d_name, &st,
                    AT_SYMLINK_NOFOLLOW) != 0)
        {
            print_error("Error: Could not inspect network/%s in the backup: %s\n",
                        entry->d_name, strerror(errno));
            failed = 1;
            continue;
        }
        if (S_ISREG(st.st_mode))
            (*count)++;
    }
    rewinddir(dir);
    return failed ? -1 : 0;
}

static void report_network_config_unapplied(
    const RestoreNetworkConfigBackend *backend, const char *dest_dir, int reason)
{
    printf("\nNetwork configuration (%s)\n", backend->name);
    printf("  Note: could not write saved network connections to %s (%s).\n"
           "  The saved files are still in the backup's network/%s/ directory. "
           "To copy them manually, run as root:\n\n"
           "    cp <backup>/network/%s/* %s/\n"
           "    chmod 600 %s/*\n",
           dest_dir, strerror(reason), backend->container_subdir,
           backend->container_subdir, dest_dir, dest_dir);
    if (backend->apply_mode == NETWORK_CONFIG_APPLY_RELOAD)
        printf("    nmcli connection reload\n");
    else
        printf("  When ready, run `%s`. This can briefly interrupt network "
               "connectivity, so migr does not run it automatically.\n",
               backend->manual_apply_hint);
}

// Returns 1 when a regular file was restored, 0 when the source entry was
// deliberately skipped, and -1 on a per-file failure.
static int restore_network_config_file_at(int network_fd, int dest_dir_fd,
                                          const char *name)
{
    struct stat entry_st;
    if (fstatat(network_fd, name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (!S_ISREG(entry_st.st_mode))
        return 0;

    int source_fd = openat(network_fd, name,
                           O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (source_fd < 0)
        return -1;

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
        close(source_fd);
        return 0;
    }

    struct stat existing_st;
    if (fstatat(dest_dir_fd, name, &existing_st, AT_SYMLINK_NOFOLLOW) == 0)
    {
        if (!S_ISREG(existing_st.st_mode))
        {
            close(source_fd);
            errno = EEXIST;
            return -1;
        }
    }
    else if (errno != ENOENT)
    {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }

    mode_t source_mode = source_st.st_mode & 0777;
    int dest_fd = openat(dest_dir_fd, name,
                         O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK |
                         O_NOFOLLOW | O_CLOEXEC,
                         source_mode);
    if (dest_fd < 0)
    {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }

    struct stat dest_st;
    int failed = 0;
    int saved_errno = 0;
    if (fstat(dest_fd, &dest_st) != 0)
    {
        saved_errno = errno;
        failed = 1;
    }
    else if (!S_ISREG(dest_st.st_mode))
    {
        saved_errno = EINVAL;
        failed = 1;
    }
    if (!failed &&
        portable_copy_regular(source_fd, dest_fd, source_st.st_size, NULL) != 0)
    {
        saved_errno = errno;
        failed = 1;
    }
    if (!failed && fchmod(dest_fd, source_mode) != 0)
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
        errno = saved_errno != 0 ? saved_errno : EIO;
        return -1;
    }
    return 1;
}

static void restore_network_config(int source_root_fd, int *had_error)
{
    int network_fd = openat(source_root_fd, "network",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (network_fd < 0)
    {
        if (errno == ENOENT)
            print_error("Error: manifest declares network configuration, "
                        "but network/ is missing from the backup\n");
        else
            print_error("Error: Could not read network/ in the backup: %s\n",
                        strerror(errno));
        *had_error = 1;
        return;
    }

    int found_backend = 0;
    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        const RestoreNetworkConfigBackend *backend =
            &RESTORE_NETWORK_CONFIG_BACKENDS[i];
        int backend_fd = openat(network_fd, backend->container_subdir,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (backend_fd < 0)
        {
            if (errno != ENOENT)
            {
                found_backend = 1;
                print_error("Error: Could not read network/%s/ in the backup: %s\n",
                            backend->container_subdir, strerror(errno));
                *had_error = 1;
            }
            continue;
        }
        found_backend = 1;

        DIR *dir = fdopendir(backend_fd);
        if (dir == NULL)
        {
            int saved_errno = errno;
            close(backend_fd);
            print_error("Error: Could not enumerate network/ in the backup: %s\n",
                        strerror(saved_errno));
            *had_error = 1;
            continue;
        }

        size_t regular_count = 0;
        if (network_config_regular_count(dir, &regular_count) != 0)
        {
            *had_error = 1;
            if (closedir(dir) != 0)
                *had_error = 1;
            continue;
        }
        if (regular_count == 0)
        {
            if (closedir(dir) != 0)
                *had_error = 1;
            continue;
        }

        const char *dest_dir = network_config_dest_dir(i);
        if (dry_run)
        {
            printf("\nNetwork configuration (%s)\n", backend->name);
            printf("  Would restore %zu network connection file%s to %s/\n",
                   regular_count, regular_count == 1 ? "" : "s", dest_dir);
            if (closedir(dir) != 0)
                *had_error = 1;
            continue;
        }

        int dest_created = 0;
        if (mkdir(dest_dir, 0700) == 0)
            dest_created = 1;
        else if (errno != EEXIST)
        {
            int saved_errno = errno;
            report_network_config_unapplied(backend, dest_dir, saved_errno);
            closedir(dir);
            continue;
        }

        int dest_dir_fd = open(dest_dir,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dest_dir_fd < 0)
        {
            int saved_errno = errno;
            if (dest_created)
                (void)rmdir(dest_dir);
            report_network_config_unapplied(backend, dest_dir, saved_errno);
            closedir(dir);
            continue;
        }
        if (faccessat(dest_dir_fd, ".", W_OK | X_OK, AT_EACCESS) != 0)
        {
            int saved_errno = errno;
            close(dest_dir_fd);
            if (dest_created)
                (void)rmdir(dest_dir);
            report_network_config_unapplied(backend, dest_dir, saved_errno);
            closedir(dir);
            continue;
        }

        printf("\nNetwork configuration (%s)\n", backend->name);
        size_t restored = 0;
        struct dirent *entry;
        for (;;)
        {
            errno = 0;
            entry = readdir(dir);
            if (entry == NULL)
            {
                if (errno != 0)
                {
                    print_error("Error: Could not enumerate network/ in the backup\n");
                    *had_error = 1;
                }
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            int file_result = restore_network_config_file_at(
                dirfd(dir), dest_dir_fd, entry->d_name);
            if (file_result < 0)
            {
                int saved_errno = errno;
                print_error("Error: Could not restore network/%s/%s: %s\n",
                            backend->container_subdir, entry->d_name, strerror(saved_errno));
                *had_error = 1;
                continue;
            }
            if (file_result > 0)
                restored++;
        }

        if (close(dest_dir_fd) != 0)
        {
            print_error("Error: Could not close network configuration destination: %s\n",
                        strerror(errno));
            *had_error = 1;
        }
        if (closedir(dir) != 0)
        {
            print_error("Error: Could not close network/ in the backup: %s\n",
                        strerror(errno));
            *had_error = 1;
        }

        if (restored == 0)
            continue;

        if (backend->apply_mode == NETWORK_CONFIG_APPLY_RELOAD)
            printf("  Restored %zu network connection file%s\n",
                   restored, restored == 1 ? "" : "s");
        if (backend->apply_mode == NETWORK_CONFIG_APPLY_MANUAL)
        {
            printf("  Restored %zu %s file(s) to %s/. Run `%s` yourself when "
                   "ready. This can briefly interrupt network connectivity, "
                   "so migr does not run it automatically.\n",
                   restored, backend->name, dest_dir, backend->manual_apply_hint);
        }
        else if (run_network_config_reload() != 0)
        {
            print_warning("Warning: restored network connection files, but "
                          "'nmcli connection reload' did not succeed. Run it "
                          "yourself, or restart NetworkManager, to apply them.\n");
        }
    }
    if (!found_backend)
    {
        print_error("Error: manifest declares network configuration, but none "
                    "of the known backend directories were present in network/\n");
        *had_error = 1;
    }
    if (close(network_fd) != 0)
    {
        print_error("Error: Could not close network/ in the backup: %s\n",
                    strerror(errno));
        *had_error = 1;
    }
}

typedef enum {
    LEGACY_HOME_ITEM_PROJECTS,
    LEGACY_HOME_ITEM_DOTFILE,
    LEGACY_HOME_ITEM_BROWSER
} LegacyHomeItemKind;

typedef struct {
    const char *name;
    LegacyHomeItemKind kind;
} LegacyHomeItem;

static const LegacyHomeItem LEGACY_HOME_ITEMS[] = {
    { "Projects",               LEGACY_HOME_ITEM_PROJECTS },
    { ".ssh",                   LEGACY_HOME_ITEM_DOTFILE },
    { ".gnupg",                 LEGACY_HOME_ITEM_DOTFILE },
    { ".gitconfig",             LEGACY_HOME_ITEM_DOTFILE },
    { ".bashrc",                LEGACY_HOME_ITEM_DOTFILE },
    { ".profile",               LEGACY_HOME_ITEM_DOTFILE },
    { ".mozilla",               LEGACY_HOME_ITEM_BROWSER },
    { ".config/google-chrome",  LEGACY_HOME_ITEM_BROWSER },
    { ".config/chromium",       LEGACY_HOME_ITEM_BROWSER },
    { ".config/BraveSoftware",  LEGACY_HOME_ITEM_BROWSER },
    { ".config/vivaldi",        LEGACY_HOME_ITEM_BROWSER },
    { ".config/microsoft-edge", LEGACY_HOME_ITEM_BROWSER },
    { ".config/opera",          LEGACY_HOME_ITEM_BROWSER },
};

enum { LEGACY_HOME_ITEM_COUNT =
    sizeof(LEGACY_HOME_ITEMS) / sizeof(LEGACY_HOME_ITEMS[0]) };

typedef struct {
    dev_t device;
    ino_t inode;
    int fd;
    int nsec_exact;
} RestoreTimestampAnchor;

typedef struct {
    RestoreTimestampAnchor *items;
    size_t count;
    size_t capacity;
} RestoreTimestampAnchors;

static void restore_timestamp_anchors_init(RestoreTimestampAnchors *anchors)
{
    memset(anchors, 0, sizeof(*anchors));
}

static void restore_timestamp_anchors_free(RestoreTimestampAnchors *anchors)
{
    if (anchors == NULL)
        return;
    for (size_t i = 0; i < anchors->count; i++)
        close(anchors->items[i].fd);
    free(anchors->items);
    memset(anchors, 0, sizeof(*anchors));
}

// Find the directory whose filesystem permissions and timestamp behaviour
// govern a destination root. Existing directory roots use themselves; an
// absent leaf or intermediate uses the nearest existing parent. This mirrors
// the restore walk without treating a missing intermediate as a shorter path.
static int restore_destination_anchor_fd(int root_fd, const char *rel)
{
    if (root_fd < 0 || rel == NULL || rel[0] == '/')
        return -1;

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    if (rel[0] == '\0')
        return current;

    const char *p = rel;
    for (;;)
    {
        const char *slash = strchr(p, '/');
        size_t length = slash == NULL ? strlen(p) : (size_t)(slash - p);
        if (length == 0 || length > NAME_MAX ||
            (length == 1 && p[0] == '.') ||
            (length == 2 && p[0] == '.' && p[1] == '.'))
        {
            close(current);
            return -1;
        }

        if (slash == NULL)
        {
            struct stat final_st;
            if (fstatat(current, p, &final_st, AT_SYMLINK_NOFOLLOW) != 0)
            {
                if (errno == ENOENT)
                    return current;
                close(current);
                return -1;
            }
            if (!S_ISDIR(final_st.st_mode))
                return current;

            int final_fd = openat(current, p,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
            if (final_fd < 0)
            {
                close(current);
                return -1;
            }
            close(current);
            return final_fd;
        }

        char component[NAME_MAX + 1];
        memcpy(component, p, length);
        component[length] = '\0';
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
        {
            if (errno == ENOENT)
                return current;
            close(current);
            return -1;
        }
        close(current);
        current = next;
        p = slash + 1;
    }
}

static int restore_timestamp_anchor_add(RestoreTimestampAnchors *anchors,
                                         int fd)
{
    if (anchors == NULL || fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    for (size_t i = 0; i < anchors->count; i++)
        if (anchors->items[i].device == st.st_dev &&
            anchors->items[i].inode == st.st_ino)
            return 0;

    if (anchors->count == anchors->capacity)
    {
        RestoreTimestampAnchor *items = array_reserve(
            anchors->items, &anchors->capacity, anchors->count, 1U,
            sizeof(*items), 8U, SIZE_MAX / sizeof(*items));
        if (items == NULL)
            return -1;
        anchors->items = items;
    }

    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0)
        return -1;
    anchors->items[anchors->count].device = st.st_dev;
    anchors->items[anchors->count].inode = st.st_ino;
    anchors->items[anchors->count].fd = copy;
    anchors->items[anchors->count].nsec_exact = 1;
    anchors->count++;
    return 0;
}

static int restore_timestamp_anchor_probe(RestoreTimestampAnchors *anchors)
{
    if (anchors == NULL)
        return -1;
    for (size_t i = 0; i < anchors->count; i++)
    {
        if (fsprobe_timestamps_fd(anchors->items[i].fd,
                                  &anchors->items[i].nsec_exact) != 0)
            return -1;
    }
    return 0;
}

static int restore_timestamp_anchor_policy(const RestoreTimestampAnchors *anchors,
                                            int fd, int *nsec_exact)
{
    if (anchors == NULL || fd < 0 || nsec_exact == NULL)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0)
        return -1;
    for (size_t i = 0; i < anchors->count; i++)
    {
        if (anchors->items[i].device == st.st_dev &&
            anchors->items[i].inode == st.st_ino)
        {
            *nsec_exact = anchors->items[i].nsec_exact;
            return 0;
        }
    }
    return -1;
}

// Reports the kernel's strict source-read refusal without suggesting an
// atime-changing fallback; a live replay also includes its partial counts.
static void report_source_safe_read_refusal(const char *label,
                                            const RestoreNativeReport *report)
{
    print_source_safe_read_refusal(label);
    if (report != NULL && report->failed_count != 0)
        print_error("Error: Native restore stopped at %s: %zu item(s) applied, "
               "%zu failed.\n",
               report->failed_logical_path[0] != '\0'
                   ? report->failed_logical_path : label,
               report->applied_count, report->failed_count);
}

static void restore_security_skipped_add(size_t *total, size_t count)
{
    if (total == NULL || count == 0 || *total == SIZE_MAX)
        return;
    if (count > SIZE_MAX - *total)
        *total = SIZE_MAX;
    else
        *total += count;
}

static void native_restore_security_dry_run_notice(size_t entries)
{
    if (entries != 0)
        printf("Security notice: %zu item(s) carry security.* attributes; "
               "whether they can be applied here is measured, not "
               "predicted, and is only found out on a live run.\n",
               entries);
}

static int native_restore_confirm(size_t security_xattr_entries)
{
    const char *ordinary_message =
        "This will restore files to your home directory. Continue?";
    if (security_xattr_entries == 0)
        return confirm_action(ordinary_message);

    char message[768];
    int length = snprintf(
        message, sizeof(message),
        "This restore includes %zu item(s) carrying security.* attributes "
        "(e.g. SELinux labels); if this destination or account cannot "
        "apply one, that item's other content and metadata will still be "
        "restored and only the attribute will be skipped. Continue?",
        security_xattr_entries);
    if (length < 0 || (size_t)length >= sizeof(message))
        return confirm_action(
            "This restore includes security.* attributes; an attribute "
            "that cannot be applied will be skipped while the item's other "
            "content and metadata are restored. Continue?");
    return confirm_action(message);
}

typedef struct {
    int printed_anything;
    struct timespec started_at;
    struct timespec last_sample_time;
    off_t last_sample_bytes;
} RestoreProgressDisplay;

static off_t progress_speed(off_t bytes_restored, off_t last_sample_bytes,
                            double sample_seconds)
{
    if (!isfinite(sample_seconds) || sample_seconds <= 0.0 ||
        bytes_restored <= last_sample_bytes)
        return 0;

    off_t delta = bytes_restored - last_sample_bytes;
    double speed = (double)delta / sample_seconds;
    if (!isfinite(speed) || speed <= 0.0)
        return 0;
    if (speed >= (double)INTMAX_MAX)
        return (off_t)INTMAX_MAX;
    return (off_t)speed;
}

static long progress_elapsed_whole_seconds(double elapsed_seconds)
{
    if (!isfinite(elapsed_seconds) || elapsed_seconds <= 0.0)
        return 0;
    if (elapsed_seconds >= (double)LONG_MAX)
        return LONG_MAX;
    return (long)elapsed_seconds;
}

static void restore_report_progress(off_t bytes_restored,
                                    const char *current_path,
                                    void *userdata)
{
    RestoreProgressDisplay *display = userdata;
    if (display == NULL)
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    if (!display->printed_anything)
    {
        display->started_at = now;
        display->last_sample_time = now;
        display->last_sample_bytes = 0;
    }

    double elapsed_seconds = timespec_elapsed_seconds(&display->started_at,
                                                      &now);
    double sample_seconds = timespec_elapsed_seconds(
        &display->last_sample_time, &now);
    off_t speed_bytes = progress_speed(bytes_restored,
                                       display->last_sample_bytes,
                                       sample_seconds);

    char restored_text[32];
    char elapsed_text[32];
    char speed_text[32];
    format_size(bytes_restored, restored_text, sizeof(restored_text));
    format_duration(progress_elapsed_whole_seconds(elapsed_seconds),
                    elapsed_text, sizeof(elapsed_text));
    format_size(speed_bytes, speed_text, sizeof(speed_text));
    const char *path_text = current_path != NULL && current_path[0] != '\0'
        ? current_path : "unknown";
    printf("\rRestored: %s so far, elapsed %s, speed %s/s, current: %s\033[K",
           restored_text, elapsed_text, speed_text, path_text);
    fflush(stdout);
    display->last_sample_time = now;
    display->last_sample_bytes = bytes_restored;
    display->printed_anything = 1;
}

// Restores one item whose source and destination relative addresses may
// differ (e.g. a v1 root's "data/<payload>" source vs. its own restore
// address), sharing the exact same status/preflight/apply behavior for
// every caller so dry-run and live can never disagree. Prints only the
// shared error messages; the caller prints its own success/preview message
// when this returns > 0, since callers want different wording.
// Returns 1 if restored (or safely previewed), 0 if an optional source is
// absent, and -1 on an error or a missing required source.
static int restore_item_at(const CloneContext *ctx,
                           int source_root_fd, const char *source_rel,
                           int dest_root_fd, const char *dest_rel,
                           const char *label, int source_required,
                           const RestoreTimestampAnchors *timestamp_anchors,
                           size_t *skipped_security_xattrs,
                           BackupCaptureReport *capture_report)
{
    RestoreSourceStatus status = restore_native_source_status_at(source_root_fd, source_rel);
    if (status == RESTORE_SOURCE_MISSING)
    {
        if (source_required)
        {
            print_error("Error: Manifest root %s is missing its declared payload\n", label);
            return -1;
        }
        return 0;
    }
    if (status == RESTORE_SOURCE_ERROR)
    {
        print_error("Error: Failed to inspect %s\n", label);
        return -1;
    }

    CloneContext effective_ctx = *ctx;
    int policy_anchor_fd = restore_destination_anchor_fd(dest_root_fd, dest_rel);
    if (policy_anchor_fd < 0)
    {
        print_error("Error: Failed to inspect restore destination for %s\n", label);
        return -1;
    }
    if (timestamp_anchors != NULL &&
        restore_timestamp_anchor_policy(timestamp_anchors, policy_anchor_fd,
                                        &effective_ctx.nsec_exact) != 0)
    {
        close(policy_anchor_fd);
        print_error("Error: Restore destination was not covered by timestamp preflight for %s\n",
               label);
        return -1;
    }
    if (timestamp_anchors != NULL)
        effective_ctx.timestamp_policy_configured = 1;
    if (close(policy_anchor_fd) != 0)
    {
        print_error("Error: Failed to inspect restore destination for %s\n", label);
        return -1;
    }
    const CloneContext *run_ctx = &effective_ctx;

    if (dry_run)
    {
        RestoreNativeStatus native_status = restore_native_preflight_at(
            run_ctx, source_root_fd, source_rel, dest_root_fd, dest_rel);
        if (native_status != RESTORE_NATIVE_OK)
        {
            if (native_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                report_source_safe_read_refusal(label, NULL);
            else
                print_error("Error: Failed to restore %s\n", label);
            return -1;
        }
        return 1;
    }

    if (verbose)
        printf("  Restoring: %s\n", label);

    RestoreNativeReport report;
    RestoreNativeStatus native_status = restore_native_at_report(
        run_ctx, source_root_fd, source_rel, dest_root_fd, dest_rel, &report,
        capture_report);
    if (skipped_security_xattrs != NULL)
        restore_security_skipped_add(skipped_security_xattrs,
                                     report.skipped_security_xattr_count);
    if (native_status != RESTORE_NATIVE_OK)
    {
        if (native_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
            report_source_safe_read_refusal(label, &report);
        else
            print_error("Error: Failed to restore %s\n", label);
        return -1;
    }
    return 1;
}

// A backup-relative path restored directly into home under the same name on
// both sides (legacy's Projects/dotfiles/browser-config items).
static int restore_home_item(const CloneContext *ctx, int source_root_fd,
                             int home_fd, const char *rel_path,
                             const RestoreTimestampAnchors *timestamp_anchors,
                             size_t *skipped_security_xattrs,
                             BackupCaptureReport *capture_report)
{
    int rc = restore_item_at(ctx, source_root_fd, rel_path, home_fd, rel_path,
                             rel_path, 0, timestamp_anchors,
                             skipped_security_xattrs, capture_report);
    if (rc > 0 && dry_run)
        printf("  Would restore: %s\n", rel_path);
    return rc;
}

// Versioned restore phases consume the same invocation-stable anchor/relative
// pair. HOME roots borrow home_fd, whose lifetime encloses the map; XDG roots
// own their held anchor. absolute remains the lexical address used by VERSION=2
// collision/order checks and by dry-run reporting.
typedef struct {
    char relative[PATH_MAX];
    int anchor_fd;
} RestoreTargetRoute;

typedef struct {
    char absolute[PATH_MAX];
    RestoreTargetRoute route;
    int owns_anchor;
    DestinationIdentityPlacement placement;
    int has_placement;
} RestoreTargetRoot;

typedef struct {
    RestoreTargetRoot *roots;
    int *order;
    size_t count;
    DestinationIdentityGraph identity_graph;
} RestoreTargetMap;

// Resolves the legacy source-side identifier for the i-th XDG slot: the
// recorded legacy manifest name if present, else the destination-locale
// directory's own basename. legacy_manifest_read() guarantees manifest_names
// is all-NULL when it fails, so no separate "has manifest" flag is needed
// here.
static const char *legacy_xdg_source_name(
    char *const manifest_names[XDG_RESTORE_COUNT],
    char *const xdg_dirs[XDG_RESTORE_COUNT], int i)
{
    if (manifest_names[i] != NULL)
        return manifest_names[i];
    const char *slash = strrchr(xdg_dirs[i], '/');
    return slash == NULL ? xdg_dirs[i] : slash + 1;
}

// Restores XDG main directories, Projects, dotfiles, and browser profiles
// from an unversioned or manifest-absent backup. This path preserves the
// legacy layout and its all-or-nothing XDG destination resolution.
static int restore_legacy(const char *source, int source_root_fd, const char *home, int home_fd,
                          const CloneContext *ctx, int *count, int *had_error,
                          const RestoreTimestampAnchors *timestamp_anchors,
                          size_t *skipped_security_xattrs,
                          BackupCaptureReport *capture_report)
{
    printf("Main Directories\n");
    char *xdg_dirs[XDG_RESTORE_COUNT];
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT) != 0)
    {
        print_error("Error: HOME path too long to resolve user directories\n");
        free_xdg_dirs(xdg_dirs);
        *had_error = 1;
        return -1;
    }
    char *manifest_names[XDG_RESTORE_COUNT];
    (void)legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT);

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        // The manifest name locates the source-locale directory; xdg_dirs[i] is
        // the destination-locale path. Fall back to its basename if absent.
        const char *name = legacy_xdg_source_name(manifest_names, xdg_dirs, i);

        RestoreSourceStatus source_status = restore_native_source_status_at(source_root_fd, name);
        if (source_status == RESTORE_SOURCE_MISSING)
            continue;
        if (source_status == RESTORE_SOURCE_ERROR)
        {
            print_error("Error: Failed to inspect %s\n", name);
            *had_error = 1;
            continue;
        }

        // xdg_dirs[i] may be any absolute path (see xdg_resolve()'s contract),
        // not necessarily under home: open (creating if needed) its own
        // directory fd and restore into it directly as the destination root
        // itself ("", docs/DECISIONS.md D16), rather than assuming it is
        // reachable via home_fd.
        int xdg_dest_fd;
        char destination_rel[PATH_MAX];
        if (open_xdg_destination_anchor(xdg_dirs[i], &xdg_dest_fd, destination_rel, sizeof(destination_rel)) != 0)
        {
            print_error("Error: Failed to restore %s\n", name);
            *had_error = 1;
            continue;
        }

        int rc = restore_item_at(ctx, source_root_fd, name, xdg_dest_fd,
                                 destination_rel, name, 0,
                                 timestamp_anchors,
                                 skipped_security_xattrs, capture_report);
        if (rc > 0 && dry_run)
            printf("  Would restore: %s -> %s/\n", name, xdg_dirs[i]);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;

        if (close(xdg_dest_fd) != 0)
            *had_error = 1;
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);
    free_xdg_dirs(xdg_dirs);

    int rc;
    // Projects is not a standard XDG directory
    for (int i = 0; i < LEGACY_HOME_ITEM_COUNT; i++)
    {
        if (LEGACY_HOME_ITEMS[i].kind != LEGACY_HOME_ITEM_PROJECTS)
            continue;
        rc = restore_home_item(ctx, source_root_fd, home_fd,
                               LEGACY_HOME_ITEMS[i].name, timestamp_anchors,
                               skipped_security_xattrs, capture_report);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
    }

    printf("\nDotfiles\n");
    for (int i = 0; i < LEGACY_HOME_ITEM_COUNT; i++)
    {
        if (LEGACY_HOME_ITEMS[i].kind != LEGACY_HOME_ITEM_DOTFILE)
            continue;
        rc = restore_home_item(ctx, source_root_fd, home_fd,
                               LEGACY_HOME_ITEMS[i].name,
                               timestamp_anchors, skipped_security_xattrs,
                               capture_report);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
    }

    printf("\nBrowser Profiles\n");
    for (int i = 0; i < LEGACY_HOME_ITEM_COUNT; i++)
    {
        if (LEGACY_HOME_ITEMS[i].kind != LEGACY_HOME_ITEM_BROWSER)
            continue;
        rc = restore_home_item(ctx, source_root_fd, home_fd,
                               LEGACY_HOME_ITEMS[i].name,
                               timestamp_anchors, skipped_security_xattrs,
                               capture_report);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
    }

    return 0;
}

static int v1_payload_rel(const ManifestRoot *root, char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "data/%s", root->payload_path);
    return n < 0 || (size_t)n >= out_size ? -1 : 0;
}

static int seed_native_restore_root(const CloneContext *ctx,
                                    const RestoreTimestampAnchors *anchors,
                                    const char *source,
                                    const char *source_rel,
                                    int destination_root_fd,
                                    const char *destination_rel)
{
    CloneContext effective_ctx = *ctx;
    int policy_anchor_fd = restore_destination_anchor_fd(destination_root_fd,
                                                         destination_rel);
    if (policy_anchor_fd < 0 ||
        restore_timestamp_anchor_policy(anchors, policy_anchor_fd,
                                        &effective_ctx.nsec_exact) != 0)
    {
        if (policy_anchor_fd >= 0)
            close(policy_anchor_fd);
        return -1;
    }
    effective_ctx.timestamp_policy_configured = 1;
    if (close(policy_anchor_fd) != 0)
        return -1;

    char source_path[PATH_MAX];
    if (source == NULL || source_rel == NULL || destination_rel == NULL)
        return -1;
    if (source_rel[0] == '\0')
    {
        int n = snprintf(source_path, sizeof(source_path), "%s", source);
        if (n < 0 || (size_t)n >= sizeof(source_path))
            return -1;
    }
    else if (path_join(source_path, sizeof(source_path), source,
                       source_rel) != 0)
        return -1;
    return native_inode_map_seed_existing(&effective_ctx, source_path,
                                          destination_root_fd,
                                          destination_rel);
}

static int seed_native_restore_v1_hardlink_map(
    const char *source, int source_root_fd, const Manifest *m,
    const RestoreTargetMap *target_map, const CloneContext *ctx,
    const RestoreTimestampAnchors *anchors)
{
    int failed = 0;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue;

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0 ||
            restore_native_source_status_at(source_root_fd, source_rel) !=
                RESTORE_SOURCE_PRESENT)
        {
            failed = 1;
            continue;
        }

        const RestoreTargetRoot *destination = &target_map->roots[i];
        if (seed_native_restore_root(ctx, anchors, source, source_rel,
                                     destination->route.anchor_fd,
                                     destination->route.relative) != 0)
            failed = 1;
    }

    return failed ? -1 : 0;
}

static int seed_native_restore_legacy_hardlink_map(
    const char *source, int source_root_fd, const char *home, int home_fd,
    const CloneContext *ctx, const RestoreTimestampAnchors *anchors)
{
    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                    XDG_RESTORE_COUNT) != 0)
    {
        free_xdg_dirs(xdg_dirs);
        return -1;
    }

    char *manifest_names[XDG_RESTORE_COUNT] = {0};
    (void)legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT);
    int failed = 0;
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        const char *name = legacy_xdg_source_name(manifest_names, xdg_dirs, i);

        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, name);
        if (status == RESTORE_SOURCE_MISSING)
            continue;
        if (status != RESTORE_SOURCE_PRESENT)
        {
            failed = 1;
            continue;
        }

        int destination_fd;
        char destination_rel[PATH_MAX];
        if (open_xdg_destination_anchor(xdg_dirs[i], &destination_fd,
                                         destination_rel,
                                         sizeof(destination_rel)) != 0)
        {
            failed = 1;
            continue;
        }
        if (seed_native_restore_root(ctx, anchors, source, name,
                                     destination_fd, destination_rel) != 0)
            failed = 1;
        if (close(destination_fd) != 0)
            failed = 1;
    }

    for (int i = 0; i < LEGACY_HOME_ITEM_COUNT; i++)
    {
        const char *name = LEGACY_HOME_ITEMS[i].name;
        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, name);
        if (status == RESTORE_SOURCE_MISSING)
            continue;
        if (status != RESTORE_SOURCE_PRESENT ||
            seed_native_restore_root(ctx, anchors, source, name,
                                     home_fd, name) != 0)
            failed = 1;
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);
    free_xdg_dirs(xdg_dirs);
    return failed ? -1 : 0;
}

// A versioned root table is an inventory, not a list of optional probes. A
// finalized container missing any declared payload is corrupt and must be
// refused before confirmation or destination mutation.
static int validate_v1_payloads(int source_root_fd, const Manifest *m)
{
    int failed = 0;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            print_error("Error: Manifest root %s has an invalid payload address\n",
                   root->id);
            failed = 1;
            continue;
        }

        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, source_rel);
        if (status == RESTORE_SOURCE_MISSING)
        {
            print_error("Error: Manifest root %s is missing its declared payload\n",
                   root->id);
            failed = 1;
        }
        else if (status == RESTORE_SOURCE_ERROR)
        {
            print_error("Error: Could not safely inspect payload for manifest root %s\n",
                   root->id);
            failed = 1;
        }
    }

    return failed ? -1 : 0;
}

static int selection_payload_open_at(int data_fd, const char *payload_path,
                                     struct stat *out, int *directory_fd)
{
    if (data_fd < 0 || payload_path == NULL || payload_path[0] == '\0' ||
        out == NULL || directory_fd == NULL ||
        strnlen(payload_path, PATH_MAX) >= PATH_MAX)
        return -1;

    *directory_fd = -1;
    char copy[PATH_MAX];
    memcpy(copy, payload_path, strlen(payload_path) + 1U);
    int parent_fd = dup_cloexec(data_fd);
    if (parent_fd < 0)
        return -1;

    char *component = copy;
    for (;;)
    {
        char *slash = strchr(component, '/');
        if (slash != NULL)
            *slash = '\0';
        if (component[0] == '\0' || !strcmp(component, ".") ||
            !strcmp(component, "..") || strlen(component) > NAME_MAX)
        {
            close(parent_fd);
            return -1;
        }

        if (slash == NULL)
            break;
        int next_fd = openat(parent_fd, component,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                 O_NOATIME | O_CLOEXEC);
        if (next_fd < 0)
        {
            close(parent_fd);
            return -1;
        }
        close(parent_fd);
        parent_fd = next_fd;
        component = slash + 1;
    }

    int object_fd = openat(parent_fd, component,
                           O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (object_fd < 0 || fstat(object_fd, out) != 0)
    {
        if (object_fd >= 0)
            close(object_fd);
        close(parent_fd);
        return -1;
    }
    close(object_fd);

    if (S_ISDIR(out->st_mode))
        *directory_fd = openat(parent_fd, component,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_NOATIME | O_CLOEXEC);
    close(parent_fd);
    return S_ISDIR(out->st_mode) && *directory_fd < 0 ? -1 : 0;
}

typedef struct {
    int index;
    size_t order;
    int automatic;
} SelectionRestoreOrder;

static int restore_order_compare(const void *left, const void *right)
{
    const SelectionRestoreOrder *a = left;
    const SelectionRestoreOrder *b = right;
    if (a->automatic != b->automatic)
        return a->automatic ? -1 : 1;
    if (a->order > b->order)
        return -1;
    if (a->order < b->order)
        return 1;
    return a->index < b->index ? -1 : a->index > b->index;
}

static void restore_target_map_init(RestoreTargetMap *map)
{
    memset(map, 0, sizeof(*map));
    destination_identity_graph_init(&map->identity_graph,
                                    DESTINATION_IDENTITY_NATIVE_BOUNDS);
}

static int restore_target_map_free(RestoreTargetMap *map)
{
    if (map == NULL)
        return 0;
    int failed = 0;
    for (size_t i = 0; i < map->count; i++)
        if (map->roots[i].owns_anchor && map->roots[i].route.anchor_fd >= 0)
        {
            if (close(map->roots[i].route.anchor_fd) != 0)
            {
                print_error("Error: Failed to close restore destination anchor %s\n",
                            map->roots[i].absolute);
                failed = 1;
            }
        }
    destination_identity_graph_free(&map->identity_graph);
    free(map->roots);
    free(map->order);
    restore_target_map_init(map);
    return failed ? -1 : 0;
}

static int restore_target_identity_add(
    RestoreTargetMap *map, const Manifest *manifest, size_t root_index,
    const char *logical, const struct stat *source_st, size_t owner,
    DestinationIdentityPlacement *placement)
{
    if (map == NULL || manifest == NULL || logical == NULL ||
        source_st == NULL || placement == NULL ||
        root_index >= (size_t)manifest->root_count ||
        root_index >= map->count)
    {
        errno = EINVAL;
        return -1;
    }

    const ManifestRoot *root = &manifest->roots[root_index];
    const RestoreTargetRoot *target = &map->roots[root_index];
    char relative[PATH_MAX];
    if (destination_relative_path_build(target->route.relative, logical,
                                        relative, sizeof(relative)) != 0)
    {
        print_error("Error: Restore destination for manifest root %s entry %s is too long\n",
                    root->id, logical[0] == '\0' ? "." : logical);
        return -1;
    }

    DestinationIdentityClaim claim = S_ISDIR(source_st->st_mode)
        ? DESTINATION_IDENTITY_DIRECTORY
        : DESTINATION_IDENTITY_NON_DIRECTORY;
    size_t conflicting_owner;
    DestinationIdentityStatus status = destination_identity_graph_add(
        &map->identity_graph, target->route.anchor_fd, relative, claim,
        owner, placement, &conflicting_owner);
    if (status == DESTINATION_IDENTITY_OK)
        return 0;

    const char *entry_name = logical[0] == '\0' ? "." : logical;
    if (status == DESTINATION_IDENTITY_COLLISION)
    {
        char destination[PATH_MAX];
        if ((logical[0] == '\0' &&
             snprintf(destination, sizeof(destination), "%s",
                      target->absolute) >= (int)sizeof(destination)) ||
            (logical[0] != '\0' &&
             path_join(destination, sizeof(destination), target->absolute,
                       logical) != 0))
            snprintf(destination, sizeof(destination), "%s", relative);
        size_t conflicting_root = conflicting_owner % MANIFEST_MAX_ROOTS;
        if (conflicting_owner != SIZE_MAX &&
            conflicting_root < (size_t)manifest->root_count)
            print_error("Error: Manifest root %s entry %s and manifest root %s have competing entries for restore destination %s\n",
                        root->id, entry_name,
                        manifest->roots[conflicting_root].id,
                        destination);
        else
            print_error("Error: Manifest root %s entry %s conflicts with an existing directory at restore destination %s\n",
                        root->id, entry_name, destination);
    }
    else if (status == DESTINATION_IDENTITY_RESOURCE_ERROR)
    {
        if (errno == E2BIG)
            print_error("Error: Native restore destination identity budget exceeded while mapping manifest root %s entry %s\n",
                        root->id, entry_name);
        else
            print_error("Error: Could not allocate destination identity state for manifest root %s entry %s\n",
                        root->id, entry_name);
    }
    else
        print_error("Error: Could not safely inspect restore destination for manifest root %s entry %s\n",
                    root->id, entry_name);
    return -1;
}

/* Keep the same safety margin as fileops.c's RESTORE_MAX_DEPTH. Both walkers
 * recurse over untrusted native payloads with PATH_MAX-sized stack frames. */
#define RESTORE_PAYLOAD_MAX_DEPTH 512U

/* Preserve a unique graph owner while making the prior root recoverable for
 * collision diagnostics, without retaining one label per payload entry. */
static int restore_target_owner_next(size_t *sequence, size_t root_index,
                                     size_t *owner)
{
    if (sequence == NULL || owner == NULL || root_index >= MANIFEST_MAX_ROOTS ||
        *sequence > (SIZE_MAX - 1U - root_index) / MANIFEST_MAX_ROOTS)
    {
        errno = E2BIG;
        return -1;
    }
    *owner = *sequence * MANIFEST_MAX_ROOTS + root_index;
    (*sequence)++;
    return 0;
}

static int restore_payload_inventory_walk(
    RestoreTargetMap *map, const Manifest *manifest, size_t root_index,
    int directory_fd, const char *logical, int validate_ownership,
    int map_identity, size_t *next_owner, size_t depth)
{
    if (depth > RESTORE_PAYLOAD_MAX_DEPTH)
    {
        close(directory_fd);
        errno = E2BIG;
        print_error("Error: Manifest root %s payload exceeds the maximum directory depth at %s\n",
                    manifest->roots[root_index].id,
                    logical[0] == '\0' ? "." : logical);
        return -1;
    }

    DIR *directory = fdopendir(directory_fd);
    if (directory == NULL)
    {
        int saved = errno;
        close(directory_fd);
        errno = saved;
        print_error("Error: Could not inspect payload entries for manifest root %s at %s\n",
                    manifest->roots[root_index].id,
                    logical[0] == '\0' ? "." : logical);
        return -1;
    }

    int failed = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL)
        {
            if (errno != 0)
            {
                print_error("Error: Could not enumerate payload entries for manifest root %s at %s\n",
                            manifest->roots[root_index].id,
                            logical[0] == '\0' ? "." : logical);
                failed = 1;
            }
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        char child[PATH_MAX];
        int child_length = logical[0] == '\0'
            ? snprintf(child, sizeof(child), "%s", entry->d_name) : 0;
        if ((logical[0] == '\0' &&
             (child_length < 0 || (size_t)child_length >= sizeof(child))) ||
            (logical[0] != '\0' &&
             path_join(child, sizeof(child), logical, entry->d_name) != 0))
        {
            print_error("Error: Payload entry path is too long for manifest root %s: %s\n",
                        manifest->roots[root_index].id, entry->d_name);
            failed = 1;
            break;
        }
        if (validate_ownership &&
            manifest_entry_owned(manifest, (int)root_index, child) != 1)
        {
            print_error("Error: Manifest root %s contains an entry outside its recorded selection: %s\n",
                        manifest->roots[root_index].id, child);
            failed = 1;
            break;
        }

        struct stat st;
        if (fstatat(dirfd(directory), entry->d_name, &st,
                    AT_SYMLINK_NOFOLLOW) != 0)
        {
            print_error("Error: Could not safely inspect payload entry for manifest root %s: %s\n",
                        manifest->roots[root_index].id, child);
            failed = 1;
            break;
        }
        size_t owner;
        if (map_identity &&
            restore_target_owner_next(next_owner, root_index, &owner) != 0)
        {
            errno = E2BIG;
            print_error("Error: Too many destination entries while mapping manifest root %s: %s\n",
                        manifest->roots[root_index].id, child);
            failed = 1;
            break;
        }

        if (map_identity)
        {
            DestinationIdentityPlacement placement;
            if (restore_target_identity_add(map, manifest, root_index, child,
                                            &st, owner, &placement) != 0)
            {
                failed = 1;
                break;
            }
        }

        if (!S_ISDIR(st.st_mode))
            continue;
        int child_fd = openat(dirfd(directory), entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_NOATIME | O_CLOEXEC);
        if (child_fd < 0)
        {
            print_error("Error: Could not safely open payload directory for manifest root %s: %s\n",
                        manifest->roots[root_index].id, child);
            failed = 1;
            break;
        }
        if (restore_payload_inventory_walk(
                map, manifest, root_index, child_fd, child,
                validate_ownership, map_identity, next_owner, depth + 1U) != 0)
        {
            failed = 1;
            break;
        }
    }

    if (closedir(directory) != 0 && !failed)
    {
        print_error("Error: Could not close payload inventory for manifest root %s at %s\n",
                    manifest->roots[root_index].id,
                    logical[0] == '\0' ? "." : logical);
        failed = 1;
    }
    return failed ? -1 : 0;
}

static int restore_target_identity_register_anchors(
    RestoreTargetMap *map, int home_fd, const Manifest *manifest)
{
    DestinationIdentityStatus anchor_status =
        destination_identity_graph_register_anchor(&map->identity_graph,
                                                   home_fd);
    if (anchor_status != DESTINATION_IDENTITY_OK)
    {
        if (anchor_status == DESTINATION_IDENTITY_RESOURCE_ERROR &&
            errno == E2BIG)
            print_error("Error: Native restore destination identity budget exceeded while registering destination HOME ancestry\n");
        else
            print_error("Error: Could not inspect destination HOME ancestry for versioned restore\n");
        return -1;
    }

    unsigned char registered_xdg[XDG_RESTORE_COUNT] = {0};
    for (size_t index = 0; index < map->count; index++)
        if (manifest->roots[index].policy == ROOT_POLICY_XDG)
        {
            int key = xdg_key_index(manifest->roots[index].id);
            if (key < 0 || key >= XDG_RESTORE_COUNT)
            {
                print_error("Error: Could not identify XDG restore destination for manifest root %s\n",
                            manifest->roots[index].id);
                return -1;
            }
            if (!registered_xdg[key])
            {
                anchor_status = destination_identity_graph_register_anchor(
                    &map->identity_graph, map->roots[index].route.anchor_fd);
                if (anchor_status != DESTINATION_IDENTITY_OK)
                {
                    if (anchor_status == DESTINATION_IDENTITY_RESOURCE_ERROR &&
                        errno == E2BIG)
                        print_error("Error: Native restore destination identity budget exceeded while registering XDG ancestry for manifest root %s\n",
                                    manifest->roots[index].id);
                    else
                        print_error("Error: Could not inspect XDG destination ancestry for manifest root %s\n",
                                    manifest->roots[index].id);
                    return -1;
                }
                registered_xdg[key] = 1;
            }
        }

    return 0;
}

static int restore_target_identity_finalize(RestoreTargetMap *map)
{
    DestinationIdentityStatus status =
        destination_identity_graph_finalize(&map->identity_graph);
    if (status == DESTINATION_IDENTITY_OK)
        return 0;
    if (status == DESTINATION_IDENTITY_CYCLE)
        print_error("Error: Restore destination namespace contains a cyclic mapping\n");
    else if (status == DESTINATION_IDENTITY_RESOURCE_ERROR && errno == E2BIG)
        print_error("Error: Native restore destination identity budget exceeded while ordering the destination namespace\n");
    else
        print_error("Error: Could not finalize the restore destination identity map\n");
    return -1;
}

static int restore_target_identity_root_preflight(
    int data_fd, const Manifest *manifest, RestoreTargetMap *map,
    SelectionRestoreOrder *items)
{
    size_t next_owner = 0;
    int validate_ownership =
        manifest->version == MANIFEST_SELECTION_VERSION;
    for (size_t index = 0; index < map->count; index++)
    {
        const ManifestRoot *root = &manifest->roots[index];
        items[index] = (SelectionRestoreOrder){
            .index = (int)index,
            .automatic = root->policy != ROOT_POLICY_MANUAL_NATIVE
        };
        if (manifest->version == MANIFEST_SELECTION_VERSION &&
            manifest_entry_owned(manifest, (int)index, "") != 1)
        {
            print_error("Error: Manifest root %s payload root is outside its recorded selection\n",
                        root->id);
            return -1;
        }
        if (!items[index].automatic && !validate_ownership)
            continue;

        struct stat st;
        int root_fd = -1;
        if (selection_payload_open_at(data_fd, root->payload_path, &st,
                                      &root_fd) != 0)
        {
            print_error("Error: Could not safely inspect payload for manifest root %s\n",
                        root->id);
            return -1;
        }
        if (items[index].automatic)
        {
            size_t owner;
            if (restore_target_owner_next(&next_owner, index, &owner) != 0)
            {
                if (root_fd >= 0)
                    close(root_fd);
                errno = E2BIG;
                print_error("Error: Too many destination entries while mapping manifest root %s\n",
                            root->id);
                return -1;
            }

            DestinationIdentityPlacement placement;
            if (restore_target_identity_add(map, manifest, index, "", &st,
                                            owner, &placement) != 0)
            {
                if (root_fd >= 0)
                    close(root_fd);
                return -1;
            }
            map->roots[index].placement = placement;
            map->roots[index].has_placement = 1;
        }

        if (root_fd >= 0 &&
            restore_payload_inventory_walk(
                map, manifest, index, root_fd, "", validate_ownership,
                items[index].automatic, &next_owner, 0U) != 0)
            return -1;
    }

    return restore_target_identity_finalize(map);
}

static int restore_target_identity_build(
    int source_root_fd, int home_fd, const Manifest *manifest,
    RestoreTargetMap *map, SelectionRestoreOrder *items)
{
    int data_fd = openat(source_root_fd, "data",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                             O_CLOEXEC);
    if (data_fd < 0)
    {
        print_error("Error: Could not open versioned restore payload inventory\n");
        return -1;
    }

    int failed = restore_target_identity_register_anchors(
                     map, home_fd, manifest) != 0 ||
        restore_target_identity_root_preflight(
            data_fd, manifest, map, items) != 0;

    if (close(data_fd) != 0 && !failed)
    {
        print_error("Error: Could not close versioned restore payload inventory\n");
        failed = 1;
    }
    if (failed)
        return -1;

    for (size_t index = 0; index < map->count; index++)
    {
        if (!items[index].automatic)
            continue;
        if (!map->roots[index].has_placement ||
            destination_identity_graph_order(
                &map->identity_graph, &map->roots[index].placement,
                &items[index].order) != 0)
        {
            print_error("Error: Could not order restore destination for manifest root %s\n",
                        manifest->roots[index].id);
            return -1;
        }
    }

    qsort(items, map->count, sizeof(*items), restore_order_compare);
    for (size_t index = 0; index < map->count; index++)
        map->order[index] = items[index].index;
    return 0;
}

static int restore_target_map_build(int source_root_fd, const char *home,
                                    int home_fd, const Manifest *manifest,
                                    RestoreTargetMap *out)
{
    restore_target_map_init(out);

    size_t count = (size_t)manifest->root_count;
    RestoreTargetRoot *roots =
        count == 0 ? NULL : calloc(count, sizeof(*roots));
    int *order = count == 0 ? NULL : calloc(count, sizeof(*order));
    SelectionRestoreOrder *items =
        count == 0 ? NULL : calloc(count, sizeof(*items));
    if (roots != NULL)
        for (size_t index = 0; index < count; index++)
            roots[index].route.anchor_fd = -1;
    if (count != 0 && (!roots || !order || !items))
    {
        print_error("Error: out of memory building the restore destination map\n");
        free(items);
        free(roots);
        free(order);
        return -1;
    }
    out->roots = roots;
    out->order = order;
    out->count = count;

    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    int xdg_ready = 0;
    for (size_t index = 0; index < count; index++)
    {
        const ManifestRoot *root = &manifest->roots[index];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue;
        if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            roots[index].route.anchor_fd = home_fd;
            int relative_length = snprintf(roots[index].route.relative, PATH_MAX,
                                           "%s", root->restore_path);
            if (relative_length < 0 || relative_length >= PATH_MAX)
            {
                print_error("Error: Restore destination for manifest root %s is too long\n",
                            root->id);
                goto fail;
            }
            if (root->restore_path[0] == '\0')
            {
                if (snprintf(roots[index].absolute, PATH_MAX, "%s", home) >=
                    PATH_MAX)
                {
                    print_error("Error: Restore destination for manifest root %s is too long\n",
                                root->id);
                    goto fail;
                }
            }
            else if (path_join(roots[index].absolute, PATH_MAX, home,
                               root->restore_path) != 0)
            {
                print_error("Error: Restore destination for manifest root %s is too long\n",
                            root->id);
                goto fail;
            }
        }
        else
        {
            if (!xdg_ready)
            {
                if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                                XDG_RESTORE_COUNT) != 0)
                {
                    print_error("Error: HOME path too long to resolve user directories\n");
                    goto fail;
                }
                xdg_ready = 1;
            }
            int key = xdg_key_index(root->id);
            if (key < 0)
            {
                print_error("Error: Unrecognized XDG root id: %s\n", root->id);
                goto fail;
            }
            if (xdg_dirs[key] == NULL ||
                snprintf(roots[index].absolute, PATH_MAX, "%s",
                         xdg_dirs[key]) >= PATH_MAX)
            {
                print_error("Error: XDG restore destination for %s is too long\n",
                            root->id);
                goto fail;
            }
            if (open_xdg_destination_anchor(
                    xdg_dirs[key], &roots[index].route.anchor_fd,
                    roots[index].route.relative,
                    sizeof(roots[index].route.relative)) != 0)
            {
                print_error("Error: Failed to anchor XDG restore destination for %s\n",
                            root->id);
                goto fail;
            }
            roots[index].owns_anchor = 1;
        }
    }

    if (count != 0 &&
        restore_target_identity_build(source_root_fd, home_fd, manifest, out,
                                      items) != 0)
        goto fail;

    free(items);
    free_xdg_dirs(xdg_dirs);
    return 0;

fail:
    free_xdg_dirs(xdg_dirs);
    free(items);
    restore_target_map_free(out);
    return -1;
}

static RestoreNativeStatus restore_metadata_item(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel, const char *label,
    int required, MetadataProfiles *profiles,
    RestoreTimestampAnchors *timestamp_anchors,
    NativeRestoreEstimate *estimate)
{
    RestoreSourceStatus status =
        restore_native_source_status_at(source_root_fd, source_rel);
    if (status == RESTORE_SOURCE_MISSING)
    {
        if (required)
            print_error("Error: Manifest root %s is missing its declared payload\n",
                   label);
        return required ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
    }
    if (status == RESTORE_SOURCE_ERROR)
    {
        print_error("Error: Failed to inspect %s\n", label);
        return RESTORE_NATIVE_ERROR;
    }
    int metadata_anchor_fd = restore_destination_anchor_fd(destination_root_fd,
                                                           destination_rel);
    if (metadata_anchor_fd < 0)
    {
        print_error("Error: Failed to inspect restore destination for %s\n", label);
        return RESTORE_NATIVE_ERROR;
    }
    int anchor_failed = restore_timestamp_anchor_add(timestamp_anchors,
                                                      metadata_anchor_fd) != 0;
    if (close(metadata_anchor_fd) != 0)
        anchor_failed = 1;
    if (anchor_failed)
    {
        print_error("Error: Failed to inspect restore destination for %s\n", label);
        return RESTORE_NATIVE_ERROR;
    }
    return restore_native_metadata_inventory_at(ctx, source_root_fd, source_rel,
                                                destination_root_fd,
                                                destination_rel, profiles,
                                                estimate);
}

static RestoreNativeStatus restore_legacy_metadata_inventory(
    const char *source, int source_root_fd, const char *home, int home_fd,
    const CloneContext *ctx, MetadataProfiles *profiles,
    RestoreTimestampAnchors *timestamp_anchors,
    NativeRestoreEstimate *estimate)
{
    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                    XDG_RESTORE_COUNT) != 0)
    {
        free_xdg_dirs(xdg_dirs);
        print_error("Error: HOME path too long to resolve user directories\n");
        return RESTORE_NATIVE_ERROR;
    }

    char *manifest_names[XDG_RESTORE_COUNT] = {0};
    (void)legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT);
    int failed = 0;
    RestoreNativeStatus result = RESTORE_NATIVE_OK;
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        const char *name = legacy_xdg_source_name(manifest_names, xdg_dirs, i);

        /* Legacy XDG roots are optional. Inspect the source first so a
         * missing source does not make an otherwise irrelevant destination
         * path fatal (the restore path has always skipped such roots). */
        RestoreSourceStatus source_status =
            restore_native_source_status_at(source_root_fd, name);
        if (source_status == RESTORE_SOURCE_MISSING)
            continue;
        if (source_status == RESTORE_SOURCE_ERROR)
        {
            print_error("Error: Failed to inspect %s\n", name);
            failed = 1;
            continue;
        }

        int destination_fd = -1;
        char destination_rel[PATH_MAX];
        if (open_xdg_destination_anchor(xdg_dirs[i], &destination_fd,
                                         destination_rel,
                                         sizeof(destination_rel)) != 0)
        {
            print_error("Error: Failed to resolve restore destination %s\n",
                   xdg_dirs[i]);
            failed = 1;
            continue;
        }
        RestoreNativeStatus item_status = restore_metadata_item(
            ctx, source_root_fd, name, destination_fd, destination_rel, name,
            0, profiles, timestamp_anchors, estimate);
        if (item_status != RESTORE_NATIVE_OK)
        {
            failed = 1;
            if (item_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                result = RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (close(destination_fd) != 0)
            failed = 1;
    }

    for (int i = 0; i < LEGACY_HOME_ITEM_COUNT; i++)
    {
        const char *name = LEGACY_HOME_ITEMS[i].name;
        RestoreNativeStatus item_status = restore_metadata_item(
            ctx, source_root_fd, name, home_fd, name, name, 0, profiles,
            timestamp_anchors, estimate);
        if (item_status != RESTORE_NATIVE_OK)
        {
            failed = 1;
            if (item_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                result = RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);
    free_xdg_dirs(xdg_dirs);
    return result != RESTORE_NATIVE_OK
        ? result : (failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK);
}

static RestoreNativeStatus restore_v1_metadata_inventory(
    int source_root_fd, const Manifest *m, const RestoreTargetMap *target_map,
    const CloneContext *ctx, MetadataProfiles *profiles,
    RestoreTimestampAnchors *timestamp_anchors,
    NativeRestoreEstimate *estimate)
{
    int failed = 0;
    RestoreNativeStatus result = RESTORE_NATIVE_OK;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue;

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            print_error("Error: Manifest root %s has an invalid payload address\n",
                   root->id);
            failed = 1;
            continue;
        }

        const RestoreTargetRoot *destination = &target_map->roots[i];
        RestoreNativeStatus item_status = restore_metadata_item(
            ctx, source_root_fd, source_rel, destination->route.anchor_fd,
            destination->route.relative, root->id, 1, profiles,
            timestamp_anchors,
            estimate);
        if (item_status != RESTORE_NATIVE_OK)
        {
            failed = 1;
            if (item_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                result = RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
    }

    return result != RESTORE_NATIVE_OK
        ? result : (failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK);
}

// Restores a valid native v1 manifest's root table (docs/DECISIONS.md D15,
// D16). HOME_RELATIVE roots restore beneath home, XDG roots map to the target
// locale, and MANUAL_NATIVE roots are reported without being auto-restored.
static void restore_v1(const char *source, int source_root_fd,
                       const CloneContext *ctx, const Manifest *m,
                       const RestoreTargetMap *target_map, int *count,
                       int *had_error,
                       const RestoreTimestampAnchors *timestamp_anchors,
                       size_t *skipped_security_xattrs,
                       BackupCaptureReport *capture_report,
                       const int *root_order)
{
    printf("Roots\n");

    for (int i = 0; i < m->root_count; i++)
    {
        int root_index = root_order == NULL ? i : root_order[i];
        const ManifestRoot *root = &m->roots[root_index];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue; // reported separately below; never auto-restored

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            print_error("Error: Failed to restore %s\n", root->id);
            *had_error = 1;
            continue;
        }

        const RestoreTargetRoot *destination = &target_map->roots[root_index];

        int rc = restore_item_at(ctx, source_root_fd, source_rel,
                                 destination->route.anchor_fd,
                                 destination->route.relative, root->id, 1,
                                 timestamp_anchors,
                                 skipped_security_xattrs, capture_report);
        if (rc > 0 && dry_run)
        {
            if (root->policy == ROOT_POLICY_HOME_RELATIVE)
            {
                if (root->restore_path[0] != '\0')
                    printf("  Would restore: %s -> ~/%s\n", root->id,
                           root->restore_path);
                else
                    printf("  Would restore: %s -> ~\n", root->id);
            }
            else
            {
                printf("  Would restore: %s -> %s/\n", root->id,
                       destination->absolute);
            }
        }
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
    }

    int manual_count = 0;
    for (int i = 0; i < m->root_count; i++)
        if (m->roots[i].policy == ROOT_POLICY_MANUAL_NATIVE)
            manual_count++;

    if (manual_count > 0)
    {
        printf("\nManual Roots\n");
        printf("  Not restored automatically; recover these from the backup directly.\n");
        for (int i = 0; i < m->root_count; i++)
        {
            const ManifestRoot *root = &m->roots[i];
            if (root->policy != ROOT_POLICY_MANUAL_NATIVE)
                continue;

            char source_rel[PATH_MAX + 8];
            if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
            {
                print_error("Error: Manifest root %s has an invalid payload address\n",
                       root->id);
                *had_error = 1;
                continue;
            }
            RestoreSourceStatus status =
                restore_native_source_status_at(source_root_fd, source_rel);
            if (status != RESTORE_SOURCE_PRESENT)
            {
                print_error("Error: Manifest root %s no longer has a readable payload\n",
                       root->id);
                *had_error = 1;
                continue;
            }

            printf("  %s\n", root->id);
            printf("    recorded source: %s\n", root->source_path);
            printf("    backup location: %s/data/%s\n", source, root->payload_path);
        }
    }
}

int restore(const char *source)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        print_error("Error: Could not get HOME directory.\n");
        return 1;
    }

    struct stat st;
    if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        print_error("Error: Source directory not found: %s\n", source);
        return 1;
    }

    // A live or abandoned ".partial" container (docs/DECISIONS.md D15) is
    // never a valid restore source: an interrupted backup may be incomplete,
    // and a still-active one may be locked by another process. Trailing
    // slashes are stripped first so they cannot hide the leaf name.
    char source_copy[PATH_MAX];
    if ((size_t)snprintf(source_copy, sizeof(source_copy), "%s", source) >= sizeof(source_copy))
    {
        print_error("Error: Source path too long: %s\n", source);
        return 1;
    }
    size_t source_len = strlen(source_copy);
    while (source_len > 1 && source_copy[source_len - 1] == '/')
        source_copy[--source_len] = '\0';
    const char *source_leaf = strrchr(source_copy, '/');
    source_leaf = source_leaf ? source_leaf + 1 : source_copy;
    if (container_name_is_partial(source_leaf))
    {
        print_error("Error: %s is an in-progress or abandoned backup container, not a finished one.\n", source);
        return 1;
    }
    int source_is_versioned_final = container_name_is_final(source_leaf);

    int source_root_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_root_fd < 0)
    {
        print_error("Error: Could not open source directory: %s\n", source);
        return 1;
    }

    // Classified before any confirmation or filesystem mutation: an unknown
    // version or malformed manifest refuses the whole restore outright,
    // rather than guessing or partially proceeding.
    Manifest m;
    ManifestStatus mst = manifest_read_v1_at(source_root_fd, &m);
    if (mst == MANIFEST_STATUS_UNKNOWN_VERSION)
    {
        print_error("Error: manifest.txt records a format version this build does not understand; refusing to guess.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_MALFORMED)
    {
        print_error("Error: manifest.txt is malformed; refusing to restore.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_IO_ERROR)
    {
        print_error("Error: Could not read manifest.txt.\n");
        close(source_root_fd);
        return 1;
    }
    // mst is now MISSING, LEGACY, or VALID.

    if (source_is_versioned_final && mst == MANIFEST_STATUS_MISSING)
    {
        print_error("Error: A finalized versioned container is missing manifest.txt; refusing to treat it as a legacy backup.\n");
        close(source_root_fd);
        return 1;
    }
    if (source_is_versioned_final && mst == MANIFEST_STATUS_LEGACY)
    {
        print_error("Error: A finalized versioned container carries a legacy manifest; refusing to guess its layout.\n");
        close(source_root_fd);
        return 1;
    }
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0)
    {
        if (errno == ENAMETOOLONG)
            print_error("Error: HOME path too long to resolve user directories\n");
        else
            print_error("Error: Could not open home directory: %s\n", home);
        if (mst == MANIFEST_STATUS_VALID)
            manifest_free(&m);
        close(source_root_fd);
        return 1;
    }

    if (mst == MANIFEST_STATUS_VALID &&
        m.representation == CLONE_PORTABLE_SIDECAR)
    {
        char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
        int has_xdg_root = 0;
        for (int index = 0; index < m.root_count; index++)
            if (m.roots[index].policy == ROOT_POLICY_XDG)
            {
                has_xdg_root = 1;
                break;
            }
        if (has_xdg_root &&
            xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                        XDG_RESTORE_COUNT) != 0)
        {
            print_error("Error: HOME path too long to resolve user directories\n");
            free_xdg_dirs(xdg_dirs);
            manifest_free(&m);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }

        PortableRestoreRequest request = {
            .source_container_fd = source_root_fd,
            .manifest = &m,
            .destination_home_fd = home_fd,
            .destination_home_path = home,
            .destination_timestamp_policy = {0}
        };
        for (int index = 0; index < XDG_RESTORE_COUNT; index++)
            request.destination_xdg_dirs[index] = xdg_dirs[index];
        BackupCaptureReport capture_report;
        backup_capture_report_init(&capture_report);
        capture_report.sync_interval_bytes = BACKUP_SYNC_INTERVAL_BYTES;
        RestoreProgressDisplay progress_display = {0};
        if (!dry_run && isatty(fileno(stdout)))
        {
            capture_report.progress_cb = restore_report_progress;
            capture_report.progress_userdata = &progress_display;
        }
        request.capture_report = &capture_report;
        PortableRestoreReplayReport report;
        PortableRestoreOutcome outcome =
            portable_restore_orchestrate_at(&request, &report);

        int had_portable_error = 0;
        if (outcome == PORTABLE_RESTORE_COMPLETE)
        {
            // Packages are published only after a fully successful replay.
            restore_packages(source_root_fd, home, &had_portable_error);
            if (m.has_network_config)
                restore_network_config(source_root_fd, &had_portable_error);
        }
        else if (outcome == PORTABLE_RESTORE_DRY_RUN &&
                 m.has_network_config)
            restore_network_config(source_root_fd, &had_portable_error);

        if (progress_display.printed_anything)
        {
            capture_report.progress_cb(capture_report.bytes_copied,
                                       capture_report.current_path,
                                       capture_report.progress_userdata);
            putchar('\n');
            fflush(stdout);
        }
        printf("\n");
        switch (outcome)
        {
            case PORTABLE_RESTORE_COMPLETE:
            {
                char item_phrase[64];
                format_item_count_phrase(item_phrase, sizeof(item_phrase),
                                         report.applied_count, "restored");
                if (had_portable_error)
                    printf("Restore finished with errors: %s, an optional restore step failed\n",
                           item_phrase);
                else
                    print_success("Restore complete: %s\n", item_phrase);
                break;
            }
            case PORTABLE_RESTORE_DRY_RUN:
            {
                char item_phrase[64];
                format_item_count_phrase(item_phrase, sizeof(item_phrase),
                                         report.live_count,
                                         "would be restored");
                if (had_portable_error)
                    printf("Dry run finished with errors: %s, an optional restore step failed\n",
                           item_phrase);
                else
                    printf("Dry run complete: %s\n", item_phrase);
                break;
            }
            case PORTABLE_RESTORE_CANCELLED:
                printf("Cancelled.\n");
                break;
            case PORTABLE_RESTORE_ERROR:
            default:
                printf("Restore finished with errors: %zu applied, %zu failed\n",
                       report.applied_count, report.failed_count);
                break;
        }
        if (report.skipped_security_xattr_count != 0)
            printf("Skipped %zu security.* attribute(s) that the destination "
                   "could not apply.\n",
                   report.skipped_security_xattr_count);
        free_xdg_dirs(xdg_dirs);
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return (outcome == PORTABLE_RESTORE_ERROR || had_portable_error) ? 1 : 0;
    }

    if (mst == MANIFEST_STATUS_VALID &&
        validate_v1_payloads(source_root_fd, &m) != 0)
    {
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return 1;
    }

    RestoreTargetMap target_map = {0};
    if (mst == MANIFEST_STATUS_VALID &&
        restore_target_map_build(source_root_fd, home, home_fd, &m,
                                 &target_map) != 0)
    {
        restore_target_map_free(&target_map);
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return 1;
    }

    CloneContext ctx = {
        .operation = CLONE_RESTORE,
        .representation = CLONE_NATIVE_TREE
    };
    BackupCaptureReport capture_report;
    backup_capture_report_init(&capture_report);
    capture_report.sync_interval_bytes = BACKUP_SYNC_INTERVAL_BYTES;
    NativeRestoreEstimate restore_estimate;
    native_restore_estimate_init(&restore_estimate);
    MetadataProfiles metadata_profiles;
    metadata_profiles_init(&metadata_profiles);
    RestoreTimestampAnchors timestamp_anchors;
    restore_timestamp_anchors_init(&timestamp_anchors);
    int result = 1;

    RestoreNativeStatus metadata_inventory_status;
    if (mst == MANIFEST_STATUS_VALID)
        metadata_inventory_status = restore_v1_metadata_inventory(
            source_root_fd, &m, &target_map, &ctx, &metadata_profiles,
            &timestamp_anchors, &restore_estimate);
    else
        metadata_inventory_status = restore_legacy_metadata_inventory(
            source, source_root_fd, home, home_fd, &ctx, &metadata_profiles,
            &timestamp_anchors, &restore_estimate);
    if (metadata_inventory_status != RESTORE_NATIVE_OK)
    {
        if (metadata_inventory_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
            report_source_safe_read_refusal("native restore payload", NULL);
        else
            print_error("Error: native metadata preflight failed; no destination was changed\n");
        native_restore_estimate_free(&restore_estimate);
        goto cleanup;
    }
    int space_refused = restore_space_preflight(
        home_fd, home, restore_estimate.estimated_bytes,
        restore_estimate.had_error) != 0;
    native_restore_estimate_free(&restore_estimate);
    if (space_refused)
        goto cleanup;
    metadata_profiles_report(&metadata_profiles);

    if (dry_run)
    {
        printf("Dry run mode enabled. No changes will be made.\n\n");
        native_restore_security_dry_run_notice(
            metadata_profiles.security_xattr_entry_count);
    }
    else if (!native_restore_confirm(
                 metadata_profiles.security_xattr_entry_count))
    {
        printf("Cancelled.\n");
        result = 0;
        goto cleanup;
    }

    printf("Restoring from: %s\n\n", source);

    int count = 0;
    int had_error = 0;
    size_t skipped_security_xattrs = 0;

    if (!dry_run)
    {
        if (restore_timestamp_anchor_probe(&timestamp_anchors) != 0)
        {
            print_error("Error: native timestamp preflight failed; no destination was changed\n");
            goto cleanup;
        }
        // ctx's own timestamp_policy_configured/nsec_exact are never read for
        // an actual apply: restore_item_at() always builds its own
        // per-destination-anchor copy from timestamp_anchors before using it.
        if (metadata_profiles_probe(&metadata_profiles,
                                    (MetadataTimestampPolicy){
                                        .nsec_exact = 0,
                                        .configured = 1
                                    }) != 0)
        {
            print_error("Error: native metadata preflight failed; no destination was changed\n");
            goto cleanup;
        }
        ctx.metadata_preflight_done = 1;
        ctx.inode_map = native_inode_map_create();
        if (ctx.inode_map == NULL)
        {
            print_error("Error: Could not initialize native hardlink restore tracking\n");
            goto cleanup;
        }

        int seed_status = mst == MANIFEST_STATUS_VALID
            ? seed_native_restore_v1_hardlink_map(
                  source, source_root_fd, &m, &target_map, &ctx,
                  &timestamp_anchors)
            : seed_native_restore_legacy_hardlink_map(
                  source, source_root_fd, home, home_fd, &ctx,
                  &timestamp_anchors);
        if (seed_status != 0)
        {
            print_error("Error: Could not seed native hardlink restore tracking\n");
            goto cleanup;
        }
    }

    RestoreProgressDisplay progress_display = {0};
    if (!dry_run && isatty(fileno(stdout)))
    {
        capture_report.progress_cb = restore_report_progress;
        capture_report.progress_userdata = &progress_display;
    }

    if (mst == MANIFEST_STATUS_VALID)
    {
        restore_v1(source, source_root_fd, &ctx, &m, &target_map, &count,
                   &had_error, &timestamp_anchors,
                   &skipped_security_xattrs, &capture_report,
                   target_map.order);
    }
    else
    {
        if (restore_legacy(source, source_root_fd, home, home_fd, &ctx,
                           &count, &had_error, &timestamp_anchors,
                           &skipped_security_xattrs, &capture_report) != 0)
            goto cleanup;
    }

    if (progress_display.printed_anything)
    {
        capture_report.progress_cb(capture_report.bytes_copied,
                                   capture_report.current_path,
                                   capture_report.progress_userdata);
        putchar('\n');
        fflush(stdout);
    }

    native_inode_map_free(ctx.inode_map);
    ctx.inode_map = NULL;

    restore_packages(source_root_fd, home, &had_error);
    if (mst == MANIFEST_STATUS_VALID && m.has_network_config)
        restore_network_config(source_root_fd, &had_error);

    printf("\n");
    char item_phrase[64];
    format_item_count_phrase(item_phrase, sizeof(item_phrase), (size_t)count,
                             dry_run ? "would be restored" : "restored");
    if (dry_run && had_error)
        printf("Dry run finished with errors: %s, some items failed validation\n",
               item_phrase);
    else if (dry_run)
        printf("Dry run complete: %s\n", item_phrase);
    else if (had_error)
        printf("Restore finished with errors: %s, some items failed\n",
               item_phrase);
    else
        print_success("Restore complete: %s\n", item_phrase);
    if (skipped_security_xattrs != 0)
        printf("Skipped %zu security.* attribute(s) that the destination "
               "could not apply.\n", skipped_security_xattrs);
    result = had_error ? 1 : 0;

cleanup:
    native_inode_map_free(ctx.inode_map);
    ctx.inode_map = NULL;
    metadata_profiles_free(&metadata_profiles);
    restore_timestamp_anchors_free(&timestamp_anchors);
    if (restore_target_map_free(&target_map) != 0)
        result = 1;
    manifest_free(&m);
    close(home_fd);
    close(source_root_fd);
    return result;
}
