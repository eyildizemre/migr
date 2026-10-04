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
#include <pwd.h>
#include <unistd.h>

#include "restore.h"
#include "backup.h"
#include "console.h"
#include "container.h"
#include "dconf_restore.h"
#include "detect.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "metadata.h"
#include "packages.h"
#include "podman_state.h"
#include "groups.h"
#include "home_rewrite.h"
#include "flatpak.h"
#include "portable.h"
#include "portable_restore.h"
#include "portable_restore_internal.h"
#include "portable_restore_replay_internal.h"
#include "utils.h"
#include "writer_apps.h"
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
    /* Written regardless of the backup's mode, which a portable container on
     * exFAT/NTFS/FAT reports as 0755: NetworkManager refuses keyfiles that are
     * not 0600, and every backend but networkd stores secrets in these files.
     * networkd reads its configuration as the unprivileged systemd-network
     * user, so its files keep the distributions' 0644 (except .netdev, see
     * network_config_file_mode()). */
    mode_t file_mode;
} RestoreNetworkConfigBackend;

static const RestoreNetworkConfigBackend RESTORE_NETWORK_CONFIG_BACKENDS[] = {
    { "NetworkManager", "networkmanager",
      "/etc/NetworkManager/system-connections",
      NETWORK_CONFIG_APPLY_RELOAD, NULL, 0600 },
    { "netplan", "netplan", "/etc/netplan",
      NETWORK_CONFIG_APPLY_MANUAL, "sudo netplan apply", 0600 },
    { "systemd-networkd", "systemd-networkd", "/etc/systemd/network",
      NETWORK_CONFIG_APPLY_MANUAL, "sudo networkctl reload", 0644 },
    { "wpa_supplicant", "wpa_supplicant", "/etc/wpa_supplicant",
      NETWORK_CONFIG_APPLY_MANUAL,
      "sudo systemctl restart wpa_supplicant@<interface> "
      "(replace <interface> with your interface name)", 0600 },
    { "netctl", "netctl", "/etc/netctl",
      NETWORK_CONFIG_APPLY_MANUAL,
      "sudo netctl restart <profile> (replace <profile> with your profile name)",
      0600 },
};

#define NETWORK_CONFIG_BACKEND_COUNT \
    (sizeof(RESTORE_NETWORK_CONFIG_BACKENDS) / \
     sizeof(RESTORE_NETWORK_CONFIG_BACKENDS[0]))

#ifdef RESTORE_TEST_HOOKS
static const char *restore_test_network_config_dest_dirs[NETWORK_CONFIG_BACKEND_COUNT];
static RestoreTestNetworkCommandHook restore_test_network_command_hook;
static void *restore_test_network_command_context;
static int restore_test_progress_force;

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

void restore_test_set_network_command_hook(RestoreTestNetworkCommandHook hook,
                                           void *context)
{
    restore_test_network_command_hook = hook;
    restore_test_network_command_context = context;
}

void restore_test_set_progress_force(int force)
{
    restore_test_progress_force = force != 0;
}
#endif

static const char *network_manager_runtime_dir = "/run/NetworkManager";

#ifdef RESTORE_TEST_HOOKS
void restore_test_set_network_manager_runtime_dir(const char *path)
{
    network_manager_runtime_dir =
        path != NULL ? path : "/run/NetworkManager";
}
#endif

// NetworkManager drives wpa_supplicant over D-Bus with its own profiles, so
// on such a system the files in /etc/wpa_supplicant are not read by anything.
static int network_manager_is_running(void)
{
    struct stat st;
    return lstat(network_manager_runtime_dir, &st) == 0 && S_ISDIR(st.st_mode);
}

static int name_has_suffix(const char *name, const char *suffix)
{
    size_t name_length = strlen(name);
    size_t suffix_length = strlen(suffix);
    return name_length > suffix_length &&
           strcmp(name + name_length - suffix_length, suffix) == 0;
}

// networkd reads its configuration as the unprivileged systemd-network user.
// .netdev files can hold WireGuard private keys, so systemd recommends 0640
// with group systemd-network for them; other files stay 0644.
static mode_t network_config_file_mode(
    const RestoreNetworkConfigBackend *backend, const char *name,
    gid_t *group_out)
{
    *group_out = (gid_t)-1;
    if (strcmp(backend->name, "systemd-networkd") == 0 &&
        name_has_suffix(name, ".netdev"))
    {
        gid_t group;
        if (local_group_gid("systemd-network", &group) == 0)
            *group_out = group;
        return 0640;
    }
    return backend->file_mode;
}

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

// Runs a command the network restore applies its files with. Its output is
// not shown: migr reports what the command did.
static int run_network_command(char *const argv[])
{
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_network_command_hook != NULL)
        return restore_test_network_command_hook(
            argv, restore_test_network_command_context);
#endif
    char output[1024];
    return run_command_capture(argv, output, sizeof(output));
}

static int run_network_config_reload(void)
{
    char *const reload_argv[] = {
        "nmcli", "connection", "reload", NULL
    };
    return run_network_command(reload_argv);
}

// How long restore waits for a network before packages, checking once a
// second (D90).
#define NETWORK_WAIT_SECONDS 90
static long network_wait_interval_ms = 1000;

#ifdef RESTORE_TEST_HOOKS
static RestoreTestNetworkQueryHook restore_test_network_query_hook;
static void *restore_test_network_query_context;

void restore_test_set_network_query_hook(RestoreTestNetworkQueryHook hook,
                                         void *context, long interval_ms)
{
    restore_test_network_query_hook = hook;
    restore_test_network_query_context = context;
    network_wait_interval_ms = hook != NULL ? interval_ms : 1000;
}
#endif

// Runs an nmcli query of the wait for a network into output.
static int network_query(char *const argv[], char *output, size_t size)
{
    output[0] = '\0';
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_network_query_hook != NULL)
        return restore_test_network_query_hook(
            argv, output, size, restore_test_network_query_context);
#endif
    return run_command_capture(argv, output, size);
}

// NetworkManager's state is "connected" once its connectivity check fetched
// the distribution's test file, or, with that check turned off, once a
// default route exists.
static int network_online(void)
{
    char *const query[] = { "nmcli", "-t", "-f", "STATE", "general", NULL };
    char state[64];
    return network_query(query, state, sizeof(state)) == 0 &&
           strcmp(state, "connected\n") == 0;
}

// Copies the next field of a line of nmcli's terse output, where ':' ends a
// field and a backslash escapes ':' and '\' in values. Returns where the
// following field starts, or NULL after the line's last field.
static const char *network_terse_field(const char *line, char *out,
                                       size_t size)
{
    size_t used = 0;
    for (; *line != '\0' && *line != '\n' && *line != ':'; line++)
    {
        if (*line == '\\' && line[1] != '\0' && line[1] != '\n')
            line++;
        if (used + 1U < size)
            out[used++] = *line;
    }
    out[used] = '\0';
    return *line == ':' ? line + 1 : NULL;
}

// From the NAME:TYPE:STATE lines of the active connections: the profile
// being activated and the first one activated, loopback aside; "" for none.
static void network_parse_connections(const char *list, char *activating,
                                      char *activated, size_t size)
{
    activating[0] = activated[0] = '\0';
    for (const char *line = list; *line != '\0';)
    {
        char name[256], type[64], state[64];
        const char *next = network_terse_field(line, name, sizeof(name));
        next = next != NULL ? network_terse_field(next, type, sizeof(type))
                            : NULL;
        if (next != NULL)
        {
            (void)network_terse_field(next, state, sizeof(state));
            char *target = strcmp(state, "activating") == 0 ? activating
                : strcmp(state, "activated") == 0 &&
                          strcmp(type, "loopback") != 0 ? activated
                : NULL;
            if (target != NULL && target[0] == '\0')
                snprintf(target, size, "%s", name);
        }
        line = strchrnul(line, '\n');
        if (*line == '\n')
            line++;
    }
}

static void network_connections(char *activating, char *activated,
                                size_t size)
{
    char *const query[] = { "nmcli", "-t", "-f", "NAME,TYPE,STATE",
                            "connection", "show", "--active", NULL };
    char list[4096];
    if (network_query(query, list, sizeof(list)) != 0)
        list[0] = '\0';
    network_parse_connections(list, activating, activated, size);
}

// Packages and Flatpak applications come from the network. Right before them,
// NetworkManager gets time to bring up a profile, restored or the installer's,
// and the user sees which one it is trying (D90). Returns 0 when the system
// stayed offline; without NetworkManager there is nothing to ask, and the
// install is tried.
static int restore_wait_for_network(int source_root_fd)
{
    if (dry_run || !network_manager_is_running() ||
        (faccessat(source_root_fd, "packages.txt", F_OK,
                   AT_SYMLINK_NOFOLLOW) != 0 &&
         faccessat(source_root_fd, "flatpak-apps.txt", F_OK,
                   AT_SYMLINK_NOFOLLOW) != 0))
        return 1;
    // A fresh check, rather than one NetworkManager made minutes ago.
    char *const check[] = { "nmcli", "networking", "connectivity", "check",
                            NULL };
    char ignored[64];
    (void)network_query(check, ignored, sizeof(ignored));
    if (network_online())
        return 1;

    printf("\nNetwork\n");
    char shown[256] = "", activating[256], activated[256];
    int waiting_shown = 0;
    for (long waited = 0; waited < NETWORK_WAIT_SECONDS * 1000L;
         waited += 1000L)
    {
        network_connections(activating, activated, sizeof(activating));
        if (activating[0] != '\0' && strcmp(activating, shown) != 0)
        {
            printf("  Connecting to %s...\n", activating);
            snprintf(shown, sizeof(shown), "%s", activating);
        }
        else if (activating[0] == '\0' && shown[0] == '\0' && !waiting_shown)
        {
            printf("  Waiting for a network connection...\n");
            waiting_shown = 1;
        }
        fflush(stdout);
        struct timespec delay = { network_wait_interval_ms / 1000L,
                                  (network_wait_interval_ms % 1000L) *
                                      1000000L };
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
            ;
        if (network_online())
        {
            network_connections(activating, activated, sizeof(activated));
            if (activated[0] != '\0')
                printf("  Connected to %s.\n", activated);
            else
                printf("  Connected.\n");
            return 1;
        }
    }
    printf("  No network connection after %d seconds. Packages and Flatpak "
           "applications are listed at the end, to install once this system "
           "is online.\n", NETWORK_WAIT_SECONDS);
    return 0;
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

int restore_network_config_would_write(int source_root_fd)
{
    int network_fd = openat(source_root_fd, "network",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (network_fd < 0)
        return errno == ENOENT ? 0 : 1;

    for (size_t i = 0; i < NETWORK_CONFIG_BACKEND_COUNT; i++)
    {
        int backend_fd = openat(network_fd,
                                RESTORE_NETWORK_CONFIG_BACKENDS[i].container_subdir,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (backend_fd < 0)
        {
            if (errno == ENOENT)
                continue;
            (void)close(network_fd);
            return 1;
        }

        DIR *dir = fdopendir(backend_fd);
        if (dir == NULL)
        {
            (void)close(backend_fd);
            (void)close(network_fd);
            return 1;
        }

        size_t regular_count = 0;
        int count_result = network_config_regular_count(dir, &regular_count);
        int close_result = closedir(dir);
        if (count_result != 0 || close_result != 0)
        {
            (void)close(network_fd);
            return 1;
        }
        if (regular_count != 0)
        {
            (void)close(network_fd);
            return 1;
        }
    }

    return close(network_fd) == 0 ? 0 : 1;
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
                                          const char *name, mode_t file_mode,
                                          gid_t file_group)
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

    int dest_fd = openat(dest_dir_fd, name,
                         O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK |
                         O_NOFOLLOW | O_CLOEXEC,
                         file_mode);
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
    // Only root can hand the file to another group; without that the mode
    // alone still keeps the secret from other users.
    if (!failed && file_group != (gid_t)-1 && geteuid() == 0 &&
        fchown(dest_fd, (uid_t)-1, file_group) != 0)
    {
        saved_errno = errno;
        failed = 1;
    }
    if (!failed && fchmod(dest_fd, file_mode) != 0)
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

// Where restore reads the restoring user's subordinate IDs (D93).
static const char *restore_subuid_path = "/etc/subuid";
static const char *restore_subgid_path = "/etc/subgid";

#ifdef RESTORE_TEST_HOOKS
void restore_test_set_subid_files(const char *subuid, const char *subgid)
{
    restore_subuid_path = subuid != NULL ? subuid : "/etc/subuid";
    restore_subgid_path = subgid != NULL ? subgid : "/etc/subgid";
}
#endif

// The backup's user, as its manifest records it, becomes the user this
// restore acts for, the sudo invoker as elsewhere (D38): a new system may
// give the same person another uid (D85). Without a recorded source user,
// owners stay as recorded.
static OwnerMap restore_owner_map(const Manifest *m)
{
    OwnerMap map = {0};
    uid_t uid = geteuid();
    gid_t gid = getegid();
    if (!m->has_source_identity || sudo_invoker(&uid, &gid, NULL) < 0)
        return map;
    map.map_uid = 1;
    map.from_uid = m->source_uid;
    map.to_uid = uid;
    map.map_gid = m->has_source_gid;
    map.from_gid = m->source_gid;
    map.to_gid = gid;
    // Rootless containers' files move from the backup user's subordinate
    // IDs to the restoring user's (D93). Without the new system's, they
    // keep the recorded IDs, and restore says so at the end.
    map.from_subuids = m->source_subuids;
    map.from_subgids = m->source_subgids;
    if (m->source_subuids.count == 0 && m->source_subgids.count == 0)
        return map;
    struct passwd *user = getpwuid(uid);
    const char *name = user != NULL ? user->pw_name : NULL;
    if (subid_ranges_read(restore_subuid_path, name, uid,
                          &map.to_subuids) != 0 ||
        subid_ranges_read(restore_subgid_path, name, uid,
                          &map.to_subgids) != 0)
        print_warning("Warning: Could not read /etc/subuid or /etc/subgid; "
                      "files of rootless containers keep the IDs the "
                      "backup recorded.\n");
    return map;
}

// Says what the old system's rootless containers need when this one gives
// the user fewer subordinate IDs (D93).
static void restore_subid_todo(const OwnerMap *map, FILE *todo)
{
    uint64_t uids = subid_ranges_total(&map->from_subuids);
    uint64_t gids = subid_ranges_total(&map->from_subgids);
    if (todo == NULL || (subid_ranges_total(&map->to_subuids) >= uids &&
                         subid_ranges_total(&map->to_subgids) >= gids))
        return;
    fprintf(todo, "  Rootless containers (Podman, Toolbox): this system gives "
                  "you fewer subordinate IDs than the old one (/etc/subuid, "
                  "/etc/subgid), so files of container users beyond them "
                  "keep the old system's IDs. Give yourself %llu of each with "
                  "sudo usermod --add-subuids and --add-subgids, then pull "
                  "those images again.\n",
            (unsigned long long)(uids > gids ? uids : gids));
}

// What a restore leaves for the user to do by hand: written by the steps
// that re-create system state, shown at the very end of the run, and kept
// next to the backup.
typedef struct {
    char *text;
    size_t size;
    FILE *stream;
    /* The packages it could not install, kept apart: from another
     * distribution they can run to hundreds of names. */
    char *packages_text;
    size_t packages_size;
    FILE *packages;
    int package_count;
    int written; /* The steps ran, so the list next to the backup is due. */
} RestoreTodo;

// More package names than this are left to the list next to the backup.
#define TODO_PACKAGES_SHOWN 10

// Re-creates the system state the backup lists, after its files and network
// configuration: packages first, since they bring Flatpak and groups along.
static void restore_system_lists(int source_root_fd, RestoreTodo *todo,
                                 int *had_error)
{
    todo->stream = open_memstream(&todo->text, &todo->size);
    todo->packages = open_memstream(&todo->packages_text,
                                    &todo->packages_size);
    if (todo->stream == NULL || todo->packages == NULL)
    {
        print_error("Error: Could not collect what is left to do by hand\n");
        *had_error = 1;
        return;
    }
    todo->written = !dry_run;
    int online = restore_wait_for_network(source_root_fd);
    todo->package_count = restore_packages(source_root_fd, online,
                                           todo->packages, had_error);
    restore_flatpak_apps(source_root_fd, online, todo->stream, had_error);
    uid_t uid;
    char user[ACCOUNT_NAME_MAX];
    int resolved = writer_apps_session_uid(&uid) == 0 &&
                   local_account_name(uid, user) == 0;
    restore_groups(source_root_fd, resolved ? user : NULL, todo->stream,
                   had_error);
}

// Saved passwords and sign-ins, encrypted with the login password (D87).
static const char login_keyring[] = ".local/share/keyrings/login.keyring";

// The login keyring in home as it is now; st_ino is 0 when there is none.
static void login_keyring_stat(int home_fd, struct stat *st)
{
    if (fstatat(home_fd, login_keyring, st, AT_SYMLINK_NOFOLLOW) != 0)
        memset(st, 0, sizeof(*st));
}

// A restore that replaced the login keyring leaves the running session with
// the one it replaced, so that session saves no new passwords; and the new
// one opens with the old system's password until it is typed once (D87).
static void restore_login_keyring_todo(int home_fd, const struct stat *before,
                                       FILE *todo)
{
    struct stat after;
    login_keyring_stat(home_fd, &after);
    if (todo == NULL || after.st_ino == 0 ||
        (after.st_dev == before->st_dev && after.st_ino == before->st_ino &&
         after.st_ctim.tv_sec == before->st_ctim.tv_sec &&
         after.st_ctim.tv_nsec == before->st_ctim.tv_nsec))
        return;
    static const char old_password[] =
        "If your password differs from the old system's, the first app that "
        "needs the keyring asks for the old one once.";
    // On a text console no session runs, and the next login opens it (D89).
    if (console_restore_service())
        fprintf(todo, "  %s\n", old_password);
    else
        fprintf(todo, "  Log out and back in before you sign in anywhere: "
                "until then, this session cannot save passwords to the "
                "restored login keyring. %s\n", old_password);
}

// Replaces <backup>-todo.txt next to the backup with text, or removes it
// when text is empty; the drive is what the user carries, and the backup
// itself stays unchanged. Returns 0, or -1 with errno.
static int restore_todo_write(const char *source, const char *text,
                              char path[PATH_MAX])
{
    char backup[PATH_MAX];
    if (realpath(source, backup) == NULL)
        return -1;
    char *slash = strrchr(backup, '/');
    if (slash == NULL || slash[1] == '\0' ||
        snprintf(path, PATH_MAX, "%s-todo.txt", backup) >= PATH_MAX)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (unlink(path) != 0 && errno != ENOENT)
        return -1;
    if (text[0] == '\0')
        return 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0644);
    if (fd < 0)
        return -1;
    uid_t uid;
    gid_t gid;
    if (sudo_invoker(&uid, &gid, NULL) == 1)
        (void)fchown(fd, uid, gid);
    FILE *out = fdopen(fd, "w");
    if (out == NULL)
    {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    int failed = fputs("What's left for you\n", out) < 0 ||
                 fputs(text, out) < 0;
    int saved = errno;
    if (fclose(out) != 0 && !failed)
    {
        failed = 1;
        saved = errno;
    }
    errno = saved;
    return failed ? -1 : 0;
}

// Ends the run with what is left to do by hand and keeps it next to the
// backup. The steps come first; a long package list stays in the copy next to
// the backup, where it does not push them off the screen.
static void restore_todo_finish(RestoreTodo *todo, const char *source)
{
    int closed = todo->stream != NULL && fclose(todo->stream) == 0 &&
                 todo->text != NULL;
    closed = todo->packages != NULL && fclose(todo->packages) == 0 &&
             todo->packages_text != NULL && closed;
    char *text = NULL;
    if (closed && todo->written &&
        asprintf(&text, "%s%s", todo->text, todo->packages_text) >= 0)
    {
        char path[PATH_MAX] = "";
        int kept = restore_todo_write(source, text, path) == 0;
        int saved = errno;
        if (text[0] != '\0')
        {
            printf("\nWhat's left for you\n%s", todo->text);
            if (kept && todo->package_count > TODO_PACKAGES_SHOWN)
                printf("  %d packages this system does not have; the copy "
                       "of this list names them.\n", todo->package_count);
            else
                printf("%s", todo->packages_text);
        }
        if (!kept)
            print_warning("Warning: could not keep this list next to the "
                          "backup%s%s: %s\n", path[0] != '\0' ? " in " : "",
                          path, strerror(saved));
        else if (text[0] != '\0')
            printf("This list is also in %s\n", path);
    }
    free(text);
    free(todo->text);
    free(todo->packages_text);
}

// What a restore defers for the applications running when it starts (D66,
// D69), and how to retire the progress line before asking about them.
typedef struct {
    RunningWriter writers[WRITER_APPS_MAX]; /* What paths point into. */
    PortableRestoreDeferredPath paths[WRITER_APPS_MAX];
    size_t count;
    void (*retire_progress)(void *context);
    void *progress;
} RestoreDeferral;

// Fills deferral with the settings of every writer application running now.
static void restore_defer_running_writers(RestoreDeferral *deferral)
{
    deferral->count = 0;
    uid_t uid;
    if (writer_apps_session_uid(&uid) != 0)
        return;
    size_t running = writer_apps_running(uid, deferral->writers,
                                         WRITER_APPS_MAX);
    for (size_t index = 0; index < running; index++)
    {
        const RunningWriter *writer = &deferral->writers[index];
        if (writer->settings[0] == '\0')
            continue;
        deferral->paths[deferral->count].label = writer->label;
        deferral->paths[deferral->count].home_relative = writer->settings;
        deferral->count++;
    }
}

// Printed right before the confirmation prompt: an open application that owns
// restored settings writes over them while the restore runs or when it exits.
// When some own settings, those are restored last; otherwise the applications
// can only be named.
static void restore_warn_running_writers(const RestoreDeferral *deferral)
{
    uid_t uid;
    if (writer_apps_session_uid(&uid) != 0)
        return;
    RunningWriter running[WRITER_APPS_MAX];
    const char *labels[WRITER_APPS_MAX];
    size_t count = writer_apps_labels(
        running, writer_apps_running(uid, running, WRITER_APPS_MAX),
        labels);
    if (count == 0)
        return;
    printf("\n");
    writer_apps_print_labels(labels, count);
    if (deferral->count != 0)
        printf(" %s open. The settings %s owns are restored last, after "
               "everything else; close %s before then.\n\n",
               count == 1 ? "is" : "are", count == 1 ? "it" : "each",
               count == 1 ? "it" : "them");
    else
        printf(" %s running and can overwrite restored settings while the "
               "restore runs or when %s. Close %s before continuing.\n\n",
               count == 1 ? "is" : "are",
               count == 1 ? "it closes" : "they close",
               count == 1 ? "it" : "them");
}

// The one question before a restore changes anything (D81).
typedef struct {
    const RestoreDeferral *deferral;
    const char *source;
    int skip_content_verification;
    int handed_over; /* 1 to a text console, -1 when that failed. */
} RestoreConfirmation;

// Asks before the first change. Started from the desktop, the restore
// continues on a text console, and this run only hands it over; that console
// run asks nothing more (D89). Returns 1 to restore here.
static int restore_confirm(void *context)
{
    RestoreConfirmation *confirmation = context;
    if (console_restore_service())
        return 1;
    int vt = console_restore_vt();
    if (vt == 0)
        restore_warn_running_writers(confirmation->deferral);
    else
        printf("The restore runs on a text screen with the desktop closed; "
               "the login screen comes back when it ends.\n");
    if (!confirm_action(
            "This will restore files to your home directory. Continue?"))
        return 0;
    if (vt == 0)
        return 1;
    confirmation->handed_over =
        console_restore_hand_over(vt, confirmation->source,
                                  confirmation->skip_content_verification) == 0
            ? 1 : -1;
    return 0;
}

// Runs once replay reaches the deferred settings (D66). Waiting here costs
// nothing: everything else is already restored. Returns 1 to restore them,
// 0 to leave them out.
static int restore_before_deferred(void *context)
{
    RestoreDeferral *deferral = context;
    if (deferral->retire_progress != NULL)
        deferral->retire_progress(deferral->progress);
    uid_t uid;
    if (writer_apps_session_uid(&uid) != 0)
        return 1;
    for (;;)
    {
        RunningWriter writers[WRITER_APPS_MAX];
        const char *running[WRITER_APPS_MAX];
        size_t running_count = writer_apps_labels(
            writers, writer_apps_running(uid, writers, WRITER_APPS_MAX),
            running);
        const char *open[WRITER_APPS_MAX];
        size_t open_count = 0;
        for (size_t index = 0; index < running_count; index++)
            for (size_t path = 0; path < deferral->count; path++)
                if (strcmp(running[index], deferral->paths[path].label) == 0)
                {
                    open[open_count++] = running[index];
                    break;
                }
        if (open_count == 0)
            return 1;
        printf("\n");
        writer_apps_print_labels(open, open_count);
        printf(" %s still open. Close %s and press Enter to restore %s "
               "settings, type s to leave them out, or c to restore them "
               "anyway: ",
               open_count == 1 ? "is" : "are", open_count == 1 ? "it" : "them",
               open_count == 1 ? "its" : "their");
        fflush(stdout);
        char answer[32];
        if (fgets(answer, sizeof(answer), stdin) == NULL)
        {
            printf("\nNo answer; restoring them now. ");
            writer_apps_print_labels(open, open_count);
            printf(" may overwrite them on closing.\n");
            return 1;
        }
        if (answer[0] == 's' || answer[0] == 'S')
            return 0;
        if (answer[0] == 'c' || answer[0] == 'C')
            return 1;
    }
}

#ifdef RESTORE_TEST_HOOKS
static RestoreTestDconfHook restore_test_dconf_hook;
static void *restore_test_dconf_context;

void restore_test_set_dconf_hook(RestoreTestDconfHook hook, void *context)
{
    restore_test_dconf_hook = hook;
    restore_test_dconf_context = context;
}
#endif

// Loads the backed-up dconf database into a running session, where replacing
// ~/.config/dconf/user alone is overwritten by the dconf service (D50), with
// paths under the backup's home folder naming this system's (D101).
static void restore_dconf_settings(int database_fd, int home_fd,
                                   const Manifest *m, const char *home,
                                   const char *const *xdg_dirs,
                                   int *had_error)
{
    if (database_fd < 0)
        return;
    size_t keys = 0;
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_dconf_hook != NULL)
    {
        restore_test_dconf_hook(database_fd, restore_test_dconf_context);
        return;
    }
#endif
    // The same table failed for the files rewritten before, and was
    // reported there.
    HomeRewritePair pairs[HOME_REWRITE_DCONF_MAX_PAIRS];
    size_t pair_count = 0;
    if (home_rewrite_dconf_pairs_build(m, xdg_dirs, home, pairs,
                                       &pair_count) != 0)
        pair_count = 0;
    DconfRestoreStatus status = dconf_restore_apply(database_fd, home_fd,
                                                    pairs, pair_count, &keys);
    if (status == DCONF_RESTORE_APPLIED && keys != 0)
    {
        printf("\nDesktop settings (dconf)\n");
        printf("  Applied %zu saved setting%s to the running session. Some, "
               "such as enabled GNOME Shell extensions, take effect after "
               "logging out and back in.\n",
               keys, keys == 1 ? "" : "s");
    }
    else if (status == DCONF_RESTORE_FAILED)
    {
        printf("\nDesktop settings (dconf)\n");
        print_warning("  Warning: could not apply the saved settings to the "
                      "running session, which may overwrite them. Log out, "
                      "then run the same restore again from a text console "
                      "(Ctrl+Alt+F3).\n");
        if (had_error != NULL)
            *had_error = 1;
    }
    else if (status == DCONF_RESTORE_HOME_NOT_REWRITTEN)
    {
        print_error("Error: Could not point the desktop settings in "
                    "~/.config/dconf/user at this system's home folder\n");
        if (had_error != NULL)
            *had_error = 1;
    }
}

static const char *crypto_policy_current = "/etc/crypto-policies/config";

#ifdef RESTORE_TEST_HOOKS
void restore_test_set_crypto_policy_current(const char *path)
{
    crypto_policy_current = path != NULL ? path : "/etc/crypto-policies/config";
}
#endif

// Sets the source system's crypto policy, which its saved connections may
// need, such as 802.1X networks that still use TLS 1.0 (D83). A target
// without crypto policies has nothing to set. Like the reload above, a
// failure is a warning with the command to run.
static void restore_crypto_policy(int network_fd)
{
    char saved[CRYPTO_POLICY_MAX], current[CRYPTO_POLICY_MAX];
    if (crypto_policy_read_at(network_fd, "crypto-policy", saved) != 0 ||
        crypto_policy_read_at(AT_FDCWD, crypto_policy_current, current) != 0 ||
        strcmp(saved, current) == 0)
        return;
    printf("\nSystem crypto policy\n");
    if (dry_run)
    {
        printf("  Would set the crypto policy to %s, as on the source system "
               "(this system: %s).\n", saved, current);
        return;
    }
    char *const set_argv[] = {
        "update-crypto-policies", "--set", saved, NULL
    };
    if (run_network_command(set_argv) == 0)
    {
        printf("  Set the crypto policy to %s, as on the source system "
               "(it was %s). Services pick it up when they start, so "
               "restart the computer. To undo: sudo update-crypto-policies "
               "--set %s\n", saved, current, current);
        return;
    }
    print_warning("  Warning: could not set the crypto policy to %s (this "
                  "system: %s). If restored Wi-Fi (802.1X) or VPN connections "
                  "fail to authenticate, run: sudo update-crypto-policies "
                  "--set %s\n", saved, current, saved);
}

// Whether restore_dconf_settings() will load the database into a running
// session, which then settles the settings of an existing ~/.config/dconf/user.
static int restore_dconf_loads_into_session(void)
{
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_dconf_hook != NULL)
        return 1;
#endif
    return dconf_restore_session_loads();
}

// Whether the target user has a running session, whose services rewrite
// live desktop state (D65, D100).
static int restore_session_running(void)
{
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_dconf_hook != NULL)
        return 1;
#endif
    return dconf_restore_session_running();
}

// A native container mirrors each root under data/<payload>, so the dconf
// database of the root captured from HOME/.config is at a fixed place.
static int native_dconf_database_fd(int source_root_fd, const Manifest *m)
{
    for (int index = 0; index < m->root_count; index++)
    {
        const ManifestRoot *root = &m->roots[index];
        if (root->policy != ROOT_POLICY_HOME_RELATIVE ||
            strcmp(root->source_path, ".config") != 0)
            continue;
        char relative[PATH_MAX];
        int length = snprintf(relative, sizeof(relative), "data/%s/dconf/user",
                              root->payload_path);
        if (length < 0 || (size_t)length >= sizeof(relative))
            return -1;
        int fd = openat(source_root_fd, relative,
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat st;
        if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)))
        {
            close(fd);
            fd = -1;
        }
        return fd;
    }
    return -1;
}

#ifdef RESTORE_TEST_HOOKS
static RestoreTestRelabelHook restore_test_relabel_hook;
static void *restore_test_relabel_context;

void restore_test_set_relabel_hook(RestoreTestRelabelHook hook, void *context)
{
    restore_test_relabel_hook = hook;
    restore_test_relabel_context = context;
}
#endif

static int restore_selinux_runs(void)
{
#ifdef RESTORE_TEST_HOOKS
    return restore_test_relabel_hook != NULL;
#else
    return selinux_runs();
#endif
}

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} RelabelList;

static int relabel_list_add(RelabelList *list, const char *path, size_t length)
{
    if (list->capacity - list->length < length + 1U)
    {
        size_t capacity = list->capacity == 0 ? 65536U : list->capacity;
        while (capacity - list->length < length + 1U)
        {
            if (capacity > SIZE_MAX / 2U)
                return -1;
            capacity *= 2U;
        }
        char *data = realloc(list->data, capacity);
        if (data == NULL)
            return -1;
        list->data = data;
        list->capacity = capacity;
    }
    memcpy(list->data + list->length, path, length);
    list->data[list->length + length] = '\0';
    list->length += length + 1U;
    return 0;
}

// Appends root and everything below it on its filesystem, NUL-separated;
// a mount point below root is left out with what is mounted there, and a
// path too long for restorecon is counted in too_long.
// The list is its own queue, so one directory is open at a time, each with
// O_NOATIME: reading a restored folder must not change its access time.
static int relabel_list_tree(RelabelList *list, const char *root,
                             size_t *too_long)
{
    struct stat root_st;
    if (strlen(root) >= PATH_MAX)
    {
        (*too_long)++;
        return 0;
    }
    if (lstat(root, &root_st) != 0)
        return errno == ENOENT ? 0 : -1; // a root with nothing restored
    size_t cursor = list->length;
    if (relabel_list_add(list, root, strlen(root)) != 0)
        return -1;
    while (cursor < list->length)
    {
        char path[PATH_MAX];
        size_t length = strlen(list->data + cursor);
        memcpy(path, list->data + cursor, length + 1U);
        cursor += length + 1U;

        // A program may remove what it wrote since the restore; that is
        // not an error of the relabel.
        struct stat st;
        if (lstat(path, &st) != 0)
        {
            if (errno == ENOENT)
                continue;
            return -1;
        }
        if (!S_ISDIR(st.st_mode))
            continue;
        int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                                O_CLOEXEC);
        if (fd < 0 && errno == ENOENT)
            continue;
        DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
        if (dir == NULL)
        {
            if (fd >= 0)
                close(fd);
            return -1;
        }
        int failed = 0;
        struct dirent *entry;
        while (!failed && (errno = 0, entry = readdir(dir)) != NULL)
        {
            struct stat child_st;
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;
            if (fstatat(dirfd(dir), entry->d_name, &child_st,
                        AT_SYMLINK_NOFOLLOW) != 0)
            {
                failed = errno != ENOENT;
                continue;
            }
            if (child_st.st_dev != root_st.st_dev)
                continue; // a mount point
            char child[PATH_MAX];
            int child_length = snprintf(child, sizeof(child), "%s/%s", path,
                                        entry->d_name);
            if (child_length < 0 || (size_t)child_length >= sizeof(child))
                (*too_long)++;
            else
                failed = relabel_list_add(list, child,
                                          (size_t)child_length) != 0;
        }
        if (!failed && errno != 0)
            failed = 1;
        if (closedir(dir) != 0 || failed)
            return -1;
    }
    return 0;
}

// Restore writes no SELinux label (D92). Where SELinux runs, the restored
// paths get the labels this system's policy sets. migr lists them and
// restorecon labels exactly those, without reading a folder itself; -F sets
// whole labels, also of the types a user may customize. The listing stays on
// each root's filesystem, so a drive mounted below a restored folder, such
// as the backup's own, is not relabelled.
static void restore_selinux_labels(const char *const *paths, size_t count,
                                   int *had_error)
{
    if (dry_run || count == 0 || !restore_selinux_runs())
        return;

    RelabelList list = {0};
    size_t too_long = 0;
    for (size_t index = 0; index < count; index++)
        if (paths[index][0] != '\0' &&
            relabel_list_tree(&list, paths[index], &too_long) != 0)
        {
            print_error("Error: Could not list %s to set its SELinux labels: "
                        "%s\n", paths[index], strerror(errno));
            *had_error = 1;
            free(list.data);
            return;
        }

    if (list.length != 0)
    {
        char *const argv[] = { "restorecon", "-F", "-0", "-f", "-", NULL };
        int status;
#ifdef RESTORE_TEST_HOOKS
        status = restore_test_relabel_hook(argv, list.data, list.length,
                                           restore_test_relabel_context);
#else
        char output[1024];
        RunCommandOptions options = {
            .stdin_data = list.data,
            .stdin_length = list.length
        };
        status = run_command_capture_with(argv, output, sizeof(output),
                                          &options);
#endif
        if (status != 0)
        {
            print_error("Error: Could not set SELinux labels on the restored "
                        "files; restorecon exited with %d\n", status);
            *had_error = 1;
        }
    }
    if (too_long != 0)
        print_warning("Warning: %zu restored path%s too long for restorecon "
                      "keep%s the SELinux label of %s folder.\n", too_long,
                      too_long == 1 ? " is" : "s are",
                      too_long == 1 ? "s" : "", too_long == 1 ? "its" : "their");
    free(list.data);
}

// Labels the roots a versioned backup restored (D92). xdg_dirs are this
// home's user folders, as the restore resolved them.
static void restore_selinux_label_roots(const Manifest *m, const char *home,
                                        const char *const *xdg_dirs,
                                        int *had_error)
{
    if (dry_run || m->root_count <= 0 || !restore_selinux_runs())
        return;
    size_t count = (size_t)m->root_count;
    char (*joined)[PATH_MAX] = calloc(count, sizeof(*joined));
    const char **paths = calloc(count, sizeof(*paths));
    if (joined == NULL || paths == NULL)
    {
        print_error("Error: Could not set SELinux labels on the restored "
                    "files: out of memory\n");
        *had_error = 1;
        free(joined);
        free(paths);
        return;
    }
    size_t used = 0;
    for (size_t index = 0; index < count; index++)
    {
        const ManifestRoot *root = &m->roots[index];
        if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            if (root->restore_path[0] == '\0')
                paths[used++] = home;
            else if (path_join(joined[index], PATH_MAX, home,
                               root->restore_path) == 0)
                paths[used++] = joined[index];
        }
        else if (root->policy == ROOT_POLICY_XDG)
        {
            int key = xdg_key_index(root->id);
            if (key >= 0 && xdg_dirs[key] != NULL)
                paths[used++] = xdg_dirs[key];
        }
    }
    restore_selinux_labels(paths, used, had_error);
    free(paths);
    free(joined);
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

            gid_t file_group;
            mode_t file_mode = network_config_file_mode(backend, entry->d_name,
                                                        &file_group);
            int file_result = restore_network_config_file_at(
                dirfd(dir), dest_dir_fd, entry->d_name, file_mode, file_group);
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
        restore_selinux_labels(&dest_dir, 1, had_error);

        if (backend->apply_mode == NETWORK_CONFIG_APPLY_RELOAD)
            printf("  Restored %zu network connection file%s\n",
                   restored, restored == 1 ? "" : "s");
        if (backend->apply_mode == NETWORK_CONFIG_APPLY_MANUAL &&
            strcmp(backend->name, "wpa_supplicant") == 0 &&
            network_manager_is_running())
        {
            printf("  Restored %zu %s file(s) to %s/. NetworkManager manages "
                   "Wi-Fi on this system and does not read them; they were "
                   "restored for reference and need no restart.\n",
                   restored, backend->name, dest_dir);
        }
        else if (backend->apply_mode == NETWORK_CONFIG_APPLY_MANUAL)
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
    restore_crypto_policy(network_fd);
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

    /* A sibling root may create an intermediate directory that did not exist
     * during preflight. Its inode is necessarily new, but timestamp precision
     * is a filesystem property, so the already-probed policy remains valid on
     * the same st_dev. A different filesystem still fails closed. */
    int found_device = 0;
    int device_nsec_exact = 0;
    for (size_t i = 0; i < anchors->count; i++)
    {
        if (anchors->items[i].device != st.st_dev)
            continue;
        if (!found_device)
        {
            found_device = 1;
            device_nsec_exact = anchors->items[i].nsec_exact;
        }
        else if (device_nsec_exact != anchors->items[i].nsec_exact)
            return -1;
    }
    if (found_device)
    {
        *nsec_exact = device_nsec_exact;
        return 0;
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

typedef struct {
    int printed_anything;
    struct timespec started_at;
    ProgressTicker ticker;
} RestoreProgressDisplay;

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

#ifdef RESTORE_TEST_HOOKS
// Drives the cumulative-average formula directly with synthetic timestamps,
// so a test can simulate a long stall followed by a burst without actually
// sleeping.
off_t restore_test_progress_speed(off_t total_bytes,
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

static void restore_render_progress(RestoreProgressDisplay *display,
                                    off_t bytes_restored,
                                    off_t speed_bytes,
                                    const char *current_path,
                                    const struct timespec *now)
{
    double elapsed_seconds = timespec_elapsed_seconds(&display->started_at,
                                                      now);
    char restored_text[32];
    char elapsed_text[32];
    char speed_text[32];
    format_size(bytes_restored, restored_text, sizeof(restored_text));
    format_duration(progress_elapsed_whole_seconds(elapsed_seconds),
                    elapsed_text, sizeof(elapsed_text));
    format_size(speed_bytes, speed_text, sizeof(speed_text));
    const char *path_text = current_path != NULL && current_path[0] != '\0'
        ? current_path : "unknown";
    char line[PATH_MAX + 256U];
    snprintf(line, sizeof(line),
             "Restored: %s so far, elapsed %s, speed %s/s, current: %s",
             restored_text, elapsed_text, speed_text, path_text);
    progress_line_fit(line, sizeof(line));
    printf("\r%s\033[K", line);
    fflush(stdout);
}

static void restore_ticker_redraw(const ProgressTickerSnapshot *snapshot,
                                  const struct timespec *now, void *context)
{
    RestoreProgressDisplay *display = context;
    restore_render_progress(display, snapshot->bytes, snapshot->speed_bytes,
                            snapshot->path, now);
}

static void restore_progress_stop_ticker(RestoreProgressDisplay *display)
{
    if (progress_ticker_stop(&display->ticker) == 0)
        return;

    print_error("Error: Could not stop the progress display thread: %s\n",
                strerror(errno));
    // Returning would let a live thread retain pointers into this stack frame.
    abort();
}

static int restore_progress_should_install(void)
{
    if (dry_run)
        return 0;
#ifdef RESTORE_TEST_HOOKS
    if (restore_test_progress_force)
        return 1;
#endif
    return isatty(STDOUT_FILENO);
}

static void restore_report_progress(off_t bytes_restored,
                                    off_t bytes_unchanged,
                                    const char *current_path,
                                    void *userdata)
{
    (void)bytes_unchanged;
    RestoreProgressDisplay *display = userdata;
    if (display == NULL)
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    if (!display->printed_anything)
        display->started_at = now;

    off_t speed_bytes = progress_speed(bytes_restored, &display->started_at,
                                       &now);

    if (progress_ticker_snapshot(&display->ticker, bytes_restored, 0,
                                 speed_bytes, 0, 0, current_path, &now) != 0)
    {
        int saved_errno = errno;
        restore_progress_stop_ticker(display);
        print_warning("  Warning: progress stall redraw disabled after a "
                      "snapshot failure: %s\n", strerror(saved_errno));
    }

    restore_render_progress(display, bytes_restored, speed_bytes,
                            current_path, &now);
    display->printed_anything = 1;
}

typedef struct {
    BackupCaptureReport *report;
    RestoreProgressDisplay *display;
    int *ticker_installed;
} RestoreProgressPhase;

static void restore_progress_finish_phase(RestoreProgressPhase *phase)
{
    if (phase == NULL || phase->report == NULL || phase->display == NULL ||
        phase->ticker_installed == NULL)
        return;
    if (*phase->ticker_installed)
    {
        restore_progress_stop_ticker(phase->display);
        *phase->ticker_installed = 0;
    }
    if (phase->display->printed_anything)
    {
        if (phase->report->progress_cb != NULL)
            phase->report->progress_cb(phase->report->bytes_copied,
                                       phase->report->bytes_unchanged,
                                       phase->report->current_path,
                                       phase->report->progress_userdata);
        putchar('\n');
        fflush(stdout);
        phase->display->printed_anything = 0;
    }
}

static void restore_before_content_verification(void *context)
{
    restore_progress_finish_phase(context);
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

// A part of a native restore held back until everything else is restored,
// because an application that was open when the restore started owns it
// (D69): a whole item, or a subtree left out of an item's walk.
typedef struct {
    char source_rel[PATH_MAX + 8];
    char home_relative[PATH_MAX];
    char label[PATH_MAX + 64];
    const char *app;
    int whole_item;
} NativeDeferredItem;

typedef struct {
    const RestoreDeferral *settings; /* Open applications' settings. */
    NativeDeferredItem *items;
    size_t count;
    size_t capacity;
} NativeDeferral;

// Whether the HOME-relative path inner is outer or lies below it.
static int home_path_within(const char *inner, const char *outer)
{
    size_t length = strlen(outer);
    if (length == 0)
        return 1;
    return strncmp(inner, outer, length) == 0 &&
           (inner[length] == '\0' || inner[length] == '/');
}

static NativeDeferredItem *native_deferral_add(NativeDeferral *deferral)
{
    if (deferral->count == deferral->capacity)
    {
        size_t capacity = deferral->capacity == 0 ? 4U
                                                  : deferral->capacity * 2U;
        NativeDeferredItem *items =
            realloc(deferral->items, capacity * sizeof(*items));
        if (items == NULL)
            return NULL;
        deferral->items = items;
        deferral->capacity = capacity;
    }
    NativeDeferredItem *item = &deferral->items[deferral->count++];
    memset(item, 0, sizeof(*item));
    return item;
}

// Records the part of an item that lands below HOME at home_relative and
// that settings owns. Returns 1 when recorded, 0 when the backup has nothing
// there, and -1 on error.
static int native_deferral_note(NativeDeferral *deferral, int source_root_fd,
                                const char *source_rel,
                                const char *home_relative, const char *label,
                                const PortableRestoreDeferredPath *settings)
{
    int whole = home_path_within(home_relative, settings->home_relative);
    NativeDeferredItem *item = native_deferral_add(deferral);
    if (item == NULL)
    {
        print_error("Error: Out of memory while ordering the restore\n");
        return -1;
    }
    item->app = settings->label;
    item->whole_item = whole;
    int written;
    if (whole)
        written = snprintf(item->source_rel, sizeof(item->source_rel), "%s",
                           source_rel) < (int)sizeof(item->source_rel) &&
                  snprintf(item->home_relative, sizeof(item->home_relative),
                           "%s", home_relative) <
                      (int)sizeof(item->home_relative) &&
                  snprintf(item->label, sizeof(item->label), "%s", label) <
                      (int)sizeof(item->label);
    else
    {
        const char *suffix = settings->home_relative + strlen(home_relative) +
                             (home_relative[0] != '\0');
        written = snprintf(item->source_rel, sizeof(item->source_rel),
                           "%s/%s", source_rel, suffix) <
                      (int)sizeof(item->source_rel) &&
                  snprintf(item->home_relative, sizeof(item->home_relative),
                           "%s", settings->home_relative) <
                      (int)sizeof(item->home_relative) &&
                  snprintf(item->label, sizeof(item->label), "%s:%s", label,
                           suffix) < (int)sizeof(item->label);
    }
    if (!written)
    {
        deferral->count--;
        print_error("Error: Failed to restore %s\n", label);
        return -1;
    }
    RestoreSourceStatus status =
        restore_native_source_status_at(source_root_fd, item->source_rel);
    if (status == RESTORE_SOURCE_PRESENT)
        return 1;
    deferral->count--;
    if (status == RESTORE_SOURCE_MISSING)
        return 0;
    print_error("Error: Failed to inspect %s\n", label);
    return -1;
}

// The new system's user-dirs.dirs stays: it names the XDG folders a restore
// puts content in (D47, D86).
static const char user_dirs[] = ".config/user-dirs.dirs";

// Restores an item that lands below HOME at home_relative. With a deferral,
// the settings of applications open at the start are held back (D69): an
// item inside such settings waits whole, and settings inside the item are
// left out of its walk; restore_native_deferred() restores both. Returns as
// restore_item_at() does, except that an item waiting whole returns 0 and
// is counted when it is restored.
static int restore_home_item_deferring(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int home_fd, const char *home_relative, const char *label,
    int source_required, NativeDeferral *deferral,
    const RestoreTimestampAnchors *timestamp_anchors,
    size_t *skipped_security_xattrs, BackupCaptureReport *capture_report)
{
    if (strcmp(home_relative, user_dirs) == 0)
        return 0;
    size_t settings_count = deferral != NULL ? deferral->settings->count : 0;
    for (size_t index = 0; index < settings_count; index++)
    {
        const PortableRestoreDeferredPath *settings =
            &deferral->settings->paths[index];
        if (home_path_within(home_relative, settings->home_relative))
            return native_deferral_note(deferral, source_root_fd, source_rel,
                                        home_relative, label, settings) < 0
                ? -1 : 0;
    }
    size_t first = deferral != NULL ? deferral->count : 0;
    for (size_t index = 0; index < settings_count; index++)
    {
        const PortableRestoreDeferredPath *settings =
            &deferral->settings->paths[index];
        if (home_path_within(settings->home_relative, home_relative) &&
            native_deferral_note(deferral, source_root_fd, source_rel,
                                 home_relative, label, settings) < 0)
            return -1;
    }

    const char *skipped[WRITER_APPS_MAX + 1];
    CloneContext item_ctx = *ctx;
    item_ctx.skipped_count = 0;
    for (size_t index = first; deferral != NULL && index < deferral->count &&
                               item_ctx.skipped_count < WRITER_APPS_MAX;
         index++)
        skipped[item_ctx.skipped_count++] = deferral->items[index].source_rel;
    char user_dirs_rel[PATH_MAX + 32];
    if (home_path_within(user_dirs, home_relative) &&
        snprintf(user_dirs_rel, sizeof(user_dirs_rel), "%s/%s", source_rel,
                 user_dirs + strlen(home_relative) +
                     (home_relative[0] != '\0')) <
            (int)sizeof(user_dirs_rel))
        skipped[item_ctx.skipped_count++] = user_dirs_rel;
    item_ctx.skipped_paths = skipped;
    return restore_item_at(&item_ctx, source_root_fd, source_rel, home_fd,
                           home_relative, label, source_required,
                           timestamp_anchors, skipped_security_xattrs,
                           capture_report);
}

// A backup-relative path restored directly into home under the same name on
// both sides (legacy's Projects/dotfiles/browser-config items).
static int restore_home_item(const CloneContext *ctx, int source_root_fd,
                             int home_fd, const char *rel_path,
                             NativeDeferral *deferral,
                             const RestoreTimestampAnchors *timestamp_anchors,
                             size_t *skipped_security_xattrs,
                             BackupCaptureReport *capture_report)
{
    int rc = restore_home_item_deferring(ctx, source_root_fd, rel_path,
                                         home_fd, rel_path, rel_path, 0,
                                         deferral, timestamp_anchors,
                                         skipped_security_xattrs,
                                         capture_report);
    if (rc > 0 && dry_run)
        printf("  Would restore: %s\n", rel_path);
    return rc;
}

// Restoring a held-back item creates it inside a folder whose times were
// already restored. Their values are read before and put back after, as if
// the item had been restored in its turn (D69). Returns an fd for
// native_parent_times_put_back(), or -1 when the folder is not there as a
// plain directory.
static int native_parent_times_take(int home_fd, const char *home_relative,
                                    struct timespec times[2])
{
    char parent[PATH_MAX];
    if (snprintf(parent, sizeof(parent), "%s", home_relative) >=
        (int)sizeof(parent))
        return -1;
    char *slash = strrchr(parent, '/');
    if (slash == NULL)
        parent[0] = '\0';
    else
        *slash = '\0';
    int fd = restore_destination_anchor_fd(home_fd, parent);
    if (fd < 0)
        return -1;
    struct stat anchor_st, parent_st;
    if (fstat(fd, &anchor_st) != 0 ||
        (parent[0] != '\0' &&
         fstatat(home_fd, parent, &parent_st, AT_SYMLINK_NOFOLLOW) != 0) ||
        (parent[0] != '\0' && (parent_st.st_dev != anchor_st.st_dev ||
                               parent_st.st_ino != anchor_st.st_ino)))
    {
        close(fd);
        return -1;
    }
    times[0] = anchor_st.st_atim;
    times[1] = anchor_st.st_mtim;
    return fd;
}

// Restores what restore_home_item_deferring() held back once everything else
// is restored, and asks first if an application that owns it is still open
// (D69). Returns 1 when the user left them out.
static int restore_native_deferred(
    const CloneContext *ctx, int source_root_fd, int home_fd,
    const NativeDeferral *deferral, int *count, int *had_error,
    const RestoreTimestampAnchors *timestamp_anchors,
    size_t *skipped_security_xattrs, BackupCaptureReport *capture_report)
{
    if (deferral->count == 0)
        return 0;
    RestoreDeferral question = {
        .retire_progress = deferral->settings->retire_progress,
        .progress = deferral->settings->progress
    };
    for (size_t index = 0; index < deferral->count; index++)
    {
        int known = 0;
        for (size_t app = 0; app < question.count && !known; app++)
            known = strcmp(question.paths[app].label,
                           deferral->items[index].app) == 0;
        if (!known && question.count < WRITER_APPS_MAX)
        {
            question.paths[question.count].label = deferral->items[index].app;
            question.paths[question.count].home_relative =
                deferral->items[index].home_relative;
            question.count++;
        }
    }
    if (!restore_before_deferred(&question))
        return 1;

    for (size_t index = 0; index < deferral->count; index++)
    {
        const NativeDeferredItem *item = &deferral->items[index];
        struct timespec times[2];
        int parent_fd = native_parent_times_take(home_fd, item->home_relative,
                                                 times);
        int rc = restore_item_at(ctx, source_root_fd, item->source_rel,
                                 home_fd, item->home_relative, item->label, 0,
                                 timestamp_anchors, skipped_security_xattrs,
                                 capture_report);
        if (rc > 0 && item->whole_item)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
        if (parent_fd >= 0)
        {
            if (futimens(parent_fd, times) != 0)
            {
                print_error("Error: Could not restore the times of the folder "
                            "holding ~/%s: %s\n", item->home_relative,
                            strerror(errno));
                *had_error = 1;
            }
            close(parent_fd);
        }
    }
    return 0;
}

static void native_deferral_print_left_out(const NativeDeferral *deferral)
{
    printf("Left out the settings of applications that stayed open (");
    for (size_t index = 0; index < deferral->count; index++)
        printf("%s~/%s", index == 0 ? "" : ", ",
               deferral->items[index].home_relative);
    printf("); close them and run the same restore again to put them "
           "back.\n");
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
                          NativeDeferral *deferral,
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
                               LEGACY_HOME_ITEMS[i].name, deferral,
                               timestamp_anchors, skipped_security_xattrs,
                               capture_report);
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
                               LEGACY_HOME_ITEMS[i].name, deferral,
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
                               LEGACY_HOME_ITEMS[i].name, deferral,
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

// Whether the backup's rootless containers would not work here (D94): they
// name the old home, or carry SELinux labels that a kernel without SELinux
// refuses. Their images and volumes are restored either way.
static int restore_leaves_out_containers(const Manifest *m, const char *home)
{
    return (m->source_home[0] != '\0' && strcmp(m->source_home, home) != 0) ||
           (m->selinux && !restore_selinux_runs());
}

// The payload paths of a native backup's podman container state, which the
// restore leaves out (D94), and the containers they belong to.
typedef struct {
    char **paths;
    size_t count;
    PodmanContainers containers;
    int read_containers;
} NativeLeftOut;

static void native_left_out_free(NativeLeftOut *left_out)
{
    for (size_t index = 0; index < left_out->count; index++)
        free(left_out->paths[index]);
    free(left_out->paths);
    podman_containers_free(&left_out->containers);
    memset(left_out, 0, sizeof(*left_out));
}

static int native_left_out_read_containers(NativeLeftOut *left_out,
                                           int storage_fd)
{
    int fd = openat(storage_fd, PODMAN_CONTAINERS_JSON,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    struct stat st;
    char *text = NULL;
    size_t length = 0;
    int failed = fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
                 st.st_size > 16 * 1024 * 1024 ||
                 (text = malloc((size_t)st.st_size + 1U)) == NULL;
    while (!failed && length < (size_t)st.st_size)
    {
        ssize_t count = read(fd, text + length, (size_t)st.st_size - length);
        if (count < 0 && errno == EINTR)
            continue;
        failed = count <= 0;
        if (!failed)
            length += (size_t)count;
    }
    failed = failed ||
             podman_containers_parse(text, length, &left_out->containers) != 0;
    free(text);
    close(fd);
    return failed ? -1 : 0;
}

// Adds what podman_state_left_out() names among the entries of folder, a
// folder below the payload's storage folder at storage_rel.
static int native_left_out_scan(NativeLeftOut *left_out, int storage_fd,
                                const char *storage_rel, const char *folder)
{
    int fd = openat(storage_fd, folder[0] != '\0' ? folder : ".",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    DIR *dir = fdopendir(fd);
    if (dir == NULL)
    {
        close(fd);
        return -1;
    }
    int failed = 0;
    struct dirent *entry;
    while (!failed && (errno = 0, entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char relative[PATH_MAX], target[PATH_MAX];
        if (snprintf(relative, sizeof(relative), "%s%s%s", folder,
                     folder[0] != '\0' ? "/" : "", entry->d_name) >=
            (int)sizeof(relative))
            continue;
        ssize_t target_length = readlinkat(dirfd(dir), entry->d_name, target,
                                           sizeof(target) - 1U);
        if (target_length >= 0)
            target[target_length] = '\0';
        if (!podman_state_left_out(&left_out->containers, relative,
                                   target_length >= 0 ? target : NULL))
            continue;
        char **paths = realloc(left_out->paths,
                               (left_out->count + 1U) * sizeof(*paths));
        char *path = NULL;
        failed = paths == NULL ||
                 asprintf(&path, "%s/%s", storage_rel, relative) < 0;
        if (paths != NULL)
            left_out->paths = paths;
        if (!failed)
            left_out->paths[left_out->count++] = path;
    }
    if (!failed && errno != 0)
        failed = 1;
    if (closedir(dir) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

// Finds the podman storage folder in the native backup's home-relative
// roots and lists what of it the restore leaves out.
static int native_left_out_build(int source_root_fd, const Manifest *m,
                                 NativeLeftOut *left_out)
{
    static const char *const folders[] = { "", "libpod", "overlay",
                                           "overlay/l" };
    for (int index = 0; index < m->root_count; index++)
    {
        const ManifestRoot *root = &m->roots[index];
        char payload[PATH_MAX + 8], storage_rel[2 * PATH_MAX];
        if (root->policy != ROOT_POLICY_HOME_RELATIVE ||
            !home_path_within(PODMAN_STORAGE, root->restore_path) ||
            v1_payload_rel(root, payload, sizeof(payload)) != 0)
            continue;
        size_t root_length = strlen(root->restore_path);
        const char *suffix = &PODMAN_STORAGE[root_length];
        if (root_length != 0 && *suffix == '/')
            suffix++;
        snprintf(storage_rel, sizeof(storage_rel), "%s%s%s", payload,
                 suffix[0] != '\0' ? "/" : "", suffix);
        int storage_fd = openat(source_root_fd, storage_rel,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (storage_fd < 0)
        {
            if (errno == ENOENT)
                continue;
            return -1;
        }
        int failed = 0;
        if (!left_out->read_containers)
        {
            failed = native_left_out_read_containers(left_out,
                                                     storage_fd) != 0;
            left_out->read_containers = 1;
        }
        for (size_t folder = 0;
             !failed && folder < sizeof(folders) / sizeof(folders[0]); folder++)
            failed = native_left_out_scan(left_out, storage_fd, storage_rel,
                                          folders[folder]) != 0;
        close(storage_fd);
        if (failed)
            return -1;
    }
    return 0;
}

// After a restore that left containers out (D94), layers.json lists only
// the layers that were restored.
static void restore_podman_layers_json(int home_fd, int *had_error)
{
    if (dry_run)
        return;
    int storage_fd = openat(home_fd, PODMAN_STORAGE,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (storage_fd < 0 && errno == ENOENT)
        return;
    if (storage_fd < 0 || podman_layers_json_drop_missing(storage_fd) < 0)
    {
        print_error("Error: Could not update ~/%s/overlay-layers/layers.json: "
                    "%s\n", PODMAN_STORAGE, strerror(errno));
        *had_error = 1;
    }
    if (storage_fd >= 0)
        close(storage_fd);
}

// Names the containers a restore left out (D94).
static void restore_containers_todo(const PodmanContainers *containers,
                                    FILE *todo)
{
    if (todo == NULL || containers->name_count == 0)
        return;
    fprintf(todo, "  Podman containers from the old system were left out, "
                  "since they would not start here: ");
    for (size_t index = 0; index < containers->name_count; index++)
        fprintf(todo, "%s%s", index == 0 ? "" : ", ",
                containers->names[index]);
    fprintf(todo, ". Their images and volumes are restored; create them "
                  "again, with podman create or toolbox create.\n");
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

// Finds the first entry along relative below anchor_fd that is a symbolic
// link, which the destination walk refuses to follow. Returns 1 with its
// path below the anchor in out, or 0 when there is none.
static int restore_first_symlink(int anchor_fd, const char *relative,
                                 char *out, size_t size)
{
    if (snprintf(out, size, "%s", relative) >= (int)size)
        return 0;
    for (char *component = out;;)
    {
        char *slash = strchr(component, '/');
        if (slash != NULL)
            *slash = '\0';
        struct stat st;
        if (fstatat(anchor_fd, out, &st, AT_SYMLINK_NOFOLLOW) != 0)
            return 0;
        if (S_ISLNK(st.st_mode))
            return 1;
        if (slash == NULL)
            return 0;
        *slash = '/';
        component = slash + 1;
    }
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
    DestinationIdentityNameConflict name_conflict;
    DestinationIdentityStatus status = destination_identity_graph_add(
        &map->identity_graph, target->route.anchor_fd, relative, claim,
        owner, placement, &conflicting_owner, &name_conflict);
    if (status == DESTINATION_IDENTITY_OK)
        return 0;

    int saved_errno = errno;
    char symlink_rel[PATH_MAX];
    const char *entry_name = logical[0] == '\0' ? "." : logical;
    char destination[PATH_MAX];
    if ((logical[0] == '\0' &&
         snprintf(destination, sizeof(destination), "%s",
                  target->absolute) >= (int)sizeof(destination)) ||
        (logical[0] != '\0' &&
         path_join(destination, sizeof(destination), target->absolute,
                   logical) != 0))
        snprintf(destination, sizeof(destination), "%s", relative);
    if (status == DESTINATION_IDENTITY_COLLISION)
    {
        size_t conflicting_root = SIZE_MAX;
        if (conflicting_owner != SIZE_MAX)
            conflicting_root = conflicting_owner % MANIFEST_MAX_ROOTS;
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
    else if (status == DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR)
    {
        const char *reason =
            name_conflict.failure == DESTINATION_NAME_FAILURE_CASEFOLD
                ? "casefold name lookup"
                : "name lookup capability is unknown";
        size_t conflicting_root = SIZE_MAX;
        if (conflicting_owner != SIZE_MAX)
            conflicting_root = conflicting_owner % MANIFEST_MAX_ROOTS;
        if (conflicting_owner != SIZE_MAX &&
            conflicting_root < (size_t)manifest->root_count)
            print_error("Error: Manifest root %s entry %s and manifest root %s have potentially equivalent destination names %.*s and %.*s under %s; refusing because %s\n",
                        root->id, entry_name,
                        manifest->roots[conflicting_root].id,
                        (int)name_conflict.current_component_length,
                        name_conflict.current_component,
                        (int)name_conflict.prior_component_length,
                        name_conflict.prior_component,
                        destination, reason);
        else
            print_error("Error: Manifest root %s entry %s has potentially equivalent destination names %.*s and %.*s under %s; refusing because %s\n",
                        root->id, entry_name,
                        (int)name_conflict.current_component_length,
                        name_conflict.current_component,
                        (int)name_conflict.prior_component_length,
                        name_conflict.prior_component,
                        destination, reason);
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
    else if (restore_first_symlink(target->route.anchor_fd, relative,
                                   symlink_rel, sizeof(symlink_rel)))
        print_destination_symlink_refusal(target->route.anchor_fd,
                                          symlink_rel);
    else
        print_error("Error: Could not safely inspect restore destination %s "
                    "for manifest root %s entry %s (%s)\n", destination,
                    root->id, entry_name, strerror(saved_errno));
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

// Native restore copies files as they are; afterwards the source HOME and
// XDG folders are rewritten in the desktop-state files that store file://
// URIs, as portable replay does while it copies them (D41, D47, D86). A file
// this run did not write holds no source paths to replace.
// The user folders a native restore put the backup's XDG roots in.
static void native_xdg_dirs(const Manifest *m,
                            const RestoreTargetMap *target_map,
                            const char *xdg_dirs[XDG_KEY_COUNT])
{
    for (int index = 0; index < XDG_KEY_COUNT; index++)
        xdg_dirs[index] = NULL;
    for (int index = 0; index < m->root_count; index++)
    {
        int key = xdg_key_index(m->roots[index].id);
        if (m->roots[index].policy == ROOT_POLICY_XDG && key >= 0)
            xdg_dirs[key] = target_map->roots[index].absolute;
    }
}

static void restore_native_rewrite_home(int home_fd, const char *home,
                                        const Manifest *m,
                                        const char *const *xdg_dirs,
                                        int *had_error)
{
    HomeRewritePair pairs[HOME_REWRITE_MAX_PAIRS];
    size_t pair_count = 0;
    if (home_rewrite_pairs_build(m, xdg_dirs, home, pairs, &pair_count) != 0)
    {
        print_error("Error: Could not map the backup's home folder to this "
                    "system's: %s\n", strerror(errno));
        *had_error = 1;
        return;
    }
    for (size_t index = 0; pair_count != 0 && index < HOME_REWRITE_FILE_COUNT;
         index++)
        if (home_rewrite_file_at(home_fd, home_rewrite_files[index], pairs,
                                 pair_count) != 0 &&
            errno != ENOENT)
        {
            print_error("Error: Could not point ~/%s at this system's home "
                        "folder: %s\n", home_rewrite_files[index],
                        strerror(errno));
            *had_error = 1;
        }
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
                       const RestoreTargetMap *target_map, int home_fd,
                       int *count, int *had_error, NativeDeferral *deferral,
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

        int rc = root->policy == ROOT_POLICY_HOME_RELATIVE &&
                         destination->route.anchor_fd == home_fd
            ? restore_home_item_deferring(ctx, source_root_fd, source_rel,
                                          home_fd,
                                          destination->route.relative,
                                          root->id, 1, deferral,
                                          timestamp_anchors,
                                          skipped_security_xattrs,
                                          capture_report)
            : restore_item_at(ctx, source_root_fd, source_rel,
                              destination->route.anchor_fd,
                              destination->route.relative, root->id, 1,
                              timestamp_anchors, skipped_security_xattrs,
                              capture_report);
        if (rc > 0 && dry_run)
        {
            if (root->policy == ROOT_POLICY_HOME_RELATIVE)
            {
                if (root->restore_path[0] != '\0')
                    printf("  Would restore: ~/%s\n", root->restore_path);
                else
                    printf("  Would restore: ~\n");
            }
            else
            {
                printf("  Would restore: %s/\n", destination->absolute);
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

int restore_with_options(const char *source, const RestoreOptions *options)
{
    int skip_content_verification =
        options != NULL && options->skip_content_verification;
    char home[PATH_MAX];
    if (resolve_target_home(home) != 0)
        return MIGR_EXIT_FAILURE;

    struct stat st;
    if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        print_error("Error: Source directory not found: %s\n", source);
        return MIGR_EXIT_FAILURE;
    }

    // A live or abandoned ".partial" container (docs/DECISIONS.md D15) is
    // never a valid restore source: an interrupted backup may be incomplete,
    // and a still-active one may be locked by another process. Trailing
    // slashes are stripped first so they cannot hide the leaf name.
    char source_copy[PATH_MAX];
    if ((size_t)snprintf(source_copy, sizeof(source_copy), "%s", source) >= sizeof(source_copy))
    {
        print_error("Error: Source path too long: %s\n", source);
        return MIGR_EXIT_FAILURE;
    }
    size_t source_len = strlen(source_copy);
    while (source_len > 1 && source_copy[source_len - 1] == '/')
        source_copy[--source_len] = '\0';
    const char *source_leaf = strrchr(source_copy, '/');
    source_leaf = source_leaf ? source_leaf + 1 : source_copy;
    if (container_name_is_partial(source_leaf))
    {
        print_error("Error: %s is an in-progress or abandoned backup container, not a finished one.\n", source);
        return MIGR_EXIT_FAILURE;
    }
    int source_is_versioned_final = container_name_is_final(source_leaf);

    int source_root_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_root_fd < 0)
    {
        print_error("Error: Could not open source directory: %s\n", source);
        return MIGR_EXIT_FAILURE;
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
        return MIGR_EXIT_FAILURE;
    }
    if (mst == MANIFEST_STATUS_MALFORMED)
    {
        print_error("Error: manifest.txt is malformed; refusing to restore.\n");
        close(source_root_fd);
        return MIGR_EXIT_FAILURE;
    }
    if (mst == MANIFEST_STATUS_IO_ERROR)
    {
        print_error("Error: Could not read manifest.txt.\n");
        close(source_root_fd);
        return MIGR_EXIT_FAILURE;
    }
    // mst is now MISSING, LEGACY, or VALID.

    if (source_is_versioned_final && mst == MANIFEST_STATUS_MISSING)
    {
        print_error("Error: A finalized versioned container is missing manifest.txt; refusing to treat it as a legacy backup.\n");
        close(source_root_fd);
        return MIGR_EXIT_FAILURE;
    }
    if (source_is_versioned_final && mst == MANIFEST_STATUS_LEGACY)
    {
        print_error("Error: A finalized versioned container carries a legacy manifest; refusing to guess its layout.\n");
        close(source_root_fd);
        return MIGR_EXIT_FAILURE;
    }
    if (mst == MANIFEST_STATUS_VALID)
        print_backup_time(m.updated);
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
        return MIGR_EXIT_FAILURE;
    }
    struct stat keyring_before;
    login_keyring_stat(home_fd, &keyring_before);

    // The run's log belongs to the new system's user, where XDG puts logs
    // (D79); a restore that ends cleanly takes it away again.
    uid_t log_uid = (uid_t)-1;
    gid_t log_gid = (gid_t)-1;
    (void)sudo_invoker(&log_uid, &log_gid, NULL);
    (void)run_log_attach(home_fd, ".local/state/migr", "restore", log_uid,
                         log_gid);

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
            return MIGR_EXIT_FAILURE;
        }

        int dconf_database_fd = -1;
        RestoreTodo todo = {0};
        RestoreDeferral deferral = {0};
        PodmanContainers left_out_containers = {0};
        int leave_out_containers = restore_leaves_out_containers(&m, home);
        restore_defer_running_writers(&deferral);
        RestoreConfirmation confirmation = {
            .deferral = &deferral,
            .source = source,
            .skip_content_verification = skip_content_verification
        };
        PortableRestoreRequest request = {
            .source_container_fd = source_root_fd,
            .manifest = &m,
            .destination_home_fd = home_fd,
            .destination_home_path = home,
            .destination_timestamp_policy = {0},
            .owner_map = restore_owner_map(&m),
            .skip_content_verification = skip_content_verification,
            // The desktop run checked the payload before handing over (D89).
            .backup_checked = console_restore_service(),
            .confirm = restore_confirm,
            .confirm_context = &confirmation,
            .before_deferred = restore_before_deferred,
            .before_deferred_context = &deferral,
            .dconf_database_fd_out = &dconf_database_fd,
            .dconf_loads_into_session = restore_dconf_loads_into_session(),
            .session_running = restore_session_running(),
            .left_out_containers =
                leave_out_containers ? &left_out_containers : NULL
        };
        for (int index = 0; index < XDG_RESTORE_COUNT; index++)
            request.destination_xdg_dirs[index] = xdg_dirs[index];
        BackupCaptureReport capture_report;
        backup_capture_report_init(&capture_report);
        capture_report.sync_interval_bytes = BACKUP_SYNC_INTERVAL_BYTES;
        RestoreProgressDisplay progress_display = {0};
        int progress_installed = 0;
        if (restore_progress_should_install())
        {
            capture_report.progress_cb = restore_report_progress;
            capture_report.progress_userdata = &progress_display;
            if (progress_ticker_start(&progress_display.ticker,
                                      restore_ticker_redraw,
                                      &progress_display) != 0)
                print_warning("  Warning: progress stall redraw is unavailable: %s\n",
                              strerror(errno));
            progress_installed = 1;
        }
        request.capture_report = &capture_report;
        RestoreProgressPhase progress_phase = {
            .report = &capture_report,
            .display = &progress_display,
            .ticker_installed = &progress_installed
        };
        request.before_content_verification =
            restore_before_content_verification;
        request.before_content_verification_context = &progress_phase;
        if (deferral.count != 0)
        {
            request.deferred_paths = deferral.paths;
            request.deferred_path_count = deferral.count;
        }
        deferral.retire_progress = restore_before_content_verification;
        deferral.progress = &progress_phase;
        PortableRestoreReplayReport report;
        PortableRestoreOutcome outcome =
            portable_restore_orchestrate_at(&request, &report);

        restore_progress_finish_phase(&progress_phase);

        int had_portable_error = 0;
        if (outcome == PORTABLE_RESTORE_COMPLETE ||
            outcome == PORTABLE_RESTORE_VERIFICATION_FAILED)
        {
            // Every entry was applied, so the dependent steps still run even
            // when verification found differences; those are reported below.
            if (leave_out_containers)
                restore_podman_layers_json(home_fd, &had_portable_error);
            restore_selinux_label_roots(&m, home,
                                        (const char *const *)xdg_dirs,
                                        &had_portable_error);
            restore_dconf_settings(dconf_database_fd, home_fd, &m, home,
                                   (const char *const *)xdg_dirs,
                                   &had_portable_error);
            if (m.has_network_config)
                restore_network_config(source_root_fd, &had_portable_error);
            restore_system_lists(source_root_fd, &todo, &had_portable_error);
            restore_login_keyring_todo(home_fd, &keyring_before, todo.stream);
            restore_subid_todo(&request.owner_map, todo.stream);
            restore_containers_todo(&left_out_containers, todo.stream);
        }
        else if (outcome == PORTABLE_RESTORE_DRY_RUN &&
                 m.has_network_config)
            restore_network_config(source_root_fd, &had_portable_error);
        if (dconf_database_fd >= 0)
            close(dconf_database_fd);
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
                if (report.verification_changed_count != 0)
                    printf("%zu of them %s changed afterwards by other "
                           "programs (listed above).\n",
                           report.verification_changed_count,
                           report.verification_changed_count == 1 ? "was"
                                                                  : "were");
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
                if (confirmation.handed_over == 0)
                    printf("Cancelled.\n");
                break;
            case PORTABLE_RESTORE_VERIFICATION_FAILED:
            {
                char item_phrase[64];
                format_item_count_phrase(item_phrase, sizeof(item_phrase),
                                         report.applied_count, "restored");
                printf("Restore finished with errors: %s, %zu differ%s from "
                       "the backup (listed above)\n",
                       item_phrase, report.verification_failed_count,
                       report.verification_failed_count == 1 ? "s" : "");
                break;
            }
            case PORTABLE_RESTORE_ERROR:
            default:
            {
                char reason[256];
                char detail[sizeof(reason) + 4U] = "";
                if (replay_failure_reason_format(&report, reason,
                                                 sizeof(reason)) == 1)
                    (void)snprintf(detail, sizeof(detail), " (%s)", reason);
                if (report.failed_root_id[0] != '\0')
                    printf("Restore finished with errors at %s:%s: %zu applied, %zu failed%s\n",
                           report.failed_root_id,
                           report.failed_logical_path[0] != '\0'
                               ? report.failed_logical_path : ".",
                           report.applied_count, report.failed_count, detail);
                else if (report.failed_logical_path[0] != '\0')
                    printf("Restore finished with errors at %s: %zu applied, %zu failed%s\n",
                           report.failed_logical_path,
                           report.applied_count, report.failed_count, detail);
                else
                    printf("Restore finished with errors: %zu applied, %zu failed%s\n",
                           report.applied_count, report.failed_count, detail);
                break;
            }
        }
        if (report.preserved_local_state_count != 0)
            printf("Left %zu locally authoritative destination file%s "
                   "untouched.\n",
                   report.preserved_local_state_count,
                   report.preserved_local_state_count == 1 ? "" : "s");
        if (report.live_state_kept_count != 0)
            printf("Left %zu file%s that running desktop services had "
                   "already written in place.\n",
                   report.live_state_kept_count,
                   report.live_state_kept_count == 1 ? "" : "s");
        if (report.deferred_skipped_count != 0)
            printf("Left out %zu settings file%s of applications that stayed "
                   "open; close them and run the same restore again to put "
                   "%s back.\n",
                   report.deferred_skipped_count,
                   report.deferred_skipped_count == 1 ? "" : "s",
                   report.deferred_skipped_count == 1 ? "it" : "them");
        if (report.left_out_count != 0)
            printf("Left out %zu item%s of podman's container state, which "
                   "would not work on this system.\n", report.left_out_count,
                   report.left_out_count == 1 ? "" : "s");
        if (report.skipped_security_xattr_count != 0)
            printf("Skipped %zu security.* attribute(s) that the destination "
                   "could not apply.\n",
                   report.skipped_security_xattr_count);
        restore_todo_finish(&todo, source);
        podman_containers_free(&left_out_containers);
        free_xdg_dirs(xdg_dirs);
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        if (outcome == PORTABLE_RESTORE_ERROR ||
            outcome == PORTABLE_RESTORE_VERIFICATION_FAILED ||
            had_portable_error || confirmation.handed_over < 0)
            return MIGR_EXIT_FAILURE;
        // Items another program changed after restore are not failures, but
        // like a backup whose source changed, the run says so (D67).
        return report.verification_changed_count != 0 ? MIGR_EXIT_CHANGED
                                                      : MIGR_EXIT_OK;
    }

    if (mst == MANIFEST_STATUS_VALID &&
        validate_v1_payloads(source_root_fd, &m) != 0)
    {
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return MIGR_EXIT_FAILURE;
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
        return MIGR_EXIT_FAILURE;
    }

    CloneContext ctx = {
        .operation = CLONE_RESTORE,
        .representation = CLONE_NATIVE_TREE,
        .owner_map = mst == MANIFEST_STATUS_VALID ? restore_owner_map(&m)
                                                 : (OwnerMap){0}
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
    RestoreProgressDisplay progress_display = {0};
    int progress_installed = 0;
    RestoreProgressPhase progress_phase = {
        .report = &capture_report,
        .display = &progress_display,
        .ticker_installed = &progress_installed
    };
    RestoreDeferral open_settings = {
        .retire_progress = restore_before_content_verification,
        .progress = &progress_phase
    };
    NativeDeferral deferral = { .settings = &open_settings };
    RestoreTodo todo = {0};
    int left_out_deferred = 0;
    int result = MIGR_EXIT_FAILURE;
    NativeLeftOut left_out = {0};
    int leave_out_containers = mst == MANIFEST_STATUS_VALID &&
                               restore_leaves_out_containers(&m, home);
    if (leave_out_containers)
    {
        if (native_left_out_build(source_root_fd, &m, &left_out) != 0)
        {
            print_error("Error: Could not read the backup's podman state: "
                        "%s\n", strerror(errno));
            goto cleanup;
        }
        ctx.left_out_paths = (const char *const *)left_out.paths;
        ctx.left_out_count = left_out.count;
    }

    RestoreNativeStatus metadata_inventory_status;
    if (mst == MANIFEST_STATUS_VALID)
        metadata_inventory_status = restore_v1_metadata_inventory(
            source_root_fd, &m, &target_map, &ctx, &metadata_profiles,
            &timestamp_anchors, &restore_estimate);
    else
        metadata_inventory_status = restore_legacy_metadata_inventory(
            source, source_root_fd, home, home_fd, &ctx, &metadata_profiles,
            &timestamp_anchors, &restore_estimate);
    int network_config_needs_privilege =
        mst == MANIFEST_STATUS_VALID && m.has_network_config &&
        restore_network_config_would_write(source_root_fd);
    if (metadata_inventory_status != RESTORE_NATIVE_OK)
    {
        // Without root, the kernel refuses the no-atime read of a file
        // another user owns: the restore needs root, which the privilege
        // refusal says in terms the user can act on (D38).
        if (metadata_inventory_status != RESTORE_NATIVE_SOURCE_SAFE_READ)
            print_error("Error: native metadata preflight failed; no destination was changed\n");
        else if (restore_privilege_preflight(1, network_config_needs_privilege) == 0)
            report_source_safe_read_refusal("native restore payload", NULL);
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

    // Runs before consent and before any destination mutation, covering both
    // v1 and legacy manifests: metadata_inventory_status above already built
    // metadata_profiles (including foreign_owner_count) for whichever of the
    // two ran, so this needs no extra pass over the payload. Kept after the
    // informational metadata_profiles_report() above so a refusal is
    // preceded by the same privilege-relevant profile detail an accepted
    // restore would have shown.
    if (dry_run)
        restore_privilege_dry_run_note();
    else if (restore_privilege_preflight(metadata_profiles.foreign_owner_count,
                                         network_config_needs_privilege) != 0)
        goto cleanup;

    if (dry_run)
        printf("Dry run mode enabled. No changes will be made.\n\n");
    else
    {
        restore_defer_running_writers(&open_settings);
        RestoreConfirmation confirmation = {
            .deferral = &open_settings,
            .source = source,
            .skip_content_verification = skip_content_verification
        };
        if (!restore_confirm(&confirmation))
        {
            if (confirmation.handed_over == 0)
                printf("Cancelled.\n");
            result = confirmation.handed_over < 0 ? MIGR_EXIT_FAILURE
                                                  : MIGR_EXIT_OK;
            goto cleanup;
        }
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

    if (restore_progress_should_install())
    {
        capture_report.progress_cb = restore_report_progress;
        capture_report.progress_userdata = &progress_display;
        if (progress_ticker_start(&progress_display.ticker,
                                  restore_ticker_redraw,
                                  &progress_display) != 0)
            print_warning("  Warning: progress stall redraw is unavailable: %s\n",
                          strerror(errno));
        progress_installed = 1;
    }

    if (mst == MANIFEST_STATUS_VALID)
    {
        restore_v1(source, source_root_fd, &ctx, &m, &target_map, home_fd,
                   &count, &had_error, dry_run ? NULL : &deferral,
                   &timestamp_anchors,
                   &skipped_security_xattrs, &capture_report,
                   target_map.order);
    }
    else
    {
        if (restore_legacy(source, source_root_fd, home, home_fd, &ctx,
                           &count, &had_error, dry_run ? NULL : &deferral,
                           &timestamp_anchors,
                           &skipped_security_xattrs, &capture_report) != 0)
            goto cleanup;
    }
    if (!dry_run)
        left_out_deferred = restore_native_deferred(
            &ctx, source_root_fd, home_fd, &deferral, &count, &had_error,
            &timestamp_anchors, &skipped_security_xattrs, &capture_report);

    restore_progress_finish_phase(&progress_phase);

    native_inode_map_free(ctx.inode_map);
    ctx.inode_map = NULL;

    if (!dry_run && mst == MANIFEST_STATUS_VALID)
    {
        const char *xdg_dirs[XDG_KEY_COUNT];
        native_xdg_dirs(&m, &target_map, xdg_dirs);
        restore_native_rewrite_home(home_fd, home, &m, xdg_dirs, &had_error);
        if (leave_out_containers)
            restore_podman_layers_json(home_fd, &had_error);
        restore_selinux_label_roots(&m, home, xdg_dirs, &had_error);
        int dconf_database_fd = native_dconf_database_fd(source_root_fd, &m);
        restore_dconf_settings(dconf_database_fd, home_fd, &m, home, xdg_dirs,
                               &had_error);
        if (dconf_database_fd >= 0)
            close(dconf_database_fd);
    }
    else if (mst != MANIFEST_STATUS_VALID)
    {
        // An unversioned backup records no roots; its folders are in home.
        const char *legacy_home = home;
        restore_selinux_labels(&legacy_home, 1, &had_error);
    }
    if (mst == MANIFEST_STATUS_VALID && m.has_network_config)
        restore_network_config(source_root_fd, &had_error);
    restore_system_lists(source_root_fd, &todo, &had_error);
    restore_login_keyring_todo(home_fd, &keyring_before, todo.stream);
    restore_subid_todo(&ctx.owner_map, todo.stream);
    restore_containers_todo(&left_out.containers, todo.stream);

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
    if (left_out_deferred)
        native_deferral_print_left_out(&deferral);
    if (skipped_security_xattrs != 0)
        printf("Skipped %zu security.* attribute(s) that the destination "
               "could not apply.\n", skipped_security_xattrs);
    restore_todo_finish(&todo, source);
    result = had_error ? MIGR_EXIT_FAILURE : MIGR_EXIT_OK;

cleanup:
    if (progress_installed)
        restore_progress_stop_ticker(&progress_display);
    native_left_out_free(&left_out);
    free(deferral.items);
    native_inode_map_free(ctx.inode_map);
    ctx.inode_map = NULL;
    metadata_profiles_free(&metadata_profiles);
    restore_timestamp_anchors_free(&timestamp_anchors);
    if (restore_target_map_free(&target_map) != 0)
        result = MIGR_EXIT_FAILURE;
    manifest_free(&m);
    close(home_fd);
    close(source_root_fd);
    return result;
}

int restore(const char *source)
{
    return restore_with_options(source, NULL);
}
