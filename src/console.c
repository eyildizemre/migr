#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/vt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "console.h"
#include "fileops.h"
#include "utils.h"

// Set in the service to the PID of the desktop run that started it.
#define SERVICE_ENV "MIGR_CONSOLE_RESTORE"
#define SESSIONS_DIR "/run/systemd/sessions"
#define BINARY_DIR "/run/migr"
#define BINARY BINARY_DIR "/migr"

// logind starts a getty on tty1 to tty6 when one of them is switched to
// (NAutoVTs), which would take the console from migr.
#define FIRST_VT 7
// The kernel's virtual consoles: character major 4, minors 1 to 63.
#define VT_MAJOR 4

static int read_text(const char *path, char *text, size_t size)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, text, size - 1U);
    close(fd);
    if (got < 0)
        return -1;
    text[got] = '\0';
    return 0;
}

// The value of key in a logind session file, or "" when it has none.
static void session_value(const char *text, const char *key, char *out,
                          size_t size)
{
    size_t key_length = strlen(key);
    out[0] = '\0';
    for (const char *line = text; *line != '\0';)
    {
        const char *end = strchrnul(line, '\n');
        if (strncmp(line, key, key_length) == 0 && line[key_length] == '=')
        {
            size_t length = (size_t)(end - line) - key_length - 1U;
            if (length < size)
            {
                memcpy(out, line + key_length + 1U, length);
                out[length] = '\0';
            }
            return;
        }
        line = *end != '\0' ? end + 1 : end;
    }
}

// Whether session id is a user's graphical login that is not closing; *uid
// gets its user. libsystemd reads these files the same way.
static int session_graphical(const char *sessions_dir, const char *id,
                             uid_t *uid)
{
    char path[PATH_MAX], text[8192];
    if (path_join(path, sizeof(path), sessions_dir, id) != 0 ||
        read_text(path, text, sizeof(text)) != 0)
        return 0;
    char type[16], class[16], state[16], user[16];
    session_value(text, "TYPE", type, sizeof(type));
    session_value(text, "CLASS", class, sizeof(class));
    session_value(text, "STATE", state, sizeof(state));
    session_value(text, "UID", user, sizeof(user));
    if ((strcmp(type, "wayland") != 0 && strcmp(type, "x11") != 0) ||
        strcmp(class, "user") != 0 || strcmp(state, "closing") == 0)
        return 0;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(user, &end, 10);
    if (user[0] == '\0' || *end != '\0' || errno != 0)
        return 0;
    *uid = (uid_t)value;
    return 1;
}

// Whether cgroup, the invoker's process's, is on uid's desktop, and that
// desktop is the only one: stopping the display manager ends every user's.
// A terminal is on the desktop either inside its graphical session (Xfce) or
// started by uid's service manager, which only the desktop does
// (user@UID.service; GNOME, KDE); an SSH or console login is a tty session.
static int graphical_session(const char *sessions_dir, const char *cgroup,
                             uid_t uid)
{
    char manager[64];
    snprintf(manager, sizeof(manager), "/user@%lu.service/",
             (unsigned long)uid);
    const char *start = strstr(cgroup, "/session-");
    char id[64] = "";
    if (start != NULL)
    {
        start += strlen("/session-");
        size_t length = strcspn(start, ".\n");
        if (length == 0 || length >= sizeof(id) ||
            strncmp(start + length, ".scope", strlen(".scope")) != 0)
            return 0;
        memcpy(id, start, length);
        id[length] = '\0';
    }
    else if (strstr(cgroup, manager) == NULL)
        return 0;

    DIR *dir = opendir(sessions_dir);
    if (dir == NULL)
        return 0;
    size_t count = 0;
    int found = 0;
    struct dirent *entry;
    // Each session also has a <id>.ref FIFO here.
    while ((entry = readdir(dir)) != NULL)
    {
        uid_t owner;
        if (entry->d_name[0] == '.' || strchr(entry->d_name, '.') != NULL ||
            !session_graphical(sessions_dir, entry->d_name, &owner))
            continue;
        count++;
        if (owner == uid && (id[0] == '\0' || strcmp(entry->d_name, id) == 0))
            found = 1;
    }
    closedir(dir);
    return count == 1 && found;
}

// The cgroup of the process that ran sudo: the first ancestor running as
// uid. sudo's own processes say nothing, as some systems give sudo a session
// of its own (pam_systemd).
static int invoker_cgroup(uid_t uid, char *cgroup, size_t size)
{
    pid_t pid = getppid();
    for (int depth = 0; pid > 1 && depth < 32; depth++)
    {
        char path[64], status[4096];
        snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
        if (read_text(path, status, sizeof(status)) != 0)
            return -1;
        const char *uids = strstr(status, "\nUid:");
        const char *ppid = strstr(status, "\nPPid:");
        unsigned long effective;
        long parent;
        if (uids == NULL || ppid == NULL ||
            sscanf(uids, "\nUid: %*s %lu", &effective) != 1 ||
            sscanf(ppid, "\nPPid: %ld", &parent) != 1)
            return -1;
        if (effective == (unsigned long)uid)
        {
            snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long)pid);
            return read_text(path, cgroup, size);
        }
        pid = (pid_t)parent;
    }
    return -1;
}

// The first console from FIRST_VT on that no program has open; in_use has a
// bit per console, as VT_GETSTATE reports them.
static int free_vt(unsigned short in_use)
{
    for (int vt = FIRST_VT; vt < 16; vt++)
        if ((in_use & (1U << vt)) == 0)
            return vt;
    return 0;
}

// systemd expands $NAME and ${NAME} in a service's command line; $$ is a $.
static int escape_dollars(const char *text, char *out, size_t size)
{
    size_t used = 0;
    for (; *text != '\0'; text++)
    {
        if (used + (*text == '$' ? 2U : 1U) >= size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (*text == '$')
            out[used++] = '$';
        out[used++] = *text;
    }
    out[used] = '\0';
    return 0;
}

int console_restore_vt(void)
{
    uid_t uid;
    gid_t gid;
    char cgroup[4096];
    if (sudo_invoker(&uid, &gid, NULL) != 1 ||
        access("/run/systemd/system", F_OK) != 0 ||
        invoker_cgroup(uid, cgroup, sizeof(cgroup)) != 0 ||
        !graphical_session(SESSIONS_DIR, cgroup, uid))
        return 0;
    char *is_active[] = { "systemctl", "is-active", "--quiet",
                          "display-manager.service", NULL };
    if (run_command(is_active) != 0)
        return 0;
    int fd = open("/dev/tty0", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    struct vt_stat state;
    int queried = fd >= 0 && ioctl(fd, VT_GETSTATE, &state) == 0;
    if (fd >= 0)
        close(fd);
    return queried ? free_vt(state.v_state) : 0;
}

// systemd's SELinux policy does not let it start a binary in a home
// directory, and a binary on the backup drive or in the home being restored
// is not one to run from. The copy lives in /run until the service removes
// it, labelled like the system's own binaries: with /run's label, the
// service would run confined as systemd itself.
static int copy_self(void)
{
    if (mkdir(BINARY_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    int in = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;
    int out = open(BINARY ".new",
                   O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0700);
    struct stat st;
    int result = -1;
    if (out >= 0 && fstat(in, &st) == 0)
    {
        off_t left = st.st_size;
        ssize_t sent;
        while (left > 0 &&
               ((sent = sendfile(out, in, NULL, (size_t)left)) > 0 ||
                (sent < 0 && errno == EINTR)))
            if (sent > 0)
                left -= sent;
        result = left == 0 ? 0 : -1;
        char label[256];
        ssize_t length = getxattr("/usr/bin", "security.selinux", label,
                                  sizeof(label));
        if (length > 0 && fsetxattr(out, "security.selinux", label,
                                    (size_t)length, 0) != 0)
            result = -1;
    }
    if (out >= 0 && close(out) != 0)
        result = -1;
    close(in);
    if (result == 0 && rename(BINARY ".new", BINARY) != 0)
        result = -1;
    return result;
}

// "--setenv=NAME=value" for a sudo variable, or NULL when it is not set.
static char *forward_env(const char *name, char *out, size_t size)
{
    const char *value = getenv(name);
    int length = value != NULL
        ? snprintf(out, size, "--setenv=%s=%s", name, value) : -1;
    return length >= 0 && (size_t)length < size ? out : NULL;
}

int console_restore_hand_over(int vt, const char *source,
                              int skip_content_verification)
{
    char path[PATH_MAX], escaped[2U * PATH_MAX];
    if (realpath(source, path) == NULL ||
        escape_dollars(path, escaped, sizeof(escaped)) != 0 ||
        copy_self() != 0)
    {
        print_error("Error: Could not prepare the restore on a text screen: "
                    "%s. Nothing was changed.\n", strerror(errno));
        return -1;
    }

    char tty[64], service[64], uid[64], gid[64], user[128];
    snprintf(tty, sizeof(tty), "--property=TTYPath=/dev/tty%d", vt);
    snprintf(service, sizeof(service), "--setenv=" SERVICE_ENV "=%ld",
             (long)getpid());
    char *argv[32];
    size_t argc = 0;
    argv[argc++] = "systemd-run";
    argv[argc++] = "--unit=migr-restore";
    argv[argc++] = "--collect";
    argv[argc++] = "--quiet";
    argv[argc++] = tty;
    argv[argc++] = "--property=StandardInput=tty";
    argv[argc++] = "--property=StandardOutput=tty";
    argv[argc++] = "--property=TTYReset=yes";
    argv[argc++] = "--property=TTYVHangup=yes";
    argv[argc++] = "--property=TTYVTDisallocate=yes";
    // However the service ends, the login screen comes back.
    argv[argc++] =
        "--property=ExecStopPost=systemctl start display-manager.service";
    argv[argc++] = service;
    // The service acts for the same user (D38).
    char *forwarded[] = {
        forward_env("SUDO_UID", uid, sizeof(uid)),
        forward_env("SUDO_GID", gid, sizeof(gid)),
        forward_env("SUDO_USER", user, sizeof(user))
    };
    for (size_t index = 0; index < 3U; index++)
        if (forwarded[index] != NULL)
            argv[argc++] = forwarded[index];
    argv[argc++] = BINARY;
    argv[argc++] = "restore";
    if (verbose)
        argv[argc++] = "--verbose";
    if (skip_content_verification)
        argv[argc++] = "--no-verify";
    argv[argc++] = "--";
    argv[argc++] = escaped;
    argv[argc] = NULL;
    if (run_command(argv) != 0)
    {
        print_error("Error: Could not start the restore on a text screen. "
                    "Nothing was changed.\n");
        return -1;
    }
    printf("Continuing on a text screen.\n");
    return 0;
}

// The console on standard input, or 0 when it is not one.
static int stdin_vt(void)
{
    struct stat st;
    if (fstat(STDIN_FILENO, &st) != 0 || !S_ISCHR(st.st_mode) ||
        major(st.st_rdev) != VT_MAJOR || minor(st.st_rdev) < 1 ||
        minor(st.st_rdev) > 63)
        return 0;
    return (int)minor(st.st_rdev);
}

int console_restore_service(void)
{
    return getenv(SERVICE_ENV) != NULL && stdin_vt() != 0;
}

static void sleep_ms(long milliseconds)
{
    struct timespec delay = { milliseconds / 1000,
                              (milliseconds % 1000) * 1000000L };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
        ;
}

// Whether a process is left in uid's slice, the user's service manager
// included.
static int user_slice_populated(uid_t uid)
{
    char path[PATH_MAX], events[256];
    snprintf(path, sizeof(path),
             "/sys/fs/cgroup/user.slice/user-%lu.slice/cgroup.events",
             (unsigned long)uid);
    return read_text(path, events, sizeof(events)) == 0 &&
           strstr(events, "populated 1") != NULL;
}

int console_restore_take_over(void)
{
    // The desktop run removes its log as it exits.
    long desktop_run = strtol(getenv(SERVICE_ENV), NULL, 10);
    for (int waited = 0; desktop_run > 0 && waited < 100 &&
                         kill((pid_t)desktop_run, 0) == 0; waited++)
        sleep_ms(100);
    (void)unlink(BINARY);
    (void)rmdir(BINARY_DIR);

    uid_t uid;
    gid_t gid;
    char *stop[] = { "systemctl", "stop", "display-manager.service", NULL };
    if (sudo_invoker(&uid, &gid, NULL) != 1 || run_command(stop) != 0)
    {
        print_error("Error: Could not close the desktop. Nothing was "
                    "changed.\n");
        return -1;
    }
    // Some display managers leave the session running.
    char user[32];
    snprintf(user, sizeof(user), "%lu", (unsigned long)uid);
    char *terminate[] = { "loginctl", "terminate-user", user, NULL };
    (void)run_command(terminate);
    for (int waited = 0; user_slice_populated(uid); waited++)
    {
        if (waited == 300)
        {
            print_warning("  Warning: some of your programs are still "
                          "running and may write over restored files.\n");
            break;
        }
        sleep_ms(100);
    }

    // Stopping the display manager shows another console.
    int vt = stdin_vt();
    if (ioctl(STDIN_FILENO, VT_ACTIVATE, vt) != 0 ||
        ioctl(STDIN_FILENO, VT_WAITACTIVE, vt) != 0)
    {
        print_error("Error: Could not show the text screen. Nothing was "
                    "changed.\n");
        return -1;
    }
    return 0;
}

void console_restore_finish(void)
{
    printf("\nPress Enter to return to the login screen. ");
    fflush(stdout);
    // Keys pressed while the restore ran do not count.
    tcflush(STDIN_FILENO, TCIFLUSH);
    int c;
    while ((c = getchar()) != EOF && c != '\n')
        ;
}

#ifdef CONSOLE_TEST_HOOKS
int console_test_graphical_session(const char *sessions_dir,
                                   const char *cgroup, uid_t uid)
{
    return graphical_session(sessions_dir, cgroup, uid);
}

int console_test_free_vt(unsigned short in_use)
{
    return free_vt(in_use);
}

int console_test_escape(const char *text, char *out, size_t size)
{
    return escape_dollars(text, out, size);
}
#endif
