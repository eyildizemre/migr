#define _GNU_SOURCE
#include "writer_apps.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

typedef struct {
    const char *comm;
    const char *label;
    /* Below HOME: what the application owns and rewrites; NULL for none. */
    const char *settings;
} WriterApp;

// Applications whose settings the default scope covers and which rewrite
// them while running or on exit, one entry per path an application owns.
// Matched by /proc/<pid>/comm (truncated to 15 bytes by the kernel). VS Code
// updates its extensions on its own (D77). GNOME Software refreshes the
// restored Flatpak repo.
static const WriterApp writer_apps[] = {
    { "code", "Visual Studio Code", ".config/Code" },
    { "code", "Visual Studio Code", ".vscode" },
    { "codium", "VSCodium", ".config/VSCodium" },
    { "codium", "VSCodium", ".vscode-oss" },
    { "firefox", "Firefox", ".mozilla/firefox" },
    { "firefox-bin", "Firefox", ".mozilla/firefox" },
    { "brave", "Brave", ".config/BraveSoftware" },
    { "chrome", "Google Chrome", ".config/google-chrome" },
    { "chromium", "Chromium", ".config/chromium" },
    { "chromium-browse", "Chromium", ".config/chromium" },
    { "vivaldi-bin", "Vivaldi", ".config/vivaldi" },
    { "msedge", "Microsoft Edge", ".config/microsoft-edge" },
    { "opera", "Opera", ".config/opera" },
    { "gnome-software", "GNOME Software", NULL }
};

#define WRITER_APP_COUNT (sizeof(writer_apps) / sizeof(writer_apps[0]))

_Static_assert(WRITER_APP_COUNT + 24U <= WRITER_APPS_MAX,
               "WRITER_APPS_MAX leaves room for open Flatpak apps");

static const char *proc_root = "/proc";

#ifdef WRITER_APPS_TEST_HOOKS
void writer_apps_test_set_proc_root(const char *path)
{
    proc_root = path != NULL ? path : "/proc";
}
#endif

static int read_small_file_at(int dir_fd, const char *name, char *out,
                              size_t size)
{
    int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, out, size - 1U);
    close(fd);
    if (got < 0)
        return -1;
    out[got] = '\0';
    return 0;
}

static int process_uid_at(int pid_fd, uid_t *uid)
{
    char status[4096];
    if (read_small_file_at(pid_fd, "status", status, sizeof(status)) != 0)
        return -1;
    const char *line = strstr(status, "\nUid:");
    if (line == NULL)
        return -1;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(line + strlen("\nUid:"), &end, 10);
    if (errno != 0 || end == line + strlen("\nUid:"))
        return -1;
    *uid = (uid_t)value;
    return 0;
}

static void writer_add(RunningWriter *writers, size_t *count, size_t max,
                       const char *label, const char *settings)
{
    for (size_t index = 0; index < *count; index++)
        if (strcmp(writers[index].label, label) == 0 &&
            strcmp(writers[index].settings, settings) == 0)
            return;
    if (*count == max)
        return;
    snprintf(writers[*count].label, sizeof(writers[*count].label), "%s",
             label);
    snprintf(writers[*count].settings, sizeof(writers[*count].settings), "%s",
             settings);
    (*count)++;
}

// A Flatpak application runs in the systemd scope
// app-flatpak-<app-id>-<number>.scope, which /proc/<pid>/cgroup names. Its
// data lives in ~/.var/app/<app-id> (D75). Returns 1 with the id.
static int flatpak_app_id(const char *cgroup,
                          char id[WRITER_APPS_FLATPAK_ID_MAX])
{
    static const char prefix[] = "/app-flatpak-";
    const char *start = strstr(cgroup, prefix);
    const char *end = start != NULL ? strstr(start, ".scope") : NULL;
    if (end == NULL)
        return 0;
    start += sizeof(prefix) - 1U;
    const char *number = end;
    while (number > start && number[-1] != '-')
        number--;
    size_t length = number > start ? (size_t)(number - 1 - start) : 0;
    if (length == 0 || length >= WRITER_APPS_FLATPAK_ID_MAX ||
        strspn(start, "abcdefghijklmnopqrstuvwxyz"
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") < length)
        return 0;
    memcpy(id, start, length);
    id[length] = '\0';
    return 1;
}

size_t writer_apps_running(uid_t uid, RunningWriter *writers, size_t max)
{
    DIR *proc = opendir(proc_root);
    if (proc == NULL)
        return 0;
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL)
    {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9' ||
            strspn(entry->d_name, "0123456789") != strlen(entry->d_name))
            continue;
        int pid_fd = openat(dirfd(proc), entry->d_name,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (pid_fd < 0)
            continue;
        char comm[64];
        char cgroup[1024];
        uid_t owner;
        int readable = process_uid_at(pid_fd, &owner) == 0 &&
                       owner == uid &&
                       read_small_file_at(pid_fd, "comm", comm,
                                          sizeof(comm)) == 0;
        int in_cgroup = readable &&
                        read_small_file_at(pid_fd, "cgroup", cgroup,
                                           sizeof(cgroup)) == 0;
        close(pid_fd);
        if (!readable)
            continue;
        comm[strcspn(comm, "\n")] = '\0';
        for (size_t index = 0; index < WRITER_APP_COUNT; index++)
        {
            const WriterApp *app = &writer_apps[index];
            if (strcmp(comm, app->comm) == 0)
                writer_add(writers, &count, max, app->label,
                           app->settings != NULL ? app->settings : "");
        }
        char id[WRITER_APPS_FLATPAK_ID_MAX];
        char settings[sizeof(writers->settings)];
        if (in_cgroup && flatpak_app_id(cgroup, id))
        {
            snprintf(settings, sizeof(settings), ".var/app/%s", id);
            writer_add(writers, &count, max, id, settings);
        }
    }
    closedir(proc);
    return count;
}

size_t writer_apps_labels(const RunningWriter *writers, size_t count,
                          const char **labels)
{
    size_t labeled = 0;
    for (size_t index = 0; index < count; index++)
    {
        int seen = 0;
        for (size_t known = 0; known < labeled && !seen; known++)
            seen = strcmp(labels[known], writers[index].label) == 0;
        if (!seen)
            labels[labeled++] = writers[index].label;
    }
    return labeled;
}

void writer_apps_print_labels(const char *const *labels, size_t count)
{
    for (size_t index = 0; index < count; index++)
        printf("%s%s", index == 0 ? ""
                       : index + 1U == count ? " and " : ", ",
               labels[index]);
}

int writer_apps_session_uid(uid_t *uid)
{
    *uid = geteuid();
    gid_t gid;
    return sudo_invoker(uid, &gid, NULL) < 0 ? -1 : 0;
}
