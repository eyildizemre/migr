#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flatpak.h"
#include "fileops.h"
#include "packages_internal.h"
#include "utils.h"

char *flatpak_apps_collect(void)
{
    char *const list[] = {
        "flatpak", "list", "--system", "--app",
        "--columns=origin,application", NULL
    };
    char *output = malloc(PACKAGE_QUERY_BUFFER_SIZE);
    if (output == NULL)
        return NULL;
    output[0] = '\0';
    if (run_command_capture(list, output, PACKAGE_QUERY_BUFFER_SIZE) != 0 ||
        strspn(output, " \t\n") == strlen(output))
    {
        free(output);
        return NULL;
    }
    return output;
}

// Remote names and application ids as Flatpak forms them; anything else in
// a restored list is skipped, so it cannot become a flatpak option.
static int flatpak_name_is_safe(const char *name)
{
    size_t length = strlen(name);
    return length != 0 && name[0] != '-' &&
           strspn(name, "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == length;
}

typedef struct {
    char remote[256];
    char app[256];
} FlatpakApp;

static FlatpakApp *read_flatpak_apps(FILE *list, size_t *count_out,
                                     int *had_error)
{
    FlatpakApp *apps = NULL;
    size_t count = 0;
    size_t capacity = 0;
    char line[600];
    while (fgets(line, sizeof(line), list) != NULL)
    {
        FlatpakApp app = {0};
        if (sscanf(line, "%255s %255s", app.remote, app.app) != 2 ||
            !flatpak_name_is_safe(app.remote) || !flatpak_name_is_safe(app.app))
            continue;
        FlatpakApp *grown = array_reserve(apps, &capacity, count, 1U,
                                          sizeof(*apps), 16U,
                                          SIZE_MAX / sizeof(*apps));
        if (grown == NULL)
        {
            *had_error = 1;
            break;
        }
        apps = grown;
        apps[count++] = app;
    }
    if (ferror(list))
        *had_error = 1;
    *count_out = count;
    return apps;
}

// Writes under heading one install command per remote for the apps pick
// selects; nothing when it selects none.
static void flatpak_todo(FILE *todo, const char *heading,
                         const FlatpakApp *apps, size_t count, const int *pick)
{
    int wrote_heading = 0;
    for (size_t first = 0; first < count; first++)
    {
        int remote_seen = !pick[first];
        for (size_t earlier = 0; earlier < first && !remote_seen; earlier++)
            remote_seen = pick[earlier] &&
                          strcmp(apps[earlier].remote, apps[first].remote) == 0;
        if (remote_seen)
            continue;
        if (!wrote_heading)
            fprintf(todo, "  %s\n", heading);
        wrote_heading = 1;
        fprintf(todo, "    sudo flatpak install --system %s",
                apps[first].remote);
        for (size_t i = first; i < count; i++)
            if (pick[i] && strcmp(apps[i].remote, apps[first].remote) == 0)
                fprintf(todo, " %s", apps[i].app);
        fprintf(todo, "\n");
    }
}

// Installs the wanted apps of each remote in one flatpak call per remote.
static void install_flatpak_apps(const FlatpakApp *apps, size_t count,
                                 const int *wanted, int *had_error)
{
    char **argv = count <= SIZE_MAX / sizeof(*argv) - 6U
        ? malloc((count + 6U) * sizeof(*argv)) : NULL;
    int *done = calloc(count, sizeof(*done));
    if (argv == NULL || done == NULL)
    {
        print_error("Error: Could not allocate the Flatpak install batch\n");
        *had_error = 1;
        free(argv);
        free(done);
        return;
    }
    for (size_t first = 0; first < count; first++)
    {
        if (!wanted[first] || done[first])
            continue;
        size_t argc = 0;
        argv[argc++] = "flatpak";
        argv[argc++] = "install";
        argv[argc++] = "--system";
        argv[argc++] = "-y";
        argv[argc++] = (char *)apps[first].remote;
        for (size_t i = first; i < count; i++)
        {
            if (!wanted[i] || done[i] ||
                strcmp(apps[i].remote, apps[first].remote) != 0)
                continue;
            argv[argc++] = (char *)apps[i].app;
            done[i] = 1;
        }
        argv[argc] = NULL;
        (void)package_run_command(argv);
    }
    free(argv);
    free(done);
}

void restore_flatpak_apps(int source_root_fd, int online, FILE *todo,
                          int *had_error)
{
    FILE *list = NULL;
    if (package_open_control_file(source_root_fd, "flatpak-apps.txt", &list,
                          had_error) != CONTROL_FILE_OPEN)
        return;
    size_t count = 0;
    FlatpakApp *apps = read_flatpak_apps(list, &count, had_error);
    fclose(list);
    if (count == 0)
    {
        free(apps);
        return;
    }

    printf("\nFlatpak Applications\n");
    char *const remotes_query[] = {
        "flatpak", "remotes", "--system", "--columns=name", NULL
    };
    char *const installed_query[] = {
        "flatpak", "list", "--system", "--app", "--columns=application", NULL
    };
    char *remotes = malloc(PACKAGE_QUERY_BUFFER_SIZE);
    int *wanted = calloc(count, sizeof(*wanted));
    int *unreachable = calloc(count, sizeof(*unreachable));
    char *installed = NULL;
    if (remotes == NULL || wanted == NULL || unreachable == NULL)
    {
        print_error("Error: Could not allocate the Flatpak application list\n");
        *had_error = 1;
        goto done;
    }
    remotes[0] = '\0';
    if (package_capture_command(remotes_query, remotes,
                                PACKAGE_QUERY_BUFFER_SIZE) != 0)
    {
        for (size_t i = 0; i < count; i++)
            unreachable[i] = 1;
        printf("  Flatpak is not installed here; %zu application%s left "
               "out.\n", count, count == 1 ? "" : "s");
        flatpak_todo(todo, "Flatpak applications, once Flatpak is installed "
                           "and has their remotes:", apps, count, unreachable);
        goto done;
    }
    installed = package_capture_query(installed_query,
                                      "installed Flatpak applications",
                                      had_error);
    if (installed == NULL)
        goto done;

    size_t wanted_count = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (package_plain_list_contains(installed, apps[i].app))
            continue;
        if (package_plain_list_contains(remotes, apps[i].remote))
        {
            wanted[i] = 1;
            wanted_count++;
        }
        else
            unreachable[i] = 1;
    }

    if (wanted_count != 0 && dry_run)
    {
        printf("  Would install");
        for (size_t i = 0; i < count; i++)
            if (wanted[i])
                printf(" %s", apps[i].app);
        printf("\n");
    }
    else if (wanted_count != 0 && !online)
    {
        printf("  No network connection; not installing.\n");
        flatpak_todo(todo, "Flatpak applications to install once this system "
                           "is online:", apps, count, wanted);
    }
    else if (wanted_count != 0)
    {
        printf("Installing Flatpak applications (this may take a while)...\n");
        install_flatpak_apps(apps, count, wanted, had_error);
        free(installed);
        installed = package_capture_query(installed_query,
                                          "installed Flatpak applications",
                                          had_error);
        if (installed == NULL)
            goto done;
        size_t failed = 0;
        for (size_t i = 0; i < count; i++)
        {
            wanted[i] = wanted[i] &&
                        !package_plain_list_contains(installed, apps[i].app);
            failed += wanted[i];
        }
        printf("  %zu installed, %zu not installed.\n", wanted_count - failed,
               failed);
        flatpak_todo(todo, "Flatpak applications that did not install:", apps,
                     count, wanted);
    }
    else
        printf("  Every saved Flatpak application this system can reach is "
               "installed.\n");

    // Adding a remote needs its signing key, which the backup does not have,
    // so a remote the system lacks is left to the user.
    size_t unreachable_count = 0;
    for (size_t i = 0; i < count; i++)
        unreachable_count += unreachable[i];
    if (unreachable_count != 0)
        printf("  %zu application%s from remotes this system does not have "
               "left out.\n", unreachable_count,
               unreachable_count == 1 ? "" : "s");
    flatpak_todo(todo, "Flatpak applications whose remote this system does "
                       "not have; add the remote, then run:",
                 apps, count, unreachable);

done:
    free(installed);
    free(remotes);
    free(wanted);
    free(unreachable);
    free(apps);
}

