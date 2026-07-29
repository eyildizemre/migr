#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include "restore.h"
#include "detect.h"
#include "fileops.h"
#include "manifest.h"
#include "utils.h"
#include "xdg.h"

// Used only for packages.txt, which is read directly (fopen), never through
// the restore_native_at() core -- out of scope for the fd-anchoring below.
static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

// Returns 1 if restored (or safely previewed), 0 if absent, and -1 if the
// source or destination fails the native-restore contract.
static int restore_home_item(const CloneContext *ctx, int source_root_fd,
                             int home_fd, const char *rel_path)
{
    RestoreSourceStatus status =
        restore_native_source_status_at(source_root_fd, rel_path);
    if (status == RESTORE_SOURCE_MISSING)
        return 0;
    if (status == RESTORE_SOURCE_ERROR)
    {
        printf("Error: Failed to inspect %s\n", rel_path);
        return -1;
    }

    if (dry_run)
    {
        if (restore_native_preflight_at(ctx, source_root_fd, rel_path,
                                        home_fd, rel_path) != 0)
        {
            printf("Error: Failed to restore %s\n", rel_path);
            return -1;
        }
        printf("  Would restore: %s\n", rel_path);
        return 1;
    }

    if (verbose)
        printf("  Restoring: %s\n", rel_path);

    if (restore_native_at(ctx, source_root_fd, rel_path, home_fd, rel_path) != 0)
    {
        printf("Error: Failed to restore %s\n", rel_path);
        return -1;
    }
    return 1;
}

// Existing XDG destinations are caller-selected trust roots and may themselves
// be symlinks or live outside HOME. If only the final component is absent, its
// parent becomes the trust root and the fd-anchored core creates the leaf.
static int open_xdg_destination_anchor(const char *path, int *out_fd,
                                       char *out_rel, size_t rel_size)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0)
    {
        *out_fd = fd;
        out_rel[0] = '\0';
        return 0;
    }
    if (errno != ENOENT)
        return -1;

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    size_t len = strlen(copy);
    while (len > 1 && copy[len - 1] == '/')
        copy[--len] = '\0';

    char *slash = strrchr(copy, '/');
    const char *leaf = slash == NULL ? copy : slash + 1;
    size_t leaf_len = strlen(leaf);
    if (leaf_len == 0 || leaf_len >= rel_size)
    {
        free(copy);
        return -1;
    }
    memcpy(out_rel, leaf, leaf_len + 1);

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
    if (fd < 0)
        return -1;

    *out_fd = fd;
    return 0;
}

int restore(const char *source)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    struct stat st;
    if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        printf("Error: Source directory not found: %s\n", source);
        return 1;
    }

    if (dry_run)
    {
        printf("Dry run mode enabled. No changes will be made.\n\n");
    }
    else if (!confirm_action("This will restore files to your home directory. Continue?"))
    {
        printf("Cancelled.\n");
        return 0;
    }

    printf("Restoring from: %s\n\n", source);

    // Resolve XDG dirs on the target (destination) system.
    // manifest.txt from the backup records the source locale's directory names, so
    // cross-locale restores (e.g. Turkish backup → English system) map correctly.
    // If the manifest is absent (old backup), fall back to the target basename.
    static const char * const xdg_keys[]      = {
        "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR", "XDG_PICTURES_DIR",
        "XDG_DESKTOP_DIR",   "XDG_VIDEOS_DIR",   "XDG_MUSIC_DIR"
    };
    static const char * const xdg_fallbacks[] = {
        "Documents", "Downloads", "Pictures",
        "Desktop",   "Videos",   "Music"
    };
    enum { XDG_RESTORE_COUNT = 6 };
    char *xdg_dirs[XDG_RESTORE_COUNT];
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT) != 0)
    {
        printf("Error: HOME path too long to resolve user directories\n");
        for (int i = 0; i < XDG_RESTORE_COUNT; i++)
            free(xdg_dirs[i]);
        return 1;
    }

    // Opened once each and reused for every restore_native_at() call below --
    // the trust boundary the fd-anchored core is built on (docs/DECISIONS.md
    // D15 and D16). Read-only opens, harmless even in dry-run mode.
    // Deliberately placed after xdg_resolve(): its own length-based refusal
    // (checked above) must still be what a pathologically long HOME reports.
    int source_root_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_root_fd < 0)
    {
        printf("Error: Could not open source directory: %s\n", source);
        for (int i = 0; i < XDG_RESTORE_COUNT; i++)
            free(xdg_dirs[i]);
        return 1;
    }
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0)
    {
        printf("Error: Could not open home directory: %s\n", home);
        close(source_root_fd);
        for (int i = 0; i < XDG_RESTORE_COUNT; i++)
            free(xdg_dirs[i]);
        return 1;
    }

    char *manifest_names[XDG_RESTORE_COUNT];
    int has_manifest = (legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT) == 0);

    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    int count = 0;
    int had_error = 0;

    // Restore always writes a native tree here; a portable source is a later phase.
    CloneContext ctx = { .operation = CLONE_RESTORE, .representation = CLONE_NATIVE_TREE };

    printf("[Main Directories]\n");
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        // The manifest name locates the source-locale directory; xdg_dirs[i] is the
        // destination-locale path. Fall back to its basename if the manifest/key is absent.
        const char *name;
        if (has_manifest && manifest_names[i] != NULL)
            name = manifest_names[i];
        else
        {
            const char *p = strrchr(xdg_dirs[i], '/');
            name = p ? p + 1 : xdg_dirs[i];
        }

        RestoreSourceStatus source_status =
            restore_native_source_status_at(source_root_fd, name);
        if (source_status == RESTORE_SOURCE_MISSING)
            continue;
        if (source_status == RESTORE_SOURCE_ERROR)
        {
            printf("Error: Failed to inspect %s\n", name);
            had_error = 1;
            continue;
        }

        int xdg_dest_fd;
        char destination_rel[NAME_MAX + 1];
        if (open_xdg_destination_anchor(xdg_dirs[i], &xdg_dest_fd,
                                        destination_rel,
                                        sizeof(destination_rel)) != 0)
        {
            printf("Error: Failed to restore %s\n", name);
            had_error = 1;
            continue;
        }

        if (!dry_run && verbose)
            printf("  Restoring: %s\n", name);

        int restore_rc = dry_run
            ? restore_native_preflight_at(&ctx, source_root_fd, name,
                                          xdg_dest_fd, destination_rel)
            : restore_native_at(&ctx, source_root_fd, name,
                                xdg_dest_fd, destination_rel);
        if (restore_rc != 0)
        {
            printf("Error: Failed to restore %s\n", name);
            had_error = 1;
        }
        else
        {
            if (dry_run)
                printf("  Would restore: %s -> %s/\n", name, xdg_dirs[i]);
            count++;
        }

        close(xdg_dest_fd);
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(xdg_dirs[i]);

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);

    // Projects is not a standard XDG directory
    int restore_result =
        restore_home_item(&ctx, source_root_fd, home_fd, "Projects");
    if (restore_result > 0)
        count++;
    else if (restore_result < 0)
        had_error = 1;

    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        restore_result =
            restore_home_item(&ctx, source_root_fd, home_fd, dotfiles[i]);
        if (restore_result > 0)
            count++;
        else if (restore_result < 0)
            had_error = 1;
    }

    const char *browser_configs[] = {
        ".mozilla",
        ".config/google-chrome",
        ".config/chromium",
        ".config/BraveSoftware",
        ".config/vivaldi",
        ".config/microsoft-edge",
        ".config/opera",
        NULL
    };

    printf("\n[Browser Profiles]\n");
    for (int i = 0; browser_configs[i] != NULL; i++)
    {
        restore_result =
            restore_home_item(&ctx, source_root_fd, home_fd,
                              browser_configs[i]);
        if (restore_result > 0)
            count++;
        else if (restore_result < 0)
            had_error = 1;
    }

    char pkg_path[PATH_MAX];
    if (path_join(pkg_path, sizeof(pkg_path), source, "packages.txt") != 0)
    {
        printf("  Warning: package list path too long, skipping\n");
        had_error = 1;
    }
    else if (file_exists(pkg_path))
    {
        printf("\n[Packages]\n");

        distro_t distro = detect_distro();

        if (distro == DISTRO_UNKNOWN)
        {
            printf("Warning: Unrecognized distro, skipping package install.\n");
        }
        else if (dry_run)
        {
            printf("  Would install packages from: %s\n", pkg_path);
        }
        else
        {
            printf("Installing packages (this may take a while)...\n");

            FILE *pkg_file = fopen(pkg_path, "r");
            if (pkg_file == NULL)
            {
                printf("Error: Could not read %s\n", pkg_path);
            }
            else
            {
                int pkg_cap = 256;
                int pkg_count = 0;
                char **pkgs = malloc(pkg_cap * sizeof(char *));

                if (pkgs != NULL)
                {
                    char line[512];
                    char pkg_name[256];

                    while (fgets(line, sizeof(line), pkg_file) != NULL)
                    {
                        if (sscanf(line, "%255s", pkg_name) != 1)
                            continue;

                        // Preserve compatibility with old dpkg "pkg\tstatus" backups by
                        // skipping deinstall entries. Current backups contain plain names;
                        // see docs/DECISIONS.md D12.
                        char *tab = strchr(line, '\t');
                        if (tab != NULL && strncmp(tab + 1, "install", 7) != 0)
                            continue;

                        if (pkg_count == pkg_cap)
                        {
                            pkg_cap *= 2;
                            char **tmp = realloc(pkgs, pkg_cap * sizeof(char *));
                            if (tmp == NULL) break;
                            pkgs = tmp;
                        }
                        pkgs[pkg_count] = strdup(pkg_name);
                        if (pkgs[pkg_count] != NULL)
                            pkg_count++;
                    }
                }
                fclose(pkg_file);

                char *batch_prefix[6];
                int prefix = 0;
                switch (distro)
                {
                    case DISTRO_DEBIAN:
                        batch_prefix[0] = "sudo";
                        batch_prefix[1] = "apt-get";
                        batch_prefix[2] = "install";
                        batch_prefix[3] = "-y";
                        batch_prefix[4] = "-m";
                        prefix = 5;
                        break;
                    case DISTRO_FEDORA:
                        batch_prefix[0] = "sudo";
                        batch_prefix[1] = "dnf";
                        batch_prefix[2] = "install";
                        batch_prefix[3] = "-y";
                        prefix = 4;
                        break;
                    case DISTRO_ARCH:
                        batch_prefix[0] = "sudo";
                        batch_prefix[1] = "pacman";
                        batch_prefix[2] = "-S";
                        batch_prefix[3] = "--needed";
                        batch_prefix[4] = "--noconfirm";
                        prefix = 5;
                        break;
                    default: break;
                }

                int installed = 0, skipped = 0;

                if (pkgs != NULL && pkg_count > 0 && prefix > 0)
                {
                    // Try one batch first; fall back per package below.
                    // See docs/DECISIONS.md D2.
                    char **batch_argv = malloc((prefix + pkg_count + 1) * sizeof(char *));
                    if (batch_argv != NULL)
                    {
                        for (int i = 0; i < prefix; i++)
                            batch_argv[i] = batch_prefix[i];
                        for (int i = 0; i < pkg_count; i++)
                            batch_argv[prefix + i] = pkgs[i];
                        batch_argv[prefix + pkg_count] = NULL;

                        int rc = run_command((char *const *)batch_argv);
                        free(batch_argv);

                        if (rc == 0)
                        {
                            installed = pkg_count;
                        }
                        else
                        {
                            // Phase 2: per-package fallback, track failures
                            char skipped_path[PATH_MAX];
                            int can_write_skip_log =
                                path_join(skipped_path, sizeof(skipped_path), home,
                                          "skipped-packages.txt") == 0;
                            FILE *skipped_f = NULL;

                            for (int i = 0; i < pkg_count; i++)
                            {
                                char *install_cmd[8];
                                switch (distro)
                                {
                                    case DISTRO_DEBIAN:
                                        install_cmd[0] = "sudo";
                                        install_cmd[1] = "apt-get";
                                        install_cmd[2] = "install";
                                        install_cmd[3] = "-y";
                                        install_cmd[4] = "-m";
                                        install_cmd[5] = pkgs[i];
                                        install_cmd[6] = NULL;
                                        break;
                                    case DISTRO_FEDORA:
                                        install_cmd[0] = "sudo";
                                        install_cmd[1] = "dnf";
                                        install_cmd[2] = "install";
                                        install_cmd[3] = "-y";
                                        install_cmd[4] = pkgs[i];
                                        install_cmd[5] = NULL;
                                        break;
                                    case DISTRO_ARCH:
                                        install_cmd[0] = "sudo";
                                        install_cmd[1] = "pacman";
                                        install_cmd[2] = "-S";
                                        install_cmd[3] = "--needed";
                                        install_cmd[4] = "--noconfirm";
                                        install_cmd[5] = pkgs[i];
                                        install_cmd[6] = NULL;
                                        break;
                                    default:
                                        install_cmd[0] = NULL;
                                        break;
                                }

                                if (install_cmd[0] == NULL) continue;

                                if (run_command((char *const *)install_cmd) != 0)
                                {
                                    if (!can_write_skip_log)
                                    {
                                        if (skipped == 0)
                                            printf("Error: Could not write skipped package log\n");
                                        had_error = 1;
                                    }
                                    else if (skipped_f == NULL)
                                    {
                                        skipped_f = fopen(skipped_path, "w");
                                        if (skipped_f == NULL)
                                        {
                                            printf("Error: Could not write skipped package log\n");
                                            can_write_skip_log = 0;
                                            had_error = 1;
                                        }
                                    }
                                    if (skipped_f != NULL)
                                        fprintf(skipped_f, "%s\n", pkgs[i]);
                                    skipped++;
                                }
                                else
                                {
                                    installed++;
                                }
                            }

                            if (skipped_f != NULL)
                            {
                                fclose(skipped_f);
                                printf("  Skipped packages written to: %s\n", skipped_path);
                            }
                        }
                    }
                }

                if (pkgs != NULL)
                {
                    for (int i = 0; i < pkg_count; i++)
                        free(pkgs[i]);
                    free(pkgs);
                }

                printf("  %d installed, %d skipped.\n", installed, skipped);
            }
        }
    }
    else
    {
        printf("\nNote: packages.txt not found, skipping package restore.\n");
    }

    printf("\n===========================================================\n");
    if (dry_run && had_error)
        printf("Dry run finished with errors: %d items would be restored, some items failed validation\n",
               count);
    else if (dry_run)
        printf("Dry run complete: %d items would be restored\n", count);
    else if (had_error)
        printf("Restore finished with errors: %d items restored, some items failed\n", count);
    else
        printf("Restore complete: %d items restored\n", count);
    printf("===========================================================\n");

    close(home_fd);
    close(source_root_fd);
    return had_error ? 1 : 0;
}
