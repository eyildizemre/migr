#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#include "restore.h"
#include "detect.h"
#include "fileops.h"
#include "manifest.h"
#include "utils.h"
#include "xdg.h"

static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

static int clone_to_home(const char *src, const char *home)
{
    // Resolve the destination before the dry-run branch so a path that would be
    // refused live is refused in dry-run too: the preview must match reality.
    const char *name = strrchr(src, '/');
    name = name ? name + 1 : src;

    char full_dest[PATH_MAX];
    if (path_join(full_dest, sizeof(full_dest), home, name) != 0)
    {
        printf("Error: Failed to restore %s\n", src);
        return 1;
    }

    if (dry_run)
    {
        printf("  Would restore: %s -> %s\n", src, full_dest);
        return 0;
    }

    if (verbose)
        printf("  Restoring: %s\n", src);

    if (clone_recursive(src, full_dest) != 0)
    {
        printf("Error: Failed to restore %s\n", src);
        return 1;
    }
    return 0;
}

// Restore a backup-relative path (e.g. ".config/google-chrome") back into home,
// creating any intermediate parent directories as needed.
// Returns 1 if restored, 0 if not in backup, -1 on error.
static int restore_nested(const char *source, const char *home, const char *rel_path)
{
    char src[PATH_MAX], dest[PATH_MAX];
    if (path_join(src, sizeof(src), source, rel_path) != 0)
        return -1;

    if (!file_exists(src))
        return 0;

    if (path_join(dest, sizeof(dest), home, rel_path) != 0)
        return -1;

    const char *slash = strrchr(rel_path, '/');
    if (slash)
    {
        char parent[PATH_MAX];
        if (path_join_n(parent, sizeof(parent), home, rel_path, (size_t)(slash - rel_path)) != 0)
            return -1;
        if (!file_exists(parent))
        {
            if (dry_run)
            {
                printf("  Would create: %s\n", parent);
            }
            else if (mkdir(parent, 0755) != 0)
            {
                printf("Error: Could not create directory %s\n", parent);
                return -1;
            }
        }
    }

    if (dry_run)
    {
        printf("  Would restore: %s -> %s\n", src, dest);
        return 1;
    }

    if (verbose)
        printf("  Restoring: %s\n", src);

    if (clone_recursive(src, dest) != 0)
    {
        printf("Error: Failed to restore %s\n", src);
        return -1;
    }
    return 1;
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

    char *manifest_names[XDG_RESTORE_COUNT];
    int has_manifest = (manifest_read(source, manifest_names, XDG_RESTORE_COUNT) == 0);

    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    char src_path[PATH_MAX];
    int count = 0;
    int had_error = 0;

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

        if (path_join(src_path, sizeof(src_path), source, name) != 0)
        {
            printf("  Warning: path too long, skipping: %s/%s\n", source, name);
            had_error = 1;
            continue;
        }
        if (file_exists(src_path))
        {
            if (dry_run)
            {
                printf("  Would restore: %s -> %s/\n", src_path, xdg_dirs[i]);
                count++;
            }
            else
            {
                if (verbose)
                    printf("  Restoring: %s\n", src_path);
                if (clone_recursive(src_path, xdg_dirs[i]) != 0)
                {
                    printf("Error: Failed to restore %s\n", src_path);
                    had_error = 1;
                }
                else
                    count++;
            }
        }
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(xdg_dirs[i]);

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);

    // Projects is not a standard XDG directory
    if (path_join(src_path, sizeof(src_path), source, "Projects") != 0)
    {
        printf("  Warning: path too long, skipping: %s/Projects\n", source);
        had_error = 1;
    }
    else if (file_exists(src_path))
    {
        if (clone_to_home(src_path, home) == 0)
            count++;
        else
            had_error = 1;
    }

    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        if (path_join(src_path, sizeof(src_path), source, dotfiles[i]) != 0)
        {
            printf("  Warning: path too long, skipping: %s/%s\n", source, dotfiles[i]);
            had_error = 1;
            continue;
        }
        if (file_exists(src_path))
        {
            if (clone_to_home(src_path, home) == 0)
                count++;
            else
                had_error = 1;
        }
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
        int r = restore_nested(source, home, browser_configs[i]);
        if (r > 0)
            count++;
        else if (r < 0)
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

    return had_error ? 1 : 0;
}
