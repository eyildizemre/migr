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
    if (dry_run)
    {
        printf("  Would restore: %s -> %s/\n", src, home);
        return 0;
    }

    if (verbose)
    {
        printf("  Restoring: %s\n", src);
    }

    const char *name = strrchr(src, '/');
    name = name ? name + 1 : src;

    char full_dest[PATH_MAX];
    snprintf(full_dest, sizeof(full_dest), "%s/%s", home, name);

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
    snprintf(src, sizeof(src), "%s/%s", source, rel_path);

    if (!file_exists(src))
        return 0;

    snprintf(dest, sizeof(dest), "%s/%s", home, rel_path);

    const char *slash = strrchr(rel_path, '/');
    if (slash)
    {
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s/%.*s", home, (int)(slash - rel_path), rel_path);
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

    // check source directory exists
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
    xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT);

    char *manifest_names[XDG_RESTORE_COUNT];
    int has_manifest = (manifest_read(source, manifest_names, XDG_RESTORE_COUNT) == 0);

    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};

    char src_path[PATH_MAX];
    int count = 0;

    printf("[Main Directories]\n");
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        // Use the manifest-recorded name (source locale) to locate the backup directory,
        // then restore to xdg_dirs[i] (destination locale). Falls back to the destination
        // basename when no manifest is present (same-locale or pre-manifest backup).
        const char *name;
        if (has_manifest && manifest_names[i] != NULL)
            name = manifest_names[i];
        else
        {
            const char *p = strrchr(xdg_dirs[i], '/');
            name = p ? p + 1 : xdg_dirs[i];
        }

        snprintf(src_path, sizeof(src_path), "%s/%s", source, name);
        if (file_exists(src_path))
        {
            if (dry_run)
                printf("  Would restore: %s -> %s/\n", src_path, xdg_dirs[i]);
            else
            {
                if (verbose)
                    printf("  Restoring: %s\n", src_path);
                if (clone_recursive(src_path, xdg_dirs[i]) != 0)
                    printf("Error: Failed to restore %s\n", src_path);
            }
            count++;
        }
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(xdg_dirs[i]);

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);

    // Projects is not a standard XDG directory
    snprintf(src_path, sizeof(src_path), "%s/Projects", source);
    if (file_exists(src_path))
    {
        clone_to_home(src_path, home);
        count++;
    }

    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        snprintf(src_path, sizeof(src_path), "%s/%s", source, dotfiles[i]);
        if (file_exists(src_path))
        {
            clone_to_home(src_path, home);
            count++;
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
        if (r > 0) count++;
    }

    char pkg_path[PATH_MAX];
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", source);

    if (file_exists(pkg_path))
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
                // Collect filtered package names into a dynamic array
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

                        // Backups written before the switch to explicitly-installed
                        // package lists used `dpkg --get-selections`, whose format is
                        // "pkg\tstatus" and which includes deinstalled entries. Current
                        // backups are plain names with no tab, so this only fires for
                        // older files — kept so they still restore correctly.
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

                // Build batch command prefix per distro
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
                    // Phase 1: single batch install
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
                            snprintf(skipped_path, sizeof(skipped_path), "%s/skipped-packages.txt", home);
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
                                    if (skipped_f == NULL)
                                        skipped_f = fopen(skipped_path, "w");
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
    if (dry_run)
        printf("Dry run complete: %d items would be restored\n", count);
    else
        printf("Restore complete: %d items restored\n", count);
    printf("===========================================================\n");

    return 0;
}
