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
#include "container.h"
#include "detect.h"
#include "fileops.h"
#include "manifest.h"
#include "utils.h"
#include "xdg.h"

// The canonical XDG key/fallback table (xdg.h) is shared by both restore
// paths: legacy records them as "KEY=value" lines in an unversioned
// manifest.txt; a v1 manifest records them as root-table entries whose id is
// one of these same keys (docs/DECISIONS.md D16).
#define XDG_RESTORE_COUNT XDG_KEY_COUNT

static int xdg_key_index(const char *id)
{
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        if (strcmp(id, xdg_keys[i]) == 0)
            return i;
    return -1;
}

static void free_xdg_dirs(char **dirs)
{
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(dirs[i]);
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
                           const char *label, int source_required)
{
    RestoreSourceStatus status = restore_native_source_status_at(source_root_fd, source_rel);
    if (status == RESTORE_SOURCE_MISSING)
    {
        if (source_required)
        {
            printf("Error: Manifest root %s is missing its declared payload\n", label);
            return -1;
        }
        return 0;
    }
    if (status == RESTORE_SOURCE_ERROR)
    {
        printf("Error: Failed to inspect %s\n", label);
        return -1;
    }

    if (dry_run)
    {
        if (restore_native_preflight_at(ctx, source_root_fd, source_rel, dest_root_fd, dest_rel) != 0)
        {
            printf("Error: Failed to restore %s\n", label);
            return -1;
        }
        return 1;
    }

    if (verbose)
        printf("  Restoring: %s\n", label);

    if (restore_native_at(ctx, source_root_fd, source_rel, dest_root_fd, dest_rel) != 0)
    {
        printf("Error: Failed to restore %s\n", label);
        return -1;
    }
    return 1;
}

// A backup-relative path restored directly into home under the same name on
// both sides (legacy's Projects/dotfiles/browser-config items).
static int restore_home_item(const CloneContext *ctx, int source_root_fd, int home_fd, const char *rel_path)
{
    int rc = restore_item_at(ctx, source_root_fd, rel_path, home_fd, rel_path,
                             rel_path, 0);
    if (rc > 0 && dry_run)
        printf("  Would restore: %s\n", rel_path);
    return rc;
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

// Restores XDG main directories, Projects, dotfiles, and browser profiles
// from an unversioned or manifest-absent backup. This path preserves the
// legacy layout and its all-or-nothing XDG destination resolution.
static int restore_legacy(const char *source, int source_root_fd, const char *home, int home_fd,
                          const CloneContext *ctx, int *count, int *had_error)
{
    printf("[Main Directories]\n");
    char *xdg_dirs[XDG_RESTORE_COUNT];
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT) != 0)
    {
        printf("Error: HOME path too long to resolve user directories\n");
        free_xdg_dirs(xdg_dirs);
        *had_error = 1;
        return -1;
    }
    else
    {
        char *manifest_names[XDG_RESTORE_COUNT];
        int has_manifest = (legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT) == 0);

        for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        {
            // The manifest name locates the source-locale directory; xdg_dirs[i] is
            // the destination-locale path. Fall back to its basename if absent.
            const char *name;
            if (has_manifest && manifest_names[i] != NULL)
                name = manifest_names[i];
            else
            {
                const char *p = strrchr(xdg_dirs[i], '/');
                name = p ? p + 1 : xdg_dirs[i];
            }

            RestoreSourceStatus source_status = restore_native_source_status_at(source_root_fd, name);
            if (source_status == RESTORE_SOURCE_MISSING)
                continue;
            if (source_status == RESTORE_SOURCE_ERROR)
            {
                printf("Error: Failed to inspect %s\n", name);
                *had_error = 1;
                continue;
            }

            // xdg_dirs[i] may be any absolute path (see xdg_resolve()'s contract),
            // not necessarily under home: open (creating if needed) its own
            // directory fd and restore into it directly as the destination root
            // itself ("", docs/DECISIONS.md D16), rather than assuming it is
            // reachable via home_fd.
            int xdg_dest_fd;
            char destination_rel[NAME_MAX + 1];
            if (open_xdg_destination_anchor(xdg_dirs[i], &xdg_dest_fd, destination_rel, sizeof(destination_rel)) != 0)
            {
                printf("Error: Failed to restore %s\n", name);
                *had_error = 1;
                continue;
            }

            int rc = restore_item_at(ctx, source_root_fd, name, xdg_dest_fd,
                                     destination_rel, name, 0);
            if (rc > 0 && dry_run)
                printf("  Would restore: %s -> %s/\n", name, xdg_dirs[i]);
            if (rc > 0)
                (*count)++;
            else if (rc < 0)
                *had_error = 1;

            close(xdg_dest_fd);
        }

        if (has_manifest)
            for (int i = 0; i < XDG_RESTORE_COUNT; i++)
                free(manifest_names[i]);
        free_xdg_dirs(xdg_dirs);
    }

    // Projects is not a standard XDG directory
    int rc = restore_home_item(ctx, source_root_fd, home_fd, "Projects");
    if (rc > 0)
        (*count)++;
    else if (rc < 0)
        *had_error = 1;

    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};
    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        rc = restore_home_item(ctx, source_root_fd, home_fd, dotfiles[i]);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
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
        rc = restore_home_item(ctx, source_root_fd, home_fd, browser_configs[i]);
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
            printf("Error: Manifest root %s has an invalid payload address\n",
                   root->id);
            failed = 1;
            continue;
        }

        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, source_rel);
        if (status == RESTORE_SOURCE_MISSING)
        {
            printf("Error: Manifest root %s is missing its declared payload\n",
                   root->id);
            failed = 1;
        }
        else if (status == RESTORE_SOURCE_ERROR)
        {
            printf("Error: Could not safely inspect payload for manifest root %s\n",
                   root->id);
            failed = 1;
        }
    }

    return failed ? -1 : 0;
}

// Restores a valid native v1 manifest's root table (docs/DECISIONS.md D15,
// D16). HOME_RELATIVE roots restore beneath home, XDG roots map to the target
// locale, and MANUAL_NATIVE roots are reported without being auto-restored.
static void restore_v1(const char *source, int source_root_fd, const char *home, int home_fd,
                       const CloneContext *ctx, const Manifest *m, int *count, int *had_error)
{
    printf("[Roots]\n");

    char *xdg_dirs[XDG_RESTORE_COUNT];
    int xdg_dirs_ready = 0;
    int xdg_dirs_failed = 0;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue; // reported separately below; never auto-restored

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            printf("Error: Failed to restore %s\n", root->id);
            *had_error = 1;
            continue;
        }

        if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            int rc = restore_item_at(ctx, source_root_fd, source_rel, home_fd,
                                     root->restore_path, root->id, 1);
            if (rc > 0 && dry_run)
            {
                if (root->restore_path[0] != '\0')
                    printf("  Would restore: %s -> ~/%s\n", root->id, root->restore_path);
                else
                    printf("  Would restore: %s -> ~\n", root->id);
            }
            if (rc > 0)
                (*count)++;
            else if (rc < 0)
                *had_error = 1;
            continue;
        }

        // ROOT_POLICY_XDG: resolved lazily, once, only if a manifest actually
        // has an XDG-policy root -- an EXPLICIT-scope backup may have none.
        if (!xdg_dirs_ready && !xdg_dirs_failed)
        {
            if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT) == 0)
                xdg_dirs_ready = 1;
            else
            {
                free_xdg_dirs(xdg_dirs);
                xdg_dirs_failed = 1;
                printf("Error: HOME path too long to resolve user directories\n");
            }
        }
        if (xdg_dirs_failed)
        {
            *had_error = 1;
            continue;
        }

        int idx = xdg_key_index(root->id);
        if (idx < 0)
        {
            printf("Error: Unrecognized XDG root id: %s\n", root->id);
            *had_error = 1;
            continue;
        }

        int xdg_dest_fd;
        char destination_rel[NAME_MAX + 1];
        if (open_xdg_destination_anchor(xdg_dirs[idx], &xdg_dest_fd, destination_rel, sizeof(destination_rel)) != 0)
        {
            printf("Error: Failed to restore %s\n", root->id);
            *had_error = 1;
            continue;
        }

        int rc = restore_item_at(ctx, source_root_fd, source_rel, xdg_dest_fd,
                                 destination_rel, root->id, 1);
        if (rc > 0 && dry_run)
            printf("  Would restore: %s -> %s/\n", root->id, xdg_dirs[idx]);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
        close(xdg_dest_fd);
    }

    if (xdg_dirs_ready)
        free_xdg_dirs(xdg_dirs);

    int manual_count = 0;
    for (int i = 0; i < m->root_count; i++)
        if (m->roots[i].policy == ROOT_POLICY_MANUAL_NATIVE)
            manual_count++;

    if (manual_count > 0)
    {
        printf("\n[Manual Roots]\n");
        printf("  Not restored automatically; recover these from the backup directly.\n");
        for (int i = 0; i < m->root_count; i++)
        {
            const ManifestRoot *root = &m->roots[i];
            if (root->policy != ROOT_POLICY_MANUAL_NATIVE)
                continue;

            char source_rel[PATH_MAX + 8];
            if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
            {
                printf("Error: Manifest root %s has an invalid payload address\n",
                       root->id);
                *had_error = 1;
                continue;
            }
            RestoreSourceStatus status =
                restore_native_source_status_at(source_root_fd, source_rel);
            if (status != RESTORE_SOURCE_PRESENT)
            {
                printf("Error: Manifest root %s no longer has a readable payload\n",
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

// Reads and processes packages.txt from the container root (never inside
// data/: it is a control artifact, not payload, in both legacy and v1
// layouts). Opened by directory fd with O_NOFOLLOW + O_NONBLOCK -- the same
// discipline manifest.c uses for manifest.txt: a symlinked packages.txt is
// never followed into an arbitrary location, and a FIFO there can never
// hang this call waiting for a writer that will never come.
static void restore_packages(int source_root_fd, const char *home, int *had_error)
{
    int fd = openat(source_root_fd, "packages.txt", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno == ENOENT)
            printf("\nNote: packages.txt not found, skipping package restore.\n");
        else
        {
            printf("Error: Could not read packages.txt\n");
            *had_error = 1;
        }
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        printf("Error: Could not inspect packages.txt\n");
        *had_error = 1;
        return;
    }
    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        printf("Warning: packages.txt is not a regular file, skipping package restore.\n");
        return;
    }

    FILE *pkg_file = fdopen(fd, "r");
    if (pkg_file == NULL)
    {
        close(fd);
        printf("Error: Could not read packages.txt\n");
        *had_error = 1;
        return;
    }

    printf("\n[Packages]\n");

    distro_t distro = detect_distro();

    if (distro == DISTRO_UNKNOWN)
    {
        printf("Warning: Unrecognized distro, skipping package install.\n");
        fclose(pkg_file);
        return;
    }
    if (dry_run)
    {
        printf("  Would install packages from packages.txt\n");
        fclose(pkg_file);
        return;
    }

    printf("Installing packages (this may take a while)...\n");

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
                            *had_error = 1;
                        }
                        else if (skipped_f == NULL)
                        {
                            skipped_f = fopen(skipped_path, "w");
                            if (skipped_f == NULL)
                            {
                                printf("Error: Could not write skipped package log\n");
                                can_write_skip_log = 0;
                                *had_error = 1;
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

    // A live or abandoned ".partial" container (docs/DECISIONS.md D15) is
    // never a valid restore source: an interrupted backup may be incomplete,
    // and a still-active one may be locked by another process. Trailing
    // slashes are stripped first so they cannot hide the leaf name.
    char source_copy[PATH_MAX];
    if ((size_t)snprintf(source_copy, sizeof(source_copy), "%s", source) >= sizeof(source_copy))
    {
        printf("Error: Source path too long: %s\n", source);
        return 1;
    }
    size_t source_len = strlen(source_copy);
    while (source_len > 1 && source_copy[source_len - 1] == '/')
        source_copy[--source_len] = '\0';
    const char *source_leaf = strrchr(source_copy, '/');
    source_leaf = source_leaf ? source_leaf + 1 : source_copy;
    if (container_name_is_partial(source_leaf))
    {
        printf("Error: %s is an in-progress or abandoned backup container, not a finished one.\n", source);
        return 1;
    }
    int source_is_versioned_final = container_name_is_final(source_leaf);

    int source_root_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_root_fd < 0)
    {
        printf("Error: Could not open source directory: %s\n", source);
        return 1;
    }

    // Classified before any confirmation or filesystem mutation: an unknown
    // version or malformed manifest refuses the whole restore outright,
    // rather than guessing or partially proceeding.
    Manifest m;
    ManifestStatus mst = manifest_read_v1_at(source_root_fd, &m);
    if (mst == MANIFEST_STATUS_UNKNOWN_VERSION)
    {
        printf("Error: manifest.txt records a format version this build does not understand; refusing to guess.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_MALFORMED)
    {
        printf("Error: manifest.txt is malformed; refusing to restore.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_IO_ERROR)
    {
        printf("Error: Could not read manifest.txt.\n");
        close(source_root_fd);
        return 1;
    }
    // mst is now MISSING, LEGACY, or VALID.

    if (source_is_versioned_final && mst == MANIFEST_STATUS_MISSING)
    {
        printf("Error: A finalized versioned container is missing manifest.txt; refusing to treat it as a legacy backup.\n");
        close(source_root_fd);
        return 1;
    }
    if (source_is_versioned_final && mst == MANIFEST_STATUS_LEGACY)
    {
        printf("Error: A finalized versioned container carries a legacy manifest; refusing to guess its layout.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_VALID &&
        m.representation != CLONE_NATIVE_TREE)
    {
        printf("Error: Portable backup restore is not implemented yet; refusing to interpret portable payload as native.\n");
        manifest_free(&m);
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_VALID &&
        validate_v1_payloads(source_root_fd, &m) != 0)
    {
        manifest_free(&m);
        close(source_root_fd);
        return 1;
    }

    if (dry_run)
    {
        printf("Dry run mode enabled. No changes will be made.\n\n");
    }
    else if (!confirm_action("This will restore files to your home directory. Continue?"))
    {
        printf("Cancelled.\n");
        if (mst == MANIFEST_STATUS_VALID)
            manifest_free(&m);
        close(source_root_fd);
        return 0;
    }

    printf("Restoring from: %s\n\n", source);

    // Opened once and reused for every restore_native_at() call below -- the
    // trust boundary the fd-anchored core is built on (docs/DECISIONS.md D15
    // and D16). Read-only, harmless even in dry-run mode. A path this long
    // (ENAMETOOLONG) is what xdg_resolve() below would also refuse on, so
    // that specific case gets the same "HOME path too long" wording.
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0)
    {
        if (errno == ENAMETOOLONG)
            printf("Error: HOME path too long to resolve user directories\n");
        else
            printf("Error: Could not open home directory: %s\n", home);
        if (mst == MANIFEST_STATUS_VALID)
            manifest_free(&m);
        close(source_root_fd);
        return 1;
    }

    int count = 0;
    int had_error = 0;

    // Restore always writes a native tree here; a portable source is a later phase.
    CloneContext ctx = { .operation = CLONE_RESTORE, .representation = CLONE_NATIVE_TREE };

    if (mst == MANIFEST_STATUS_VALID)
    {
        restore_v1(source, source_root_fd, home, home_fd, &ctx, &m, &count, &had_error);
        manifest_free(&m);
    }
    else
    {
        if (restore_legacy(source, source_root_fd, home, home_fd, &ctx,
                           &count, &had_error) != 0)
        {
            close(home_fd);
            close(source_root_fd);
            return 1;
        }
    }

    restore_packages(source_root_fd, home, &had_error);

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
