#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "packages.h"
#include "detect.h"
#include "fileops.h"
#include "utils.h"

// Runs the distro's listing command and returns its whole output. Both public
// entries share this, so the exported format can never differ depending on how
// the destination was addressed.
static char *collect_packages(int *count_out)
{
    distro_t distro = detect_distro();
    char *const *cmd = get_package_cmd(distro);

    if (cmd == NULL)
    {
        print_error("Error: Could not detect distribution.\n");
        return NULL;
    }

    if (verbose)
    {
        printf("Detected: %s\n", get_distro_name(distro));
        printf("Running: %s %s\n", cmd[0], cmd[1]);
    }

    size_t buf_size = 5 * 1024 * 1024; // 5 MB
    char *buffer = malloc(buf_size);
    if (buffer == NULL)
    {
        print_error("Error: Could not allocate buffer.\n");
        return NULL;
    }

    buffer[0] = '\0';

    if (run_command_capture(cmd, buffer, buf_size) != 0)
    {
        print_error("Error: Could not run package command.\n");
        free(buffer);
        return NULL;
    }

    int count = 0;
    for (char *p = buffer; *p; p++)
    {
        if (*p == '\n')
            count++;
    }

    *count_out = count;
    return buffer;
}

// Writes and closes f, checking every step. A short write or a failed close
// would otherwise leave a package list that looks complete but is truncated.
static int write_package_list(FILE *f, const char *buffer)
{
    int failed = 0;
    if (fputs(buffer, f) < 0) failed = 1;
    if (!failed && fflush(f) != 0) failed = 1;
    if (fclose(f) != 0) failed = 1;
    return failed;
}

static int leaf_is_safe(const char *leaf)
{
    return leaf != NULL && leaf[0] != '\0' && strchr(leaf, '/') == NULL &&
           strcmp(leaf, ".") != 0 && strcmp(leaf, "..") != 0;
}

int packages_clear_at(int container_fd, const char *leaf)
{
    if (container_fd < 0 || !leaf_is_safe(leaf))
        return -1;

    if (unlinkat(container_fd, leaf, 0) == 0 || errno == ENOENT)
        return 0;

    // A directory (EISDIR/EPERM) or any other object this cannot remove stays
    // where it is, so the slot is *not* clean and the caller must not go on to
    // publish the container around it.
    if (errno == EISDIR || errno == EPERM)
    {
        if (unlinkat(container_fd, leaf, AT_REMOVEDIR) == 0)
            return 0;
    }
    return -1;
}

int packages_at(int container_fd, const char *leaf)
{
    if (container_fd < 0 || !leaf_is_safe(leaf))
        return -1;

    int count = 0;
    char *buffer = collect_packages(&count);
    if (buffer == NULL)
    {
        // Nothing was written, but an earlier run's list may still be sitting
        // there. Clearing it is what keeps a stale list out of a container
        // whose refresh demonstrably failed -- and a clear that itself fails
        // leaves the slot unsafe, which is a different and harder failure.
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    // Whatever already occupies this slot is never opened, let alone written
    // into. Reusing it would mean opening an object of unknown type and
    // provenance: a FIFO blocks the whole backup on a reader that will never
    // come, and a hardlink to a file outside the container would have that
    // file truncated and overwritten with the package list. Removing the name
    // first is what makes both harmless -- unlinking one hardlink leaves the
    // other name's data untouched -- and O_EXCL then guarantees the fd refers
    // to an inode this call alone created, with nothing substitutable in
    // between.
    if (packages_clear_at(container_fd, leaf) != 0)
    {
        free(buffer);
        return -1;
    }

    int fd = openat(container_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                    0644);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        if (fd >= 0)
            close(fd);
        free(buffer);
        print_error("Error: Could not write %s.\n", leaf);
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    FILE *out = fdopen(fd, "w");
    if (out == NULL)
    {
        close(fd);
        free(buffer);
        print_error("Error: Could not write %s.\n", leaf);
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    int failed = write_package_list(out, buffer);
    free(buffer);

    if (failed)
    {
        print_error("Error: Could not write %s.\n", leaf);
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    printf("Saved %d packages to %s\n", count, leaf);
    return 0;
}

int package_token_is_safe(const char *token)
{
    return token != NULL && token[0] != '\0' && token[0] != '-';
}

void read_package_list(FILE *pkg_file, char ***pkgs_out, int *pkg_count_out,
                       int *had_error)
{
    int pkg_cap = 256;
    int pkg_count = 0;
    char **pkgs = malloc((size_t)pkg_cap * sizeof(*pkgs));

    if (pkgs == NULL)
    {
        *had_error = 1;
        *pkgs_out = NULL;
        *pkg_count_out = 0;
        return;
    }

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

        // Current backups never emit option-shaped names. Treat one as an
        // invalid entry instead of allowing restored data to alter the
        // privileged package-manager command line.
        if (!package_token_is_safe(pkg_name))
            continue;

        if (pkg_count == pkg_cap)
        {
            pkg_cap *= 2;
            char **tmp = realloc(pkgs, (size_t)pkg_cap * sizeof(*pkgs));
            if (tmp == NULL)
            {
                *had_error = 1;
                break;
            }
            pkgs = tmp;
        }

        pkgs[pkg_count] = strdup(pkg_name);
        if (pkgs[pkg_count] == NULL)
        {
            *had_error = 1;
            break;
        }
        pkg_count++;
    }

    if (ferror(pkg_file))
        *had_error = 1;

    *pkgs_out = pkgs;
    *pkg_count_out = pkg_count;
}

// Reads and processes packages.txt from the container root (never inside
// data/: it is a control artifact, not payload, in both legacy and v1
// layouts). Opened by directory fd with O_NOFOLLOW + O_NONBLOCK -- the same
// discipline manifest.c uses for manifest.txt: a symlinked packages.txt is
// never followed into an arbitrary location, and a FIFO there can never
// hang this call waiting for a writer that will never come.
void restore_packages(int source_root_fd, const char *home, int *had_error)
{
    int fd = openat(source_root_fd, "packages.txt", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno == ENOENT)
            printf("\nNote: packages.txt not found, skipping package restore.\n");
        else
        {
            print_error("Error: Could not read packages.txt\n");
            *had_error = 1;
        }
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        print_error("Error: Could not inspect packages.txt\n");
        *had_error = 1;
        return;
    }
    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        print_warning("Warning: packages.txt is not a regular file, skipping package restore.\n");
        return;
    }

    FILE *pkg_file = fdopen(fd, "r");
    if (pkg_file == NULL)
    {
        close(fd);
        print_error("Error: Could not read packages.txt\n");
        *had_error = 1;
        return;
    }

    printf("\nPackages\n");

    distro_t distro = detect_distro();

    if (distro == DISTRO_UNKNOWN)
    {
        print_warning("Warning: Unrecognized distro, skipping package install.\n");
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

    char **pkgs = NULL;
    int pkg_count = 0;
    read_package_list(pkg_file, &pkgs, &pkg_count, had_error);
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
                                print_error("Error: Could not write skipped package log\n");
                            *had_error = 1;
                        }
                        else if (skipped_f == NULL)
                        {
                            skipped_f = fopen(skipped_path, "w");
                            if (skipped_f == NULL)
                            {
                                print_error("Error: Could not write skipped package log\n");
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
