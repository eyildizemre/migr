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

#ifdef PACKAGES_TEST_HOOKS
static int packages_test_restore_override;
static distro_t packages_test_restore_distro;
static PackagesTestRunHook packages_test_run_hook;
static PackagesTestCaptureHook packages_test_capture_hook;
static void *packages_test_run_context;

void packages_test_set_restore_hooks(distro_t distro,
                                     PackagesTestRunHook run_hook,
                                     PackagesTestCaptureHook capture_hook,
                                     void *context)
{
    packages_test_restore_override = 1;
    packages_test_restore_distro = distro;
    packages_test_run_hook = run_hook;
    packages_test_capture_hook = capture_hook;
    packages_test_run_context = context;
}

void packages_test_clear_restore_hooks(void)
{
    packages_test_restore_override = 0;
    packages_test_restore_distro = DISTRO_UNKNOWN;
    packages_test_run_hook = NULL;
    packages_test_capture_hook = NULL;
    packages_test_run_context = NULL;
}
#endif

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
// would otherwise leave a text control artifact that looks complete but is
// truncated.
static int write_text_buffer(FILE *f, const char *buffer)
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

int write_container_text_file_at(int container_fd, const char *leaf,
                                 const char *buffer)
{
    if (container_fd < 0 || !leaf_is_safe(leaf))
        return -1;

    if (buffer == NULL)
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;

    // Whatever already occupies this slot is never opened, let alone written
    // into. Reusing it would mean opening an object of unknown type and
    // provenance: a FIFO blocks the whole backup on a reader that will never
    // come, and a hardlink to a file outside the container would have that
    // file truncated and overwritten. Removing the name first makes both
    // harmless, and O_EXCL then guarantees the fd refers to an inode this call
    // alone created, with nothing substitutable in between.
    if (packages_clear_at(container_fd, leaf) != 0)
        return -1;

    int fd = openat(container_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                    0644);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        if (fd >= 0)
            close(fd);
        print_error("Error: Could not write %s.\n", leaf);
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    FILE *out = fdopen(fd, "w");
    if (out == NULL)
    {
        close(fd);
        print_error("Error: Could not write %s.\n", leaf);
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    if (write_text_buffer(out, buffer) != 0)
    {
        print_error("Error: Could not write %s.\n", leaf);
        return packages_clear_at(container_fd, leaf) == 0 ? 1 : -1;
    }

    return 0;
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

    int write_result = write_container_text_file_at(container_fd, leaf, buffer);
    free(buffer);

    if (write_result == 0)
        printf("Saved %d packages to %s\n", count, leaf);
    return write_result;
}

int package_token_is_safe(const char *token)
{
    return token != NULL && token[0] != '\0' && token[0] != '-';
}

void read_package_list(FILE *pkg_file, char ***pkgs_out, int *pkg_count_out,
                       int *had_error)
{
    size_t pkg_cap = 256;
    int pkg_count = 0;
    char **pkgs = malloc(pkg_cap * sizeof(*pkgs));

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

        if ((size_t)pkg_count == pkg_cap)
        {
            char **tmp = array_reserve(
                pkgs, &pkg_cap, (size_t)pkg_count, 1U, sizeof(*pkgs),
                256U, SIZE_MAX / sizeof(*pkgs));
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

enum {
    PACKAGE_INSTALL_PREFIX_MAX = 5,
    PACKAGE_QUERY_BUFFER_SIZE = 5 * 1024 * 1024
};

static size_t package_install_prefix(distro_t distro,
                                     char *prefix[PACKAGE_INSTALL_PREFIX_MAX])
{
    switch (distro)
    {
        case DISTRO_DEBIAN:
            prefix[0] = "sudo";
            prefix[1] = "apt-get";
            prefix[2] = "install";
            prefix[3] = "-y";
            prefix[4] = "-m";
            return 5U;
        case DISTRO_FEDORA:
            prefix[0] = "sudo";
            prefix[1] = "dnf";
            prefix[2] = "install";
            prefix[3] = "-y";
            prefix[4] = "--skip-unavailable";
            return 5U;
        case DISTRO_ARCH:
            prefix[0] = "sudo";
            prefix[1] = "pacman";
            prefix[2] = "-S";
            prefix[3] = "--needed";
            prefix[4] = "--noconfirm";
            return 5U;
        default:
            return 0U;
    }
}

static distro_t package_restore_distro(void)
{
#ifdef PACKAGES_TEST_HOOKS
    if (packages_test_restore_override)
        return packages_test_restore_distro;
#endif
    return detect_distro();
}

static int package_run_command(char *const argv[])
{
#ifdef PACKAGES_TEST_HOOKS
    if (packages_test_restore_override && packages_test_run_hook != NULL)
        return packages_test_run_hook(argv, packages_test_run_context);
#endif
    return run_command(argv);
}

static int package_capture_command(char *const argv[], char *output,
                                   size_t output_size)
{
#ifdef PACKAGES_TEST_HOOKS
    if (packages_test_restore_override)
    {
        if (packages_test_capture_hook == NULL)
            return -1;
        return packages_test_capture_hook(argv, output, output_size,
                                          packages_test_run_context);
    }
#endif
    return run_command_capture(argv, output, output_size);
}

static char *const *package_installed_query(distro_t distro)
{
    static char *const debian_query[] = {
        "dpkg-query", "-W",
        "-f=${Package}\\t${binary:Package}\\t${db:Status-Status}\\n", NULL
    };
    static char *const fedora_query[] = {
        "rpm", "-qa", "--qf", "%{NAME}\\n", NULL
    };
    static char *const arch_query[] = {"pacman", "-Qq", NULL};

    switch (distro)
    {
        case DISTRO_DEBIAN: return debian_query;
        case DISTRO_FEDORA: return fedora_query;
        case DISTRO_ARCH: return arch_query;
        default: return NULL;
    }
}

static char *capture_package_query(char *const argv[], const char *label,
                                   int *had_error)
{
    char *output = malloc(PACKAGE_QUERY_BUFFER_SIZE);
    if (output == NULL)
    {
        print_error("Error: Could not allocate package query buffer\n");
        *had_error = 1;
        return NULL;
    }

    output[0] = '\0';
    int result = package_capture_command(argv, output,
                                         PACKAGE_QUERY_BUFFER_SIZE);
    size_t length = strnlen(output, PACKAGE_QUERY_BUFFER_SIZE);
    if (result != 0 || length >= PACKAGE_QUERY_BUFFER_SIZE - 1U)
    {
        print_error("Error: Could not query %s\n", label);
        *had_error = 1;
        free(output);
        return NULL;
    }
    return output;
}

static int package_plain_list_contains(const char *list, const char *package)
{
    if (list == NULL || package == NULL)
        return 0;

    size_t package_length = strlen(package);
    const char *line = list;
    while (*line != '\0')
    {
        const char *newline = strchr(line, '\n');
        size_t length = newline != NULL ? (size_t)(newline - line) : strlen(line);
        if (length != 0 && line[length - 1U] == '\r')
            length--;
        if (length == package_length &&
            memcmp(line, package, package_length) == 0)
            return 1;
        if (newline == NULL)
            break;
        line = newline + 1;
    }
    return 0;
}

static int package_inventory_contains(distro_t distro, const char *inventory,
                                      const char *package)
{
    if (distro != DISTRO_DEBIAN)
        return package_plain_list_contains(inventory, package);
    if (inventory == NULL || package == NULL)
        return 0;

    size_t package_length = strlen(package);
    const char *line = inventory;
    while (*line != '\0')
    {
        const char *newline = strchr(line, '\n');
        size_t length = newline != NULL ? (size_t)(newline - line) : strlen(line);
        if (length != 0 && line[length - 1U] == '\r')
            length--;
        const char *first_tab = memchr(line, '\t', length);
        if (first_tab != NULL)
        {
            size_t bare_length = (size_t)(first_tab - line);
            const char *binary_name = first_tab + 1;
            size_t after_first = length - bare_length - 1U;
            const char *second_tab = memchr(binary_name, '\t', after_first);
            if (second_tab != NULL)
            {
                size_t binary_length = (size_t)(second_tab - binary_name);
                const char *status = second_tab + 1;
                size_t status_length = after_first - binary_length - 1U;
                int name_matches =
                    (bare_length == package_length &&
                     memcmp(line, package, package_length) == 0) ||
                    (binary_length == package_length &&
                     memcmp(binary_name, package, package_length) == 0);
                if (name_matches && status_length == strlen("installed") &&
                    memcmp(status, "installed", status_length) == 0)
                    return 1;
            }
        }
        if (newline == NULL)
            break;
        line = newline + 1;
    }
    return 0;
}

static char *package_arch_available(int *had_error)
{
    char *const query[] = {"pacman", "-Slq", NULL};
    return capture_package_query(query, "Arch package availability", had_error);
}

typedef struct {
    char path[PATH_MAX];
    FILE *stream;
    int path_valid;
    int write_failed;
} PackageSkipLog;

static void package_skip_log_init(PackageSkipLog *log, const char *home)
{
    memset(log, 0, sizeof(*log));
    log->path_valid =
        path_join(log->path, sizeof(log->path), home,
                  "skipped-packages.txt") == 0;
}

static void package_skip_log_record(PackageSkipLog *log, const char *package,
                                    int *had_error)
{
    if (!log->path_valid)
    {
        if (!log->write_failed)
            print_error("Error: Could not write skipped package log\n");
        log->write_failed = 1;
        *had_error = 1;
        return;
    }

    if (log->stream == NULL)
    {
        log->stream = fopen(log->path, "w");
        if (log->stream == NULL)
        {
            if (!log->write_failed)
                print_error("Error: Could not write skipped package log\n");
            log->write_failed = 1;
            log->path_valid = 0;
            *had_error = 1;
            return;
        }
    }

    if (fprintf(log->stream, "%s\n", package) < 0)
    {
        if (!log->write_failed)
            print_error("Error: Could not write skipped package log\n");
        log->write_failed = 1;
        *had_error = 1;
    }
}

static void package_skip_log_close(PackageSkipLog *log, int *had_error)
{
    if (log->stream == NULL)
        return;

    if (fclose(log->stream) != 0)
    {
        if (!log->write_failed)
            print_error("Error: Could not write skipped package log\n");
        log->write_failed = 1;
        *had_error = 1;
    }
    else if (!log->write_failed)
    {
        printf("  Skipped packages written to: %s\n", log->path);
    }
    log->stream = NULL;
}

static void package_skip_log_clear_if_empty(PackageSkipLog *log, int skipped,
                                            int *had_error)
{
    if (skipped != 0 || !log->path_valid)
        return;

    if (unlink(log->path) != 0 && errno != ENOENT)
    {
        print_error("Error: Could not clear skipped package log\n");
        *had_error = 1;
    }
}

static size_t package_build_install_argv(char **argv, char *const *prefix,
                                         size_t prefix_count, char **pkgs,
                                         size_t pkg_count,
                                         const char *arch_available)
{
    for (size_t index = 0; index < prefix_count; index++)
        argv[index] = prefix[index];

    size_t install_count = 0;
    for (size_t index = 0; index < pkg_count; index++)
    {
        if (arch_available != NULL &&
            !package_plain_list_contains(arch_available, pkgs[index]))
            continue;
        argv[prefix_count + install_count] = pkgs[index];
        install_count++;
    }
    argv[prefix_count + install_count] = NULL;
    return install_count;
}

static int package_account_final_state(distro_t distro, char **pkgs,
                                       size_t pkg_count, const char *home,
                                       int *installed, int *skipped,
                                       int *had_error)
{
    char *const *query = package_installed_query(distro);
    if (query == NULL)
        return -1;

    char *inventory = capture_package_query(query, "installed packages",
                                            had_error);
    if (inventory == NULL)
        return -1;

    PackageSkipLog skip_log;
    package_skip_log_init(&skip_log, home);
    for (size_t index = 0; index < pkg_count; index++)
    {
        if (package_inventory_contains(distro, inventory, pkgs[index]))
            (*installed)++;
        else
        {
            package_skip_log_record(&skip_log, pkgs[index], had_error);
            (*skipped)++;
        }
    }

    package_skip_log_close(&skip_log, had_error);
    package_skip_log_clear_if_empty(&skip_log, *skipped, had_error);
    free(inventory);
    return 0;
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

    distro_t distro = package_restore_distro();

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

    char *batch_prefix[PACKAGE_INSTALL_PREFIX_MAX];
    size_t prefix = package_install_prefix(distro, batch_prefix);

    int installed = 0, skipped = 0;
    int accounting_complete = pkg_count == 0;

    if (pkgs != NULL && pkg_count > 0 && prefix > 0)
    {
        size_t pkg_count_size = (size_t)pkg_count;
        size_t argv_count = prefix + pkg_count_size + 1U;
        char **batch_argv = argv_count <= SIZE_MAX / sizeof(*batch_argv)
            ? malloc(argv_count * sizeof(*batch_argv)) : NULL;
        if (batch_argv != NULL)
        {
            char *arch_available = NULL;
            int may_install = 1;
            if (distro == DISTRO_ARCH)
            {
                arch_available = package_arch_available(had_error);
                if (arch_available == NULL)
                    may_install = 0;
            }

            if (may_install)
            {
                size_t install_count = package_build_install_argv(
                    batch_argv, batch_prefix, prefix, pkgs, pkg_count_size,
                    arch_available);
                if (install_count != 0)
                    (void)package_run_command(batch_argv);
            }
            free(arch_available);
            free(batch_argv);

            accounting_complete = package_account_final_state(
                distro, pkgs, pkg_count_size, home, &installed, &skipped,
                had_error) == 0;
        }
        else
        {
            print_error("Error: Could not allocate package install batch\n");
            *had_error = 1;
        }
    }

    if (pkgs != NULL)
    {
        for (int i = 0; i < pkg_count; i++)
            free(pkgs[i]);
        free(pkgs);
    }

    if (accounting_complete)
        printf("  %d installed, %d skipped.\n", installed, skipped);
}
