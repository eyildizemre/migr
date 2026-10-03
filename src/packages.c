#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "packages.h"
#include "packages_internal.h"
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

static int package_name_is_kernel_pinned(const char *name, size_t length)
{
    static const char *const arch_suffixes[] = {
        ".x86_64", ".aarch64", ".i686", ".ppc64le", ".s390x"
    };
    if (length <= strlen("kmod-") || strncmp(name, "kmod-", 5) != 0)
        return 0;
    for (size_t index = 0;
         index < sizeof(arch_suffixes) / sizeof(arch_suffixes[0]); index++)
    {
        size_t suffix_length = strlen(arch_suffixes[index]);
        if (length > suffix_length &&
            memcmp(name + length - suffix_length, arch_suffixes[index],
                   suffix_length) == 0)
            return 1;
    }
    return 0;
}

// akmods names each module package it builds after one kernel release
// (kmod-nvidia-7.2.5-200.fc44.x86_64). Such a package can only ever install
// on that kernel, so a list for a new system drops it; the akmod-* package
// that rebuilds it is listed on its own. Returns the remaining line count.
static int drop_kernel_pinned_packages(char *buffer)
{
    char *read = buffer;
    char *write = buffer;
    int count = 0;
    while (*read != '\0')
    {
        char *end = strchr(read, '\n');
        size_t length = end != NULL ? (size_t)(end - read) : strlen(read);
        size_t line_length = end != NULL ? length + 1U : length;
        if (!package_name_is_kernel_pinned(read, length))
        {
            memmove(write, read, line_length);
            write += line_length;
            if (end != NULL)
                count++;
        }
        read += line_length;
    }
    *write = '\0';
    return count;
}

#ifdef PACKAGES_TEST_HOOKS
int packages_test_drop_kernel_pinned(char *buffer)
{
    return drop_kernel_pinned_packages(buffer);
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

    *count_out = drop_kernel_pinned_packages(buffer);
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
        int saved = fd >= 0 ? EINVAL : errno;
        if (fd >= 0)
            close(fd);
        (void)packages_clear_at(container_fd, leaf);
        errno = saved;
        return -1;
    }

    FILE *out = fdopen(fd, "w");
    if (out == NULL)
    {
        int saved = errno;
        close(fd);
        (void)packages_clear_at(container_fd, leaf);
        errno = saved;
        return -1;
    }

    // A list the destination could not store is a failed write, not an
    // empty list: the truncated file goes, and the caller is told.
    if (write_text_buffer(out, buffer) != 0)
    {
        int saved = errno;
        (void)packages_clear_at(container_fd, leaf);
        errno = saved;
        return -1;
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

enum { PACKAGE_INSTALL_PREFIX_MAX = 6 };

static size_t package_install_prefix(distro_t distro,
                                     char *prefix[PACKAGE_INSTALL_PREFIX_MAX])
{
    switch (distro)
    {
        // restore runs as root (D62), so these need no sudo of their own.
        case DISTRO_DEBIAN:
            // A package's debconf question would stop the restore until
            // answered; unasked, each keeps its default or current answer
            // (D91).
            prefix[0] = "env";
            prefix[1] = "DEBIAN_FRONTEND=noninteractive";
            prefix[2] = "apt-get";
            prefix[3] = "install";
            prefix[4] = "-y";
            prefix[5] = "-m";
            return 6U;
        case DISTRO_FEDORA:
            prefix[0] = "dnf";
            prefix[1] = "install";
            prefix[2] = "-y";
            prefix[3] = "--skip-unavailable";
            return 4U;
        case DISTRO_ARCH:
            prefix[0] = "pacman";
            prefix[1] = "-S";
            prefix[2] = "--needed";
            prefix[3] = "--noconfirm";
            return 4U;
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

int package_run_command(char *const argv[])
{
#ifdef PACKAGES_TEST_HOOKS
    if (packages_test_restore_override && packages_test_run_hook != NULL)
        return packages_test_run_hook(argv, packages_test_run_context);
#endif
    return run_command(argv);
}

int package_capture_command(char *const argv[], char *output,
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

typedef struct {
    const char *line;
    struct timespec started;
} PackageInstallDisplay;

static void package_install_redraw(const ProgressTickerSnapshot *snapshot,
                                   const struct timespec *now, void *context)
{
    (void)snapshot;
    const PackageInstallDisplay *display = context;
    char elapsed[32];
    format_duration((long)timespec_elapsed_seconds(&display->started, now),
                    elapsed, sizeof(elapsed));
    printf("\r%s elapsed %s", display->line, elapsed);
    fflush(stdout);
}

int package_install_command(char *const argv[], const char *line)
{
    printf("%s", line);
#ifdef PACKAGES_TEST_HOOKS
    if (packages_test_restore_override && packages_test_run_hook != NULL)
    {
        printf("\n");
        return packages_test_run_hook(argv, packages_test_run_context);
    }
#endif
    // The ticker redraws only once no snapshot came for a while; one at the
    // start keeps it redrawing the elapsed time until the command ends.
    PackageInstallDisplay display = { .line = line };
    ProgressTicker ticker;
    int ticking = isatty(STDOUT_FILENO) &&
                  clock_gettime(CLOCK_MONOTONIC, &display.started) == 0 &&
                  progress_ticker_start(&ticker, package_install_redraw,
                                        &display) == 0;
    if (ticking)
        (void)progress_ticker_snapshot(&ticker, 0, 0, 0, 0, 0, NULL,
                                       &display.started);
    char errors[4096];
    int status = run_command_errors(argv, errors, sizeof(errors));
    // A live thread would keep pointers into this stack frame.
    if (ticking && progress_ticker_stop(&ticker) != 0)
        abort();
    printf("\n");
    if (status != 0)
    {
        // Named after the program env runs, not env (D91).
        size_t name = 0;
        while (argv[name + 1] != NULL && (strcmp(argv[name], "env") == 0 ||
                                          strchr(argv[name], '=') != NULL))
            name++;
        print_warning("  %s exited with status %d.\n", argv[name], status);
        if (errors[0] != '\0')
            fprintf(stderr, "%s%s", errors,
                    errors[strlen(errors) - 1U] == '\n' ? "" : "\n");
    }
    return status;
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

char *package_capture_query(char *const argv[], const char *label,
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

int package_plain_list_contains(const char *list, const char *package)
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

// The names its repositories have, where one name they lack makes the
// package manager refuse the whole install (pacman, apt-get); NULL where it
// skips such names itself (dnf --skip-unavailable).
static char *const *package_available_query(distro_t distro)
{
    static char *const debian_query[] = {"apt-cache", "pkgnames", NULL};
    static char *const arch_query[] = {"pacman", "-Slq", NULL};
    switch (distro)
    {
        case DISTRO_DEBIAN: return debian_query;
        case DISTRO_ARCH: return arch_query;
        default: return NULL;
    }
}

// A Debian name can carry an architecture ("libc6:i386"); the repositories
// list the name without it.
static int package_available_contains(const char *available,
                                      const char *package)
{
    const char *colon = strchr(package, ':');
    if (colon == NULL)
        return package_plain_list_contains(available, package);
    char name[256];
    size_t length = (size_t)(colon - package);
    if (length >= sizeof(name))
        return 0;
    memcpy(name, package, length);
    name[length] = '\0';
    return package_plain_list_contains(available, name);
}

static size_t package_build_argv(char **argv, char *const *prefix,
                                 size_t prefix_count, char **pkgs,
                                 size_t pkg_count, const char *available)
{
    for (size_t index = 0; index < prefix_count; index++)
        argv[index] = prefix[index];

    size_t install_count = 0;
    for (size_t index = 0; index < pkg_count; index++)
    {
        if (available != NULL &&
            !package_available_contains(available, pkgs[index]))
            continue;
        argv[prefix_count + install_count] = pkgs[index];
        install_count++;
    }
    argv[prefix_count + install_count] = NULL;
    return install_count;
}

// Counts the packages inventory has and lists the others in todo under
// heading.
static void package_account_final_state(distro_t distro, const char *inventory,
                                        char **pkgs, size_t pkg_count,
                                        FILE *todo, const char *heading,
                                        int *installed, int *skipped)
{
    for (size_t index = 0; index < pkg_count; index++)
    {
        if (package_inventory_contains(distro, inventory, pkgs[index]))
        {
            (*installed)++;
            continue;
        }
        if (*skipped == 0)
            fprintf(todo, "  %s\n    ", heading);
        fprintf(todo, "%s%s", *skipped == 0 ? "" : " ", pkgs[index]);
        (*skipped)++;
    }
    if (*skipped != 0)
        fprintf(todo, "\n");
}

// Opens a list at the container root (never inside data/: it is a control
// artifact, not payload, in both legacy and v1 layouts). Opened by directory
// fd with O_NOFOLLOW + O_NONBLOCK -- the same discipline manifest.c uses for
// manifest.txt: a symlinked list is never followed into an arbitrary
// location, and a FIFO there can never hang this call waiting for a writer
// that will never come.
int package_open_control_file(int source_root_fd, const char *leaf,
                              FILE **out, int *had_error)
{
    int fd = openat(source_root_fd, leaf,
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno == ENOENT)
            return CONTROL_FILE_ABSENT;
        print_error("Error: Could not read %s\n", leaf);
        *had_error = 1;
        return CONTROL_FILE_UNUSABLE;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        print_error("Error: Could not inspect %s\n", leaf);
        *had_error = 1;
        return CONTROL_FILE_UNUSABLE;
    }
    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        print_warning("Warning: %s is not a regular file, skipping it.\n",
                      leaf);
        return CONTROL_FILE_UNUSABLE;
    }

    *out = fdopen(fd, "r");
    if (*out == NULL)
    {
        close(fd);
        print_error("Error: Could not read %s\n", leaf);
        *had_error = 1;
        return CONTROL_FILE_UNUSABLE;
    }
    return CONTROL_FILE_OPEN;
}

void package_free_name_list(char **names, int count)
{
    if (names == NULL)
        return;
    for (int i = 0; i < count; i++)
        free(names[i]);
    free(names);
}

// Installs pkgs in one package manager call; with apt and pacman, only those
// their repositories have.
static void package_install_batch(distro_t distro, char *const *prefix,
                                  size_t prefix_count, char **pkgs,
                                  size_t pkg_count, const char *line,
                                  int *had_error)
{
    size_t argv_count = prefix_count + pkg_count + 1U;
    char **argv = argv_count <= SIZE_MAX / sizeof(*argv)
        ? malloc(argv_count * sizeof(*argv)) : NULL;
    if (argv == NULL)
    {
        print_error("Error: Could not allocate package install batch\n");
        *had_error = 1;
        return;
    }
    char *const *query = package_available_query(distro);
    char *available = NULL;
    if (query == NULL ||
        (available = package_capture_query(query, "package availability",
                                           had_error)) != NULL)
    {
        if (package_build_argv(argv, prefix, prefix_count, pkgs, pkg_count,
                               available) != 0)
            (void)package_install_command(argv, line);
    }
    free(available);
    free(argv);
}

// Marks installed packages as explicitly installed. The backup listed them
// as such, but here something else pulled them in; unmarked, the next backup
// would leave them out and autoremove could take them away (D95). The
// command's output is a state change, not progress, so only errors show.
static void package_mark_explicit(distro_t distro, char **pkgs,
                                  size_t pkg_count)
{
    static char *const debian_mark[] = {"apt-mark", "manual"};
    static char *const fedora_mark[] = {"dnf", "-y", "-q", "mark", "user"};
    static char *const arch_mark[] = {"pacman", "-D", "--asexplicit"};
    char *const *prefix;
    size_t prefix_count;
    switch (distro)
    {
        case DISTRO_DEBIAN:
            prefix = debian_mark;
            prefix_count = sizeof(debian_mark) / sizeof(debian_mark[0]);
            break;
        case DISTRO_FEDORA:
            prefix = fedora_mark;
            prefix_count = sizeof(fedora_mark) / sizeof(fedora_mark[0]);
            break;
        case DISTRO_ARCH:
            prefix = arch_mark;
            prefix_count = sizeof(arch_mark) / sizeof(arch_mark[0]);
            break;
        default:
            return;
    }

    char **argv = malloc((prefix_count + pkg_count + 1U) * sizeof(*argv));
    int failed = argv == NULL;
    if (!failed)
    {
        char output[4096];
        package_build_argv(argv, prefix, prefix_count, pkgs, pkg_count, NULL);
        failed = package_capture_command(argv, output, sizeof(output)) != 0;
    }
    if (failed)
        print_warning("Warning: Could not mark %zu installed package(s) as "
                      "explicitly installed.\n", pkg_count);
    free(argv);
}

// Installs the listed packages the system lacks, marks the ones it has, and
// accounts for the list from the final state (D46, D95). Packages already
// there never reach the package manager, which would print a line for each.
// Returns -1 when the installed state cannot be read.
static int package_restore_list(distro_t distro, char *const *prefix,
                                size_t prefix_count, char **pkgs,
                                size_t pkg_count, int online, FILE *todo,
                                int *installed, int *skipped, int *had_error)
{
    char *const *query = package_installed_query(distro);
    char *inventory = package_capture_query(query, "installed packages",
                                            had_error);
    if (inventory == NULL)
        return -1;
    char *explicit_list = package_capture_query(
        get_package_cmd(distro), "explicitly installed packages", had_error);
    char **missing = malloc(pkg_count * sizeof(*missing));
    char **unmarked = malloc(pkg_count * sizeof(*unmarked));
    if (missing == NULL || unmarked == NULL)
    {
        print_error("Error: Could not allocate the package lists\n");
        *had_error = 1;
        free(missing);
        free(unmarked);
        free(explicit_list);
        free(inventory);
        return -1;
    }

    size_t missing_count = 0, unmarked_count = 0;
    for (size_t index = 0; index < pkg_count; index++)
    {
        if (!package_inventory_contains(distro, inventory, pkgs[index]))
            missing[missing_count++] = pkgs[index];
        else if (explicit_list != NULL &&
                 !package_plain_list_contains(explicit_list, pkgs[index]))
            unmarked[unmarked_count++] = pkgs[index];
    }
    if (unmarked_count != 0)
        package_mark_explicit(distro, unmarked, unmarked_count);

    if (online && missing_count != 0)
    {
        char line[128];
        snprintf(line, sizeof(line), "  %zu of %zu are already installed; "
                 "installing %zu (this may take a while)...",
                 pkg_count - missing_count, pkg_count, missing_count);
        package_install_batch(distro, prefix, prefix_count, missing,
                              missing_count, line, had_error);
        free(inventory);
        inventory = package_capture_query(query, "installed packages",
                                          had_error);
    }
    if (inventory != NULL)
        package_account_final_state(
            distro, inventory, pkgs, pkg_count, todo,
            online ? "Packages this system could not install, often from a "
                     "repository it does not have yet:"
                   : "Packages to install once this system is online:",
            installed, skipped);

    int result = inventory != NULL ? 0 : -1;
    free(missing);
    free(unmarked);
    free(explicit_list);
    free(inventory);
    return result;
}

void restore_packages(int source_root_fd, int online, FILE *todo,
                      int *had_error)
{
    FILE *pkg_file = NULL;
    int opened = package_open_control_file(source_root_fd, "packages.txt",
                                           &pkg_file, had_error);
    if (opened == CONTROL_FILE_ABSENT)
        printf("\nNote: packages.txt not found, skipping package restore.\n");
    if (opened != CONTROL_FILE_OPEN)
        return;

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

    if (!online)
        printf("  No network connection; not installing.\n");

    char **pkgs = NULL;
    int pkg_count = 0;
    read_package_list(pkg_file, &pkgs, &pkg_count, had_error);
    fclose(pkg_file);

    char *batch_prefix[PACKAGE_INSTALL_PREFIX_MAX];
    size_t prefix = package_install_prefix(distro, batch_prefix);

    int installed = 0, skipped = 0;
    int accounting_complete = pkg_count == 0;

    if (pkgs != NULL && pkg_count > 0 && prefix > 0)
        accounting_complete = package_restore_list(
            distro, batch_prefix, prefix, pkgs, (size_t)pkg_count, online,
            todo, &installed, &skipped, had_error) == 0;

    package_free_name_list(pkgs, pkg_count);

    if (accounting_complete)
        printf("  %d installed, %d skipped.\n", installed, skipped);
}
