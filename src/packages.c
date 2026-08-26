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
