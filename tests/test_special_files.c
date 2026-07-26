// Unit tests for the special-file policy in clone_recursive() and get_dir_size().
//
// These types cannot be exercised reliably through the CLI: a socket must be
// created with bind(), a device node needs root, and opening a FIFO as a regular
// file would block the whole suite on a missing writer. So the nodes are built
// directly here and the policy is asserted: a FIFO has its node recreated (never
// its contents), while sockets and device nodes are skipped without a destination
// and add no bytes to a size measurement. /dev/null stands in as a character
// device the test can reach without privileges.

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "fileops.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

int main(void)
{
    printf(BLUE "::" NC " special files (unit)\n");

    char root[] = "/tmp/migr_special_XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        printf(RED "could not create temporary directory" NC "\n");
        return 1;
    }

    char src_fifo[PATH_MAX], dest_fifo[PATH_MAX];
    char src_socket[PATH_MAX], dest_socket[PATH_MAX];
    char dest_device[PATH_MAX];
    if (path_join(src_fifo, sizeof(src_fifo), root, "source.fifo") != 0 ||
        path_join(dest_fifo, sizeof(dest_fifo), root, "copied.fifo") != 0 ||
        path_join(src_socket, sizeof(src_socket), root, "source.socket") != 0 ||
        path_join(dest_socket, sizeof(dest_socket), root, "copied.socket") != 0 ||
        path_join(dest_device, sizeof(dest_device), root, "copied.device") != 0)
    {
        rmdir(root);
        printf(RED "could not build fixture paths" NC "\n");
        return 1;
    }

    if (mkfifo(src_fifo, 0640) != 0)
    {
        rmdir(root);
        printf(RED "could not create FIFO fixture" NC "\n");
        return 1;
    }

    struct stat st = {0};
    struct stat src_st = {0};
    int fifo_created = clone_recursive(src_fifo, dest_fifo) == 0 &&
                       lstat(src_fifo, &src_st) == 0 &&
                       lstat(dest_fifo, &st) == 0 &&
                       S_ISFIFO(st.st_mode);
    check(fifo_created,
          "FIFO is recreated as a FIFO");
    check(fifo_created && (st.st_mode & 0777) == (src_st.st_mode & 0777),
          "FIFO permissions are preserved");
    check(clone_recursive(src_fifo, dest_fifo) == 0,
          "an existing destination FIFO is accepted on resume");

    off_t size = 17;
    check(get_dir_size(src_fifo, &size) == 0 && size == 17,
          "FIFO contributes no payload bytes");

    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;

    if (strlen(src_socket) >= sizeof(address.sun_path) || socket_fd == -1)
    {
        if (socket_fd != -1)
            close(socket_fd);
        unlink(dest_fifo);
        unlink(src_fifo);
        rmdir(root);
        printf(RED "could not create Unix socket fixture" NC "\n");
        return 1;
    }
    strcpy(address.sun_path, src_socket);

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        perror("bind");
        close(socket_fd);
        unlink(dest_fifo);
        unlink(src_fifo);
        rmdir(root);
        printf(RED "could not create Unix socket fixture" NC "\n");
        return 1;
    }

    errno = 0;
    check(clone_recursive(src_socket, dest_socket) == 0 &&
          lstat(dest_socket, &st) == -1 &&
          errno == ENOENT,
          "Unix socket is skipped without creating a destination");

    size = 23;
    check(get_dir_size(src_socket, &size) == 0 && size == 23,
          "Unix socket contributes no payload bytes");

    int device_fixture = lstat("/dev/null", &st) == 0 && S_ISCHR(st.st_mode);
    check(device_fixture,
          "/dev/null is available as the device-node fixture");
    errno = 0;
    check(device_fixture &&
          clone_recursive("/dev/null", dest_device) == 0 &&
          lstat(dest_device, &st) == -1 &&
          errno == ENOENT,
          "device node is skipped without creating a destination");

    size = 29;
    check(device_fixture &&
          get_dir_size("/dev/null", &size) == 0 &&
          size == 29,
          "device node contributes no payload bytes");

    close(socket_fd);
    unlink(src_socket);
    unlink(dest_fifo);
    unlink(src_fifo);
    rmdir(root);

    if (failures > 0)
    {
        printf(RED "%d special-file test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
