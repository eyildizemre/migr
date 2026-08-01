// Unit tests for backup_capture_at(): the native capture walker, whose source
// side is pathname-based and whose destination side is anchored to a directory
// fd the caller owns (docs/DECISIONS.md D15).
//
// Two groups. The first is the special-file policy, which cannot be exercised
// through the CLI: a socket must be created with bind(), a device node needs
// root, and opening a FIFO as a regular file would block the whole suite on a
// missing writer. So the nodes are built directly here and the policy is
// asserted -- a FIFO has its node recreated (never its contents), while sockets
// and device nodes are skipped without a destination and add no bytes to a size
// measurement. /dev/null stands in as a character device the test can reach
// without privileges.
//
// The second is the destination contract that makes writing into an adopted,
// already-populated container safe: no symlink at any destination address is
// followed, work a previous run finished is resumed past, and every other
// collision is refused rather than overwritten. A sentinel outside the
// destination directory proves the refusals are real rather than merely
// reported.
//
// A final group checks the orchestration contract the entry point enforces: a
// NULL, wrong-direction, or portable context is refused, never silently cloned,
// and neither is a destination leaf that is not a single safe component.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
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

static void fatal(const char *message)
{
    printf(RED "%s" NC "\n", message);
    exit(1);
}

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
        fatal("fixture: could not write a file");
    fputs(content, f);
    fclose(f);
}

static int remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

// FTW_PHYS so the symlink fixtures are removed as themselves rather than
// followed out of the fixture tree.
static void remove_tree(const char *path)
{
    if (nftw(path, remove_cb, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fatal("fixture: could not clean up the test root");
}

static int file_contains(const char *path, const char *expected)
{
    char buffer[512];
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 0;
    size_t n = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);
    buffer[n] = '\0';
    return strcmp(buffer, expected) == 0;
}

int main(void)
{
    printf(BLUE "::" NC " backup capture walker (unit)\n");

    CloneContext ctx = { .operation = CLONE_BACKUP, .representation = CLONE_NATIVE_TREE };

    char root[] = "/tmp/migr_special_XXXXXX";
    if (mkdtemp(root) == NULL)
        fatal("could not create temporary directory");

    // dest/ is the container stand-in the walker is anchored to; outside/ is
    // deliberately its sibling, so any symlink escape has somewhere visible to
    // land.
    char dest_dir[PATH_MAX], outside_dir[PATH_MAX], src_dir[PATH_MAX];
    if (path_join(dest_dir, sizeof(dest_dir), root, "dest") != 0 ||
        path_join(outside_dir, sizeof(outside_dir), root, "outside") != 0 ||
        path_join(src_dir, sizeof(src_dir), root, "src") != 0)
        fatal("could not build fixture paths");
    if (mkdir(dest_dir, 0755) != 0 || mkdir(outside_dir, 0755) != 0 || mkdir(src_dir, 0755) != 0)
        fatal("could not create fixture directories");

    int dest_fd = open(dest_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dest_fd < 0)
        fatal("could not open the destination directory");

    /* --------------------------------------------------------------------- */
    /* Special-file policy                                                    */
    /* --------------------------------------------------------------------- */

    char src_fifo[PATH_MAX], src_socket[PATH_MAX];
    char dest_fifo[PATH_MAX], dest_socket[PATH_MAX], dest_device[PATH_MAX];
    if (path_join(src_fifo, sizeof(src_fifo), src_dir, "source.fifo") != 0 ||
        path_join(src_socket, sizeof(src_socket), src_dir, "source.socket") != 0 ||
        path_join(dest_fifo, sizeof(dest_fifo), dest_dir, "copied.fifo") != 0 ||
        path_join(dest_socket, sizeof(dest_socket), dest_dir, "copied.socket") != 0 ||
        path_join(dest_device, sizeof(dest_device), dest_dir, "copied.device") != 0)
        fatal("could not build fixture paths");

    if (mkfifo(src_fifo, 0640) != 0)
        fatal("could not create FIFO fixture");

    struct stat st = {0};
    struct stat src_st = {0};
    int fifo_created = backup_capture_at(&ctx, src_fifo, dest_fd, "copied.fifo") == 0 &&
                       lstat(src_fifo, &src_st) == 0 &&
                       lstat(dest_fifo, &st) == 0 &&
                       S_ISFIFO(st.st_mode);
    check(fifo_created, "FIFO is recreated as a FIFO");
    check(fifo_created && (st.st_mode & 0777) == (src_st.st_mode & 0777),
          "FIFO permissions are preserved");
    check(backup_capture_at(&ctx, src_fifo, dest_fd, "copied.fifo") == 0,
          "an existing destination FIFO of the right type is accepted on resume");

    off_t size = 17;
    check(get_dir_size(src_fifo, &size) == 0 && size == 17,
          "FIFO contributes no payload bytes");

    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0 && (errno == EPERM || errno == EACCES ||
                          errno == EAFNOSUPPORT))
    {
        printf("  " BLUE "-" NC " Unix socket fixture unavailable on this host\n");
    }
    else
    {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        if (strlen(src_socket) >= sizeof(address.sun_path))
            fatal("Unix socket fixture path is too long");
        strcpy(address.sun_path, src_socket);
        if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        {
            if (errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT)
                printf("  " BLUE "-" NC " Unix socket fixture unavailable on this host\n");
            else
                fatal("could not bind Unix socket fixture");
        }
        else
        {
            errno = 0;
            check(backup_capture_at(&ctx, src_socket, dest_fd, "copied.socket") == 0 &&
                  lstat(dest_socket, &st) == -1 && errno == ENOENT,
                  "Unix socket is skipped without creating a destination");

            size = 23;
            check(get_dir_size(src_socket, &size) == 0 && size == 23,
                  "Unix socket contributes no payload bytes");
        }
    }

    int device_fixture = lstat("/dev/null", &st) == 0 && S_ISCHR(st.st_mode);
    check(device_fixture, "/dev/null is available as the device-node fixture");
    errno = 0;
    check(device_fixture &&
          backup_capture_at(&ctx, "/dev/null", dest_fd, "copied.device") == 0 &&
          lstat(dest_device, &st) == -1 && errno == ENOENT,
          "device node is skipped without creating a destination");

    size = 29;
    check(device_fixture && get_dir_size("/dev/null", &size) == 0 && size == 29,
          "device node contributes no payload bytes");

    /* --------------------------------------------------------------------- */
    /* Destination anchoring: symlinks are never followed                     */
    /* --------------------------------------------------------------------- */

    char sentinel[PATH_MAX];
    if (path_join(sentinel, sizeof(sentinel), outside_dir, "sentinel.txt") != 0)
        fatal("could not build fixture paths");
    write_file(sentinel, "untouched");

    char src_file[PATH_MAX];
    if (path_join(src_file, sizeof(src_file), src_dir, "payload.txt") != 0)
        fatal("could not build fixture paths");
    write_file(src_file, "payload");

    // A symlink standing exactly where the walker would create its final
    // object: writing through it would land in outside/, so it must be refused.
    char final_link[PATH_MAX];
    if (path_join(final_link, sizeof(final_link), dest_dir, "final_link") != 0)
        fatal("could not build fixture paths");
    if (symlink(sentinel, final_link) != 0)
        fatal("could not create the final-destination symlink fixture");

    check(backup_capture_at(&ctx, src_file, dest_fd, "final_link") != 0,
          "a symlink at the final destination address is refused, not written through");
    check(file_contains(sentinel, "untouched"),
          "the file outside the destination is unchanged by that refusal");

    // The same escape one level down: the source is a directory, and the
    // destination already holds a symlinked subdirectory the walker would
    // otherwise descend into.
    char nested_src[PATH_MAX], nested_child[PATH_MAX];
    if (path_join(nested_src, sizeof(nested_src), src_dir, "tree") != 0)
        fatal("could not build fixture paths");
    if (mkdir(nested_src, 0755) != 0)
        fatal("could not create the nested source fixture");
    if (path_join(nested_child, sizeof(nested_child), nested_src, "inner") != 0)
        fatal("could not build fixture paths");
    if (mkdir(nested_child, 0755) != 0)
        fatal("could not create the nested source fixture");

    char smuggled_src[PATH_MAX];
    if (path_join(smuggled_src, sizeof(smuggled_src), nested_child, "sentinel.txt") != 0)
        fatal("could not build fixture paths");
    write_file(smuggled_src, "smuggled");

    char tree_dest[PATH_MAX], intermediate_link[PATH_MAX];
    if (path_join(tree_dest, sizeof(tree_dest), dest_dir, "tree") != 0)
        fatal("could not build fixture paths");
    if (mkdir(tree_dest, 0755) != 0)
        fatal("could not create the nested destination fixture");
    if (path_join(intermediate_link, sizeof(intermediate_link), tree_dest, "inner") != 0)
        fatal("could not build fixture paths");
    if (symlink(outside_dir, intermediate_link) != 0)
        fatal("could not create the intermediate symlink fixture");

    check(backup_capture_at(&ctx, nested_src, dest_fd, "tree") != 0,
          "an intermediate destination symlink is refused, not descended through");
    check(file_contains(sentinel, "untouched"),
          "the file outside the destination is unchanged by that refusal either");

    /* --------------------------------------------------------------------- */
    /* Resume and collision                                                   */
    /* --------------------------------------------------------------------- */

    char resumed_dest[PATH_MAX];
    if (path_join(resumed_dest, sizeof(resumed_dest), dest_dir, "resumed.txt") != 0)
        fatal("could not build fixture paths");

    check(backup_capture_at(&ctx, src_file, dest_fd, "resumed.txt") == 0 &&
          file_contains(resumed_dest, "payload"),
          "a regular file is captured");
    check(backup_capture_at(&ctx, src_file, dest_fd, "resumed.txt") == 0 &&
          file_contains(resumed_dest, "payload"),
          "an existing regular file with matching size and mtime is resumed past");

    // A stale destination of the same name but different content is rewritten:
    // matching size and mtime is what marks work as already done, and this
    // matches neither.
    write_file(resumed_dest, "stale-and-longer-than-the-source");
    check(backup_capture_at(&ctx, src_file, dest_fd, "resumed.txt") == 0 &&
          file_contains(resumed_dest, "payload"),
          "a destination file that does not match the source is captured again");

    char src_symlink[PATH_MAX];
    if (path_join(src_symlink, sizeof(src_symlink), src_dir, "link") != 0)
        fatal("could not build fixture paths");
    if (symlink("target-of-the-source-link", src_symlink) != 0)
        fatal("could not create the source symlink fixture");

    check(backup_capture_at(&ctx, src_symlink, dest_fd, "copied.link") == 0,
          "a symlink is captured as a symlink");
    check(backup_capture_at(&ctx, src_symlink, dest_fd, "copied.link") == 0,
          "an existing symlink with the identical target is resumed past");

    char differing_link[PATH_MAX];
    if (path_join(differing_link, sizeof(differing_link), dest_dir, "differing.link") != 0)
        fatal("could not build fixture paths");
    if (symlink("some-other-target", differing_link) != 0)
        fatal("could not create the differing symlink fixture");
    check(backup_capture_at(&ctx, src_symlink, dest_fd, "differing.link") != 0,
          "an existing symlink with a different target is refused, not replaced");

    char existing_dir_dest[PATH_MAX], existing_dir_child[PATH_MAX];
    if (path_join(existing_dir_dest, sizeof(existing_dir_dest), dest_dir, "existing_tree") != 0)
        fatal("could not build fixture paths");
    if (mkdir(existing_dir_dest, 0755) != 0)
        fatal("could not create the existing destination directory fixture");
    check(backup_capture_at(&ctx, nested_child, dest_fd, "existing_tree") == 0,
          "an existing destination directory of the right type is accepted on resume");
    check(path_join(existing_dir_child, sizeof(existing_dir_child), existing_dir_dest, "sentinel.txt") == 0 &&
          file_contains(existing_dir_child, "smuggled"),
          "resuming into it still writes the source's own children");

    // Type collisions in both directions: a regular file where a directory
    // belongs, and a directory where a regular file belongs.
    char collide_file[PATH_MAX];
    if (path_join(collide_file, sizeof(collide_file), dest_dir, "collide_file") != 0)
        fatal("could not build fixture paths");
    write_file(collide_file, "not a directory");
    check(backup_capture_at(&ctx, nested_child, dest_fd, "collide_file") != 0,
          "a regular file where a directory belongs is refused");

    char collide_dir[PATH_MAX];
    if (path_join(collide_dir, sizeof(collide_dir), dest_dir, "collide_dir") != 0)
        fatal("could not build fixture paths");
    if (mkdir(collide_dir, 0755) != 0)
        fatal("could not create the colliding directory fixture");
    check(backup_capture_at(&ctx, src_file, dest_fd, "collide_dir") != 0,
          "a directory where a regular file belongs is refused");
    check(backup_capture_at(&ctx, src_fifo, dest_fd, "collide_dir") != 0,
          "a directory where a FIFO belongs is refused");

    /* --------------------------------------------------------------------- */
    /* Entry-point contract                                                   */
    /* --------------------------------------------------------------------- */

    CloneContext portable_ctx = { .operation = CLONE_BACKUP, .representation = CLONE_PORTABLE_SIDECAR };
    CloneContext restore_ctx  = { .operation = CLONE_RESTORE, .representation = CLONE_NATIVE_TREE };

    check(backup_capture_at(NULL, src_file, dest_fd, "refused") == -1,
          "backup_capture_at refuses a NULL context");
    check(backup_capture_at(&restore_ctx, src_file, dest_fd, "refused") == -1,
          "backup_capture_at refuses a restore context");
    check(backup_capture_at(&portable_ctx, src_file, dest_fd, "refused") == -1,
          "portable representation is refused, not run as a native clone");
    check(backup_capture_at(&ctx, src_file, -1, "refused") == -1,
          "an invalid destination fd is refused");

    static const char *const unsafe_leaves[] = { "", ".", "..", "a/b", "/abs", NULL };
    int all_unsafe_refused = 1;
    for (int i = 0; unsafe_leaves[i] != NULL; i++)
        if (backup_capture_at(&ctx, src_file, dest_fd, unsafe_leaves[i]) != -1)
            all_unsafe_refused = 0;
    check(all_unsafe_refused && backup_capture_at(&ctx, src_file, dest_fd, NULL) == -1,
          "a destination leaf that is not a single safe component is refused");

    char refused_path[PATH_MAX];
    check(path_join(refused_path, sizeof(refused_path), dest_dir, "refused") == 0 &&
          lstat(refused_path, &st) == -1,
          "no refused call wrote a destination");

    close(dest_fd);
    if (socket_fd >= 0)
        close(socket_fd); // must precede removal: the bound socket is a fixture file
    remove_tree(root);

    if (failures > 0)
    {
        printf(RED "%d capture walker test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
