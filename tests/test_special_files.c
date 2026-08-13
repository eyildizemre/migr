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

extern int native_hardlink_identity_matches(const struct stat *linked,
                                            const struct stat *reference);
extern int native_visited_contains(const void *set, const char *root_key,
                                   const char *rel_path);

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

static void test_native_hardlinks(void)
{
    printf(BLUE "::" NC " native hardlink capture (unit)\n");

    char root[] = "/tmp/migr_native_hardlink_XXXXXX";
    if (mkdtemp(root) == NULL)
        fatal("could not create native hardlink test root");

    char source[PATH_MAX], destination[PATH_MAX];
    if (path_join(source, sizeof(source), root, "source") != 0 ||
        path_join(destination, sizeof(destination), root, "destination") != 0 ||
        mkdir(source, 0755) != 0 || mkdir(destination, 0755) != 0)
        fatal("could not create native hardlink test directories");

    char first_dir[PATH_MAX], second_dir[PATH_MAX];
    char first[PATH_MAX], second[PATH_MAX];
    if (path_join(first_dir, sizeof(first_dir), source, "first") != 0 ||
        path_join(second_dir, sizeof(second_dir), source, "second") != 0 ||
        mkdir(first_dir, 0755) != 0 || mkdir(second_dir, 0755) != 0 ||
        path_join(first, sizeof(first), first_dir, "representative") != 0 ||
        path_join(second, sizeof(second), second_dir, "alias") != 0)
        fatal("could not create native hardlink source layout");

    write_file(first, "native-hardlink-content");
    if (link(first, second) != 0)
        fatal("could not create native hardlink source pair");
    if (chmod(first, 0640) != 0)
        fatal("could not set native hardlink source mode");
    struct timespec times[2] = {
        { .tv_sec = 1234567890, .tv_nsec = 123456789 },
        { .tv_sec = 1234567890, .tv_nsec = 987654321 }
    };
    if (utimensat(AT_FDCWD, first, times, 0) != 0)
        fatal("could not set native hardlink source times");

    struct stat source_st;
    check(lstat(first, &source_st) == 0 && lstat(second, &source_st) == 0,
          "native hardlink source pair is present");
    struct stat first_source_st;
    struct stat second_source_st;
    int source_pair_ok = lstat(first, &first_source_st) == 0 &&
                         lstat(second, &second_source_st) == 0 &&
                         first_source_st.st_dev == second_source_st.st_dev &&
                         first_source_st.st_ino == second_source_st.st_ino &&
                         first_source_st.st_nlink == 2;
    check(source_pair_ok, "native hardlink source pair shares one inode");

    int destination_fd = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (destination_fd < 0)
        fatal("could not open native hardlink destination");

    void *map = native_inode_map_create();
    if (map == NULL)
        fatal("could not create native hardlink inode map");
    CloneContext context = {
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1,
        .metadata_preflight_done = 1,
        .inode_map = map
    };

    check(backup_capture_at(&context, source, destination_fd, "tree") == 0,
          "nested native hardlink capture succeeds");

    char destination_first[PATH_MAX], destination_second[PATH_MAX];
    if (path_join(destination_first, sizeof(destination_first), destination,
                  "tree/first/representative") != 0 ||
        path_join(destination_second, sizeof(destination_second), destination,
                  "tree/second/alias") != 0)
        fatal("could not build native hardlink destination paths");
    struct stat destination_first_st;
    struct stat destination_second_st;
    int destination_pair_ok =
        lstat(destination_first, &destination_first_st) == 0 &&
        lstat(destination_second, &destination_second_st) == 0 &&
        native_hardlink_identity_matches(&destination_first_st,
                                         &destination_second_st) &&
        destination_first_st.st_nlink == 2 &&
        file_contains(destination_first, "native-hardlink-content") &&
        file_contains(destination_second, "native-hardlink-content");
    check(destination_pair_ok,
          "nested native hardlink capture preserves the destination inode");
    check(destination_pair_ok &&
              (destination_first_st.st_mode & 07777) ==
                  (first_source_st.st_mode & 07777) &&
              destination_first_st.st_uid == first_source_st.st_uid &&
              destination_first_st.st_gid == first_source_st.st_gid &&
              destination_first_st.st_atim.tv_sec == first_source_st.st_atim.tv_sec &&
              destination_first_st.st_atim.tv_nsec == first_source_st.st_atim.tv_nsec &&
              destination_first_st.st_mtim.tv_sec == first_source_st.st_mtim.tv_sec &&
              destination_first_st.st_mtim.tv_nsec == first_source_st.st_mtim.tv_nsec,
          "native hardlink representative metadata is preserved");
    native_inode_map_free(map);

    map = native_inode_map_create();
    if (map == NULL)
        fatal("could not create native hardlink resume map");
    context.inode_map = map;
    check(backup_capture_at(&context, source, destination_fd, "tree") == 0,
          "native hardlink capture resumes an existing pair");
    struct stat resumed_first_st;
    struct stat resumed_second_st;
    int resumed_pair_ok = lstat(destination_first, &resumed_first_st) == 0 &&
                          lstat(destination_second, &resumed_second_st) == 0 &&
                          native_hardlink_identity_matches(&resumed_first_st,
                                                           &resumed_second_st);
    check(resumed_pair_ok, "resume keeps both native hardlink names linked");
    native_inode_map_free(map);

    char source_a[PATH_MAX], source_b[PATH_MAX];
    char source_a_file[PATH_MAX], source_b_file[PATH_MAX];
    char destination_a[PATH_MAX], destination_b[PATH_MAX];
    if (path_join(source_a, sizeof(source_a), root, "source-a") != 0 ||
        path_join(source_b, sizeof(source_b), root, "source-b") != 0 ||
        mkdir(source_a, 0755) != 0 || mkdir(source_b, 0755) != 0 ||
        path_join(source_a_file, sizeof(source_a_file), source_a, "payload") != 0 ||
        path_join(source_b_file, sizeof(source_b_file), source_b, "payload") != 0)
        fatal("could not create cross-root native hardlink sources");
    write_file(source_a_file, "cross-root-content");
    if (link(source_a_file, source_b_file) != 0)
        fatal("could not create cross-root native hardlink pair");
    if (path_join(destination_a, sizeof(destination_a), destination, "root-a") != 0 ||
        path_join(destination_b, sizeof(destination_b), destination, "root-b") != 0 ||
        mkdir(destination_a, 0755) != 0 || mkdir(destination_b, 0755) != 0)
        fatal("could not create cross-root native hardlink destinations");

    map = native_inode_map_create();
    if (map == NULL)
        fatal("could not create native cross-root hardlink map");
    context.inode_map = map;
    check(backup_capture_at(&context, source_a, destination_fd, "root-a") == 0 &&
              backup_capture_at(&context, source_b, destination_fd, "root-b") == 0,
          "cross-root native hardlink capture succeeds");
    char destination_a_file[PATH_MAX], destination_b_file[PATH_MAX];
    if (path_join(destination_a_file, sizeof(destination_a_file), destination_a,
                  "payload") != 0 ||
        path_join(destination_b_file, sizeof(destination_b_file), destination_b,
                  "payload") != 0)
        fatal("could not build cross-root native hardlink destinations");
    struct stat destination_a_st;
    struct stat destination_b_st;
    check(lstat(destination_a_file, &destination_a_st) == 0 &&
              lstat(destination_b_file, &destination_b_st) == 0 &&
              native_hardlink_identity_matches(&destination_a_st,
                                               &destination_b_st) &&
              destination_a_st.st_nlink == 2,
          "native hardlinks remain linked across capture roots");
    native_inode_map_free(map);

    struct stat identity_a = {0};
    struct stat identity_b = {0};
    identity_a.st_dev = 1;
    identity_a.st_ino = 2;
    identity_b = identity_a;
    check(native_hardlink_identity_matches(&identity_a, &identity_b),
          "native hardlink identity accepts matching device and inode");
    identity_b.st_ino++;
    check(!native_hardlink_identity_matches(&identity_a, &identity_b),
          "native hardlink identity rejects an inode mismatch");
    identity_b = identity_a;
    identity_b.st_dev++;
    check(!native_hardlink_identity_matches(&identity_a, &identity_b),
          "native hardlink identity rejects a device mismatch");

    close(destination_fd);
    remove_tree(root);
}

static void test_native_visited_paths(void)
{
    printf(BLUE "::" NC " native capture visited paths (unit)\n");

    char root[] = "/tmp/migr_native_visited_XXXXXX";
    if (mkdtemp(root) == NULL)
        fatal("could not create native visited test root");

    char source[PATH_MAX], destination[PATH_MAX], file[PATH_MAX];
    char subdir[PATH_MAX], nested[PATH_MAX], link_path[PATH_MAX];
    char fifo[PATH_MAX], socket_path[PATH_MAX];
    if (path_join(source, sizeof(source), root, "source") != 0 ||
        path_join(destination, sizeof(destination), root, "destination") != 0 ||
        path_join(file, sizeof(file), source, "file.txt") != 0 ||
        path_join(subdir, sizeof(subdir), source, "subdir") != 0 ||
        path_join(nested, sizeof(nested), subdir, "nested.txt") != 0 ||
        path_join(link_path, sizeof(link_path), source, "link") != 0 ||
        path_join(fifo, sizeof(fifo), source, "fifo") != 0 ||
        path_join(socket_path, sizeof(socket_path), source, "sock") != 0 ||
        mkdir(source, 0755) != 0 || mkdir(destination, 0755) != 0 ||
        mkdir(subdir, 0755) != 0)
        fatal("could not create native visited test layout");
    write_file(file, "visited-file");
    write_file(nested, "visited-nested");
    if (symlink("visited-target", link_path) != 0 ||
        mkfifo(fifo, 0640) != 0)
        fatal("could not create native visited test entries");

    int socket_available = 0;
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        if (errno != EPERM && errno != EACCES && errno != EAFNOSUPPORT)
            fatal("could not create native visited socket fixture");
    }
    else
    {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        if (strlen(socket_path) >= sizeof(address.sun_path))
            fatal("native visited socket fixture path is too long");
        strcpy(address.sun_path, socket_path);
        if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) == 0)
            socket_available = 1;
        else if (errno != EPERM && errno != EACCES && errno != EAFNOSUPPORT)
            fatal("could not bind native visited socket fixture");
        close(socket_fd);
        if (!socket_available)
            unlink(socket_path);
    }

    int destination_fd = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (destination_fd < 0)
        fatal("could not open native visited destination");
    void *visited = native_visited_create();
    if (visited == NULL)
        fatal("could not create native visited set");
    CloneContext context = {
        .operation = CLONE_BACKUP,
        .representation = CLONE_NATIVE_TREE,
        .timestamp_policy_configured = 1,
        .nsec_exact = 1,
        .metadata_preflight_done = 1,
        .visited = visited
    };

    check(backup_capture_at(&context, source, destination_fd, "tree") == 0,
          "native capture with visited tracking succeeds");
    check(native_visited_contains(context.visited, "tree", "") == 1,
          "visited set records the root object");
    check(native_visited_contains(context.visited, "tree", "file.txt") == 1,
          "visited set records a regular file");
    check(native_visited_contains(context.visited, "tree", "subdir") == 1,
          "visited set records a nested directory");
    check(native_visited_contains(context.visited, "tree",
                                  "subdir/nested.txt") == 1,
          "visited set records a nested regular file without a leading slash");
    check(native_visited_contains(context.visited, "tree", "link") == 1,
          "visited set records a symlink");
    check(native_visited_contains(context.visited, "tree", "fifo") == 1,
          "visited set records a FIFO");
    if (socket_available)
        check(native_visited_contains(context.visited, "tree", "sock") == 0,
              "visited set excludes a skipped socket");
    else
        printf("  " BLUE "-" NC " Unix socket fixture unavailable on this host\n");
    struct stat device_st;
    int device_available = lstat("/dev/null", &device_st) == 0 &&
                           S_ISCHR(device_st.st_mode);
    if (device_available)
        check(backup_capture_at(&context, "/dev/null", destination_fd,
                                "device") == 0 &&
                  native_visited_contains(context.visited, "device", "") == 0,
              "visited set excludes a skipped device node");
    else
        printf("  " BLUE "-" NC " device-node fixture unavailable on this host\n");
    check(native_visited_contains(context.visited, "tree", "/file.txt") == 0,
          "visited set does not add a leading slash to relative paths");

    native_visited_free(context.visited);
    close(destination_fd);
    remove_tree(root);
}

int main(void)
{
    printf(BLUE "::" NC " backup capture walker (unit)\n");

    test_native_hardlinks();
    test_native_visited_paths();

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
