// Unit tests for the FD-anchored native restore core (docs/DECISIONS.md D15
// and D16): restore_native_at(), restore_native_preflight_at(), and
// restore_native_source_status_at(), all declared in fileops.h. Backup's own
// path-based walker (clone_tree() / backup_capture()) is untouched by this
// module and is covered separately by tests/test_special_files.c.
//
// restore_native_at() always runs restore_native_preflight_at()'s exact
// validation pass before mutating anything, so the two can never disagree in
// practice; most cases below exercise both through the single entry point.
// A few symlink-escape cases additionally call restore_native_preflight_at()
// and restore_native_source_status_at() directly, since those are the
// functions restore.c's own dry-run path calls without ever reaching
// restore_native_at() at all.
//
// Full end-to-end restore orchestration (XDG dirs, dotfiles, browser
// profiles, manifest-driven naming) stays in tests/test.sh, which also
// covers the two behavior changes this core introduces: a dangling payload
// symlink is now previewed and restored rather than silently skipped, and
// dry-run now refuses an unsafe destination exactly like a live restore does.

#define _GNU_SOURCE
#include <dirent.h>
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
#include <time.h>
#include <unistd.h>

#include "fileops.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static const CloneContext RESTORE_CTX = { .operation = CLONE_RESTORE, .representation = CLONE_NATIVE_TREE };

static void fresh_mkdtemp(char *buf, size_t bufsize, const char *prefix)
{
    if ((size_t)snprintf(buf, bufsize, "/tmp/%s_XXXXXX", prefix) >= bufsize || mkdtemp(buf) == NULL)
    {
        printf(RED "fixture: could not create a temp dir for %s" NC "\n", prefix);
        exit(1);
    }
}

static int remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path)
{
    if (nftw(path, remove_cb, 16, FTW_DEPTH | FTW_PHYS) != 0)
    {
        printf(RED "fixture: could not clean up %s" NC "\n", path);
        exit(1);
    }
}

static int open_dir_fd(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
    {
        printf(RED "fixture: could not open directory %s" NC "\n", path);
        exit(1);
    }
    return fd;
}

static int fd_still_names_same_directory(int fd, const struct stat *before)
{
    struct stat after;
    return fcntl(fd, F_GETFD) >= 0 &&
           fstat(fd, &after) == 0 &&
           after.st_dev == before->st_dev &&
           after.st_ino == before->st_ino &&
           S_ISDIR(after.st_mode);
}

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "fixture: could not write %s" NC "\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

// snprintf(out, sizeof(out), "%s/%s", a, b) triggers -Wformat-truncation
// here regardless of actual runtime lengths: with every fixture buffer the
// same PATH_MAX size, gcc's worst-case analysis can't see that a and b are
// each far short of it. A plain length-checked concatenation sidesteps that
// warning class entirely (it isn't a printf-family call at all) while still
// refusing -- not silently truncating -- a genuinely oversized join.
static void join_path(char *out, size_t out_size, const char *a, const char *b)
{
    size_t a_len = strlen(a);
    size_t b_len = strlen(b);
    if (a_len + 1 + b_len + 1 > out_size)
    {
        printf(RED "fixture: path too long" NC "\n");
        exit(1);
    }
    memcpy(out, a, a_len);
    out[a_len] = '/';
    memcpy(out + a_len + 1, b, b_len + 1);
}

static void write_file_under(const char *root, const char *rel, const char *content)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), root, rel);
    write_file(path, content);
}

static void read_file(const char *path, char *buf, size_t bufsize)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        printf(RED "fixture: could not read %s" NC "\n", path);
        exit(1);
    }
    size_t n = fread(buf, 1, bufsize - 1, f);
    buf[n] = '\0';
    fclose(f);
}

/* ========================================================================= */
/* Escape rejection                                                         */
/* ========================================================================= */

static void test_rejects_destination_intermediate_symlink_escape(void)
{
    printf(BLUE "::" NC " restore_native_at: an intermediate destination symlink escape is rejected\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX], outside_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");
    fresh_mkdtemp(outside_root, sizeof(outside_root), "restore_outside");

    char sentinel_path[PATH_MAX];
    join_path(sentinel_path, sizeof(sentinel_path), outside_root, "sentinel.txt");
    write_file(sentinel_path, "sentinel-content");

    write_file_under(source_root, "note.txt", "note-content");

    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), dest_root, "escape_link");
    check(symlink(outside_root, link_path) == 0,
          "fixture: create an intermediate destination symlink pointing outside dest_root");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_preflight_at(&RESTORE_CTX, source_fd, "note.txt",
                                      dest_fd, "escape_link/smuggled.txt") != 0,
          "preflight refuses the intermediate destination symlink");
    int rc = restore_native_at(&RESTORE_CTX, source_fd, "note.txt",
                               dest_fd, "escape_link/smuggled.txt");
    check(rc != 0, "restoring through an intermediate destination symlink is refused");

    char check_path[PATH_MAX];
    join_path(check_path, sizeof(check_path), outside_root, "smuggled.txt");
    struct stat st;
    check(stat(check_path, &st) != 0, "nothing was smuggled into the symlink's real target");

    char content[64];
    read_file(sentinel_path, content, sizeof(content));
    check(strcmp(content, "sentinel-content") == 0, "the sentinel file outside dest_root is byte-for-byte unchanged");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
    remove_tree(outside_root);
}

static void test_rejects_final_destination_symlink(void)
{
    printf(BLUE "::" NC " restore_native_at: an existing final destination symlink is rejected\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX], outside_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");
    fresh_mkdtemp(outside_root, sizeof(outside_root), "restore_outside");

    char sentinel_path[PATH_MAX];
    join_path(sentinel_path, sizeof(sentinel_path), outside_root, "secret.txt");
    write_file(sentinel_path, "do-not-touch");

    write_file_under(source_root, "note.txt", "attacker-controlled-content");

    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), dest_root, "note.txt");
    check(symlink(sentinel_path, link_path) == 0, "fixture: dest leaf is a pre-existing symlink to an outside file");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    int rc = restore_native_at(&RESTORE_CTX, source_fd, "note.txt", dest_fd, "note.txt");
    check(rc != 0, "restoring onto an existing destination symlink is refused, regardless of source type");

    char content[64];
    read_file(sentinel_path, content, sizeof(content));
    check(strcmp(content, "do-not-touch") == 0, "the symlink's real target is byte-for-byte unchanged");

    struct stat st;
    check(lstat(link_path, &st) == 0 && S_ISLNK(st.st_mode),
          "the destination symlink itself is left in place, never replaced");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
    remove_tree(outside_root);
}

static void test_rejects_source_intermediate_symlink_redirect(void)
{
    printf(BLUE "::" NC " restore_native_at: an intermediate source symlink redirect is rejected\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX], outside_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");
    fresh_mkdtemp(outside_root, sizeof(outside_root), "restore_outside");

    char secret_path[PATH_MAX];
    join_path(secret_path, sizeof(secret_path), outside_root, "secret.txt");
    write_file(secret_path, "outside-payload-content");

    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source_root, "redirect");
    check(symlink(outside_root, link_path) == 0,
          "fixture: an intermediate source symlink points outside source_root");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_source_status_at(source_fd,
                                          "redirect/secret.txt") ==
              RESTORE_SOURCE_ERROR,
          "source status reports an unsafe intermediate symlink as an error");
    check(restore_native_preflight_at(&RESTORE_CTX, source_fd,
                                      "redirect/secret.txt",
                                      dest_fd, "out.txt") != 0,
          "preflight refuses the intermediate source symlink");
    int rc = restore_native_at(&RESTORE_CTX, source_fd,
                               "redirect/secret.txt", dest_fd, "out.txt");
    check(rc != 0, "reading through an intermediate source symlink is refused");

    char dest_check[PATH_MAX];
    join_path(dest_check, sizeof(dest_check), dest_root, "out.txt");
    struct stat st;
    check(stat(dest_check, &st) != 0, "nothing was written to the destination");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
    remove_tree(outside_root);
}

static void test_recreates_source_leaf_symlink_without_following(void)
{
    printf(BLUE "::" NC " restore_native_at: a genuine source leaf symlink is recreated by target string, not followed\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    // Deliberately absolute AND containing "..": neither disqualifies a
    // symlink *object* from being copied -- only the address used to reach
    // the object being restored is validated, never the symlink's own
    // stored target string.
    const char *target = "/some/../weird/target-that-does-not-exist";
    char link_path[PATH_MAX];
    join_path(link_path, sizeof(link_path), source_root, "mylink");
    check(symlink(target, link_path) == 0, "fixture: create the source symlink");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_source_status_at(source_fd, "mylink") ==
              RESTORE_SOURCE_PRESENT,
          "a dangling leaf symlink is a present source object");
    check(restore_native_source_status_at(source_fd, "absent") ==
              RESTORE_SOURCE_MISSING,
          "an absent final component is reported as missing");
    int rc = restore_native_at(&RESTORE_CTX, source_fd, "mylink", dest_fd, "mylink");
    check(rc == 0, "restoring a genuine symlink object succeeds");

    char dest_link[PATH_MAX];
    join_path(dest_link, sizeof(dest_link), dest_root, "mylink");
    struct stat st;
    check(lstat(dest_link, &st) == 0 && S_ISLNK(st.st_mode),
          "the destination is itself a symlink, never a followed/resolved file");

    char readback[PATH_MAX];
    ssize_t len = readlink(dest_link, readback, sizeof(readback) - 1);
    check(len >= 0, "fixture: readlink the recreated symlink");
    if (len >= 0)
    {
        readback[len] = '\0';
        check(strcmp(readback, target) == 0,
              "the recreated symlink's target string exactly matches the source's, absolute-and-'..' included");
    }

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

/* ========================================================================= */
/* Path lexical validation                                                  */
/* ========================================================================= */

typedef struct
{
    const char *source_rel;
    const char *dest_rel;
    const char *label;
} InvalidRelCase;

static const InvalidRelCase invalid_rel_cases[] = {
    { "/etc/passwd", "out.txt",   "a leading '/' in source_rel is rejected" },
    { "note.txt",    "/tmp/evil", "a leading '/' in destination_rel is rejected" },
    { "../escape",   "out.txt",   "a leading '..' component in source_rel is rejected" },
    { "note.txt",    "../escape", "a leading '..' component in destination_rel is rejected" },
    { "a/../b",      "out.txt",   "an interior '..' component in source_rel is rejected" },
    { "note.txt",    "a/../b",    "an interior '..' component in destination_rel is rejected" },
    { "a//b",        "out.txt",   "an empty interior component (\"a//b\") in source_rel is rejected" },
    { "note.txt",    "a/",        "a trailing slash in destination_rel is rejected" },
    { "./note.txt",  "out.txt",   "a bare '.' component in source_rel is rejected" },
};

static int dir_is_empty(const char *path)
{
    DIR *d = opendir(path);
    if (d == NULL)
        return 0;
    struct dirent *entry;
    int empty = 1;
    while ((entry = readdir(d)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            empty = 0;
    closedir(d);
    return empty;
}

static void test_rejects_lexically_invalid_relative_paths(void)
{
    printf(BLUE "::" NC " restore_native_at: lexically invalid relative addresses are rejected without any mutation\n");

    for (size_t i = 0; i < sizeof(invalid_rel_cases) / sizeof(invalid_rel_cases[0]); i++)
    {
        char source_base[PATH_MAX], source_root[PATH_MAX];
        char dest_base[PATH_MAX], dest_root[PATH_MAX];
        fresh_mkdtemp(source_base, sizeof(source_base), "restore_src");
        fresh_mkdtemp(dest_base, sizeof(dest_base), "restore_dst");
        join_path(source_root, sizeof(source_root), source_base, "root");
        join_path(dest_root, sizeof(dest_root), dest_base, "root");
        check(mkdir(source_root, 0755) == 0, "fixture: create nested source root");
        check(mkdir(dest_root, 0755) == 0, "fixture: create nested destination root");
        write_file_under(source_root, "note.txt", "content");
        write_file_under(source_root, "b", "normalized-source");

        char source_a[PATH_MAX];
        join_path(source_a, sizeof(source_a), source_root, "a");
        check(mkdir(source_a, 0755) == 0, "fixture: create source a/");
        write_file_under(source_root, "a/b", "collapsed-source");

        char source_escape[PATH_MAX];
        join_path(source_escape, sizeof(source_escape), source_base, "escape");
        write_file(source_escape, "parent-source");

        char absolute_dest[PATH_MAX];
        join_path(absolute_dest, sizeof(absolute_dest), dest_base, "absolute");
        char parent_dest[PATH_MAX];
        join_path(parent_dest, sizeof(parent_dest), dest_base, "escape");
        write_file(parent_dest, "outside-sentinel");
        const char *source_rel = invalid_rel_cases[i].source_rel;
        const char *dest_rel = invalid_rel_cases[i].dest_rel;
        if (strcmp(dest_rel, "/tmp/evil") == 0)
            dest_rel = absolute_dest;

        int source_fd = open_dir_fd(source_root);
        int dest_fd = open_dir_fd(dest_root);

        int rc = restore_native_at(&RESTORE_CTX, source_fd, source_rel,
                                   dest_fd, dest_rel);
        check(rc != 0, invalid_rel_cases[i].label);
        check(dir_is_empty(dest_root), "no mutation occurred in dest_root for this rejected address");
        struct stat st;
        check(lstat(absolute_dest, &st) != 0,
              "an absolute destination address did not write outside dest_root");
        char outside_content[32];
        read_file(parent_dest, outside_content, sizeof(outside_content));
        check(strcmp(outside_content, "outside-sentinel") == 0,
              "a parent destination address did not alter its outside sentinel");

        close(source_fd);
        close(dest_fd);
        remove_tree(source_base);
        remove_tree(dest_base);
    }
}

/* ========================================================================= */
/* Normal restore behavior                                                  */
/* ========================================================================= */

static void test_restores_nested_files_and_directories(void)
{
    printf(BLUE "::" NC " restore_native_at: a normal nested tree of files and directories restores correctly\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    char proj_path[PATH_MAX], sub_path[PATH_MAX], sub2_path[PATH_MAX];
    join_path(proj_path, sizeof(proj_path), source_root, "proj");
    check(mkdir(proj_path, 0755) == 0, "fixture: mkdir proj");
    join_path(sub_path, sizeof(sub_path), proj_path, "sub");
    check(mkdir(sub_path, 0755) == 0, "fixture: mkdir proj/sub");
    join_path(sub2_path, sizeof(sub2_path), proj_path, "sub2");
    check(mkdir(sub2_path, 0755) == 0, "fixture: mkdir proj/sub2 (left empty)");
    write_file_under(source_root, "proj/sub/file.txt", "nested-content");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(&RESTORE_CTX, source_fd, "proj", dest_fd, "proj") == 0,
          "restoring the nested tree succeeds");

    char dest_file[PATH_MAX];
    join_path(dest_file, sizeof(dest_file), dest_root, "proj/sub/file.txt");
    char content[64];
    read_file(dest_file, content, sizeof(content));
    check(strcmp(content, "nested-content") == 0, "the nested file's content matches the source");

    char dest_sub2[PATH_MAX];
    join_path(dest_sub2, sizeof(dest_sub2), dest_root, "proj/sub2");
    struct stat st;
    check(stat(dest_sub2, &st) == 0 && S_ISDIR(st.st_mode), "the empty nested directory was recreated");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

static void test_regular_file_resume_and_overwrite(void)
{
    printf(BLUE "::" NC " restore_native_at: an existing regular file resumes (matching) or is overwritten (stale)\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    write_file_under(source_root, "file.txt", "source-content-v1");
    char source_file[PATH_MAX];
    join_path(source_file, sizeof(source_file), source_root, "file.txt");
    struct timespec times[2] = { { .tv_sec = 1700000000, .tv_nsec = 0 }, { .tv_sec = 1700000000, .tv_nsec = 0 } };
    check(utimensat(AT_FDCWD, source_file, times, 0) == 0, "fixture: set a known mtime on the source file");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(&RESTORE_CTX, source_fd, "file.txt", dest_fd, "file.txt") == 0,
          "first restore succeeds");

    char dest_file[PATH_MAX];
    join_path(dest_file, sizeof(dest_file), dest_root, "file.txt");
    char content[64];
    read_file(dest_file, content, sizeof(content));
    check(strcmp(content, "source-content-v1") == 0, "the file was copied correctly");

    // Tamper with dest's content while keeping its size and mtime identical
    // to the source, then restore again: if the resume/skip path is
    // genuinely exercised, this tampered content must survive untouched.
    write_file(dest_file, "source-content-v2"); // same length as v1
    check(utimensat(AT_FDCWD, dest_file, times, 0) == 0, "fixture: restore dest's mtime to match source exactly");

    check(restore_native_at(&RESTORE_CTX, source_fd, "file.txt", dest_fd, "file.txt") == 0,
          "second restore (matching size/mtime) succeeds");
    read_file(dest_file, content, sizeof(content));
    check(strcmp(content, "source-content-v2") == 0,
          "a dest file matching source's size and mtime is left alone (resumed), not re-copied");

    // Now make dest genuinely stale: restore must overwrite it.
    struct timespec old_times[2] = { { .tv_sec = 1000000000, .tv_nsec = 0 }, { .tv_sec = 1000000000, .tv_nsec = 0 } };
    check(utimensat(AT_FDCWD, dest_file, old_times, 0) == 0, "fixture: make dest's mtime stale");
    check(restore_native_at(&RESTORE_CTX, source_fd, "file.txt", dest_fd, "file.txt") == 0,
          "third restore (stale dest) succeeds");
    read_file(dest_file, content, sizeof(content));
    check(strcmp(content, "source-content-v1") == 0,
          "a dest file with a stale mtime is overwritten with the source's content");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

static void test_restores_fifo(void)
{
    printf(BLUE "::" NC " restore_native_at: a normal FIFO restores as a FIFO\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    char fifo_path[PATH_MAX];
    join_path(fifo_path, sizeof(fifo_path), source_root, "myfifo");
    check(mkfifo(fifo_path, 0600) == 0, "fixture: create a source FIFO");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(&RESTORE_CTX, source_fd, "myfifo", dest_fd, "myfifo") == 0,
          "restoring a FIFO succeeds");

    char dest_fifo[PATH_MAX];
    join_path(dest_fifo, sizeof(dest_fifo), dest_root, "myfifo");
    struct stat st;
    check(lstat(dest_fifo, &st) == 0 && S_ISFIFO(st.st_mode), "the destination is a genuine FIFO");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

static void test_rejects_wrong_existing_destination_types(void)
{
    printf(BLUE "::" NC " restore_native_at: existing destination objects must have the source type\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    write_file_under(source_root, "regular", "regular-source");
    char source_dir[PATH_MAX];
    join_path(source_dir, sizeof(source_dir), source_root, "directory");
    check(mkdir(source_dir, 0755) == 0, "fixture: create source directory");
    write_file_under(source_root, "directory/inside", "nested");
    char source_fifo[PATH_MAX];
    join_path(source_fifo, sizeof(source_fifo), source_root, "fifo");
    check(mkfifo(source_fifo, 0600) == 0, "fixture: create source FIFO");

    char dest_regular[PATH_MAX];
    join_path(dest_regular, sizeof(dest_regular), dest_root, "regular");
    check(mkdir(dest_regular, 0755) == 0,
          "fixture: put a directory where a regular file would be restored");
    char dest_directory[PATH_MAX];
    join_path(dest_directory, sizeof(dest_directory), dest_root, "directory");
    write_file(dest_directory, "directory-sentinel");
    char dest_fifo[PATH_MAX];
    join_path(dest_fifo, sizeof(dest_fifo), dest_root, "fifo");
    write_file(dest_fifo, "fifo-sentinel");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(&RESTORE_CTX, source_fd, "regular",
                            dest_fd, "regular") != 0,
          "regular-to-directory replacement is refused");
    check(restore_native_at(&RESTORE_CTX, source_fd, "directory",
                            dest_fd, "directory") != 0,
          "directory-to-regular replacement is refused");
    check(restore_native_at(&RESTORE_CTX, source_fd, "fifo",
                            dest_fd, "fifo") != 0,
          "FIFO-to-regular replacement is refused");

    struct stat st;
    check(lstat(dest_regular, &st) == 0 && S_ISDIR(st.st_mode),
          "the wrong-type destination directory remains intact");
    char content[64];
    read_file(dest_directory, content, sizeof(content));
    check(strcmp(content, "directory-sentinel") == 0,
          "the directory target's regular-file sentinel remains intact");
    read_file(dest_fifo, content, sizeof(content));
    check(strcmp(content, "fifo-sentinel") == 0,
          "the FIFO target's regular-file sentinel remains intact");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

static void test_skips_socket_without_failing(void)
{
    printf(BLUE "::" NC " restore_native_at: a socket inside a restored directory is skipped, not failed\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    char proj_path[PATH_MAX];
    join_path(proj_path, sizeof(proj_path), source_root, "proj");
    check(mkdir(proj_path, 0755) == 0, "fixture: create a source directory");
    write_file_under(source_root, "proj/regular.txt", "still-restored");

    char sock_path[PATH_MAX];
    join_path(sock_path, sizeof(sock_path), source_root, "proj/sock");
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    check(sock_fd >= 0, "fixture: create a socket fd");
    if (sock_fd >= 0)
    {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        size_t sock_path_len = strlen(sock_path);
        check(sock_path_len < sizeof(addr.sun_path), "fixture: socket path fits sun_path");
        if (sock_path_len < sizeof(addr.sun_path))
        {
            memcpy(addr.sun_path, sock_path, sock_path_len + 1);
            int bind_rc =
                bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
            if (bind_rc != 0)
                perror("fixture bind");
            check(bind_rc == 0, "fixture: bind the socket into proj/");
        }
        close(sock_fd);
    }

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(&RESTORE_CTX, source_fd, "proj", dest_fd, "proj") == 0,
          "restoring a directory containing a socket still succeeds overall");

    char dest_regular[PATH_MAX];
    join_path(dest_regular, sizeof(dest_regular), dest_root, "proj/regular.txt");
    struct stat st;
    check(stat(dest_regular, &st) == 0, "the sibling regular file was still restored");

    char dest_sock[PATH_MAX];
    join_path(dest_sock, sizeof(dest_sock), dest_root, "proj/sock");
    check(lstat(dest_sock, &st) != 0, "no destination object was created for the skipped socket");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

static void test_skips_device_node_without_failing(void)
{
    printf(BLUE "::" NC " restore_native_at: a device node is skipped without a destination\n");

    char dest_root[PATH_MAX];
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");

    int source_fd = open_dir_fd("/dev");
    int dest_fd = open_dir_fd(dest_root);
    struct stat source_st;
    int fixture_ok =
        fstatat(source_fd, "null", &source_st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISCHR(source_st.st_mode);
    check(fixture_ok, "/dev/null is available as a character-device fixture");
    if (fixture_ok)
        check(restore_native_at(&RESTORE_CTX, source_fd, "null",
                                dest_fd, "null") == 0,
              "restoring the device-node fixture succeeds by skipping it");

    char dest_device[PATH_MAX];
    join_path(dest_device, sizeof(dest_device), dest_root, "null");
    struct stat dest_st;
    check(lstat(dest_device, &dest_st) != 0,
          "skipping the device node creates no destination object");

    close(source_fd);
    close(dest_fd);
    remove_tree(dest_root);
}

static void test_preserves_caller_owned_root_fds(void)
{
    printf(BLUE "::" NC " restore_native_at: caller-owned root fds remain open and unchanged\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");
    write_file_under(source_root, "note.txt", "content");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);
    struct stat source_before;
    struct stat dest_before;
    check(fstat(source_fd, &source_before) == 0 &&
          fstat(dest_fd, &dest_before) == 0,
          "fixture: record both root fd identities");

    check(restore_native_at(&RESTORE_CTX, source_fd, "note.txt",
                            dest_fd, "note.txt") == 0,
          "a successful restore completes");
    check(fd_still_names_same_directory(source_fd, &source_before) &&
          fd_still_names_same_directory(dest_fd, &dest_before),
          "both caller root fds survive a successful restore");

    check(restore_native_at(&RESTORE_CTX, source_fd, "note.txt",
                            dest_fd, "../escape") != 0,
          "an unsafe restore request is refused");
    check(fd_still_names_same_directory(source_fd, &source_before) &&
          fd_still_names_same_directory(dest_fd, &dest_before),
          "both caller root fds survive a refused restore");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

static void test_empty_relative_path_means_root_object_itself(void)
{
    printf(BLUE "::" NC " restore_native_at: an empty relative address means the root object itself\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");
    write_file_under(source_root, "inside.txt", "root-restore-content");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(&RESTORE_CTX, source_fd, "", dest_fd, "") == 0,
          "an empty relative address on both sides restores the root directory itself (docs/DECISIONS.md D16)");

    char dest_inside[PATH_MAX];
    join_path(dest_inside, sizeof(dest_inside), dest_root, "inside.txt");
    char content[64];
    read_file(dest_inside, content, sizeof(content));
    check(strcmp(content, "root-restore-content") == 0, "the root directory's own contents were restored");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

/* ========================================================================= */
/* CloneContext validation                                                  */
/* ========================================================================= */

static void test_rejects_invalid_context(void)
{
    printf(BLUE "::" NC " restore_native_at: an invalid or mismatched CloneContext is refused\n");

    char source_root[PATH_MAX], dest_root[PATH_MAX];
    fresh_mkdtemp(source_root, sizeof(source_root), "restore_src");
    fresh_mkdtemp(dest_root, sizeof(dest_root), "restore_dst");
    write_file_under(source_root, "note.txt", "content");

    int source_fd = open_dir_fd(source_root);
    int dest_fd = open_dir_fd(dest_root);

    check(restore_native_at(NULL, source_fd, "note.txt", dest_fd, "note.txt") != 0,
          "a NULL ctx is refused");

    CloneContext backup_ctx = { .operation = CLONE_BACKUP, .representation = CLONE_NATIVE_TREE };
    check(restore_native_at(&backup_ctx, source_fd, "note.txt", dest_fd, "note.txt") != 0,
          "a CLONE_BACKUP operation is refused");

    CloneContext portable_ctx = { .operation = CLONE_RESTORE, .representation = CLONE_PORTABLE_SIDECAR };
    check(restore_native_at(&portable_ctx, source_fd, "note.txt", dest_fd, "note.txt") != 0,
          "a CLONE_PORTABLE_SIDECAR representation is refused");

    check(restore_native_at(&RESTORE_CTX, -1, "note.txt", dest_fd, "note.txt") != 0,
          "a negative source_root_fd is refused");
    check(restore_native_at(&RESTORE_CTX, source_fd, "note.txt", -1, "note.txt") != 0,
          "a negative destination_root_fd is refused");

    close(source_fd);
    close(dest_fd);
    remove_tree(source_root);
    remove_tree(dest_root);
}

int main(void)
{
    printf(BLUE "::" NC " restore_native_at (unit)\n");

    test_rejects_destination_intermediate_symlink_escape();
    test_rejects_final_destination_symlink();
    test_rejects_source_intermediate_symlink_redirect();
    test_recreates_source_leaf_symlink_without_following();

    test_rejects_lexically_invalid_relative_paths();

    test_restores_nested_files_and_directories();
    test_regular_file_resume_and_overwrite();
    test_restores_fifo();
    test_rejects_wrong_existing_destination_types();
    test_skips_socket_without_failing();
    test_skips_device_node_without_failing();
    test_preserves_caller_owned_root_fds();
    test_empty_relative_path_means_root_object_itself();

    test_rejects_invalid_context();

    if (failures > 0)
    {
        printf(RED "%d restore_native_at test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
