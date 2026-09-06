// Unit tests for restore()'s manifest-driven dispatch (docs/DECISIONS.md D15/D16):
// a valid v1 manifest routes to the root-table walker; an unversioned or
// absent manifest routes to the isolated legacy path; an unknown version or
// malformed v1 manifest refuses the whole restore before any confirmation or
// mutation; a ".partial" source is refused outright (docs/DECISIONS.md D15).
//
// Most cases here run with dry_run forced on for the whole binary (set once
// in main(), inherited by every fork()ed restore() call below), so none of
// this ever needs an interactive confirm_action() prompt or touches a real
// destination. The space-refusal case also runs once with dry_run disabled:
// it must prove that the free-space gate precedes confirmation. Happy-path v1
// fixtures are written with the real manifest_write_v1() so the fixture can
// never silently drift from what the reader actually accepts;
// malformed/unknown-version fixtures are raw strings, so a writer bug can
// never mask a reader bug -- see tests/test_manifest.c for the same split.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backup.h"
#include "manifest.h"
#include "restore.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
#define NC    "\033[0m"

enum { CHILD_SKIP = 77 };

static int failures = 0;
static int skips = 0;

static int file_content_is(const char *path, const char *content);

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

static void skip_case(const char *label, const char *reason)
{
    printf("  " YELLOW "-" NC " %s skipped: %s\n", label, reason);
    skips++;
}

static void force_no_free_space(off_t needed, off_t *free_bytes,
                                void *context)
{
    (void)needed;
    (void)context;
    if (free_bytes != NULL)
        *free_bytes = 0;
}

static void set_test_block_size(off_t *block_size, void *context)
{
    if (block_size != NULL && context != NULL)
        *block_size = *(const off_t *)context;
}

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

// Genuinely recursive (unlike mkdir(2)): creates every missing intermediate
// component, since fixtures below need "data/<payload>" and "data" itself is
// never created ahead of time.
static void mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(buf))
    {
        printf(RED "fixture: path too long: %s" NC "\n", path);
        exit(1);
    }
    memcpy(buf, path, len + 1);

    for (size_t i = 1; i < len; i++)
    {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        {
            printf(RED "fixture: could not mkdir %s" NC "\n", buf);
            exit(1);
        }
        buf[i] = '/';
    }

    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
    {
        printf(RED "fixture: could not mkdir %s" NC "\n", buf);
        exit(1);
    }
}

static void make_deep_payload_directory(const char *source,
                                        const char *payload, size_t levels)
{
    char data[PATH_MAX];
    join_path(data, sizeof(data), source, "data");
    mkdir_p(data);

    int data_fd = open(data, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (data_fd < 0 || mkdirat(data_fd, payload, 0755) != 0)
        exit(1);
    int current = openat(data_fd, payload,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0 || close(data_fd) != 0)
        exit(1);
    for (size_t level = 0; level < levels; level++)
    {
        if (mkdirat(current, "d", 0755) != 0)
            exit(1);
        int next = openat(current, "d",
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || close(current) != 0)
            exit(1);
        current = next;
    }
    if (close(current) != 0)
        exit(1);
}

// Creates dir/rel (rel may have one level, e.g. "data/EXPLICIT_0") and writes
// content into dir/rel/name.
static void write_payload_file(const char *dir, const char *rel, const char *name, const char *content)
{
    char sub[PATH_MAX];
    join_path(sub, sizeof(sub), dir, rel);
    mkdir_p(sub);
    char file_path[PATH_MAX];
    join_path(file_path, sizeof(file_path), sub, name);
    FILE *f = fopen(file_path, "w");
    if (f == NULL)
    {
        printf(RED "fixture: could not write %s" NC "\n", file_path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

static void write_raw(const char *dir, const char *content)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), dir, "manifest.txt");
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "fixture: could not write %s" NC "\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

static void remove_fixture_packages(const char *source)
{
    char path[PATH_MAX];
    join_path(path, sizeof(path), source, "packages.txt");
    if (unlink(path) != 0 && errno != ENOENT)
    {
        printf(RED "fixture: could not remove %s" NC "\n", path);
        exit(1);
    }
}

// Forks so restore()'s output can be captured in isolation per call without
// one test's output or any accidental global mutation leaking into the next.
// input may be NULL; live happy-path tests pass "y\n" through stdin so they
// still exercise the production confirmation path.
static int run_restore_capturing_with_input(const char *source,
                                            const char *input,
                                            char *output,
                                            size_t output_size)
{
    int output_pipe[2];
    int input_pipe[2];
    if (pipe(output_pipe) != 0 || pipe(input_pipe) != 0)
    {
        perror("pipe");
        exit(1);
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork");
        exit(1);
    }
    if (pid == 0)
    {
        close(output_pipe[0]);
        close(input_pipe[1]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0 ||
            dup2(input_pipe[0], STDIN_FILENO) < 0)
            _exit(2);
        close(output_pipe[1]);
        close(input_pipe[0]);
        int rc = restore(source);
        fflush(stdout);
        fflush(stderr);
        _exit(rc == 0 ? 0 : 1);
    }

    close(output_pipe[1]);
    close(input_pipe[0]);
    if (input != NULL)
    {
        size_t input_len = strlen(input);
        ssize_t written = write(input_pipe[1], input, input_len);
        if (written < 0 || (size_t)written != input_len)
        {
            perror("write");
            exit(1);
        }
    }
    close(input_pipe[1]);

    size_t total = 0;
    ssize_t n;
    while (total < output_size - 1 &&
           (n = read(output_pipe[0], output + total,
                     output_size - 1 - total)) > 0)
        total += n;
    output[total] = '\0';
    close(output_pipe[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_restore_capturing(const char *source, char *output,
                                 size_t output_size)
{
    return run_restore_capturing_with_input(source, NULL, output, output_size);
}

static int write_proc_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t length = strlen(content);
    ssize_t written = write(fd, content, length);
    int saved_errno = errno;
    int close_rc = close(fd);
    if (written < 0)
        errno = saved_errno;
    return written == (ssize_t)length && close_rc == 0 ? 0 : -1;
}

static int setup_bind_mount_namespace(void)
{
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
        return -1;

    char mapping[64];
    int length = snprintf(mapping, sizeof(mapping), "0 %lu 1\n",
                          (unsigned long)host_uid);
    if (length < 0 || (size_t)length >= sizeof(mapping) ||
        write_proc_file("/proc/self/uid_map", mapping) != 0 ||
        write_proc_file("/proc/self/setgroups", "deny\n") != 0)
        return -1;

    length = snprintf(mapping, sizeof(mapping), "0 %lu 1\n",
                      (unsigned long)host_gid);
    if (length < 0 || (size_t)length >= sizeof(mapping) ||
        write_proc_file("/proc/self/gid_map", mapping) != 0)
        return -1;

    return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
}

static int run_bind_mount_restore(const char *source, const char *home,
                                  const char *documents_shared,
                                  const char *downloads_shared,
                                  char *output, size_t output_size)
{
    int output_pipe[2];
    int input_pipe[2];
    if (pipe(output_pipe) != 0 || pipe(input_pipe) != 0)
    {
        perror("pipe");
        exit(1);
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork");
        exit(1);
    }
    if (pid == 0)
    {
        close(output_pipe[0]);
        close(input_pipe[1]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0 ||
            dup2(input_pipe[0], STDIN_FILENO) < 0)
            _exit(2);
        close(output_pipe[1]);
        close(input_pipe[0]);

        if (setup_bind_mount_namespace() != 0 ||
            mount(downloads_shared, documents_shared, NULL, MS_BIND, NULL) != 0)
            _exit(CHILD_SKIP);

        struct stat documents_st, downloads_st;
        if (stat(documents_shared, &documents_st) != 0 ||
            stat(downloads_shared, &downloads_st) != 0 ||
            documents_st.st_dev != downloads_st.st_dev ||
            documents_st.st_ino != downloads_st.st_ino)
            _exit(CHILD_SKIP);

        if (setenv("HOME", home, 1) != 0)
            _exit(2);
        dry_run = 0;
        int restore_rc = restore(source);
        char documents_file[PATH_MAX], downloads_file[PATH_MAX];
        join_path(documents_file, sizeof(documents_file), documents_shared,
                  "file");
        join_path(downloads_file, sizeof(downloads_file), downloads_shared,
                  "file");
        int intact = file_content_is(documents_file, "ORIGINAL") &&
                     file_content_is(downloads_file, "ORIGINAL");
        fflush(stdout);
        fflush(stderr);
        _exit(restore_rc != 0 && intact ? 0 : 1);
    }

    close(output_pipe[1]);
    close(input_pipe[0]);
    const char input[] = "y\n";
    if (write(input_pipe[1], input, sizeof(input) - 1U) !=
        (ssize_t)(sizeof(input) - 1U))
    {
        perror("write");
        exit(1);
    }
    close(input_pipe[1]);

    size_t total = 0;
    ssize_t n;
    while (total < output_size - 1U &&
           (n = read(output_pipe[0], output + total,
                     output_size - 1U - total)) > 0)
        total += (size_t)n;
    output[total] = '\0';
    close(output_pipe[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ========================================================================= */
/* Dispatch: legacy vs. v1 vs. refusal                                     */
/* ========================================================================= */

static void test_dispatch_routes_missing_manifest_to_legacy(void)
{
    printf(BLUE "::" NC " restore dispatch: an absent manifest.txt routes to the legacy path\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_payload_file(source, ".", "note.txt", "irrelevant"); // no manifest.txt at all

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds with no manifest.txt present");
    check(strstr(output, "Main Directories") != NULL, "the legacy section header appears");
    check(strstr(output, "Roots") == NULL, "the v1 section header does not appear");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_routes_legacy_xdg_manifest_to_legacy(void)
{
    printf(BLUE "::" NC " restore dispatch: an unversioned XDG-key manifest routes to the legacy path\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_raw(source, "XDG_DOCUMENTS_DIR=Belgeler\n");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds with an old-style XDG-key manifest.txt");
    check(strstr(output, "Main Directories") != NULL, "the legacy section header appears");
    check(strstr(output, "Roots") == NULL, "the v1 section header does not appear");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_refuses_unknown_version(void)
{
    printf(BLUE "::" NC " restore dispatch: an unrecognized manifest version refuses the whole restore\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_raw(source, "MIGR_MANIFEST\nVERSION=999\n");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "restore refuses an unrecognized manifest version");
    check(strstr(output, "Main Directories") == NULL, "the legacy path is never attempted");
    check(strstr(output, "Roots") == NULL, "the v1 path is never attempted");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_refuses_malformed_v1(void)
{
    printf(BLUE "::" NC " restore dispatch: a malformed v1 manifest refuses the whole restore\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    write_raw(source, "MIGR_MANIFEST\nVERSION=1\n"); // truncated: declares a header, nothing more

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "restore refuses a malformed v1 manifest");
    check(strstr(output, "Main Directories") == NULL, "the legacy path is never attempted");
    check(strstr(output, "Roots") == NULL, "the v1 path is never attempted");

    remove_tree(source);
    remove_tree(home);
}

static void test_dispatch_refuses_partial_source(void)
{
    printf(BLUE "::" NC " restore dispatch: a \".partial\" source is refused before manifest dispatch\n");

    char parent[PATH_MAX];
    fresh_mkdtemp(parent, sizeof(parent), "dispatch_parent");
    char source[PATH_MAX];
    join_path(source, sizeof(source), parent, "migr_backup_20260101_000000.partial");
    mkdir_p(source);

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "restore refuses a .partial-named source directory");
    check(strstr(output, "in-progress or abandoned") != NULL,
          "the refusal names the reason: an in-progress/abandoned container");

    remove_tree(parent);
    remove_tree(home);
}

static void test_dispatch_requires_v1_manifest_for_final_container_name(void)
{
    printf(BLUE "::" NC " restore dispatch: a canonical final-container name requires a v1 manifest\n");

    char parent[PATH_MAX];
    fresh_mkdtemp(parent, sizeof(parent), "dispatch_parent");
    char source[PATH_MAX];
    join_path(source, sizeof(source), parent, "migr_backup_20260101_000000");
    mkdir_p(source);
    write_payload_file(source, "data/EXPLICIT_0", "note.txt", "orphaned-v1-payload");

    char home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "a finalized versioned name without manifest.txt is refused");
    check(strstr(output, "missing manifest.txt") != NULL,
          "the error identifies the missing versioned control artifact");
    check(strstr(output, "Main Directories") == NULL,
          "the manifest-absent container is not guessed to be legacy");

    char legacy_source[PATH_MAX];
    join_path(legacy_source, sizeof(legacy_source), parent,
              "migr_backup_20260101_000000-1");
    mkdir_p(legacy_source);
    write_raw(legacy_source, "XDG_DOCUMENTS_DIR=Belgeler\n");

    rc = run_restore_capturing(legacy_source, output, sizeof(output));
    check(rc != 0, "a finalized versioned name carrying a legacy manifest is refused");
    check(strstr(output, "carries a legacy manifest") != NULL,
          "the error identifies the contradictory version boundary");
    check(strstr(output, "Main Directories") == NULL,
          "the canonical versioned container never enters the legacy walker");

    remove_tree(parent);
    remove_tree(home);
}

/* ========================================================================= */
/* v1 root-table walker                                                    */
/* ========================================================================= */

static void make_v1_manifest(Manifest *m, ManifestRoot *roots, int root_count)
{
    memset(m, 0, sizeof(*m));
    m->version = MANIFEST_CURRENT_VERSION;
    m->representation = CLONE_NATIVE_TREE;
    m->scope = MANIFEST_SCOPE_EXPLICIT;
    m->sidecar_version = 0;
    m->has_source_identity = 0;
    m->root_count = root_count;
    m->roots = roots;
}

static void make_v2_selection_manifest(Manifest *m, ManifestRoot roots[2])
{
    memset(m, 0, sizeof(*m));
    memset(roots, 0, 2U * sizeof(*roots));

    strcpy(roots[0].id, "CONFIG_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "CONFIG_0");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "/source/home/Belgeler");

    m->version = MANIFEST_SELECTION_VERSION;
    m->representation = CLONE_NATIVE_TREE;
    m->scope = MANIFEST_SCOPE_CRITICAL;
    strcpy(m->source_home, "/source/home");
    m->root_count = 2;
    m->roots = roots;
}

// Fills a restore_path[PATH_MAX] buffer with NAME_MAX-bounded components
// (never ".", "..", or over NAME_MAX -- the same shape canonical_path() in
// manifest.c requires of the real writer) packed as tightly as that
// validation allows, so the string itself stays under PATH_MAX while still
// being one join onto any real $HOME away from overflowing it.
static void build_long_restore_path(char *out, size_t out_size)
{
    char segment[NAME_MAX + 1];
    memset(segment, 'a', NAME_MAX);
    segment[NAME_MAX] = '\0';

    size_t pos = 0;
    size_t limit = out_size - 2; // canonical_path rejects a string of exactly PATH_MAX
    while (pos + 1 + NAME_MAX <= limit)
    {
        if (pos)
            out[pos++] = '/';
        memcpy(out + pos, segment, NAME_MAX);
        pos += NAME_MAX;
    }
    size_t remaining = limit - pos;
    if (remaining > 1)
    {
        out[pos++] = '/';
        remaining--;
        memcpy(out + pos, segment, remaining);
        pos += remaining;
    }
    out[pos] = '\0';
}

static void write_file_mode(const char *path, const char *content, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
    {
        printf(RED "fixture: could not write %s" NC "\n", path);
        exit(1);
    }
    size_t len = strlen(content);
    ssize_t written = write(fd, content, len);
    if (written < 0 || (size_t)written != len ||
        fchmod(fd, mode) != 0 || close(fd) != 0)
    {
        printf(RED "fixture: could not finish %s" NC "\n", path);
        exit(1);
    }
}

static int file_matches(const char *path, const char *content, mode_t mode)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0777) != mode || st.st_size < 0 ||
        (size_t)st.st_size != strlen(content))
        return 0;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    char buf[256];
    if ((size_t)st.st_size >= sizeof(buf))
    {
        close(fd);
        return 0;
    }
    ssize_t n = read(fd, buf, sizeof(buf));
    int saved_errno = errno;
    int close_rc = close(fd);
    errno = saved_errno;
    return n == st.st_size && close_rc == 0 &&
           memcmp(buf, content, (size_t)n) == 0;
}

static int file_content_is(const char *path, const char *content)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (size_t)st.st_size != strlen(content))
        return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    char buf[256];
    if ((size_t)st.st_size >= sizeof(buf))
    {
        close(fd);
        return 0;
    }
    ssize_t n = read(fd, buf, sizeof(buf));
    int close_rc = close(fd);
    return n == st.st_size && close_rc == 0 &&
           memcmp(buf, content, (size_t)n) == 0;
}

static void write_user_dirs(const char *home, const char *documents,
                            const char *downloads)
{
    char content[PATH_MAX * 2U];
    int length = snprintf(content, sizeof(content),
                          "XDG_DOCUMENTS_DIR=\"$HOME/%s\"\n"
                          "XDG_DOWNLOAD_DIR=\"$HOME/%s\"\n",
                          documents, downloads);
    if (length < 0 || (size_t)length >= sizeof(content))
    {
        printf(RED "fixture: user-dirs.dirs content is too long" NC "\n");
        exit(1);
    }
    write_payload_file(home, ".config", "user-dirs.dirs", content);
}

static void make_v1_alias_manifest(Manifest *manifest,
                                   ManifestRoot roots[2])
{
    memset(roots, 0, 2U * sizeof(*roots));
    strcpy(roots[0].id, "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    strcpy(roots[0].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[0].source_path, "Documents");

    strcpy(roots[1].id, "XDG_DOWNLOAD_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOWNLOAD_DIR");
    strcpy(roots[1].source_path, "Downloads");

    make_v1_manifest(manifest, roots, 2);
}

static void test_versioned_restore_rejects_non_directory_payload_paths(void)
{
    printf(BLUE "::" NC " restore dispatch: disjoint roots inspect every payload entry\n");

    const char *variants[] = { "regular file", "symlink" };
    for (size_t variant = 0; variant < sizeof(variants) / sizeof(variants[0]);
         variant++)
    {
        char source[PATH_MAX], home[PATH_MAX], documents[PATH_MAX];
        char downloads[PATH_MAX], blocked[PATH_MAX], sentinel[PATH_MAX];
        char output[16384];
        ManifestRoot roots[2];
        Manifest manifest;
        int previous_dry_run = dry_run;

        fresh_mkdtemp(source, sizeof(source), "dispatch_identity_entry_src");
        fresh_mkdtemp(home, sizeof(home), "dispatch_identity_entry_home");
        setenv("HOME", home, 1);
        write_user_dirs(home, "Documents", "Downloads");
        join_path(documents, sizeof(documents), home, "Documents");
        join_path(downloads, sizeof(downloads), home, "Downloads");
        mkdir_p(documents);
        mkdir_p(downloads);
        make_v1_alias_manifest(&manifest, roots);
        check(manifest_write_v1(source, &manifest) == 0,
              "fixture: write the disjoint-root payload-entry manifest");
        write_payload_file(source, "data/XDG_DOCUMENTS_DIR/shared",
                           "file", "DOCS");
        write_payload_file(source, "data/XDG_DOWNLOAD_DIR", "file",
                           "DOWNLOADS");

        join_path(blocked, sizeof(blocked), documents, "shared");
        if (variant == 0)
        {
            strcpy(sentinel, blocked);
            write_file_mode(blocked, "ORIGINAL", 0600);
        }
        else
        {
            join_path(sentinel, sizeof(sentinel), documents,
                      "symlink-target");
            write_file_mode(sentinel, "ORIGINAL", 0600);
            if (symlink("symlink-target", blocked) != 0)
                exit(1);
        }
        remove_fixture_packages(source);

        dry_run = 0;
        int rc = run_restore_capturing_with_input(
            source, "y\n", output, sizeof(output));
        dry_run = previous_dry_run;

        struct stat blocked_st;
        int blocked_intact = lstat(blocked, &blocked_st) == 0 &&
            ((variant == 0 && S_ISREG(blocked_st.st_mode) &&
              file_content_is(blocked, "ORIGINAL")) ||
             (variant == 1 && S_ISLNK(blocked_st.st_mode) &&
              file_content_is(sentinel, "ORIGINAL")));
        check(rc != 0 &&
                  strstr(output,
                         "manifest root XDG_DOCUMENTS_DIR entry shared") != NULL &&
                  blocked_intact,
              variants[variant]);

        remove_tree(source);
        remove_tree(home);
    }
}

static void test_versioned_restore_refuses_bind_mount_aliases(void)
{
    printf(BLUE "::" NC " restore dispatch: disjoint roots inspect bind-mounted aliases\n");

    char source[PATH_MAX], home[PATH_MAX], documents_shared[PATH_MAX];
    char downloads_shared[PATH_MAX], documents_file[PATH_MAX];
    char downloads_file[PATH_MAX], output[16384];
    ManifestRoot roots[2];
    Manifest manifest;

    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_bind_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_bind_home");
    setenv("HOME", home, 1);
    write_user_dirs(home, "Documents", "Downloads");
    join_path(documents_shared, sizeof(documents_shared), home,
              "Documents/shared");
    join_path(downloads_shared, sizeof(downloads_shared), home,
              "Downloads/shared");
    mkdir_p(documents_shared);
    mkdir_p(downloads_shared);
    join_path(documents_file, sizeof(documents_file), documents_shared, "file");
    join_path(downloads_file, sizeof(downloads_file), downloads_shared, "file");
    write_file_mode(documents_file, "ORIGINAL", 0600);
    write_file_mode(downloads_file, "ORIGINAL", 0600);
    make_v1_alias_manifest(&manifest, roots);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the bind-alias payload-entry manifest");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR/shared", "file",
                       "DOCS");
    write_payload_file(source, "data/XDG_DOWNLOAD_DIR/shared", "file",
                       "DOWNLOADS");
    remove_fixture_packages(source);

    int rc = run_bind_mount_restore(source, home, documents_shared,
                                    downloads_shared, output, sizeof(output));
    if (rc == CHILD_SKIP)
    {
        skip_case("bind-mounted destination aliases",
                  "user and mount namespaces are unavailable");
    }
    else
    {
        check(rc == 0 &&
                  strstr(output, "XDG_DOCUMENTS_DIR") != NULL &&
                  strstr(output, "XDG_DOWNLOAD_DIR") != NULL &&
                  strstr(output, downloads_shared) != NULL,
              "bind-mounted aliases name both roots and the unchanged destination");
    }

    remove_tree(source);
    remove_tree(home);
}

static int record_network_reload(char *const argv[], void *context)
{
    const char *marker_path = context;
    FILE *f = fopen(marker_path, "a");
    if (f == NULL)
        return -1;
    for (size_t i = 0; argv[i] != NULL; i++)
        if (fprintf(f, "%s\n", argv[i]) < 0)
        {
            fclose(f);
            return -1;
    }
    return fclose(f) == 0 ? 0 : -1;
}

static int record_failed_network_reload(char *const argv[], void *context)
{
    if (record_network_reload(argv, context) != 0)
        return -1;
    return 1;
}

static void write_network_manifest(const char *source)
{
    Manifest m;
    make_v1_manifest(&m, NULL, 0);
    m.has_network_config = 1;
    if (manifest_write_v1(source, &m) != 0)
    {
        printf(RED "fixture: could not write network manifest" NC "\n");
        exit(1);
    }
}

static void test_dispatch_refuses_portable_v1(void)
{
    printf(BLUE "::" NC " restore dispatch: portable v1 payload is never interpreted as a native tree\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "EXPLICIT_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "EXPLICIT_0");
    strcpy(root.source_path, "Documents/project");
    strcpy(root.restore_path, "Documents/project");
    root.has_restore_path = 1;

    Manifest m;
    make_v1_manifest(&m, &root, 1);
    m.representation = CLONE_PORTABLE_SIDECAR;
    m.sidecar_version = 1;
    check(manifest_write_v1(source, &m) == 0,
          "fixture: write a valid portable v1 manifest");
    write_payload_file(source, "data/EXPLICIT_0", "note.txt", "encoded-or-degraded-content");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "portable v1 restore is refused while its replay path is absent");
    check(strstr(output, "Portable restore preflight refused") != NULL,
          "the refusal identifies the portable preflight path");
    check(strstr(output, "Roots") == NULL,
          "portable payload never reaches the native root walker");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_refuses_missing_declared_payloads(void)
{
    printf(BLUE "::" NC " restore dispatch: every v1 root must have its declared payload\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));

    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "Documents/project");
    strcpy(roots[0].restore_path, "Documents/project");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "EXPLICIT_1");
    roots[1].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots[1].payload_path, "EXPLICIT_1");
    strcpy(roots[1].source_path, "/mnt/external/project");
    roots[1].has_restore_path = 0;

    Manifest m;
    make_v1_manifest(&m, roots, 2);
    check(manifest_write_v1(source, &m) == 0,
          "fixture: write a valid v1 manifest without its declared payloads");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0, "missing declared payloads refuse the versioned restore");
    check(strstr(output, "EXPLICIT_0 is missing its declared payload") != NULL,
          "the missing automatic root is reported");
    check(strstr(output, "EXPLICIT_1 is missing its declared payload") != NULL,
          "the missing manual root is reported");
    check(strstr(output, "backup location:") == NULL,
          "restore never advertises a nonexistent MANUAL_NATIVE payload");
    check(strstr(output, "Roots") == NULL,
          "payload validation fails before the root walker starts");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_restores_home_relative_and_xdg_reports_manual_native(void)
{
    printf(BLUE "::" NC " restore dispatch: a valid v1 manifest restores HOME_RELATIVE/XDG roots and reports MANUAL_NATIVE\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[3];
    memset(roots, 0, sizeof(roots));

    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "Documents/project");
    strcpy(roots[0].restore_path, "Documents/project");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "Belgeler");
    roots[1].has_restore_path = 0;

    strcpy(roots[2].id, "EXPLICIT_1");
    roots[2].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots[2].payload_path, "EXPLICIT_1");
    strcpy(roots[2].source_path, "/mnt/external/project");
    roots[2].has_restore_path = 0;

    Manifest m;
    make_v1_manifest(&m, roots, 3);
    check(manifest_write_v1(source, &m) == 0, "fixture: write a valid v1 manifest via the real writer");

    write_payload_file(source, "data/EXPLICIT_0", "note.txt", "home-relative-content");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "doc.txt", "xdg-content");
    write_payload_file(source, "data/EXPLICIT_1", "external.txt", "manual-native-content");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds on a valid v1 manifest");
    check(strstr(output, "Roots") != NULL, "the v1 section header appears");
    check(strstr(output, "Main Directories") == NULL, "the legacy path is never attempted");

    check(strstr(output, "Would restore: EXPLICIT_0 -> ~/Documents/project\n") != NULL,
          "the HOME_RELATIVE root is previewed at its recorded restore address");

    char expected_xdg_preview[PATH_MAX + 64];
    int expected_xdg_preview_length = snprintf(
        expected_xdg_preview, sizeof(expected_xdg_preview),
        "Would restore: XDG_DOCUMENTS_DIR -> %s/Documents/\n", home);
    check(expected_xdg_preview_length > 0 &&
              (size_t)expected_xdg_preview_length < sizeof(expected_xdg_preview) &&
              strstr(output, expected_xdg_preview) != NULL,
          "the XDG root is previewed against the target locale's resolved directory");

    check(strstr(output, "Manual Roots") != NULL, "the manual-roots section appears");
    check(strstr(output, "EXPLICIT_1") != NULL, "the MANUAL_NATIVE root's id is listed");
    check(strstr(output, "/mnt/external/project") != NULL,
          "the MANUAL_NATIVE root's recorded source path is listed (docs/DECISIONS.md D16)");
    check(strstr(output, "data/EXPLICIT_1") != NULL,
          "the MANUAL_NATIVE root's backup payload location is listed");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_empty_restore_path_means_home_itself(void)
{
    printf(BLUE "::" NC " restore dispatch: an empty HOME_RELATIVE restore_path addresses $HOME itself (docs/DECISIONS.md D16)\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "EXPLICIT_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "EXPLICIT_0");
    strcpy(root.source_path, "");
    root.restore_path[0] = '\0';
    root.has_restore_path = 1;

    Manifest m;
    make_v1_manifest(&m, &root, 1);
    check(manifest_write_v1(source, &m) == 0, "fixture: write a valid v1 manifest with an empty restore_path");

    write_payload_file(source, "data/EXPLICIT_0", "inside.txt", "home-root-content");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0, "restore succeeds");
    check(strstr(output, "Would restore: EXPLICIT_0 -> ~\n") != NULL,
          "an empty restore_path previews as the home directory itself, not a trailing-slash address");

    remove_tree(source);
    remove_tree(home);
}

static void test_v2_selection_restore_refusals(void)
{
    printf(BLUE "::" NC " restore dispatch: VERSION=2 ownership and target-map refusals\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_v2_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_v2_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[2];
    Manifest manifest;
    make_v2_selection_manifest(&manifest, roots);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write a valid VERSION=2 selection manifest");
    write_payload_file(source, "data/CONFIG_0", "Belgeler", "wrong owner");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "doc.txt", "selected child");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0 && strstr(output, "outside its recorded selection") != NULL,
          "a delegated child planted in the parent payload is refused before replay");
    remove_tree(source);

    fresh_mkdtemp(source, sizeof(source), "dispatch_v2_collision");
    make_v2_selection_manifest(&manifest, roots);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the VERSION=2 target-collision manifest");
    write_payload_file(source, "data/CONFIG_0/Documents", "parent.txt", "parent mapping");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "child.txt", "xdg mapping");

    int previous_dry_run = dry_run;
    dry_run = 0;
    rc = run_restore_capturing(source, output, sizeof(output));
    dry_run = previous_dry_run;
    check(rc != 0 && strstr(output, "competing entries for restore destination") != NULL,
          "distinct selected entries mapping to one target are refused before confirmation");

    char documents[PATH_MAX];
    join_path(documents, sizeof(documents), home, "Documents");
    check(access(documents, F_OK) != 0,
          "VERSION=2 target collision leaves the destination untouched");

    remove_tree(source);
    remove_tree(home);
}

static void test_v2_payload_depth_is_bounded(void)
{
    printf(BLUE "::" NC " restore dispatch: VERSION=2 payload depth is bounded\n");

    char source[PATH_MAX], home[PATH_MAX], output[16384];
    fresh_mkdtemp(source, sizeof(source), "dispatch_v2_depth_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_v2_depth_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "CONFIG_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "CONFIG_0");
    strcpy(root.source_path, "/source/home/deep");
    strcpy(root.restore_path, "deep");
    root.has_restore_path = 1;

    Manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    manifest.version = MANIFEST_SELECTION_VERSION;
    manifest.representation = CLONE_NATIVE_TREE;
    manifest.scope = MANIFEST_SCOPE_CRITICAL;
    strcpy(manifest.source_home, "/source/home");
    manifest.root_count = 1;
    manifest.roots = &root;
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the deep VERSION=2 manifest");
    make_deep_payload_directory(source, root.payload_path, 513U);
    remove_fixture_packages(source);

    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0 && strstr(output, "maximum directory depth") != NULL &&
              strstr(output, root.id) != NULL,
          "an over-deep payload is refused cleanly with its manifest root named");

    remove_tree(source);
    remove_tree(home);
}

static void test_v2_home_relative_restore_destination_too_long(void)
{
    printf(BLUE "::" NC " restore dispatch: VERSION=2 HOME_RELATIVE restore destination overflow names its root\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_v2_long_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_v2_long_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[2];
    Manifest manifest;
    make_v2_selection_manifest(&manifest, roots);
    build_long_restore_path(roots[0].restore_path, sizeof(roots[0].restore_path));
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write a VERSION=2 manifest whose HOME_RELATIVE root has a restore_path too long to join onto HOME");

    write_payload_file(source, "data/CONFIG_0", "inside.txt", "home-relative-content");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "doc.txt", "selected child");

    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0,
          "restore refuses when a HOME_RELATIVE restore destination cannot be joined onto $HOME");
    check(strstr(output, "Error: Restore destination for manifest root CONFIG_0 is too long") != NULL,
          "the overflow names the offending manifest root instead of failing silently (P4)");

    remove_tree(source);
    remove_tree(home);
}

static void test_versioned_restore_freezes_xdg_target_map(void)
{
    printf(BLUE "::" NC " restore dispatch: versioned restore freezes XDG target addresses for the invocation\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_frozen_map_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_frozen_map_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[2];
    Manifest manifest;
    make_v2_selection_manifest(&manifest, roots);
    strcpy(roots[0].source_path, ".config");
    strcpy(roots[0].restore_path, ".config");
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the VERSION=2 frozen-map manifest");

    write_payload_file(
        source, "data/CONFIG_0", "user-dirs.dirs",
        "XDG_DOCUMENTS_DIR=\"$HOME/Belgeler\"\n");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "doc", "SAVED-DATA");

    char source_doc[PATH_MAX], source_link[PATH_MAX], source_xdg[PATH_MAX];
    join_path(source_xdg, sizeof(source_xdg), source,
              "data/XDG_DOCUMENTS_DIR");
    join_path(source_doc, sizeof(source_doc), source_xdg, "doc");
    join_path(source_link, sizeof(source_link), source_xdg, "doc-link");
    check(link(source_doc, source_link) == 0,
          "fixture: add a hardlink inside the mapped XDG root");
    struct timespec xdg_times[2] = {
        { .tv_sec = 1700000900, .tv_nsec = 123456789 },
        { .tv_sec = 1700000901, .tv_nsec = 234567890 }
    };
    check(chmod(source_xdg, 0750) == 0 &&
              utimensat(AT_FDCWD, source_xdg, xdg_times, 0) == 0,
          "fixture: set mapped XDG root metadata");

    write_payload_file(
        home, ".config", "user-dirs.dirs",
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n");
    remove_fixture_packages(source);

    char dry_output[16384];
    int previous_dry_run = dry_run;
    dry_run = 1;
    int dry_rc = run_restore_capturing(source, dry_output, sizeof(dry_output));
    char expected_preview[PATH_MAX + 80];
    int preview_len = snprintf(
        expected_preview, sizeof(expected_preview),
        "Would restore: XDG_DOCUMENTS_DIR -> %s/Documents/\n", home);
    check(dry_rc == 0 && preview_len > 0 &&
              (size_t)preview_len < sizeof(expected_preview) &&
              strstr(dry_output, expected_preview) != NULL,
          "dry-run maps Documents using the target configuration present at invocation start");

    dry_run = 0;
    char live_output[16384];
    int live_rc = run_restore_capturing_with_input(
        source, "y\n", live_output, sizeof(live_output));
    dry_run = previous_dry_run;

    char documents[PATH_MAX], document[PATH_MAX], document_link[PATH_MAX];
    char belgeler[PATH_MAX];
    join_path(documents, sizeof(documents), home, "Documents");
    join_path(document, sizeof(document), documents, "doc");
    join_path(document_link, sizeof(document_link), documents, "doc-link");
    join_path(belgeler, sizeof(belgeler), home, "Belgeler");

    struct stat documents_st, document_st, document_link_st;
    int mapped_metadata_ok =
        stat(documents, &documents_st) == 0 &&
        stat(document, &document_st) == 0 &&
        stat(document_link, &document_link_st) == 0;
    check(live_rc == 0 && file_content_is(document, "SAVED-DATA") &&
              access(belgeler, F_OK) != 0,
          "live restore uses the same Documents address after restoring user-dirs.dirs");
    check(mapped_metadata_ok &&
              document_st.st_dev == document_link_st.st_dev &&
              document_st.st_ino == document_link_st.st_ino &&
              (documents_st.st_mode & 07777) == 0750 &&
              documents_st.st_mtim.tv_sec == xdg_times[1].tv_sec,
          "hardlink seeding and directory metadata use the frozen mapped destination");

    remove_tree(source);
    remove_tree(home);

    fresh_mkdtemp(source, sizeof(source), "dispatch_frozen_conflict_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_frozen_conflict_home");
    setenv("HOME", home, 1);
    make_v2_selection_manifest(&manifest, roots);
    strcpy(roots[0].source_path, ".config");
    strcpy(roots[0].restore_path, ".config");
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the VERSION=2 conflicting-retarget manifest");
    write_payload_file(
        source, "data/CONFIG_0", "user-dirs.dirs",
        "XDG_DOCUMENTS_DIR=\"$HOME/.config\"\n");
    write_payload_file(
        source, "data/XDG_DOCUMENTS_DIR", "doc", "CONFLICT-SAFE");
    write_payload_file(
        home, ".config", "user-dirs.dirs",
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n");
    remove_fixture_packages(source);

    previous_dry_run = dry_run;
    dry_run = 0;
    live_rc = run_restore_capturing_with_input(
        source, "y\n", live_output, sizeof(live_output));
    dry_run = previous_dry_run;

    char conflicting_entry[PATH_MAX];
    join_path(documents, sizeof(documents), home, "Documents");
    join_path(document, sizeof(document), documents, "doc");
    join_path(conflicting_entry, sizeof(conflicting_entry), home, ".config/doc");
    check(live_rc == 0 && file_content_is(document, "CONFLICT-SAFE") &&
              access(conflicting_entry, F_OK) != 0,
          "restored XDG configuration cannot redirect a later root into the CONFIG_0 destination");

    remove_tree(source);
    remove_tree(home);
}

static void test_versioned_restore_refuses_destination_alias_collisions(void)
{
    printf(BLUE "::" NC " restore dispatch: versioned destinations collide by resolved identity\n");

    char source[PATH_MAX], home[PATH_MAX], shared[PATH_MAX], alias[PATH_MAX];
    char sentinel[PATH_MAX], output[16384];
    ManifestRoot roots[2];
    Manifest manifest;
    int previous_dry_run = dry_run;

    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_files_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_files_home");
    setenv("HOME", home, 1);
    join_path(shared, sizeof(shared), home, "Shared");
    mkdir_p(shared);
    join_path(alias, sizeof(alias), home, "Alias");
    if (symlink("Shared", alias) != 0)
        exit(1);
    write_user_dirs(home, "Shared", "Alias");
    make_v1_alias_manifest(&manifest, roots);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the VERSION=1 Shared/Alias collision manifest");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "file", "DOCS");
    write_payload_file(source, "data/XDG_DOWNLOAD_DIR", "file", "DOWNLOADS");
    join_path(sentinel, sizeof(sentinel), shared, "file");
    write_file_mode(sentinel, "ORIGINAL", 0600);
    remove_fixture_packages(source);

    dry_run = 0;
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                               sizeof(output));
    dry_run = previous_dry_run;
    check(rc != 0 && strstr(output, "competing entries for restore destination") != NULL &&
              strstr(output, "XDG_DOCUMENTS_DIR") != NULL &&
              strstr(output, "XDG_DOWNLOAD_DIR") != NULL &&
              strstr(output, alias) != NULL &&
              file_content_is(sentinel, "ORIGINAL"),
          "VERSION=1 Shared/Alias duplicate files name both roots and the destination before refusing");
    remove_tree(source);
    remove_tree(home);

    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_nested_file_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_nested_file_home");
    setenv("HOME", home, 1);
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "PARENT");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "PARENT");
    strcpy(roots[0].source_path, "Parent");
    strcpy(roots[0].restore_path, "Parent");
    roots[0].has_restore_path = 1;
    strcpy(roots[1].id, "CHILD");
    roots[1].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[1].payload_path, "CHILD");
    strcpy(roots[1].source_path, "Parent/child");
    strcpy(roots[1].restore_path, "Parent/child");
    roots[1].has_restore_path = 1;
    make_v1_manifest(&manifest, roots, 2);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the nested non-directory root manifest");
    write_payload_file(source, "data/PARENT", "child", "PARENT");
    char child_payload[PATH_MAX];
    join_path(child_payload, sizeof(child_payload), source, "data/CHILD");
    write_file_mode(child_payload, "CHILD", 0600);
    join_path(shared, sizeof(shared), home, "Parent");
    mkdir_p(shared);
    join_path(sentinel, sizeof(sentinel), shared, "child");
    write_file_mode(sentinel, "ORIGINAL", 0600);
    remove_fixture_packages(source);

    dry_run = 0;
    rc = run_restore_capturing_with_input(source, "y\n", output,
                                          sizeof(output));
    dry_run = previous_dry_run;
    check(rc != 0 && strstr(output, "PARENT") != NULL &&
              strstr(output, "CHILD") != NULL &&
              strstr(output, sentinel) != NULL &&
              file_content_is(sentinel, "ORIGINAL"),
          "a file root nested below a directory root triggers the entry walk and refuses before mutation");
    remove_tree(source);
    remove_tree(home);

    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_dirs_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_dirs_home");
    setenv("HOME", home, 1);
    join_path(shared, sizeof(shared), home, "Shared");
    mkdir_p(shared);
    if (chmod(shared, 0701) != 0)
        exit(1);
    join_path(alias, sizeof(alias), home, "Alias");
    if (symlink("Shared", alias) != 0)
        exit(1);
    write_user_dirs(home, "Shared", "Alias");
    make_v1_alias_manifest(&manifest, roots);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the VERSION=1 duplicate-directory alias manifest");
    char docs_payload[PATH_MAX], downloads_payload[PATH_MAX];
    join_path(docs_payload, sizeof(docs_payload), source,
              "data/XDG_DOCUMENTS_DIR");
    join_path(downloads_payload, sizeof(downloads_payload), source,
              "data/XDG_DOWNLOAD_DIR");
    mkdir_p(docs_payload);
    mkdir_p(downloads_payload);
    if (chmod(docs_payload, 0750) != 0 || chmod(downloads_payload, 0755) != 0)
        exit(1);
    join_path(sentinel, sizeof(sentinel), shared, "sentinel");
    write_file_mode(sentinel, "ORIGINAL", 0600);
    remove_fixture_packages(source);

    dry_run = 0;
    rc = run_restore_capturing_with_input(source, "y\n", output,
                                          sizeof(output));
    dry_run = previous_dry_run;
    struct stat shared_st;
    int shared_ok = stat(shared, &shared_st) == 0;
    check(rc != 0 && strstr(output, "competing entries for restore destination") != NULL &&
              file_content_is(sentinel, "ORIGINAL") && shared_ok &&
              (shared_st.st_mode & 07777) == 0701,
          "distinct empty source directories cannot both own metadata for one aliased target");
    remove_tree(source);
    remove_tree(home);

    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_suffix_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_suffix_home");
    setenv("HOME", home, 1);
    char existing[PATH_MAX], missing[PATH_MAX];
    join_path(existing, sizeof(existing), home, "a");
    mkdir_p(existing);
    write_user_dirs(home, "a", "Downloads");
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "source-new");
    strcpy(roots[0].restore_path, "a/new");
    roots[0].has_restore_path = 1;
    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "Documents");
    make_v1_manifest(&manifest, roots, 2);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the converging missing-suffix manifest");
    char explicit_payload[PATH_MAX], xdg_payload[PATH_MAX], xdg_new[PATH_MAX];
    join_path(explicit_payload, sizeof(explicit_payload), source,
              "data/EXPLICIT_0");
    join_path(xdg_payload, sizeof(xdg_payload), source,
              "data/XDG_DOCUMENTS_DIR");
    join_path(xdg_new, sizeof(xdg_new), xdg_payload, "new");
    mkdir_p(explicit_payload);
    mkdir_p(xdg_new);
    join_path(sentinel, sizeof(sentinel), existing, "sentinel");
    write_file_mode(sentinel, "ORIGINAL", 0600);
    join_path(missing, sizeof(missing), existing, "new");
    remove_fixture_packages(source);

    dry_run = 0;
    rc = run_restore_capturing_with_input(source, "y\n", output,
                                          sizeof(output));
    dry_run = previous_dry_run;
    check(rc != 0 && strstr(output, "competing entries for restore destination") != NULL &&
              access(missing, F_OK) != 0 && file_content_is(sentinel, "ORIGINAL"),
          "routes from different existing ancestors converge in memory before a missing suffix is created");
    remove_tree(source);
    remove_tree(home);

    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_home_xdg_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_home_xdg_home");
    setenv("HOME", home, 1);
    join_path(shared, sizeof(shared), home, "Shared");
    mkdir_p(shared);
    join_path(alias, sizeof(alias), home, "Alias");
    if (symlink("Shared", alias) != 0)
        exit(1);
    write_user_dirs(home, "Alias", "Downloads");
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "home-child");
    strcpy(roots[0].restore_path, "Shared/home-child");
    roots[0].has_restore_path = 1;
    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "Documents");
    make_v1_manifest(&manifest, roots, 2);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the HOME/XDG alias convergence manifest");
    join_path(explicit_payload, sizeof(explicit_payload), source,
              "data/EXPLICIT_0");
    join_path(xdg_payload, sizeof(xdg_payload), source,
              "data/XDG_DOCUMENTS_DIR");
    join_path(xdg_new, sizeof(xdg_new), xdg_payload, "home-child");
    mkdir_p(explicit_payload);
    mkdir_p(xdg_new);
    join_path(sentinel, sizeof(sentinel), shared, "sentinel");
    write_file_mode(sentinel, "ORIGINAL", 0600);
    join_path(missing, sizeof(missing), shared, "home-child");
    remove_fixture_packages(source);

    dry_run = 0;
    rc = run_restore_capturing_with_input(source, "y\n", output,
                                          sizeof(output));
    dry_run = previous_dry_run;
    check(rc != 0 && strstr(output, "competing entries for restore destination") != NULL &&
              access(missing, F_OK) != 0 && file_content_is(sentinel, "ORIGINAL"),
          "HOME-relative and XDG routes converging through an alias refuse before mutation");
    remove_tree(source);
    remove_tree(home);
}

static void test_versioned_restore_identity_order_and_cross_root_hardlinks(void)
{
    printf(BLUE "::" NC " restore dispatch: resolved namespace order preserves legitimate nested aliases\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_identity_success_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_identity_success_home");
    setenv("HOME", home, 1);

    char outer[PATH_MAX], middle[PATH_MAX], leaf[PATH_MAX];
    char docs_alias[PATH_MAX], downloads_alias[PATH_MAX];
    join_path(outer, sizeof(outer), home, "Outer");
    join_path(middle, sizeof(middle), outer, "Middle");
    join_path(leaf, sizeof(leaf), middle, "Leaf");
    mkdir_p(leaf);
    join_path(docs_alias, sizeof(docs_alias), home, "d");
    join_path(downloads_alias, sizeof(downloads_alias), home,
              "a-very-long-download-alias");
    if (symlink("Outer/Middle", docs_alias) != 0 ||
        symlink("Outer/Middle/Leaf", downloads_alias) != 0)
        exit(1);
    write_user_dirs(home, "d", "a-very-long-download-alias");

    ManifestRoot roots[3];
    memset(roots, 0, sizeof(roots));
    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "EXPLICIT_0");
    strcpy(roots[0].source_path, "Outer");
    strcpy(roots[0].restore_path, "Outer");
    roots[0].has_restore_path = 1;
    strcpy(roots[1].id, "XDG_DOCUMENTS_DIR");
    roots[1].policy = ROOT_POLICY_XDG;
    strcpy(roots[1].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[1].source_path, "Documents");
    strcpy(roots[2].id, "XDG_DOWNLOAD_DIR");
    roots[2].policy = ROOT_POLICY_XDG;
    strcpy(roots[2].payload_path, "XDG_DOWNLOAD_DIR");
    strcpy(roots[2].source_path, "Downloads");
    Manifest manifest;
    make_v1_manifest(&manifest, roots, 3);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the three-level nested alias manifest");

    write_payload_file(source, "data/EXPLICIT_0", "outer.txt", "LINKED");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "middle.txt", "MIDDLE");
    char outer_payload[PATH_MAX], middle_payload[PATH_MAX], leaf_payload[PATH_MAX];
    char outer_file[PATH_MAX], leaf_file[PATH_MAX];
    join_path(outer_payload, sizeof(outer_payload), source, "data/EXPLICIT_0");
    join_path(middle_payload, sizeof(middle_payload), source,
              "data/XDG_DOCUMENTS_DIR");
    join_path(leaf_payload, sizeof(leaf_payload), source,
              "data/XDG_DOWNLOAD_DIR");
    mkdir_p(leaf_payload);
    join_path(outer_file, sizeof(outer_file), outer_payload, "outer.txt");
    join_path(leaf_file, sizeof(leaf_file), leaf_payload, "leaf-link.txt");
    check(link(outer_file, leaf_file) == 0,
          "fixture: hardlink one payload across manifest roots");

    struct timespec outer_times[2] = {
        { .tv_sec = 1700001200, .tv_nsec = 100000001 },
        { .tv_sec = 1700001201, .tv_nsec = 100000002 }
    };
    struct timespec middle_times[2] = {
        { .tv_sec = 1700001210, .tv_nsec = 200000001 },
        { .tv_sec = 1700001211, .tv_nsec = 200000002 }
    };
    struct timespec leaf_times[2] = {
        { .tv_sec = 1700001220, .tv_nsec = 300000001 },
        { .tv_sec = 1700001221, .tv_nsec = 300000002 }
    };
    check(chmod(outer_payload, 0711) == 0 &&
              chmod(middle_payload, 0722) == 0 &&
              chmod(leaf_payload, 0733) == 0 &&
              utimensat(AT_FDCWD, outer_payload, outer_times, 0) == 0 &&
              utimensat(AT_FDCWD, middle_payload, middle_times, 0) == 0 &&
              utimensat(AT_FDCWD, leaf_payload, leaf_times, 0) == 0,
          "fixture: set distinct metadata on the three physical levels");
    remove_fixture_packages(source);

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[16384];
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                               sizeof(output));
    dry_run = previous_dry_run;

    char restored_outer_file[PATH_MAX], restored_leaf_file[PATH_MAX];
    join_path(restored_outer_file, sizeof(restored_outer_file), outer,
              "outer.txt");
    join_path(restored_leaf_file, sizeof(restored_leaf_file), leaf,
              "leaf-link.txt");
    struct stat outer_st, middle_st, leaf_st, first_st, second_st;
    int metadata_ok = stat(outer, &outer_st) == 0 &&
                      stat(middle, &middle_st) == 0 &&
                      stat(leaf, &leaf_st) == 0;
    int hardlink_ok = stat(restored_outer_file, &first_st) == 0 &&
                      stat(restored_leaf_file, &second_st) == 0 &&
                      first_st.st_dev == second_st.st_dev &&
                      first_st.st_ino == second_st.st_ino;
    check(rc == 0 && file_content_is(restored_outer_file, "LINKED") &&
              file_content_is(restored_leaf_file, "LINKED") && hardlink_ok,
          "non-conflicting nested alias targets restore with cross-root hardlink identity intact");
    check(metadata_ok && (outer_st.st_mode & 07777) == 0711 &&
              (middle_st.st_mode & 07777) == 0722 &&
              (leaf_st.st_mode & 07777) == 0733 &&
              outer_st.st_mtim.tv_sec == outer_times[1].tv_sec &&
              middle_st.st_mtim.tv_sec == middle_times[1].tv_sec &&
              leaf_st.st_mtim.tv_sec == leaf_times[1].tv_sec,
          "directory metadata follows physical child-before-parent order despite alias spelling lengths");

    remove_tree(source);
    remove_tree(home);
}

static void test_v2_selection_restore_nested_metadata_order(void)
{
    printf(BLUE "::" NC " restore dispatch: VERSION=2 nested-root directory metadata order\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_v2_metadata");
    fresh_mkdtemp(home, sizeof(home), "dispatch_v2_metadata_home");
    setenv("HOME", home, 1);

    ManifestRoot roots[2];
    Manifest manifest;
    make_v2_selection_manifest(&manifest, roots);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write the nested VERSION=2 selection manifest");
    write_payload_file(source, "data/CONFIG_0", "ordinary.txt", "home sibling");
    write_payload_file(source, "data/XDG_DOCUMENTS_DIR", "doc.txt", "localized document");

    char parent_payload[PATH_MAX], child_payload[PATH_MAX];
    join_path(parent_payload, sizeof(parent_payload), source, "data/CONFIG_0");
    join_path(child_payload, sizeof(child_payload), source, "data/XDG_DOCUMENTS_DIR");
    check(chmod(parent_payload, 0711) == 0 && chmod(child_payload, 0750) == 0,
          "fixture: set distinct root directory modes");
    struct timespec parent_times[2] = {
        { .tv_sec = 1700000800, .tv_nsec = 123456789 },
        { .tv_sec = 1700000801, .tv_nsec = 234567890 }
    };
    struct timespec child_times[2] = {
        { .tv_sec = 1700000810, .tv_nsec = 345678901 },
        { .tv_sec = 1700000811, .tv_nsec = 456789012 }
    };
    check(utimensat(AT_FDCWD, parent_payload, parent_times, 0) == 0 &&
              utimensat(AT_FDCWD, child_payload, child_times, 0) == 0,
          "fixture: set distinct root directory timestamps");

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[8192];
    int rc = run_restore_capturing_with_input(source, "y\n", output, sizeof(output));
    dry_run = previous_dry_run;

    char documents[PATH_MAX];
    join_path(documents, sizeof(documents), home, "Documents");
    struct stat home_st, documents_st;
    int metadata_ok = stat(home, &home_st) == 0 && stat(documents, &documents_st) == 0;
    check(rc == 0 && metadata_ok &&
              (home_st.st_mode & 07777) == 0711 &&
              (documents_st.st_mode & 07777) == 0750 &&
              home_st.st_mtim.tv_sec == parent_times[1].tv_sec &&
              documents_st.st_mtim.tv_sec == child_times[1].tv_sec,
          "child replay cannot perturb final HOME or child directory metadata");

    remove_tree(source);
    remove_tree(home);
}

static void test_v1_restore_space_preflight(void)
{
    printf(BLUE "::" NC " native restore free-space preflight and hardlink estimate\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "dispatch_src");
    fresh_mkdtemp(home, sizeof(home), "dispatch_home");
    setenv("HOME", home, 1);

    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "EXPLICIT_0");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "EXPLICIT_0");
    strcpy(root.source_path, "Documents/hardlinks");
    strcpy(root.restore_path, "Documents/hardlinks");
    root.has_restore_path = 1;

    Manifest manifest;
    make_v1_manifest(&manifest, &root, 1);
    check(manifest_write_v1(source, &manifest) == 0,
          "fixture: write a valid v1 manifest for the space preflight");
    write_payload_file(source, "data/EXPLICIT_0", "first", "payload");

    char first[PATH_MAX], second[PATH_MAX];
    join_path(first, sizeof(first), source, "data/EXPLICIT_0/first");
    join_path(second, sizeof(second), source, "data/EXPLICIT_0/second");
    if (link(first, second) != 0)
    {
        check(0, "fixture: create a hardlinked second payload member");
        remove_tree(source);
        remove_tree(home);
        return;
    }

    char payload_root[PATH_MAX];
    join_path(payload_root, sizeof(payload_root), source, "data/EXPLICIT_0");
    struct stat payload_root_st;
    int payload_root_ok = stat(payload_root, &payload_root_st) == 0 &&
                          S_ISDIR(payload_root_st.st_mode) &&
                          payload_root_st.st_size >= 0;
    check(payload_root_ok, "fixture: inspect the native payload directory size");
    if (!payload_root_ok)
    {
        remove_tree(source);
        remove_tree(home);
        return;
    }
    off_t expected_estimate = payload_root_st.st_size +
                              (off_t)strlen("payload");
    char expected_estimate_text[32];
    format_size(expected_estimate, expected_estimate_text,
                sizeof(expected_estimate_text));
    char expected_estimate_line[64];
    int expected_estimate_line_length = snprintf(
        expected_estimate_line, sizeof(expected_estimate_line),
        "Estimated restore size: %s", expected_estimate_text);
    int expected_estimate_line_valid = expected_estimate_line_length >= 0 &&
        (size_t)expected_estimate_line_length < sizeof(expected_estimate_line);

    char output[8192];
    int previous_dry_run = dry_run;
    dry_run = 1;
    int rc = run_restore_capturing(source, output, sizeof(output));
    check(rc == 0 && expected_estimate_line_valid &&
              strstr(output, expected_estimate_line) != NULL &&
              strstr(output, "Estimated restore size: 7B") == NULL,
          "native restore estimate counts directory size and a hardlink group only once");

    off_t block_size = 1;
    backup_test_set_block_size_hook(set_test_block_size, &block_size);
    backup_test_set_free_space_hook(force_no_free_space, NULL);

    rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0 && expected_estimate_line_valid &&
              strstr(output, expected_estimate_line) != NULL &&
              strstr(output, "Destination free space: 0B") != NULL &&
              strstr(output, "Error: not enough free space at ") != NULL &&
              strstr(output, home) != NULL && strstr(output, "Continue?") == NULL,
          "native dry-run refuses before confirmation when space is insufficient");

    dry_run = 0;
    rc = run_restore_capturing(source, output, sizeof(output));
    check(rc != 0 && expected_estimate_line_valid &&
              strstr(output, expected_estimate_line) != NULL &&
              strstr(output, "Destination free space: 0B") != NULL &&
              strstr(output, "Error: not enough free space at ") != NULL &&
              strstr(output, home) != NULL && strstr(output, "Continue?") == NULL,
          "native live restore refuses before confirmation when space is insufficient");
    dry_run = previous_dry_run;

    backup_test_set_block_size_hook(NULL, NULL);
    backup_test_set_free_space_hook(NULL, NULL);
    char restored[PATH_MAX];
    join_path(restored, sizeof(restored), home, "Documents/hardlinks");
    check(access(restored, F_OK) != 0,
          "native space refusal leaves the destination untouched");

    remove_tree(source);
    remove_tree(home);
}

static void test_network_config_restore_success(void)
{
    printf(BLUE "::" NC " network config: live restore copies regular files and reloads NetworkManager\n");

    char source[PATH_MAX], home[PATH_MAX], dest_parent[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_src");
    fresh_mkdtemp(home, sizeof(home), "network_home");
    fresh_mkdtemp(dest_parent, sizeof(dest_parent), "network_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    char network_dir[PATH_MAX];
    join_path(network_dir, sizeof(network_dir), source, "network/networkmanager");
    mkdir_p(network_dir);
    char office_source[PATH_MAX], wifi_source[PATH_MAX];
    join_path(office_source, sizeof(office_source), network_dir,
              "office.nmconnection");
    join_path(wifi_source, sizeof(wifi_source), network_dir,
              "wifi.nmconnection");
    write_file_mode(office_source, "[connection]\nid=office\n", 0600);
    write_file_mode(wifi_source, "[connection]\nid=wifi\n", 0640);

    char ignored_dir[PATH_MAX], ignored_link[PATH_MAX];
    join_path(ignored_dir, sizeof(ignored_dir), network_dir, "ignored-dir");
    mkdir_p(ignored_dir);
    join_path(ignored_link, sizeof(ignored_link), network_dir, "ignored-link");
    if (symlink("office.nmconnection", ignored_link) != 0)
    {
        printf(RED "fixture: could not create network symlink" NC "\n");
        exit(1);
    }

    char dest_dir[PATH_MAX];
    join_path(dest_dir, sizeof(dest_dir), dest_parent, "system-connections");
    mkdir_p(dest_dir);
    char office_dest[PATH_MAX], wifi_dest[PATH_MAX];
    join_path(office_dest, sizeof(office_dest), dest_dir,
              "office.nmconnection");
    join_path(wifi_dest, sizeof(wifi_dest), dest_dir, "wifi.nmconnection");
    write_file_mode(office_dest, "stale", 0600);

    char reload_marker[PATH_MAX];
    join_path(reload_marker, sizeof(reload_marker), dest_parent,
              "reload.marker");
    restore_test_set_network_config_dest_dir("NetworkManager", dest_dir);
    restore_test_set_network_reload_hook(record_network_reload, reload_marker);

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[8192];
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                              sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    restore_test_set_network_config_dest_dir("NetworkManager", NULL);

    check(rc == 0, "live restore succeeds when the network destination is writable");
    check(file_matches(office_dest, "[connection]\nid=office\n", 0600),
          "an existing connection file is replaced with the saved bytes and mode");
    check(file_matches(wifi_dest, "[connection]\nid=wifi\n", 0640),
          "a missing connection file is created with the saved bytes and mode");

    char ignored_dest[PATH_MAX];
    join_path(ignored_dest, sizeof(ignored_dest), dest_dir, "ignored-dir");
    check(access(ignored_dest, F_OK) != 0,
          "non-regular network backup entries are skipped");
    check(file_content_is(reload_marker,
                          "sudo\nnmcli\nconnection\nreload\n"),
          "reload uses exactly sudo nmcli connection reload once");
    check(strstr(output, "Restored 2 network connection files") != NULL,
          "the live restore reports the number of applied connection files");

    remove_tree(source);
    remove_tree(home);
    remove_tree(dest_parent);
}

static void test_network_config_restore_dry_run(void)
{
    printf(BLUE "::" NC " network config: dry-run previews without touching the destination\n");

    char source[PATH_MAX], home[PATH_MAX], dest_parent[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_dry_src");
    fresh_mkdtemp(home, sizeof(home), "network_dry_home");
    fresh_mkdtemp(dest_parent, sizeof(dest_parent), "network_dry_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    char network_dir[PATH_MAX], saved_file[PATH_MAX];
    join_path(network_dir, sizeof(network_dir), source, "network/networkmanager");
    mkdir_p(network_dir);
    join_path(saved_file, sizeof(saved_file), network_dir, "wifi.nmconnection");
    write_file_mode(saved_file, "wifi", 0600);

    char dest_dir[PATH_MAX], reload_marker[PATH_MAX];
    join_path(dest_dir, sizeof(dest_dir), dest_parent, "system-connections");
    join_path(reload_marker, sizeof(reload_marker), dest_parent,
              "reload.marker");
    restore_test_set_network_config_dest_dir("NetworkManager", dest_dir);
    restore_test_set_network_reload_hook(record_network_reload, reload_marker);

    int previous_dry_run = dry_run;
    dry_run = 1;
    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    restore_test_set_network_config_dest_dir("NetworkManager", NULL);

    check(rc == 0, "network dry-run succeeds");
    check(strstr(output, "Would restore 1 network connection file to") != NULL &&
              strstr(output, dest_dir) != NULL,
          "network dry-run previews the manifest-driven destination");
    check(access(dest_dir, F_OK) != 0,
          "network dry-run does not create the destination directory");
    check(access(reload_marker, F_OK) != 0,
          "network dry-run never invokes the reload command");

    remove_tree(source);
    remove_tree(home);
    remove_tree(dest_parent);
}

static void test_network_config_reload_failure_is_best_effort(void)
{
    printf(BLUE "::" NC " network config: reload failure warns without failing restore\n");

    char source[PATH_MAX], home[PATH_MAX], dest_parent[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_reload_src");
    fresh_mkdtemp(home, sizeof(home), "network_reload_home");
    fresh_mkdtemp(dest_parent, sizeof(dest_parent), "network_reload_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    char network_dir[PATH_MAX], saved_file[PATH_MAX];
    join_path(network_dir, sizeof(network_dir), source, "network/networkmanager");
    mkdir_p(network_dir);
    join_path(saved_file, sizeof(saved_file), network_dir, "wifi.nmconnection");
    write_file_mode(saved_file, "wifi", 0600);

    char dest_dir[PATH_MAX], reload_marker[PATH_MAX];
    join_path(dest_dir, sizeof(dest_dir), dest_parent, "system-connections");
    join_path(reload_marker, sizeof(reload_marker), dest_parent,
              "reload.marker");
    restore_test_set_network_config_dest_dir("NetworkManager", dest_dir);
    restore_test_set_network_reload_hook(record_failed_network_reload,
                                         reload_marker);

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[8192];
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                              sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    restore_test_set_network_config_dest_dir("NetworkManager", NULL);

    check(rc == 0, "reload failure does not mark an otherwise successful restore failed");
    check(strstr(output,
                 "'nmcli connection reload' did not succeed") != NULL,
          "reload failure emits the best-effort warning");
    check(file_content_is(reload_marker,
                          "sudo\nnmcli\nconnection\nreload\n"),
          "the failing reload path still receives the exact command argv");

    remove_tree(source);
    remove_tree(home);
    remove_tree(dest_parent);
}

static void test_network_config_restore_continues_after_file_error(void)
{
    printf(BLUE "::" NC " network config: one bad destination entry does not cost the remaining files\n");

    char source[PATH_MAX], home[PATH_MAX], dest_parent[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_error_src");
    fresh_mkdtemp(home, sizeof(home), "network_error_home");
    fresh_mkdtemp(dest_parent, sizeof(dest_parent), "network_error_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    char network_dir[PATH_MAX];
    join_path(network_dir, sizeof(network_dir), source, "network/networkmanager");
    mkdir_p(network_dir);
    char bad_source[PATH_MAX], good_source[PATH_MAX];
    join_path(bad_source, sizeof(bad_source), network_dir, "bad.nmconnection");
    join_path(good_source, sizeof(good_source), network_dir,
              "good.nmconnection");
    write_file_mode(bad_source, "bad", 0600);
    write_file_mode(good_source, "good", 0600);

    char dest_dir[PATH_MAX];
    join_path(dest_dir, sizeof(dest_dir), dest_parent, "system-connections");
    mkdir_p(dest_dir);
    char bad_dest[PATH_MAX], good_dest[PATH_MAX], reload_marker[PATH_MAX];
    join_path(bad_dest, sizeof(bad_dest), dest_dir, "bad.nmconnection");
    mkdir_p(bad_dest);
    join_path(good_dest, sizeof(good_dest), dest_dir, "good.nmconnection");
    join_path(reload_marker, sizeof(reload_marker), dest_parent,
              "reload.marker");
    restore_test_set_network_config_dest_dir("NetworkManager", dest_dir);
    restore_test_set_network_reload_hook(record_network_reload, reload_marker);

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[8192];
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                              sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    restore_test_set_network_config_dest_dir("NetworkManager", NULL);

    check(rc != 0, "an unexpected per-file failure marks the overall restore failed");
    check(strstr(output, "Could not restore network/networkmanager/bad.nmconnection") != NULL,
          "the failed connection file is identified");
    check(file_matches(good_dest, "good", 0600),
          "later regular connection files are still restored");
    check(file_content_is(reload_marker,
                          "sudo\nnmcli\nconnection\nreload\n"),
          "reload still runs after at least one connection file was restored");

    remove_tree(source);
    remove_tree(home);
    remove_tree(dest_parent);
}

static void test_network_config_restore_empty(void)
{
    printf(BLUE "::" NC " network config: an empty saved directory is a no-op\n");

    char source[PATH_MAX], home[PATH_MAX], dest_parent[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_empty_src");
    fresh_mkdtemp(home, sizeof(home), "network_empty_home");
    fresh_mkdtemp(dest_parent, sizeof(dest_parent), "network_empty_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    char network_dir[PATH_MAX];
    join_path(network_dir, sizeof(network_dir), source, "network/networkmanager");
    mkdir_p(network_dir);
    char dest_dir[PATH_MAX], reload_marker[PATH_MAX];
    join_path(dest_dir, sizeof(dest_dir), dest_parent, "system-connections");
    join_path(reload_marker, sizeof(reload_marker), dest_parent,
              "reload.marker");
    restore_test_set_network_config_dest_dir("NetworkManager", dest_dir);
    restore_test_set_network_reload_hook(record_network_reload, reload_marker);

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[8192];
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                              sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    restore_test_set_network_config_dest_dir("NetworkManager", NULL);

    check(rc == 0, "an empty saved network directory does not fail restore");
    check(strstr(output, "Network configuration") == NULL,
          "an empty saved network directory produces no network section");
    check(access(dest_dir, F_OK) != 0,
          "an empty saved network directory does not create the destination");
    check(access(reload_marker, F_OK) != 0,
          "an empty saved network directory does not reload NetworkManager");

    remove_tree(source);
    remove_tree(home);
    remove_tree(dest_parent);
}

static void test_network_config_restore_unapplied_note(void)
{
    printf(BLUE "::" NC " network config: an unavailable destination is informational\n");

    char source[PATH_MAX], home[PATH_MAX], dest_parent[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_note_src");
    fresh_mkdtemp(home, sizeof(home), "network_note_home");
    fresh_mkdtemp(dest_parent, sizeof(dest_parent), "network_note_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    char network_dir[PATH_MAX], saved_file[PATH_MAX];
    join_path(network_dir, sizeof(network_dir), source, "network/networkmanager");
    mkdir_p(network_dir);
    join_path(saved_file, sizeof(saved_file), network_dir, "wifi.nmconnection");
    write_file_mode(saved_file, "wifi", 0600);

    char blocker[PATH_MAX], dest_dir[PATH_MAX], reload_marker[PATH_MAX];
    join_path(blocker, sizeof(blocker), dest_parent, "not-a-directory");
    write_file_mode(blocker, "blocker", 0600);
    join_path(dest_dir, sizeof(dest_dir), blocker, "system-connections");
    join_path(reload_marker, sizeof(reload_marker), dest_parent,
              "reload.marker");
    restore_test_set_network_config_dest_dir("NetworkManager", dest_dir);
    restore_test_set_network_reload_hook(record_network_reload, reload_marker);

    int previous_dry_run = dry_run;
    dry_run = 0;
    char output[8192];
    int rc = run_restore_capturing_with_input(source, "y\n", output,
                                              sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    restore_test_set_network_config_dest_dir("NetworkManager", NULL);

    check(rc == 0,
          "an unavailable network destination does not mark the overall restore failed");
    check(strstr(output, "Note: could not write saved network connections") != NULL &&
              strstr(output, "saved files are still in the backup's network/networkmanager/ directory") != NULL,
          "the note explains that the saved connections remain in the backup");
    check(access(reload_marker, F_OK) != 0,
          "an unapplied network restore does not invoke reload");

    remove_tree(source);
    remove_tree(home);
    remove_tree(dest_parent);
}

static void test_network_config_restore_requires_declared_directory(void)
{
    printf(BLUE "::" NC " network config: NETWORK_CONFIG=1 requires network/ to exist\n");

    char source[PATH_MAX], home[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "network_missing_src");
    fresh_mkdtemp(home, sizeof(home), "network_missing_home");
    setenv("HOME", home, 1);
    write_network_manifest(source);

    int previous_dry_run = dry_run;
    dry_run = 1;
    char output[8192];
    int rc = run_restore_capturing(source, output, sizeof(output));
    dry_run = previous_dry_run;

    check(rc != 0,
          "a manifest that declares network configuration but lacks network/ fails");
    check(strstr(output,
                 "manifest declares network configuration, but network/ is missing") != NULL,
          "the inconsistent backup is diagnosed explicitly");

    remove_tree(source);
    remove_tree(home);
}

static void test_network_config_backends(unsigned int mask, int blocked_index,
                                         int broken_index, int preview)
{
    printf(BLUE "::" NC " network config: backend isolation (%u, %d, %d, %d)\n",
           mask, blocked_index, broken_index, preview);
    const char *names[] = { "NetworkManager", "netplan", "systemd-networkd",
                            "wpa_supplicant", "netctl" };
    const char *subdirs[] = { "networkmanager", "netplan", "systemd-networkd",
                            "wpa_supplicant", "netctl" };
    const char *files[] = { "wifi.nmconnection", "01-network.yaml", "10-wired.network",
                            "wpa_supplicant-wlan0.conf", "home-wifi" };
    const char *contents[] = { "[connection]\nid=wifi\n", "network: {version: 2}\n",
                               "[Match]\nName=eth0\n", "network={psk=\"fixture\"}\n",
                               "Key=fixture\n" };
    const size_t backend_count = sizeof(names) / sizeof(names[0]);
    const char *hints[] = { NULL, "sudo netplan apply", "sudo networkctl reload",
                           "sudo systemctl restart wpa_supplicant@<interface>",
                           "sudo netctl restart <profile>" };
    char source[PATH_MAX], home[PATH_MAX], target[PATH_MAX];
    fresh_mkdtemp(source, sizeof(source), "backends_src");
    fresh_mkdtemp(home, sizeof(home), "backends_home");
    fresh_mkdtemp(target, sizeof(target), "backends_dest");
    setenv("HOME", home, 1);
    write_network_manifest(source);
    char network[PATH_MAX], dest[sizeof(names) / sizeof(names[0])][PATH_MAX], marker[PATH_MAX];
    join_path(network, sizeof(network), source, "network");
    mkdir_p(network);
    join_path(marker, sizeof(marker), target, "reload.marker");
    for (size_t i = 0; i < backend_count; i++)
    {
        char backend[PATH_MAX], file[PATH_MAX];
        join_path(backend, sizeof(backend), network, subdirs[i]);
        join_path(dest[i], sizeof(dest[i]), target, subdirs[i]);
        restore_test_set_network_config_dest_dir(names[i], dest[i]);
        if (!(mask & (1u << i)))
            continue;
        if ((int)i == broken_index)
        {
            write_file_mode(backend, "not a directory", 0600);
            continue;
        }
        mkdir_p(backend);
        join_path(file, sizeof(file), backend, files[i]);
        write_file_mode(file, contents[i], 0600);
        if ((int)i == blocked_index)
        {
            mkdir_p(dest[i]);
            if (chmod(dest[i], 0500) != 0)
                exit(1);
        }
    }
    restore_test_set_network_reload_hook(record_network_reload, marker);
    int previous_dry_run = dry_run;
    dry_run = preview;
    char output[16384];
    int rc = run_restore_capturing_with_input(source, "y\n", output, sizeof(output));
    dry_run = previous_dry_run;
    restore_test_set_network_reload_hook(NULL, NULL);
    for (size_t i = 0; i < backend_count; i++)
        restore_test_set_network_config_dest_dir(names[i], NULL);
    check((rc != 0) == (mask == 0 || broken_index >= 0),
          "only missing backends or corrupt sources fail restore");
    for (size_t i = 0; i < backend_count; i++)
    {
        char file[PATH_MAX];
        join_path(file, sizeof(file), dest[i], files[i]);
        int expected = (mask & (1u << i)) && !preview &&
                       (int)i != blocked_index && (int)i != broken_index;
        check(expected ? file_matches(file, contents[i], 0600) : access(file, F_OK) != 0,
              "each backend restores only its own saved bytes and mode");
    }
    if ((mask & 1u) && !preview && blocked_index != 0 && broken_index != 0)
        check(file_content_is(marker, "sudo\nnmcli\nconnection\nreload\n"),
              "only NetworkManager invokes the reload hook, exactly once");
    else
        check(access(marker, F_OK) != 0, "no automatic reload without live NetworkManager files");
    for (size_t i = 1; i < backend_count; i++)
    {
        int should_hint = !preview && (mask & (1u << i)) && (int)i != broken_index;
        check((strstr(output, hints[i]) != NULL) == should_hint,
              "each manual backend emits its own hint only when applicable");
        if (should_hint)
            check(strstr(output, "interrupt network connectivity") != NULL,
                  "manual apply explains the interruption risk");
        if (should_hint && i >= 3)
            check(strstr(output, i == 3 ? "replace <interface>" : "replace <profile>") != NULL,
                  "manual restart identifies the value the user must substitute");
    }
    if (blocked_index >= 0)
    {
        char saved_path[128];
        snprintf(saved_path, sizeof(saved_path), "network/%s/", subdirs[blocked_index]);
        check(strstr(output, "Note: could not write") != NULL &&
              strstr(output, saved_path) != NULL,
              "unwritable backend identifies the saved source in an informational note");
        if (chmod(dest[blocked_index], 0700) != 0)
            exit(1);
    }
    if (broken_index >= 0)
    {
        char diagnostic[128];
        snprintf(diagnostic, sizeof(diagnostic), "Could not read network/%s/",
                 subdirs[broken_index]);
        check(strstr(output, diagnostic) != NULL,
              "a corrupt backend source is identified while healthy backends succeed");
        if (mask == (1u << broken_index))
            check(strstr(output, "none of the known backend directories were present") == NULL,
                  "a corrupt sole backend is not also reported as entirely missing");
    }
    if (mask == 0)
        check(strstr(output, "none of the known backend directories were present") != NULL &&
              strstr(output, "network/ is missing") == NULL,
              "missing backend directories are distinct from a missing network directory");
    if (preview)
        check(strstr(output, "sudo netplan apply") == NULL &&
              strstr(output, "sudo networkctl reload") == NULL,
              "dry-run emits no live apply instructions");
    remove_tree(source);
    remove_tree(home);
    remove_tree(target);
}

static void test_network_config_roundtrip(const char *backend_name,
                                           const char *filename,
                                           const char *hint)
{
    printf(BLUE "::" NC " network config: %s backup-to-restore round trip\n", backend_name);
    const char *names[] = { "NetworkManager", "netplan", "systemd-networkd",
                            "wpa_supplicant", "netctl" };
    char home[PATH_MAX], target[PATH_MAX], restored_home[PATH_MAX];
    fresh_mkdtemp(home, sizeof(home), "network_roundtrip_home");
    fresh_mkdtemp(target, sizeof(target), "network_roundtrip_backup");
    fresh_mkdtemp(restored_home, sizeof(restored_home), "network_roundtrip_restore");
    char source_dir[PATH_MAX], source_file[PATH_MAX], payload[PATH_MAX], missing[PATH_MAX];
    join_path(source_dir, sizeof(source_dir), home, "network-source");
    mkdir_p(source_dir);
    join_path(source_file, sizeof(source_file), source_dir, filename);
    write_file_mode(source_file, "fixture network configuration\n", 0600);
    join_path(payload, sizeof(payload), home, "payload");
    write_file_mode(payload, "fixture payload\n", 0600);
    join_path(missing, sizeof(missing), home, "absent-backend");
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        backup_test_set_network_config_source_dir(
            names[i], strcmp(names[i], backend_name) == 0 ? source_dir : missing);
    setenv("HOME", home, 1);
    int previous_dry_run = dry_run;
    dry_run = 0;
    char *paths[] = { payload, NULL };
    int backup_rc = backup(target, BACKUP_EXPLICIT_PATHS, paths, 0, 1);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        backup_test_set_network_config_source_dir(names[i], NULL);

    char container[PATH_MAX] = "";
    DIR *dir = opendir(target);
    if (dir == NULL)
        exit(1);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        if (strncmp(entry->d_name, "migr_backup_", 12) == 0 &&
            strstr(entry->d_name, ".partial") == NULL)
            join_path(container, sizeof(container), target, entry->d_name);
    if (closedir(dir) != 0)
        exit(1);
    check(backup_rc == 0 && container[0] != '\0',
          "production backup publishes a container for the sole backend");
    if (backup_rc == 0 && container[0] != '\0')
    {
        char dest[PATH_MAX], restored[PATH_MAX], marker[PATH_MAX];
        join_path(dest, sizeof(dest), restored_home, "network-destination");
        join_path(restored, sizeof(restored), dest, filename);
        join_path(marker, sizeof(marker), restored_home, "reload.marker");
        setenv("HOME", restored_home, 1);
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            restore_test_set_network_config_dest_dir(names[i], dest);
        restore_test_set_network_reload_hook(record_network_reload, marker);
        char output[16384];
        int rc = run_restore_capturing_with_input(container, "y\n", output, sizeof(output));
        restore_test_set_network_reload_hook(NULL, NULL);
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            restore_test_set_network_config_dest_dir(names[i], NULL);
        check(rc == 0 && file_matches(restored, "fixture network configuration\n", 0600),
              "restore consumes the actual backup layout and preserves network bytes and mode");
        check(strstr(output, hint) != NULL &&
              strstr(output, "interrupt network connectivity") != NULL &&
              access(marker, F_OK) != 0,
              "the round trip provides manual apply guidance without invoking automatic reload");
    }
    dry_run = previous_dry_run;
    remove_tree(home);
    remove_tree(target);
    remove_tree(restored_home);
}

int main(void)
{
    printf(BLUE "::" NC " restore dispatch (unit)\n");

    dry_run = 1; // inherited by every fork()ed restore() call below; no confirm_action() prompt is ever reached

    test_dispatch_routes_missing_manifest_to_legacy();
    test_dispatch_routes_legacy_xdg_manifest_to_legacy();
    test_dispatch_refuses_unknown_version();
    test_dispatch_refuses_malformed_v1();
    test_dispatch_refuses_partial_source();
    test_dispatch_requires_v1_manifest_for_final_container_name();
    test_dispatch_refuses_portable_v1();
    test_v1_refuses_missing_declared_payloads();

    test_v1_restores_home_relative_and_xdg_reports_manual_native();
    test_v1_empty_restore_path_means_home_itself();
    test_v2_selection_restore_refusals();
    test_v2_payload_depth_is_bounded();
    test_v2_home_relative_restore_destination_too_long();
    test_versioned_restore_freezes_xdg_target_map();
    test_versioned_restore_rejects_non_directory_payload_paths();
    test_versioned_restore_refuses_bind_mount_aliases();
    test_versioned_restore_refuses_destination_alias_collisions();
    test_versioned_restore_identity_order_and_cross_root_hardlinks();
    test_v2_selection_restore_nested_metadata_order();
    test_v1_restore_space_preflight();
    test_network_config_backends(2, -1, -1, 0);
    test_network_config_backends(4, -1, -1, 0);
    test_network_config_backends(7, -1, -1, 0);
    test_network_config_backends(7, 1, -1, 0);
    test_network_config_backends(7, -1, 1, 0);
    test_network_config_backends(7, -1, -1, 1);
    test_network_config_backends(0, -1, -1, 0);
    test_network_config_backends(2, -1, 1, 0);
    test_network_config_backends(8, -1, -1, 0);
    test_network_config_backends(16, -1, -1, 0);
    test_network_config_backends(8, -1, 3, 0);
    test_network_config_backends(16, -1, 4, 0);
    test_network_config_backends(31, -1, -1, 0);
    test_network_config_backends(31, -1, -1, 1);
    test_network_config_backends(31, 3, -1, 0);
    test_network_config_backends(31, 4, -1, 0);
    test_network_config_roundtrip("wpa_supplicant", "wpa_supplicant-wlan0.conf",
                                  "sudo systemctl restart wpa_supplicant@<interface>");
    test_network_config_roundtrip("netctl", "home-wifi", "sudo netctl restart <profile>");
    test_network_config_restore_success();
    test_network_config_restore_dry_run();
    test_network_config_reload_failure_is_best_effort();
    test_network_config_restore_continues_after_file_error();
    test_network_config_restore_empty();
    test_network_config_restore_unapplied_note();
    test_network_config_restore_requires_declared_directory();

    if (failures > 0)
    {
        printf(RED "%d restore dispatch test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
