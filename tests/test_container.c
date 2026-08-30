// Unit tests for the atomic backup container lifecycle (docs/DECISIONS.md D15)
// and its manifest-side support: manifest_read_v1_at() and
// manifest_resume_identity_compare() (declared in manifest.h, exercised
// directly below as well as indirectly through container_adopt()).

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h> /* flock */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "container.h"
#include "manifest.h"

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

// A fixed, arbitrary instant. Every naming assertion below computes its own
// expectation from this same value via gmtime_r() rather than hard-coding a
// date string, so it stays correct regardless of which instant is chosen.
static const time_t FIXED_TIME = 1735689600;

static char test_root[] = "/tmp/migr_container_XXXXXX";

static int remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_fixture_tree(const char *path)
{
    if (nftw(path, remove_cb, 16, FTW_DEPTH | FTW_PHYS) != 0)
    {
        printf(RED "fixture: could not fully clean up a test tree" NC "\n");
        exit(1);
    }
}

static void clean_test_root(void)
{
    // A failed cleanup is fixture-fatal, not silently ignored: a partially
    // removed test_root left behind by one test could otherwise let a later
    // test's fixture succeed (or fail) for the wrong reason.
    remove_fixture_tree(test_root);
}

// Recreates test_root as a fresh, empty directory. Fixture setup failure is
// fatal (exit), never a soft check(): a broken fixture invalidates every
// assertion that follows it, so continuing would just produce noise.
static void fresh_test_root(void)
{
    clean_test_root();
    if (mkdir(test_root, 0700) != 0)
    {
        printf(RED "fixture: could not recreate the test root" NC "\n");
        exit(1);
    }
}

static void force_utc_timezone(void)
{
    setenv("TZ", "UTC", 1);
    tzset();
}

static void path_under_root(char *buf, size_t bufsize, const char *name)
{
    if ((size_t)snprintf(buf, bufsize, "%s/%s", test_root, name) >= bufsize)
    {
        printf(RED "fixture: path too long" NC "\n");
        exit(1);
    }
}

static void write_raw(const char *path, const char *content)
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

// The exact "migr_backup_YYYYMMDD_HHMMSS" string container_reserve() must
// produce for FIXED_TIME, under the forced UTC timezone (localtime_r ==
// gmtime_r there).
static void compute_expected_base(char *out, size_t out_size)
{
    struct tm tmbuf;
    gmtime_r(&FIXED_TIME, &tmbuf);
    snprintf(out, out_size, "migr_backup_%04d%02d%02d_%02d%02d%02d",
              tmbuf.tm_year + 1900, tmbuf.tm_mon + 1, tmbuf.tm_mday,
              tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec);
}

static void make_reference_manifest(Manifest *m)
{
    memset(m, 0, sizeof(*m));
    m->version = MANIFEST_CURRENT_VERSION;
    m->representation = CLONE_NATIVE_TREE;
    m->scope = MANIFEST_SCOPE_EXPLICIT;
    m->sidecar_version = 0;
    m->has_source_identity = 1;
    strcpy(m->machine_id, "deadbeefcafef00d0123456789abcdef");
    m->source_uid = 1000;
    m->root_count = 0;
    m->roots = NULL;
}

/* ========================================================================= */
/* Naming and reservation                                                    */
/* ========================================================================= */

static void test_reserve_generates_expected_stamp(void)
{
    printf(BLUE "::" NC " container: reserve names by local time (forced to UTC for this test)\n");
    fresh_test_root();

    char expected_final[CONTAINER_NAME_MAX];
    compute_expected_base(expected_final, sizeof(expected_final));
    char expected_partial[CONTAINER_NAME_MAX + 16]; // + ".partial", generously
    snprintf(expected_partial, sizeof(expected_partial), "%s.partial", expected_final);

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "reserve succeeds");
    check(strcmp(c.final_name, expected_final) == 0, "final_name matches the expected local-time stamp");
    check(strcmp(c.partial_name, expected_partial) == 0, "partial_name is final_name + \".partial\"");
    check(c.suffix == 0, "first reservation has no suffix");

    container_close(&c);
    fresh_test_root();
}

static void test_reserve_partial_collision_advances_suffix(void)
{
    printf(BLUE "::" NC " container: a partial-name collision advances to the next suffix\n");
    fresh_test_root();

    BackupContainer first;
    check(container_reserve(test_root, FIXED_TIME, &first) == CONTAINER_OK, "fixture: first reservation");
    check(first.suffix == 0, "fixture: first reservation has suffix 0");

    BackupContainer second;
    check(container_reserve(test_root, FIXED_TIME, &second) == CONTAINER_OK,
          "second same-second reservation still succeeds");
    check(second.suffix == 1, "second reservation advances to suffix 1");
    check(strcmp(first.partial_name, second.partial_name) != 0, "the two partials have distinct names");

    container_close(&first);
    container_close(&second);
    fresh_test_root();
}

static void test_reserve_fd_is_anchored(void)
{
    printf(BLUE "::" NC " container: reserve_fd stays on the opened destination after a path swap\n");
    fresh_test_root();

    int root_fd = open(test_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(root_fd >= 0, "fixture: open the destination root before swapping its path");
    if (root_fd < 0)
        return;

    char saved[PATH_MAX];
    if (snprintf(saved, sizeof(saved), "%s.saved", test_root) < 0 ||
        rename(test_root, saved) != 0)
    {
        check(0, "fixture: move the originally opened destination aside");
        close(root_fd);
        return;
    }
    check(mkdir(test_root, 0700) == 0,
          "fixture: replace the destination path with a different directory");

    BackupContainer reserved = {0};
    ContainerStatus status = container_reserve_fd(root_fd, FIXED_TIME, &reserved);
    check(status == CONTAINER_OK,
          "reserve_fd succeeds against the originally opened destination");
    check(fstat(root_fd, &(struct stat){0}) == 0,
          "reserve_fd leaves the borrowed destination fd open");

    if (status == CONTAINER_OK)
    {
        struct stat original_entry;
        check(fstatat(root_fd, reserved.partial_name, &original_entry,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(original_entry.st_mode),
              "reserve_fd claims its partial under the opened destination");

        int swapped_fd = open(test_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(swapped_fd >= 0, "fixture: open the swapped-in destination");
        if (swapped_fd >= 0)
        {
            struct stat swapped_entry;
            check(fstatat(swapped_fd, reserved.partial_name, &swapped_entry,
                          AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
                  "reserve_fd does not claim a partial under the swapped path");
            close(swapped_fd);
        }
    }

    container_close(&reserved);
    close(root_fd);
    remove_fixture_tree(test_root);
    remove_fixture_tree(saved);
    check(mkdir(test_root, 0700) == 0,
          "fixture: recreate the destination root for later checks");
    fresh_test_root();
}

static void test_reserve_final_collision_advances_suffix(void)
{
    printf(BLUE "::" NC " container: a pre-existing final name advances to the next suffix, untouched\n");
    fresh_test_root();

    char preexisting[CONTAINER_NAME_MAX];
    compute_expected_base(preexisting, sizeof(preexisting));
    char preexisting_path[PATH_MAX];
    path_under_root(preexisting_path, sizeof(preexisting_path), preexisting);
    check(mkdir(preexisting_path, 0700) == 0, "fixture: pre-create the final name for suffix 0");

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK,
          "reserve succeeds by skipping the taken suffix");
    check(c.suffix == 1, "suffix 0's final was taken, so suffix 1 was claimed instead");

    struct stat st;
    check(stat(preexisting_path, &st) == 0 && S_ISDIR(st.st_mode),
          "the pre-existing final directory is untouched");

    container_close(&c);
    fresh_test_root();
}

// Each child reports that it reached the start gate and waits for a release
// token. The parent sends both tokens only after receiving both ready signals,
// so neither child enters container_reserve() before both reach the gate.
static void test_concurrent_reserve_claims_distinct_partials(void)
{
    printf(BLUE "::" NC " container: two same-second reservations claim distinct partials\n");
    fresh_test_root();

    int ready_pipe[2]; // children -> parent: "I'm at the gate"
    int go_pipe[2];    // parent -> children: "go"
    int result_pipe[2]; // children -> parent: suffix (or -1 on failure)
    if (pipe(ready_pipe) != 0 || pipe(go_pipe) != 0 || pipe(result_pipe) != 0)
    {
        perror("pipe");
        exit(1);
    }

    pid_t pids[2];
    for (int i = 0; i < 2; i++)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            exit(1);
        }
        if (pid == 0)
        {
            close(ready_pipe[0]);
            close(go_pipe[1]);
            close(result_pipe[0]);

            char byte = 1;
            if (write(ready_pipe[1], &byte, 1) != 1)
                _exit(2);
            close(ready_pipe[1]);

            char go_byte = 0;
            if (read(go_pipe[0], &go_byte, 1) != 1 || go_byte != 1)
                _exit(2);
            close(go_pipe[0]);

            BackupContainer c;
            ContainerStatus st = container_reserve(test_root, FIXED_TIME, &c);
            int reply = (st == CONTAINER_OK) ? c.suffix : -1;
            if (write(result_pipe[1], &reply, sizeof(reply)) != (ssize_t)sizeof(reply))
                _exit(2);
            close(result_pipe[1]);
            _exit(0);
        }
        pids[i] = pid;
    }

    close(ready_pipe[1]);
    close(go_pipe[0]);
    close(result_pipe[1]);

    for (int i = 0; i < 2; i++)
    {
        char byte = 0;
        ssize_t r = read(ready_pipe[0], &byte, 1);
        check(r == 1, "fixture: a child reported ready at the start gate");
    }
    close(ready_pipe[0]);

    char go_byte = 1;
    ssize_t w1 = write(go_pipe[1], &go_byte, 1);
    ssize_t w2 = write(go_pipe[1], &go_byte, 1);
    check(w1 == 1 && w2 == 1, "fixture: released both children from the start gate");
    close(go_pipe[1]);

    int replies[2] = {-1, -1};
    for (int i = 0; i < 2; i++)
    {
        ssize_t got = read(result_pipe[0], &replies[i], sizeof(replies[i]));
        check(got == (ssize_t)sizeof(replies[i]), "fixture: received a child's result");
    }
    close(result_pipe[0]);

    int both_exited_cleanly = 1;
    for (int i = 0; i < 2; i++)
    {
        int status = 0;
        pid_t waited;
        do
        {
            waited = waitpid(pids[i], &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != pids[i] || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            both_exited_cleanly = 0;
    }
    check(both_exited_cleanly, "both children exited cleanly");

    check(replies[0] >= 0 && replies[1] >= 0, "both concurrent reservations succeeded");
    if (replies[0] >= 0 && replies[1] >= 0)
    {
        int suffixes_distinct =
            (replies[0] == 0 && replies[1] == 1) || (replies[0] == 1 && replies[1] == 0);
        check(suffixes_distinct, "the two concurrent reservations claimed suffixes {0,1}, not the same one");
    }

    fresh_test_root();
}

// Deterministically simulates a concurrent container_adopt_fd() scan
// winning the flock() on a just-created partial before container_reserve_fd()
// gets to it, via container_test_set_reserve_hook() (CONTAINER_TEST_HOOKS) --
// fires synchronously inside container_reserve_fd() right after mkdirat(),
// so this needs no real inter-process race or timing assumption.
static int reserve_race_hook_fd = -1;
static int reserve_race_hook_fired = 0;

static void reserve_race_hook(int dir_fd, const char *partial_name,
                              void *context)
{
    (void)context;
    if (reserve_race_hook_fired)
        return;
    reserve_race_hook_fired = 1;
    reserve_race_hook_fd = openat(dir_fd, partial_name,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (reserve_race_hook_fd >= 0)
        (void)flock(reserve_race_hook_fd, LOCK_EX | LOCK_NB);
}

static void test_reserve_flock_race_advances_suffix(void)
{
    printf(BLUE "::" NC " container: losing the flock race to a concurrent adopt-scan advances the suffix instead of failing\n");
    fresh_test_root();

    reserve_race_hook_fd = -1;
    reserve_race_hook_fired = 0;
    container_test_set_reserve_hook(reserve_race_hook, NULL);

    BackupContainer c;
    ContainerStatus status = container_reserve(test_root, FIXED_TIME, &c);

    container_test_set_reserve_hook(NULL, NULL);

    check(status == CONTAINER_OK && c.suffix == 1,
          "reserve retries the next suffix instead of failing when it loses the flock race");
    check(reserve_race_hook_fd >= 0, "fixture: the simulated concurrent holder actually acquired the lock");

    char contested_partial[CONTAINER_NAME_MAX + 16];
    char expected_final[CONTAINER_NAME_MAX];
    compute_expected_base(expected_final, sizeof(expected_final));
    snprintf(contested_partial, sizeof(contested_partial), "%s.partial", expected_final);
    char contested_path[PATH_MAX];
    path_under_root(contested_path, sizeof(contested_path), contested_partial);
    struct stat st;
    check(stat(contested_path, &st) == 0 && S_ISDIR(st.st_mode),
          "the contended suffix-0 partial is left on disk, not unlinked out from under its holder");

    if (reserve_race_hook_fd >= 0)
        close(reserve_race_hook_fd);
    if (status == CONTAINER_OK)
        container_close(&c);
    fresh_test_root();
}

/* ========================================================================= */
/* Finalize / close                                                         */
/* ========================================================================= */

static void test_finalize_success(void)
{
    printf(BLUE "::" NC " container: successful finalize removes the partial name and creates the final\n");
    fresh_test_root();

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve");

    char partial_path[PATH_MAX], final_path[PATH_MAX];
    path_under_root(partial_path, sizeof(partial_path), c.partial_name);
    path_under_root(final_path, sizeof(final_path), c.final_name);

    char payload_path[PATH_MAX];
    if ((size_t)snprintf(payload_path, sizeof(payload_path), "%s/payload.txt",
                         partial_path) >= sizeof(payload_path))
    {
        printf(RED "fixture: payload path too long" NC "\n");
        exit(1);
    }
    write_raw(payload_path, "durable test payload\n");

    check(container_finalize(&c) == CONTAINER_OK, "finalize succeeds");
    check(c.state == CONTAINER_STATE_FINALIZED, "the handle reports CONTAINER_STATE_FINALIZED");

    struct stat st;
    check(stat(partial_path, &st) != 0 && errno == ENOENT, "the .partial name no longer exists");
    check(stat(final_path, &st) == 0 && S_ISDIR(st.st_mode), "the final name now exists");

    char published_payload_path[PATH_MAX];
    if ((size_t)snprintf(published_payload_path, sizeof(published_payload_path),
                         "%s/payload.txt", final_path) >= sizeof(published_payload_path))
    {
        printf(RED "fixture: published payload path too long" NC "\n");
        exit(1);
    }
    check(stat(published_payload_path, &st) == 0 && S_ISREG(st.st_mode),
          "the finalized container retains its payload");

    container_close(&c);
    fresh_test_root();
}

static void test_finalize_sync_failure_leaves_partial(void)
{
    printf(BLUE "::" NC " container: a pre-rename sync failure leaves the partial untouched\n");
    fresh_test_root();

    BackupContainer c;
    ContainerStatus reserve_status = container_reserve(test_root, FIXED_TIME, &c);
    check(reserve_status == CONTAINER_OK, "fixture: reserve");
    if (reserve_status != CONTAINER_OK)
    {
        fresh_test_root();
        return;
    }

    char partial_path[PATH_MAX], final_path[PATH_MAX];
    path_under_root(partial_path, sizeof(partial_path), c.partial_name);
    path_under_root(final_path, sizeof(final_path), c.final_name);

    int partial_fd = container_root_fd(&c);
    int close_status = close(partial_fd);
    ContainerStatus finalize_status = container_finalize(&c);

    check(close_status == 0 && finalize_status == CONTAINER_ERR_IO,
          "an invalid payload fd makes finalize fail closed before rename");
    check(c.state == CONTAINER_STATE_PARTIAL,
          "the handle remains PARTIAL after a pre-rename sync failure");

    struct stat st;
    check(stat(partial_path, &st) == 0 && S_ISDIR(st.st_mode),
          "the partial name remains after a pre-rename sync failure");
    check(stat(final_path, &st) != 0 && errno == ENOENT,
          "the final name is not created after a pre-rename sync failure");

    /* The fd was closed deliberately above; prevent container_close() from
       treating its now-reusable number as still owned by the handle. */
    c.partial_fd = -1;
    container_close(&c);
    fresh_test_root();
}

static void test_finalize_refuses_existing_final(void)
{
    printf(BLUE "::" NC " container: finalize refuses to replace an existing final, leaving the partial intact\n");
    fresh_test_root();

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve");

    char final_path[PATH_MAX];
    path_under_root(final_path, sizeof(final_path), c.final_name);
    check(mkdir(final_path, 0700) == 0, "fixture: a concurrent finalize already claimed the final name");

    check(container_finalize(&c) == CONTAINER_ERR_FINAL_EXISTS,
          "finalize refuses rather than replacing the existing final");
    check(c.state == CONTAINER_STATE_PARTIAL, "the handle remains a valid PARTIAL state after refusal");

    char partial_path[PATH_MAX];
    path_under_root(partial_path, sizeof(partial_path), c.partial_name);
    struct stat st;
    check(stat(partial_path, &st) == 0 && S_ISDIR(st.st_mode),
          "the partial is left in place after a refused finalize");

    container_close(&c);
    fresh_test_root();
}

static void test_finalize_rejects_invalid_handle(void)
{
    printf(BLUE "::" NC " container: finalize rejects an empty or already-finalized handle\n");

    BackupContainer zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    check(container_finalize(&zeroed) == CONTAINER_ERR_INVALID, "finalize on a zeroed handle is refused");

    fresh_test_root();
    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve");
    check(container_finalize(&c) == CONTAINER_OK, "fixture: finalize once");
    check(container_finalize(&c) == CONTAINER_ERR_INVALID,
          "finalizing an already-finalized handle is refused");

    container_close(&c);
    fresh_test_root();
}

static void test_close_does_not_delete(void)
{
    printf(BLUE "::" NC " container: close releases the handle but leaves the partial on disk\n");
    fresh_test_root();

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve");
    char partial_path[PATH_MAX];
    path_under_root(partial_path, sizeof(partial_path), c.partial_name);

    container_close(&c);

    struct stat st;
    check(stat(partial_path, &st) == 0 && S_ISDIR(st.st_mode),
          "the partial directory still exists after close()");
    check(c.state == CONTAINER_STATE_EMPTY && c.dir_fd == -1 && c.partial_fd == -1,
          "the handle itself is reset to empty (dir_fd/partial_fd == -1)");

    fresh_test_root();
}

static void test_close_on_zeroed_is_safe(void)
{
    printf(BLUE "::" NC " container: close on a zero-initialized handle never touches fd 0/1\n");

    int saved_in = dup(0);
    int saved_out = dup(1);
    if (saved_in < 0 || saved_out < 0)
    {
        printf(RED "fixture: could not save stdin/stdout" NC "\n");
        exit(1);
    }

    BackupContainer c;
    memset(&c, 0, sizeof(c)); // dir_fd/partial_fd are 0 under {0}: must not become close(0)/close(1)
    container_close(&c);

    check(fcntl(0, F_GETFD) != -1, "fd 0 (stdin) is still open after closing a zeroed handle");
    check(fcntl(1, F_GETFD) != -1, "fd 1 (stdout) is still open after closing a zeroed handle");

    dup2(saved_in, 0);
    dup2(saved_out, 1);
    close(saved_in);
    close(saved_out);
}

/* ========================================================================= */
/* NULL / invalid-argument safety                                          */
/* ========================================================================= */

static void test_null_arguments_are_rejected_safely(void)
{
    printf(BLUE "::" NC " container: NULL/missing arguments are rejected without crashing\n");

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, NULL) == CONTAINER_ERR_INVALID,
          "reserve with a NULL out is rejected");
    check(container_reserve(NULL, FIXED_TIME, &c) == CONTAINER_ERR_INVALID,
          "reserve with a NULL dest_root is rejected");
    check(container_reserve_fd(-1, FIXED_TIME, &c) == CONTAINER_ERR_INVALID,
          "reserve_fd with an invalid dest_root_fd is rejected");

    Manifest wanted;
    make_reference_manifest(&wanted);
    check(container_adopt(test_root, &wanted, NULL) == CONTAINER_ERR_INVALID,
          "adopt with a NULL out is rejected");
    check(container_adopt(NULL, &wanted, &c) == CONTAINER_ERR_INVALID,
          "adopt with a NULL dest_root is rejected");
    check(container_adopt(test_root, NULL, &c) == CONTAINER_ERR_INVALID,
          "adopt with a NULL wanted_identity is rejected");
    check(container_adopt_fd(-1, &wanted, &c) == CONTAINER_ERR_INVALID,
          "adopt_fd with an invalid dest_root_fd is rejected");

    check(container_finalize(NULL) == CONTAINER_ERR_INVALID, "finalize(NULL) is rejected");

    container_close(NULL);
    check(1, "close(NULL) does not crash");
}

/* ========================================================================= */
/* Adoption                                                                 */
/* ========================================================================= */

static void test_adopt_rejects_wanted_without_identity(void)
{
    printf(BLUE "::" NC " container: adopt refuses a caller with no source identity, before any scan\n");
    fresh_test_root();

    Manifest wanted;
    make_reference_manifest(&wanted);
    wanted.has_source_identity = 0;

    BackupContainer adopted;
    check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_NO_MATCH,
          "an invocation without a source identity can never adopt anything");
    container_close(&adopted);
}

static void test_adopt_matches_and_retains_inode(void)
{
    printf(BLUE "::" NC " container: adopt resumes a matching partial and keeps its verified inode\n");
    fresh_test_root();

    BackupContainer reserved;
    check(container_reserve(test_root, FIXED_TIME, &reserved) == CONTAINER_OK, "fixture: reserve");

    char reserved_name_copy[CONTAINER_NAME_MAX];
    snprintf(reserved_name_copy, sizeof(reserved_name_copy), "%s", reserved.partial_name);

    Manifest m;
    make_reference_manifest(&m);
    char dir_path[PATH_MAX];
    path_under_root(dir_path, sizeof(dir_path), reserved.partial_name);
    check(manifest_write_v1(dir_path, &m) == 0, "fixture: write a matching manifest");

    struct stat before;
    check(fstat(reserved.partial_fd, &before) == 0, "fixture: stat the reserved directory");

    container_close(&reserved); // release the lock so adopt() can see it as unlocked

    Manifest wanted;
    make_reference_manifest(&wanted);
    BackupContainer adopted;
    ContainerStatus st = container_adopt(test_root, &wanted, &adopted);
    check(st == CONTAINER_OK, "a partial with a matching manifest is adopted");

    if (st == CONTAINER_OK)
    {
        check(strcmp(adopted.partial_name, reserved_name_copy) == 0, "adopted handle names the same partial");

        char renamed_path[PATH_MAX];
        path_under_root(renamed_path, sizeof(renamed_path), "renamed_elsewhere");
        char old_path[PATH_MAX];
        path_under_root(old_path, sizeof(old_path), adopted.partial_name);
        check(rename(old_path, renamed_path) == 0, "fixture: rename the adopted partial externally");

        struct stat after;
        check(fstat(adopted.partial_fd, &after) == 0, "stat the adopted fd after the external rename");
        check(before.st_ino == after.st_ino && before.st_dev == after.st_dev,
              "the adopted fd still refers to the same inode after an external rename");
    }

    container_close(&adopted);
    fresh_test_root();
}

static void test_adopt_fd_is_anchored(void)
{
    printf(BLUE "::" NC " container: adopt_fd stays on the opened destination after a path swap\n");
    fresh_test_root();

    Manifest manifest;
    make_reference_manifest(&manifest);

    BackupContainer reserved;
    check(container_reserve(test_root, FIXED_TIME, &reserved) == CONTAINER_OK,
          "fixture: reserve a partial for fd adoption");
    char partial_name[CONTAINER_NAME_MAX] = {0};
    snprintf(partial_name, sizeof(partial_name), "%s", reserved.partial_name);
    char partial_path[PATH_MAX];
    path_under_root(partial_path, sizeof(partial_path), reserved.partial_name);
    check(manifest_write_v1(partial_path, &manifest) == 0,
          "fixture: write the matching manifest");
    container_close(&reserved);

    int root_fd = open(test_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(root_fd >= 0, "fixture: open the destination root before swapping its path");
    if (root_fd < 0)
    {
        fresh_test_root();
        return;
    }

    char saved[PATH_MAX];
    if (snprintf(saved, sizeof(saved), "%s.saved", test_root) < 0 ||
        rename(test_root, saved) != 0)
    {
        check(0, "fixture: move the originally opened destination aside");
        close(root_fd);
        fresh_test_root();
        return;
    }
    check(mkdir(test_root, 0700) == 0,
          "fixture: replace the destination path with a different directory");

    BackupContainer adopted = {0};
    ContainerStatus status = container_adopt_fd(root_fd, &manifest, &adopted);
    check(status == CONTAINER_OK,
          "adopt_fd finds the matching partial under the opened destination");
    check(fstat(root_fd, &(struct stat){0}) == 0,
          "adopt_fd leaves the borrowed destination fd open");

    if (status == CONTAINER_OK)
    {
        check(strcmp(adopted.partial_name, partial_name) == 0,
              "adopt_fd returns the expected partial name");
        struct stat original_entry;
        check(fstatat(root_fd, adopted.partial_name, &original_entry,
                      AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(original_entry.st_mode),
              "adopt_fd opened the candidate under the opened destination");

        int swapped_fd = open(test_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(swapped_fd >= 0, "fixture: open the swapped-in destination");
        if (swapped_fd >= 0)
        {
            struct stat swapped_entry;
            check(fstatat(swapped_fd, adopted.partial_name, &swapped_entry,
                          AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
                  "adopt_fd does not scan the swapped path");
            close(swapped_fd);
        }
    }

    container_close(&adopted);
    close(root_fd);
    remove_fixture_tree(test_root);
    remove_fixture_tree(saved);
    check(mkdir(test_root, 0700) == 0,
          "fixture: recreate the destination root for later checks");
    fresh_test_root();
}

static void test_adopt_fd_failure_keeps_borrowed_fd(void)
{
    printf(BLUE "::" NC " container: adopt_fd keeps the borrowed fd open on an ambiguous failure\n");
    fresh_test_root();

    Manifest manifest;
    make_reference_manifest(&manifest);

    BackupContainer first;
    check(container_reserve(test_root, FIXED_TIME, &first) == CONTAINER_OK,
          "fixture: reserve the first matching partial");
    char first_path[PATH_MAX];
    path_under_root(first_path, sizeof(first_path), first.partial_name);
    check(manifest_write_v1(first_path, &manifest) == 0,
          "fixture: write the first matching manifest");
    container_close(&first);

    BackupContainer second;
    check(container_reserve(test_root, FIXED_TIME, &second) == CONTAINER_OK,
          "fixture: reserve the second matching partial");
    char second_path[PATH_MAX];
    path_under_root(second_path, sizeof(second_path), second.partial_name);
    check(manifest_write_v1(second_path, &manifest) == 0,
          "fixture: write the second matching manifest");
    container_close(&second);

    int root_fd = open(test_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(root_fd >= 0, "fixture: open the destination root for the failing adopt");
    if (root_fd >= 0)
    {
        BackupContainer adopted = {0};
        check(container_adopt_fd(root_fd, &manifest, &adopted) == CONTAINER_ERR_AMBIGUOUS,
              "adopt_fd refuses two matching partials without guessing");
        check(fstat(root_fd, &(struct stat){0}) == 0,
              "adopt_fd leaves the borrowed destination fd open after failure");
        container_close(&adopted);
        close(root_fd);
    }

    fresh_test_root();
}

static void test_adopt_skips_locked_partial(void)
{
    printf(BLUE "::" NC " container: a partial still locked by a live handle is not adopted\n");
    fresh_test_root();

    BackupContainer holder;
    check(container_reserve(test_root, FIXED_TIME, &holder) == CONTAINER_OK, "fixture: reserve");

    Manifest m;
    make_reference_manifest(&m);
    char dir_path[PATH_MAX];
    path_under_root(dir_path, sizeof(dir_path), holder.partial_name);
    check(manifest_write_v1(dir_path, &m) == 0, "fixture: write a matching manifest");
    // holder is deliberately not closed yet: its flock() is still held, as if
    // a live backup process were still running.

    Manifest wanted;
    make_reference_manifest(&wanted);
    BackupContainer adopted;
    check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_NO_MATCH,
          "the only matching partial is locked, so nothing is adopted");

    container_close(&adopted);
    container_close(&holder);
    fresh_test_root();
}

static void test_adopt_ambiguous_on_multiple_matches(void)
{
    printf(BLUE "::" NC " container: two unlocked exact matches make adoption ambiguous\n");
    fresh_test_root();

    Manifest m;
    make_reference_manifest(&m);

    BackupContainer first;
    check(container_reserve(test_root, FIXED_TIME, &first) == CONTAINER_OK, "fixture: reserve first");
    char first_dir[PATH_MAX];
    path_under_root(first_dir, sizeof(first_dir), first.partial_name);
    check(manifest_write_v1(first_dir, &m) == 0, "fixture: write manifest into first");
    container_close(&first);

    BackupContainer second;
    check(container_reserve(test_root, FIXED_TIME, &second) == CONTAINER_OK, "fixture: reserve second");
    check(second.suffix != 0, "fixture: second reservation collided to a distinct suffix");
    char second_dir[PATH_MAX];
    path_under_root(second_dir, sizeof(second_dir), second.partial_name);
    check(manifest_write_v1(second_dir, &m) == 0, "fixture: write the identical manifest into second");
    container_close(&second);

    Manifest wanted;
    make_reference_manifest(&wanted);
    BackupContainer adopted;
    check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_AMBIGUOUS,
          "two unlocked exact matches are refused as ambiguous, not guessed at");
    container_close(&adopted);
    fresh_test_root();
}

typedef struct
{
    void (*mutate)(Manifest *m);
    const char *label;
} MismatchCase;

static void mutate_representation(Manifest *m) { m->representation = CLONE_PORTABLE_SIDECAR; }
static void mutate_scope(Manifest *m) { m->scope = MANIFEST_SCOPE_CRITICAL; }
static void mutate_sidecar_version(Manifest *m) { m->sidecar_version = 7; }
static void mutate_machine_id(Manifest *m) { strcpy(m->machine_id, "00000000000000000000000000000000"); }
static void mutate_source_uid(Manifest *m) { m->source_uid = 2000; }
static void mutate_no_identity(Manifest *m) { m->has_source_identity = 0; }

static const MismatchCase mismatch_cases[] = {
    { mutate_representation,  "a representation mismatch is not adopted" },
    { mutate_scope,           "a scope mismatch is not adopted" },
    { mutate_sidecar_version, "a sidecar_version mismatch is not adopted" },
    { mutate_machine_id,      "a machine_id mismatch is not adopted" },
    { mutate_source_uid,      "a source_uid mismatch is not adopted" },
    { mutate_no_identity,     "a candidate without a source identity is not adopted" },
};

static void test_adopt_rejects_identity_mismatches(void)
{
    printf(BLUE "::" NC " container: adopt rejects every identity-field mismatch\n");

    for (size_t i = 0; i < sizeof(mismatch_cases) / sizeof(mismatch_cases[0]); i++)
    {
        fresh_test_root();

        BackupContainer c;
        check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve a container");

        Manifest variant;
        make_reference_manifest(&variant);
        mismatch_cases[i].mutate(&variant);

        char dir_path[PATH_MAX];
        path_under_root(dir_path, sizeof(dir_path), c.partial_name);
        check(manifest_write_v1(dir_path, &variant) == 0, "fixture: write the variant manifest");
        container_close(&c); // release our own lock so adopt()'s scan can see it as unlocked

        Manifest wanted;
        make_reference_manifest(&wanted);
        BackupContainer adopted;
        check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_NO_MATCH,
              mismatch_cases[i].label);
        container_close(&adopted);
    }

    fresh_test_root();
}

typedef struct
{
    void (*setup)(ManifestRoot *candidate, ManifestRoot *wanted);
    const char *label;
} RootMismatchCase;

static void root_mismatch_setup_source_path(ManifestRoot *c, ManifestRoot *w)
{
    memset(c, 0, sizeof(*c));
    strcpy(c->id, "EXPLICIT_0");
    c->policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(c->payload_path, "EXPLICIT_0");
    strcpy(c->source_path, "/mnt/data/project-a");

    *w = *c;
    strcpy(w->source_path, "/mnt/data/project-b");
}

static void root_mismatch_setup_payload_path(ManifestRoot *c, ManifestRoot *w)
{
    memset(c, 0, sizeof(*c));
    strcpy(c->id, "EXPLICIT_0");
    c->policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(c->payload_path, "EXPLICIT_0");
    strcpy(c->source_path, "/mnt/data/project-a");

    *w = *c;
    strcpy(w->payload_path, "EXPLICIT_0_renamed");
}

// policy necessarily flips has_restore_path along with it (HOME_RELATIVE
// requires a restore_path, every other policy forbids one), so this is the
// only way a has_restore_path difference can occur between two otherwise
// validly-written manifests -- it cannot be isolated as an independent axis.
static void root_mismatch_setup_policy(ManifestRoot *c, ManifestRoot *w)
{
    memset(c, 0, sizeof(*c));
    strcpy(c->id, "EXPLICIT_0");
    c->policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(c->payload_path, "EXPLICIT_0");
    strcpy(c->source_path, "/mnt/data/project-a");

    memset(w, 0, sizeof(*w));
    strcpy(w->id, "EXPLICIT_0");
    w->policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(w->payload_path, "EXPLICIT_0");
    strcpy(w->source_path, "Documents/project-a");
    w->has_restore_path = 1;
    strcpy(w->restore_path, "Documents/project-a");
}

static void root_mismatch_setup_restore_path_value(ManifestRoot *c, ManifestRoot *w)
{
    memset(c, 0, sizeof(*c));
    strcpy(c->id, "EXPLICIT_0");
    c->policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(c->payload_path, "EXPLICIT_0");
    strcpy(c->source_path, "Documents/project-a");
    c->has_restore_path = 1;
    strcpy(c->restore_path, "Documents/project-a");

    *w = *c;
    strcpy(w->restore_path, "Documents/project-a-elsewhere");
}

static const RootMismatchCase root_mismatch_cases[] = {
    { root_mismatch_setup_source_path,        "a source_path-only difference is not adopted" },
    { root_mismatch_setup_payload_path,       "a payload_path-only difference is not adopted" },
    { root_mismatch_setup_policy,             "a policy (and has_restore_path) difference is not adopted" },
    { root_mismatch_setup_restore_path_value, "a restore_path value difference is not adopted" },
};

static void test_adopt_rejects_root_table_mismatch(void)
{
    printf(BLUE "::" NC " container: a differing root table is not adopted"
                " (source_path/payload_path/policy/restore_path)\n");

    for (size_t i = 0; i < sizeof(root_mismatch_cases) / sizeof(root_mismatch_cases[0]); i++)
    {
        fresh_test_root();

        ManifestRoot candidate_root, wanted_root;
        root_mismatch_cases[i].setup(&candidate_root, &wanted_root);

        Manifest candidate;
        make_reference_manifest(&candidate);
        candidate.root_count = 1;
        candidate.roots = &candidate_root;

        BackupContainer c;
        check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve");
        char dir_path[PATH_MAX];
        path_under_root(dir_path, sizeof(dir_path), c.partial_name);
        check(manifest_write_v1(dir_path, &candidate) == 0, "fixture: write the candidate's root table");
        container_close(&c);

        Manifest wanted;
        make_reference_manifest(&wanted);
        wanted.root_count = 1;
        wanted.roots = &wanted_root;

        BackupContainer adopted;
        check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_NO_MATCH,
              root_mismatch_cases[i].label);
        container_close(&adopted);
    }

    fresh_test_root();
}

typedef struct
{
    const char *content; // NULL means "write no manifest.txt at all"
    const char *label;
} RawManifestCase;

static const RawManifestCase raw_manifest_cases[] = {
    { NULL,                              "a partial with no manifest.txt at all is not adopted" },
    { "not a valid manifest\n",           "a partial with a malformed manifest is not adopted" },
    { "XDG_DOCUMENTS_DIR=Documents\n",    "a partial with a legacy manifest is not adopted" },
    { "MIGR_MANIFEST\nVERSION=999\n",     "a partial with an unknown manifest version is not adopted" },
};

static void test_adopt_rejects_non_valid_manifests(void)
{
    printf(BLUE "::" NC " container: missing/legacy/malformed/unknown-version manifests are not adopted\n");

    for (size_t i = 0; i < sizeof(raw_manifest_cases) / sizeof(raw_manifest_cases[0]); i++)
    {
        fresh_test_root();

        BackupContainer c;
        check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve a container");

        if (raw_manifest_cases[i].content != NULL)
        {
            char manifest_path[PATH_MAX];
            snprintf(manifest_path, sizeof(manifest_path), "%s/%s/manifest.txt", test_root, c.partial_name);
            write_raw(manifest_path, raw_manifest_cases[i].content);
        }
        container_close(&c);

        Manifest wanted;
        make_reference_manifest(&wanted);
        BackupContainer adopted;
        check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_NO_MATCH,
              raw_manifest_cases[i].label);
        container_close(&adopted);
    }

    fresh_test_root();
}

static void test_adopt_fails_closed_on_scan_error(void)
{
    printf(BLUE "::" NC " container: an unreadable candidate fails the whole adopt closed, even with a match present\n");
    fresh_test_root();

    Manifest m;
    make_reference_manifest(&m);

    BackupContainer good;
    check(container_reserve(test_root, FIXED_TIME, &good) == CONTAINER_OK,
          "fixture: reserve a genuinely matching container");
    char good_dir[PATH_MAX];
    path_under_root(good_dir, sizeof(good_dir), good.partial_name);
    check(manifest_write_v1(good_dir, &m) == 0, "fixture: write its matching manifest");

    char good_final_copy[CONTAINER_NAME_MAX];
    snprintf(good_final_copy, sizeof(good_final_copy), "%s", good.final_name);
    container_close(&good);

    // A second, distinct-suffix name that matches the naming grammar but is a
    // *file*, not a directory: openat(..., O_DIRECTORY) on it fails ENOTDIR --
    // a real, portable, root-independent operational error during the scan.
    char bogus_name[CONTAINER_NAME_MAX + 16]; // + "-1.partial", generously
    snprintf(bogus_name, sizeof(bogus_name), "%s-1.partial", good_final_copy);
    char bogus_path[PATH_MAX];
    path_under_root(bogus_path, sizeof(bogus_path), bogus_name);
    int fd = creat(bogus_path, 0600);
    check(fd >= 0, "fixture: create a bogus file candidate");
    if (fd >= 0)
        close(fd);

    Manifest wanted;
    make_reference_manifest(&wanted);
    BackupContainer adopted;
    check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_IO,
          "the unreadable bogus candidate fails the scan closed, not just skips itself");
    container_close(&adopted);
    fresh_test_root();
}

static void test_adopt_ignores_names_outside_the_grammar(void)
{
    printf(BLUE "::" NC " container: adopt ignores directory entries outside the exact naming grammar\n");
    fresh_test_root();

    Manifest m;
    make_reference_manifest(&m);

    // Each of these carries a fully matching manifest: if the grammar filter
    // ever accepted one as a candidate, it would be wrongly adopted. Since
    // none of them is recognized as a candidate at all, the whole call must
    // still report NO_MATCH.
    static const char *bogus_bases[] = {
        "migr_backup_20260101_000000-0",            // "-0": never produced (no leading-zero suffix)
        "migr_backup_20260101_000000-00",           // leading zero, longer
        "migr_backup_20260101_000000-01",           // leading zero before a real digit
        "migr_backup_20260101_00000",               // time-of-day one digit short
        "not_migr_backup_20260101_000000",          // wrong prefix
        "migr_backup_20260101_000000-2147483647",   // suffix == INT_MAX: reserve()'s loop
                                                     // condition ("suffix < INT_MAX") means
                                                     // it can never actually produce this
                                                     // value, only up to INT_MAX - 1
    };

    for (size_t i = 0; i < sizeof(bogus_bases) / sizeof(bogus_bases[0]); i++)
    {
        char entry_name[CONTAINER_NAME_MAX];
        snprintf(entry_name, sizeof(entry_name), "%s.partial", bogus_bases[i]);
        char entry_path[PATH_MAX];
        path_under_root(entry_path, sizeof(entry_path), entry_name);
        check(mkdir(entry_path, 0700) == 0, "fixture: create a name outside the grammar");
        check(manifest_write_v1(entry_path, &m) == 0, "fixture: give it a fully matching manifest");
    }

    Manifest wanted;
    make_reference_manifest(&wanted);
    BackupContainer adopted;
    check(container_adopt(test_root, &wanted, &adopted) == CONTAINER_ERR_NO_MATCH,
          "none of the grammar-violating names are recognized as candidates, despite matching manifests");
    container_close(&adopted);
    fresh_test_root();
}

/* ========================================================================= */
/* container_name_is_partial()                                             */
/* ========================================================================= */

static void test_name_is_partial_matches_the_reserve_grammar(void)
{
    printf(BLUE "::" NC " container: public name classifiers match the reserve/finalize grammar\n");

    check(container_name_is_partial(NULL) == 0, "a NULL name is not partial");
    check(container_name_is_final(NULL) == 0, "a NULL name is not final");
    check(container_name_is_partial("") == 0, "an empty name is not partial");
    check(container_name_is_final("") == 0, "an empty name is not final");

    static const char *valid_partials[] = {
        "migr_backup_20260101_000000.partial",
        "migr_backup_20260101_000000-1.partial",
        "migr_backup_20260101_000000-42.partial",
    };
    for (size_t i = 0; i < sizeof(valid_partials) / sizeof(valid_partials[0]); i++)
        check(container_name_is_partial(valid_partials[i]) != 0,
              "a genuine .partial container name is recognized");

    static const char *valid_finals[] = {
        "migr_backup_20260101_000000",
        "migr_backup_20260101_000000-1",
        "migr_backup_20260101_000000-42",
    };
    for (size_t i = 0; i < sizeof(valid_finals) / sizeof(valid_finals[0]); i++)
        check(container_name_is_final(valid_finals[i]) != 0,
              "a genuine finalized container name is recognized");

    static const char *not_partials[] = {
        "migr_backup_20260101_000000",              // finalized: no ".partial" at all
        "migr_backup_20260101_000000-0.partial",    // "-0": never produced (no leading-zero suffix)
        "migr_backup_20260101_00000.partial",       // stamp one digit short
        "not_migr_backup_20260101_000000.partial",  // wrong prefix
        "myfiles.partial",                          // an unrelated directory, not ours
        "migr_backup_20260101_000000.partial/",     // trailing slash: not a bare leaf name
    };
    for (size_t i = 0; i < sizeof(not_partials) / sizeof(not_partials[0]); i++)
        check(container_name_is_partial(not_partials[i]) == 0,
              "a name outside the exact grammar is not treated as partial");

    static const char *not_finals[] = {
        "migr_backup_20260101_000000.partial",
        "migr_backup_20260101_000000-0",
        "migr_backup_20260101_00000",
        "not_migr_backup_20260101_000000",
        "migr_backup_20260101_000000/",
    };
    for (size_t i = 0; i < sizeof(not_finals) / sizeof(not_finals[0]); i++)
        check(container_name_is_final(not_finals[i]) == 0,
              "a name outside the exact grammar is not treated as final");
}

/* ========================================================================= */
/* manifest_read_v1_at() non-regular-object handling                       */
/* ========================================================================= */

static void test_manifest_read_v1_at_rejects_non_regular(void)
{
    printf(BLUE "::" NC " container: manifest_read_v1_at refuses non-regular objects without blocking\n");
    fresh_test_root();

    BackupContainer c;
    check(container_reserve(test_root, FIXED_TIME, &c) == CONTAINER_OK, "fixture: reserve a container");

    char dir_path[PATH_MAX];
    path_under_root(dir_path, sizeof(dir_path), c.partial_name);
    char manifest_path[PATH_MAX + 32]; // + "/manifest.txt", generously
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.txt", dir_path);

    check(mkdir(manifest_path, 0700) == 0, "fixture: create manifest.txt as a directory");
    Manifest m;
    check(manifest_read_v1_at(c.partial_fd, &m) == MANIFEST_STATUS_MALFORMED,
          "manifest.txt as a directory is refused as malformed");
    check(rmdir(manifest_path) == 0, "fixture cleanup: remove the directory");

    check(symlink("/etc/hostname", manifest_path) == 0, "fixture: create manifest.txt as a symlink");
    check(manifest_read_v1_at(c.partial_fd, &m) == MANIFEST_STATUS_MALFORMED,
          "manifest.txt as a symlink is refused as malformed");
    check(unlink(manifest_path) == 0, "fixture cleanup: remove the symlink");

    check(mkfifo(manifest_path, 0600) == 0, "fixture: create manifest.txt as a FIFO");
    alarm(5); // must never hang on a FIFO with no writer; default SIGALRM kills the test if it does
    ManifestStatus fifo_status = manifest_read_v1_at(c.partial_fd, &m);
    alarm(0);
    check(fifo_status == MANIFEST_STATUS_MALFORMED,
          "manifest.txt as a FIFO with no writer is refused as malformed, without blocking");
    check(unlink(manifest_path) == 0, "fixture cleanup: remove the FIFO");

    // manifest.txt as a Unix domain socket: open() always fails ENXIO here,
    // never reaching the fstat()+S_ISREG check -- a genuinely distinct code
    // path from the directory/FIFO cases above, so it needs its own case.
    size_t manifest_path_len = strlen(manifest_path);
    if (manifest_path_len < sizeof(((struct sockaddr_un *)0)->sun_path))
    {
        int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        check(sock_fd >= 0, "fixture: create a Unix domain socket");
        if (sock_fd >= 0)
        {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            // memcpy, not snprintf: sun_path's fixed 108-byte OS size can't
            // be grown the way an ordinary local buffer could, and the
            // length check just above already proves this fits exactly --
            // a format-string copy here only invites the same conservative
            // -Wformat-truncation false positive seen elsewhere in this
            // codebase for a cross-statement bound gcc can't see.
            memcpy(addr.sun_path, manifest_path, manifest_path_len + 1);
            int bind_rc = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
            if (bind_rc == 0)
            {
                check(1, "fixture: bind the socket to manifest.txt's path");
                check(manifest_read_v1_at(c.partial_fd, &m) == MANIFEST_STATUS_MALFORMED,
                      "manifest.txt as a Unix domain socket is refused as malformed");
                check(unlink(manifest_path) == 0,
                      "fixture cleanup: remove the socket");
            }
            else if (errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT)
                printf(BLUE "  (skipped: Unix socket bind unavailable on this host)\n" NC);
            else
                check(0, "fixture: bind the socket to manifest.txt's path");
            close(sock_fd);
        }
    }
    else
    {
        printf(BLUE "  (skipped: sun_path too short for this test root's path)\n" NC);
    }

    container_close(&c);
    fresh_test_root();
}

/* ========================================================================= */
/* manifest_resume_identity_compare()                                       */
/* ========================================================================= */

static void test_resume_identity_compare_ignores_root_order(void)
{
    printf(BLUE "::" NC " manifest: resume identity comparison ignores root order\n");

    ManifestRoot roots_a[2], roots_b[2];
    memset(roots_a, 0, sizeof(roots_a));
    memset(roots_b, 0, sizeof(roots_b));

    strcpy(roots_a[0].id, "EXPLICIT_0");
    roots_a[0].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots_a[0].payload_path, "EXPLICIT_0");
    strcpy(roots_a[0].source_path, "/a");
    strcpy(roots_a[1].id, "EXPLICIT_1");
    roots_a[1].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots_a[1].payload_path, "EXPLICIT_1");
    strcpy(roots_a[1].source_path, "/b");

    roots_b[0] = roots_a[1]; // same two roots, opposite order
    roots_b[1] = roots_a[0];

    Manifest a, b;
    make_reference_manifest(&a);
    a.root_count = 2;
    a.roots = roots_a;
    make_reference_manifest(&b);
    b.root_count = 2;
    b.roots = roots_b;

    check(manifest_resume_identity_compare(&a, &b) == MANIFEST_IDENTITY_EQUAL,
          "identical root sets compare equal regardless of on-disk/in-memory order");

    strcpy(b.roots[0].source_path, "/different");
    check(manifest_resume_identity_compare(&a, &b) == MANIFEST_IDENTITY_DIFFERENT,
          "a genuinely different root set compares unequal");

    check(manifest_resume_identity_compare(NULL, &a) == MANIFEST_IDENTITY_DIFFERENT,
          "NULL a is handled without crashing");
    check(manifest_resume_identity_compare(&a, NULL) == MANIFEST_IDENTITY_DIFFERENT,
          "NULL b is handled without crashing");
}

int main(void)
{
    printf(BLUE "::" NC " container (unit)\n");

    force_utc_timezone();

    if (mkdtemp(test_root) == NULL)
    {
        printf(RED "could not create a test root" NC "\n");
        return 1;
    }

    test_reserve_generates_expected_stamp();
    test_reserve_partial_collision_advances_suffix();
    test_reserve_fd_is_anchored();
    test_reserve_final_collision_advances_suffix();
    test_concurrent_reserve_claims_distinct_partials();
    test_reserve_flock_race_advances_suffix();

    test_finalize_success();
    test_finalize_sync_failure_leaves_partial();
    test_finalize_refuses_existing_final();
    test_finalize_rejects_invalid_handle();

    test_close_does_not_delete();
    test_close_on_zeroed_is_safe();

    test_null_arguments_are_rejected_safely();

    test_adopt_rejects_wanted_without_identity();
    test_adopt_matches_and_retains_inode();
    test_adopt_fd_is_anchored();
    test_adopt_fd_failure_keeps_borrowed_fd();
    test_adopt_skips_locked_partial();
    test_adopt_ambiguous_on_multiple_matches();
    test_adopt_rejects_identity_mismatches();
    test_adopt_rejects_root_table_mismatch();
    test_adopt_rejects_non_valid_manifests();
    test_adopt_fails_closed_on_scan_error();
    test_adopt_ignores_names_outside_the_grammar();
    test_name_is_partial_matches_the_reserve_grammar();

    test_manifest_read_v1_at_rejects_non_regular();
    test_resume_identity_compare_ignores_root_order();

    clean_test_root();

    if (failures > 0)
    {
        printf(RED "%d container test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
