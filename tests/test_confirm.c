#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"

static int failures = 0;

static void progress_ticker_noop_redraw(
    const ProgressTickerSnapshot *snapshot,
    const struct timespec *now,
    void *context)
{
    (void)snapshot;
    (void)now;
    (void)context;
}

static void check(int condition, const char *label)
{
    if (condition)
        printf("  ok: %s\n", label);
    else
    {
        printf("  FAIL: %s\n", label);
        failures++;
    }
}

static int run_confirm(const char *input, int default_yes,
                       char *output, size_t output_size)
{
    int input_pipe[2];
    int output_pipe[2];
    if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0)
    {
        perror("pipe");
        exit(1);
    }

    if (input != NULL)
    {
        size_t length = strlen(input);
        if (write(input_pipe[1], input, length) != (ssize_t)length)
        {
            perror("write");
            exit(1);
        }
    }
    close(input_pipe[1]);

    fflush(stdout);
    int saved_stdin = dup(STDIN_FILENO);
    int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdin < 0 || saved_stdout < 0 ||
        dup2(input_pipe[0], STDIN_FILENO) < 0 ||
        dup2(output_pipe[1], STDOUT_FILENO) < 0)
    {
        perror("dup2");
        exit(1);
    }
    close(input_pipe[0]);
    close(output_pipe[1]);
    clearerr(stdin);

    int result = default_yes
        ? confirm_action_default_yes("Continue?")
        : confirm_action("Continue?");
    fflush(stdout);

    if (dup2(saved_stdin, STDIN_FILENO) < 0 ||
        dup2(saved_stdout, STDOUT_FILENO) < 0)
    {
        perror("dup2 restore");
        exit(1);
    }
    close(saved_stdin);
    close(saved_stdout);
    clearerr(stdin);

    size_t total = 0;
    ssize_t n;
    while (total + 1 < output_size &&
           (n = read(output_pipe[0], output + total,
                     output_size - 1 - total)) > 0)
        total += (size_t)n;
    output[total] = '\0';
    close(output_pipe[0]);
    return result;
}

#ifdef USER_CONTEXT_TEST_HOOKS
static void write_fixture(const char *path, const char *contents)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
    {
        perror("open passwd fixture");
        exit(1);
    }
    size_t length = strlen(contents);
    if (write(fd, contents, length) != (ssize_t)length)
    {
        perror("write passwd fixture");
        close(fd);
        exit(1);
    }
    if (close(fd) != 0)
    {
        perror("close passwd fixture");
        exit(1);
    }
}

static int run_target_home(const char *home_env, const char *sudo_uid_env,
                           const char *passwd_path, int running_as_root,
                           char home[PATH_MAX],
                           char *diagnostic, size_t diagnostic_size)
{
    int output_pipe[2];
    if (pipe(output_pipe) != 0)
    {
        perror("pipe");
        exit(1);
    }

    fflush(stderr);
    int saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0 ||
        dup2(output_pipe[1], STDERR_FILENO) < 0)
    {
        perror("dup2 stderr");
        exit(1);
    }
    close(output_pipe[1]);

    int result = resolve_target_home_for_test(home_env, sudo_uid_env,
                                              passwd_path, running_as_root,
                                              home);
    fflush(stderr);

    if (dup2(saved_stderr, STDERR_FILENO) < 0)
    {
        perror("dup2 stderr restore");
        exit(1);
    }
    close(saved_stderr);

    size_t total = 0;
    ssize_t n;
    while (total + 1 < diagnostic_size &&
           (n = read(output_pipe[0], diagnostic + total,
                     diagnostic_size - 1 - total)) > 0)
        total += (size_t)n;
    diagnostic[total] = '\0';
    close(output_pipe[0]);
    return result;
}

static void test_sudo_identity_resolution(const char *passwd_path)
{
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    char home[PATH_MAX];

    write_fixture(passwd_path,
                  "user:x:001000:02000::/home/invoker:/bin/sh\n");
    check(resolve_sudo_identity_for_test("01000", passwd_path,
                                         &uid, &gid, home) == 0 &&
              uid == (uid_t)1000 && gid == (gid_t)2000 &&
              strcmp(home, "/home/invoker") == 0,
          "SUDO_UID resolves the matching local uid, primary gid, and home");

    write_fixture(passwd_path,
                  "user:x:1000:not-a-gid::/home/invoker:/bin/sh\n");
    check(resolve_sudo_identity_for_test("1000", passwd_path,
                                         &uid, &gid, home) != 0,
          "matching passwd record with malformed gid is rejected");

    write_fixture(passwd_path,
                  "first:x:1000:1000::/home/first:/bin/sh\n"
                  "second:x:1000:1000::/home/second:/bin/sh\n");
    check(resolve_sudo_identity_for_test("1000", passwd_path,
                                         &uid, &gid, home) != 0,
          "duplicate local passwd uid is rejected for identity resolution");

    write_fixture(passwd_path, "user:x:1000\n");
    check(resolve_sudo_identity_for_test("1000", passwd_path,
                                         &uid, &gid, home) != 0,
          "matching malformed passwd record is rejected for identity resolution");

    write_fixture(passwd_path,
                  "user:x:1000:1000::relative/home:/bin/sh\n");
    check(resolve_sudo_identity_for_test("1000", passwd_path,
                                         &uid, &gid, home) != 0,
          "invalid local home rejects sudo identity resolution");

    write_fixture(passwd_path,
                  "other:x:2000:2000::/home/other:/bin/sh\n");
    check(resolve_sudo_identity_for_test("1000", passwd_path,
                                         &uid, &gid, home) != 0,
          "missing local passwd uid is rejected for identity resolution");
}

static void test_local_account_name(const char *passwd_path)
{
    char name[ACCOUNT_NAME_MAX];

    write_fixture(passwd_path,
                  "root:x:0:0::/root:/bin/sh\n"
                  "eyildizemre:x:1000:1000::/home/eyildizemre:/bin/sh\n");
    check(local_account_name_for_test(1000, passwd_path, name) == 0 &&
              strcmp(name, "eyildizemre") == 0,
          "a uid resolves to its local login name");

    check(local_account_name_for_test(2000, passwd_path, name) != 0,
          "a uid with no local entry has no name");

    write_fixture(passwd_path,
                  "eyildizemre:x:1000:1000::/home/eyildizemre:/bin/sh\n"
                  "twin:x:1000:1000::/home/twin:/bin/sh\n");
    check(local_account_name_for_test(1000, passwd_path, name) != 0,
          "a uid shared by two local entries has no name");

    write_fixture(passwd_path, ":x:1000:1000::/home/eyildizemre:/bin/sh\n");
    check(local_account_name_for_test(1000, passwd_path, name) != 0,
          "an entry with an empty name has no name");
}

static void test_target_home_resolution(void)
{
    char passwd_path[] = "/tmp/migr-passwd-XXXXXX";
    int passwd_fd = mkstemp(passwd_path);
    if (passwd_fd < 0)
    {
        perror("mkstemp passwd fixture");
        exit(1);
    }
    close(passwd_fd);

    test_sudo_identity_resolution(passwd_path);
    test_local_account_name(passwd_path);

    char home[PATH_MAX];
    char diagnostic[512];

    check(run_target_home("/home/ordinary", NULL, passwd_path, 0, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/ordinary") == 0,
          "ordinary invocation returns HOME unchanged");

    check(run_target_home(NULL, NULL, passwd_path, 0, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "HOME is not set or is empty") != NULL,
          "ordinary invocation rejects a missing HOME");
    check(run_target_home("", NULL, passwd_path, 0, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "HOME is not set or is empty") != NULL,
          "ordinary invocation rejects an empty HOME");

    char oversized_home[PATH_MAX + 1];
    memset(oversized_home, 'h', PATH_MAX);
    oversized_home[PATH_MAX] = '\0';
    check(run_target_home(oversized_home, NULL, passwd_path, 0, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "HOME path too long") != NULL,
          "ordinary invocation rejects HOME that cannot fit PATH_MAX");

    write_fixture(passwd_path,
                  "user:x:1000:1000::/home/invoker:/bin/sh\n");
    check(run_target_home("/home/explicit", "1000", passwd_path, 0, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/explicit") == 0,
          "non-root invocation ignores inherited SUDO_UID and keeps HOME");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/invoker") == 0,
          "SUDO_UID ignores elevated HOME and selects the invoking user's home");
    check(run_target_home(NULL, "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/invoker") == 0,
          "SUDO_UID resolution does not require ambient HOME");

    write_fixture(passwd_path,
                  "user:x:001000:1000::/home/leading-zero:/bin/sh\n");
    check(run_target_home("/root", "01000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/leading-zero") == 0,
          "SUDO_UID and passwd UID use the same decimal parser");

    const char *invalid_uids[] = {
        "", "+1000", "-1", " 1000", "1000 ", "1000x", "not-a-uid",
        "184467440737095516160", NULL
    };
    for (size_t i = 0; invalid_uids[i] != NULL; i++)
    {
        char label[128];
        snprintf(label, sizeof(label),
                 "malformed SUDO_UID case %zu fails without HOME fallback", i + 1);
        check(run_target_home("/root", invalid_uids[i], passwd_path, 1, home,
                              diagnostic, sizeof(diagnostic)) < 0 &&
                  home[0] == '\0' &&
                  strstr(diagnostic, "SUDO_UID is invalid") != NULL,
              label);
    }

    char rejected_uid[64];
    snprintf(rejected_uid, sizeof(rejected_uid), "%ju",
             (uintmax_t)(uid_t)-1);
    check(run_target_home("/root", rejected_uid, passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "SUDO_UID is invalid") != NULL,
          "the reserved uid_t -1 value is rejected");

    write_fixture(passwd_path,
                  "other:x:2000:2000::/home/other:/bin/sh\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "does not match a local") != NULL,
          "missing local passwd UID fails closed");

    write_fixture(passwd_path,
                  "first:x:1000:1000::/home/first:/bin/sh\n"
                  "second:x:1000:1000::/home/second:/bin/sh\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "multiple local") != NULL,
          "duplicate local passwd UID is rejected as ambiguous");

    write_fixture(passwd_path, "user:x:1000\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "malformed") != NULL,
          "matching malformed passwd record fails closed");

    write_fixture(passwd_path,
                  "user:x:1000:1000:::/bin/sh\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "invalid home") != NULL,
          "matching passwd record with empty home is rejected");

    write_fixture(passwd_path,
                  "user:x:1000:1000::home/relative:/bin/sh\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "invalid home") != NULL,
          "matching passwd record with relative home is rejected");

    char *long_home = malloc(PATH_MAX + 1U);
    if (long_home == NULL)
    {
        perror("malloc long home");
        exit(1);
    }
    long_home[0] = '/';
    memset(long_home + 1, 'a', PATH_MAX - 1U);
    long_home[PATH_MAX] = '\0';
    size_t record_size = strlen(long_home) + 64U;
    char *record = malloc(record_size);
    if (record == NULL)
    {
        perror("malloc passwd record");
        exit(1);
    }
    snprintf(record, record_size, "user:x:1000:1000::%s:/bin/sh\n",
             long_home);
    write_fixture(passwd_path, record);
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "invalid home") != NULL,
          "matching passwd record with PATH_MAX-overflowing home is rejected");
    free(record);
    free(long_home);

    write_fixture(passwd_path,
                  "user:x:1000:1000::/home/Target User:/bin/sh\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/Target User") == 0,
          "valid passwd home containing spaces is preserved exactly");

    write_fixture(passwd_path,
                  "not even a passwd record\n"
                  "other:x:not-numeric:2000::/home/other:/bin/sh\n"
                  "user:x:1000:1000::/home/invoker:/bin/sh\n");
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) == 0 &&
              strcmp(home, "/home/invoker") == 0,
          "unrelated malformed passwd records do not manufacture a match");

    unlink(passwd_path);
    check(run_target_home("/root", "1000", passwd_path, 1, home,
                          diagnostic, sizeof(diagnostic)) < 0 &&
              strstr(diagnostic, "Could not read local passwd database") != NULL,
          "missing passwd database fails closed");
}
#endif

static void test_progress_ticker_stop_ignores_resolved_thread_error(void)
{
    ProgressTicker ticker;
    const struct timespec snapshot_at = {0};

    int rc = progress_ticker_start(&ticker, progress_ticker_noop_redraw, NULL);
    check(rc == 0, "progress ticker starts for stop regression");
    if (rc != 0)
        return;

    check(ticker.initialized && ticker.running,
          "progress ticker reports a live worker after start");
    check(progress_ticker_snapshot(&ticker, 1, 1, 0, 0,
                                   "fixture", &snapshot_at) == 0,
          "progress ticker accepts a synchronized snapshot");

    rc = pthread_mutex_lock(&ticker.lock);
    check(rc == 0, "progress ticker state can be locked for fault injection");
    if (rc == 0)
    {
        ticker.thread_error = EIO;
        rc = pthread_mutex_unlock(&ticker.lock);
        check(rc == 0,
              "progress ticker state unlocks after fault injection");
    }

    rc = progress_ticker_stop(&ticker);
    check(rc == 0,
          "resolved ticker thread error does not fail stop after join");
    if (rc == 0)
    {
        ProgressTicker cleared = {0};
        check(memcmp(&ticker, &cleared, sizeof(ticker)) == 0,
              "successful ticker stop clears ticker state");
    }
}

static void fill_progress_line(char *line, size_t capacity, size_t length)
{
    if (length >= capacity)
    {
        fprintf(stderr, "progress-line fixture exceeds its buffer\n");
        exit(1);
    }
    memset(line, 'x', length);
    line[length] = '\0';
}

static void test_progress_line_fit_fallback(void)
{
    char short_line[96];
    char boundary_line[96];
    char over_line[96];
    fill_progress_line(short_line, sizeof(short_line), 24U);
    fill_progress_line(boundary_line, sizeof(boundary_line), 79U);
    fill_progress_line(over_line, sizeof(over_line), 80U);

    int pipefd[2];
    int saved_stdout = dup(STDOUT_FILENO);
    if (pipe(pipefd) != 0 || saved_stdout < 0 ||
        dup2(pipefd[1], STDOUT_FILENO) < 0)
    {
        perror("progress-line stdout fixture");
        exit(1);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    progress_line_fit(short_line, sizeof(short_line));
    progress_line_fit(boundary_line, sizeof(boundary_line));
    progress_line_fit(over_line, sizeof(over_line));

    if (dup2(saved_stdout, STDOUT_FILENO) < 0 || close(saved_stdout) != 0)
    {
        perror("progress-line stdout restore");
        exit(1);
    }

    check(strlen(short_line) == 24U,
          "progress line below the fallback width is unchanged");
    check(strlen(boundary_line) == 79U,
          "progress line at columns minus one is unchanged");
    check(strlen(over_line) == 79U,
          "progress line beyond the fallback width is clamped to columns minus one");
}

static int read_small(const char *path, char *out, size_t size)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    size_t length = fread(out, 1, size - 1U, f);
    out[length] = '\0';
    fclose(f);
    return 0;
}

// Runs one logged "run" into base/<dir>, printing what a real one does:
// colors, a progress line redrawn with '\r', and a line for the log only.
// restored, when set, gets its times set midway, as a restore sets those of
// the folders it restores. The terminal side goes to /dev/null. Returns the
// kept path, or NULL.
static const char *logged_run(int base_fd, const char *dir, int keep,
                              const char *restored)
{
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    int null_fd = open("/dev/null", O_WRONLY);
    dup2(null_fd, STDOUT_FILENO);
    close(null_fd);
    char *argv[] = { "migr", "restore", "/backup", NULL };
    const char *kept = NULL;
    fflush(stderr);
    int saved_err = dup(STDERR_FILENO);
    dup2(STDOUT_FILENO, STDERR_FILENO);
    if (run_log_start(3, argv) == 0)
    {
        printf("before attach\n");
        run_log_attach(base_fd, dir, "restore", (uid_t)-1, (gid_t)-1);
        printf("\033[1;31mError: red\033[0m\n");
        printf("\rCopying 10%%");
        fflush(stdout);
        printf("\rCopying 100%%\n");
        run_log_printf("Listed only here: a/b\n");
        struct timespec times[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
        if (restored != NULL)
            utimensat(AT_FDCWD, restored, times, 0);
        fprintf(stderr, "unterminated");
        kept = run_log_finish(keep);
    }
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    dup2(saved_err, STDERR_FILENO);
    close(saved_err);
    return kept;
}

static void test_run_log(void)
{
    char base[] = "/tmp/migr-run-log-XXXXXX";
    if (mkdtemp(base) == NULL)
    {
        check(0, "run log fixture is created");
        return;
    }
    char state[PATH_MAX];
    snprintf(state, sizeof(state), "%s/.local", base);
    int base_fd = open(base, O_RDONLY | O_DIRECTORY);

    const char *kept = logged_run(base_fd, ".local/state/migr", 1, NULL);
    char text[1024] = "";
    check(kept != NULL && read_small(kept, text, sizeof(text)) == 0 &&
              strncmp(text, "migr run started ", 17) == 0 &&
              strstr(text, ": migr restore /backup\n\nbefore attach\n"
                           "Error: red\nCopying 100%\nListed only here: "
                           "a/b\nunterminated\n") != NULL,
          "a kept log holds the run as printed, without colors, with a "
          "redrawn line as last drawn, and the log-only lines");
    struct stat st;
    check(kept != NULL && stat(kept, &st) == 0 && (st.st_mode & 0777) == 0600,
          "a log is readable by its owner only");

    // A clean run on a system whose .local/state is there, and gets its
    // times from the restore, leaves it exactly so.
    char aside[] = "/tmp/migr-run-log-aside-XXXXXX";
    char local_state[PATH_MAX];
    snprintf(local_state, sizeof(local_state), "%s/.local/state", base);
    int moved = mkdtemp(aside) != NULL && rmdir(aside) == 0 &&
                rename(state, aside) == 0 && mkdir(state, 0700) == 0 &&
                mkdir(local_state, 0700) == 0;
    kept = logged_run(base_fd, ".local/state/migr", 0, local_state);
    char migr_dir[PATH_MAX + 8];
    snprintf(migr_dir, sizeof(migr_dir), "%s/migr", local_state);
    struct stat state_st;
    check(moved && kept == NULL && access(migr_dir, F_OK) != 0 &&
              stat(local_state, &state_st) == 0 &&
              state_st.st_mtim.tv_sec == 1000000000,
          "a log that is not kept goes away with the folder made for it, and "
          "the folder holding it keeps the times the run gave it");

    // With nothing there, the folders made for the log go too.
    moved = rmdir(local_state) == 0 && rmdir(state) == 0;
    kept = logged_run(base_fd, ".local/state/migr", 0, NULL);
    check(moved && kept == NULL && access(state, F_OK) != 0,
          "every folder made only for a log that is not kept goes away");
    rename(aside, state);

    for (int i = 0; i < 12; i++)
    {
        char old_log[PATH_MAX + 64];
        snprintf(old_log, sizeof(old_log), "%s/restore-2000-01-%02d-000000.log",
                 migr_dir, i + 1);
        FILE *f = fopen(old_log, "w");
        if (f != NULL)
            fclose(f);
    }
    kept = logged_run(base_fd, ".local/state/migr", 1, NULL);
    char oldest_kept[PATH_MAX + 64], dropped[PATH_MAX + 64];
    // With the two logs of this test's runs, the newest ten reach back to
    // the fifth.
    snprintf(oldest_kept, sizeof(oldest_kept),
             "%s/restore-2000-01-05-000000.log", migr_dir);
    snprintf(dropped, sizeof(dropped), "%s/restore-2000-01-04-000000.log",
             migr_dir);
    check(kept != NULL && access(oldest_kept, F_OK) == 0 &&
              access(dropped, F_OK) != 0,
          "the newest ten logs are kept");

    close(base_fd);
    char command[PATH_MAX + 16];
    snprintf(command, sizeof(command), "rm -rf %s", base);
    if (system(command) != 0)
        check(0, "run log fixture is removed");
}

int main(void)
{
    char output[256];

    test_run_log();

#ifdef USER_CONTEXT_TEST_HOOKS
    test_target_home_resolution();
#endif
    test_progress_ticker_stop_ignores_resolved_thread_error();
    test_progress_line_fit_fallback();

    check(run_confirm("\n", 1, output, sizeof(output)) == 1,
          "bare Enter accepts the default-yes prompt");
    check(strstr(output, "[Y/n]") != NULL,
          "default-yes prompt displays [Y/n]");

    check(run_confirm("\n", 0, output, sizeof(output)) == 0,
          "bare Enter declines the existing default-no prompt");
    check(strstr(output, "[y/N]") != NULL,
          "default-no prompt still displays [y/N]");

    check(run_confirm("n\n", 1, output, sizeof(output)) == 0,
          "explicit n overrides default yes");
    check(run_confirm("y\n", 0, output, sizeof(output)) == 1,
          "explicit y overrides default no");

    check(run_confirm(" \t\n", 1, output, sizeof(output)) == 1,
          "whitespace-only input accepts default yes");
    check(run_confirm(" \t\n", 0, output, sizeof(output)) == 0,
          "whitespace-only input keeps default no");

    check(run_confirm(NULL, 1, output, sizeof(output)) == 0,
          "true EOF declines even when yes is displayed as the default");
    check(run_confirm(NULL, 0, output, sizeof(output)) == 0,
          "true EOF declines the default-no prompt");

    if (failures != 0)
    {
        printf("%d utility helper test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
