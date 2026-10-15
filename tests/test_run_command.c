#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "fileops.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

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

// run_command_capture()'s own capture loop is the only read() this binary
// calls once armed, so a one-shot fire-on-the-next-call trigger (no fd or
// path match needed) is enough to simulate a signal landing mid-capture.
static int eintr_enabled;
static int eintr_triggered;

extern ssize_t __real_read(int fd, void *buf, size_t count);

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if (eintr_enabled && !eintr_triggered && count > 0)
    {
        eintr_triggered = 1;
        errno = EINTR;
        return -1;
    }
    return __real_read(fd, buf, count);
}

// Runs argv with fds 1 and 2 pointing at one temporary file and a fully
// buffered stdout holding "before\n", then returns what the file got.
static void run_into_file(char *const argv[], int capture, char *out,
                          size_t out_size)
{
    out[0] = '\0';
    char path[] = "/tmp/migr_run_command_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return;
    fflush(stdout);
    fflush(stderr);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    setvbuf(stdout, NULL, _IOFBF, BUFSIZ);
    printf("before\n");
    char captured[64];
    if (capture)
        (void)run_command_capture(argv, captured, sizeof(captured));
    else
        (void)run_command(argv);
    fflush(stdout);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
    ssize_t length = pread(fd, out, out_size - 1U, 0);
    out[length > 0 ? length : 0] = '\0';
    close(fd);
    unlink(path);
}

int main(void)
{
    printf(BLUE "::" NC " run_command (unit)\n");

    char text[256];
    char *const missing_quiet[] = { "migr-test-nonexistent-binary-xyz", NULL };
    run_into_file(missing_quiet, 0, text, sizeof(text));
    check(strcmp(text, "before\n") == 0,
          "a command that cannot be run prints nothing of its own");
    run_into_file(missing_quiet, 1, text, sizeof(text));
    check(strcmp(text, "before\n") == 0,
          "a captured command that cannot be run prints nothing of its own");
    char *const after_argv[] = { "sh", "-c", "echo after", NULL };
    run_into_file(after_argv, 0, text, sizeof(text));
    check(strcmp(text, "before\nafter\n") == 0,
          "what migr printed comes before the command's output");
    char *const after_err_argv[] = { "sh", "-c", "echo after >&2", NULL };
    run_into_file(after_err_argv, 1, text, sizeof(text));
    check(strcmp(text, "before\nafter\n") == 0,
          "what migr printed comes before a captured command's stderr");

    char *const true_argv[] = { "true", NULL };
    check(run_command(true_argv) == 0, "a successful command exits 0");

    char *const false_argv[] = { "false", NULL };
    check(run_command(false_argv) == 1, "a failing command's exit code is propagated");

    char *const missing_argv[] = { "migr-test-nonexistent-binary-xyz", NULL };
    check(run_command(missing_argv) == 1,
          "a nonexistent binary's failed exec is reported as the child's exit(1)");

    printf(BLUE "::" NC " run_command_capture (unit)\n");

    char output[256];
    char *const echo_argv[] = { "echo", "hello", "world", NULL };
    int rc = run_command_capture(echo_argv, output, sizeof(output));
    check(rc == 0 && strcmp(output, "hello world\n") == 0,
          "captured stdout matches the command's real output");

    char *const false_argv2[] = { "false", NULL };
    output[0] = '\1';
    rc = run_command_capture(false_argv2, output, sizeof(output));
    check(rc == 1 && output[0] == '\0',
          "a failing command with no output still null-terminates and reports its exit code");

    char small[8];
    char *const long_argv[] = { "echo", "0123456789abcdef", NULL };
    rc = run_command_capture(long_argv, small, sizeof(small));
    check(rc == 0 && strlen(small) == sizeof(small) - 1 &&
              small[sizeof(small) - 1] == '\0',
          "captured output is truncated safely while preserving the child's exit code");

    // "0123456789abcdef" (17 bytes) fits in a single write() well under the
    // pipe's own kernel buffer (~64 KB), so it can't reproduce a child that's
    // still writing when the capture buffer fills. seq's multi-megabyte
    // output forces the child to block on write() past that point, which is
    // what actually exercises the SIGPIPE race this test guards against.
    char truncated[4096];
    char *const seq_argv[] = { "seq", "1", "500000", NULL };
    rc = run_command_capture(seq_argv, truncated, sizeof(truncated));
    check(rc == 0 && strlen(truncated) == sizeof(truncated) - 1 &&
              truncated[sizeof(truncated) - 1] == '\0',
          "output far exceeding both the capture buffer and the pipe buffer "
          "still reports the child's real exit code, not a SIGPIPE-death -1");

    // A read() interrupted by EINTR must be retried, not treated as EOF --
    // otherwise a signal arriving mid-capture (SIGCHLD from an unrelated
    // fork, a progress handler, etc.) silently truncates the captured output
    // with no error signaled. seq 1 3000's output (13893 bytes) is well
    // under the 16384-byte capture buffer here, so without the fix -- the
    // wrapper fires the EINTR on the very first read(), before any real data
    // has arrived -- capture would stop with an empty buffer instead of the
    // full output; this is a stronger discriminator than the earlier
    // buffer-overflowing fixtures above, which would truncate to the same
    // final size whether or not EINTR is retried.
    char eintr_output[16384];
    char *const seq_small_argv[] = { "seq", "1", "3000", NULL };
    eintr_triggered = 0;
    eintr_enabled = 1;
    rc = run_command_capture(seq_small_argv, eintr_output, sizeof(eintr_output));
    eintr_enabled = 0;
    check(eintr_triggered && rc == 0 && strlen(eintr_output) == 13893 &&
              strncmp(eintr_output, "1\n2\n3\n4\n5\n", 10) == 0 &&
              strcmp(eintr_output + 13893 - 10, "2999\n3000\n") == 0,
          "a read() interrupted mid-capture by EINTR is retried, not treated as EOF");

    check(run_command_capture(echo_argv, NULL, sizeof(output)) == -1,
          "a NULL output buffer is rejected before anything is spawned");
    check(run_command_capture(echo_argv, output, 0) == -1,
          "a zero-size output buffer is rejected before anything is spawned");

    printf(BLUE "::" NC " run_command_errors (unit)\n");

    char errors[64];
    char *const mixed_argv[] = {
        "sh", "-c", "echo progress; echo broken >&2; exit 3", NULL
    };
    rc = run_command_errors(mixed_argv, errors, sizeof(errors));
    check(rc == 3 && strcmp(errors, "broken\n") == 0,
          "only the command's errors are kept, with its exit code");
    char tail[16];
    char *const many_errors_argv[] = { "sh", "-c", "seq 1 3000 >&2", NULL };
    rc = run_command_errors(many_errors_argv, tail, sizeof(tail));
    check(rc == 0 && strlen(tail) == sizeof(tail) - 1U &&
              strcmp(tail + strlen(tail) - 10, "2999\n3000\n") == 0,
          "errors longer than the buffer keep their end");
    check(run_command_errors(true_argv, NULL, sizeof(errors)) == -1 &&
              run_command_errors(true_argv, errors, 0) == -1,
          "a missing errors buffer is rejected before anything is spawned");

    printf(BLUE "::" NC " run_command_capture_with (unit)\n");

    setenv("MIGR_TEST_INHERITED", "base", 1);
    setenv("MIGR_TEST_REPLACED", "old", 1);
    const char *const overrides[] = {
        "MIGR_TEST_REPLACED=new", "MIGR_TEST_ADDED=1", NULL
    };
    RunCommandOptions env_options = { .env = overrides };
    char *const env_argv[] = {
        "sh", "-c",
        "printf '%s|%s|%s|' \"$MIGR_TEST_INHERITED\" \"$MIGR_TEST_REPLACED\" "
        "\"$MIGR_TEST_ADDED\"",
        NULL
    };
    rc = run_command_capture_with(env_argv, output, sizeof(output),
                                  &env_options);
    check(rc == 0 && strncmp(output, "base|new|1|", 11) == 0,
          "env entries are added and replace inherited ones");
    // The shell would collapse duplicate names, so inspect the raw
    // environment the child was given.
    char raw_env[65536];
    char *const raw_env_argv[] = { "env", NULL };
    rc = run_command_capture_with(raw_env_argv, raw_env, sizeof(raw_env),
                                  &env_options);
    size_t replaced_count = 0;
    for (const char *line = raw_env; line != NULL && *line != '\0';)
    {
        if (strncmp(line, "MIGR_TEST_REPLACED=", 19) == 0)
            replaced_count++;
        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }
    check(rc == 0 && replaced_count == 1 &&
              strstr(raw_env, "MIGR_TEST_REPLACED=new\n") != NULL,
          "a replaced name appears exactly once in the child's environment");

    const char *const malformed[] = { "NOEQUALS", NULL };
    RunCommandOptions malformed_options = { .env = malformed };
    check(run_command_capture_with(echo_argv, output, sizeof(output),
                                   &malformed_options) == -1,
          "a malformed env entry is rejected before anything is spawned");
    RunCommandOptions homeless_drop = {
        .drop_identity = 1, .uid = getuid(), .gid = getgid()
    };
    check(run_command_capture_with(echo_argv, output, sizeof(output),
                                   &homeless_drop) == -1,
          "an identity drop without a home is rejected before spawning");

    char *const cat_argv[] = { "cat", NULL };
    RunCommandOptions stdin_options = {
        .stdin_data = "hello\n", .stdin_length = strlen("hello\n")
    };
    rc = run_command_capture_with(cat_argv, output, sizeof(output),
                                  &stdin_options);
    check(rc == 0 && strcmp(output, "hello\n") == 0,
          "stdin data reaches the child");

    RunCommandOptions empty_stdin = { .stdin_data = "", .stdin_length = 0 };
    output[0] = '\1';
    rc = run_command_capture_with(cat_argv, output, sizeof(output),
                                  &empty_stdin);
    check(rc == 0 && output[0] == '\0',
          "empty stdin data gives the child an immediate EOF");

    // Far larger than both pipe buffers: cat echoes while migr is still
    // writing, so a write-all-then-read implementation would deadlock.
    size_t big_length = 2U * 1024U * 1024U;
    char *big = malloc(big_length);
    if (big == NULL)
    {
        printf("could not allocate the large stdin fixture\n");
        return 1;
    }
    memset(big, 'x', big_length);
    RunCommandOptions big_options = {
        .stdin_data = big, .stdin_length = big_length
    };
    char tiny[16];
    rc = run_command_capture_with(cat_argv, tiny, sizeof(tiny), &big_options);
    check(rc == 0 && strlen(tiny) == sizeof(tiny) - 1U,
          "large stdin is fed while stdout is drained, without deadlock");

    char *const ignore_argv[] = { "true", NULL };
    rc = run_command_capture_with(ignore_argv, output, sizeof(output),
                                  &big_options);
    sigset_t mask, pending;
    sigemptyset(&mask);
    sigemptyset(&pending);
    int mask_ok = sigprocmask(SIG_BLOCK, NULL, &mask) == 0 &&
                  sigpending(&pending) == 0;
    check(rc == 0 && mask_ok && !sigismember(&mask, SIGPIPE) &&
              !sigismember(&pending, SIGPIPE),
          "a child that ignores its stdin cannot kill migr with SIGPIPE, "
          "and the signal mask is restored");
    free(big);

    printf("run_command tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
