#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>

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

int main(void)
{
    printf(BLUE "::" NC " run_command (unit)\n");

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

    printf("run_command tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
