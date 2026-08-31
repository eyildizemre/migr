#define _GNU_SOURCE

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

    check(run_command_capture(echo_argv, NULL, sizeof(output)) == -1,
          "a NULL output buffer is rejected before anything is spawned");
    check(run_command_capture(echo_argv, output, 0) == -1,
          "a zero-size output buffer is rejected before anything is spawned");

    printf("run_command tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
