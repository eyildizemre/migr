#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(void)
{
    char output[256];

    test_progress_ticker_stop_ignores_resolved_thread_error();

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
