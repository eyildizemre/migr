#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "report.h"
#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;
static struct stat target_directory;
static int target_directory_valid;
static unsigned int target_readdir_calls;
static int readdir_failure_injected;

struct dirent *__real_readdir(DIR *directory);

struct dirent *__wrap_readdir(DIR *directory)
{
    struct stat current_directory;
    int directory_fd = dirfd(directory);

    if (target_directory_valid && directory_fd >= 0 &&
        fstat(directory_fd, &current_directory) == 0 &&
        current_directory.st_dev == target_directory.st_dev &&
        current_directory.st_ino == target_directory.st_ino)
    {
        /* Let . .. and one real child pass, then fail during the walk. */
        if (target_readdir_calls++ == 3U)
        {
            readdir_failure_injected = 1;
            errno = EIO;
            return NULL;
        }
    }

    return __real_readdir(directory);
}

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

static int join_path(char *out, size_t out_size, const char *parent,
                     const char *leaf)
{
    int length = snprintf(out, out_size, "%s/%s", parent, leaf);
    return length >= 0 && (size_t)length < out_size ? 0 : -1;
}

static int write_fixture_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    const char contents[] = "payload\n";
    ssize_t written = write(fd, contents, sizeof(contents) - 1U);
    int close_result = close(fd);
    return written == (ssize_t)(sizeof(contents) - 1U) && close_result == 0
               ? 0
               : -1;
}

static void remove_fixture(const char *base)
{
    char documents[PATH_MAX];
    char nested[PATH_MAX];
    char payload[PATH_MAX];

    if (join_path(documents, sizeof(documents), base, "Documents") != 0 ||
        join_path(nested, sizeof(nested), documents, "nested") != 0 ||
        join_path(payload, sizeof(payload), nested, "payload.txt") != 0)
        return;

    unlink(payload);
    rmdir(nested);
    rmdir(documents);
    rmdir(base);
}

static void test_plain_report_detects_readdir_failure(void)
{
    char base[] = "/tmp/migr_report_XXXXXX";
    if (mkdtemp(base) == NULL)
    {
        check(0, "fixture directory can be created");
        return;
    }

    char documents[PATH_MAX];
    char nested[PATH_MAX];
    char payload[PATH_MAX];
    int fixture_ok = join_path(documents, sizeof(documents), base,
                               "Documents") == 0 &&
                     mkdir(documents, 0700) == 0 &&
                     join_path(nested, sizeof(nested), documents, "nested") == 0 &&
                     mkdir(nested, 0700) == 0 &&
                     join_path(payload, sizeof(payload), nested,
                               "payload.txt") == 0 &&
                     write_fixture_file(payload) == 0 &&
                     stat(nested, &target_directory) == 0;
    if (!fixture_ok)
    {
        check(0, "readdir failure fixture can be created");
        remove_fixture(base);
        return;
    }

    const char *old_home = getenv("HOME");
    char *old_home_copy = old_home == NULL ? NULL : strdup(old_home);
    int home_set = setenv("HOME", base, 1) == 0;
    target_directory_valid = home_set;
    target_readdir_calls = 0;
    readdir_failure_injected = 0;
    verbose = 0;

    int saved_stdout = dup(STDOUT_FILENO);
    FILE *sink = tmpfile();
    int report_result = -1;
    char output[4096] = { 0 };
    if (home_set && saved_stdout >= 0 && sink != NULL)
    {
        fflush(stdout);
        if (dup2(fileno(sink), STDOUT_FILENO) >= 0)
        {
            ReportDepth depth = { REPORT_DEPTH_DEFAULT, 0 };
            report_result = report(BACKUP_CRITICAL, 0, 0, depth);
            fflush(stdout);
            dup2(saved_stdout, STDOUT_FILENO);
            if (fseek(sink, 0, SEEK_SET) == 0)
            {
                size_t length = fread(output, 1, sizeof(output) - 1U, sink);
                output[length] = '\0';
            }
        }
    }

    if (saved_stdout >= 0)
        close(saved_stdout);
    if (sink != NULL)
        fclose(sink);
    if (old_home_copy != NULL)
        setenv("HOME", old_home_copy, 1);
    else
        unsetenv("HOME");
    free(old_home_copy);
    target_directory_valid = 0;

    check(readdir_failure_injected,
          "the nested directory readdir call is made to fail");
    check(report_result != 0 && strstr(output, "report is incomplete") != NULL,
          "plain report reports a readdir failure instead of under-counting");
    remove_fixture(base);
}

int main(void)
{
    printf(BLUE "::" NC " report measurement (unit)\n");
    test_plain_report_detects_readdir_failure();

    if (failures > 0)
    {
        printf(RED "%d report test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
