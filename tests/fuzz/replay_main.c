// Deterministic replay for one fuzz harness, linked in place of libFuzzer.
// It feeds the harness every generated seed and every file in the target's
// checked-in corpus, tests/fuzz/corpus/<target>/ (or the files given as
// arguments), and compares each outcome with the expected one: a seed states
// it in code, a corpus file in its name, <outcome>-<description>. The corpus
// holds only minimized inputs discovery found, so before the first one the
// directory does not exist and replay runs the seeds alone.
//
// An oracle violation aborts; the handler below names the input first.
//
// With --write-seeds DIR it writes the seeds there instead, named like corpus
// files, as the starting corpus for discovery.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz.h"

#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define MAX_CORPUS_INPUT (1024U * 1024U)

static int failures;
static char current[PATH_MAX];

static void name_failure(int signal_number)
{
    char message[sizeof(current) + 64U];
    int length = snprintf(message, sizeof(message),
                          "replay: an oracle failed on %s\n", current);
    if (length > 0)
    {
        ssize_t written = write(STDERR_FILENO, message, (size_t)length);
        (void)written;
    }
    raise(signal_number);
}

static void check_outcome(const char *expected, const char *actual)
{
    if (strcmp(expected, actual) == 0)
        return;
    printf("  " RED "x" NC " %s: expected %s, got %s\n", current, expected,
           actual);
    failures++;
}

static void replay_seeds(const FuzzSeed *seeds, size_t count)
{
    for (size_t index = 0; index < count; index++)
    {
        const FuzzSeed *seed = &seeds[index];
        snprintf(current, sizeof(current), "seed %s", seed->name);
        LLVMFuzzerTestOneInput(seed->data, seed->size);
        check_outcome(fuzz_seed_outcome(seed),
                      fuzz_outcome(seed->data, seed->size));
        fuzz_check_seed(seed);
    }
    printf("  %zu generated seeds\n", count);
}

static int read_input(const char *path, unsigned char **data, size_t *size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uint64_t)st.st_size > MAX_CORPUS_INPUT)
    {
        close(fd);
        return -1;
    }
    *size = (size_t)st.st_size;
    *data = malloc(*size > 0 ? *size : 1U);
    ssize_t received = *data != NULL ? read(fd, *data, *size) : -1;
    close(fd);
    if (received != (ssize_t)*size)
    {
        free(*data);
        return -1;
    }
    return 0;
}

static void replay_file(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash != NULL ? slash + 1 : path;
    unsigned char *data;
    size_t size;
    snprintf(current, sizeof(current), "%s", path);
    if (read_input(path, &data, &size) != 0)
    {
        printf("  " RED "x" NC " %s: cannot be read\n", path);
        failures++;
        return;
    }
    LLVMFuzzerTestOneInput(data, size);
    const char *outcome = fuzz_outcome(data, size);
    size_t length = strlen(outcome);
    if (strncmp(name, outcome, length) != 0 || name[length] != '-')
    {
        printf("  " RED "x" NC " %s: its name does not begin with its "
               "outcome, %s-\n", path, outcome);
        failures++;
    }
    free(data);
}

static size_t replay_corpus(void)
{
    char directory[128];
    snprintf(directory, sizeof(directory), "tests/fuzz/corpus/%s",
             fuzz_target_name);
    DIR *stream = opendir(directory);
    if (stream == NULL)
    {
        if (errno != ENOENT)
        {
            printf("  " RED "x" NC " %s: cannot be opened\n", directory);
            failures++;
        }
        return 0;
    }
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        replay_file(path);
        count++;
    }
    closedir(stream);
    return count;
}

static int write_seeds(const char *directory, const FuzzSeed *seeds,
                       size_t count)
{
    for (size_t index = 0; index < count; index++)
    {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s-%s", directory,
                 fuzz_seed_outcome(&seeds[index]), seeds[index].name);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0 ||
            write(fd, seeds[index].data, seeds[index].size) !=
                (ssize_t)seeds[index].size ||
            close(fd) != 0)
        {
            fprintf(stderr, "replay: cannot write %s: %s\n", path,
                    strerror(errno));
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    FuzzSeed *seeds;
    size_t count;
    fuzz_seeds_build(&seeds, &count);
    if (argc == 3 && strcmp(argv[1], "--write-seeds") == 0)
    {
        int status = write_seeds(argv[2], seeds, count);
        fuzz_seeds_free(seeds, count);
        return status;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = name_failure;
    action.sa_flags = SA_RESETHAND;
    sigaction(SIGABRT, &action, NULL);

    printf(BLUE "::" NC " fuzz replay: %s\n", fuzz_target_name);
    replay_seeds(seeds, count);
    if (argc > 1)
    {
        for (int index = 1; index < argc; index++)
            replay_file(argv[index]);
        printf("  %d given inputs\n", argc - 1);
    }
    else
        printf("  %zu corpus inputs\n", replay_corpus());
    fuzz_seeds_free(seeds, count);
    printf("fuzz replay %s: %d failure(s)\n", fuzz_target_name, failures);
    return failures == 0 ? 0 : 1;
}
