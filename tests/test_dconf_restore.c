#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "dconf_restore.h"
#include "home_rewrite.h"
#include "manifest.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define DATABASE_BYTES "GVDB-test-bytes"
#define DUMP_TEXT \
    "[org/gnome/desktop/background]\n" \
    "picture-uri='file:///home/old/Pictures/sky.jpg'\n" \
    "\n" \
    "[org/gnome/desktop/interface]\n" \
    "color-scheme='prefer-dark'\n" \
    "\n" \
    "[org/gnome/shell]\n" \
    "favorite-apps=['/home/old', \"/home/old/it's\", '/home/older']\n"
#define REWRITTEN_TEXT \
    "[org/gnome/desktop/background]\n" \
    "picture-uri='file:///home/new/Pictures/sky.jpg'\n" \
    "\n" \
    "[org/gnome/desktop/interface]\n" \
    "color-scheme='prefer-dark'\n" \
    "\n" \
    "[org/gnome/shell]\n" \
    "favorite-apps=['/home/new', \"/home/new/it's\", '/home/older']\n"
#define COMPILED_PREFIX "compiled\n"

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

static void fatal(const char *message)
{
    perror(message);
    exit(1);
}

static char *read_all_fd(int fd)
{
    size_t capacity = 4096, length = 0;
    char *data = malloc(capacity);
    if (data == NULL)
        return NULL;
    for (;;)
    {
        if (length + 1U == capacity)
        {
            char *grown = realloc(data, capacity * 2U);
            if (grown == NULL)
            {
                free(data);
                return NULL;
            }
            data = grown;
            capacity *= 2U;
        }
        ssize_t got = read(fd, data + length, capacity - 1U - length);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        length += (size_t)got;
    }
    data[length] = '\0';
    return data;
}

static char *read_all_path(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    char *data = read_all_fd(fd);
    close(fd);
    return data;
}

static void log_line(const char *line)
{
    const char *log = getenv("MIGR_FAKE_DCONF_LOG");
    if (log == NULL)
        return;
    FILE *file = fopen(log, "a");
    if (file == NULL)
        return;
    fputs(line, file);
    fputc('\n', file);
    fclose(file);
}

static int env_is(const char *name, const char *value)
{
    const char *actual = getenv(name);
    return actual != NULL && strcmp(actual, value) == 0;
}

// The test binary doubles as the dconf command through a PATH symlink. It
// validates what migr hands it and records the verdict for the test.
static int fake_dconf(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[1], "dump") == 0 &&
        strcmp(argv[2], "/") == 0)
    {
        const char *config = getenv("XDG_CONFIG_HOME");
        const char *profile_path = getenv("DCONF_PROFILE");
        char database_path[PATH_MAX], line[PATH_MAX + 32];
        char *profile = profile_path != NULL ? read_all_path(profile_path)
                                             : NULL;
        char *database = NULL;
        if (config != NULL &&
            snprintf(database_path, sizeof(database_path), "%s/dconf/user",
                     config) < (int)sizeof(database_path))
            database = read_all_path(database_path);
        char expected_profile[PATH_MAX + 16];
        snprintf(expected_profile, sizeof(expected_profile), "%s/profile",
                 config != NULL ? config : "");
        int valid = profile != NULL && database != NULL &&
                    strcmp(profile, "user-db:user\n") == 0 &&
                    strcmp(database, DATABASE_BYTES) == 0 &&
                    env_is("DCONF_PROFILE", expected_profile);
        free(profile);
        free(database);
        const char *runtime = getenv("XDG_RUNTIME_DIR");
        snprintf(line, sizeof(line), "dump %s config=%s runtime=%s",
                 valid ? "valid" : "invalid", config != NULL ? config : "",
                 runtime != NULL ? runtime : "");
        log_line(line);
        if (env_is("MIGR_FAKE_DCONF_FAIL", "dump"))
            return 3;
        if (env_is("MIGR_FAKE_DCONF_EMPTY", "1"))
            return 0;
        fputs(DUMP_TEXT, stdout);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "load") == 0 &&
        strcmp(argv[2], "/") == 0)
    {
        char *input = read_all_fd(STDIN_FILENO);
        const char *bus = getenv("DBUS_SESSION_BUS_ADDRESS");
        const char *runtime = getenv("XDG_RUNTIME_DIR");
        char line[PATH_MAX * 2 + 64];
        snprintf(line, sizeof(line), "load stdin=%s bus=%s runtime=%s",
                 input == NULL ? "differs" :
                 strcmp(input, DUMP_TEXT) == 0 ? "match" :
                 strcmp(input, REWRITTEN_TEXT) == 0 ? "rewritten" : "differs",
                 bus != NULL ? bus : "", runtime != NULL ? runtime : "");
        free(input);
        log_line(line);
        return env_is("MIGR_FAKE_DCONF_FAIL", "load") ? 4 : 0;
    }
    if (argc == 4 && strcmp(argv[1], "compile") == 0)
    {
        char keyfile[PATH_MAX];
        snprintf(keyfile, sizeof(keyfile), "%s/user", argv[3]);
        char *input = read_all_path(keyfile);
        log_line("compile");
        FILE *output = fopen(argv[2], "w");
        int written = input != NULL && output != NULL &&
                      fputs(COMPILED_PREFIX, output) >= 0 &&
                      fputs(input, output) >= 0;
        free(input);
        if (output != NULL && fclose(output) != 0)
            written = 0;
        return written && !env_is("MIGR_FAKE_DCONF_FAIL", "compile") ? 0 : 5;
    }
    log_line("unexpected invocation");
    return 2;
}

typedef struct {
    char root[PATH_MAX];
    char bin[PATH_MAX];
    char empty_bin[PATH_MAX];
    char runtime_root[PATH_MAX];
    char runtime_dir[PATH_MAX];
    char bus[PATH_MAX];
    char log[PATH_MAX];
    char database[PATH_MAX];
    char home[PATH_MAX];
    char home_database[PATH_MAX];
} Fixture;

static void fixture_path(char *out, const char *base, const char *leaf)
{
    if (snprintf(out, PATH_MAX, "%s/%s", base, leaf) >= PATH_MAX)
        fatal("fixture path too long");
}

static void fixture_open(Fixture *fixture)
{
    snprintf(fixture->root, sizeof(fixture->root),
             "/tmp/migr-dconf-test-XXXXXX");
    if (mkdtemp(fixture->root) == NULL)
        fatal("mkdtemp dconf fixture");
    fixture_path(fixture->bin, fixture->root, "bin");
    fixture_path(fixture->empty_bin, fixture->root, "empty-bin");
    fixture_path(fixture->runtime_root, fixture->root, "run-user");
    fixture_path(fixture->log, fixture->root, "log");
    fixture_path(fixture->database, fixture->root, "database");
    fixture_path(fixture->home, fixture->root, "home");
    fixture_path(fixture->home_database, fixture->home,
                 ".config/dconf/user");
    if (snprintf(fixture->runtime_dir, sizeof(fixture->runtime_dir), "%s/%ju",
                 fixture->runtime_root, (uintmax_t)geteuid()) >=
        (int)sizeof(fixture->runtime_dir))
        fatal("runtime path too long");
    fixture_path(fixture->bus, fixture->runtime_dir, "bus");

    char dconf_link[PATH_MAX];
    fixture_path(dconf_link, fixture->bin, "dconf");
    if (mkdir(fixture->bin, 0755) != 0 || mkdir(fixture->empty_bin, 0755) != 0 ||
        mkdir(fixture->runtime_root, 0755) != 0 ||
        mkdir(fixture->runtime_dir, 0700) != 0 ||
        mkdir(fixture->home, 0700) != 0 ||
        symlink("/proc/self/exe", dconf_link) != 0)
        fatal("prepare dconf fixture");

    FILE *database = fopen(fixture->database, "w");
    if (database == NULL || fputs(DATABASE_BYTES, database) < 0 ||
        fclose(database) != 0)
        fatal("write database fixture");
    dconf_restore_test_set_runtime_root(fixture->runtime_root);
    setenv("MIGR_FAKE_DCONF_LOG", fixture->log, 1);
    setenv("PATH", fixture->bin, 1);
}

static void fixture_bind_bus(Fixture *fixture)
{
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (sock < 0 || strlen(fixture->bus) >= sizeof(address.sun_path))
        fatal("create bus socket");
    memcpy(address.sun_path, fixture->bus, strlen(fixture->bus) + 1U);
    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) != 0)
        fatal("bind bus socket");
    close(sock);
}

static void fixture_reset_log(Fixture *fixture)
{
    unlink(fixture->log);
    unsetenv("MIGR_FAKE_DCONF_FAIL");
    unsetenv("MIGR_FAKE_DCONF_EMPTY");
    dconf_restore_test_set_dump_limit(0);
}

static char *fixture_log(Fixture *fixture)
{
    char *log = read_all_path(fixture->log);
    return log != NULL ? log : strdup("");
}

static void fixture_close(Fixture *fixture)
{
    char path[PATH_MAX];
    unlink(fixture->log);
    unlink(fixture->database);
    unlink(fixture->home_database);
    fixture_path(path, fixture->home, ".config/dconf");
    rmdir(path);
    fixture_path(path, fixture->home, ".config");
    rmdir(path);
    rmdir(fixture->home);
    unlink(fixture->bus);
    fixture_path(path, fixture->bin, "dconf");
    unlink(path);
    rmdir(fixture->bin);
    rmdir(fixture->empty_bin);
    rmdir(fixture->runtime_dir);
    rmdir(fixture->runtime_root);
    rmdir(fixture->root);
    dconf_restore_test_set_runtime_root(NULL);
}

static int open_database(Fixture *fixture)
{
    int fd = open(fixture->database, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fatal("open database fixture");
    return fd;
}

// Extracts the private work directory the dump saw, so the test can prove
// it was removed afterwards.
static int work_dir_removed(const char *log)
{
    const char *marker = strstr(log, "config=");
    if (marker == NULL)
        return 0;
    char path[PATH_MAX];
    size_t length = strcspn(marker + 7, "\n");
    if (length == 0 || length >= sizeof(path))
        return 0;
    memcpy(path, marker + 7, length);
    path[length] = '\0';
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}

// The restored database in the home folder, as replay leaves it.
static int fixture_home_open(Fixture *fixture)
{
    char path[PATH_MAX];
    fixture_path(path, fixture->home, ".config");
    if (mkdir(path, 0700) != 0)
        fatal("prepare home fixture");
    fixture_path(path, fixture->home, ".config/dconf");
    FILE *database = NULL;
    if (mkdir(path, 0700) != 0 ||
        (database = fopen(fixture->home_database, "w")) == NULL ||
        fputs(DATABASE_BYTES, database) < 0 || fclose(database) != 0)
        fatal("write home database fixture");
    int fd = open(fixture->home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        fatal("open home fixture");
    return fd;
}

static void fixture_reset_home(Fixture *fixture)
{
    fixture_reset_log(fixture);
    FILE *database = fopen(fixture->home_database, "w");
    if (database == NULL || fputs(DATABASE_BYTES, database) < 0 ||
        fclose(database) != 0)
        fatal("reset home database fixture");
}

static void build_pairs(const char *source_home, HomeRewritePair *pairs,
                        size_t *pair_count)
{
    static Manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    snprintf(manifest.source_home, sizeof(manifest.source_home), "%s",
             source_home);
    if (home_rewrite_dconf_pairs_build(&manifest, NULL, "/home/new", pairs,
                                       pair_count) != 0)
        fatal("build rewrite pairs");
}

static int home_database_is(Fixture *fixture, const char *expected)
{
    char *content = read_all_path(fixture->home_database);
    int same = content != NULL && strcmp(content, expected) == 0;
    free(content);
    return same;
}

int main(int argc, char *argv[])
{
    const char *slash = strrchr(argv[0], '/');
    if (strcmp(slash != NULL ? slash + 1 : argv[0], "dconf") == 0)
        return fake_dconf(argc, argv);

    printf(BLUE "::" NC " dconf restore into a running session\n");
    if (geteuid() == 0)
        unsetenv("SUDO_UID");
    Fixture fixture;
    fixture_open(&fixture);

    size_t keys = 99;
    int database_fd = open_database(&fixture);
    int home_fd = fixture_home_open(&fixture);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_NO_SESSION && keys == 0,
          "without a session bus the restored file is left as the result");
    char *log = fixture_log(&fixture);
    check(log[0] == '\0', "no dconf command runs without a session");
    free(log);

    HomeRewritePair pairs[HOME_REWRITE_DCONF_MAX_PAIRS];
    size_t pair_count = 0;
    build_pairs("/home/old", pairs, &pair_count);
    struct stat before, after;
    if (stat(fixture.home_database, &before) != 0)
        fatal("stat home database");
    check(dconf_restore_apply(database_fd, home_fd, pairs, pair_count,
                              &keys) == DCONF_RESTORE_NO_SESSION,
          "without a session, settings naming the old home are rewritten");
    check(home_database_is(&fixture, COMPILED_PREFIX REWRITTEN_TEXT) &&
              stat(fixture.home_database, &after) == 0 &&
              after.st_ino == before.st_ino,
          "the rewritten dump is compiled into the same restored file, "
          "URIs and quoted paths alike, longer names untouched");
    log = fixture_log(&fixture);
    check(work_dir_removed(log), "the private work directory is removed");
    free(log);

    fixture_reset_home(&fixture);
    build_pairs("/home/elsewhere", pairs, &pair_count);
    check(dconf_restore_apply(database_fd, home_fd, pairs, pair_count,
                              &keys) == DCONF_RESTORE_NO_SESSION &&
              home_database_is(&fixture, DATABASE_BYTES),
          "a database with nothing to rewrite stays as restored");
    log = fixture_log(&fixture);
    check(strstr(log, "compile") == NULL, "nothing is compiled for it");
    free(log);

    fixture_reset_home(&fixture);
    build_pairs("/home/old", pairs, &pair_count);
    setenv("MIGR_FAKE_DCONF_FAIL", "compile", 1);
    check(dconf_restore_apply(database_fd, home_fd, pairs, pair_count,
                              &keys) == DCONF_RESTORE_HOME_NOT_REWRITTEN &&
              home_database_is(&fixture, DATABASE_BYTES),
          "a failed compile is reported and leaves the restored file");
    fixture_reset_home(&fixture);

    fixture_bind_bus(&fixture);
    setenv("PATH", fixture.empty_bin, 1);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_UNAVAILABLE,
          "a session without dconf installed is reported as unavailable");
    setenv("PATH", fixture.bin, 1);

    fixture_reset_log(&fixture);
    // sudo may leave root's runtime directory in the environment.
    const char *inherited = getenv("XDG_RUNTIME_DIR");
    char *saved_runtime = inherited != NULL ? strdup(inherited) : NULL;
    setenv("XDG_RUNTIME_DIR", "/run/user/0", 1);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_APPLIED && keys == 3,
          "a running session gets the backup's settings loaded");
    if (saved_runtime != NULL)
        setenv("XDG_RUNTIME_DIR", saved_runtime, 1);
    else
        unsetenv("XDG_RUNTIME_DIR");
    free(saved_runtime);
    log = fixture_log(&fixture);
    char expected_load[PATH_MAX * 2 + 64];
    snprintf(expected_load, sizeof(expected_load),
             "load stdin=match bus=unix:path=%s runtime=%s\n", fixture.bus,
             fixture.runtime_dir);
    char expected_dump_runtime[PATH_MAX + 16];
    snprintf(expected_dump_runtime, sizeof(expected_dump_runtime),
             "runtime=%s\nload", fixture.runtime_dir);
    check(strstr(log, "dump valid config=") != NULL,
          "the dump reads a private copy of the backup through its own profile");
    check(strstr(log, expected_dump_runtime) != NULL,
          "the dump uses the user's runtime directory, not the invoker's");
    check(strstr(log, expected_load) != NULL,
          "the load receives the whole dump over the user's session bus");
    check(work_dir_removed(log), "the private work directory is removed");
    free(log);

    fixture_reset_log(&fixture);
    check(dconf_restore_apply(database_fd, home_fd, pairs, pair_count,
                              &keys) == DCONF_RESTORE_APPLIED && keys == 3,
          "a running session gets the rewritten settings loaded");
    log = fixture_log(&fixture);
    check(strstr(log, "load stdin=rewritten") != NULL &&
              strstr(log, "compile") == NULL &&
              home_database_is(&fixture, DATABASE_BYTES),
          "the load carries the paths of this system's home, and the file "
          "is left to the session");
    free(log);

    fixture_reset_log(&fixture);
    setenv("MIGR_FAKE_DCONF_FAIL", "dump", 1);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_FAILED,
          "a failed dump is reported");
    log = fixture_log(&fixture);
    check(strstr(log, "load") == NULL && work_dir_removed(log),
          "a failed dump loads nothing and still cleans up");
    free(log);

    fixture_reset_log(&fixture);
    setenv("MIGR_FAKE_DCONF_FAIL", "load", 1);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_FAILED && keys == 0,
          "a failed load is reported");

    fixture_reset_log(&fixture);
    dconf_restore_test_set_dump_limit(16);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_FAILED,
          "a dump larger than the limit is rejected");
    log = fixture_log(&fixture);
    check(strstr(log, "load") == NULL,
          "a truncated dump is never loaded");
    free(log);

    fixture_reset_log(&fixture);
    setenv("MIGR_FAKE_DCONF_EMPTY", "1", 1);
    check(dconf_restore_apply(database_fd, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_APPLIED &&
              keys == 0,
          "an empty database applies nothing");
    log = fixture_log(&fixture);
    check(strstr(log, "load") == NULL, "an empty dump is not loaded");
    free(log);

    fixture_reset_log(&fixture);
    check(dconf_restore_apply(-1, home_fd, NULL, 0, &keys) ==
              DCONF_RESTORE_FAILED,
          "an invalid database fd is rejected");

    close(home_fd);
    close(database_fd);
    fixture_close(&fixture);
    if (failures != 0)
    {
        printf("%d dconf restore test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
