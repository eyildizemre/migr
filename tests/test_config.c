#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); failures++; \
} } while (0)

static int interrupt_wait;
static int read_mode;
static const char *read_path;
ssize_t __real_read(int fd, void *buf, size_t count);
pid_t __real_waitpid(pid_t pid, int *status, int options);

pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    if (interrupt_wait)
    {
        interrupt_wait = 0;
        errno = EINTR;
        return -1;
    }
    return __real_waitpid(pid, status, options);
}

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    int mode = read_mode;
    read_mode = 0;
    if (mode == 1 || mode == 2)
    {
        errno = mode == 1 ? EINTR : EIO;
        return -1;
    }
    ssize_t n = __real_read(fd, buf, count);
    if (mode == 3)
    {
        int writer = open(read_path, O_WRONLY | O_APPEND);
        CHECK(writer >= 0);
        if (writer >= 0)
        {
            CHECK(write(writer, "# changed\n", 10) == 10);
            CHECK(close(writer) == 0);
        }
    }
    if (mode == 4)
    {
        char replacement[PATH_MAX];
        int len = snprintf(replacement, sizeof(replacement), "%s.new", read_path);
        CHECK(len > 0 && (size_t)len < sizeof(replacement));
        int writer = open(replacement, O_WRONLY | O_CREAT | O_EXCL, 0600);
        CHECK(writer >= 0);
        if (writer >= 0)
        {
            CHECK(write(writer, "# replacement\n", 14) == 14);
            CHECK(close(writer) == 0);
            CHECK(rename(replacement, read_path) == 0);
        }
    }
    return n;
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    CHECK(fputs(text, f) >= 0);
    CHECK(fclose(f) == 0);
}

static void parser_tests(void)
{
    const char *valid = "# comment\r\n[critical]\r\n [include]\r\n"
        " foo bar # literal \\name \r\n\" #quoted\\n\\r\\t\\x41\\\\\\\" \"\n"
        "[exclude]\nISO\n[comprehensive]\n[exclude]\nISO\n";
    Config c = {0};
    CHECK(config_parse(valid, strlen(valid), "fixture", &c) == 0);
    CHECK(c.count == 4);
    if (c.count == 4)
    {
        CHECK(strcmp(c.rules[0].path, "foo bar # literal \\name") == 0);
        CHECK(c.rules[0].line == 4);
        CHECK(strcmp(c.rules[1].path, " #quoted\n\r\tA\\\" ") == 0);
        CHECK(c.rules[2].scope == CONFIG_CRITICAL && c.rules[2].action == CONFIG_EXCLUDE);
        CHECK(c.rules[3].scope == CONFIG_COMPREHENSIVE);
    }
    config_free(&c);
    const char *bad[] = {"[unknown]", "[include]", "path", "[critical]\npath",
        "[critical]\n[critical]", "[critical]\n[include]\n[include]",
        "[critical]\n[include]\n\"unterminated", "[critical]\n[include]\n\"x\" tail",
        "[critical]\n[include]\n\"\\q\"", "[critical]\n[include]\n\"\\x0g\"",
        "[critical]\n[include]\n\"\\x00\"", "[critical]\n[include]\n\"\"",
        "[critical]\n[include]\nvalid\n[bad]"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++)
    {
        CHECK(config_parse(bad[i], strlen(bad[i]), "invalid", &c) < 0);
        CHECK(c.count == 0 && c.rules == NULL);
    }
    CHECK(config_parse("", 0, "empty", &c) == 0);
    CHECK(config_parse("a\0b", 3, "nul", &c) < 0);
    char *large = malloc(CONFIG_MAX_BYTES + 1U);
    CHECK(large != NULL);
    if (!large) return;
    memset(large, ' ', CONFIG_MAX_BYTES + 1U);
    CHECK(config_parse(large, CONFIG_MAX_BYTES, "limit", &c) == 0);
    CHECK(config_parse(large, CONFIG_MAX_BYTES + 1U, "limit", &c) < 0);
    const char *header = "[critical]\n[include]\n";
    size_t n = strlen(header);
    memcpy(large, header, n);
    memset(large + n, 'a', PATH_MAX);
    CHECK(config_parse(large, n + PATH_MAX - 1, "path-limit", &c) == 0);
    config_free(&c);
    CHECK(config_parse(large, n + PATH_MAX, "path-limit", &c) < 0);
    for (size_t i = 0; i < CONFIG_MAX_RULES + 1U; i++)
        memcpy(large + n + i * 2, "x\n", 2);
    CHECK(config_parse(large, n + CONFIG_MAX_RULES * 2, "rule-limit", &c) == 0);
    CHECK(c.count == CONFIG_MAX_RULES);
    config_free(&c);
    CHECK(config_parse(large, n + (CONFIG_MAX_RULES + 1U) * 2, "rule-limit", &c) < 0);
    free(large);
}

static void service_tests(void)
{
    /* Instrumented editor children must not create debuginfod caches in HOME. */
    CHECK(setenv("DEBUGINFOD_URLS", "", 1) == 0);
    char base[] = "/tmp/migr-config-XXXXXX";
    CHECK(mkdtemp(base) != NULL);
    CHECK(chdir(base) == 0);
    CHECK(mkdir("home space", 0700) == 0);
    char *home = realpath("home space", NULL);
    CHECK(home != NULL);
    if (!home) return;
    CHECK(setenv("HOME", home, 1) == 0);
    unsetenv("XDG_CONFIG_HOME");
    char *path = NULL;
    CHECK(config_path(&path) == 0);
    Config c = {0};
    CHECK(config_load(path, &c) == 0 && c.count == 0);
    CHECK(access(path, F_OK) < 0 && errno == ENOENT);
    char *fallback = strdup(path);
    free(path); path = NULL;
    setenv("XDG_CONFIG_HOME", "relative", 1);
    CHECK(config_path(&path) == 0 && strcmp(path, fallback) == 0);
    free(path); path = NULL;
    setenv("XDG_CONFIG_HOME", "", 1);
    CHECK(config_path(&path) == 0 && strcmp(path, fallback) == 0);
    free(path); path = NULL;
    setenv("XDG_CONFIG_HOME", home, 1);
    CHECK(config_path(&path) == 0 && strcmp(path, fallback) != 0);
    free(fallback);
    /* The test executable acts as an editor; inherited stdio needs no terminal. */
    char self[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    CHECK(len > 0);
    if (len <= 0) exit(1);
    self[len] = 0;
    char editor[PATH_MAX + 128];
    snprintf(editor, sizeof(editor), "'%s' --editor 'two words' \"\" semi\\;colon", self);
    setenv("EDITOR", editor, 1);
    setenv("CONFIG_EDITOR_MODE", "template", 1);
    interrupt_wait = 1;
    CHECK(config_edit() == 0);
    CHECK(interrupt_wait == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(stat("home space/migr", &st) == 0 && (st.st_mode & 0777) == 0700);
    CHECK(config_load(path, &c) == 0 && c.count == 0);
    config_free(&c);
    setenv("CONFIG_EDITOR_MODE", "inspect", 1);
    write_file(path, "# preserved\n[critical]\n[include]\nDocuments\n");
    CHECK(chmod(path, 0640) == 0);
    CHECK(config_edit() == 0);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0640);
    FILE *preserved = fopen(path, "r");
    CHECK(preserved != NULL);
    if (preserved)
    {
        char contents[128] = {0};
        CHECK(fread(contents, 1, sizeof(contents) - 1, preserved) > 0);
        CHECK(strcmp(contents, "# preserved\n[critical]\n[include]\nDocuments\n") == 0);
        CHECK(fclose(preserved) == 0);
    }
    CHECK(config_load(path, &c) == 0 && c.count == 1);
    config_free(&c);
    read_mode = 1;
    CHECK(config_load(path, &c) == 0);
    config_free(&c);
    read_mode = 2;
    CHECK(config_load(path, &c) < 0 && c.count == 0);
    read_mode = 4;
    read_path = path;
    CHECK(config_load(path, &c) == 0 && c.count == 1);
    config_free(&c);
    CHECK(config_load(path, &c) == 0 && c.count == 0);
    config_free(&c);
    read_mode = 3;
    read_path = path;
    CHECK(config_load(path, &c) < 0 && c.count == 0);
    write_file(path, "invalid");
    CHECK(config_edit() < 0);
    setenv("CONFIG_EDITOR_MODE", "repair", 1);
    CHECK(config_edit() == 0);
    setenv("CONFIG_EDITOR_MODE", "remove", 1);
    CHECK(config_edit() < 0);
    setenv("CONFIG_EDITOR_MODE", "repair", 1);
    CHECK(config_edit() == 0);
    setenv("CONFIG_EDITOR_MODE", "fail", 1);
    CHECK(config_edit() < 0);
    setenv("CONFIG_EDITOR_MODE", "signal", 1);
    CHECK(config_edit() < 0);
    setenv("CONFIG_EDITOR_MODE", "inspect", 1);
    setenv("VISUAL", editor, 1);
    setenv("EDITOR", "", 1);
    CHECK(config_edit() == 0);
    setenv("EDITOR", "'unterminated", 1);
    CHECK(config_edit() < 0);
    setenv("EDITOR", "/nonexistent-editor", 1);
    CHECK(config_edit() < 0);
    char oversized[16386];
    memset(oversized, 'a', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = 0;
    setenv("EDITOR", oversized, 1);
    CHECK(config_edit() < 0);
    for (size_t i = 0; i < 256; i += 2) memcpy(oversized + i, "a ", 2);
    oversized[256] = 0;
    setenv("EDITOR", oversized, 1);
    CHECK(config_edit() < 0);
    CHECK(symlink(self, "vi") == 0);
    char *old_path = getenv("PATH") ? strdup(getenv("PATH")) : NULL;
    setenv("PATH", base, 1);
    unsetenv("EDITOR");
    unsetenv("VISUAL");
    setenv("CONFIG_FALLBACK_EDITOR", "1", 1);
    CHECK(config_edit() == 0);
    unsetenv("CONFIG_FALLBACK_EDITOR");
    if (old_path) setenv("PATH", old_path, 1); else unsetenv("PATH");
    free(old_path);
    CHECK(unlink("vi") == 0);
    setenv("EDITOR", editor, 1);
    CHECK(rename(path, "target") == 0);
    char *target = realpath("target", NULL);
    CHECK(target != NULL);
    CHECK(symlink(target, path) == 0);
    setenv("CONFIG_EXPECT_PATH", target, 1);
    CHECK(config_edit() == 0);
    CHECK(lstat(path, &st) == 0 && S_ISLNK(st.st_mode));
    unsetenv("CONFIG_EXPECT_PATH");
    CHECK(unlink("target") == 0);
    CHECK(config_load(path, &c) < 0);
    CHECK(config_edit() < 0);
    CHECK(unlink(path) == 0);
    CHECK(mkfifo(path, 0600) == 0);
    CHECK(config_load(path, &c) < 0);
    CHECK(config_edit() < 0);
    CHECK(unlink(path) == 0);
    CHECK(mkdir(path, 0700) == 0);
    CHECK(config_load(path, &c) < 0);
    CHECK(config_edit() < 0);
    CHECK(rmdir(path) == 0);
    setenv("CONFIG_EDITOR_MODE", "template", 1);
    /* Both initializers must see a complete published template. */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(config_edit() == 0 ? 0 : 1);
    CHECK(config_edit() == 0);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(unlink(path) == 0);
    CHECK(rmdir("home space/migr") == 0);
    CHECK(symlink("missing-parent", "home space/migr") == 0);
    CHECK(config_load(path, &c) < 0);
    CHECK(config_edit() < 0);
    CHECK(unlink("home space/migr") == 0);
    CHECK(rmdir("home space") == 0);
    CHECK(chdir("/") == 0);
    CHECK(rmdir(base) == 0);
    free(target); free(path); free(home);
}

int main(int argc, char **argv)
{
    if (argc == 2 && getenv("CONFIG_FALLBACK_EDITOR"))
    {
        Config parsed = {0};
        int result = config_load(argv[1], &parsed);
        config_free(&parsed);
        return result == 0 ? 0 : 1;
    }
    if (argc > 1 && strcmp(argv[1], "--editor") == 0)
    {
        if (argc != 6 || strcmp(argv[2], "two words") || argv[3][0] ||
            strcmp(argv[4], "semi;colon") || argv[5][0] != '/') return 2;
        const char *expected = getenv("CONFIG_EXPECT_PATH");
        if (expected && strcmp(expected, argv[5])) return 3;
        const char *mode = getenv("CONFIG_EDITOR_MODE");
        if (strcmp(mode, "template") == 0)
        {
            FILE *file = fopen(argv[5], "r");
            if (!file) return 4;
            char contents[1024] = {0};
            size_t n = fread(contents, 1, sizeof(contents) - 1, file);
            int closed = fclose(file);
            if (!n || closed || contents[0] != '#' ||
                !strstr(contents, "[critical]\n    [include]\n\n    [exclude]\n\n[comprehensive]\n    [include]\n\n    [exclude]\n"))
                return 5;
        }
        if (strcmp(mode, "remove") == 0) return unlink(argv[5]) == 0 ? 0 : 1;
        if (strcmp(mode, "fail") == 0) return 7;
        if (strcmp(mode, "signal") == 0) { raise(SIGTERM); return 8; }
        if (strcmp(mode, "repair") == 0) write_file(argv[5], "[critical]\n[include]\nfixed\n");
        return failures ? 1 : 0;
    }
    parser_tests();
    service_tests();
    printf("config tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
