#define _GNU_SOURCE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xdg.h"

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

static void free_dirs(char **out, int n)
{
    for (int i = 0; i < n; i++)
        free(out[i]);
}

static int dirs_all_null(char **out, int n)
{
    for (int i = 0; i < n; i++)
        if (out[i] != NULL)
            return 0;
    return 1;
}

static int make_home(char *home, size_t home_size)
{
    if (home_size == 0)
        return -1;
    home[0] = '\0';

    char template[] = "/tmp/xdg_test_XXXXXX";
    char *created = mkdtemp(template);
    if (created == NULL)
        return -1;

    int n = snprintf(home, home_size, "%s", created);
    if (n < 0 || (size_t)n >= home_size)
    {
        rmdir(created);
        return -1;
    }
    return 0;
}

static int fixture_path(char *out, size_t out_size,
                        const char *home, const char *suffix)
{
    int n = snprintf(out, out_size, "%s/%s", home, suffix);
    return (n >= 0 && (size_t)n < out_size) ? 0 : -1;
}

static int write_mixed_config(const char *path)
{
    FILE *config = fopen(path, "w");
    if (config == NULL)
        return -1;

    int ok = fputs("XDG_DOCUMENTS_DIR=\"$HOME/MyDocs\"\n", config) >= 0 &&
             fputs("XDG_DOWNLOAD_DIR=\"/mnt/external/Downloads\"\n", config) >= 0;
    if (fclose(config) != 0)
        ok = 0;
    return ok ? 0 : -1;
}

static void test_no_config_file(void)
{
    char home[PATH_MAX] = {0};
    check(make_home(home, sizeof(home)) == 0,
          "fixture: home without config is created");
    if (home[0] == '\0')
        return;

    char *out[XDG_KEY_COUNT];
    int rc = xdg_resolve(home, xdg_keys, xdg_fallbacks, out, XDG_KEY_COUNT);
    check(rc == 0, "missing config uses XDG fallbacks");

    int all_fallbacks = rc == 0;
    for (int i = 0; all_fallbacks && i < XDG_KEY_COUNT; i++)
    {
        char expected[PATH_MAX];
        if (fixture_path(expected, sizeof(expected), home, xdg_fallbacks[i]) != 0 ||
            out[i] == NULL || strcmp(out[i], expected) != 0)
            all_fallbacks = 0;
    }
    check(all_fallbacks, "every absent key resolves to its English fallback");

    free_dirs(out, XDG_KEY_COUNT);
    check(rmdir(home) == 0, "fixture: fallback-only home is removed");
}

static void test_config_open_failure_is_reported(void)
{
    char home[PATH_MAX] = {0};
    check(make_home(home, sizeof(home)) == 0,
          "fixture: config-open-error home is created");
    if (home[0] == '\0')
        return;

    char config_component[PATH_MAX] = {0};
    int fixture_ok = fixture_path(config_component, sizeof(config_component),
                                  home, ".config") == 0;
    FILE *not_a_directory = fixture_ok ? fopen(config_component, "w") : NULL;
    if (not_a_directory == NULL)
        fixture_ok = 0;
    else if (fclose(not_a_directory) != 0)
        fixture_ok = 0;
    check(fixture_ok, "fixture: .config is a regular file");

    if (fixture_ok)
    {
        char *out[XDG_KEY_COUNT];
        int rc = xdg_resolve(home, xdg_keys, xdg_fallbacks, out, XDG_KEY_COUNT);
        check(rc == -1, "non-ENOENT config open failure is reported");
        check(dirs_all_null(out, XDG_KEY_COUNT),
              "config open failure is not converted into fallback paths");
        free_dirs(out, XDG_KEY_COUNT);
    }

    if (config_component[0] != '\0')
        unlink(config_component);
    check(rmdir(home) == 0, "fixture: config-open-error home is removed");
}

static void test_config_resolves_home_relative_and_absolute(void)
{
    char home[PATH_MAX] = {0};
    check(make_home(home, sizeof(home)) == 0,
          "fixture: configured home is created");
    if (home[0] == '\0')
        return;

    char config_dir[PATH_MAX] = {0};
    char config_path[PATH_MAX] = {0};
    int fixture_ok = fixture_path(config_dir, sizeof(config_dir), home, ".config") == 0 &&
                     fixture_path(config_path, sizeof(config_path), home,
                                  ".config/user-dirs.dirs") == 0 &&
                     mkdir(config_dir, 0700) == 0 &&
                     write_mixed_config(config_path) == 0;
    check(fixture_ok, "fixture: mixed XDG config is written");

    if (fixture_ok)
    {
        char *out[XDG_KEY_COUNT];
        int rc = xdg_resolve(home, xdg_keys, xdg_fallbacks, out, XDG_KEY_COUNT);
        check(rc == 0, "configured and absent XDG keys resolve together");

        char documents[PATH_MAX];
        int docs_ok = fixture_path(documents, sizeof(documents), home, "MyDocs") == 0;
        check(docs_ok && out[0] != NULL && strcmp(out[0], documents) == 0,
              "$HOME-relative XDG value expands against the supplied home");
        check(out[1] != NULL && strcmp(out[1], "/mnt/external/Downloads") == 0,
              "absolute XDG value is preserved exactly");

        int absent_fallbacks = rc == 0;
        for (int i = 2; absent_fallbacks && i < XDG_KEY_COUNT; i++)
        {
            char expected[PATH_MAX];
            if (fixture_path(expected, sizeof(expected), home, xdg_fallbacks[i]) != 0 ||
                out[i] == NULL || strcmp(out[i], expected) != 0)
                absent_fallbacks = 0;
        }
        check(absent_fallbacks, "unmentioned XDG keys still use fallbacks");
        free_dirs(out, XDG_KEY_COUNT);
    }

    if (config_path[0] != '\0')
        unlink(config_path);
    if (config_dir[0] != '\0')
        rmdir(config_dir);
    check(rmdir(home) == 0, "fixture: configured home is removed");
}

static void test_stream_read_failure_is_reported(void)
{
    char home[PATH_MAX] = {0};
    check(make_home(home, sizeof(home)) == 0,
          "fixture: stream-error home is created");
    if (home[0] == '\0')
        return;

    char config_dir[PATH_MAX] = {0};
    char config_path[PATH_MAX] = {0};
    int fixture_ok = fixture_path(config_dir, sizeof(config_dir), home, ".config") == 0 &&
                     fixture_path(config_path, sizeof(config_path), home,
                                  ".config/user-dirs.dirs") == 0 &&
                     mkdir(config_dir, 0700) == 0 &&
                     mkdir(config_path, 0700) == 0;
    check(fixture_ok, "fixture: user-dirs.dirs is a directory");

    if (fixture_ok)
    {
        char *out[XDG_KEY_COUNT];
        int rc = xdg_resolve(home, xdg_keys, xdg_fallbacks, out, XDG_KEY_COUNT);
        check(rc == -1, "stream read failure is reported");

        check(dirs_all_null(out, XDG_KEY_COUNT),
              "stream failure is not converted into fallback paths");
        free_dirs(out, XDG_KEY_COUNT);
    }

    if (config_path[0] != '\0')
        rmdir(config_path);
    if (config_dir[0] != '\0')
        rmdir(config_dir);
    check(rmdir(home) == 0, "fixture: stream-error home is removed");
}

int main(void)
{
    printf(BLUE "::" NC " xdg_resolve (unit)\n");
    test_no_config_file();
    test_config_open_failure_is_reported();
    test_config_resolves_home_relative_and_absolute();
    test_stream_read_failure_is_reported();

    printf("xdg tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
