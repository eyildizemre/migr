#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "packages.h"

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

static FILE *fixture_stream(const char *content)
{
    FILE *stream = tmpfile();
    if (stream == NULL)
        return NULL;

    if (fputs(content, stream) < 0 || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_SET) != 0)
    {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static void free_package_list(char **pkgs, int pkg_count)
{
    if (pkgs == NULL)
        return;
    for (int i = 0; i < pkg_count; i++)
        free(pkgs[i]);
    free(pkgs);
}

static void test_normal_list(void)
{
    FILE *stream = fixture_stream("vim\nfirefox\ngit\n");
    check(stream != NULL, "fixture: normal package list opens");
    if (stream == NULL)
        return;

    char **pkgs = NULL;
    int pkg_count = 0;
    int had_error = 0;
    read_package_list(stream, &pkgs, &pkg_count, &had_error);

    check(had_error == 0, "normal list leaves had_error clear");
    check(pkg_count == 3, "normal list preserves every package");
    check(pkg_count == 3 && strcmp(pkgs[0], "vim") == 0 &&
              strcmp(pkgs[1], "firefox") == 0 &&
              strcmp(pkgs[2], "git") == 0,
          "normal list preserves package order and names");

    free_package_list(pkgs, pkg_count);
    fclose(stream);
}

static void test_legacy_status_list(void)
{
    FILE *stream = fixture_stream(
        "foo\tinstall ok installed\n"
        "bar\tdeinstall ok config-files\n");
    check(stream != NULL, "fixture: legacy package list opens");
    if (stream == NULL)
        return;

    char **pkgs = NULL;
    int pkg_count = 0;
    int had_error = 0;
    read_package_list(stream, &pkgs, &pkg_count, &had_error);

    check(had_error == 0, "legacy list leaves had_error clear");
    check(pkg_count == 1 && strcmp(pkgs[0], "foo") == 0,
          "legacy install entry is kept and deinstall entry is skipped");

    free_package_list(pkgs, pkg_count);
    fclose(stream);
}

static void test_option_shaped_tokens(void)
{
    FILE *stream = fixture_stream("vim\n-y\n--purge\ngit\n");
    check(stream != NULL, "fixture: option-shaped package list opens");
    if (stream == NULL)
        return;

    char **pkgs = NULL;
    int pkg_count = 0;
    int had_error = 0;
    read_package_list(stream, &pkgs, &pkg_count, &had_error);

    check(had_error == 0, "rejected option-shaped tokens are not read errors");
    check(pkg_count == 2 && strcmp(pkgs[0], "vim") == 0 &&
              strcmp(pkgs[1], "git") == 0,
          "option-shaped tokens never enter the package list");

    free_package_list(pkgs, pkg_count);
    fclose(stream);
}

static void test_growth(void)
{
    FILE *stream = tmpfile();
    check(stream != NULL, "fixture: growth package list opens");
    if (stream == NULL)
        return;

    int fixture_ok = 1;
    for (int i = 0; i < 300; i++)
    {
        if (fprintf(stream, "pkg-%03d\n", i) < 0)
        {
            fixture_ok = 0;
            break;
        }
    }
    if (fixture_ok && (fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0))
        fixture_ok = 0;
    check(fixture_ok, "fixture: growth list is written and rewound");
    if (!fixture_ok)
    {
        fclose(stream);
        return;
    }

    char **pkgs = NULL;
    int pkg_count = 0;
    int had_error = 0;
    read_package_list(stream, &pkgs, &pkg_count, &had_error);

    int contents_ok = pkg_count == 300;
    for (int i = 0; contents_ok && i < pkg_count; i++)
    {
        char expected[16];
        snprintf(expected, sizeof(expected), "pkg-%03d", i);
        if (strcmp(pkgs[i], expected) != 0)
            contents_ok = 0;
    }
    check(had_error == 0, "growth path leaves had_error clear");
    check(contents_ok, "growth path preserves more than 256 packages in order");

    free_package_list(pkgs, pkg_count);
    fclose(stream);
}

static void test_stream_error(void)
{
    int fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(fd >= 0, "fixture: directory fd opens for stream-error case");
    if (fd < 0)
        return;

    FILE *stream = fdopen(fd, "r");
    check(stream != NULL, "fixture: directory fd becomes a readable stream");
    if (stream == NULL)
    {
        close(fd);
        return;
    }

    char **pkgs = NULL;
    int pkg_count = 0;
    int had_error = 0;
    read_package_list(stream, &pkgs, &pkg_count, &had_error);

    check(ferror(stream) != 0, "fixture: directory read produces a stream error");
    check(had_error == 1, "stream read error sets had_error");
    check(pkg_count == 0, "stream read error does not invent package entries");

    free_package_list(pkgs, pkg_count);
    fclose(stream);
}

int main(void)
{
    printf(BLUE "::" NC " package_token_is_safe (unit)\n");
    check(package_token_is_safe("vim") == 1, "a plain package name is safe");
    check(package_token_is_safe("lib32-glibc") == 1,
          "a name with digits/hyphen is safe");
    check(package_token_is_safe("-y") == 0,
          "a token starting with '-' is rejected");
    check(package_token_is_safe("--purge") == 0,
          "a long-option-shaped token is rejected");
    check(package_token_is_safe("") == 0, "an empty token is rejected");
    check(package_token_is_safe(NULL) == 0, "a NULL token is rejected");

    printf(BLUE "::" NC " read_package_list (unit)\n");
    test_normal_list();
    test_legacy_status_list();
    test_option_shaped_tokens();
    test_growth();
    test_stream_error();

    printf("packages tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
