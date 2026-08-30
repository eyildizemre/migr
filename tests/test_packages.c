#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "detect.h"
#include "packages.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

// Intercepts malloc() by exact requested size, not call order: restore_packages()
// makes many incidental allocations (detect_distro(), read_package_list()'s own
// growth, strdup() per package) before reaching the one this simulates failing.
// Matching by size lets the fixture pick a size no ordinary allocation in that
// path would plausibly produce, without needing to know or preserve a call count.
static size_t wrap_malloc_target_size;
static int wrap_malloc_fired;

extern void *__real_malloc(size_t size);

void *__wrap_malloc(size_t size)
{
    if (wrap_malloc_target_size != 0 && size == wrap_malloc_target_size &&
        !wrap_malloc_fired)
    {
        wrap_malloc_fired = 1;
        return NULL;
    }
    return __real_malloc(size);
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

static void test_restore_packages_batch_alloc_failure_is_reported(void)
{
    printf(BLUE "::" NC " restore_packages reports an error when the batch argv allocation fails\n");

    distro_t distro = detect_distro();
    if (distro == DISTRO_UNKNOWN)
    {
        printf("  " BLUE "-" NC " unrecognized distro in this environment -- restore_packages()'s batch-install path is unreachable here, skipping\n");
        return;
    }

    // Mirrors restore_packages()'s own switch purely to compute the exact
    // batch_argv size it will request; not a duplicate of any decision logic.
    int prefix;
    switch (distro)
    {
        case DISTRO_DEBIAN: prefix = 5; break;
        case DISTRO_FEDORA: prefix = 4; break;
        case DISTRO_ARCH:   prefix = 5; break;
        default:            prefix = 0; break;
    }
    if (prefix == 0)
        return;

    char dir_path[] = "/tmp/migr_packages_alloc_fail_XXXXXX";
    char *dir = mkdtemp(dir_path);
    check(dir != NULL, "fixture: temp container directory is created");
    if (dir == NULL)
        return;

    char pkg_path[PATH_MAX];
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", dir_path);
    FILE *pkg_file = fopen(pkg_path, "w");
    check(pkg_file != NULL, "fixture: packages.txt is created");
    if (pkg_file == NULL)
    {
        rmdir(dir_path);
        return;
    }

    enum { PKG_COUNT = 4096 };
    for (int i = 0; i < PKG_COUNT; i++)
        fprintf(pkg_file, "pkg%d\n", i);
    fclose(pkg_file);

    int dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(dir_fd >= 0, "fixture: container directory opens");
    if (dir_fd < 0)
    {
        unlink(pkg_path);
        rmdir(dir_path);
        return;
    }

    wrap_malloc_target_size = (size_t)(prefix + PKG_COUNT + 1) * sizeof(char *);
    wrap_malloc_fired = 0;

    int had_error = 0;
    restore_packages(dir_fd, "/tmp", &had_error);

    wrap_malloc_target_size = 0;

    check(wrap_malloc_fired,
          "fixture: the simulated batch-argv allocation failure actually fired");
    check(had_error == 1,
          "restore_packages reports an error instead of silently claiming 0 installed, 0 skipped");

    close(dir_fd);
    unlink(pkg_path);
    rmdir(dir_path);
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

    printf(BLUE "::" NC " restore_packages (unit)\n");
    test_restore_packages_batch_alloc_failure_is_reported();

    printf("packages tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
