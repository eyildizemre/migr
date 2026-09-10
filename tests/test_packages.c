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

static int file_equals_text(const char *path, const char *expected);

typedef struct {
    const char *const *expected_prefix;
    size_t expected_prefix_count;
    const char *const *fail_tokens;
    size_t fail_token_count;
    size_t call_count;
    size_t max_batch_count;
    int prefix_ok;
} PackageRunFixture;

static int package_run_fixture(char *const argv[], void *context)
{
    PackageRunFixture *fixture = context;
    fixture->call_count++;

    size_t argc = 0;
    while (argv[argc] != NULL)
        argc++;

    if (argc < fixture->expected_prefix_count)
        fixture->prefix_ok = 0;
    else
    {
        for (size_t i = 0; i < fixture->expected_prefix_count; i++)
            if (strcmp(argv[i], fixture->expected_prefix[i]) != 0)
                fixture->prefix_ok = 0;
    }

    size_t batch_count = argc >= fixture->expected_prefix_count
        ? argc - fixture->expected_prefix_count : 0U;
    if (batch_count > fixture->max_batch_count)
        fixture->max_batch_count = batch_count;

    for (size_t i = fixture->expected_prefix_count; i < argc; i++)
        for (size_t j = 0; j < fixture->fail_token_count; j++)
            if (strcmp(argv[i], fixture->fail_tokens[j]) == 0)
                return 1;

    return 0;
}

typedef struct {
    int had_error;
    int skipped_exists;
    int skipped_matches;
} PackageRestoreCaseResult;

static int run_restore_packages_case(distro_t distro, const char *contents,
                                     PackageRunFixture *runner,
                                     const char *expected_skipped,
                                     PackageRestoreCaseResult *result)
{
    char dir_path[] = "/tmp/migr_packages_restore_XXXXXX";
    char *dir = mkdtemp(dir_path);
    if (dir == NULL)
        return 0;

    char pkg_path[PATH_MAX];
    char skipped_path[PATH_MAX];
    int pkg_path_len = snprintf(pkg_path, sizeof(pkg_path),
                                "%s/packages.txt", dir);
    int skipped_path_len = snprintf(skipped_path, sizeof(skipped_path),
                                    "%s/skipped-packages.txt", dir);
    if (pkg_path_len < 0 || (size_t)pkg_path_len >= sizeof(pkg_path) ||
        skipped_path_len < 0 ||
        (size_t)skipped_path_len >= sizeof(skipped_path))
    {
        rmdir(dir);
        return 0;
    }

    FILE *pkg_file = fopen(pkg_path, "w");
    if (pkg_file == NULL)
    {
        rmdir(dir);
        return 0;
    }
    int fixture_ok = fputs(contents, pkg_file) >= 0 && fclose(pkg_file) == 0;
    if (!fixture_ok)
    {
        unlink(pkg_path);
        rmdir(dir);
        return 0;
    }

    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0)
    {
        unlink(pkg_path);
        rmdir(dir);
        return 0;
    }

    runner->prefix_ok = 1;
    packages_test_set_restore_hooks(distro, package_run_fixture, runner);
    result->had_error = 0;
    restore_packages(dir_fd, dir, &result->had_error);
    packages_test_clear_restore_hooks();
    close(dir_fd);

    result->skipped_exists = access(skipped_path, F_OK) == 0;
    result->skipped_matches = expected_skipped != NULL
        ? file_equals_text(skipped_path, expected_skipped)
        : !result->skipped_exists;

    unlink(skipped_path);
    unlink(pkg_path);
    rmdir(dir);
    return 1;
}

static int file_equals_text(const char *path, const char *expected)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return 0;

    size_t expected_len = strlen(expected);
    char buffer[256];
    if (expected_len >= sizeof(buffer))
    {
        fclose(f);
        return 0;
    }

    size_t n = fread(buffer, 1, sizeof(buffer), f);
    int ok = !ferror(f) && n == expected_len &&
             memcmp(buffer, expected, expected_len) == 0;
    fclose(f);
    return ok;
}

static void test_write_container_text_file_at(void)
{
    printf(BLUE "::" NC " write_container_text_file_at (unit)\n");

    char dir_path[] = "/tmp/migr_container_text_XXXXXX";
    char *dir = mkdtemp(dir_path);
    check(dir != NULL, "fixture: text-artifact container directory is created");
    if (dir == NULL)
        return;

    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(dir_fd >= 0, "fixture: text-artifact container directory opens");
    if (dir_fd < 0)
    {
        rmdir(dir);
        return;
    }

    const char *snapshot = "alpha@1.0\nbeta@2.0\n";
    int rc = write_container_text_file_at(dir_fd, "snapshot.txt", snapshot);
    char snapshot_path[PATH_MAX];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/snapshot.txt", dir);
    check(rc == 0 && file_equals_text(snapshot_path, snapshot),
          "a complete text artifact is created with exact contents");

    rc = write_container_text_file_at(dir_fd, "snapshot.txt", NULL);
    check(rc == 1 && access(snapshot_path, F_OK) != 0,
          "no content clears a stale artifact and reports the tolerable empty state");

    char outside_path[PATH_MAX], hostile_path[PATH_MAX];
    snprintf(outside_path, sizeof(outside_path), "%s/outside.txt", dir);
    snprintf(hostile_path, sizeof(hostile_path), "%s/hostile.txt", dir);
    FILE *outside = fopen(outside_path, "wb");
    check(outside != NULL, "fixture: hardlink target file is created");
    if (outside == NULL)
    {
        close(dir_fd);
        rmdir(dir);
        return;
    }
    fputs("outside-data\n", outside);
    fclose(outside);

    check(link(outside_path, hostile_path) == 0,
          "fixture: hostile control slot is a hardlink");
    rc = write_container_text_file_at(dir_fd, "hostile.txt", "replacement\n");

    struct stat outside_st, hostile_st;
    int separate_inodes = stat(outside_path, &outside_st) == 0 &&
                          stat(hostile_path, &hostile_st) == 0 &&
                          outside_st.st_ino != hostile_st.st_ino;
    check(rc == 0 && separate_inodes &&
              file_equals_text(outside_path, "outside-data\n") &&
              file_equals_text(hostile_path, "replacement\n"),
          "a hostile hardlink is removed, not followed or overwritten");

    unlink(hostile_path);
    unlink(outside_path);
    close(dir_fd);
    rmdir(dir);
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

static void test_restore_packages_batch_prefixes(void)
{
    printf(BLUE "::" NC " restore_packages batches all supported package managers\n");

    static const char *const debian_prefix[] = {
        "sudo", "apt-get", "install", "-y", "-m"
    };
    static const char *const fedora_prefix[] = {
        "sudo", "dnf", "install", "-y"
    };
    static const char *const arch_prefix[] = {
        "sudo", "pacman", "-S", "--needed", "--noconfirm"
    };
    struct {
        distro_t distro;
        const char *name;
        const char *const *prefix;
        size_t prefix_count;
    } cases[] = {
        { DISTRO_DEBIAN, "Debian", debian_prefix,
          sizeof(debian_prefix) / sizeof(debian_prefix[0]) },
        { DISTRO_FEDORA, "Fedora", fedora_prefix,
          sizeof(fedora_prefix) / sizeof(fedora_prefix[0]) },
        { DISTRO_ARCH, "Arch", arch_prefix,
          sizeof(arch_prefix) / sizeof(arch_prefix[0]) },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        PackageRunFixture runner = {
            .expected_prefix = cases[i].prefix,
            .expected_prefix_count = cases[i].prefix_count,
        };
        PackageRestoreCaseResult result = {0};
        int fixture_ok = run_restore_packages_case(
            cases[i].distro, "alpha\nbeta\n", &runner, NULL, &result);
        char label[160];

        snprintf(label, sizeof(label),
                 "%s fixture runs through the package restore path",
                 cases[i].name);
        check(fixture_ok, label);
        if (!fixture_ok)
            continue;

        snprintf(label, sizeof(label),
                 "%s uses one full two-package batch with the canonical prefix",
                 cases[i].name);
        check(runner.prefix_ok && runner.call_count == 1U &&
                  runner.max_batch_count == 2U,
              label);
        snprintf(label, sizeof(label),
                 "%s successful batch creates no skipped-package log",
                 cases[i].name);
        check(result.had_error == 0 && result.skipped_matches, label);
    }
}

static void test_restore_packages_adaptive_isolation(distro_t distro,
                                                     const char *name,
                                                     const char *const *prefix,
                                                     size_t prefix_count)
{
    char packages[1024] = {0};
    size_t used = 0;
    for (int i = 0; i < 32; i++)
    {
        const char *package = i == 7 ? "bad-seven" :
                              i == 23 ? "bad-twenty-three" : NULL;
        char generated[32];
        if (package == NULL)
        {
            snprintf(generated, sizeof(generated), "pkg-%02d", i);
            package = generated;
        }
        int written = snprintf(packages + used, sizeof(packages) - used,
                               "%s\n", package);
        if (written < 0 || (size_t)written >= sizeof(packages) - used)
        {
            check(0, "fixture: adaptive package list fits its buffer");
            return;
        }
        used += (size_t)written;
    }

    static const char *const failures[] = {
        "bad-seven", "bad-twenty-three"
    };
    PackageRunFixture runner = {
        .expected_prefix = prefix,
        .expected_prefix_count = prefix_count,
        .fail_tokens = failures,
        .fail_token_count = sizeof(failures) / sizeof(failures[0]),
    };
    PackageRestoreCaseResult result = {0};
    int fixture_ok = run_restore_packages_case(
        distro, packages, &runner,
        "bad-seven\nbad-twenty-three\n", &result);
    char label[192];

    snprintf(label, sizeof(label),
             "%s adaptive-isolation fixture runs", name);
    check(fixture_ok, label);
    if (!fixture_ok)
        return;

    snprintf(label, sizeof(label),
             "%s keeps every retry on the canonical package-manager prefix",
             name);
    check(runner.prefix_ok, label);
    snprintf(label, sizeof(label),
             "%s starts with the complete package batch", name);
    check(runner.max_batch_count == 32U, label);
    snprintf(label, sizeof(label),
             "%s isolates sparse failures with fewer calls than per-package fallback",
             name);
    check(runner.call_count < 33U, label);
    snprintf(label, sizeof(label),
             "%s records only the two failing package names", name);
    check(result.had_error == 0 && result.skipped_exists &&
              result.skipped_matches,
          label);
}

static void test_restore_packages_adaptive_batching(void)
{
    printf(BLUE "::" NC " restore_packages adaptively isolates failed batches\n");

    static const char *const fedora_prefix[] = {
        "sudo", "dnf", "install", "-y"
    };
    static const char *const arch_prefix[] = {
        "sudo", "pacman", "-S", "--needed", "--noconfirm"
    };

    test_restore_packages_adaptive_isolation(
        DISTRO_FEDORA, "Fedora", fedora_prefix,
        sizeof(fedora_prefix) / sizeof(fedora_prefix[0]));
    test_restore_packages_adaptive_isolation(
        DISTRO_ARCH, "Arch", arch_prefix,
        sizeof(arch_prefix) / sizeof(arch_prefix[0]));
}

static void test_restore_packages_batch_alloc_failure_is_reported(void)
{
    printf(BLUE "::" NC " restore_packages reports an error when the batch argv allocation fails\n");

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

    wrap_malloc_target_size = (size_t)(4 + PKG_COUNT + 1) * sizeof(char *);
    wrap_malloc_fired = 0;

    static const char *const fedora_prefix[] = {
        "sudo", "dnf", "install", "-y"
    };
    PackageRunFixture runner = {
        .expected_prefix = fedora_prefix,
        .expected_prefix_count = sizeof(fedora_prefix) / sizeof(fedora_prefix[0]),
    };
    packages_test_set_restore_hooks(DISTRO_FEDORA, package_run_fixture, &runner);
    int had_error = 0;
    restore_packages(dir_fd, "/tmp", &had_error);
    packages_test_clear_restore_hooks();

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
    test_write_container_text_file_at();

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
    test_restore_packages_batch_prefixes();
    test_restore_packages_adaptive_batching();
    test_restore_packages_batch_alloc_failure_is_reported();

    printf("packages tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
