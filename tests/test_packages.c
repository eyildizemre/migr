#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "detect.h"
#include "packages.h"
#include "groups.h"
#include "flatpak.h"
#include "utils.h"

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
static int write_text(const char *path, const char *text);

typedef struct {
    distro_t distro;
    const char *const *expected_prefix;
    size_t expected_prefix_count;
    const char *const *forbidden_tokens;
    size_t forbidden_token_count;
    // What the system has before the install transaction (NULL: nothing)
    // and after it, and which of its packages are explicitly installed
    // (NULL: none).
    const char *installed_before;
    const char *installed_output;
    const char *explicit_output;
    const char *available_output;
    int run_result;
    size_t call_count;
    size_t max_batch_count;
    size_t installed_query_count;
    size_t explicit_query_count;
    size_t availability_query_count;
    size_t mark_count;
    char marked[256];
    int prefix_ok;
    int forbidden_seen;
    int capture_ok;
} PackageRunFixture;

static size_t argv_length(char *const argv[])
{
    size_t argc = 0;
    while (argv[argc] != NULL)
        argc++;
    return argc;
}

static int argv_starts_with(char *const argv[], const char *const *prefix,
                            size_t prefix_count)
{
    for (size_t i = 0; i < prefix_count; i++)
        if (argv[i] == NULL || strcmp(argv[i], prefix[i]) != 0)
            return 0;
    return 1;
}

// The mark command per distro, and the names it was given, space-separated.
static int package_mark_fixture(PackageRunFixture *fixture,
                                char *const argv[])
{
    static const char *const debian_mark[] = {"apt-mark", "manual"};
    static const char *const fedora_mark[] = {"dnf", "-y", "-q", "mark",
                                              "user"};
    static const char *const arch_mark[] = {"pacman", "-D", "--asexplicit"};
    const char *const *prefix = fixture->distro == DISTRO_DEBIAN ? debian_mark
        : fixture->distro == DISTRO_FEDORA ? fedora_mark : arch_mark;
    size_t prefix_count = fixture->distro == DISTRO_DEBIAN ? 2U
        : fixture->distro == DISTRO_FEDORA ? 5U : 3U;
    if (!argv_starts_with(argv, prefix, prefix_count))
        return 0;
    fixture->mark_count++;
    for (size_t i = prefix_count; argv[i] != NULL; i++)
    {
        size_t used = strlen(fixture->marked);
        snprintf(fixture->marked + used, sizeof(fixture->marked) - used,
                 "%s%s", used != 0 ? " " : "", argv[i]);
    }
    return 1;
}

static int package_run_fixture(char *const argv[], void *context)
{
    PackageRunFixture *fixture = context;
    fixture->call_count++;

    size_t argc = argv_length(argv);

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
        for (size_t j = 0; j < fixture->forbidden_token_count; j++)
            if (strcmp(argv[i], fixture->forbidden_tokens[j]) == 0)
                fixture->forbidden_seen = 1;

    return fixture->run_result;
}

static int package_capture_fixture(char *const argv[], char *output,
                                   size_t output_size, void *context)
{
    PackageRunFixture *fixture = context;
    const char *text = NULL;
    // Before the install transaction runs, the system has what it had.
    const char *installed = fixture->call_count == 0
        ? (fixture->installed_before != NULL ? fixture->installed_before : "")
        : fixture->installed_output;
    char *const *explicit_query = get_package_cmd(fixture->distro);

    if (explicit_query != NULL &&
        argv_length(argv) == argv_length(explicit_query) &&
        argv_starts_with(argv, (const char *const *)explicit_query,
                         argv_length(explicit_query)))
    {
        fixture->explicit_query_count++;
        text = fixture->explicit_output != NULL ? fixture->explicit_output : "";
    }
    else if (package_mark_fixture(fixture, argv))
        text = "";
    else if (fixture->distro == DISTRO_DEBIAN &&
        strcmp(argv[0], "dpkg-query") == 0 &&
        argv[1] != NULL && strcmp(argv[1], "-W") == 0 &&
        argv[2] != NULL &&
        strcmp(argv[2],
               "-f=${Package}\\t${binary:Package}\\t${db:Status-Status}\\n") == 0 &&
        argv[3] == NULL)
    {
        fixture->installed_query_count++;
        text = installed;
    }
    else if (fixture->distro == DISTRO_FEDORA &&
             strcmp(argv[0], "rpm") == 0 &&
             argv[1] != NULL && strcmp(argv[1], "-qa") == 0 &&
             argv[2] != NULL && strcmp(argv[2], "--qf") == 0 &&
             argv[3] != NULL && strcmp(argv[3], "%{NAME}\\n") == 0 &&
             argv[4] == NULL)
    {
        fixture->installed_query_count++;
        text = installed;
    }
    else if (fixture->distro == DISTRO_ARCH &&
             strcmp(argv[0], "pacman") == 0 &&
             argv[1] != NULL && strcmp(argv[1], "-Qq") == 0 &&
             argv[2] == NULL)
    {
        fixture->installed_query_count++;
        text = installed;
    }
    else if ((fixture->distro == DISTRO_ARCH &&
              strcmp(argv[0], "pacman") == 0 &&
              argv[1] != NULL && strcmp(argv[1], "-Slq") == 0 &&
              argv[2] == NULL) ||
             (fixture->distro == DISTRO_DEBIAN &&
              strcmp(argv[0], "apt-cache") == 0 &&
              argv[1] != NULL && strcmp(argv[1], "pkgnames") == 0 &&
              argv[2] == NULL))
    {
        fixture->availability_query_count++;
        text = fixture->available_output;
    }
    else
    {
        fixture->capture_ok = 0;
        return -1;
    }

    if (text == NULL || strlen(text) >= output_size)
    {
        fixture->capture_ok = 0;
        return -1;
    }
    memcpy(output, text, strlen(text) + 1U);
    return 0;
}

typedef struct {
    int had_error;
    int skipped_exists;
    int skipped_matches;
} PackageRestoreCaseResult;

// Whether the package and Flatpak restores below run with a network (D90).
static int restore_online = 1;

// Runs restore_packages() on contents. expected_skipped lists, one per
// line, the packages the todo must name as not installed; NULL means none.
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
    snprintf(pkg_path, sizeof(pkg_path), "%s/packages.txt", dir);
    int dir_fd = -1;
    char *todo_text = NULL;
    size_t todo_size = 0;
    FILE *todo = NULL;
    if (write_text(pkg_path, contents) != 0 ||
        (dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0 ||
        (todo = open_memstream(&todo_text, &todo_size)) == NULL)
    {
        if (dir_fd >= 0)
            close(dir_fd);
        unlink(pkg_path);
        rmdir(dir);
        return 0;
    }

    runner->distro = distro;
    runner->prefix_ok = 1;
    runner->capture_ok = 1;
    packages_test_set_restore_hooks(distro, package_run_fixture,
                                    package_capture_fixture, runner);
    result->had_error = 0;
    restore_packages(dir_fd, restore_online, todo, &result->had_error);
    packages_test_clear_restore_hooks();
    close(dir_fd);
    fclose(todo);

    // The todo names the packages on one line, as "    a b c".
    char expected[8192] = "    ";
    for (const char *p = expected_skipped; p != NULL && *p != '\0'; p++)
    {
        size_t used = strlen(expected);
        if (used + 2U < sizeof(expected))
        {
            expected[used] = *p == '\n' ? (p[1] != '\0' ? ' ' : '\n') : *p;
            expected[used + 1U] = '\0';
        }
    }
    size_t text_length = strlen(todo_text);
    size_t expected_length = strlen(expected);
    result->skipped_exists = text_length != 0;
    result->skipped_matches = expected_skipped != NULL
        ? strstr(todo_text, restore_online
                                ? "could not install"
                                : "to install once this system is online") !=
                  NULL &&
              text_length >= expected_length &&
              strcmp(todo_text + text_length - expected_length, expected) == 0
        : !result->skipped_exists;

    free(todo_text);
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

    // A destination that cannot store the list fails the write: nothing
    // truncated is left, and it does not read as an empty list.
    struct rlimit limit, small;
    check(getrlimit(RLIMIT_FSIZE, &limit) == 0, "fixture: read the file size limit");
    small = limit;
    small.rlim_cur = 4;
    void (*previous)(int) = signal(SIGXFSZ, SIG_IGN);
    check(setrlimit(RLIMIT_FSIZE, &small) == 0, "fixture: cap the file size");
    rc = write_container_text_file_at(dir_fd, "snapshot.txt", snapshot);
    int saved = errno;
    check(setrlimit(RLIMIT_FSIZE, &limit) == 0, "fixture: restore the file size limit");
    signal(SIGXFSZ, previous);
    check(rc == -1 && saved == EFBIG && access(snapshot_path, F_OK) != 0,
          "a failed write is an error with its cause, and leaves no truncated list");

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
    printf(BLUE "::" NC " restore_packages uses one native install transaction\n");

    static const char *const debian_prefix[] = {
        "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
        "-m"
    };
    static const char *const fedora_prefix[] = {
        "dnf", "install", "-y", "--skip-unavailable"
    };
    static const char *const arch_prefix[] = {
        "pacman", "-S", "--needed", "--noconfirm"
    };
    struct {
        distro_t distro;
        const char *name;
        const char *const *prefix;
        size_t prefix_count;
        const char *installed_output;
        const char *available_output;
        size_t expected_availability_queries;
    } cases[] = {
        { DISTRO_DEBIAN, "Debian", debian_prefix,
          sizeof(debian_prefix) / sizeof(debian_prefix[0]),
          "alpha\talpha\tinstalled\nbeta\tbeta\tinstalled\n", "alpha\nbeta\n",
          1U },
        { DISTRO_FEDORA, "Fedora", fedora_prefix,
          sizeof(fedora_prefix) / sizeof(fedora_prefix[0]),
          "alpha\nbeta\n", NULL, 0U },
        { DISTRO_ARCH, "Arch", arch_prefix,
          sizeof(arch_prefix) / sizeof(arch_prefix[0]),
          "alpha\nbeta\n", "alpha\nbeta\n", 1U },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        PackageRunFixture runner = {
            .expected_prefix = cases[i].prefix,
            .expected_prefix_count = cases[i].prefix_count,
            .installed_output = cases[i].installed_output,
            .available_output = cases[i].available_output,
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
                 "%s reads installed state before and after the transaction",
                 cases[i].name);
        check(runner.capture_ok && runner.installed_query_count == 2U &&
                  runner.availability_query_count ==
                      cases[i].expected_availability_queries,
              label);
        snprintf(label, sizeof(label),
                 "%s successful batch leaves nothing to do by hand",
                 cases[i].name);
        check(result.had_error == 0 && result.skipped_matches, label);
    }
}

static int fixture_append_line(char *buffer, size_t capacity, size_t *used,
                               const char *line)
{
    int written = snprintf(buffer + *used, capacity - *used, "%s\n", line);
    if (written < 0 || (size_t)written >= capacity - *used)
        return -1;
    *used += (size_t)written;
    return 0;
}

static int fixture_index_is_unavailable(int index, const int *indices,
                                        size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (indices[i] == index)
            return 1;
    return 0;
}

static void test_restore_packages_sparse_unavailable(distro_t distro,
                                                     const char *name,
                                                     const char *const *prefix,
                                                     size_t prefix_count)
{
    enum { PKG_COUNT = 455, UNAVAILABLE_COUNT = 14 };
    static const int unavailable_indices[UNAVAILABLE_COUNT] = {
        7, 23, 51, 78, 104, 137, 169, 203, 241, 277, 309, 344, 389, 431
    };
    char package_names[PKG_COUNT][16];
    const char *unavailable[UNAVAILABLE_COUNT];
    char packages[8192] = {0};
    char installed[8192] = {0};
    char expected_skipped[512] = {0};
    size_t packages_used = 0, installed_used = 0, skipped_used = 0;
    size_t unavailable_used = 0;
    int fixture_ok = 1;

    for (int i = 0; i < PKG_COUNT; i++)
    {
        snprintf(package_names[i], sizeof(package_names[i]), "pkg-%03d", i);
        if (fixture_append_line(packages, sizeof(packages), &packages_used,
                                package_names[i]) != 0)
            fixture_ok = 0;
        if (fixture_index_is_unavailable(
                i, unavailable_indices, UNAVAILABLE_COUNT))
        {
            unavailable[unavailable_used++] = package_names[i];
            if (fixture_append_line(expected_skipped,
                                    sizeof(expected_skipped), &skipped_used,
                                    package_names[i]) != 0)
                fixture_ok = 0;
        }
        else if (fixture_append_line(installed, sizeof(installed),
                                     &installed_used, package_names[i]) != 0)
            fixture_ok = 0;
    }
    check(fixture_ok && unavailable_used == UNAVAILABLE_COUNT,
          "fixture: 455-package sparse-unavailable set is constructed");
    if (!fixture_ok || unavailable_used != UNAVAILABLE_COUNT)
        return;

    PackageRunFixture runner = {
        .expected_prefix = prefix,
        .expected_prefix_count = prefix_count,
        .forbidden_tokens = distro == DISTRO_ARCH ? unavailable : NULL,
        .forbidden_token_count = distro == DISTRO_ARCH
            ? UNAVAILABLE_COUNT : 0U,
        .installed_output = installed,
        .available_output = distro == DISTRO_ARCH ? installed : NULL,
    };
    PackageRestoreCaseResult result = {0};
    fixture_ok = run_restore_packages_case(
        distro, packages, &runner, expected_skipped, &result);
    char label[192];

    snprintf(label, sizeof(label),
             "%s sparse-unavailable fixture runs", name);
    check(fixture_ok, label);
    if (!fixture_ok)
        return;

    snprintf(label, sizeof(label),
             "%s keeps the single install on the canonical package-manager prefix",
             name);
    check(runner.prefix_ok && runner.call_count == 1U, label);
    snprintf(label, sizeof(label),
             "%s sends the expected number of targets in its only install call",
             name);
    check(runner.max_batch_count ==
              (distro == DISTRO_ARCH
                   ? PKG_COUNT - UNAVAILABLE_COUNT : PKG_COUNT),
          label);
    snprintf(label, sizeof(label),
             "%s reads installed state before and after, with no adaptive "
             "retries", name);
    check(runner.installed_query_count == 2U &&
              runner.availability_query_count ==
                  (distro == DISTRO_ARCH ? 1U : 0U),
          label);
    snprintf(label, sizeof(label),
             "%s leaves exactly the 14 packages absent from final state to "
             "do by hand", name);
    check(result.had_error == 0 && result.skipped_exists &&
              result.skipped_matches,
          label);
    if (distro == DISTRO_ARCH)
        check(!runner.forbidden_seen,
              "Arch omits unavailable sync-db targets from the one install transaction");
}

static void test_restore_packages_single_pass_accounting(void)
{
    printf(BLUE "::" NC " restore_packages derives skips from final package state\n");

    static const char *const fedora_prefix[] = {
        "dnf", "install", "-y", "--skip-unavailable"
    };
    static const char *const arch_prefix[] = {
        "pacman", "-S", "--needed", "--noconfirm"
    };

    test_restore_packages_sparse_unavailable(
        DISTRO_FEDORA, "Fedora", fedora_prefix,
        sizeof(fedora_prefix) / sizeof(fedora_prefix[0]));
    test_restore_packages_sparse_unavailable(
        DISTRO_ARCH, "Arch", arch_prefix,
        sizeof(arch_prefix) / sizeof(arch_prefix[0]));

    PackageRunFixture failed_transaction = {
        .expected_prefix = fedora_prefix,
        .expected_prefix_count = sizeof(fedora_prefix) /
                                 sizeof(fedora_prefix[0]),
        .installed_output = "alpha\ngamma\n",
        .run_result = 1,
    };
    PackageRestoreCaseResult failed_result = {0};
    int fixture_ok = run_restore_packages_case(
        DISTRO_FEDORA, "alpha\nbeta\ngamma\n", &failed_transaction,
        "beta\n", &failed_result);
    check(fixture_ok,
          "nonzero install-transaction fixture runs");
    check(fixture_ok && failed_transaction.call_count == 1U &&
              failed_transaction.installed_query_count == 2U &&
              failed_result.had_error == 0 && failed_result.skipped_matches,
          "a non-availability install failure is classified from final state, not command exit status");

    static const char *const unavailable_preinstalled[] = {"beta"};
    PackageRunFixture preinstalled = {
        .expected_prefix = arch_prefix,
        .expected_prefix_count = sizeof(arch_prefix) / sizeof(arch_prefix[0]),
        .forbidden_tokens = unavailable_preinstalled,
        .forbidden_token_count = 1U,
        .installed_before = "beta\n",
        .installed_output = "alpha\nbeta\n",
        .explicit_output = "beta\n",
        .available_output = "alpha\n",
    };
    PackageRestoreCaseResult preinstalled_result = {0};
    fixture_ok = run_restore_packages_case(
        DISTRO_ARCH, "alpha\nbeta\n", &preinstalled, NULL,
        &preinstalled_result);
    check(fixture_ok && preinstalled.call_count == 1U &&
              preinstalled.max_batch_count == 1U &&
              !preinstalled.forbidden_seen &&
              preinstalled_result.had_error == 0 &&
              preinstalled_result.skipped_matches,
          "an already-installed Arch package need not be available in sync databases to count as restored");

    static const char *const debian_prefix[] = {
        "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
        "-m"
    };
    PackageRunFixture debian_status = {
        .expected_prefix = debian_prefix,
        .expected_prefix_count = sizeof(debian_prefix) /
                                 sizeof(debian_prefix[0]),
        .installed_before =
            "alpha\talpha\tinstalled\n"
            "beta\tbeta\tconfig-files\n",
        .installed_output =
            "alpha\talpha\tinstalled\n"
            "beta\tbeta\tconfig-files\n",
        .explicit_output = "alpha\n",
        .available_output = "alpha\nbeta\n",
    };
    PackageRestoreCaseResult debian_status_result = {0};
    fixture_ok = run_restore_packages_case(
        DISTRO_DEBIAN, "alpha\nbeta\n", &debian_status, "beta\n",
        &debian_status_result);
    check(fixture_ok && debian_status.installed_query_count == 2U &&
              debian_status.max_batch_count == 1U &&
              debian_status_result.had_error == 0 &&
              debian_status_result.skipped_matches,
          "Debian final-state accounting accepts only installed dpkg states");

    // apt-get refuses a whole install for one name it cannot find.
    static const char *const debian_unavailable[] = {"code"};
    PackageRunFixture debian_filter = {
        .expected_prefix = debian_prefix,
        .expected_prefix_count = sizeof(debian_prefix) /
                                 sizeof(debian_prefix[0]),
        .forbidden_tokens = debian_unavailable,
        .forbidden_token_count = 1U,
        .installed_before = "",
        .installed_output =
            "alpha\talpha\tinstalled\n"
            "libfoo\tlibfoo:i386\tinstalled\n",
        .explicit_output = "",
        .available_output = "alpha\nlibfoo\n",
    };
    PackageRestoreCaseResult debian_filter_result = {0};
    fixture_ok = run_restore_packages_case(
        DISTRO_DEBIAN, "alpha\ncode\nlibfoo:i386\n", &debian_filter,
        "code\n", &debian_filter_result);
    check(fixture_ok && debian_filter.capture_ok &&
              debian_filter.availability_query_count == 1U &&
              debian_filter.call_count == 1U &&
              debian_filter.max_batch_count == 2U &&
              !debian_filter.forbidden_seen &&
              debian_filter_result.skipped_matches,
          "Debian sends apt-get only what its repositories have, foreign "
          "architectures included, and lists the rest");

    PackageRunFixture offline = {
        .expected_prefix = fedora_prefix,
        .expected_prefix_count = sizeof(fedora_prefix) /
                                 sizeof(fedora_prefix[0]),
        .installed_before = "alpha\n",
        .explicit_output = "alpha\n",
    };
    PackageRestoreCaseResult offline_result = {0};
    restore_online = 0;
    fixture_ok = run_restore_packages_case(
        DISTRO_FEDORA, "alpha\nbeta\n", &offline, "beta\n", &offline_result);
    restore_online = 1;
    check(fixture_ok && offline.call_count == 0U &&
              offline.installed_query_count == 1U &&
              offline_result.had_error == 0 && offline_result.skipped_matches,
          "offline, nothing is installed and the missing packages are listed "
          "to install once the system is online");
}

static void test_restore_packages_skips_what_is_installed(void)
{
    printf(BLUE "::" NC " restore_packages leaves installed packages out of "
                "the transaction and marks them explicit\n");

    static const char *const fedora_prefix[] = {
        "dnf", "install", "-y", "--skip-unavailable"
    };
    static const char *const installed_packages[] = {"alpha", "beta"};
    PackageRunFixture partial = {
        .expected_prefix = fedora_prefix,
        .expected_prefix_count = sizeof(fedora_prefix) /
                                 sizeof(fedora_prefix[0]),
        .forbidden_tokens = installed_packages,
        .forbidden_token_count = 2U,
        .installed_before = "alpha\nbeta\n",
        .installed_output = "alpha\nbeta\ngamma\n",
        .explicit_output = "alpha\n",
    };
    PackageRestoreCaseResult result = {0};
    int fixture_ok = run_restore_packages_case(
        DISTRO_FEDORA, "alpha\nbeta\ngamma\n", &partial, NULL, &result);
    check(fixture_ok && partial.call_count == 1U &&
              partial.max_batch_count == 1U && !partial.forbidden_seen &&
              result.had_error == 0 && result.skipped_matches,
          "only the missing package reaches the package manager");
    check(partial.mark_count == 1U && strcmp(partial.marked, "beta") == 0,
          "an installed package not marked explicit is marked, once");

    static const struct {
        distro_t distro;
        const char *name;
        const char *installed;
    } cases[] = {
        { DISTRO_DEBIAN, "Debian",
          "alpha\talpha\tinstalled\nbeta\tbeta\tinstalled\n" },
        { DISTRO_FEDORA, "Fedora", "alpha\nbeta\n" },
        { DISTRO_ARCH, "Arch", "alpha\nbeta\n" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        PackageRunFixture complete = {
            .installed_before = cases[i].installed,
            .explicit_output = "alpha\nbeta\n",
        };
        PackageRestoreCaseResult complete_result = {0};
        fixture_ok = run_restore_packages_case(
            cases[i].distro, "alpha\nbeta\n", &complete, NULL,
            &complete_result);
        char label[160];
        snprintf(label, sizeof(label),
                 "%s with everything installed and marked runs no package "
                 "manager command", cases[i].name);
        check(fixture_ok && complete.capture_ok && complete.call_count == 0U &&
                  complete.mark_count == 0U &&
                  complete.installed_query_count == 1U &&
                  complete.explicit_query_count == 1U &&
                  complete.availability_query_count == 0U &&
                  complete_result.had_error == 0 &&
                  complete_result.skipped_matches,
              label);

        PackageRunFixture unmarked = {
            .installed_before = cases[i].installed,
            .explicit_output = "",
        };
        PackageRestoreCaseResult unmarked_result = {0};
        fixture_ok = run_restore_packages_case(
            cases[i].distro, "alpha\nbeta\n", &unmarked, NULL,
            &unmarked_result);
        snprintf(label, sizeof(label),
                 "%s marks installed packages with its own command",
                 cases[i].name);
        check(fixture_ok && unmarked.capture_ok && unmarked.call_count == 0U &&
                  unmarked.mark_count == 1U &&
                  strcmp(unmarked.marked, "alpha beta") == 0 &&
                  unmarked_result.had_error == 0,
              label);
    }
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
        "dnf", "install", "-y", "--skip-unavailable"
    };
    PackageRunFixture runner = {
        .distro = DISTRO_FEDORA,
        .expected_prefix = fedora_prefix,
        .expected_prefix_count = sizeof(fedora_prefix) / sizeof(fedora_prefix[0]),
        .installed_output = "",
    };
    packages_test_set_restore_hooks(DISTRO_FEDORA, package_run_fixture,
                                    package_capture_fixture, &runner);
    int had_error = 0;
    FILE *todo = tmpfile();
    restore_packages(dir_fd, 1, todo, &had_error);
    packages_test_clear_restore_hooks();
    if (todo != NULL)
        fclose(todo);

    wrap_malloc_target_size = 0;

    check(wrap_malloc_fired,
          "fixture: the simulated batch-argv allocation failure actually fired");
    check(had_error == 1,
          "restore_packages reports an error instead of silently claiming 0 installed, 0 skipped");

    close(dir_fd);
    unlink(pkg_path);
    rmdir(dir_path);
}

static void test_kernel_pinned_packages_are_dropped(void)
{
    printf(BLUE "::" NC " kernel-pinned module packages are left out of the list\n");
    char buffer[] =
        "akmod-nvidia\n"
        "kmod-nvidia-7.1.13-200.fc44.x86_64\n"
        "kmod-nvidia\n"
        "kernel-core\n"
        "kmod-v4l2loopback-7.2.5-200.fc44.aarch64\n"
        "kmodtool\n"
        "nvidia-kmod-common\n";
    int count = packages_test_drop_kernel_pinned(buffer);
    check(count == 5 &&
              strcmp(buffer, "akmod-nvidia\nkmod-nvidia\nkernel-core\n"
                             "kmodtool\nnvidia-kmod-common\n") == 0,
          "per-kernel kmod-* builds are dropped; akmod and meta packages stay");
    char unterminated[] = "bash\nkmod-zfs-6.1.0-1.el9.x86_64";
    check(packages_test_drop_kernel_pinned(unterminated) == 1 &&
              strcmp(unterminated, "bash\n") == 0,
          "an unterminated final kernel-pinned line is dropped too");
}

static int write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return -1;
    int ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok ? 0 : -1;
}

static void test_groups_collect(void)
{
    printf(BLUE "::" NC " groups_collect (unit)\n");
    char path[] = "/tmp/migr_group_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
    {
        check(0, "group fixture is created");
        return;
    }
    close(fd);

    check(write_text(path,
                     "root:x:0:\n"
                     "wheel:x:10:eyildizemre,other\n"
                     "libvirt:x:970:eyildizemre\n"
                     "docker:x:971:bob\n"
                     "eyildizemre:x:1000:\n"
                     "not a group line\n"
                     "bad,name:x:5:eyildizemre\n"
                     "-G:x:6:eyildizemre\n"
                     "extra:x:8:eyildizemre,other:more\n"
                     "eyildizemre2:x:7:eyildizemre2\n"
                     "short:x:9:ale\n"
                     "badgid:x:9x:eyildizemre\n"
                     "twice:x:20:\n"
                     "twice:x:21:\n"
                     "dialout:x:18:bob,eyildizemre") == 0,
          "group fixture is written");
    groups_test_set_group_file(path);
    char *groups = groups_collect("eyildizemre");
    check(groups != NULL && strcmp(groups, "wheel\nlibvirt\ndialout\n") == 0,
          "only groups whose member list names the user are listed, in file "
          "order, without malformed lines or unsafe names");
    free(groups);

    groups = groups_collect("carol");
    check(groups != NULL && groups[0] == '\0',
          "a user in no group gets an empty list, not a failure");
    free(groups);

    gid_t gid = 0;
    check(local_group_gid("libvirt", &gid) == 0 && gid == 970,
          "a group's gid is looked up by its name");
    check(local_group_gid("twice", &gid) != 0 &&
              local_group_gid("nosuch", &gid) != 0 &&
              local_group_gid("badgid", &gid) != 0,
          "a group listed twice, absent, or with a malformed gid has none");

    unlink(path);
    check(groups_collect("eyildizemre") == NULL &&
              local_group_gid("libvirt", &gid) != 0,
          "an unreadable group file yields no list and no gid");
    groups_test_set_group_file(NULL);
}

typedef struct {
    int calls;
    int result;
    char argv_text[512];
} GroupRunFixture;

static int group_run_fixture(char *const argv[], void *context)
{
    GroupRunFixture *fixture = context;
    fixture->calls++;
    fixture->argv_text[0] = '\0';
    for (size_t i = 0; argv[i] != NULL; i++)
    {
        size_t used = strlen(fixture->argv_text);
        snprintf(fixture->argv_text + used, sizeof(fixture->argv_text) - used,
                 "%s%s", i == 0 ? "" : " ", argv[i]);
    }
    return fixture->result;
}

typedef void (*RestoreStep)(int dir_fd, FILE *todo, int *had_error,
                            void *context);

// What a restore step left to do by hand in the last run_control_file_case().
static char last_todo[2048];

// Runs step against a container holding leaf with contents (none when NULL),
// capturing what it prints and its todo. Returns had_error, or -1 when the
// fixture could not be built.
static int run_control_file_case(const char *leaf, const char *contents,
                                 RestoreStep step, void *context,
                                 char *output, size_t output_size)
{
    last_todo[0] = '\0';
    char dir[] = "/tmp/migr_control_restore_XXXXXX";
    if (mkdtemp(dir) == NULL)
        return -1;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, leaf);
    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    FILE *captured = tmpfile();
    int saved_stdout = dup(STDOUT_FILENO);
    int ready = dir_fd >= 0 && captured != NULL && saved_stdout >= 0 &&
                (contents == NULL || write_text(path, contents) == 0);

    int had_error = -1;
    if (ready)
    {
        fflush(stdout);
        dup2(fileno(captured), STDOUT_FILENO);
        had_error = 0;
        FILE *todo = fmemopen(last_todo, sizeof(last_todo), "w");
        step(dir_fd, todo, &had_error, context);
        if (todo != NULL)
            fclose(todo);
        fflush(stdout);
        dup2(saved_stdout, STDOUT_FILENO);

        size_t length = 0;
        if (fseek(captured, 0, SEEK_SET) == 0)
            length = fread(output, 1, output_size - 1U, captured);
        output[length] = '\0';
    }

    if (saved_stdout >= 0)
        close(saved_stdout);
    if (captured != NULL)
        fclose(captured);
    if (dir_fd >= 0)
        close(dir_fd);
    unlink(path);
    rmdir(dir);
    return had_error;
}

static void restore_groups_step(int dir_fd, FILE *todo, int *had_error,
                                void *context)
{
    restore_groups(dir_fd, context, todo, had_error);
}

// Runs restore_groups() for user against a target group file.
static int run_restore_groups_case(const char *groups_txt,
                                   const char *group_file, const char *user,
                                   GroupRunFixture *runner,
                                   char *output, size_t output_size)
{
    char group_path[] = "/tmp/migr_group_target_XXXXXX";
    int fd = mkstemp(group_path);
    if (fd < 0)
        return -1;
    close(fd);
    int rc = -1;
    if (write_text(group_path, group_file) == 0)
    {
        packages_test_set_restore_hooks(DISTRO_FEDORA, group_run_fixture, NULL,
                                        runner);
        groups_test_set_group_file(group_path);
        rc = run_control_file_case("groups.txt", groups_txt,
                                   restore_groups_step, (void *)user, output,
                                   output_size);
        packages_test_clear_restore_hooks();
        groups_test_set_group_file(NULL);
    }
    unlink(group_path);
    return rc;
}

static void test_restore_groups(void)
{
    printf(BLUE "::" NC " restore_groups (unit)\n");
    const char *saved = "wheel\nlibvirt\ndialout\nmedia\n-G\nbad,name\n";
    const char *target = "wheel:x:10:eyildizemre\n"
                         "libvirt:x:970:\n"
                         "dialout:x:18:bob\n";
    char output[1024];
    GroupRunFixture runner = {0};

    int rc = run_restore_groups_case(saved, target, "eyildizemre", &runner, output,
                                     sizeof(output));
    check(rc == 0 && runner.calls == 1 &&
              strcmp(runner.argv_text,
                     "usermod -a -G libvirt,dialout -- eyildizemre") == 0,
          "the user is added in one usermod to the saved groups the system "
          "has and does not list them in yet");
    check(strstr(output, "Added eyildizemre to libvirt, dialout. This takes effect "
                         "at the next login.") != NULL &&
              strstr(output, "Left out, not on this system: media.") != NULL &&
              strstr(last_todo, "    sudo usermod -a -G media eyildizemre\n") !=
                  NULL,
          "the summary names the groups added and the ones this system "
          "lacks, with the command for later, and skips saved names no "
          "system could have");

    memset(&runner, 0, sizeof(runner));
    dry_run = 1;
    rc = run_restore_groups_case(saved, target, "eyildizemre", &runner, output,
                                 sizeof(output));
    dry_run = 0;
    check(rc == 0 && runner.calls == 0 &&
              strstr(output, "Would add eyildizemre to libvirt, dialout.") != NULL,
          "a dry run says which groups it would add and runs nothing");

    memset(&runner, 0, sizeof(runner));
    runner.result = 6;
    rc = run_restore_groups_case(saved, target, "eyildizemre", &runner, output,
                                 sizeof(output));
    check(rc == 1 && runner.calls == 1,
          "a failed usermod fails the step");

    memset(&runner, 0, sizeof(runner));
    rc = run_restore_groups_case("wheel\n", target, "eyildizemre", &runner, output,
                                 sizeof(output));
    check(rc == 0 && runner.calls == 0 &&
              strstr(output, "already in every saved group") != NULL,
          "nothing runs when the user is already in every saved group");

    memset(&runner, 0, sizeof(runner));
    rc = run_restore_groups_case(saved, target, NULL, &runner, output,
                                 sizeof(output));
    check(rc == 1 && runner.calls == 0,
          "an unresolved user fails the step without running usermod");

    memset(&runner, 0, sizeof(runner));
    rc = run_restore_groups_case("", target, NULL, &runner, output,
                                 sizeof(output));
    check(rc == 0 && runner.calls == 0 &&
              strstr(output, "saved no group memberships") != NULL,
          "an empty list needs no user and changes nothing");

    memset(&runner, 0, sizeof(runner));
    rc = run_restore_groups_case(NULL, target, "eyildizemre", &runner, output,
                                 sizeof(output));
    check(rc == 0 && runner.calls == 0 && output[0] == '\0',
          "a backup without groups.txt is skipped silently");
}

typedef struct {
    const char *remotes; /* NULL: flatpak is not installed. */
    const char *installed_before;
    const char *installed_after;
    int installs;
    char install_argv[3][256];
} FlatpakFixture;

static int flatpak_capture_fixture(char *const argv[], char *output,
                                   size_t output_size, void *context)
{
    FlatpakFixture *fixture = context;
    const char *text = NULL;
    if (strcmp(argv[1], "remotes") == 0)
        text = fixture->remotes;
    else if (strcmp(argv[1], "list") == 0)
        text = fixture->installs == 0 ? fixture->installed_before
                                      : fixture->installed_after;
    if (text == NULL)
        return 1;
    snprintf(output, output_size, "%s", text);
    return 0;
}

static int flatpak_run_fixture(char *const argv[], void *context)
{
    FlatpakFixture *fixture = context;
    if (fixture->installs < 3)
    {
        char *joined = fixture->install_argv[fixture->installs];
        joined[0] = '\0';
        for (size_t i = 0; argv[i] != NULL; i++)
        {
            size_t used = strlen(joined);
            snprintf(joined + used, 256U - used, "%s%s", i == 0 ? "" : " ",
                     argv[i]);
        }
    }
    fixture->installs++;
    return 0;
}

static void restore_flatpak_step(int dir_fd, FILE *todo, int *had_error,
                                 void *context)
{
    (void)context;
    restore_flatpak_apps(dir_fd, restore_online, todo, had_error);
}

static int run_restore_flatpak_case(const char *list, FlatpakFixture *fixture,
                                    char *output, size_t output_size)
{
    packages_test_set_restore_hooks(DISTRO_FEDORA, flatpak_run_fixture,
                                    flatpak_capture_fixture, fixture);
    int rc = run_control_file_case("flatpak-apps.txt", list,
                                   restore_flatpak_step, NULL, output,
                                   output_size);
    packages_test_clear_restore_hooks();
    return rc;
}

static void test_restore_flatpak_apps(void)
{
    printf(BLUE "::" NC " restore_flatpak_apps (unit)\n");
    const char *list = "flathub\tcom.example.A\n"
                       "flathub\tcom.example.B\n"
                       "fedora\torg.example.C\n"
                       "flathub\tcom.example.D\n"
                       "elsewhere\tnet.example.E\n"
                       "elsewhere\tnet.example.G\n"
                       "-x\tnet.example.F\n"
                       "flathub\t--or-update\n";
    char output[2048];
    FlatpakFixture fixture = {
        .remotes = "fedora\nflathub\n",
        .installed_before = "com.example.B\n",
        .installed_after = "com.example.A\ncom.example.B\norg.example.C\n"
    };
    int rc = run_restore_flatpak_case(list, &fixture, output, sizeof(output));
    check(rc == 0 && fixture.installs == 2 &&
              strcmp(fixture.install_argv[0], "flatpak install --system -y "
                     "flathub com.example.A com.example.D") == 0 &&
              strcmp(fixture.install_argv[1], "flatpak install --system -y "
                     "fedora org.example.C") == 0,
          "missing apps are installed with one call per remote the system "
          "has, skipping installed apps and unsafe names");
    const char *hint = strstr(last_todo, "add the remote, then run:\n"
                                         "    sudo flatpak install --system "
                                         "elsewhere net.example.E "
                                         "net.example.G\n");
    check(strstr(output, "2 installed, 1 not installed.") != NULL &&
              strstr(last_todo, "did not install:\n    sudo flatpak install "
                                "--system flathub com.example.D\n") != NULL &&
              hint != NULL &&
              strstr(strstr(hint, "--system elsewhere") + 1,
                     "--system elsewhere") == NULL,
          "the summary names apps that did not install and gives the "
          "command for a remote the system lacks");

    FlatpakFixture dry = fixture;
    dry.installs = 0;
    dry_run = 1;
    rc = run_restore_flatpak_case(list, &dry, output, sizeof(output));
    dry_run = 0;
    check(rc == 0 && dry.installs == 0 &&
              strstr(output, "Would install com.example.A org.example.C "
                             "com.example.D") != NULL,
          "a dry run says what it would install and installs nothing");

    FlatpakFixture offline = fixture;
    offline.installs = 0;
    restore_online = 0;
    rc = run_restore_flatpak_case(list, &offline, output, sizeof(output));
    restore_online = 1;
    check(rc == 0 && offline.installs == 0 &&
              strstr(output, "No network connection; not installing.") !=
                  NULL &&
              strstr(last_todo, "to install once this system is online:\n"
                                "    sudo flatpak install --system flathub "
                                "com.example.A com.example.D\n") != NULL,
          "offline, nothing is installed and the missing apps are listed "
          "with their command");

    FlatpakFixture absent = { .remotes = NULL };
    rc = run_restore_flatpak_case(list, &absent, output, sizeof(output));
    check(rc == 0 && absent.installs == 0 &&
              strstr(output, "Flatpak is not installed here; 6 applications "
                             "left out.") != NULL &&
              strstr(last_todo, "    sudo flatpak install --system flathub "
                                "com.example.A com.example.B "
                                "com.example.D\n") != NULL &&
              strstr(last_todo, "--system fedora org.example.C\n") != NULL,
          "without flatpak the apps are listed, not a failure");

    FlatpakFixture unused = fixture;
    unused.installs = 0;
    rc = run_restore_flatpak_case(NULL, &unused, output, sizeof(output));
    check(rc == 0 && unused.installs == 0 && output[0] == '\0',
          "a backup without flatpak-apps.txt is skipped silently");
}

int main(void)
{
    // A direct sudo run must not aim restores at the invoking user's home
    // (D38); make and test.sh drop SUDO_UID already.
    unsetenv("SUDO_UID");
    test_kernel_pinned_packages_are_dropped();
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
    test_restore_packages_single_pass_accounting();
    test_restore_packages_skips_what_is_installed();
    test_restore_packages_batch_alloc_failure_is_reported();

    test_groups_collect();
    test_restore_groups();
    test_restore_flatpak_apps();

    printf("packages tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
