// Tests for `migr repair` (docs/DECISIONS.md D61): a real portable capture
// has its journal damaged in place, and the repaired copy must parse, keep
// every undamaged item, and verify against its own payload.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "container.h"
#include "manifest.h"
#include "portable.h"
#include "repair.h"
#include "sidecar.h"
#include "utils.h"
#include "verify.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define NC "\033[0m"

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void fatal(const char *message)
{
    printf(RED "fixture: %s" NC "\n", message);
    exit(1);
}

static int remove_cb(const char *path, const struct stat *sb, int typeflag,
                     struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path)
{
    nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static void join(char *out, size_t size, const char *left, const char *right)
{
    if (snprintf(out, size, "%s/%s", left, right) >= (int)size)
        fatal("path too long");
}

static void write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(text);
    if (fd < 0 || write(fd, text, length) != (ssize_t)length || close(fd) != 0)
        fatal("could not write a file");
}

static unsigned char *read_all(const char *path, size_t *length)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0)
        fatal("could not open a file for reading");
    unsigned char *data = malloc((size_t)st.st_size + 1U);
    if (data == NULL ||
        read(fd, data, (size_t)st.st_size) != (ssize_t)st.st_size)
        fatal("could not read a file");
    close(fd);
    *length = (size_t)st.st_size;
    return data;
}

static void write_all_to(const char *path, const unsigned char *data,
                         size_t length)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write(fd, data, length) != (ssize_t)length || close(fd) != 0)
        fatal("could not rewrite a file");
}

typedef int (*CapturedCall)(const char *first, const char *second);

static int call_repair(const char *first, const char *second)
{
    return repair_backup(first, second);
}

static int call_verify(const char *first, const char *second)
{
    (void)second;
    return verify_backup(first);
}

static int run_captured(CapturedCall call, const char *first,
                        const char *second, char *output, size_t size)
{
    char capture[] = "/tmp/migr_repair_output_XXXXXX";
    int capture_fd = mkstemp(capture);
    if (capture_fd < 0)
        fatal("could not create the output capture");
    unlink(capture);
    fflush(stdout);
    pid_t child = fork();
    if (child < 0)
        fatal("could not fork");
    if (child == 0)
    {
        dup2(capture_fd, STDOUT_FILENO);
        dup2(capture_fd, STDERR_FILENO);
        int result = call(first, second);
        fflush(stdout);
        fflush(stderr);
        _exit(result);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        fatal("could not wait for the child");
    ssize_t length = pread(capture_fd, output, size - 1U, 0);
    output[length > 0 ? length : 0] = '\0';
    close(capture_fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

typedef struct {
    char base[PATH_MAX];
    char source[PATH_MAX];
    char container[PATH_MAX];
    char journal[PATH_MAX];
    char output[PATH_MAX];
} Fixture;

/* case_collisions adds the directories Dup/ and dup/ and captures as if onto
 * a case-insensitive filesystem, so one of them carries a collision suffix. */
static void fixture_create_with(Fixture *fixture, int case_collisions)
{
    snprintf(fixture->base, sizeof(fixture->base), "/tmp/migr_repair_XXXXXX");
    if (mkdtemp(fixture->base) == NULL)
        fatal("could not create the fixture directory");
    join(fixture->source, sizeof(fixture->source), fixture->base, "source");
    join(fixture->container, sizeof(fixture->container), fixture->base,
         "container");
    join(fixture->journal, sizeof(fixture->journal), fixture->container,
         SIDECAR_SLOT_NAME);
    join(fixture->output, sizeof(fixture->output), fixture->base, "output");

    static const char *const directories[] = { "", "d1", "d1/inner", "d2" };
    static const char *const files[] = {
        "top.txt", "d1/one.txt", "d1/two.txt", "d1/inner/deep.txt",
        "d2/three.txt"
    };
    char path[PATH_MAX];
    for (size_t index = 0; index < sizeof(directories) / sizeof(*directories);
         index++)
    {
        join(path, sizeof(path), fixture->source, directories[index]);
        if (mkdir(path, 0750) != 0)
            fatal("could not create a source directory");
    }
    for (size_t index = 0; index < sizeof(files) / sizeof(*files); index++)
    {
        join(path, sizeof(path), fixture->source, files[index]);
        write_text(path, files[index]);
    }
    if (mkdir(fixture->output, 0700) != 0)
        fatal("could not create the output directory");
    if (case_collisions)
    {
        static const char *const pair[] = { "Dup", "dup" };
        for (size_t index = 0; index < 2; index++)
        {
            join(path, sizeof(path), fixture->source, pair[index]);
            if (mkdir(path, 0750) != 0)
                fatal("could not create a colliding directory");
            char file[PATH_MAX];
            join(file, sizeof(file), path, "a.txt");
            write_text(file, pair[index]);
        }
    }

    PortableRootSpec root = {
        .id = "ROOT",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = fixture->source,
        .payload_path = "ROOT",
        .source_path = fixture->source,
        .restore_path = "",
        .has_restore_path = 1
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "a1",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1,
        .nsec_exact = 1,
        .case_sensitive = !case_collisions
    };
    if (mkdir(fixture->container, 0700) != 0)
        fatal("could not create the container");
    int container_fd = open(fixture->container,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0 ||
        portable_capture_fresh_at(container_fd, &request, NULL) != 0 ||
        close(container_fd) != 0)
        fatal("could not capture the portable fixture");
}

static void fixture_create(Fixture *fixture)
{
    fixture_create_with(fixture, 0);
}

/* Overwrites the first byte of the kind field of path's record of the given
 * type, so that this one record no longer parses. */
static void damage_record(Fixture *fixture, const char *type,
                          const char *logical, const char *kind)
{
    size_t length = 0;
    unsigned char *data = read_all(fixture->journal, &length);
    char needle[PATH_MAX];
    int needle_length = snprintf(needle, sizeof(needle), "%s%cROOT%c%s%c",
                                 type, 0, 0, logical, 0);
    unsigned char *found = memmem(data, length, needle, (size_t)needle_length);
    if (found == NULL)
        fatal("could not find the record to damage");
    unsigned char *kind_field = memmem(found, length - (size_t)(found - data),
                                       kind, strlen(kind));
    if (kind_field == NULL)
        fatal("could not find the kind field to damage");
    kind_field[0] = '#';
    write_all_to(fixture->journal, data, length);
    free(data);
}

static int find_final_container(const char *directory, char *out, size_t size)
{
    DIR *dir = opendir(directory);
    if (dir == NULL)
        return 0;
    int found = 0;
    struct dirent *item;
    while ((item = readdir(dir)) != NULL)
    {
        if (item->d_name[0] == '.')
            continue;
        if (container_name_is_final(item->d_name))
        {
            join(out, size, directory, item->d_name);
            found++;
        }
        else
            found += 100;
    }
    closedir(dir);
    return found == 1;
}

typedef struct {
    int live;
    int regular_digests_set;
} JournalCount;

static int count_live(const SidecarLiveView *view, void *context)
{
    JournalCount *count = context;
    count->live++;
    if (view->entry->kind == SIDECAR_KIND_REGULAR &&
        view->entry->content_digest != 0)
        count->regular_digests_set++;
    return 0;
}

static int journal_has(const char *container, const char *logical,
                       SidecarEntry *out, JournalCount *count)
{
    int fd = open(container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    SidecarLog log = {0};
    if (fd < 0 || sidecar_log_adopt_at(fd, &log) != SIDECAR_OPEN_RESUMABLE)
    {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    SidecarLiveView view;
    int found = sidecar_log_find(
        &log, (SidecarBytes){ (const unsigned char *)"ROOT", 4 },
        (SidecarBytes){ (const unsigned char *)logical, strlen(logical) },
        &view);
    if (found == 1 && out != NULL)
    {
        out->mode = view.entry->mode;
        out->kind = view.entry->kind;
        static unsigned char suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
        memcpy(suffix, view.entry->collision_suffix.data,
               view.entry->collision_suffix.length);
        suffix[view.entry->collision_suffix.length] = '\0';
        out->collision_suffix = (SidecarBytes){
            suffix, view.entry->collision_suffix.length
        };
    }
    if (count != NULL)
    {
        memset(count, 0, sizeof(*count));
        sidecar_log_foreach(&log, count_live, count);
    }
    if (sidecar_log_claim_count(&log) != 0)
        found = -2;
    sidecar_log_close(&log);
    close(fd);
    return found;
}

static void test_intact_journal(void)
{
    printf(BLUE "::" NC " repair: an intact journal needs no repair\n");
    Fixture fixture;
    fixture_create(&fixture);
    char output[8192];
    int rc = run_captured(call_repair, fixture.container, fixture.output,
                          output, sizeof(output));
    DIR *dir = opendir(fixture.output);
    int entries = 0;
    struct dirent *item;
    while (dir != NULL && (item = readdir(dir)) != NULL)
        entries += item->d_name[0] != '.';
    if (dir != NULL)
        closedir(dir);
    check(rc == 0 && strstr(output, "nothing to repair") != NULL &&
              entries == 0,
          "an intact journal is reported as such and no copy is left behind");
    remove_tree(fixture.base);
}

static void test_damaged_file_record(void)
{
    printf(BLUE "::" NC " repair: a damaged file record\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "ENTRY", "d1/two.txt", "regular");
    size_t before_length = 0;
    unsigned char *before = read_all(fixture.journal, &before_length);

    char output[8192];
    int rc = run_captured(call_repair, fixture.container, fixture.output,
                          output, sizeof(output));
    char repaired[PATH_MAX];
    int published = find_final_container(fixture.output, repaired,
                                         sizeof(repaired));
    check(rc == 0 && published &&
              strstr(output, "Skipped 1 damaged region of the journal") !=
                  NULL &&
              strstr(output, "Left out: their records were lost (1):\n"
                             "  ROOT:d1/two.txt\n") != NULL,
          "the damaged record is skipped and its path is reported as lost");

    JournalCount count;
    SidecarEntry kept = {0};
    check(published &&
              journal_has(repaired, "d1/two.txt", NULL, NULL) == 0 &&
              journal_has(repaired, "d1/one.txt", &kept, &count) == 1 &&
              count.live == 8 && count.regular_digests_set == 4,
          "every other item survives with its digest and no claim is open");

    char verify_output[8192];
    rc = run_captured(call_verify, repaired, NULL, verify_output,
                      sizeof(verify_output));
    check(rc == 0 && strstr(verify_output, "Backup verified") != NULL,
          "the repaired copy verifies against its copied payload");

    size_t after_length = 0;
    unsigned char *after = read_all(fixture.journal, &after_length);
    check(before_length == after_length &&
              memcmp(before, after, before_length) == 0,
          "the original journal is left exactly as it was");
    free(before);
    free(after);
    remove_tree(fixture.base);
}

static void test_damaged_directory_record(void)
{
    printf(BLUE "::" NC " repair: a damaged directory record\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "ENTRY", "d1", "directory");

    char output[8192];
    int rc = run_captured(call_repair, fixture.container, fixture.output,
                          output, sizeof(output));
    char repaired[PATH_MAX];
    int published = find_final_container(fixture.output, repaired,
                                         sizeof(repaired));
    check(rc == 0 && published &&
              strstr(output, "Re-created directories, their own records "
                             "lost (metadata taken from the directory above "
                             "them) (1):\n  ROOT:d1\n") != NULL &&
              strstr(output, "Left out") == NULL,
          "a directory whose record was lost is re-created, losing nothing");

    SidecarEntry recreated = {0}, parent = {0};
    JournalCount count;
    check(published &&
              journal_has(repaired, "d1", &recreated, &count) == 1 &&
              journal_has(repaired, "", &parent, NULL) == 1 &&
              recreated.kind == SIDECAR_KIND_DIRECTORY &&
              recreated.mode == parent.mode && count.live == 9 &&
              journal_has(repaired, "d1/inner/deep.txt", NULL, NULL) == 1,
          "the directory takes its parent's mode and keeps its children");
    remove_tree(fixture.base);
}

static void test_recreated_directory_keeps_suffix(void)
{
    printf(BLUE "::" NC " repair: a re-created directory with a collision "
                        "suffix\n");
    Fixture fixture;
    fixture_create_with(&fixture, 1);
    damage_record(&fixture, "ENTRY", "dup", "directory");

    char output[8192];
    int rc = run_captured(call_repair, fixture.container, fixture.output,
                          output, sizeof(output));
    char repaired[PATH_MAX];
    int published = find_final_container(fixture.output, repaired,
                                         sizeof(repaired));
    SidecarEntry recreated = {0};
    char verify_output[8192];
    check(rc == 0 && published &&
              journal_has(repaired, "dup", &recreated, NULL) == 1 &&
              recreated.collision_suffix.length == 4 &&
              memcmp(recreated.collision_suffix.data, "%7E1", 4) == 0 &&
              run_captured(call_verify, repaired, NULL, verify_output,
                           sizeof(verify_output)) == 0,
          "its collision suffix is recovered from the physical leaf");
    remove_tree(fixture.base);
}

static void test_damaged_directory_claim(void)
{
    printf(BLUE "::" NC " repair: a damaged directory CLAIM\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "CLAIM", "d1/inner", "directory");

    char output[8192];
    int rc = run_captured(call_repair, fixture.container, fixture.output,
                          output, sizeof(output));
    char repaired[PATH_MAX];
    int published = find_final_container(fixture.output, repaired,
                                         sizeof(repaired));
    JournalCount count;
    check(rc == 0 && published &&
              strstr(output, "Left out: their records conflict with the rest "
                             "of the journal (2):\n  ROOT:d1/inner\n"
                             "  ROOT:d1/inner/deep.txt\n") != NULL &&
              journal_has(repaired, "d1", NULL, &count) == 1 &&
              count.live == 7,
          "items that depend on a lost CLAIM are left out and listed once");
    remove_tree(fixture.base);
}

static void test_truncated_journal(void)
{
    printf(BLUE "::" NC " repair: a journal cut short\n");
    Fixture fixture;
    fixture_create(&fixture);
    size_t length = 0;
    unsigned char *data = read_all(fixture.journal, &length);
    // The root directory is committed last; cutting the final bytes loses it.
    write_all_to(fixture.journal, data, length - 3U);
    free(data);

    char output[8192];
    int rc = run_captured(call_repair, fixture.container, fixture.output,
                          output, sizeof(output));
    char repaired[PATH_MAX];
    int published = find_final_container(fixture.output, repaired,
                                         sizeof(repaired));
    JournalCount count;
    check(rc == 0 && published &&
              strstr(output, "  ROOT:.\n") != NULL &&
              journal_has(repaired, "", NULL, &count) == 1 &&
              count.live == 9,
          "a lost root directory record is re-created from its payload");
    remove_tree(fixture.base);
}

static void test_refusals(void)
{
    printf(BLUE "::" NC " repair: refusals\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "ENTRY", "d1/two.txt", "regular");
    char inside[PATH_MAX];
    join(inside, sizeof(inside), fixture.container, "data");
    char output[8192];
    int rc = run_captured(call_repair, fixture.container, inside, output,
                          sizeof(output));
    check(rc == 1 && strstr(output, "inside the backup") != NULL,
          "the repaired copy is never written inside the damaged backup");
    rc = run_captured(call_repair, fixture.container, fixture.base, output,
                      sizeof(output));
    check(rc == 1 && strstr(output, "find two backups of this install") != NULL,
          "the repaired copy is never written next to the damaged backup");

    size_t length = 0;
    unsigned char *data = read_all(fixture.journal, &length);
    data[0] = 'X';
    write_all_to(fixture.journal, data, length);
    free(data);
    rc = run_captured(call_repair, fixture.container, fixture.output, output,
                      sizeof(output));
    DIR *dir = opendir(fixture.output);
    int entries = 0;
    struct dirent *item;
    while (dir != NULL && (item = readdir(dir)) != NULL)
        entries += item->d_name[0] != '.';
    if (dir != NULL)
        closedir(dir);
    check(rc == 1 && strstr(output, "header is damaged") != NULL &&
              entries == 0,
          "a damaged header is refused and leaves nothing behind");
    remove_tree(fixture.base);
}

int main(void)
{
    // A direct sudo run must not aim restores at the invoking user's home
    // (D38); make and test.sh drop SUDO_UID already.
    unsetenv("SUDO_UID");
    printf(BLUE "::" NC " migr repair\n");
    test_intact_journal();
    test_damaged_file_record();
    test_damaged_directory_record();
    test_recreated_directory_keeps_suffix();
    test_damaged_directory_claim();
    test_truncated_journal();
    test_refusals();
    if (failures != 0)
    {
        printf(RED "%d repair test failure%s" NC "\n", failures,
               failures == 1 ? "" : "s");
        return 1;
    }
    printf(GREEN "repair tests passed" NC "\n");
    return 0;
}
