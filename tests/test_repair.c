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
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "container.h"
#include "manifest.h"
#include "portable.h"
#include "portable_name.h"
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
    (void)second;
    return repair_backup(first);
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

static int staging_left(const Fixture *fixture)
{
    char staging[PATH_MAX];
    join(staging, sizeof(staging), fixture->container, "staging");
    return access(staging, F_OK) == 0;
}

static int run_repair(const Fixture *fixture, char *output, size_t size)
{
    return run_captured(call_repair, fixture->container, NULL, output, size);
}

static int run_verify(const Fixture *fixture)
{
    char output[8192];
    return run_captured(call_verify, fixture->container, NULL, output,
                        sizeof(output));
}

// Whether the journal still holds exactly the bytes it held before.
static int journal_unchanged(const Fixture *fixture,
                             const unsigned char *before, size_t length)
{
    size_t now_length = 0;
    unsigned char *now = read_all(fixture->journal, &now_length);
    int same = now_length == length && memcmp(now, before, length) == 0;
    free(now);
    return same;
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
        out->size = view.entry->size;
        out->content_digest = view.entry->content_digest;
        static unsigned char suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
        if (view.entry->collision_suffix.length != 0)
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
    size_t length = 0;
    unsigned char *before = read_all(fixture.journal, &length);
    char output[8192];
    int rc = run_repair(&fixture, output, sizeof(output));
    check(rc == 0 && strstr(output, "nothing to repair") != NULL &&
              journal_unchanged(&fixture, before, length) &&
              !staging_left(&fixture),
          "an intact journal is reported as such and left as it was");
    free(before);
    remove_tree(fixture.base);
}

static const char recreated_heading[] =
    "Re-created from the payload, their own records lost (metadata taken "
    "from the folder above them)";

// The journal is rebuilt in place: in a finished backup a claimed file's
// payload is whole, so its file comes back under the claim's name.
static void test_damaged_file_record(void)
{
    printf(BLUE "::" NC " repair: a damaged file record\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "ENTRY", "d1/two.txt", "regular");
    // What an interrupted update left in staging/ is not part of the backup
    // (D110).
    char staging[PATH_MAX], staged[PATH_MAX];
    join(staging, sizeof(staging), fixture.container, "staging");
    join(staged, sizeof(staged), staging, "copy");
    int staged_fd = mkdir(staging, 0700) == 0
        ? open(staged, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600) : -1;
    if (staged_fd < 0 || close(staged_fd) != 0)
        fatal("could not stage a copy");

    char output[8192], expected[512];
    int rc = run_repair(&fixture, output, sizeof(output));
    snprintf(expected, sizeof(expected), "%s (1):\n  ROOT:d1/two.txt\n",
             recreated_heading);
    check(rc == 0 &&
              strstr(output, "Skipped 1 damaged region of the journal") !=
                  NULL &&
              strstr(output, expected) != NULL &&
              strstr(output, "Left out") == NULL &&
              strstr(output, "Repaired the backup") != NULL,
          "the damaged record is skipped and its file re-created");

    JournalCount count;
    SidecarEntry file = {0}, folder = {0};
    check(journal_has(fixture.container, "d1/two.txt", &file, &count) == 1 &&
              journal_has(fixture.container, "d1", &folder, NULL) == 1 &&
              file.kind == SIDECAR_KIND_REGULAR &&
              file.size == strlen("d1/two.txt") &&
              file.mode == (folder.mode & 0666) &&
              count.live == 9 && count.regular_digests_set == 5,
          "it takes the folder's mode without execute bits, its own size and "
          "digest");
    check(!staging_left(&fixture),
          "staging/ is gone, with what an update had left there");
    check(run_verify(&fixture) == 0,
          "the repaired backup verifies against its payload");
    rc = run_repair(&fixture, output, sizeof(output));
    check(rc == 0 && strstr(output, "nothing to repair") != NULL,
          "a second repair finds the journal intact");
    remove_tree(fixture.base);
}

// A journal that parses whole beside payload it does not record, as the
// copies of earlier versions of repair hold, is not intact.
static void test_unrecorded_payload(void)
{
    printf(BLUE "::" NC " repair: payload the journal does not record\n");
    Fixture fixture;
    fixture_create(&fixture);
    char stray[PATH_MAX];
    join(stray, sizeof(stray), fixture.container, "data/ROOT/d2/stray.txt");
    write_text(stray, "no record");
    char output[8192], expected[512];
    int rc = run_repair(&fixture, output, sizeof(output));
    snprintf(expected, sizeof(expected), "%s (1):\n  ROOT:d2/stray.txt\n",
             recreated_heading);
    SidecarEntry file = {0};
    check(rc == 0 && strstr(output, expected) != NULL &&
              journal_has(fixture.container, "d2/stray.txt", &file, NULL) ==
                  1 &&
              file.size == strlen("no record") && access(stray, F_OK) == 0 &&
              run_verify(&fixture) == 0,
          "a file no record names is re-created under its own name");
    remove_tree(fixture.base);
}

// A name that was encoded on its way to the payload cannot be read back: the
// name on disk becomes the item's, and the file is renamed to its form.
static void test_unrecorded_encoded_name(void)
{
    printf(BLUE "::" NC " repair: an unrecorded file with an encoded name\n");
    Fixture fixture;
    fixture_create(&fixture);
    PortablePhysicalName encoded;
    if (portable_physical_name_map("a:b.txt", 0, &encoded) != 0 ||
        strcmp(encoded.physical_leaf, "a:b.txt") == 0)
        fatal("the fixture name is not encoded");
    char folder[PATH_MAX], stray[PATH_MAX];
    join(folder, sizeof(folder), fixture.container, "data/ROOT/d2");
    join(stray, sizeof(stray), folder, encoded.physical_leaf);
    write_text(stray, "encoded");
    char output[8192], logical[PATH_MAX];
    snprintf(logical, sizeof(logical), "d2/%s", encoded.physical_leaf);
    int rc = run_repair(&fixture, output, sizeof(output));
    check(rc == 0 &&
              journal_has(fixture.container, logical, NULL, NULL) == 1 &&
              access(stray, F_OK) != 0 && run_verify(&fixture) == 0,
          "it is recorded under the name on disk, its file renamed to match");
    remove_tree(fixture.base);
}

static void test_damaged_directory_record(void)
{
    printf(BLUE "::" NC " repair: a damaged directory record\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "ENTRY", "d1", "directory");

    char output[8192], expected[512];
    int rc = run_repair(&fixture, output, sizeof(output));
    snprintf(expected, sizeof(expected), "%s (1):\n  ROOT:d1\n",
             recreated_heading);
    check(rc == 0 && strstr(output, expected) != NULL &&
              strstr(output, "Left out") == NULL,
          "a directory whose record was lost is re-created, losing nothing");

    SidecarEntry recreated = {0}, parent = {0};
    JournalCount count;
    check(journal_has(fixture.container, "d1", &recreated, &count) == 1 &&
              journal_has(fixture.container, "", &parent, NULL) == 1 &&
              recreated.kind == SIDECAR_KIND_DIRECTORY &&
              recreated.mode == parent.mode && count.live == 9 &&
              journal_has(fixture.container, "d1/inner/deep.txt", NULL,
                          NULL) == 1,
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
    int rc = run_repair(&fixture, output, sizeof(output));
    SidecarEntry recreated = {0};
    check(rc == 0 &&
              journal_has(fixture.container, "dup", &recreated, NULL) == 1 &&
              recreated.collision_suffix.length == 4 &&
              memcmp(recreated.collision_suffix.data, "%7E1", 4) == 0 &&
              run_verify(&fixture) == 0,
          "its collision suffix is recovered from the physical leaf");
    remove_tree(fixture.base);
}

// A lost CLAIM makes the state layer refuse the folder's records and its
// children's; the payload brings all of them back.
static void test_damaged_directory_claim(void)
{
    printf(BLUE "::" NC " repair: a damaged directory CLAIM\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "CLAIM", "d1/inner", "directory");

    char output[8192], expected[512];
    int rc = run_repair(&fixture, output, sizeof(output));
    snprintf(expected, sizeof(expected),
             "%s (2):\n  ROOT:d1/inner\n  ROOT:d1/inner/deep.txt\n",
             recreated_heading);
    JournalCount count;
    check(rc == 0 && strstr(output, expected) != NULL &&
              strstr(output, "Left out") == NULL &&
              journal_has(fixture.container, "d1/inner/deep.txt", NULL,
                          &count) == 1 &&
              count.live == 9 && run_verify(&fixture) == 0,
          "items that depend on a lost CLAIM are re-created from the payload");
    remove_tree(fixture.base);
}

// With the root's own CLAIM lost, the state layer refuses every record of
// the root, which leaves its whole payload without one.
static void test_damaged_root_claim(void)
{
    printf(BLUE "::" NC " repair: a damaged root CLAIM\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "CLAIM", "", "directory");

    char output[8192];
    int rc = run_repair(&fixture, output, sizeof(output));
    JournalCount count;
    check(rc == 0 && strstr(output, "Left out") == NULL &&
              journal_has(fixture.container, "", NULL, &count) == 1 &&
              journal_has(fixture.container, "d1/inner/deep.txt", NULL,
                          NULL) == 1 &&
              count.live == 9 && count.regular_digests_set == 5 &&
              run_verify(&fixture) == 0,
          "the root and everything in it are re-created from the payload");
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
    int rc = run_repair(&fixture, output, sizeof(output));
    JournalCount count;
    check(rc == 0 && strstr(output, "  ROOT:.\n") != NULL &&
              journal_has(fixture.container, "", NULL, &count) == 1 &&
              count.live == 9,
          "a lost root directory record is re-created from its payload");
    remove_tree(fixture.base);
}

// Nothing changes in a backup repair refuses.
static void test_refusals(void)
{
    printf(BLUE "::" NC " repair: refusals\n");
    Fixture fixture;
    fixture_create(&fixture);
    damage_record(&fixture, "ENTRY", "d1/two.txt", "regular");
    size_t length = 0;
    unsigned char *before = read_all(fixture.journal, &length);
    char output[8192];

    char other[PATH_MAX], inside[PATH_MAX];
    join(other, sizeof(other), fixture.container, "data/OTHER");
    join(inside, sizeof(inside), other, "x");
    if (mkdir(other, 0700) != 0)
        fatal("could not create a folder in data/");
    write_text(inside, "no root");
    int rc = run_repair(&fixture, output, sizeof(output));
    check(rc == 1 &&
              strstr(output, "data/OTHER belongs to none of the backup's "
                             "folders") != NULL &&
              journal_unchanged(&fixture, before, length) &&
              !staging_left(&fixture) && access(inside, F_OK) == 0,
          "payload that lies in no root is refused, and nothing changes");
    if (unlink(inside) != 0 || rmdir(other) != 0)
        fatal("could not remove the folder in data/");

    int held = open(fixture.container, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (held < 0 || flock(held, LOCK_EX | LOCK_NB) != 0)
        fatal("could not lock the container");
    rc = run_repair(&fixture, output, sizeof(output));
    close(held);
    check(rc == 1 && strstr(output, "another migr is using") != NULL &&
              journal_unchanged(&fixture, before, length),
          "a backup another migr is using is refused");

    unsigned char *damaged = read_all(fixture.journal, &length);
    damaged[0] = 'X';
    write_all_to(fixture.journal, damaged, length);
    rc = run_repair(&fixture, output, sizeof(output));
    check(rc == 1 && strstr(output, "header is damaged") != NULL &&
              journal_unchanged(&fixture, damaged, length) &&
              !staging_left(&fixture),
          "a damaged header is refused and the journal is left as it was");
    free(damaged);
    free(before);
    remove_tree(fixture.base);
}

// Sets the header's version field, whose one byte follows the magic and its
// NUL, and runs repair on the journal.
static int repair_with_version(Fixture *fixture, char version, char *output,
                               size_t size)
{
    size_t length = 0;
    unsigned char *data = read_all(fixture->journal, &length);
    size_t field = strlen(SIDECAR_MAGIC) + 1U;
    if (length < field + 2U || data[field + 1U] != '\0')
        fatal("the journal header has an unexpected layout");
    data[field] = (unsigned char)version;
    write_all_to(fixture->journal, data, length);
    free(data);
    return run_repair(fixture, output, size);
}

static void test_other_version(void)
{
    printf(BLUE "::" NC " repair: a header of another version\n");
    Fixture fixture;
    fixture_create(&fixture);
    char output[8192];
    int rc = repair_with_version(&fixture, '7', output, sizeof(output));
    char expected[128];
    snprintf(expected, sizeof(expected), "header names version 7, but its "
             "manifest and this build use version %d", SIDECAR_VERSION);
    check(rc == 1 && strstr(output, expected) != NULL &&
              !staging_left(&fixture),
          "an intact journal of another version is refused, nothing changed");
    rc = repair_with_version(&fixture, 'x', output, sizeof(output));
    check(rc == 1 && strstr(output, "header is damaged") != NULL &&
              !staging_left(&fixture),
          "a version field that is not a number is refused as damage");
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
    test_unrecorded_payload();
    test_unrecorded_encoded_name();
    test_damaged_directory_record();
    test_recreated_directory_keeps_suffix();
    test_damaged_directory_claim();
    test_damaged_root_claim();
    test_truncated_journal();
    test_refusals();
    test_other_version();
    if (failures != 0)
    {
        printf(RED "%d repair test failure%s" NC "\n", failures,
               failures == 1 ? "" : "s");
        return 1;
    }
    printf(GREEN "repair tests passed" NC "\n");
    return 0;
}
