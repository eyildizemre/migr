// Tests for `migr verify` (docs/DECISIONS.md D59): a real portable capture is
// checked against its own journal, then damaged one way at a time.
#define _GNU_SOURCE
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

#include "manifest.h"
#include "portable.h"
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

static void append_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    size_t length = strlen(text);
    if (fd < 0 || write(fd, text, length) != (ssize_t)length || close(fd) != 0)
        fatal("could not append to a file");
}

/* Runs verify_backup() in a child with stdout and stderr captured. */
static int run_verify(const char *path, char *output, size_t size)
{
    char capture[] = "/tmp/migr_verify_output_XXXXXX";
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
        int result = verify_backup(path);
        fflush(stdout);
        fflush(stderr);
        _exit(result);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        fatal("could not wait for the verify child");
    ssize_t length = pread(capture_fd, output, size - 1U, 0);
    output[length > 0 ? length : 0] = '\0';
    close(capture_fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

typedef struct {
    char base[PATH_MAX];
    char source[PATH_MAX];
    char container[PATH_MAX];
    char payload[PATH_MAX];
} Fixture;

static const char b_text[] = "content of b";
static const char c_text[] = "content of c";

static void fixture_create(Fixture *fixture)
{
    snprintf(fixture->base, sizeof(fixture->base), "/tmp/migr_verify_XXXXXX");
    if (mkdtemp(fixture->base) == NULL)
        fatal("could not create the fixture directory");
    join(fixture->source, sizeof(fixture->source), fixture->base, "source");
    join(fixture->container, sizeof(fixture->container), fixture->base,
         "container");
    join(fixture->payload, sizeof(fixture->payload), fixture->container,
         "data/ROOT");

    char path[PATH_MAX], other[PATH_MAX];
    if (mkdir(fixture->source, 0700) != 0)
        fatal("could not create the source");
    join(path, sizeof(path), fixture->source, "a");
    if (mkdir(path, 0700) != 0)
        fatal("could not create a source directory");
    join(path, sizeof(path), fixture->source, "a/b.txt");
    write_text(path, b_text);
    join(path, sizeof(path), fixture->source, "c.txt");
    write_text(path, c_text);
    join(other, sizeof(other), fixture->source, "hard");
    if (link(path, other) != 0)
        fatal("could not create a hardlink");
    join(path, sizeof(path), fixture->source, "link");
    if (symlink("a/b.txt", path) != 0)
        fatal("could not create a symlink");

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
        .case_sensitive = 1
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

static void test_clean_backup(void)
{
    printf(BLUE "::" NC " verify: an intact portable backup\n");
    Fixture fixture;
    fixture_create(&fixture);
    char output[8192];
    int rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 0 && strstr(output, "Verifying 6 items") != NULL &&
              strstr(output, "Backup verified: all 6 items match what was "
                             "captured") != NULL &&
              strstr(output, "Backup taken") == NULL,
          "every item of an intact backup matches its capture record");

    Manifest manifest;
    int container_fd = open(fixture.container,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0 ||
        manifest_read_v1_at(container_fd, &manifest) != MANIFEST_STATUS_VALID)
        fatal("could not read the fixture manifest");
    manifest.updated = 1790500000; // 2026-09-27 09:06:40 UTC
    if (manifest_write_v1_at(container_fd, &manifest) != 0)
        fatal("could not stamp the fixture manifest");
    manifest_free(&manifest);
    close(container_fd);
    setenv("TZ", "UTC", 1);
    tzset();
    rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 0 && strstr(output, "Backup taken 2026-09-27 09:06\n") != NULL,
          "when the backup was taken is shown before verifying it");
    remove_tree(fixture.base);
}

static void test_damaged_payloads(void)
{
    printf(BLUE "::" NC " verify: damaged payloads are named\n");
    Fixture fixture;
    fixture_create(&fixture);
    char path[PATH_MAX];
    char output[8192];

    // Same size, different bytes: only the capture digest can tell.
    join(path, sizeof(path), fixture.payload, "a/b.txt");
    write_text(path, "content of B");
    int rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 1 &&
              strstr(output, "Verification found 1 item that differs from "
                             "what was captured:") != NULL &&
              strstr(output, "ROOT:a/b.txt (content differs from what was "
                             "captured)") != NULL,
          "a same-size content change is reported as a content difference");
    write_text(path, b_text);

    join(path, sizeof(path), fixture.payload, "link");
    write_text(path, "x");
    rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 1 &&
              strstr(output, "ROOT:link (its placeholder is not an empty "
                             "file)") != NULL,
          "a symlink placeholder with content is reported");
    write_text(path, "");

    join(path, sizeof(path), fixture.payload, "a/b.txt");
    write_text(path, "short");
    rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 1 &&
              strstr(output, "ROOT:a/b.txt (size is 5 bytes, captured as "
                             "12)") != NULL,
          "a truncated file is reported with both sizes");
    write_text(path, b_text);

    rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 0, "restoring the damaged bytes makes the backup verify again");

    join(path, sizeof(path), fixture.payload, "a");
    char file[PATH_MAX];
    join(file, sizeof(file), path, "b.txt");
    if (unlink(file) != 0 || rmdir(path) != 0)
        fatal("could not remove a payload directory");
    rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 1 &&
              strstr(output, "Verification found 2 items that differ") !=
                  NULL &&
              strstr(output, "ROOT:a (missing from the backup)") != NULL &&
              strstr(output, "ROOT:a/b.txt (missing from the backup)") != NULL,
          "a missing directory and the file inside it are both reported");
    remove_tree(fixture.base);
}

static void test_refusals(void)
{
    printf(BLUE "::" NC " verify: backups it cannot check are refused\n");
    Fixture fixture;
    fixture_create(&fixture);
    char path[PATH_MAX];
    char output[8192];

    join(path, sizeof(path), fixture.container, SIDECAR_SLOT_NAME);
    append_text(path, "ENTRY");
    int rc = run_verify(fixture.container, output, sizeof(output));
    check(rc == 2 && strstr(output, "Backup verified") == NULL &&
              strstr(output, SIDECAR_SLOT_NAME) != NULL,
          "an incomplete journal is refused and named");
    remove_tree(fixture.base);

    char native[] = "/tmp/migr_verify_native_XXXXXX";
    if (mkdtemp(native) == NULL)
        fatal("could not create the native fixture");
    int native_fd = open(native, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ManifestRoot root;
    memset(&root, 0, sizeof(root));
    strcpy(root.id, "ROOT");
    root.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(root.payload_path, "ROOT");
    root.has_restore_path = 1;
    Manifest manifest = {
        .version = MANIFEST_CURRENT_VERSION,
        .representation = CLONE_NATIVE_TREE,
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .root_count = 1,
        .roots = &root
    };
    if (native_fd < 0 || manifest_write_v1_at(native_fd, &manifest) != 0)
        fatal("could not write the native manifest");
    close(native_fd);
    rc = run_verify(native, output, sizeof(output));
    check(rc == 2 && strstr(output, "is a native backup") != NULL,
          "a native backup is refused: it records no content digests");
    remove_tree(native);
}

int main(void)
{
    // A direct sudo run must not aim restores at the invoking user's home
    // (D38); make and test.sh drop SUDO_UID already.
    unsetenv("SUDO_UID");
    printf(BLUE "::" NC " migr verify\n");
    test_clean_backup();
    test_damaged_payloads();
    test_refusals();
    if (failures != 0)
    {
        printf(RED "%d verify test failure%s" NC "\n", failures,
               failures == 1 ? "" : "s");
        return 1;
    }
    printf(GREEN "verify tests passed" NC "\n");
    return 0;
}
