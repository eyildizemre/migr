// Fuzz harness for the versioned manifest reader: the input becomes the
// manifest.txt of a throwaway container directory and manifest_read_v1_at()
// classifies it. The reader accepts exactly the models the writer writes.
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind.
// - Untrusted bytes end the read as valid, malformed, legacy, or an unknown
//   version, never as a missing file or an I/O error, and every result but
//   valid leaves the output zeroed.
// - Acceptance, checked without migr's own validators: every payload is a
//   relative path, every restore address one or empty, SOURCE_HOME an
//   absolute path or empty, and every exclude an absolute path, each with
//   nonempty components other than . and .. (/ itself has none); the restore side's
//   relative_path_valid() accepts the payloads and restore addresses too.
// - The writer writes every model the reader accepts, and reading what it
//   wrote gives the same model.

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzz.h"
#include "manifest.h"
#include "portable_restore_internal.h"

const char fuzz_target_name[] = "manifest";

static char container_path[4096];
static int container_fd = -1;

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_manifest: %s\n", what);
    abort();
}

static void remove_container(void)
{
    unlinkat(container_fd, "manifest.txt", 0);
    unlinkat(container_fd, "manifest.txt.new", 0);
    close(container_fd);
    rmdir(container_path);
}

static int container(void)
{
    if (container_fd >= 0)
        return container_fd;
    const char *temporary = getenv("TMPDIR");
    snprintf(container_path, sizeof(container_path),
             "%s/migr-fuzz-manifest-XXXXXX",
             temporary != NULL && temporary[0] != '\0' ? temporary : "/tmp");
    if (mkdtemp(container_path) == NULL)
        fail("cannot create the container directory");
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fail("cannot open the container directory");
    atexit(remove_container);
    return container_fd;
}

static int path_valid(const char *path, int absolute, int empty_ok)
{
    if (path[0] == '\0')
        return empty_ok;
    if ((path[0] == '/') != absolute)
        return 0;
    if (absolute && path[1] == '\0')
        return 1; // the root directory, no components at all
    const char *component = path + absolute;
    for (;;)
    {
        size_t length = strcspn(component, "/");
        if (length == 0 || (length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.'))
            return 0;
        if (component[length] == '\0')
            return 1;
        component += length + 1;
    }
}

static void check_accepted(const Manifest *m)
{
    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (!path_valid(root->payload_path, 0, 0) ||
            !relative_path_valid(root->payload_path, 0))
            fail("the reader accepted an invalid payload address");
        if (root->has_restore_path &&
            (!path_valid(root->restore_path, 0, 1) ||
             !relative_path_valid(root->restore_path, 1)))
            fail("the reader accepted an invalid restore address");
    }
    if (!path_valid(m->source_home, 1, 1))
        fail("the reader accepted an invalid SOURCE_HOME");
    for (size_t i = 0; i < m->exclude_count; i++)
        if (!path_valid(m->excludes[i], 1, 0))
            fail("the reader accepted an invalid exclude");
}

static int ranges_equal(const SubidRanges *a, const SubidRanges *b)
{
    return a->count == b->count &&
           memcmp(a->ranges, b->ranges, a->count * sizeof(*a->ranges)) == 0;
}

static int manifests_equal(const Manifest *a, const Manifest *b)
{
    if (a->version != b->version || a->representation != b->representation ||
        a->scope != b->scope || a->sidecar_version != b->sidecar_version ||
        a->has_source_identity != b->has_source_identity ||
        strcmp(a->machine_id, b->machine_id) != 0 ||
        a->source_uid != b->source_uid ||
        a->has_source_gid != b->has_source_gid ||
        a->source_gid != b->source_gid ||
        !ranges_equal(&a->source_subuids, &b->source_subuids) ||
        !ranges_equal(&a->source_subgids, &b->source_subgids) ||
        a->has_self_binary != b->has_self_binary ||
        strcmp(a->arch, b->arch) != 0 ||
        a->has_network_config != b->has_network_config ||
        a->selinux != b->selinux || a->updated != b->updated ||
        a->size != b->size || strcmp(a->source_home, b->source_home) != 0 ||
        a->root_count != b->root_count || a->exclude_count != b->exclude_count)
        return 0;
    for (int i = 0; i < a->root_count; i++)
        if (!manifest_root_equal(&a->roots[i], &b->roots[i]))
            return 0;
    for (size_t i = 0; i < a->exclude_count; i++)
        if (strcmp(a->excludes[i], b->excludes[i]) != 0)
            return 0;
    return 1;
}

static void check_round_trip(int directory, const Manifest *m)
{
    if (manifest_write_v1_at(directory, m) != 0)
        fail("the writer refuses a model the reader accepted");
    Manifest again;
    if (manifest_read_v1_at(directory, &again) != MANIFEST_STATUS_VALID)
        fail("the reader refuses what the writer wrote");
    if (!manifests_equal(m, &again))
        fail("what the writer wrote reads as a different model");
    manifest_free(&again);
}

static const char *read_input(const uint8_t *data, size_t size)
{
    int directory = container();
    int fd = openat(directory, "manifest.txt",
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size) ||
        close(fd) != 0)
        fail("cannot write the manifest");

    static const Manifest zero;
    Manifest m;
    ManifestStatus status = manifest_read_v1_at(directory, &m);
    if (status != MANIFEST_STATUS_VALID && memcmp(&m, &zero, sizeof(m)) != 0)
        fail("a read that is not valid leaves the output set");
    switch (status)
    {
        case MANIFEST_STATUS_VALID:
            check_accepted(&m);
            check_round_trip(directory, &m);
            manifest_free(&m);
            return "valid";
        case MANIFEST_STATUS_MALFORMED:
            return "malformed";
        case MANIFEST_STATUS_LEGACY:
            return "legacy";
        case MANIFEST_STATUS_UNKNOWN_VERSION:
            return "unknown_version";
        default:
            fail("a read ends with an unexpected status");
    }
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    read_input(data, size);
    return 0;
}

const char *fuzz_outcome(const uint8_t *data, size_t size)
{
    return read_input(data, size);
}

const char *fuzz_seed_outcome(const FuzzSeed *seed)
{
    return seed->outcome;
}

void fuzz_check_seed(const FuzzSeed *seed)
{
    (void)seed;
}
