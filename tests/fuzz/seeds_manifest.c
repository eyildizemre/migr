// Generated seeds for the manifest fuzzer: what the writer writes for a
// manifest with every optional field, a portable explicit selection, a
// filtered selection (VERSION=2), and no roots at all, then the variants the
// reader still accepts and one case past each rule it enforces. Each seed
// states how the reader classifies it.

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz.h"
#include "manifest.h"

#define MAX_SEEDS 24U
#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static void die(const char *what)
{
    fprintf(stderr, "fuzz seeds: %s\n", what);
    abort();
}

static void add_bytes(FuzzSeed *seeds, size_t *count, const char *name,
                      const char *outcome, const void *data, size_t size)
{
    if (*count == MAX_SEEDS)
        die("more seeds than MAX_SEEDS");
    FuzzSeed *seed = &seeds[(*count)++];
    seed->name = name;
    seed->outcome = outcome;
    seed->data = malloc(size > 0 ? size : 1U);
    if (seed->data == NULL)
        die("cannot allocate a seed");
    memcpy(seed->data, data, size);
    seed->size = size;
}

static void add_text(FuzzSeed *seeds, size_t *count, const char *name,
                     const char *outcome, const char *text)
{
    add_bytes(seeds, count, name, outcome, text, strlen(text));
}

// The bytes manifest_write_v1() writes for m.
static void add_written(FuzzSeed *seeds, size_t *count, const char *name,
                        const Manifest *m)
{
    const char *temporary = getenv("TMPDIR");
    char directory[4096], path[4096 + 16U];
    snprintf(directory, sizeof(directory), "%s/migr-fuzz-seeds-XXXXXX",
             temporary != NULL && temporary[0] != '\0' ? temporary : "/tmp");
    if (mkdtemp(directory) == NULL)
        die("cannot create a directory for the writer");
    snprintf(path, sizeof(path), "%s/manifest.txt", directory);
    if (manifest_write_v1(directory, m) != 0)
        die("the writer refuses a seed's model");

    static char text[65536];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t size = fd >= 0 ? read(fd, text, sizeof(text)) : -1;
    if (size < 0 || (size_t)size == sizeof(text))
        die("cannot read what the writer wrote");
    close(fd);
    unlink(path);
    rmdir(directory);
    add_bytes(seeds, count, name, "valid", text, (size_t)size);
}

static ManifestRoot root(const char *id, RootPolicy policy, const char *payload,
                         const char *source, const char *restore)
{
    ManifestRoot r;
    memset(&r, 0, sizeof(r));
    snprintf(r.id, sizeof(r.id), "%s", id);
    r.policy = policy;
    snprintf(r.payload_path, sizeof(r.payload_path), "%s", payload);
    snprintf(r.source_path, sizeof(r.source_path), "%s", source);
    if (restore != NULL)
    {
        snprintf(r.restore_path, sizeof(r.restore_path), "%s", restore);
        r.has_restore_path = 1;
    }
    return r;
}

static void build_written(FuzzSeed *seeds, size_t *count)
{
    // Every optional field, a root of each policy, and paths that need
    // percent-encoding.
    ManifestRoot full_roots[] = {
        root("XDG_DOCUMENTS_DIR", ROOT_POLICY_XDG, "XDG_DOCUMENTS_DIR",
             "/home/u/Documents", NULL),
        root("EXPLICIT_0", ROOT_POLICY_HOME_RELATIVE, "home", "", ""),
        root("EXPLICIT_1", ROOT_POLICY_HOME_RELATIVE,
             "settings/with space %25 \xc3\xbc", "with space/%25 \xc3\xbc",
             "with space/%25 \xc3\xbc"),
        root("EXPLICIT_2", ROOT_POLICY_MANUAL_NATIVE, "EXPLICIT_2", "/", NULL),
    };
    Manifest full;
    memset(&full, 0, sizeof(full));
    full.version = MANIFEST_CURRENT_VERSION;
    full.representation = CLONE_NATIVE_TREE;
    full.scope = MANIFEST_SCOPE_EXPLICIT;
    full.sidecar_version = 1;
    full.has_source_identity = 1;
    snprintf(full.machine_id, sizeof(full.machine_id), "%s",
             "0123456789abcdef0123456789abcdef");
    full.source_uid = 1000;
    full.has_source_gid = 1;
    full.source_gid = 1000;
    full.source_subuids = (SubidRanges){ 2, { { 100000, 65536 },
                                              { 300000, 1 } } };
    full.source_subgids = (SubidRanges){ 1, { { 100000, 65536 } } };
    full.has_self_binary = 1;
    snprintf(full.arch, sizeof(full.arch), "%s", "x86_64");
    full.has_network_config = 1;
    full.selinux = 1;
    full.updated = 1760000000;
    full.size = 123456789;
    manifest_set_source_home(&full, "/home/u");
    full.root_count = (int)COUNT(full_roots);
    full.roots = full_roots;
    add_written(seeds, count, "every-field", &full);

    ManifestRoot portable_roots[] = {
        root("EXPLICIT_0", ROOT_POLICY_HOME_RELATIVE, "Projects",
             "Projects", "Projects"),
        root("EXPLICIT_1", ROOT_POLICY_HOME_RELATIVE, "settings/config-app",
             ".config/app", ".config/app"),
    };
    Manifest portable;
    memset(&portable, 0, sizeof(portable));
    portable.version = MANIFEST_CURRENT_VERSION;
    portable.representation = CLONE_PORTABLE_SIDECAR;
    portable.scope = MANIFEST_SCOPE_EXPLICIT;
    portable.sidecar_version = 1;
    portable.root_count = (int)COUNT(portable_roots);
    portable.roots = portable_roots;
    add_written(seeds, count, "portable-explicit", &portable);

    ManifestRoot selection_roots[] = {
        root("EXPLICIT_0", ROOT_POLICY_HOME_RELATIVE, "settings/config",
             ".config", ".config"),
        root("EXPLICIT_1", ROOT_POLICY_HOME_RELATIVE, "Documents",
             "Documents", "Documents"),
    };
    char exclude_cache[] = "/home/u/.config/cache";
    char exclude_tmp[] = "/home/u/Documents/tmp";
    char *excludes[] = { exclude_cache, exclude_tmp };
    Manifest selection;
    memset(&selection, 0, sizeof(selection));
    selection.version = MANIFEST_SELECTION_VERSION;
    selection.representation = CLONE_NATIVE_TREE;
    selection.scope = MANIFEST_SCOPE_CRITICAL;
    manifest_set_source_home(&selection, "/home/u");
    selection.root_count = (int)COUNT(selection_roots);
    selection.roots = selection_roots;
    selection.exclude_count = COUNT(excludes);
    selection.excludes = excludes;
    add_written(seeds, count, "selection-with-excludes", &selection);

    Manifest empty;
    memset(&empty, 0, sizeof(empty));
    empty.version = MANIFEST_CURRENT_VERSION;
    empty.representation = CLONE_NATIVE_TREE;
    empty.scope = MANIFEST_SCOPE_CRITICAL;
    add_written(seeds, count, "no-roots", &empty);
}

#define HEADER "MIGR_MANIFEST\nVERSION=1\nREPRESENTATION=native\n" \
               "SCOPE=critical\nSIDECAR_VERSION=0\n"

static void build_edges(FuzzSeed *seeds, size_t *count)
{
    // Forms the writer never writes that still read as one of its models.
    add_text(seeds, count, "crlf", "valid",
             "MIGR_MANIFEST\r\nVERSION=1\r\nREPRESENTATION=native\r\n"
             "SCOPE=critical\r\nSIDECAR_VERSION=0\r\nROOT_COUNT=0\r\n");
    add_text(seeds, count, "leading-zeros", "valid",
             "MIGR_MANIFEST\nVERSION=01\nREPRESENTATION=native\n"
             "SCOPE=critical\nSIDECAR_VERSION=00\nROOT_COUNT=0\n");

    // An account whose home is the root directory.
    add_text(seeds, count, "source-home-root", "valid",
             HEADER "SOURCE_HOME=%2F\nROOT_COUNT=0\n");

    add_text(seeds, count, "empty", "malformed", "");
    add_text(seeds, count, "legacy", "legacy",
             "XDG_DOCUMENTS_DIR=/home/u/Documents\n");
    add_text(seeds, count, "unknown-version", "unknown_version",
             "MIGR_MANIFEST\nVERSION=3\n");
    add_text(seeds, count, "trailing-line", "malformed",
             HEADER "ROOT_COUNT=1\n"
             "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=%2Fsrv\n"
             "ROOT ID=EXPLICIT_1 POLICY=MANUAL_NATIVE PAYLOAD=b SOURCE=%2Fopt\n");
    add_text(seeds, count, "duplicate-id", "malformed",
             HEADER "ROOT_COUNT=2\n"
             "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=%2Fsrv\n"
             "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=b SOURCE=%2Fopt\n");
    add_text(seeds, count, "payload-climbs-out", "malformed",
             HEADER "ROOT_COUNT=1\nROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE "
             "PAYLOAD=..%2F..%2Fvictim SOURCE=%2Fsrv\n");
    add_text(seeds, count, "source-home-not-canonical", "malformed",
             HEADER "SOURCE_HOME=%2Fhome%2Fu%2F\nROOT_COUNT=0\n");
    add_text(seeds, count, "restore-without-home-relative", "malformed",
             HEADER "ROOT_COUNT=1\nROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE "
             "PAYLOAD=a SOURCE=%2Fsrv RESTORE=a\n");
    add_text(seeds, count, "cut-escape", "malformed",
             HEADER "ROOT_COUNT=1\nROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE "
             "PAYLOAD=a%2 SOURCE=%2Fsrv\n");
    static const char nul_in_line[] =
        HEADER "ROOT_COUNT=1\nROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE "
        "PAYLOAD=a SOURCE=%2Fsrv\0hidden\n";
    add_bytes(seeds, count, "nul-in-line", "malformed", nul_in_line,
              sizeof(nul_in_line) - 1U);
}

void fuzz_seeds_build(FuzzSeed **seeds, size_t *count)
{
    *seeds = calloc(MAX_SEEDS, sizeof(**seeds));
    if (*seeds == NULL)
        die("cannot allocate the seeds");
    *count = 0;
    build_written(*seeds, count);
    build_edges(*seeds, count);
}

void fuzz_seeds_free(FuzzSeed *seeds, size_t count)
{
    for (size_t index = 0; index < count; index++)
        free(seeds[index].data);
    free(seeds);
}
