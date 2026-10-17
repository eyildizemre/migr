// Generated seeds for the round-trip fuzzer, in the input format
// fuzz_sidecar_roundtrip.c decodes: an entry of every kind, the numeric and
// length ceilings, the edges of the xattr value, and one case past each rule
// the writer enforces. Each seed states whether the writer writes it.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "sidecar.h"

#define MAX_SEEDS 40U

typedef struct {
    unsigned char *data;
    size_t size;
} Encoded;

static void die(const char *what)
{
    fprintf(stderr, "fuzz seeds: %s\n", what);
    abort();
}

static SidecarBytes text(const char *value)
{
    return (SidecarBytes){ (const unsigned char *)value, strlen(value) };
}

// length bytes of fill, from a buffer large enough for every ceiling.
static SidecarBytes filled(size_t length)
{
    static unsigned char fill[SIDECAR_MAX_XATTR_VALUE + 1U];
    if (length > sizeof(fill))
        die("a filled field past every ceiling");
    memset(fill, 'f', sizeof(fill));
    return (SidecarBytes){ fill, length };
}

static void put(Encoded *encoded, const void *data, size_t length)
{
    unsigned char *grown = realloc(encoded->data, encoded->size + length);
    if (grown == NULL)
        die("cannot grow a seed");
    if (length > 0)
        memcpy(grown + encoded->size, data, length);
    encoded->data = grown;
    encoded->size += length;
}

static void put_number(Encoded *encoded, uint64_t value, size_t width)
{
    for (size_t index = 0; index < width; index++)
    {
        unsigned char byte = (unsigned char)(value >> (8U * index));
        put(encoded, &byte, 1);
    }
}

static void put_signed(Encoded *encoded, int64_t value)
{
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    put_number(encoded, bits, 8);
}

static void put_bytes(Encoded *encoded, SidecarBytes bytes, size_t width)
{
    put_number(encoded, bytes.length, width);
    put(encoded, bytes.data, bytes.length);
}

static void add(FuzzSeed *seeds, size_t *count, const char *name,
                const char *outcome, const SidecarEntry *entry,
                const SidecarXattr *xattrs)
{
    if (*count == MAX_SEEDS)
        die("more seeds than MAX_SEEDS");
    Encoded encoded = {0};
    put_number(&encoded, (uint64_t)entry->kind, 1);
    put_number(&encoded, entry->mode, 4);
    put_number(&encoded, entry->uid, 4);
    put_number(&encoded, entry->gid, 4);
    put_signed(&encoded, entry->atime_sec);
    put_number(&encoded, entry->atime_nsec, 4);
    put_signed(&encoded, entry->mtime_sec);
    put_number(&encoded, entry->mtime_nsec, 4);
    put_number(&encoded, entry->size, 8);
    put_number(&encoded, entry->content_digest, 8);
    put_number(&encoded, entry->xattr_count, 2);
    put_bytes(&encoded, entry->root_id, 2);
    put_bytes(&encoded, entry->logical_path, 2);
    put_bytes(&encoded, entry->physical_leaf, 2);
    put_bytes(&encoded, entry->collision_suffix, 2);
    put_bytes(&encoded, entry->symlink_target, 2);
    put_bytes(&encoded, entry->hardlink_root_id, 2);
    put_bytes(&encoded, entry->hardlink_logical_path, 2);
    for (uint32_t index = 0; index < entry->xattr_count; index++)
    {
        put_bytes(&encoded, xattrs[index].name, 2);
        put_bytes(&encoded, xattrs[index].value, 4);
    }

    FuzzSeed *seed = &seeds[(*count)++];
    memset(seed, 0, sizeof(*seed));
    seed->name = name;
    seed->outcome = outcome;
    seed->data = encoded.data;
    seed->size = encoded.size;
}

static SidecarEntry regular(void)
{
    return (SidecarEntry){
        .root_id = text("HOME"),
        .logical_path = text("docs/notes.txt"),
        .physical_leaf = text("notes.txt"),
        .kind = SIDECAR_KIND_REGULAR,
        .mode = 0644,
        .uid = 1000,
        .gid = 1000,
        .atime_sec = 1700000000,
        .atime_nsec = 5,
        .mtime_sec = -1,
        .mtime_nsec = 999999999,
        .size = 12,
        .content_digest = 0x1234
    };
}

static SidecarEntry other_kind(SidecarObjectKind kind)
{
    SidecarEntry entry = regular();
    entry.kind = kind;
    entry.size = 0;
    entry.content_digest = 0;
    return entry;
}

static void build_written(FuzzSeed *seeds, size_t *count)
{
    // One value holds a NUL, which only this length-prefixed field may.
    static const SidecarXattr xattrs[] = {
        { { (const unsigned char *)"user.a", 6 },
          { (const unsigned char *)"v\0w", 3 } },
        { { (const unsigned char *)"user.empty", 10 }, { NULL, 0 } },
        { { (const unsigned char *)"user.commit", 11 },
          { (const unsigned char *)"\0ENTRY_COMMIT\0", 14 } }
    };
    SidecarEntry entry = regular();
    add(seeds, count, "regular", "written", &entry, NULL);
    entry.xattr_count = 3;
    add(seeds, count, "xattrs", "written", &entry, xattrs);

    entry = other_kind(SIDECAR_KIND_DIRECTORY);
    entry.size = 4096;
    add(seeds, count, "directory", "written", &entry, NULL);
    entry.logical_path = text("");
    entry.physical_leaf = text("");
    add(seeds, count, "root-object", "written", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_SYMLINK);
    entry.symlink_target = text("../target");
    add(seeds, count, "symlink", "written", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_HARDLINK);
    entry.hardlink_root_id = text("XDG_DOCUMENTS_DIR");
    entry.hardlink_logical_path = text("report.txt");
    add(seeds, count, "hardlink", "written", &entry, NULL);
    entry.hardlink_logical_path = text("");
    add(seeds, count, "hardlink-to-root-object", "written", &entry, NULL);

    // Written and parsed; only the claim writer refuses it.
    entry = other_kind(SIDECAR_KIND_FIFO);
    add(seeds, count, "fifo", "written", &entry, NULL);

    entry = regular();
    entry.logical_path = text("dup");
    entry.physical_leaf = text("dup%7E1");
    entry.collision_suffix = text("%7E1");
    add(seeds, count, "collision-suffix", "written", &entry, NULL);

    entry = regular();
    entry.mode = SIDECAR_MAX_MODE;
    entry.uid = UINT32_MAX;
    entry.gid = UINT32_MAX;
    entry.atime_sec = INT64_MIN;
    entry.atime_nsec = SIDECAR_MAX_NSEC;
    entry.mtime_sec = INT64_MAX;
    entry.size = UINT64_MAX;
    entry.content_digest = UINT64_MAX;
    add(seeds, count, "number-ceilings", "written", &entry, NULL);
    entry.mode = 0;
    entry.uid = 0;
    entry.gid = 0;
    entry.atime_sec = 0;
    entry.atime_nsec = 0;
    entry.mtime_sec = 0;
    entry.mtime_nsec = 0;
    entry.size = 0;
    entry.content_digest = 0;
    add(seeds, count, "number-floors", "written", &entry, NULL);

    entry = regular();
    entry.root_id = filled(SIDECAR_MAX_ROOT_ID);
    entry.logical_path = filled(SIDECAR_MAX_PATH);
    entry.physical_leaf = filled(SIDECAR_MAX_PHYSICAL_LEAF);
    entry.collision_suffix = filled(SIDECAR_MAX_COLLISION_SUFFIX);
    add(seeds, count, "field-ceilings", "written", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_SYMLINK);
    entry.symlink_target = filled(SIDECAR_MAX_SYMLINK_TARGET);
    add(seeds, count, "symlink-target-ceiling", "written", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_HARDLINK);
    entry.hardlink_root_id = filled(SIDECAR_MAX_ROOT_ID);
    entry.hardlink_logical_path = filled(SIDECAR_MAX_PATH);
    add(seeds, count, "hardlink-ceilings", "written", &entry, NULL);

    SidecarXattr big = { filled(SIDECAR_MAX_XATTR_NAME),
                         filled(SIDECAR_MAX_XATTR_VALUE) };
    entry = regular();
    entry.xattr_count = 1;
    add(seeds, count, "xattr-ceilings", "written", &entry, &big);
}

static void build_refused(FuzzSeed *seeds, size_t *count)
{
    SidecarEntry entry = regular();
    entry.mode = SIDECAR_MAX_MODE + 1U;
    add(seeds, count, "mode-over-ceiling", "refused", &entry, NULL);

    entry = regular();
    entry.mtime_nsec = SIDECAR_MAX_NSEC + 1U;
    add(seeds, count, "nsec-over-ceiling", "refused", &entry, NULL);

    entry = regular();
    entry.kind = (SidecarObjectKind)(SIDECAR_KIND_HARDLINK + 1);
    add(seeds, count, "unknown-kind", "refused", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_FIFO);
    entry.size = 1;
    add(seeds, count, "fifo-with-size", "refused", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_DIRECTORY);
    entry.content_digest = 1;
    add(seeds, count, "directory-with-digest", "refused", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_SYMLINK);
    add(seeds, count, "symlink-without-target", "refused", &entry, NULL);

    entry = regular();
    entry.symlink_target = text("stray");
    add(seeds, count, "regular-with-target", "refused", &entry, NULL);

    SidecarXattr xattr = { text("user.a"), text("v") };
    entry = other_kind(SIDECAR_KIND_HARDLINK);
    entry.hardlink_root_id = text("HOME");
    entry.xattr_count = 1;
    add(seeds, count, "hardlink-with-xattr", "refused", &entry, &xattr);

    entry = regular();
    entry.root_id = (SidecarBytes){ (const unsigned char *)"HO\0ME", 5 };
    add(seeds, count, "nul-in-root", "refused", &entry, NULL);

    entry = regular();
    entry.root_id = text("");
    add(seeds, count, "empty-root", "refused", &entry, NULL);

    entry = regular();
    entry.logical_path = filled(SIDECAR_MAX_PATH + 1U);
    add(seeds, count, "path-over-ceiling", "refused", &entry, NULL);

    entry = regular();
    entry.physical_leaf = text("..");
    add(seeds, count, "dotdot-leaf", "refused", &entry, NULL);

    entry = regular();
    entry.physical_leaf = text("a/b");
    add(seeds, count, "slash-in-leaf", "refused", &entry, NULL);

    entry = other_kind(SIDECAR_KIND_DIRECTORY);
    entry.logical_path = text("");
    entry.physical_leaf = text("");
    entry.collision_suffix = text("%7E1");
    add(seeds, count, "root-object-with-suffix", "refused", &entry, NULL);

    // A count past the ceiling, with that many xattrs behind it.
    static SidecarXattr many[SIDECAR_MAX_XATTRS_PER_ENTRY + 1U];
    for (size_t index = 0; index < SIDECAR_MAX_XATTRS_PER_ENTRY + 1U; index++)
        many[index] = xattr;
    entry = regular();
    entry.xattr_count = SIDECAR_MAX_XATTRS_PER_ENTRY + 1U;
    add(seeds, count, "xattr-count-over-ceiling", "refused", &entry, many);

    SidecarXattr big = { text("user.big"),
                         filled(SIDECAR_MAX_XATTR_VALUE + 1U) };
    entry = regular();
    entry.xattr_count = 1;
    add(seeds, count, "xattr-value-over-ceiling", "refused", &entry, &big);

    SidecarXattr unnamed = { text(""), text("v") };
    add(seeds, count, "xattr-without-name", "refused", &entry, &unnamed);
}

void fuzz_seeds_build(FuzzSeed **seeds, size_t *count)
{
    *seeds = calloc(MAX_SEEDS, sizeof(**seeds));
    if (*seeds == NULL)
        die("cannot allocate the seeds");
    *count = 0;
    build_written(*seeds, count);
    build_refused(*seeds, count);
}

void fuzz_seeds_free(FuzzSeed *seeds, size_t count)
{
    for (size_t index = 0; index < count; index++)
        free(seeds[index].data);
    free(seeds);
}
