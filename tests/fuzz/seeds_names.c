// Generated seeds for the names fuzzer, in the input format fuzz_names.c
// reads: for each codec, check, and the name map, the cases its rules name
// and one past each. Each seed states whether its subject is valid.

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "sidecar.h"

#define MAX_SEEDS 64U

enum { MANIFEST_CODEC, COMPONENT_CODEC, NAME_MAP, RELATIVE_PATH, SUFFIX };

static void die(const char *what)
{
    fprintf(stderr, "fuzz seeds: %s\n", what);
    abort();
}

// A seed of the selector, the head bytes, and the subject bytes.
static void add_bytes(FuzzSeed *seeds, size_t *count, const char *name,
                      const char *outcome, unsigned char selector,
                      const void *head, size_t head_size,
                      const void *subject, size_t subject_size)
{
    if (*count == MAX_SEEDS)
        die("more seeds than MAX_SEEDS");
    FuzzSeed *seed = &seeds[(*count)++];
    memset(seed, 0, sizeof(*seed));
    seed->name = name;
    seed->outcome = outcome;
    seed->size = 1U + head_size + subject_size;
    seed->data = malloc(seed->size);
    if (seed->data == NULL)
        die("cannot allocate a seed");
    seed->data[0] = selector;
    if (head_size > 0)
        memcpy(seed->data + 1, head, head_size);
    if (subject_size > 0)
        memcpy(seed->data + 1 + head_size, subject, subject_size);
}

static void add_text(FuzzSeed *seeds, size_t *count, const char *name,
                     const char *outcome, unsigned char selector,
                     const char *subject)
{
    add_bytes(seeds, count, name, outcome, selector, NULL, 0, subject,
              strlen(subject));
}

// length bytes of fill, from a buffer large enough for every seed.
static const char *filled(char byte, size_t length)
{
    static char fill[PATH_MAX + 1U];
    if (length >= sizeof(fill))
        die("a filled subject past every ceiling");
    memset(fill, byte, length);
    fill[length] = '\0';
    return fill;
}

// Valid components joined by '/', length bytes in all; it ends in a
// component for each length the seeds use.
static const char *long_path(size_t length)
{
    static char path[PATH_MAX + 1U];
    if (length >= sizeof(path))
        die("a path past every ceiling");
    for (size_t index = 0; index < length; index++)
        path[index] = index % 100U == 99U ? '/' : 'p';
    path[length] = '\0';
    return path;
}

static void build_codecs(FuzzSeed *seeds, size_t *count)
{
    add_text(seeds, count, "manifest-path", "valid", MANIFEST_CODEC,
             "home/user/Documents");
    add_text(seeds, count, "manifest-empty", "valid", MANIFEST_CODEC, "");
    add_text(seeds, count, "manifest-escapes", "valid", MANIFEST_CODEC,
             "My%20Files/%C3%A7%2F");
    add_text(seeds, count, "manifest-lowercase-escape", "valid",
             MANIFEST_CODEC, "%c3%a7");
    add_text(seeds, count, "manifest-raw-space", "invalid", MANIFEST_CODEC,
             "My Files");
    add_text(seeds, count, "manifest-escaped-nul", "invalid", MANIFEST_CODEC,
             "a%00b");
    add_text(seeds, count, "manifest-short-escape", "invalid",
             MANIFEST_CODEC, "a%4");
    add_text(seeds, count, "manifest-bad-hex", "invalid", MANIFEST_CODEC,
             "%zz");

    add_text(seeds, count, "component", "valid", COMPONENT_CODEC,
             "notes.txt");
    add_text(seeds, count, "component-raw-utf8", "valid", COMPONENT_CODEC,
             "\xc3\xa7" "ay");
    add_text(seeds, count, "component-escaped-trailing-dot", "valid",
             COMPONENT_CODEC, "a%2E");
    // The decode is the encoding's inverse, not a filename check.
    add_text(seeds, count, "component-escaped-slash", "valid",
             COMPONENT_CODEC, "a%2Fb");
    add_text(seeds, count, "component-raw-trailing-dot", "invalid",
             COMPONENT_CODEC, "a.");
    add_text(seeds, count, "component-raw-slash", "invalid", COMPONENT_CODEC,
             "a/b");
    add_text(seeds, count, "component-lone-lead-byte", "invalid",
             COMPONENT_CODEC, "a\xc3");
    add_text(seeds, count, "component-overlong-utf8", "invalid",
             COMPONENT_CODEC, "\xc0\xaf");
    add_text(seeds, count, "component-escaped-nul", "invalid",
             COMPONENT_CODEC, "%00");
}

static void add_map(FuzzSeed *seeds, size_t *count, const char *name,
                    const char *outcome, uint64_t collision_number,
                    const char *first, const char *second)
{
    unsigned char head[8];
    for (size_t index = 0; index < sizeof(head); index++)
        head[index] = (unsigned char)(collision_number >> (8U * index));
    size_t first_size = strlen(first) + 1U;
    size_t second_size = strlen(second);
    char *leaves = malloc(first_size + second_size);
    if (leaves == NULL)
        die("cannot allocate leaves");
    memcpy(leaves, first, first_size);
    memcpy(leaves + first_size, second, second_size);
    add_bytes(seeds, count, name, outcome, NAME_MAP, head, sizeof(head),
              leaves, first_size + second_size);
    free(leaves);
}

static void build_name_map(FuzzSeed *seeds, size_t *count)
{
    add_map(seeds, count, "map", "valid", 0, "notes.txt", "notes.txt.bak");
    add_map(seeds, count, "map-collision", "valid", 1, "Notes", "notes");
    add_map(seeds, count, "map-tilde-suffix", "valid", 1, "a~1", "a");
    add_map(seeds, count, "map-collision-ceiling", "valid", UINT64_MAX,
            "a", "b");
    add_map(seeds, count, "map-escapes", "valid", 0, "a b.", ".hidden");
    add_map(seeds, count, "map-name-max", "valid", 0,
            filled('n', NAME_MAX), "n");
    // Every space escapes to three bytes, so the leaf is shortened.
    add_map(seeds, count, "map-shortened", "valid", 2, filled(' ', NAME_MAX),
            "x");
    add_map(seeds, count, "map-over-name-max", "invalid", 0,
            filled('n', NAME_MAX + 1U), "n");
    add_map(seeds, count, "map-empty", "invalid", 0, "", "a");
    add_map(seeds, count, "map-dot", "invalid", 0, ".", "a");
    add_map(seeds, count, "map-dotdot", "invalid", 0, "..", "a");
    add_map(seeds, count, "map-slash", "invalid", 0, "a/b", "a");
}

static void add_relative(FuzzSeed *seeds, size_t *count, const char *name,
                         const char *outcome, int allow_empty,
                         const void *path, size_t length)
{
    unsigned char flag = allow_empty ? 1U : 0U;
    add_bytes(seeds, count, name, outcome, RELATIVE_PATH, &flag, 1, path,
              length);
}

static void add_relative_text(FuzzSeed *seeds, size_t *count,
                              const char *name, const char *outcome,
                              int allow_empty, const char *path)
{
    add_relative(seeds, count, name, outcome, allow_empty, path,
                 strlen(path));
}

static void build_relative(FuzzSeed *seeds, size_t *count)
{
    add_relative_text(seeds, count, "relative", "valid", 0, "a/b/c.txt");
    add_relative_text(seeds, count, "relative-empty-allowed", "valid", 1,
                      "");
    add_relative_text(seeds, count, "relative-under-path-max", "valid", 0,
                      long_path(PATH_MAX - 1U));
    add_relative_text(seeds, count, "relative-empty", "invalid", 0, "");
    add_relative_text(seeds, count, "relative-absolute", "invalid", 0,
                      "/etc/passwd");
    add_relative_text(seeds, count, "relative-trailing-slash", "invalid", 0,
                      "a/");
    add_relative_text(seeds, count, "relative-empty-component", "invalid", 0,
                      "a//b");
    add_relative_text(seeds, count, "relative-dotdot", "invalid", 0,
                      "a/../b");
    add_relative_text(seeds, count, "relative-dot", "invalid", 0, "./a");
    add_relative(seeds, count, "relative-nul", "invalid", 0, "a\0b", 3);
    add_relative_text(seeds, count, "relative-over-name-max", "invalid", 0,
                      filled('c', NAME_MAX + 1U));
    add_relative_text(seeds, count, "relative-path-max", "invalid", 0,
                      long_path(PATH_MAX));
}

static void build_suffix(FuzzSeed *seeds, size_t *count)
{
    add_text(seeds, count, "suffix", "valid", SUFFIX, "%7E1");
    add_text(seeds, count, "suffix-ceiling", "valid", SUFFIX,
             "%7E18446744073709551615");
    add_text(seeds, count, "suffix-over-ceiling", "invalid", SUFFIX,
             "%7E18446744073709551616");
    add_text(seeds, count, "suffix-zero", "invalid", SUFFIX, "%7E0");
    add_text(seeds, count, "suffix-leading-zero", "invalid", SUFFIX,
             "%7E01");
    add_text(seeds, count, "suffix-lowercase", "invalid", SUFFIX, "%7e1");
    add_text(seeds, count, "suffix-without-number", "invalid", SUFFIX,
             "%7E");
    add_text(seeds, count, "suffix-letter", "invalid", SUFFIX, "%7E1a");
    add_bytes(seeds, count, "suffix-nul", "invalid", SUFFIX, NULL, 0,
              "%7E1\0", 5);
}

void fuzz_seeds_build(FuzzSeed **seeds, size_t *count)
{
    *seeds = calloc(MAX_SEEDS, sizeof(**seeds));
    if (*seeds == NULL)
        die("cannot allocate the seeds");
    *count = 0;
    build_codecs(*seeds, count);
    build_name_map(*seeds, count);
    build_relative(*seeds, count);
    build_suffix(*seeds, count);
}

void fuzz_seeds_free(FuzzSeed *seeds, size_t count)
{
    for (size_t index = 0; index < count; index++)
        free(seeds[index].data);
    free(seeds);
}
