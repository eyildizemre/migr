// Generated seeds for the home-rewrite fuzzer, in the input format
// fuzz_home_rewrite.c decodes: the pairs restore builds for a file and for a
// dconf dump, matches at and past a path component's end, and chunkings that
// cut a match, its boundary byte, and a full read after a carried tail. Each
// seed states whether the rewrite changes its text.

#define _GNU_SOURCE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "home_rewrite.h"

#define MAX_SEEDS 24U
#define URI_MAX (HOME_REWRITE_URI_PREFIX_LENGTH + PATH_MAX - 1U)

typedef struct {
    const char *source;
    const char *destination;
} Pair;

typedef struct {
    unsigned char *data;
    size_t size;
} Encoded;

static void die(const char *what)
{
    fprintf(stderr, "fuzz seeds: %s\n", what);
    abort();
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

static void put_number(Encoded *encoded, size_t value, size_t width)
{
    for (size_t index = 0; index < width; index++)
    {
        unsigned char byte = (unsigned char)(value >> (8U * index));
        put(encoded, &byte, 1);
    }
}

// A string the harness reads back whole: its length minus one, then it.
static void put_string(Encoded *encoded, const char *text, size_t length)
{
    if (length == 0 || length > URI_MAX)
        die("a seed string the harness cannot read back");
    put_number(encoded, length - 1U, 2);
    put(encoded, text, length);
}

static void add_bytes(FuzzSeed *seeds, size_t *count, const char *name,
                      const char *outcome, const Pair *pairs,
                      size_t pair_count, const size_t *chunks,
                      size_t chunk_count, const char *text, size_t length)
{
    if (*count == MAX_SEEDS)
        die("more seeds than MAX_SEEDS");
    Encoded encoded = {0};
    put_number(&encoded, pair_count - 1U, 1);
    for (size_t index = 0; index < pair_count; index++)
    {
        put_string(&encoded, pairs[index].source,
                   strlen(pairs[index].source));
        put_string(&encoded, pairs[index].destination,
                   strlen(pairs[index].destination));
    }
    put_number(&encoded, chunk_count, 1);
    for (size_t index = 0; index < chunk_count; index++)
        put_number(&encoded, chunks[index] - 1U, 2);
    put(&encoded, text, length);

    FuzzSeed *seed = &seeds[(*count)++];
    memset(seed, 0, sizeof(*seed));
    seed->name = name;
    seed->outcome = outcome;
    seed->data = encoded.data;
    seed->size = encoded.size;
}

static void add(FuzzSeed *seeds, size_t *count, const char *name,
                const char *outcome, const Pair *pairs, size_t pair_count,
                const size_t *chunks, size_t chunk_count, const char *text)
{
    add_bytes(seeds, count, name, outcome, pairs, pair_count, chunks,
              chunk_count, text, strlen(text));
}

// The pairs home_rewrite_pairs_build() gives for a home with one XDG folder,
// the folder first.
static const Pair file_pairs[] = {
    { "file:///home/old/Belgeler", "file:///home/new/Documents" },
    { "file:///home/old", "file:///home/new" }
};

// The same as home_rewrite_dconf_pairs_build() gives them.
static const Pair dconf_pairs[] = {
    { "file:///home/old/Belgeler", "file:///home/new/Documents" },
    { "'/home/old/Belgeler", "'/home/new/Documents" },
    { "\"/home/old/Belgeler", "\"/home/new/Documents" },
    { "file:///home/old", "file:///home/new" },
    { "'/home/old", "'/home/new" },
    { "\"/home/old", "\"/home/new" }
};

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

// A file:// URI of URI_MAX bytes, the longest source a caller passes.
static const char *longest_source(void)
{
    static char source[URI_MAX + 1U];
    memcpy(source, "file://", 7);
    memset(source + 7, 'l', URI_MAX - 7U);
    source[URI_MAX] = '\0';
    return source;
}

static void build_whole(FuzzSeed *seeds, size_t *count)
{
    add(seeds, count, "recent-file", "changed", file_pairs,
        COUNT(file_pairs), NULL, 0,
        "<bookmark href=\"file:///home/old/Belgeler/report.odt\"/>\n"
        "<bookmark href=\"file:///home/old/notes.txt\"/>\n");
    add(seeds, count, "home-itself", "changed", file_pairs,
        COUNT(file_pairs), NULL, 0, "file:///home/old");
    add(seeds, count, "longer-name", "unchanged", file_pairs,
        COUNT(file_pairs), NULL, 0, "file:///home/olden/a file:///home/old2");
    add(seeds, count, "other-home", "unchanged", file_pairs,
        COUNT(file_pairs), NULL, 0, "file:///home/other/a\n");
    add(seeds, count, "dconf-dump", "changed", dconf_pairs,
        COUNT(dconf_pairs), NULL, 0,
        "[org/gnome/nautilus]\nlast-folder='/home/old/Belgeler'\n"
        "favorites=[\"/home/old/Music\", 'file:///home/old']\n");
    add(seeds, count, "empty-text", "unchanged", file_pairs,
        COUNT(file_pairs), NULL, 0, "");

    // A rejected candidate whose own suffix starts a later match.
    static const Pair repeating[] = { { "/x/x", "/y" } };
    add(seeds, count, "self-overlapping-source", "changed", repeating,
        COUNT(repeating), NULL, 0, "/x/xx/x/x\n");

    const Pair longest[] = { { longest_source(), "file:///short" } };
    static char long_text[URI_MAX + 3U];
    snprintf(long_text, sizeof(long_text), "%s/\n", longest_source());
    add(seeds, count, "longest-source", "changed", longest, COUNT(longest),
        NULL, 0, long_text);
}

static void build_chunked(FuzzSeed *seeds, size_t *count)
{
    const char *text = "a file:///home/old/Belgeler/b c\n";

    static const size_t inside_match[] = { 10, 3, 1 };
    add(seeds, count, "chunk-inside-match", "changed", file_pairs,
        COUNT(file_pairs), inside_match, COUNT(inside_match), text);

    // The match ends a chunk; its boundary byte comes with the next.
    static const size_t before_boundary[] = { 27 };
    add(seeds, count, "chunk-before-boundary", "changed", file_pairs,
        COUNT(file_pairs), before_boundary, COUNT(before_boundary), text);

    static const size_t single_bytes[] = { 1, 1, 1, 1, 1, 1, 1, 1,
                                           1, 1, 1, 1, 1, 1, 1, 1 };
    add(seeds, count, "single-byte-chunks", "changed", file_pairs,
        COUNT(file_pairs), single_bytes, COUNT(single_bytes),
        "file:///home/old/x\n");

    // The shorter pair matches first; the longer one needs the next chunk
    // to know it matches too.
    static const size_t between_pairs[] = { 20 };
    add(seeds, count, "chunk-between-pairs", "changed", file_pairs,
        COUNT(file_pairs), between_pairs, COUNT(between_pairs),
        "file:///home/old/Belgeler\n");

    // With the longest source among the pairs the copy carries URI_MAX
    // bytes past a read, and a full read lands behind them; a match
    // straddles the two.
    const Pair carrying[] = { file_pairs[0], file_pairs[1],
                              { longest_source(), "file:///short" } };
    static char large[65536U + 4096U + 100U];
    size_t length = sizeof(large);
    memset(large, 'z', length);
    memcpy(large + 4190U, "file:///home/old/Belgeler/", 26);
    memcpy(large + length - 18U, " file:///home/old", 17);
    large[length - 1U] = '\n';
    static const size_t carry_then_full[] = { 4200, 65536 };
    add_bytes(seeds, count, "carry-then-full-read", "changed", carrying,
              COUNT(carrying), carry_then_full, COUNT(carry_then_full),
              large, length);
}

static void build_skipped(FuzzSeed *seeds, size_t *count)
{
    add_bytes(seeds, count, "nul-in-text", "skipped", file_pairs,
              COUNT(file_pairs), NULL, 0, "file:///home/old\0/a", 19);
    // The destination's one byte, after the pair count, the source, and
    // the destination's length, becomes a NUL.
    static const Pair nul_pair[] = { { "file:///home/old", "a" } };
    add(seeds, count, "nul-in-pair", "skipped", nul_pair, COUNT(nul_pair),
        NULL, 0, "file:///home/old/a");
    unsigned char *destination = &seeds[*count - 1U].data[1U + 2U + 16U + 2U];
    if (*destination != 'a')
        die("the nul-in-pair seed has no destination there");
    *destination = '\0';
}

void fuzz_seeds_build(FuzzSeed **seeds, size_t *count)
{
    *seeds = calloc(MAX_SEEDS, sizeof(**seeds));
    if (*seeds == NULL)
        die("cannot allocate the seeds");
    *count = 0;
    build_whole(*seeds, count);
    build_chunked(*seeds, count);
    build_skipped(*seeds, count);
}

void fuzz_seeds_free(FuzzSeed *seeds, size_t count)
{
    for (size_t index = 0; index < count; index++)
        free(seeds[index].data);
    free(seeds);
}
