// Fuzz harness for the home-path rewrite restore applies to desktop state:
// home_rewrite_copy() streams a file through the replacement in reads, and
// home_rewrite_text() runs it over a whole buffer. The text reaches the
// copy through a SOCK_SEQPACKET socket, which returns one sent message per
// read, so the input chooses where the reads end.
//
// Input format, numbers little-endian, every byte string a length followed
// by that many bytes (what the input lacks reads as zero or empty):
//   pair_count 1 | per pair: source, destination (length 2 each) |
//   chunk_count 1 | chunk sizes 2 each | the text, the rest of the input
// Counts and lengths are taken modulo their ceilings, plus one.
//
// The callers' pairs come from C strings, nonempty and at most URI_MAX
// bytes, and the dconf text is a C string too: an input that holds a NUL in
// either, or an empty pair, is skipped, as is a text larger than the socket
// holds at once.
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind.
// - The streamed output equals the whole-buffer output for any chunking.
// - The copy's digests are those of the bytes it wrote and read.

#define _GNU_SOURCE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fuzz.h"
#include "hash.h"
#include "home_rewrite.h"

// The longest URI pair_set() builds: the prefix and a path shorter than
// PATH_MAX.
#define URI_MAX (HOME_REWRITE_URI_PREFIX_LENGTH + PATH_MAX - 1U)
#define MAX_CHUNKS 16U
// One read's worth: the copy reads at most 64 KiB at a time.
#define MAX_CHUNK 65536U
// Every message sits in the socket before the copy reads the first, so the
// text stays well inside its default send buffer.
#define MAX_TEXT (MAX_CHUNK + MAX_CHUNK / 2U)

const char fuzz_target_name[] = "home_rewrite";

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t at;
} Input;

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_home_rewrite: %s\n", what);
    abort();
}

static size_t take_number(Input *input, size_t width)
{
    size_t value = 0;
    for (size_t index = 0; index < width; index++)
    {
        size_t byte = input->at < input->size ? input->data[input->at++] : 0;
        value |= byte << (8U * index);
    }
    return value;
}

// A string of 1 to ceiling bytes; nonzero when it is nonempty and holds no
// NUL.
static int take_string(Input *input, unsigned char *out, size_t *length,
                       size_t ceiling)
{
    size_t wanted = take_number(input, 2) % ceiling + 1U;
    size_t left = input->size - input->at;
    *length = wanted < left ? wanted : left;
    memcpy(out, input->data + input->at, *length);
    input->at += *length;
    return *length != 0 && memchr(out, '\0', *length) == NULL;
}

static unsigned char *stream_copy(const char *text, size_t length,
                                  const size_t *chunks, size_t chunk_count,
                                  const HomeRewritePair *pairs,
                                  size_t pair_count, size_t *out_length)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
        fail("cannot create a socket pair");
    size_t sent = 0;
    for (size_t index = 0; sent < length; index++)
    {
        size_t chunk = index < chunk_count ? chunks[index] : MAX_CHUNK;
        if (chunk > length - sent)
            chunk = length - sent;
        if (send(sockets[0], text + sent, chunk, 0) != (ssize_t)chunk)
            fail("cannot send a chunk");
        sent += chunk;
    }
    shutdown(sockets[0], SHUT_WR);

    int out = memfd_create("fuzz-rewrite", MFD_CLOEXEC);
    uint64_t digest = 0, source_digest = 0;
    if (out < 0 ||
        home_rewrite_copy(sockets[1], out, (off_t)length, pairs, pair_count,
                          NULL, &digest, &source_digest) != 0)
        fail("the streamed copy fails");
    off_t size = lseek(out, 0, SEEK_CUR);
    unsigned char *written = malloc(size > 0 ? (size_t)size : 1U);
    if (size < 0 || written == NULL ||
        pread(out, written, (size_t)size, 0) != size)
        fail("cannot read the streamed copy back");
    close(out);
    close(sockets[0]);
    close(sockets[1]);

    *out_length = (size_t)size;
    if (digest != hash_fnv1a_bytes(HASH_FNV1A_OFFSET_BASIS, written,
                                   *out_length) ||
        source_digest != hash_fnv1a_bytes(HASH_FNV1A_OFFSET_BASIS,
                                          (const unsigned char *)text,
                                          length))
        fail("a digest differs from the bytes copied");
    return written;
}

static const char *check_input(const uint8_t *data, size_t size)
{
    Input input = { data, size, 0 };
    static HomeRewritePair pairs[HOME_REWRITE_DCONF_MAX_PAIRS];
    size_t pair_count = take_number(&input, 1) %
                        HOME_REWRITE_DCONF_MAX_PAIRS + 1U;
    int valid = 1;
    for (size_t index = 0; index < pair_count; index++)
    {
        HomeRewritePair *pair = &pairs[index];
        valid &= take_string(&input, pair->source_uri,
                             &pair->source_uri_length, URI_MAX);
        valid &= take_string(&input, pair->destination_uri,
                             &pair->destination_uri_length, URI_MAX);
    }
    size_t chunks[MAX_CHUNKS];
    size_t chunk_count = take_number(&input, 1) % (MAX_CHUNKS + 1U);
    for (size_t index = 0; index < chunk_count; index++)
        chunks[index] = take_number(&input, 2) % MAX_CHUNK + 1U;

    const char *text = (const char *)data + input.at;
    size_t length = size - input.at;
    if (!valid || length > MAX_TEXT || memchr(text, '\0', length) != NULL)
        return "skipped";

    char *whole_text = strndup(text, length);
    char *expected = whole_text != NULL
        ? home_rewrite_text(whole_text, pairs, pair_count) : NULL;
    if (expected == NULL)
        fail("the whole-buffer rewrite fails");
    size_t streamed_length;
    unsigned char *streamed = stream_copy(text, length, chunks, chunk_count,
                                          pairs, pair_count,
                                          &streamed_length);
    if (streamed_length != strlen(expected) ||
        memcmp(streamed, expected, streamed_length) != 0)
        fail("the streamed output differs from the whole-buffer output");

    const char *outcome = streamed_length == length &&
                          memcmp(streamed, text, length) == 0
        ? "unchanged" : "changed";
    free(streamed);
    free(expected);
    free(whole_text);
    return outcome;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    check_input(data, size);
    return 0;
}

const char *fuzz_outcome(const uint8_t *data, size_t size)
{
    return check_input(data, size);
}

const char *fuzz_seed_outcome(const FuzzSeed *seed)
{
    return seed->outcome;
}

void fuzz_check_seed(const FuzzSeed *seed)
{
    (void)seed;
}
