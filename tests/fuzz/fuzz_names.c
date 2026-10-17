// Fuzz harness for the name codecs and validators: the percent encoding in
// both modes, the portable physical-name map, and the checks restore applies
// to journal paths and collision suffixes. Each takes bytes and gives a
// verdict, so one harness serves them all.
//
// Input format: a selector byte (modulo 5; a missing one reads as zero), then
// the subject:
//   0, 1: text for the manifest-path (0) or component (1) codec, up to its
//         first NUL
//   2: collision number 8 (little-endian; what the input lacks reads as
//      zero), then two logical leaves, each up to a NUL
//   3: allow_empty 1, then a relative path, NULs included
//   4: a collision suffix, NULs included
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind. Every output buffer is
//   allocated at exactly the size passed for it.
// - Codecs: decode(encode(x)) == x; each call fits in its output's length
//   plus one and refuses one byte less; decode never emits a NUL (it shrinks
//   the text by two bytes per '%').
// - Name map: accepts exactly the valid components; its leaf is a valid
//   component and journal leaf and ends with the collision suffix, which
//   portable_collision_suffix_parse() reads back as the collision number; two
//   distinct leaves map apart for one collision number unless shortened.
// - Validators agree with the references below, written from the rules; an
//   accepted suffix is the canonical "%7E<number>" of the value it reports.

#define _GNU_SOURCE

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "fuzz.h"
#include "portable.h"
#include "portable_name.h"
#include "sidecar.h"

const char fuzz_target_name[] = "names";

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_names: %s\n", what);
    abort();
}

// The bytes up to the first NUL or the end, as a C string.
static char *text_of(const uint8_t *data, size_t size, size_t *taken)
{
    const uint8_t *nul = memchr(data, '\0', size);
    size_t length = nul != NULL ? (size_t)(nul - data) : size;
    char *text = malloc(length + 1U);
    if (text == NULL)
        fail("cannot allocate a text");
    memcpy(text, data, length);
    text[length] = '\0';
    if (taken != NULL)
        *taken = nul != NULL ? length + 1U : length;
    return text;
}

typedef int (*Codec)(EncodingMode mode, const char *in, char *out,
                     size_t out_size);

// Runs codec into a buffer of exactly out_size bytes; the result, if any,
// is a C string the caller frees.
static char *run_codec(Codec codec, EncodingMode mode, const char *in,
                       size_t out_size)
{
    char *out = malloc(out_size > 0 ? out_size : 1U);
    if (out == NULL)
        fail("cannot allocate a codec buffer");
    if (codec(mode, in, out, out_size) == 0)
        return out;
    free(out);
    return NULL;
}

// Codes in at the size its first result needs, and one byte less.
static char *code_exactly(Codec codec, EncodingMode mode, const char *in,
                          size_t room)
{
    char *roomy = run_codec(codec, mode, in, room);
    if (roomy == NULL)
        return NULL;
    size_t length = strlen(roomy);
    char *exact = run_codec(codec, mode, in, length + 1U);
    char *short_one = run_codec(codec, mode, in, length);
    if (exact == NULL || strcmp(exact, roomy) != 0)
        fail("a codec refuses, or changes, an output of exactly its size");
    if (short_one != NULL)
        fail("a codec writes past the size it was given");
    free(roomy);
    return exact;
}

static size_t count_byte(const char *text, char byte)
{
    size_t count = 0;
    for (; *text != '\0'; text++)
        count += *text == byte;
    return count;
}

static const char *check_codec(EncodingMode mode, const uint8_t *data,
                               size_t size)
{
    char *text = text_of(data, size, NULL);
    size_t length = strlen(text);

    char *encoded = code_exactly(encoding_percent_encode, mode, text,
                                 3U * length + 1U);
    if (encoded == NULL)
        fail("the encoder refuses a text");
    char *round = code_exactly(encoding_percent_decode, mode, encoded,
                               strlen(encoded) + 1U);
    if (round == NULL || strcmp(round, text) != 0)
        fail("decoding an encoded text does not give it back");
    free(round);
    free(encoded);

    char *decoded = code_exactly(encoding_percent_decode, mode, text,
                                 length + 1U);
    if (decoded != NULL &&
        strlen(decoded) != length - 2U * count_byte(text, '%'))
        fail("a decoded text holds a NUL");
    const char *outcome = decoded != NULL ? "valid" : "invalid";
    free(decoded);
    free(text);
    return outcome;
}

static int component_ok(const uint8_t *data, size_t length)
{
    return length != 0 && length <= NAME_MAX &&
           memchr(data, '/', length) == NULL &&
           memchr(data, '\0', length) == NULL &&
           !(length == 1 && data[0] == '.') &&
           !(length == 2 && data[0] == '.' && data[1] == '.');
}

static int ends_with(const char *text, const char *suffix)
{
    size_t length = strlen(text);
    size_t suffix_length = strlen(suffix);
    return suffix_length <= length &&
           strcmp(text + length - suffix_length, suffix) == 0;
}

static void check_mapped(const char *logical, uint64_t collision_number,
                         const PortablePhysicalName *mapped)
{
    size_t length = strlen(mapped->physical_leaf);
    SidecarBytes logical_bytes = { (const unsigned char *)logical,
                                   strlen(logical) };
    SidecarBytes leaf = { (const unsigned char *)mapped->physical_leaf,
                          length };
    if (!component_ok(leaf.data, length) ||
        !sidecar_physical_leaf_valid(logical_bytes, leaf))
        fail("a mapped leaf is not a valid component");

    char suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U] = "";
    if (collision_number != 0)
        snprintf(suffix, sizeof(suffix), "%%7E%" PRIu64, collision_number);
    if (strcmp(mapped->collision_suffix, suffix) != 0 ||
        !ends_with(mapped->physical_leaf, suffix))
        fail("a mapped leaf does not end with its collision suffix");

    uint64_t parsed = 0;
    if (collision_number != 0 &&
        (!portable_collision_suffix_parse(suffix, strlen(suffix), &parsed) ||
         parsed != collision_number))
        fail("a mapped collision suffix does not parse back");
}

static const char *check_name_map(const uint8_t *data, size_t size)
{
    uint64_t collision_number = 0;
    size_t at = 0;
    for (; at < 8U; at++)
        collision_number |= (uint64_t)(at < size ? data[at] : 0) << (8U * at);
    at = size < at ? size : at;

    size_t taken;
    char *first = text_of(data + at, size - at, &taken);
    at += taken;
    char *second = text_of(data + at, size - at, NULL);

    PortablePhysicalName first_mapped, second_mapped;
    int first_ok = portable_physical_name_map(first, collision_number,
                                              &first_mapped) == 0;
    int second_ok = portable_physical_name_map(second, collision_number,
                                               &second_mapped) == 0;
    if (first_ok != component_ok((const uint8_t *)first, strlen(first)) ||
        second_ok != component_ok((const uint8_t *)second, strlen(second)))
        fail("the name map's verdict differs from the component rule");
    if (first_ok)
        check_mapped(first, collision_number, &first_mapped);
    if (second_ok)
        check_mapped(second, collision_number, &second_mapped);
    if (first_ok && second_ok && !first_mapped.shortened &&
        !second_mapped.shortened && strcmp(first, second) != 0 &&
        strcmp(first_mapped.physical_leaf, second_mapped.physical_leaf) == 0)
        fail("two leaves map to one physical leaf");

    free(first);
    free(second);
    return first_ok ? "valid" : "invalid";
}

static int relative_ok(const uint8_t *data, size_t length, int allow_empty)
{
    if (length == 0)
        return allow_empty;
    if (length >= PATH_MAX)
        return 0;
    size_t start = 0;
    for (size_t index = 0; index <= length; index++)
        if (index == length || data[index] == '/')
        {
            if (!component_ok(data + start, index - start))
                return 0;
            start = index + 1U;
        }
    return 1;
}

static const char *check_relative(const uint8_t *data, size_t size)
{
    int allow_empty = size > 0 && (data[0] & 1U);
    const uint8_t *path = size > 0 ? data + 1 : data;
    size_t length = size > 0 ? size - 1U : 0;
    int valid = portable_relative_bytes_valid((const char *)path, length,
                                              allow_empty);
    if (valid != relative_ok(path, length, allow_empty))
        fail("the relative-path check differs from the rule");
    return valid ? "valid" : "invalid";
}

// "%7E", a nonzero digit, more digits, at most SIDECAR_MAX_COLLISION_SUFFIX
// bytes, and a value that fits in 64 bits.
static int suffix_ok(const uint8_t *data, size_t length)
{
    static const char max_digits[] = "18446744073709551615";
    if (length < 4U || length > SIDECAR_MAX_COLLISION_SUFFIX ||
        memcmp(data, "%7E", 3) != 0 || data[3] < '1' || data[3] > '9')
        return 0;
    for (size_t index = 4U; index < length; index++)
        if (data[index] < '0' || data[index] > '9')
            return 0;
    size_t digits = length - 3U;
    return digits < sizeof(max_digits) - 1U ||
           (digits == sizeof(max_digits) - 1U &&
            memcmp(data + 3, max_digits, digits) <= 0);
}

static const char *check_suffix(const uint8_t *data, size_t size)
{
    uint64_t value = 0;
    int valid = portable_collision_suffix_parse((const char *)data, size,
                                                &value);
    if (valid != suffix_ok(data, size))
        fail("the collision-suffix check differs from the rule");
    if (valid)
    {
        char canonical[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
        int length = snprintf(canonical, sizeof(canonical), "%%7E%" PRIu64,
                              value);
        if (length < 0 || (size_t)length != size ||
            memcmp(canonical, data, size) != 0)
            fail("an accepted suffix is not its value's canonical form");
    }
    return valid ? "valid" : "invalid";
}

static const char *check_input(const uint8_t *data, size_t size)
{
    unsigned selector = size > 0 ? data[0] % 5U : 0;
    const uint8_t *subject = size > 0 ? data + 1 : data;
    size_t length = size > 0 ? size - 1U : 0;
    switch (selector)
    {
        case 0:
            return check_codec(ENCODING_MODE_MANIFEST_PATH, subject, length);
        case 1:
            return check_codec(ENCODING_MODE_COMPONENT, subject, length);
        case 2:
            return check_name_map(subject, length);
        case 3:
            return check_relative(subject, length);
        default:
            return check_suffix(subject, length);
    }
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
