// Unit tests for the shared percent encoder/decoder (docs/DECISIONS.md D19).
// It covers both the existing manifest-path mode and the component mode used
// by portable payload names.

#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void test_problem_bytes_round_trip(void)
{
    printf(BLUE "::" NC " encoding: manifest-path problem bytes round-trip\n");

    const char raw[] = "safe.A_/-=\twith%percent\nand-newline\xFF";
    char encoded[256];
    char decoded[sizeof(raw)];

    check(encoding_percent_encode(ENCODING_MODE_MANIFEST_PATH,
                                  raw, encoded, sizeof(encoded)) == 0,
          "problem bytes encode successfully");
    check(encoding_percent_decode(ENCODING_MODE_MANIFEST_PATH,
                                  encoded, decoded, sizeof(decoded)) == 0,
          "encoded problem bytes decode successfully");
    check(memcmp(decoded, raw, sizeof(raw)) == 0,
          "decoded bytes match the original exactly");
}

static void test_decode_rejects_malformed_values(void)
{
    printf(BLUE "::" NC " encoding: malformed manifest-path values are refused\n");

    char out[32];
    check(encoding_percent_decode(ENCODING_MODE_MANIFEST_PATH,
                                  "%ZZ", out, sizeof(out)) != 0,
          "bad hex escape is refused");
    check(encoding_percent_decode(ENCODING_MODE_MANIFEST_PATH,
                                  "%", out, sizeof(out)) != 0,
          "trailing percent with no hex digits is refused");
    check(encoding_percent_decode(ENCODING_MODE_MANIFEST_PATH,
                                  "%4", out, sizeof(out)) != 0,
          "trailing percent with one hex digit is refused");
    check(encoding_percent_decode(ENCODING_MODE_MANIFEST_PATH,
                                  "%00", out, sizeof(out)) != 0,
          "decoded NUL is refused");
}

static void test_decode_overflow_is_refused(void)
{
    printf(BLUE "::" NC " encoding: decoded path overflow is refused\n");

    char encoded[3 * PATH_MAX + 1];
    char decoded[PATH_MAX];
    size_t offset = 0;
    for (size_t i = 0; i < PATH_MAX; i++)
    {
        encoded[offset++] = '%';
        encoded[offset++] = '4';
        encoded[offset++] = '1';
    }
    encoded[offset] = '\0';

    check(encoding_percent_decode(ENCODING_MODE_MANIFEST_PATH,
                                  encoded, decoded, sizeof(decoded)) != 0,
          "decoded value reaching PATH_MAX is refused, not truncated");
}

static void test_encode_overflow_is_refused(void)
{
    printf(BLUE "::" NC " encoding: encoded output overflow is refused\n");

    char out[3];
    check(encoding_percent_encode(ENCODING_MODE_MANIFEST_PATH,
                                  "=", out, sizeof(out)) != 0,
          "encoded output that cannot fit is refused");
}

static void check_component_encoding(const char *raw, const char *expected,
                                     const char *label)
{
    char encoded[256];
    check(encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                  raw, encoded, sizeof(encoded)) == 0 &&
          strcmp(encoded, expected) == 0, label);
}

static void check_component_round_trip(const char *raw, const char *label)
{
    char encoded[256];
    char decoded[256];
    size_t raw_length = strlen(raw);

    int encoded_ok = encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                              raw, encoded, sizeof(encoded)) == 0;
    int decoded_ok = encoded_ok &&
        encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                encoded, decoded, sizeof(decoded)) == 0;
    check(encoded_ok && decoded_ok &&
          memcmp(decoded, raw, raw_length + 1) == 0, label);
}

static void test_component_n1_rules(void)
{
    printf(BLUE "::" NC " encoding: component N-1 rules\n");

    check_component_encoding("/", "%2F",
                             "a slash is always percent-encoded in a component");
    check_component_encoding("a..", "a.%2E",
                             "only the final byte of a.. is encoded");
    check_component_encoding("a...", "a..%2E",
                             "only the final byte of a... is encoded");
    check_component_encoding("%", "%25",
                             "a literal percent is percent-encoded");
    check_component_round_trip("/",
                               "a slash round-trips through component encoding");
    check_component_round_trip("a..",
                               "a.. round-trips through component encoding");
    check_component_round_trip("a...",
                               "a... round-trips through component encoding");
    check_component_round_trip("%",
                               "a literal percent round-trips through component encoding");

    const char two_byte[] = "\xC2\xA2";
    const char three_e0[] = "\xE0\xA0\x80";
    const char three_general[] = "\xE1\x80\x80";
    const char three_ed[] = "\xED\x9F\xBF";
    const char four_f0[] = "\xF0\x90\x80\x80";
    const char four_general[] = "\xF1\x80\x80\x80";
    const char four_f4[] = "\xF4\x8F\xBF\xBF";
    const char *valid[] = {
        two_byte, three_e0, three_general, three_ed,
        four_f0, four_general, four_f4
    };
    const char *labels[] = {
        "a valid 2-byte UTF-8 sequence passes through unchanged",
        "a valid E0 3-byte UTF-8 sequence passes through unchanged",
        "a valid general 3-byte UTF-8 sequence passes through unchanged",
        "a valid ED 3-byte UTF-8 sequence passes through unchanged",
        "a valid F0 4-byte UTF-8 sequence passes through unchanged",
        "a valid general 4-byte UTF-8 sequence passes through unchanged",
        "a valid F4 4-byte UTF-8 sequence passes through unchanged"
    };

    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
    {
        char encoded[256];
        size_t length = strlen(valid[i]);
        check(encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                      valid[i], encoded, sizeof(encoded)) == 0 &&
              memcmp(encoded, valid[i], length + 1) == 0, labels[i]);
        check_component_round_trip(valid[i],
                                   "a well-formed UTF-8 component round-trips");
    }

    const char overlong_two[] = "\xC0\xAF";
    const char lone_continuation[] = "\x80";
    const char truncated_three[] = "\xE2\x82";
    const char surrogate_three[] = "\xED\xA0\x80";
    const char out_of_range_four[] = "\xF4\x90\x80\x80";
    check_component_encoding(overlong_two, "%C0%AF",
                             "an overlong 2-byte sequence is escaped byte-by-byte");
    check_component_encoding(lone_continuation, "%80",
                             "a lone continuation byte is escaped");
    check_component_encoding(truncated_three, "%E2%82",
                             "a truncated UTF-8 sequence is escaped byte-by-byte");
    check_component_encoding(surrogate_three, "%ED%A0%80",
                             "a surrogate-range sequence is escaped byte-by-byte");
    check_component_encoding(out_of_range_four, "%F4%90%80%80",
                             "an out-of-range sequence is escaped byte-by-byte");
    check_component_round_trip(overlong_two,
                               "an overlong sequence round-trips through escapes");
    check_component_round_trip(lone_continuation,
                               "a lone continuation byte round-trips through escapes");
    check_component_round_trip(truncated_three,
                               "a truncated sequence round-trips through escapes");
    check_component_round_trip(surrogate_three,
                               "a surrogate-range sequence round-trips through escapes");
    check_component_round_trip(out_of_range_four,
                               "an out-of-range sequence round-trips through escapes");
}

static void test_component_raw_name_corpus(void)
{
    printf(BLUE "::" NC " encoding: raw-name corpus acceptance gate\n");

    // Keep these literals in sync by hand with fsprobe.c's raw_name_corpus.
    const char *raw_name_corpus[] = {
        "migr:probe", "migr?probe", "trailing.", "trailing "
    };

    for (size_t i = 0; i < sizeof(raw_name_corpus) / sizeof(raw_name_corpus[0]); i++)
    {
        char encoded[256];
        check(encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                      raw_name_corpus[i], encoded,
                                      sizeof(encoded)) == 0,
              "raw-name corpus entry encodes successfully");
        check(strchr(encoded, ':') == NULL && strchr(encoded, '?') == NULL &&
              encoded[0] != '\0' && encoded[strlen(encoded) - 1] != '.' &&
              encoded[strlen(encoded) - 1] != ' ',
              "raw-name corpus entry has no hostile raw suffix or punctuation");
        check_component_round_trip(raw_name_corpus[i],
                                   "raw-name corpus entry round-trips");
    }
}

static void test_component_injectivity(void)
{
    printf(BLUE "::" NC " encoding: component injectivity\n");

    const char literal_dot[] = "a%2E";
    const char actual_dot[] = "a.";
    const char literal_slash[] = "a%2F";
    const char actual_slash[] = "a/";
    char literal_dot_encoded[256], actual_dot_encoded[256];
    char literal_slash_encoded[256], actual_slash_encoded[256];

    check(encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                  literal_dot, literal_dot_encoded,
                                  sizeof(literal_dot_encoded)) == 0 &&
          encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                  actual_dot, actual_dot_encoded,
                                  sizeof(actual_dot_encoded)) == 0 &&
          strcmp(literal_dot_encoded, actual_dot_encoded) != 0,
          "literal %2E and a trailing dot have distinct encodings");
    check(encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                  literal_slash, literal_slash_encoded,
                                  sizeof(literal_slash_encoded)) == 0 &&
          encoding_percent_encode(ENCODING_MODE_COMPONENT,
                                  actual_slash, actual_slash_encoded,
                                  sizeof(actual_slash_encoded)) == 0 &&
          strcmp(literal_slash_encoded, actual_slash_encoded) != 0,
          "literal %2F and a slash have distinct encodings");
    check_component_round_trip(literal_dot,
                               "literal %2E decodes back to its own input");
    check_component_round_trip(actual_dot,
                               "a trailing dot decodes back to its own input");
    check_component_round_trip(literal_slash,
                               "literal %2F decodes back to its own input");
    check_component_round_trip(actual_slash,
                               "a slash decodes back to its own input");
}

static void test_component_decode_rejects_raw_unsafe_bytes(void)
{
    printf(BLUE "::" NC " encoding: component decoder is fail-closed\n");

    char out[32];
    const char raw_continuation[] = { (char)0x80, '\0' };
    check(encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                  "/", out, sizeof(out)) != 0,
          "a raw slash is refused by the component decoder");
    check(encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                  " ", out, sizeof(out)) != 0,
          "a raw space is refused by the component decoder");
    check(encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                  raw_continuation, out, sizeof(out)) != 0,
          "a raw lone continuation byte is refused by the component decoder");
    check(encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                  "a.", out, sizeof(out)) != 0,
          "a raw trailing dot is refused by the component decoder, since "
          "the encoder always escapes it (%%2E)");
    check(encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                  "a..", out, sizeof(out)) != 0,
          "a raw trailing dot after other dots is still refused");
    check(encoding_percent_decode(ENCODING_MODE_COMPONENT,
                                  "a.b", out, sizeof(out)) == 0 &&
          strcmp(out, "a.b") == 0,
          "a non-trailing dot decodes normally");
}

int main(void)
{
    printf(BLUE "::" NC " encoding (unit)\n");

    test_problem_bytes_round_trip();
    test_decode_rejects_malformed_values();
    test_decode_overflow_is_refused();
    test_encode_overflow_is_refused();
    test_component_n1_rules();
    test_component_raw_name_corpus();
    test_component_injectivity();
    test_component_decode_rejects_raw_unsafe_bytes();

    if (failures > 0)
    {
        printf(RED "%d encoding test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
