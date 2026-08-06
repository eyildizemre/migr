// Unit tests for the shared percent encoder/decoder (docs/DECISIONS.md D19).
// This binary covers only the existing manifest-path mode; component encoding
// is added in the next step.

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

int main(void)
{
    printf(BLUE "::" NC " encoding (unit)\n");

    test_problem_bytes_round_trip();
    test_decode_rejects_malformed_values();
    test_decode_overflow_is_refused();
    test_encode_overflow_is_refused();

    if (failures > 0)
    {
        printf(RED "%d encoding test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
