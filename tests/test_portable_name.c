// Focused tests for the deterministic physical-leaf mapping in D39 R-1.

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "portable_name.h"

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

static void fill_bytes(char *buffer, size_t count, unsigned char byte)
{
    memset(buffer, byte, count);
    buffer[count] = '\0';
}

static int physical_name_equal(const PortablePhysicalName *left,
                               const PortablePhysicalName *right)
{
    return strcmp(left->physical_leaf, right->physical_leaf) == 0 &&
           strcmp(left->collision_suffix, right->collision_suffix) == 0 &&
           left->shortened == right->shortened;
}

static void check_fit(const char *logical, uint64_t collision_number,
                      const char *expected, const char *label)
{
    PortablePhysicalName mapped;
    check(portable_physical_name_map(logical, collision_number, &mapped) == 0 &&
          strcmp(mapped.physical_leaf, expected) == 0 &&
          mapped.shortened == 0, label);
}

static void test_fitting_representation(void)
{
    printf(BLUE "::" NC " portable physical name: fitting representation\n");

    check_fit("report.txt", 0, "report.txt",
              "safe ASCII stays byte-for-byte unchanged");
    check_fit("a b?.txt", 0, "a%20b%3F.txt",
              "spaces and punctuation use the existing component encoding");
    check_fit("note.", 0, "note%2E",
              "a trailing dot keeps the existing component encoding");

    const char utf8_name[] = "\xE2\x82\xAC.txt";
    check_fit(utf8_name, 0, utf8_name,
              "valid UTF-8 stays literal when the encoded name fits");

    const char invalid_utf8[] = {'x', (char)0xFF, 'y', '\0'};
    check_fit(invalid_utf8, 0, "x%FFy",
              "invalid UTF-8 bytes retain lossless percent encoding");
    check_fit("report.txt", 1, "report.txt%7E1",
              "a fitting collision suffix uses canonical D21 spelling");
}

static void test_exact_shortening_vector(void)
{
    printf(BLUE "::" NC " portable physical name: exact shortening vector\n");

    char logical[NAME_MAX + 1U];
    fill_bytes(logical, NAME_MAX, '!');

    char expected[NAME_MAX + 1U];
    size_t offset = 0;
    for (size_t i = 0; i < 78; i++)
    {
        memcpy(expected + offset, "%21", 3);
        offset += 3;
    }
    memcpy(expected + offset, "%7EH1B70C7FC136F8DD0", 20);
    offset += 20;
    expected[offset] = '\0';

    PortablePhysicalName mapped;
    check(portable_physical_name_map(logical, 0, &mapped) == 0 &&
          strcmp(mapped.physical_leaf, expected) == 0 &&
          strlen(mapped.physical_leaf) == 254 && mapped.shortened == 1,
          "255 exclamation bytes match the fixed repository-FNV vector");

    PortablePhysicalName forced;
    check(portable_physical_name_map_with_fingerprint_for_test(
              logical, 0, UINT64_C(0x0123456789ABCDEF), &forced) == 0 &&
          strstr(forced.physical_leaf, "%7EH0123456789ABCDEF") != NULL &&
          forced.shortened == 1,
          "the shortening marker is 16-digit uppercase hexadecimal");
}

static void test_percent_escape_boundary(void)
{
    printf(BLUE "::" NC " portable physical name: percent-escape boundary\n");

    char logical[87];
    fill_bytes(logical, 86, '!');

    PortablePhysicalName mapped;
    int status = portable_physical_name_map_with_fingerprint_for_test(
        logical, 0, UINT64_C(0x0123456789ABCDEF), &mapped);
    check(status == 0 && mapped.shortened == 1,
          "an overflowing percent-encoded component is shortened");
    check(status == 0 &&
          strncmp(mapped.physical_leaf + 234,
                  "%7EH0123456789ABCDEF", 20) == 0,
          "the prefix stops before a percent escape that would be split");
    check(status == 0 && strlen(mapped.physical_leaf) == 254,
          "unused sub-token budget is left unused rather than truncating an escape");
}

static void check_utf8_boundary(const char *sequence, size_t sequence_length,
                                const char *label)
{
    char logical[128];
    size_t offset = 0;
    for (size_t i = 0; i < 78; i++)
        logical[offset++] = '!';
    memcpy(logical + offset, sequence, sequence_length);
    offset += sequence_length;
    for (size_t i = 0; i < 10; i++)
        logical[offset++] = '?';
    logical[offset] = '\0';

    PortablePhysicalName mapped;
    int status = portable_physical_name_map_with_fingerprint_for_test(
        logical, 0, UINT64_C(0x0123456789ABCDEF), &mapped);
    check(status == 0 && mapped.shortened == 1 &&
          strncmp(mapped.physical_leaf + 234,
                  "%7EH0123456789ABCDEF", 20) == 0 &&
          memcmp(mapped.physical_leaf + 234, sequence, sequence_length) != 0,
          label);
}

static void test_utf8_boundaries(void)
{
    printf(BLUE "::" NC " portable physical name: UTF-8 boundaries\n");

    check_utf8_boundary("\xC2\xA2", 2,
                        "a 2-byte UTF-8 code point is never split");
    check_utf8_boundary("\xE2\x82\xAC", 3,
                        "a 3-byte UTF-8 code point is never split");
    check_utf8_boundary("\xF0\x9F\x98\x80", 4,
                        "a 4-byte UTF-8 code point is never split");
}

static void test_suffix_rebudgeting(void)
{
    printf(BLUE "::" NC " portable physical name: collision suffix budgeting\n");

    char logical[87];
    fill_bytes(logical, 86, '!');
    const uint64_t fingerprint = UINT64_C(0x0123456789ABCDEF);

    PortablePhysicalName none;
    PortablePhysicalName one;
    PortablePhysicalName maximum;
    int none_ok = portable_physical_name_map_with_fingerprint_for_test(
        logical, 0, fingerprint, &none) == 0;
    int one_ok = portable_physical_name_map_with_fingerprint_for_test(
        logical, 1, fingerprint, &one) == 0;
    int max_ok = portable_physical_name_map_with_fingerprint_for_test(
        logical, UINT64_MAX, fingerprint, &maximum) == 0;

    check(none_ok && one_ok && strstr(none.physical_leaf,
                                      "%7EH0123456789ABCDEF") == none.physical_leaf + 234 &&
          strstr(one.physical_leaf,
                 "%7EH0123456789ABCDEF") == one.physical_leaf + 231,
          "suffix growth reduces the retained encoded prefix before mapping");
    check(one_ok && strcmp(one.collision_suffix, "%7E1") == 0 &&
          strlen(one.physical_leaf) <= NAME_MAX &&
          strcmp(one.physical_leaf + strlen(one.physical_leaf) - 4, "%7E1") == 0,
          "collision number 1 stays canonical and within NAME_MAX");
    check(max_ok &&
          strcmp(maximum.collision_suffix, "%7E18446744073709551615") == 0 &&
          strlen(maximum.physical_leaf) <= NAME_MAX &&
          strcmp(maximum.physical_leaf + strlen(maximum.physical_leaf) -
                 strlen(maximum.collision_suffix), maximum.collision_suffix) == 0,
          "UINT64_MAX is canonically suffixed and rebudgeted without overflow");
}

static void test_determinism(void)
{
    printf(BLUE "::" NC " portable physical name: deterministic mapping\n");

    char long_punctuation[96];
    fill_bytes(long_punctuation, 95, '!');
    const char *logical[] = {
        "alpha.txt", "two words.txt", long_punctuation, "\xE2\x82\xAC-name"
    };
    const uint64_t suffix[] = {0, 4, 0, 12};
    enum { COUNT = 4 };
    PortablePhysicalName forward[COUNT];
    PortablePhysicalName reverse[COUNT];

    int ok = 1;
    for (size_t i = 0; i < COUNT; i++)
        ok = ok && portable_physical_name_map(logical[i], suffix[i],
                                               &forward[i]) == 0;
    for (size_t i = COUNT; i > 0; i--)
        ok = ok && portable_physical_name_map(logical[i - 1], suffix[i - 1],
                                               &reverse[i - 1]) == 0;
    for (size_t i = 0; i < COUNT; i++)
        ok = ok && physical_name_equal(&forward[i], &reverse[i]);

    check(ok, "mapping is byte-identical when call order is reversed");
}

static void test_forced_fingerprint_collision(void)
{
    printf(BLUE "::" NC " portable physical name: forced fingerprint collision\n");

    char first[96];
    char second[96];
    size_t offset = 0;
    for (size_t i = 0; i < 79; i++)
    {
        first[offset] = '!';
        second[offset] = '!';
        offset++;
    }
    for (size_t i = 0; i < 10; i++)
    {
        first[offset] = '?';
        second[offset] = '?';
        offset++;
    }
    first[offset] = 'A';
    second[offset] = 'B';
    first[offset + 1] = '\0';
    second[offset + 1] = '\0';

    PortablePhysicalName a;
    PortablePhysicalName b;
    const uint64_t fingerprint = UINT64_C(0xA5A5A5A5A5A5A5A5);
    int a_ok = portable_physical_name_map_with_fingerprint_for_test(
        first, 0, fingerprint, &a) == 0;
    int b_ok = portable_physical_name_map_with_fingerprint_for_test(
        second, 0, fingerprint, &b) == 0;

    check(a_ok && b_ok && a.shortened == 1 && b.shortened == 1 &&
          strcmp(a.physical_leaf, b.physical_leaf) == 0,
          "the mapper adds no hidden discriminator for equal fingerprints");
}

static void check_failure(const char *logical, const char *label)
{
    PortablePhysicalName mapped;
    memset(&mapped, 0xA5, sizeof(mapped));
    check(portable_physical_name_map(logical, 0, &mapped) == -1 &&
          mapped.physical_leaf[0] == '\0' &&
          mapped.collision_suffix[0] == '\0' && mapped.shortened == 0,
          label);
}

static void test_invalid_inputs(void)
{
    printf(BLUE "::" NC " portable physical name: invalid inputs\n");

    check_failure(NULL, "a NULL logical component fails with empty output");
    check_failure("", "an empty logical component is refused");
    check_failure(".", "dot is refused as a component");
    check_failure("..", "dot-dot is refused as a component");
    check_failure("a/b", "an embedded path separator is refused");

    char too_long[NAME_MAX + 2U];
    fill_bytes(too_long, NAME_MAX + 1U, 'a');
    check_failure(too_long, "a raw component longer than NAME_MAX is refused");
    check(portable_physical_name_map("ok", 0, NULL) == -1,
          "a NULL output pointer is refused");
}

int main(void)
{
    test_fitting_representation();
    test_exact_shortening_vector();
    test_percent_escape_boundary();
    test_utf8_boundaries();
    test_suffix_rebudgeting();
    test_determinism();
    test_forced_fingerprint_collision();
    test_invalid_inputs();

    if (failures != 0)
    {
        printf(RED "%d portable physical-name test(s) failed\n" NC, failures);
        return 1;
    }

    printf(GREEN "All portable physical-name tests passed\n" NC);
    return 0;
}
