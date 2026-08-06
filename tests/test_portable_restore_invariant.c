// Unit tests for the portable restore path invariant (docs/DECISIONS.md D19).

#define _GNU_SOURCE

#include <stdio.h>

#include "sidecar.h"

extern int physical_matches_logical(SidecarBytes logical,
                                     SidecarBytes physical);

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void test_exact_ascii(void)
{
    printf(BLUE "::" NC " physical/logical invariant: exact ASCII path\n");

    const unsigned char logical_data[] = "Documents/file.txt";
    const unsigned char physical_data[] = "Documents/file.txt";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 1,
          "ASCII logical and physical paths match");
}

static void test_trailing_dot_encoding(void)
{
    const unsigned char logical_data[] = "notes.";
    const unsigned char physical_data[] = "notes%2E";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 1,
          "trailing dot uses its component encoding");
}

static void test_illegal_byte_encoding(void)
{
    const unsigned char logical_data[] = "migr:probe";
    const unsigned char physical_data[] = "migr%3Aprobe";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 1,
          "illegal component byte uses percent encoding");
}

static void test_non_ascii_passthrough(void)
{
    const unsigned char logical_data[] = "caf\xC3\xA9";
    const unsigned char physical_data[] = "caf\xC3\xA9";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 1,
          "valid non-ASCII UTF-8 bytes remain unescaped");
}

static void test_deliberate_mismatch(void)
{
    const unsigned char logical_data[] = "innocuous.txt";
    const unsigned char physical_data[] = "something-else.txt";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 0,
          "different physical name is rejected");
}

static void test_component_count(void)
{
    const unsigned char logical_data[] = "a/b";
    const unsigned char short_physical_data[] = "a";
    const unsigned char short_logical_data[] = "a";
    const unsigned char physical_data[] = "a/b";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes short_physical = {
        .data = short_physical_data,
        .length = sizeof(short_physical_data) - 1U
    };
    SidecarBytes short_logical = {
        .data = short_logical_data,
        .length = sizeof(short_logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, short_physical) == 0,
          "missing physical component is rejected");
    check(physical_matches_logical(short_logical, physical) == 0,
          "extra physical component is rejected");
}

static void test_root_entry(void)
{
    SidecarBytes logical = { .data = NULL, .length = 0 };
    SidecarBytes physical = { .data = NULL, .length = 0 };
    check(physical_matches_logical(logical, physical) == 1,
          "empty root paths match");
}

static void test_nested_path(void)
{
    const unsigned char logical_data[] = "a/b/c.txt";
    const unsigned char physical_data[] = "a/b/c.txt";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 1,
          "nested components are compared independently");
}

static void test_per_component_encoding(void)
{
    const unsigned char logical_data[] = "migr:probe/file.txt";
    const unsigned char physical_data[] = "migr%3Aprobe/file.txt";
    SidecarBytes logical = {
        .data = logical_data,
        .length = sizeof(logical_data) - 1U
    };
    SidecarBytes physical = {
        .data = physical_data,
        .length = sizeof(physical_data) - 1U
    };
    check(physical_matches_logical(logical, physical) == 1,
          "encoding is applied per component, not to the joined path");
}

int main(void)
{
    test_exact_ascii();
    test_trailing_dot_encoding();
    test_illegal_byte_encoding();
    test_non_ascii_passthrough();
    test_deliberate_mismatch();
    test_component_count();
    test_root_entry();
    test_nested_path();
    test_per_component_encoding();

    if (failures != 0)
        printf(RED "portable restore invariant failed: %d assertion(s)\n" NC,
               failures);
    else
        printf(GREEN "portable restore invariant passed\n" NC);
    return failures == 0 ? 0 : 1;
}
