#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "subid.h"

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

static void write_fixture(const char *path, const char *content)
{
    FILE *file = fopen(path, "w");
    if (file == NULL || fputs(content, file) == EOF || fclose(file) != 0)
    {
        perror("fixture: write subid file");
        exit(1);
    }
}

static void test_read(void)
{
    printf(BLUE "::" NC " a user's ranges are read as the shadow tools list them\n");
    char path[] = "/tmp/migr-subid-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
    {
        perror("fixture: mkstemp");
        exit(1);
    }
    close(fd);
    write_fixture(path, "other:100000:65536\n"
                        "migr:524288:65536\n"
                        "migr:not-a-number:5\n"
                        "1000:700000:1000\n"
                        "migr:4294967295:2\n");
    SubidRanges ranges;
    check(subid_ranges_read(path, "migr", 1000, &ranges) == 0 &&
              ranges.count == 2 && ranges.ranges[0].start == 524288 &&
              ranges.ranges[0].count == 65536 &&
              ranges.ranges[1].start == 700000 &&
              ranges.ranges[1].count == 1000,
          "lines by name and by uid, in file order; malformed and "
          "overflowing lines are passed over");
    check(subid_ranges_read(path, "nobody-here", 4242, &ranges) == 0 &&
              ranges.count == 0,
          "a user without ranges has none");
    unlink(path);
    check(subid_ranges_read(path, "migr", 1000, &ranges) == 0 &&
              ranges.count == 0,
          "a missing file gives no ranges");
}

static void test_text(void)
{
    printf(BLUE "::" NC " the manifest's text of the ranges reads back the same\n");
    SubidRanges ranges = { .count = 2,
                           .ranges = { { 524288, 65536 }, { 700000, 1000 } } };
    char text[SUBID_TEXT_MAX];
    SubidRanges parsed;
    check(subid_ranges_format(&ranges, text, sizeof(text)) == 0 &&
              strcmp(text, "524288:65536,700000:1000") == 0 &&
              subid_ranges_parse(text, &parsed) == 0 &&
              memcmp(&parsed, &ranges, sizeof(ranges)) == 0,
          "start:count pairs, comma-separated");
    static const char *const malformed[] = {
        "1", "1:", ":1", "1:0", "1:2,", "1:2,,3:4", "-1:2", "1:2 ",
        "4294967295:2", "1:2,3:4,5:6,7:8,9:10,11:12,13:14,15:16,17:18"
    };
    int refused = 1;
    for (size_t index = 0; index < sizeof(malformed) / sizeof(malformed[0]);
         index++)
        refused &= subid_ranges_parse(malformed[index], &parsed) == -1 &&
                   parsed.count == 0;
    check(refused, "a malformed, empty-count, overflowing, or overlong "
                   "list is refused");
    check(subid_ranges_parse("", &parsed) == 0 && parsed.count == 0,
          "an empty text is no ranges");
}

static void test_map(void)
{
    printf(BLUE "::" NC " a container user keeps its place among the IDs\n");
    SubidRanges fedora = { .count = 1, .ranges = { { 524288, 65536 } } };
    SubidRanges ubuntu = { .count = 1, .ranges = { { 100000, 65536 } } };
    SubidRanges split = { .count = 2,
                          .ranges = { { 200000, 10 }, { 300000, 65526 } } };
    SubidRanges small = { .count = 1, .ranges = { { 100000, 100 } } };
    uint32_t id = 0;
    check(subid_map(&fedora, &ubuntu, 524288 + 42, &id) == 1 &&
              id == 100000 + 42,
          "the same offset in the other system's range");
    check(subid_map(&fedora, &split, 524288 + 12, &id) == 1 &&
              id == 300000 + 2,
          "positions continue across ranges");
    check(subid_map(&split, &fedora, 300000 + 2, &id) == 1 &&
              id == 524288 + 12,
          "and back");
    check(subid_map(&fedora, &ubuntu, 1000, &id) == 0,
          "an ID outside the ranges is not the containers'");
    check(subid_map(&fedora, &small, 524288 + 100, &id) == -1,
          "a position the new ranges do not reach has no ID");
}

int main(void)
{
    test_read();
    test_text();
    test_map();

    if (failures == 0)
        printf(GREEN "subid tests passed" NC "\n");
    else
        printf(RED "subid tests: %d failure(s)" NC "\n", failures);
    return failures == 0 ? 0 : 1;
}
