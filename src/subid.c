#define _GNU_SOURCE

#include "subid.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parses a decimal uint32_t that ends at end; strtoul alone accepts signs,
// spaces, and values past 32 bits.
static int parse_u32(const char *text, char **end, uint32_t *out)
{
    if (text[0] < '0' || text[0] > '9')
        return -1;
    errno = 0;
    unsigned long long value = strtoull(text, end, 10);
    if (errno != 0 || value > UINT32_MAX)
        return -1;
    *out = (uint32_t)value;
    return 0;
}

// A range whose IDs fit in 32 bits, with at least one ID.
static int range_valid(const SubidRange *range)
{
    return range->count != 0 &&
           (uint64_t)range->start + range->count - 1U <= UINT32_MAX;
}

int subid_ranges_read(const char *path, const char *name, uid_t uid,
                      SubidRanges *out)
{
    memset(out, 0, sizeof(*out));
    FILE *file = fopen(path, "re");
    if (file == NULL)
        return errno == ENOENT ? 0 : -1;

    char uid_text[24];
    snprintf(uid_text, sizeof(uid_text), "%lu", (unsigned long)uid);
    char *line = NULL;
    size_t capacity = 0;
    int failed = 0;
    while (!failed && getline(&line, &capacity, file) != -1)
    {
        // owner:start:count, where owner is a user name or a uid.
        char *first = strchr(line, ':');
        if (first == NULL)
            continue;
        *first = '\0';
        if (strcmp(line, uid_text) != 0 &&
            (name == NULL || strcmp(line, name) != 0))
            continue;
        SubidRange range;
        char *end;
        if (parse_u32(first + 1, &end, &range.start) != 0 || *end != ':' ||
            parse_u32(end + 1, &end, &range.count) != 0 ||
            (*end != '\n' && *end != '\0') || !range_valid(&range))
            continue; // not a line the shadow tools would use either
        if (out->count == SUBID_RANGES_MAX)
            failed = 1;
        else
            out->ranges[out->count++] = range;
    }
    if (ferror(file))
        failed = 1;
    free(line);
    if (fclose(file) != 0)
        failed = 1;
    if (failed)
        memset(out, 0, sizeof(*out));
    return failed ? -1 : 0;
}

int subid_ranges_format(const SubidRanges *ranges, char *out, size_t size)
{
    size_t used = 0;
    if (size == 0)
        return -1;
    out[0] = '\0';
    for (size_t index = 0; index < ranges->count; index++)
    {
        int length = snprintf(out + used, size - used, "%s%" PRIu32 ":%" PRIu32,
                              index == 0 ? "" : ",",
                              ranges->ranges[index].start,
                              ranges->ranges[index].count);
        if (length < 0 || (size_t)length >= size - used)
            return -1;
        used += (size_t)length;
    }
    return 0;
}

int subid_ranges_parse(const char *text, SubidRanges *out)
{
    memset(out, 0, sizeof(*out));
    const char *cursor = text;
    while (*cursor != '\0')
    {
        SubidRange range;
        char *end;
        if (out->count == SUBID_RANGES_MAX ||
            parse_u32(cursor, &end, &range.start) != 0 || *end != ':' ||
            parse_u32(end + 1, &end, &range.count) != 0 ||
            !range_valid(&range) || (*end != ',' && *end != '\0') ||
            (*end == ',' && end[1] == '\0'))
        {
            memset(out, 0, sizeof(*out));
            return -1;
        }
        out->ranges[out->count++] = range;
        cursor = *end == ',' ? end + 1 : end;
    }
    return 0;
}

uint64_t subid_ranges_total(const SubidRanges *ranges)
{
    uint64_t total = 0;
    for (size_t index = 0; index < ranges->count; index++)
        total += ranges->ranges[index].count;
    return total;
}

int subid_map(const SubidRanges *from, const SubidRanges *to, uint32_t id,
              uint32_t *out)
{
    uint64_t position = 0;
    size_t index = 0;
    for (; index < from->count; index++)
    {
        const SubidRange *range = &from->ranges[index];
        if (id >= range->start && id - range->start < range->count)
        {
            position += id - range->start;
            break;
        }
        position += range->count;
    }
    if (index == from->count)
        return 0;
    for (index = 0; index < to->count; index++)
    {
        const SubidRange *range = &to->ranges[index];
        if (position < range->count)
        {
            *out = range->start + (uint32_t)position;
            return 1;
        }
        position -= range->count;
    }
    return -1;
}
