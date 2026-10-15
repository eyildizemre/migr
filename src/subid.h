#ifndef SUBID_H
#define SUBID_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * A user's subordinate IDs, as /etc/subuid or /etc/subgid gives them, in file
 * order. A rootless container's users are these IDs on disk: its user N is
 * the Nth of them, counted across the ranges (D93).
 */
#define SUBID_RANGES_MAX 8

typedef struct {
    uint32_t start;
    uint32_t count;
} SubidRange;

typedef struct {
    size_t count;
    SubidRange ranges[SUBID_RANGES_MAX];
} SubidRanges;

/* Longest "start:count,..." text subid_ranges_format() writes, with its NUL. */
#define SUBID_TEXT_MAX (SUBID_RANGES_MAX * 22)

/*
 * Reads the ranges path gives name, or uid written as a number. A missing
 * file or a user without ranges leaves out empty; -1 only when the file
 * cannot be read or holds more than SUBID_RANGES_MAX ranges for the user.
 */
int subid_ranges_read(const char *path, const char *name, uid_t uid,
                      SubidRanges *out);

/* "start:count[,start:count...]", as the manifest records the ranges. */
int subid_ranges_format(const SubidRanges *ranges, char *out, size_t size);
int subid_ranges_parse(const char *text, SubidRanges *out);

uint64_t subid_ranges_total(const SubidRanges *ranges);

/*
 * Gives the ID at id's position in from the same position in to. Returns 1
 * with *out set, 0 when id is not in from, and -1 when to has no ID at that
 * position.
 */
int subid_map(const SubidRanges *from, const SubidRanges *to, uint32_t id,
              uint32_t *out);

#endif
