// Fuzz harness for the writer-to-parser round trip: the input decodes into
// an entry and its xattrs, sidecar_write_entry_group() writes them after a
// header, and sidecar_parse_fd() reads them back. The input is not a journal,
// so the writer meets values the parser would never deliver, which is where
// the two can disagree.
//
// Input format, every number little-endian, every byte string a length
// followed by that many bytes (what the input lacks reads as zero or empty):
//   kind 1 | mode 4 | uid 4 | gid 4 | atime_sec 8 | atime_nsec 4 |
//   mtime_sec 8 | mtime_nsec 4 | size 8 | content_digest 8 | xattr_count 2 |
//   root_id, logical_path, physical_leaf, collision_suffix, symlink_target,
//   hardlink_root_id, hardlink_logical_path: length 2 each |
//   xattr_count times: name (length 2), value (length 4)
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind.
// - A written group parses as OK to the end and gives back every field:
//   ENTRY, its xattrs in order, ENTRY_COMMIT.
// - A refused group leaves nothing behind.
// - sidecar_append_claimed_group() accepts exactly what the group writer
//   accepts, except FIFO, which claims exclude; it appends the bytes
//   sidecar_write_claim() and sidecar_write_entry_group() write, leaves the
//   bytes before them alone, and on refusal leaves the length too. Those
//   bytes parse as the CLAIM and then the same group.
// - Every prefix of what the writers wrote, up to PREFIX_CLOSURE_LIMIT
//   bytes, cut at a field's end or a byte either side of it, parses as OK or
//   as a truncated tail: what a killed process leaves.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz.h"
#include "sidecar.h"

// Each cut parses its prefix again, so the cost grows with the square of
// the output; a larger output gets the round trip alone.
#define PREFIX_CLOSURE_LIMIT 1024U

const char fuzz_target_name[] = "sidecar_roundtrip";

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t at;
} Input;

typedef struct {
    SidecarEntry entry;
    SidecarXattr *xattrs;
} Group;

typedef struct {
    const Group *group;
    int claimed;
    size_t next;
} Expected;

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_sidecar_roundtrip: %s\n", what);
    abort();
}

static uint64_t take_number(Input *input, size_t width)
{
    uint64_t value = 0;
    for (size_t index = 0; index < width; index++)
    {
        uint64_t byte = input->at < input->size ? input->data[input->at++] : 0;
        value |= byte << (8U * index);
    }
    return value;
}

static int64_t take_signed(Input *input)
{
    uint64_t bits = take_number(input, 8);
    int64_t value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static SidecarBytes take_bytes(Input *input, size_t width)
{
    uint64_t length = take_number(input, width);
    size_t left = input->size - input->at;
    SidecarBytes bytes = {
        input->data + input->at,
        length < left ? (size_t)length : left
    };
    input->at += bytes.length;
    return bytes;
}

static void decode(const uint8_t *data, size_t size, Group *group)
{
    Input input = { data, size, 0 };
    SidecarEntry *entry = &group->entry;
    memset(group, 0, sizeof(*group));
    entry->kind = (SidecarObjectKind)take_number(&input, 1);
    entry->mode = (uint32_t)take_number(&input, 4);
    entry->uid = (uint32_t)take_number(&input, 4);
    entry->gid = (uint32_t)take_number(&input, 4);
    entry->atime_sec = take_signed(&input);
    entry->atime_nsec = (uint32_t)take_number(&input, 4);
    entry->mtime_sec = take_signed(&input);
    entry->mtime_nsec = (uint32_t)take_number(&input, 4);
    entry->size = take_number(&input, 8);
    entry->content_digest = take_number(&input, 8);
    entry->xattr_count = (uint32_t)take_number(&input, 2);
    entry->root_id = take_bytes(&input, 2);
    entry->logical_path = take_bytes(&input, 2);
    entry->physical_leaf = take_bytes(&input, 2);
    entry->collision_suffix = take_bytes(&input, 2);
    entry->symlink_target = take_bytes(&input, 2);
    entry->hardlink_root_id = take_bytes(&input, 2);
    entry->hardlink_logical_path = take_bytes(&input, 2);

    // The writer's callers pass exactly xattr_count xattrs, NULL for none.
    if (entry->xattr_count == 0)
        return;
    group->xattrs = calloc(entry->xattr_count, sizeof(*group->xattrs));
    if (group->xattrs == NULL)
        fail("cannot allocate the xattrs");
    for (uint32_t index = 0; index < entry->xattr_count; index++)
    {
        group->xattrs[index].name = take_bytes(&input, 2);
        group->xattrs[index].value = take_bytes(&input, 4);
    }
}

static int memfd_holding(const unsigned char *data, size_t size)
{
    int fd = memfd_create("fuzz", MFD_CLOEXEC);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size))
        fail("cannot hold bytes in a memfd");
    return fd;
}

static unsigned char *read_whole(int fd, size_t *size)
{
    struct stat st;
    if (fstat(fd, &st) != 0)
        fail("cannot size a journal");
    *size = (size_t)st.st_size;
    unsigned char *data = malloc(*size);
    if (data == NULL || pread(fd, data, *size, 0) != (ssize_t)*size)
        fail("cannot read a journal back");
    return data;
}

static size_t header_length(void)
{
    static size_t length;
    if (length == 0)
    {
        int fd = memfd_create("fuzz-header", MFD_CLOEXEC);
        struct stat st;
        if (fd < 0 || sidecar_write_header(fd) != 0 || fstat(fd, &st) != 0)
            fail("cannot measure the header");
        length = (size_t)st.st_size;
        close(fd);
    }
    return length;
}

static SidecarClaim claim_of(const SidecarEntry *entry)
{
    return (SidecarClaim){ entry->root_id, entry->logical_path,
                           entry->physical_leaf, entry->kind };
}

// A header, the entry's claim when claimed, and the group; NULL when a
// writer refuses.
static unsigned char *write_journal(const Group *group, int claimed,
                                    size_t *size)
{
    int fd = memfd_create("fuzz-journal", MFD_CLOEXEC);
    if (fd < 0 || sidecar_write_header(fd) != 0)
        fail("cannot write a header");
    SidecarClaim claim = claim_of(&group->entry);
    int written = (!claimed || sidecar_write_claim(fd, &claim) == 0) &&
                  sidecar_write_entry_group(fd, &group->entry,
                                            group->xattrs) == 0;
    unsigned char *journal = read_whole(fd, size);
    close(fd);
    if (written)
        return journal;
    if (!claimed && *size != header_length())
        fail("a refused group leaves bytes behind");
    free(journal);
    return NULL;
}

static int bytes_equal(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 || memcmp(left.data, right.data, left.length) == 0);
}

static int entry_equal(const SidecarEntry *left, const SidecarEntry *right)
{
    return bytes_equal(left->root_id, right->root_id) &&
           bytes_equal(left->logical_path, right->logical_path) &&
           bytes_equal(left->physical_leaf, right->physical_leaf) &&
           bytes_equal(left->collision_suffix, right->collision_suffix) &&
           bytes_equal(left->symlink_target, right->symlink_target) &&
           bytes_equal(left->hardlink_root_id, right->hardlink_root_id) &&
           bytes_equal(left->hardlink_logical_path,
                       right->hardlink_logical_path) &&
           left->kind == right->kind && left->mode == right->mode &&
           left->uid == right->uid && left->gid == right->gid &&
           left->atime_sec == right->atime_sec &&
           left->atime_nsec == right->atime_nsec &&
           left->mtime_sec == right->mtime_sec &&
           left->mtime_nsec == right->mtime_nsec &&
           left->size == right->size &&
           left->xattr_count == right->xattr_count &&
           left->content_digest == right->content_digest;
}

static int expect_record(const SidecarRecord *record, void *context)
{
    Expected *expected = context;
    const SidecarEntry *entry = &expected->group->entry;
    size_t first = expected->claimed ? 1U : 0U;
    size_t index = expected->next++;
    int same;
    if (index < first)
    {
        SidecarClaim claim = claim_of(entry);
        const SidecarClaim *parsed = &record->value.claim;
        same = record->type == SIDECAR_RECORD_CLAIM &&
               bytes_equal(parsed->root_id, claim.root_id) &&
               bytes_equal(parsed->logical_path, claim.logical_path) &&
               bytes_equal(parsed->physical_leaf, claim.physical_leaf) &&
               parsed->kind == claim.kind;
    }
    else if (index == first)
        same = record->type == SIDECAR_RECORD_ENTRY &&
               entry_equal(&record->value.entry, entry);
    else if (index <= first + entry->xattr_count)
    {
        const SidecarXattr *xattr =
            &expected->group->xattrs[index - first - 1U];
        same = record->type == SIDECAR_RECORD_XATTR &&
               bytes_equal(record->value.xattr.name, xattr->name) &&
               bytes_equal(record->value.xattr.value, xattr->value);
    }
    else
        same = index == first + entry->xattr_count + 1U &&
               record->type == SIDECAR_RECORD_ENTRY_COMMIT &&
               entry_equal(&record->value.entry, entry);
    if (!same)
        fail("a parsed record differs from what was written");
    return 0;
}

static void check_parse(const unsigned char *journal, size_t size,
                        const Group *group, int claimed)
{
    int fd = memfd_holding(journal, size);
    Expected expected = { group, claimed, 0 };
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, expect_record, &expected,
                                            &result);
    close(fd);
    if (status != SIDECAR_STATUS_OK || result.bytes_read != size ||
        result.last_valid_boundary != size ||
        expected.next != (claimed ? 1U : 0U) + group->entry.xattr_count + 2U)
        fail("a written journal does not parse back whole");
}

// A cut inside a field ends the parse like any other inside it; the ones
// next to a field's end decide between a complete and a truncated record.
static int next_to_field_end(const unsigned char *journal, size_t length)
{
    return journal[length] == '\0' || journal[length - 1U] == '\0' ||
           journal[length - 2U] == '\0';
}

static void check_prefixes(const unsigned char *journal, size_t size)
{
    if (size > PREFIX_CLOSURE_LIMIT)
        return;
    int fd = memfd_holding(journal, size);
    // Shrinking one memfd walks the prefixes down to the header.
    for (size_t length = size - 1U; length >= header_length(); length--)
    {
        if (!next_to_field_end(journal, length))
            continue;
        SidecarParseResult result;
        if (ftruncate(fd, (off_t)length) != 0)
            fail("cannot cut a journal");
        SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &result);
        if (status != SIDECAR_STATUS_OK &&
            status != SIDECAR_STATUS_TRUNCATED_TAIL)
            fail("a prefix of writer output does not parse as OK or as a "
                 "truncated tail");
    }
    close(fd);
}

static void check_claimed(const Group *group, int written)
{
    static const unsigned char before[] = "kept";
    size_t kept = sizeof(before) - 1U;
    size_t length = kept;
    size_t capacity = kept;
    unsigned char *buffer = malloc(capacity);
    if (buffer == NULL)
        fail("cannot allocate a buffer");
    memcpy(buffer, before, kept);
    int appended = sidecar_append_claimed_group(&group->entry, group->xattrs,
                                                &buffer, &length,
                                                &capacity) == 0;
    if (appended != (written && group->entry.kind != SIDECAR_KIND_FIFO))
        fail("the claimed group and the group writer accept different "
             "entries");
    if (memcmp(buffer, before, kept) != 0 || (!appended && length != kept))
        fail("appending a claimed group changes bytes it does not own");

    size_t size = 0;
    unsigned char *journal = write_journal(group, 1, &size);
    if (appended != (journal != NULL))
        fail("the claimed group and the claim writer accept different "
             "entries");
    if (appended)
    {
        if (length - kept != size - header_length() ||
            memcmp(buffer + kept, journal + header_length(),
                   length - kept) != 0)
            fail("a claimed group differs from the claim and group writers' "
                 "bytes");
        check_parse(journal, size, group, 1);
        check_prefixes(journal, size);
    }
    free(journal);
    free(buffer);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Group group;
    decode(data, size, &group);
    size_t journal_size = 0;
    unsigned char *journal = write_journal(&group, 0, &journal_size);
    if (journal != NULL)
    {
        check_parse(journal, journal_size, &group, 0);
        check_prefixes(journal, journal_size);
    }
    check_claimed(&group, journal != NULL);
    free(journal);
    free(group.xattrs);
    return 0;
}

const char *fuzz_outcome(const uint8_t *data, size_t size)
{
    Group group;
    decode(data, size, &group);
    size_t journal_size = 0;
    unsigned char *journal = write_journal(&group, 0, &journal_size);
    const char *outcome = journal != NULL ? "written" : "refused";
    free(journal);
    free(group.xattrs);
    return outcome;
}

const char *fuzz_seed_outcome(const FuzzSeed *seed)
{
    return seed->outcome;
}

void fuzz_check_seed(const FuzzSeed *seed)
{
    (void)seed;
}
