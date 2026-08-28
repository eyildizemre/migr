// Unit tests for the sidecar v3 codec (docs/DECISIONS.md D17/D21/D22/D25): magic/version
// header, ENTRY/XATTR/ENTRY_COMMIT/DELETE/CLAIM record framing, canonical numeric
// parsing, and every SIDECAR_MAX_* ceiling declared there. This is the codec
// alone -- no live-state map, no resume, no adopt; that stateful layer is a
// separate step built on top of this one.
//
// Round-trip coverage writes real records with sidecar_write_*() and reads
// them back through sidecar_parse_fd()'s callback, so a writer bug can never
// mask a reader bug (same split as tests/test_manifest.c). Corruption
// fixtures are raw byte buffers assembled by hand instead, for the same
// reason: a malformed-input test must not depend on the writer refusing to
// produce what it is checking the reader rejects.
//
// Ceiling tests are paired at the boundary (exactly at the limit is
// accepted, one past it is refused) rather than tested with an arbitrary
// value on either side. The total-byte ceiling fixture uses a sparse file
// (ftruncate, no data written) to exercise the real 4 GiB limit without
// actually allocating or writing that much. Tail recovery distinguishes a
// clean EOF mid-record (truncated tail, resumable) from malformed content
// anywhere in the file (interior corruption, unusable) per D17. Symlink and
// hardlink records are exercised through the writer and reader, including
// their kind-specific field validation.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sidecar.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

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

static int reset_file(int fd)
{
    return ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0 ? 0 : -1;
}

static int write_all_test(int fd, const unsigned char *data, size_t length)
{
    size_t written = 0;
    while (written < length)
    {
        ssize_t result = write(fd, data + written, length - written);
        if (result <= 0)
            return -1;
        written += (size_t)result;
    }
    return 0;
}

static int file_size(int fd, uint64_t *out)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0)
        return -1;
    *out = (uint64_t)st.st_size;
    return 0;
}

typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
} RawBuffer;

static void raw_free(RawBuffer *buffer)
{
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static int raw_reserve(RawBuffer *buffer, size_t extra)
{
    if (extra > SIZE_MAX - buffer->length)
        return -1;
    size_t needed = buffer->length + extra;
    if (needed <= buffer->capacity)
        return 0;
    size_t capacity = buffer->capacity == 0 ? 128U : buffer->capacity;
    while (capacity < needed)
        capacity *= 2U;
    unsigned char *data = realloc(buffer->data, capacity);
    if (data == NULL)
        return -1;
    buffer->data = data;
    buffer->capacity = capacity;
    return 0;
}

static int raw_append(RawBuffer *buffer, const void *data, size_t length)
{
    if (raw_reserve(buffer, length) != 0)
        return -1;
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

static int raw_field(RawBuffer *buffer, const void *data, size_t length)
{
    unsigned char zero = 0;
    return raw_append(buffer, data, length) == 0 &&
           raw_append(buffer, &zero, 1) == 0 ? 0 : -1;
}

static int raw_text_field(RawBuffer *buffer, const char *text)
{
    return raw_field(buffer, text, strlen(text));
}

static int raw_tag(RawBuffer *buffer, const char *tag)
{
    return raw_text_field(buffer, tag);
}

static int append_header(RawBuffer *buffer, const char *version)
{
    return raw_text_field(buffer, SIDECAR_MAGIC) == 0 &&
           raw_text_field(buffer, version) == 0 ? 0 : -1;
}

static int append_regular_entry_with_logical(RawBuffer *buffer,
                                             const void *logical,
                                             size_t logical_length,
                                             const char *mode,
                                             const char *xattr_count)
{
    return raw_tag(buffer, "ENTRY") == 0 &&
           raw_text_field(buffer, "ROOT") == 0 &&
           raw_field(buffer, logical, logical_length) == 0 &&
           raw_text_field(buffer, "payload/file") == 0 &&
           raw_text_field(buffer, "") == 0 &&
           raw_text_field(buffer, "regular") == 0 &&
           raw_text_field(buffer, mode) == 0 &&
           raw_text_field(buffer, "1000") == 0 &&
           raw_text_field(buffer, "1000") == 0 &&
           raw_text_field(buffer, "-7") == 0 &&
           raw_text_field(buffer, "0") == 0 &&
           raw_text_field(buffer, "8") == 0 &&
           raw_text_field(buffer, "123") == 0 &&
           raw_text_field(buffer, "0") == 0 &&
           raw_text_field(buffer, xattr_count) == 0 ? 0 : -1;
}

static int append_regular_entry(RawBuffer *buffer, const char *mode,
                                const char *xattr_count)
{
    static const char logical[] = "dir/file";
    return append_regular_entry_with_logical(buffer, logical,
                                             sizeof(logical) - 1U, mode,
                                             xattr_count);
}

static int append_commit(RawBuffer *buffer)
{
    return raw_tag(buffer, "ENTRY_COMMIT");
}

static int append_claim(RawBuffer *buffer, const char *root,
                        const char *logical, const char *physical,
                        const char *kind)
{
    return raw_tag(buffer, "CLAIM") == 0 &&
           raw_text_field(buffer, root) == 0 &&
           raw_text_field(buffer, logical) == 0 &&
           raw_text_field(buffer, physical) == 0 &&
           raw_text_field(buffer, kind) == 0 ? 0 : -1;
}

static int set_raw_file(int fd, const RawBuffer *buffer)
{
    return reset_file(fd) == 0 &&
           write_all_test(fd, buffer->data, buffer->length) == 0 ? 0 : -1;
}

static SidecarEntry sample_entry(void)
{
    static const unsigned char root[] = "ROOT";
    static const unsigned char logical[] = "dir/file";
    static const unsigned char physical[] = "payload/file";
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = (SidecarBytes){ root, sizeof(root) - 1U };
    entry.logical_path = (SidecarBytes){ logical, sizeof(logical) - 1U };
    entry.physical_path = (SidecarBytes){ physical, sizeof(physical) - 1U };
    entry.kind = SIDECAR_KIND_REGULAR;
    entry.mode = 0644;
    entry.uid = 1000;
    entry.gid = 1000;
    entry.atime_sec = -7;
    entry.atime_nsec = 8;
    entry.mtime_sec = 123;
    entry.mtime_nsec = 456789;
    entry.size = 321;
    entry.xattr_count = 1;
    return entry;
}

typedef struct {
    int entries;
    int xattrs;
    int commits;
    int deletes;
    int claims;
    int valid;
} RoundTripState;

static int roundtrip_callback(const SidecarRecord *record, void *context)
{
    RoundTripState *state = context;
    if (record->type == SIDECAR_RECORD_ENTRY)
    {
        const SidecarEntry *entry = &record->value.entry;
        state->entries++;
        if (entry->kind != SIDECAR_KIND_REGULAR || entry->mode != 0644 ||
            entry->uid != 1000 || entry->gid != 1000 || entry->size != 321 ||
            entry->atime_sec != -7 || entry->mtime_nsec != 456789 ||
            entry->root_id.length != 4 ||
            memcmp(entry->root_id.data, "ROOT", 4) != 0)
            state->valid = 0;
    }
    else if (record->type == SIDECAR_RECORD_XATTR)
    {
        static const unsigned char expected[] = { 0x00, 0x01, 0xff, 0x00 };
        const SidecarXattr *xattr = &record->value.xattr;
        state->xattrs++;
        if (xattr->name.length != 9 ||
            memcmp(xattr->name.data, "user.test", 9) != 0 ||
            xattr->value.length != sizeof(expected) ||
            memcmp(xattr->value.data, expected, sizeof(expected)) != 0)
            state->valid = 0;
    }
    else if (record->type == SIDECAR_RECORD_ENTRY_COMMIT)
        state->commits++;
    else if (record->type == SIDECAR_RECORD_DELETE)
    {
        state->deletes++;
        if (record->value.deletion.root_id.length != 4 ||
            memcmp(record->value.deletion.root_id.data, "ROOT", 4) != 0 ||
            record->value.deletion.logical_path.length != 8 ||
            memcmp(record->value.deletion.logical_path.data, "dir/file", 8) != 0)
            state->valid = 0;
    }
    else if (record->type == SIDECAR_RECORD_CLAIM)
    {
        const SidecarClaim *claim = &record->value.claim;
        state->claims++;
        if (claim->root_id.length != 4 ||
            memcmp(claim->root_id.data, "ROOT", 4) != 0 ||
            claim->logical_path.length != 8 ||
            memcmp(claim->logical_path.data, "dir/file", 8) != 0 ||
            claim->physical_path.length != 12 ||
            memcmp(claim->physical_path.data, "payload/file", 12) != 0 ||
            claim->kind != SIDECAR_KIND_REGULAR)
            state->valid = 0;
    }
    return 0;
}

static void test_header_and_roundtrip(int fd)
{
    printf(BLUE "::" NC " sidecar header and record round trip\n");
    check(reset_file(fd) == 0, "temporary sidecar is reset");
    check(sidecar_write_header(fd) == 0, "canonical header writes");

    unsigned char actual[32] = {0};
    ssize_t count = pread(fd, actual, sizeof(actual), 0);
    const unsigned char expected[] = SIDECAR_MAGIC "\0" "3\0";
    check(count == (ssize_t)sizeof(expected) - 1 &&
          memcmp(actual, expected, sizeof(expected) - 1U) == 0,
          "header bytes are byte-exact");

    SidecarEntry entry = sample_entry();
    static const unsigned char xattr_value[] = { 0x00, 0x01, 0xff, 0x00 };
    SidecarXattr xattr = {
        .name = { (const unsigned char *)"user.test", 9 },
        .value = { xattr_value, sizeof(xattr_value) }
    };
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"dir/file", 8 }
    };
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"dir/file", 8 },
        .physical_path = { (const unsigned char *)"payload/file", 12 },
        .kind = SIDECAR_KIND_REGULAR
    };
    check(sidecar_write_claim(fd, &claim) == 0, "CLAIM writes");
    check(sidecar_write_entry(fd, &entry) == 0, "ENTRY writes");
    check(sidecar_write_xattr(fd, &xattr) == 0, "binary XATTR writes");
    check(sidecar_write_entry_commit(fd) == 0, "ENTRY_COMMIT writes");
    check(sidecar_write_delete(fd, &deletion) == 0, "DELETE writes");

    RoundTripState state = { .valid = 1 };
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, roundtrip_callback, &state, &result);
    check(status == SIDECAR_STATUS_OK, "complete log parses successfully");
    check(state.valid && state.entries == 1 && state.xattrs == 1 &&
          state.commits == 1 && state.deletes == 1 && state.claims == 1,
          "all records round-trip through the callback");
    check(result.last_valid_boundary == result.bytes_read &&
          result.records_read == 5,
          "clean EOF boundary is the complete file");
    check(result.allocation_peak > 0 && result.allocation_peak <= SIDECAR_MAX_ALLOC_BUDGET,
          "parser allocation remains within the published budget");
}

static void test_writer_validation(int fd)
{
    printf(BLUE "::" NC " sidecar writer validation and ceilings\n");
    SidecarEntry entry = sample_entry();
    uint64_t before = 0;

    char *root = malloc(SIDECAR_MAX_ROOT_ID + 1U);
    char *path = malloc(SIDECAR_MAX_PATH + 1U);
    char *name = malloc(SIDECAR_MAX_XATTR_NAME + 1U);
    unsigned char *value = malloc(SIDECAR_MAX_XATTR_VALUE + 1U);
    check(root != NULL && path != NULL && name != NULL && value != NULL,
          "ceiling fixtures allocate");
    if (root == NULL || path == NULL || name == NULL || value == NULL)
        goto done;
    memset(root, 'r', SIDECAR_MAX_ROOT_ID + 1U);
    memset(path, 'p', SIDECAR_MAX_PATH + 1U);
    memset(name, 'n', SIDECAR_MAX_XATTR_NAME + 1U);
    memset(value, 0xa5, SIDECAR_MAX_XATTR_VALUE + 1U);

    entry.root_id = (SidecarBytes){ (unsigned char *)root, SIDECAR_MAX_ROOT_ID };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "root id at its ceiling is accepted");
    entry.root_id.length++;
    check(sidecar_write_entry(fd, &entry) != 0, "root id over ceiling is refused");
    check(file_size(fd, &before) == 0 && before > 0,
          "invalid entry does not truncate the existing file");
    entry.root_id.length = SIDECAR_MAX_ROOT_ID;

    entry.logical_path = (SidecarBytes){ (unsigned char *)path, SIDECAR_MAX_PATH };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "path at its ceiling is accepted");
    entry.logical_path.length++;
    check(sidecar_write_entry(fd, &entry) != 0, "path over ceiling is refused");
    entry.logical_path.length = SIDECAR_MAX_PATH;

    SidecarXattr xattr = {
        .name = { (unsigned char *)name, SIDECAR_MAX_XATTR_NAME },
        .value = { value, SIDECAR_MAX_XATTR_VALUE }
    };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_xattr(fd, &xattr) == 0,
          "xattr name and value at their ceilings are accepted");
    xattr.name.length++;
    check(sidecar_write_xattr(fd, &xattr) != 0, "xattr name over ceiling is refused");
    xattr.name.length = SIDECAR_MAX_XATTR_NAME;
    xattr.value.length++;
    check(sidecar_write_xattr(fd, &xattr) != 0, "xattr value over ceiling is refused");

    entry.xattr_count = SIDECAR_MAX_XATTRS_PER_ENTRY;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "xattr count at its ceiling is accepted");
    entry.xattr_count++;
    check(sidecar_write_entry(fd, &entry) != 0, "xattr count over ceiling is refused");

    entry.xattr_count = 0;
    entry.mode = SIDECAR_MAX_MODE;
    entry.atime_nsec = SIDECAR_MAX_NSEC;
    entry.mtime_nsec = SIDECAR_MAX_NSEC;
    entry.size = UINT64_MAX;
    entry.atime_sec = INT64_MIN;
    entry.mtime_sec = INT64_MAX;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0,
          "numeric lower and upper bounds are accepted");
    entry.mode = SIDECAR_MAX_MODE + 1U;
    check(sidecar_write_entry(fd, &entry) != 0, "mode over ceiling is refused");
    entry.mode = SIDECAR_MAX_MODE;
    entry.atime_nsec = SIDECAR_MAX_NSEC + 1U;
    check(sidecar_write_entry(fd, &entry) != 0, "nanoseconds over ceiling are refused");

    entry.atime_nsec = 0;
    entry.root_id = (SidecarBytes){ (const unsigned char *)"bad\0root", 8 };
    check(sidecar_write_entry(fd, &entry) != 0, "NUL-containing fields are refused");

done:
    free(root);
    free(path);
    free(name);
    free(value);
}

static void test_claim_writer_validation(int fd)
{
    printf(BLUE "::" NC " CLAIM writer validation and ceilings\n");
    char *root = malloc(SIDECAR_MAX_ROOT_ID + 1U);
    char *path = malloc(SIDECAR_MAX_PATH + 1U);
    check(root != NULL && path != NULL, "claim ceiling fixtures allocate");
    if (root == NULL || path == NULL)
    {
        free(root);
        free(path);
        return;
    }
    memset(root, 'r', SIDECAR_MAX_ROOT_ID + 1U);
    memset(path, 'p', SIDECAR_MAX_PATH + 1U);

    SidecarClaim claim = {
        .root_id = { (const unsigned char *)root, SIDECAR_MAX_ROOT_ID },
        .logical_path = { NULL, 0 },
        .physical_path = { NULL, 0 },
        .kind = SIDECAR_KIND_DIRECTORY
    };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_claim(fd, &claim) == 0,
          "claim root id at its ceiling is accepted");
    claim.root_id.length++;
    errno = 0;
    check(sidecar_write_claim(fd, &claim) != 0 && errno == EINVAL,
          "claim root id over ceiling is refused");

    claim.root_id.length = SIDECAR_MAX_ROOT_ID;
    claim.logical_path = (SidecarBytes){ (const unsigned char *)path,
                                         SIDECAR_MAX_PATH };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_claim(fd, &claim) == 0,
          "claim logical path at its ceiling is accepted");
    claim.logical_path.length++;
    errno = 0;
    check(sidecar_write_claim(fd, &claim) != 0 && errno == EINVAL,
          "claim logical path over ceiling is refused");

    claim.logical_path.length = SIDECAR_MAX_PATH;
    claim.physical_path = (SidecarBytes){ (const unsigned char *)path,
                                          SIDECAR_MAX_PATH };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_claim(fd, &claim) == 0,
          "claim physical path at its ceiling is accepted");
    claim.physical_path.length++;
    errno = 0;
    check(sidecar_write_claim(fd, &claim) != 0 && errno == EINVAL,
          "claim physical path over ceiling is refused");

    claim.root_id = (SidecarBytes){ (const unsigned char *)"ROOT", 4 };
    claim.logical_path = (SidecarBytes){ (const unsigned char *)"logical", 7 };
    claim.physical_path = (SidecarBytes){ (const unsigned char *)"physical", 8 };
    claim.kind = SIDECAR_KIND_FIFO;
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_claim(fd, &claim) != 0 && errno == EINVAL,
          "FIFO claim kind is refused");

    static const unsigned char nul_root[] = { 'R', 'O', 'O', '\0', 'T' };
    claim.kind = SIDECAR_KIND_REGULAR;
    claim.root_id = (SidecarBytes){ nul_root, sizeof(nul_root) };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_claim(fd, &claim) != 0 && errno == EINVAL,
          "NUL-containing claim fields are refused");

    free(root);
    free(path);
}

typedef struct {
    const unsigned char *expected;
    size_t expected_length;
    int entries;
    int valid;
} CollisionSuffixRoundTripState;

static int collision_suffix_callback(const SidecarRecord *record,
                                     void *context)
{
    CollisionSuffixRoundTripState *state = context;
    if (record->type != SIDECAR_RECORD_ENTRY)
        return 0;

    const SidecarBytes suffix = record->value.entry.collision_suffix;
    state->entries++;
    if (suffix.length != state->expected_length ||
        (suffix.length != 0 &&
         memcmp(suffix.data, state->expected, suffix.length) != 0))
        state->valid = 0;
    return 0;
}

static void test_collision_suffix(int fd)
{
    printf(BLUE "::" NC " collision suffix codec contract\n");
    static const unsigned char suffix[] = "%7E1";
    SidecarEntry entry = sample_entry();
    entry.xattr_count = 0;
    entry.collision_suffix = (SidecarBytes){ suffix, sizeof(suffix) - 1U };

    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0 &&
          sidecar_write_entry_commit(fd) == 0,
          "non-empty collision suffix writes");
    CollisionSuffixRoundTripState state = {
        .expected = suffix,
        .expected_length = sizeof(suffix) - 1U,
        .valid = 1
    };
    SidecarParseResult result;
    check(sidecar_parse_fd(fd, collision_suffix_callback, &state, &result) ==
              SIDECAR_STATUS_OK && state.valid && state.entries == 1,
          "non-empty collision suffix round-trips byte-for-byte");

    entry = sample_entry();
    entry.xattr_count = 0;
    state = (CollisionSuffixRoundTripState){ .valid = 1 };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0 &&
          sidecar_write_entry_commit(fd) == 0 &&
          sidecar_parse_fd(fd, collision_suffix_callback, &state, &result) ==
              SIDECAR_STATUS_OK && state.valid && state.entries == 1,
          "empty collision suffix round-trips as the structural empty field");

    unsigned char *oversized = malloc(SIDECAR_MAX_COLLISION_SUFFIX + 1U);
    check(oversized != NULL, "collision suffix ceiling fixture allocates");
    if (oversized != NULL)
    {
        memset(oversized, 's', SIDECAR_MAX_COLLISION_SUFFIX + 1U);
        entry = sample_entry();
        entry.xattr_count = 0;
        entry.collision_suffix = (SidecarBytes){
            oversized, SIDECAR_MAX_COLLISION_SUFFIX
        };
        check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
              sidecar_write_entry(fd, &entry) == 0,
              "collision suffix at its ceiling is accepted");
        entry.collision_suffix.length++;
        errno = 0;
        check(sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
              "collision suffix over its ceiling is refused");
        free(oversized);
    }

    static const unsigned char nul_suffix[] = { 's', '\0', '1' };
    entry = sample_entry();
    entry.xattr_count = 0;
    entry.collision_suffix = (SidecarBytes){ nul_suffix,
                                             sizeof(nul_suffix) };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "NUL-containing collision suffix is refused");
}

typedef struct {
    const unsigned char *target;
    size_t target_length;
    int entries;
    int valid;
} SymlinkRoundTripState;

static int symlink_roundtrip_callback(const SidecarRecord *record,
                                      void *context)
{
    SymlinkRoundTripState *state = context;
    if (record->type != SIDECAR_RECORD_ENTRY)
        return 0;

    const SidecarEntry *entry = &record->value.entry;
    state->entries++;
    if (entry->kind != SIDECAR_KIND_SYMLINK || entry->size != 0 ||
        entry->symlink_target.length != state->target_length ||
        (state->target_length != 0 &&
         memcmp(entry->symlink_target.data, state->target,
                state->target_length) != 0))
        state->valid = 0;
    return 0;
}

typedef struct {
    int entries;
    int valid;
} HardlinkRoundTripState;

static int hardlink_roundtrip_callback(const SidecarRecord *record,
                                       void *context)
{
    HardlinkRoundTripState *state = context;
    if (record->type != SIDECAR_RECORD_ENTRY)
        return 0;

    const SidecarEntry *entry = &record->value.entry;
    state->entries++;
    if (entry->kind != SIDECAR_KIND_HARDLINK || entry->size != 0 ||
        entry->xattr_count != 0 || entry->hardlink_root_id.length != 4 ||
        memcmp(entry->hardlink_root_id.data, "ROOT", 4) != 0 ||
        entry->hardlink_logical_path.length != 8 ||
        memcmp(entry->hardlink_logical_path.data, "dir/file", 8) != 0 ||
        entry->symlink_target.length != 0)
        state->valid = 0;
    return 0;
}

static void test_symlink_and_hardlink_writer(int fd)
{
    printf(BLUE "::" NC " symlink and hardlink writer validation and round trip\n");
    static const unsigned char target[] = "../target";

    SidecarEntry entry = sample_entry();
    entry.kind = SIDECAR_KIND_SYMLINK;
    entry.size = 0;
    entry.xattr_count = 0;
    entry.symlink_target = (SidecarBytes){ target, sizeof(target) - 1U };
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0 &&
          sidecar_write_entry_commit(fd) == 0,
          "well-formed symlink entry writes");

    SymlinkRoundTripState state = {
        .target = target,
        .target_length = sizeof(target) - 1U,
        .valid = 1
    };
    SidecarParseResult result;
    check(sidecar_parse_fd(fd, symlink_roundtrip_callback, &state, &result) ==
              SIDECAR_STATUS_OK && state.valid && state.entries == 1,
          "written symlink target round-trips byte-for-byte");

    entry = sample_entry();
    entry.kind = SIDECAR_KIND_SYMLINK;
    entry.size = 0;
    entry.xattr_count = 0;
    entry.symlink_target = (SidecarBytes){ NULL, 0 };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "empty symlink target is rejected as malformed");

    entry = sample_entry();
    entry.kind = SIDECAR_KIND_SYMLINK;
    entry.size = 0;
    entry.xattr_count = 0;
    entry.symlink_target = (SidecarBytes){ target, sizeof(target) - 1U };
    entry.hardlink_root_id = entry.root_id;
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "symlink hardlink fields are rejected");

    entry = sample_entry();
    entry.kind = SIDECAR_KIND_SYMLINK;
    entry.size = 1;
    entry.xattr_count = 0;
    entry.symlink_target = (SidecarBytes){ target, sizeof(target) - 1U };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "non-zero symlink size is rejected");

    entry = sample_entry();
    entry.kind = SIDECAR_KIND_HARDLINK;
    entry.size = 0;
    entry.xattr_count = 0;
    entry.hardlink_root_id = entry.root_id;
    entry.hardlink_logical_path = entry.logical_path;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) == 0 &&
          sidecar_write_entry_commit(fd) == 0,
          "well-formed hardlink entry writes");

    HardlinkRoundTripState hardlink_state = { .valid = 1 };
    check(sidecar_parse_fd(fd, hardlink_roundtrip_callback, &hardlink_state,
                           &result) == SIDECAR_STATUS_OK &&
          hardlink_state.valid && hardlink_state.entries == 1,
          "hardlink reference fields round-trip byte-for-byte");

    entry.hardlink_root_id = (SidecarBytes){ NULL, 0 };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "hardlink missing root reference is rejected");

    entry = sample_entry();
    entry.kind = SIDECAR_KIND_HARDLINK;
    entry.size = 0;
    entry.xattr_count = 0;
    entry.hardlink_root_id = entry.root_id;
    entry.hardlink_logical_path = (SidecarBytes){ NULL, 0 };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "hardlink missing logical reference is rejected");

    entry.hardlink_logical_path = entry.logical_path;
    entry.xattr_count = 1;
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "hardlink xattrs are rejected");

    entry.xattr_count = 0;
    entry.symlink_target = (SidecarBytes){
        (const unsigned char *)"target", 6
    };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "hardlink symlink target is rejected");

    unsigned char *long_target = malloc(SIDECAR_MAX_SYMLINK_TARGET + 1U);
    check(long_target != NULL, "symlink boundary fixture allocates");
    if (long_target != NULL)
    {
        memset(long_target, 't', SIDECAR_MAX_SYMLINK_TARGET + 1U);
        entry = sample_entry();
        entry.kind = SIDECAR_KIND_SYMLINK;
        entry.size = 0;
        entry.xattr_count = 0;
        entry.symlink_target = (SidecarBytes){
            long_target, SIDECAR_MAX_SYMLINK_TARGET
        };
        check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
              sidecar_write_entry(fd, &entry) == 0,
              "symlink target at its ceiling is accepted");
        entry.symlink_target.length++;
        errno = 0;
        check(sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
              "symlink target over its ceiling is rejected");
        free(long_target);
    }

    static const unsigned char nul_target[] = { 'a', '\0', 'b' };
    entry = sample_entry();
    entry.kind = SIDECAR_KIND_SYMLINK;
    entry.size = 0;
    entry.xattr_count = 0;
    entry.symlink_target = (SidecarBytes){ nul_target, sizeof(nul_target) };
    errno = 0;
    check(reset_file(fd) == 0 && sidecar_write_header(fd) == 0 &&
          sidecar_write_entry(fd, &entry) != 0 && errno == EINVAL,
          "NUL-containing symlink target is rejected");
}

static void test_tail_and_boundary(int fd)
{
    printf(BLUE "::" NC " sidecar tail recovery and boundaries\n");
    RawBuffer buffer = {0};
    check(append_header(&buffer, "3") == 0 &&
          append_regular_entry(&buffer, "420", "0") == 0 &&
          append_commit(&buffer) == 0,
          "valid prefix fixture is built");
    check(set_raw_file(fd, &buffer) == 0, "valid prefix is written");

    uint64_t boundary = buffer.length;
    static const unsigned char partial_delete[] = "DELETE\0ROOT\0dir/file";
    check(write_all_test(fd, partial_delete, sizeof(partial_delete) - 1U) == 0,
          "partial DELETE is appended");
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_TRUNCATED_TAIL,
          "incomplete EOF record is a truncated tail");
    check(result.last_valid_boundary == boundary,
          "tail recovery returns the last committed boundary");

    check(set_raw_file(fd, &buffer) == 0, "claim tail prefix is restored");
    static const unsigned char partial_claim[] = "CLAIM\0ROOT\0dir";
    check(write_all_test(fd, partial_claim, sizeof(partial_claim) - 1U) == 0,
          "partial CLAIM is appended");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_TRUNCATED_TAIL &&
              result.last_valid_boundary == boundary,
          "incomplete CLAIM is a truncated tail at the prior boundary");

    RawBuffer complete_claim = {0};
    check(append_header(&complete_claim, "3") == 0 &&
              append_claim(&complete_claim, "ROOT", "dir/file",
                           "payload/file", "regular") == 0 &&
              set_raw_file(fd, &complete_claim) == 0,
          "complete CLAIM boundary fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_OK &&
              result.last_valid_boundary == result.bytes_read,
          "complete CLAIM advances the valid boundary");
    raw_free(&complete_claim);

    check(set_raw_file(fd, &buffer) == 0, "prefix is restored");
    RawBuffer uncommitted = {0};
    check(append_header(&uncommitted, "3") == 0 &&
          append_regular_entry(&uncommitted, "420", "0") == 0 &&
          set_raw_file(fd, &uncommitted) == 0,
          "uncommitted group is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_TRUNCATED_TAIL,
          "complete group without commit is non-live tail state");
    check(result.last_valid_boundary == sizeof(SIDECAR_MAGIC) + 2U,
          "uncommitted group boundary stays at the header");

    raw_free(&uncommitted);
    raw_free(&buffer);
}

static void test_corruption_and_versions(int fd)
{
    printf(BLUE "::" NC " sidecar corruption classification\n");
    RawBuffer buffer = {0};
    SidecarParseResult result;
    SidecarStatus status;

    check(append_header(&buffer, "1") == 0 && set_raw_file(fd, &buffer) == 0,
          "legacy v1 version fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_UNKNOWN_VERSION,
          "unknown version is not treated as an empty sidecar");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "2") == 0 &&
              append_claim(&buffer, "ROOT", "dir/file", "payload/file",
                           "regular") == 0 &&
              set_raw_file(fd, &buffer) == 0,
          "v2 CLAIM fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_UNKNOWN_VERSION,
          "v2 CLAIM is refused at the v3 version boundary");

    check(reset_file(fd) == 0 &&
          write_all_test(fd, (const unsigned char *)"MIGR_SIDECAR\0", 13) == 0 &&
          write_all_test(fd, (const unsigned char *)"01\0", 3) == 0,
          "non-canonical version fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "non-canonical version is corruption");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "3") == 0 &&
          append_regular_entry(&buffer, "0420", "0") == 0 &&
          append_commit(&buffer) == 0 && set_raw_file(fd, &buffer) == 0,
          "non-canonical numeric fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "leading-zero numeric field is corruption");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "3") == 0 && raw_tag(&buffer, "UNKNOWN") == 0 &&
          set_raw_file(fd, &buffer) == 0,
          "unknown tag fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "unknown record tag is interior corruption");
    raw_free(&buffer);

    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "3") == 0 &&
              append_claim(&buffer, "ROOT", "dir/file", "payload/file",
                           "fifo") == 0 && set_raw_file(fd, &buffer) == 0,
          "unsupported CLAIM kind fixture is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "FIFO CLAIM kind is corruption");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "3") == 0 && raw_tag(&buffer, "ENTRY") == 0 &&
              raw_text_field(&buffer, "ROOT") == 0 &&
              raw_text_field(&buffer, "dir/file") == 0 &&
              raw_text_field(&buffer, "payload/file") == 0 &&
              raw_text_field(&buffer, "") == 0 &&
              raw_text_field(&buffer, "regular") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_text_field(&buffer, "0") == 0 &&
              raw_tag(&buffer, "CLAIM") == 0 &&
              raw_text_field(&buffer, "ROOT") == 0 &&
              raw_text_field(&buffer, "dir/file") == 0 &&
              raw_text_field(&buffer, "payload/file") == 0 &&
              raw_text_field(&buffer, "regular") == 0 &&
              set_raw_file(fd, &buffer) == 0,
          "CLAIM inside an open ENTRY group is written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "CLAIM inside an open ENTRY group is corruption");

    raw_free(&buffer);
    memset(&buffer, 0, sizeof(buffer));
    check(append_header(&buffer, "3") == 0 && raw_tag(&buffer, "CLAIM") == 0 &&
              raw_text_field(&buffer, "ROOT") == 0 &&
              raw_text_field(&buffer, "dir/file") == 0 &&
              raw_text_field(&buffer, "regular") == 0 &&
              raw_text_field(&buffer, "payload/file") == 0 &&
              set_raw_file(fd, &buffer) == 0,
          "out-of-order CLAIM fields are written");
    status = sidecar_parse_fd(fd, NULL, NULL, &result);
    check(status == SIDECAR_STATUS_CORRUPT,
          "out-of-order CLAIM fields are corruption");
    raw_free(&buffer);
}

static int symlink_kind_callback(const SidecarRecord *record, void *context)
{
    int *count = context;
    if (record->type == SIDECAR_RECORD_ENTRY &&
        record->value.entry.kind == SIDECAR_KIND_SYMLINK &&
        record->value.entry.symlink_target.length == 9 &&
        memcmp(record->value.entry.symlink_target.data, "../target", 9) == 0)
        (*count)++;
    return 0;
}

static void test_symlink_kind_parsing(int fd)
{
    printf(BLUE "::" NC " sidecar symlink grammar\n");
    RawBuffer buffer = {0};
    check(append_header(&buffer, "3") == 0 && raw_tag(&buffer, "ENTRY") == 0 &&
          raw_text_field(&buffer, "ROOT") == 0 &&
          raw_text_field(&buffer, "link") == 0 &&
          raw_text_field(&buffer, "payload/link") == 0 &&
          raw_text_field(&buffer, "") == 0 &&
          raw_text_field(&buffer, "symlink") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "1000") == 0 &&
          raw_text_field(&buffer, "1000") == 0 &&
          raw_text_field(&buffer, "1") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "2") == 0 &&
          raw_text_field(&buffer, "3") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "0") == 0 &&
          raw_text_field(&buffer, "../target") == 0 &&
          append_commit(&buffer) == 0 && set_raw_file(fd, &buffer) == 0,
          "raw symlink record fixture is written");

    int seen = 0;
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, symlink_kind_callback, &seen,
                                            &result);
    check(status == SIDECAR_STATUS_OK && seen == 1,
          "symlink target field parses from a raw record");
    raw_free(&buffer);
}

static void test_reader_path_ceiling(int fd)
{
    printf(BLUE "::" NC " sidecar reader path ceiling\n");
    unsigned char *path = malloc(SIDECAR_MAX_PATH + 1U);
    RawBuffer buffer = {0};
    check(path != NULL, "reader path ceiling fixture allocates");
    if (path == NULL)
        return;
    memset(path, 'p', SIDECAR_MAX_PATH + 1U);

    check(append_header(&buffer, "3") == 0 &&
          append_regular_entry_with_logical(&buffer, path, SIDECAR_MAX_PATH,
                                            "0", "0") == 0 &&
          append_commit(&buffer) == 0 && set_raw_file(fd, &buffer) == 0,
          "raw entry at the path ceiling is written");
    SidecarParseResult result;
    check(sidecar_parse_fd(fd, NULL, NULL, &result) == SIDECAR_STATUS_OK,
          "reader accepts a path at its ceiling");

    raw_free(&buffer);
    check(append_header(&buffer, "3") == 0 &&
          append_regular_entry_with_logical(&buffer, path,
                                            SIDECAR_MAX_PATH + 1U,
                                            "0", "0") == 0 &&
          append_commit(&buffer) == 0 && set_raw_file(fd, &buffer) == 0,
          "raw entry over the path ceiling is written");
    check(sidecar_parse_fd(fd, NULL, NULL, &result) == SIDECAR_STATUS_LIMIT,
          "reader refuses a path over its ceiling");

    raw_free(&buffer);
    free(path);
}

static void test_total_limit(int fd)
{
    printf(BLUE "::" NC " sidecar total-byte ceiling\n");
    if (sizeof(off_t) < 8)
    {
        check(1, "host off_t is too narrow for the four-gigabyte fixture");
        return;
    }
    check(reset_file(fd) == 0 &&
          ftruncate(fd, (off_t)(SIDECAR_MAX_TOTAL_BYTES + 1U)) == 0,
          "oversized sparse fixture is created");
    SidecarParseResult result;
    check(sidecar_parse_fd(fd, NULL, NULL, &result) == SIDECAR_STATUS_LIMIT,
          "sidecar larger than total-byte ceiling is refused before parsing");
    check(reset_file(fd) == 0, "oversized fixture is removed");
}

static void test_live_entry_ceiling(void)
{
    printf(BLUE "::" NC " sidecar live-entry ceiling helper\n");
    check(sidecar_live_entry_count_allowed(SIDECAR_MAX_LIVE_ENTRIES),
          "live-entry count at its ceiling is accepted");
    check(!sidecar_live_entry_count_allowed(
              (uint64_t)SIDECAR_MAX_LIVE_ENTRIES + 1U),
          "live-entry count over its ceiling is refused");
}

int main(void)
{
    char path[] = "/tmp/migr_sidecar_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
    {
        perror("mkstemp");
        return 1;
    }
    unlink(path);

    test_header_and_roundtrip(fd);
    test_writer_validation(fd);
    test_claim_writer_validation(fd);
    test_collision_suffix(fd);
    test_symlink_and_hardlink_writer(fd);
    test_tail_and_boundary(fd);
    test_corruption_and_versions(fd);
    test_symlink_kind_parsing(fd);
    test_reader_path_ceiling(fd);
    test_total_limit(fd);
    test_live_entry_ceiling();

    close(fd);
    printf("sidecar tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
