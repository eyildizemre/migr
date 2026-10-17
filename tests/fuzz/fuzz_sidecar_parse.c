// Fuzz harness for the journal grammar: sidecar_parse_fd() and
// sidecar_parse_fd_from() over arbitrary bytes. The callback only observes,
// hashing every record it is given, so two parses can be compared.
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind.
// - Boundary sanity: offsets never pass the input, an OK parse ends at its
//   end, and a zero boundary means the header itself failed.
// - Split identity: the input up to a nonzero boundary parses on its own as
//   OK, and parsing on from that boundary delivers the rest, so the two give
//   the whole parse's records and result.
// - A parse from any offset past the header, as repair resumes after damage,
//   keeps its offsets inside the input.
// Over unedited writer output (fuzz_check_seed), every prefix parses as OK or
// as a truncated tail, which is what a killed process leaves, and the split
// identity holds at every group boundary.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz.h"
#include "sidecar.h"

// Every prefix of a writer seed is parsed, so its size bounds the cost.
#define PREFIX_CLOSURE_LIMIT 16384U

#define FNV_OFFSET UINT64_C(14695981039346656037)
#define FNV_PRIME UINT64_C(1099511628211)

const char fuzz_target_name[] = "sidecar_parse";

typedef struct {
    uint64_t hash;
    uint64_t count;
} Trace;

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_sidecar_parse: %s\n", what);
    abort();
}

static uint64_t mix(uint64_t hash, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    for (size_t index = 0; index < length; index++)
    {
        hash ^= bytes[index];
        hash *= FNV_PRIME;
    }
    return hash;
}

static uint64_t mix_bytes(uint64_t hash, SidecarBytes field)
{
    hash = mix(hash, &field.length, sizeof(field.length));
    return mix(hash, field.data, field.length);
}

static uint64_t mix_entry(uint64_t hash, const SidecarEntry *entry)
{
    hash = mix_bytes(hash, entry->root_id);
    hash = mix_bytes(hash, entry->logical_path);
    hash = mix_bytes(hash, entry->physical_leaf);
    hash = mix_bytes(hash, entry->collision_suffix);
    hash = mix_bytes(hash, entry->symlink_target);
    hash = mix_bytes(hash, entry->hardlink_root_id);
    hash = mix_bytes(hash, entry->hardlink_logical_path);
    hash = mix(hash, &entry->kind, sizeof(entry->kind));
    hash = mix(hash, &entry->mode, sizeof(entry->mode));
    hash = mix(hash, &entry->uid, sizeof(entry->uid));
    hash = mix(hash, &entry->gid, sizeof(entry->gid));
    hash = mix(hash, &entry->atime_sec, sizeof(entry->atime_sec));
    hash = mix(hash, &entry->atime_nsec, sizeof(entry->atime_nsec));
    hash = mix(hash, &entry->mtime_sec, sizeof(entry->mtime_sec));
    hash = mix(hash, &entry->mtime_nsec, sizeof(entry->mtime_nsec));
    hash = mix(hash, &entry->size, sizeof(entry->size));
    hash = mix(hash, &entry->xattr_count, sizeof(entry->xattr_count));
    return mix(hash, &entry->content_digest, sizeof(entry->content_digest));
}

static int observe(const SidecarRecord *record, void *context)
{
    Trace *trace = context;
    uint64_t hash = mix(trace->hash, &record->type, sizeof(record->type));
    switch (record->type)
    {
        case SIDECAR_RECORD_ENTRY:
        case SIDECAR_RECORD_ENTRY_COMMIT:
            hash = mix_entry(hash, &record->value.entry);
            break;
        case SIDECAR_RECORD_XATTR:
            hash = mix_bytes(hash, record->value.xattr.name);
            hash = mix_bytes(hash, record->value.xattr.value);
            break;
        case SIDECAR_RECORD_DELETE:
            hash = mix_bytes(hash, record->value.deletion.root_id);
            hash = mix_bytes(hash, record->value.deletion.logical_path);
            break;
        case SIDECAR_RECORD_CLAIM:
            hash = mix_bytes(hash, record->value.claim.root_id);
            hash = mix_bytes(hash, record->value.claim.logical_path);
            hash = mix_bytes(hash, record->value.claim.physical_leaf);
            hash = mix(hash, &record->value.claim.kind,
                       sizeof(record->value.claim.kind));
            break;
    }
    trace->hash = hash;
    trace->count++;
    return 0;
}

static int memfd_holding(const uint8_t *data, size_t size)
{
    int fd = memfd_create("fuzz", MFD_CLOEXEC);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size))
        fail("cannot hold the input in a memfd");
    return fd;
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

// The statuses a parse of untrusted bytes may end with; the others mean an
// I/O, allocation, or caller error.
static int status_expected(SidecarStatus status)
{
    return status == SIDECAR_STATUS_OK ||
           status == SIDECAR_STATUS_TRUNCATED_TAIL ||
           status == SIDECAR_STATUS_CORRUPT ||
           status == SIDECAR_STATUS_UNKNOWN_VERSION ||
           status == SIDECAR_STATUS_LIMIT;
}

static void check_split(int fd, const uint8_t *data, uint64_t boundary,
                        SidecarStatus whole_status,
                        const SidecarParseResult *whole, const Trace *traced)
{
    int prefix_fd = memfd_holding(data, (size_t)boundary);
    Trace trace = { FNV_OFFSET, 0 };
    SidecarParseResult prefix;
    SidecarStatus status = sidecar_parse_fd(prefix_fd, observe, &trace,
                                            &prefix);
    close(prefix_fd);
    if (status != SIDECAR_STATUS_OK || prefix.last_valid_boundary != boundary)
        fail("the input up to a boundary does not parse as OK on its own");

    SidecarParseResult rest;
    status = sidecar_parse_fd_from(fd, boundary, observe, &trace, &rest);
    if (status != whole_status || trace.hash != traced->hash ||
        trace.count != traced->count ||
        prefix.records_read + rest.records_read != whole->records_read ||
        rest.bytes_read != whole->bytes_read ||
        rest.last_valid_boundary != whole->last_valid_boundary)
        fail("parsing on from a boundary differs from the whole parse");
}

// Any offset past the header, chosen from the input itself.
static void check_start(int fd, const uint8_t *data, size_t size)
{
    size_t header = header_length();
    uint64_t start = header +
        mix(FNV_OFFSET, data, size) % (uint64_t)(size - header + 1U);
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd_from(fd, start, NULL, NULL,
                                                 &result);
    if (!status_expected(status))
        fail("a parse from an offset ends with an unexpected status");
    if (result.bytes_read > size || result.last_valid_boundary < start ||
        result.last_valid_boundary > result.bytes_read)
        fail("a parse from an offset reports offsets outside the input");
    if (status == SIDECAR_STATUS_OK && result.bytes_read != size)
        fail("a parse from an offset is OK before the input's end");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_holding(data, size);
    Trace trace = { FNV_OFFSET, 0 };
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, observe, &trace, &result);
    if (!status_expected(status))
        fail("a parse ends with an unexpected status");
    if (result.bytes_read > size ||
        result.last_valid_boundary > result.bytes_read)
        fail("a parse reports offsets past the input");
    // The boundary is set only once the header has parsed.
    if (result.last_valid_boundary == 0)
    {
        if ((status != SIDECAR_STATUS_CORRUPT &&
             status != SIDECAR_STATUS_UNKNOWN_VERSION &&
             status != SIDECAR_STATUS_LIMIT) ||
            trace.count != 0)
            fail("a header failure delivers records or an unexpected status");
    }
    else
    {
        if (status == SIDECAR_STATUS_OK && result.last_valid_boundary != size)
            fail("an OK parse ends before the input's end");
        check_split(fd, data, result.last_valid_boundary, status, &result,
                    &trace);
        check_start(fd, data, size);
    }
    close(fd);
    return 0;
}

const char *fuzz_outcome(const uint8_t *data, size_t size)
{
    int fd = memfd_holding(data, size);
    SidecarParseResult result;
    SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &result);
    close(fd);
    switch (status)
    {
        case SIDECAR_STATUS_OK: return "ok";
        case SIDECAR_STATUS_TRUNCATED_TAIL: return "truncated";
        case SIDECAR_STATUS_CORRUPT: return "corrupt";
        case SIDECAR_STATUS_UNKNOWN_VERSION: return "unknown-version";
        case SIDECAR_STATUS_LIMIT: return "limit";
        default: return "unexpected";
    }
}

const char *fuzz_seed_outcome(const FuzzSeed *seed)
{
    return seed->parse_outcome;
}

void fuzz_check_seed(const FuzzSeed *seed)
{
    if (!seed->writer_output)
        return;
    if (seed->size > PREFIX_CLOSURE_LIMIT)
        fail("a writer seed is too large for the prefix closure");

    int fd = memfd_holding(seed->data, seed->size);
    Trace trace = { FNV_OFFSET, 0 };
    SidecarParseResult whole;
    SidecarStatus status = sidecar_parse_fd(fd, observe, &trace, &whole);
    for (size_t index = 0; index < seed->boundary_count; index++)
        check_split(fd, seed->data, seed->boundaries[index], status, &whole,
                    &trace);

    // Shrinking one memfd walks every prefix down to the header.
    for (size_t length = seed->size; length >= header_length(); length--)
    {
        SidecarParseResult prefix;
        if (ftruncate(fd, (off_t)length) != 0)
            fail("cannot cut a seed");
        status = sidecar_parse_fd(fd, NULL, NULL, &prefix);
        if (status != SIDECAR_STATUS_OK &&
            status != SIDECAR_STATUS_TRUNCATED_TAIL)
            fail("a prefix of writer output does not parse as OK or as a "
                 "truncated tail");
    }
    close(fd);
}
