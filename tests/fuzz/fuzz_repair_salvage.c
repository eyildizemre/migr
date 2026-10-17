// Fuzz harness for repair's salvage, the second parser of damaged journals:
// the input is replayed into a fresh journal the way migr repair rebuilds
// one, skipping each damaged region up to the next record start, and the
// result is checked against the read-only load verify and restore use.
// Salvage runs without a manifest or payload, so settling open claims stays
// with test_repair.
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind.
// - Salvage refuses exactly the journals whose header fails, an unknown
//   version among them: a version this build does not write is never
//   reinterpreted.
// - The salvaged journal loads.
// - A journal that parses as OK and loads salvages intact, with no damaged
//   region and no rejected record, to the same live entries and claims.
// - A journal with a truncated tail, which the read-only load refuses,
//   salvages to its prefix up to the last valid boundary: when that prefix
//   loads, one damaged region, no rejected record, and the prefix's live
//   entries and claims.

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz.h"
#include "repair.h"
#include "sidecar.h"

const char fuzz_target_name[] = "repair_salvage";

static char container_path[4096];
static int container_fd = -1;

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_repair_salvage: %s\n", what);
    abort();
}

static void remove_container(void)
{
    unlinkat(container_fd, SIDECAR_SLOT_NAME, 0);
    close(container_fd);
    rmdir(container_path);
}

static int container(void)
{
    if (container_fd >= 0)
        return container_fd;
    const char *temporary = getenv("TMPDIR");
    snprintf(container_path, sizeof(container_path),
             "%s/migr-fuzz-salvage-XXXXXX",
             temporary != NULL && temporary[0] != '\0' ? temporary : "/tmp");
    if (mkdtemp(container_path) == NULL)
        fail("cannot create the container directory");
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fail("cannot open the container directory");
    atexit(remove_container);
    return container_fd;
}

static void write_slot(const uint8_t *data, size_t size)
{
    int fd = openat(container(), SIDECAR_SLOT_NAME,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size) ||
        close(fd) != 0)
        fail("cannot write the journal");
}

static void remove_slot(void)
{
    if (unlinkat(container(), SIDECAR_SLOT_NAME, 0) != 0)
        fail("cannot remove the journal");
}

// Loads size bytes of data read-only; nonzero when the log is usable.
static int load(const uint8_t *data, size_t size, SidecarLog *log)
{
    write_slot(data, size);
    memset(log, 0, sizeof(*log));
    SidecarOpenStatus status = sidecar_log_open_readonly_at(container(), log);
    remove_slot();
    if (status != SIDECAR_OPEN_RESUMABLE && status != SIDECAR_OPEN_UNUSABLE)
        fail("a load ends with an unexpected status");
    return status == SIDECAR_OPEN_RESUMABLE;
}

// Repair's messages go to the stderr stream; the sanitizers write to the
// descriptor, so their reports still show.
static int salvage(const uint8_t *data, size_t size, SidecarLog *loaded,
                   size_t *damaged_regions, size_t *rejected)
{
    static FILE *quiet;
    if (quiet == NULL && (quiet = fopen("/dev/null", "w")) == NULL)
        fail("cannot open /dev/null");

    SidecarLog log = {0};
    if (sidecar_log_create_at(container(), &log) != SIDECAR_OPEN_FRESH)
        fail("cannot create the salvaged journal");
    FILE *saved = stderr;
    stderr = quiet;
    int result = repair_test_salvage(&log, data, size, damaged_regions,
                                     rejected);
    stderr = saved;
    if (sidecar_log_close(&log) != SIDECAR_STATUS_OK)
        fail("cannot close the salvaged journal");

    memset(loaded, 0, sizeof(*loaded));
    SidecarOpenStatus status = result == 0
        ? sidecar_log_open_readonly_at(container(), loaded)
        : SIDECAR_OPEN_RESUMABLE;
    remove_slot();
    if (status != SIDECAR_OPEN_RESUMABLE)
        fail("a salvaged journal does not load");
    return result;
}

static int bytes_equal(SidecarBytes left, SidecarBytes right)
{
    return left.length == right.length &&
           (left.length == 0 || memcmp(left.data, right.data, left.length) == 0);
}

// An entry group's bytes, which the writer derives from every field.
static unsigned char *group_bytes(const SidecarLiveView *view, size_t *length)
{
    unsigned char *buffer = NULL;
    size_t capacity = 0;
    *length = 0;
    if (sidecar_append_claimed_group(view->entry, view->xattrs, &buffer,
                                     length, &capacity) != 0)
        fail("cannot write a live entry");
    return buffer;
}

static int same_live(const SidecarLiveView *view, void *context)
{
    const SidecarLog *other = context;
    SidecarLiveView match;
    if (sidecar_log_find(other, view->entry->root_id,
                         view->entry->logical_path, &match) != 1)
        fail("a live entry is missing after salvage");
    size_t length, match_length;
    unsigned char *bytes = group_bytes(view, &length);
    unsigned char *match_bytes = group_bytes(&match, &match_length);
    if (length != match_length || memcmp(bytes, match_bytes, length) != 0)
        fail("a live entry differs after salvage");
    free(bytes);
    free(match_bytes);
    return 0;
}

static int same_claim(const SidecarClaimView *view, void *context)
{
    const SidecarLog *other = context;
    const SidecarClaim *claim = view->claim;
    SidecarClaimView match;
    if (sidecar_log_find_claim(other, claim->root_id, claim->logical_path,
                               &match) != 1 ||
        !bytes_equal(claim->physical_leaf, match.claim->physical_leaf) ||
        claim->kind != match.claim->kind)
        fail("a claim differs after salvage");
    return 0;
}

static void check_same(SidecarLog *expected, SidecarLog *salvaged)
{
    if (sidecar_log_live_count(expected) != sidecar_log_live_count(salvaged) ||
        sidecar_log_claim_count(expected) !=
            sidecar_log_claim_count(salvaged))
        fail("salvage changes the number of live entries or claims");
    if (sidecar_log_foreach(expected, same_live, salvaged) !=
            SIDECAR_STATUS_OK ||
        sidecar_log_claim_foreach(expected, same_claim, salvaged) !=
            SIDECAR_STATUS_OK)
        fail("cannot walk a loaded journal");
}

static const char *check_input(const uint8_t *data, size_t size)
{
    SidecarParseResult parsed;
    int fd = memfd_create("fuzz", MFD_CLOEXEC);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size))
        fail("cannot hold the input in a memfd");
    SidecarStatus status = sidecar_parse_fd(fd, NULL, NULL, &parsed);
    close(fd);

    // What salvage must give: the whole journal when it parses, the prefix
    // up to its last valid boundary when only its tail is cut.
    SidecarLog expected = {0};
    int compare = 0;
    if (status == SIDECAR_STATUS_OK)
        compare = load(data, size, &expected);
    else if (status == SIDECAR_STATUS_TRUNCATED_TAIL)
        compare = load(data, (size_t)parsed.last_valid_boundary, &expected);

    SidecarLog salvaged;
    size_t damaged_regions = 0, rejected = 0;
    int result = salvage(data, size, &salvaged, &damaged_regions, &rejected);
    if ((result == 0) != (parsed.last_valid_boundary != 0))
        fail("salvage and the parser disagree about the header");

    if (compare)
    {
        size_t damage = status == SIDECAR_STATUS_OK ? 0 : 1U;
        if (damaged_regions != damage || rejected != 0)
            fail("salvage reports damage a loading journal does not have");
        check_same(&expected, &salvaged);
        sidecar_log_close(&expected);
    }
    if (result != 0)
        return "refused";
    sidecar_log_close(&salvaged);
    return damaged_regions == 0 && rejected == 0 ? "intact" : "salvaged";
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    check_input(data, size);
    return 0;
}

const char *fuzz_outcome(const uint8_t *data, size_t size)
{
    return check_input(data, size);
}

const char *fuzz_seed_outcome(const FuzzSeed *seed)
{
    return seed->salvage_outcome;
}

void fuzz_check_seed(const FuzzSeed *seed)
{
    (void)seed;
}
