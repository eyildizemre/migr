// Fuzz harness for the load path verify and restore use: the input becomes
// the journal of a throwaway container directory, sidecar_log_open_readonly_at()
// loads it, and restore_address_index_build() decides whether restore may act
// on it.
//
// Oracles, each an abort:
// - Memory safety, from the sanitizers or Valgrind.
// - Untrusted bytes end the load as usable or unusable, never as an I/O,
//   allocation, or caller error.
// - The claim map's rehash work stays linear in the claims loaded. A rehash
//   in place frees at least a quarter of the map and growth doubles it, so
//   the slots rehashes walk stay under REHASH_SLOTS_PER_CLAIM per claim.
// - Acceptance, checked without migr's own validators: every live logical
//   path is relative with nonempty components other than . and .., every
//   other entry has a physical leaf that is a single component, every
//   parent is a live directory, and the root object has no leaf.

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fuzz.h"
#include "portable_restore_internal.h"
#include "sidecar.h"

#define REHASH_SLOTS_PER_CLAIM 8U
#define REHASH_SLOTS_FIXED 64U

// From the sidecar_state_map_test.o build.
extern uint64_t sidecar_state_test_claim_rehash_slot_count(void);

const char fuzz_target_name[] = "sidecar_load";

static char container_path[4096];
static int container_fd = -1;

static void fail(const char *what)
{
    fprintf(stderr, "fuzz_sidecar_load: %s\n", what);
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
    snprintf(container_path, sizeof(container_path), "%s/migr-fuzz-load-XXXXXX",
             temporary != NULL && temporary[0] != '\0' ? temporary : "/tmp");
    if (mkdtemp(container_path) == NULL)
        fail("cannot create the container directory");
    container_fd = open(container_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
        fail("cannot open the container directory");
    atexit(remove_container);
    return container_fd;
}

static int count_claim(const SidecarRecord *record, void *context)
{
    if (record->type == SIDECAR_RECORD_CLAIM)
        (*(uint64_t *)context)++;
    return 0;
}

static uint64_t claim_records(const uint8_t *data, size_t size)
{
    uint64_t claims = 0;
    SidecarParseResult result;
    int fd = memfd_create("fuzz", MFD_CLOEXEC);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size))
        fail("cannot hold the input in a memfd");
    sidecar_parse_fd(fd, count_claim, &claims, &result);
    close(fd);
    return claims;
}

static int component_valid(const unsigned char *data, size_t length)
{
    return length > 0 && memchr(data, '/', length) == NULL &&
           !(length == 1 && data[0] == '.') &&
           !(length == 2 && data[0] == '.' && data[1] == '.');
}

static int logical_path_valid(SidecarBytes path)
{
    size_t start = 0;
    for (size_t index = 0; index <= path.length; index++)
    {
        if (index < path.length && path.data[index] != '/')
            continue;
        if (!component_valid(path.data + start, index - start))
            return 0;
        start = index + 1;
    }
    return 1;
}

static int check_live(const SidecarLiveView *view, void *context)
{
    const SidecarLog *log = context;
    const SidecarEntry *entry = view->entry;
    SidecarBytes path = entry->logical_path;
    if (path.length == 0)
    {
        if (entry->physical_leaf.length != 0)
            fail("the gate accepted a root object with a leaf");
        return 0;
    }
    if (!logical_path_valid(path))
        fail("the gate accepted an invalid logical path");
    if (!component_valid(entry->physical_leaf.data,
                         entry->physical_leaf.length))
        fail("the gate accepted an invalid physical leaf");

    size_t cut = path.length;
    while (cut > 0 && path.data[cut - 1] != '/')
        cut--;
    SidecarBytes parent = { path.data, cut > 0 ? cut - 1 : 0 };
    SidecarLiveView parent_view;
    if (sidecar_log_find(log, entry->root_id, parent, &parent_view) != 1 ||
        parent_view.entry->kind != SIDECAR_KIND_DIRECTORY)
        fail("the gate accepted an entry without a live directory parent");
    return 0;
}

static const char *load(const uint8_t *data, size_t size)
{
    int directory = container();
    int fd = openat(directory, SIDECAR_SLOT_NAME,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || (size > 0 && write(fd, data, size) != (ssize_t)size) ||
        close(fd) != 0)
        fail("cannot write the journal");

    uint64_t walked = sidecar_state_test_claim_rehash_slot_count();
    SidecarLog log = {0};
    SidecarOpenStatus status = sidecar_log_open_readonly_at(directory, &log);
    walked = sidecar_state_test_claim_rehash_slot_count() - walked;
    if (walked > REHASH_SLOTS_PER_CLAIM * claim_records(data, size) +
                     REHASH_SLOTS_FIXED)
        fail("the claim map's rehash work grows faster than its claims");

    if (status == SIDECAR_OPEN_UNUSABLE)
        return "unusable";
    if (status != SIDECAR_OPEN_RESUMABLE)
        fail("a load ends with an unexpected status");

    RestoreAddressIndex index;
    PreflightMemory memory;
    memset(&index, 0, sizeof(index));
    memset(&memory, 0, sizeof(memory));
    const char *outcome = "refused";
    if (restore_address_index_build(&index, &memory, &log, NULL) == 0)
    {
        outcome = "accepted";
        sidecar_log_foreach(&log, check_live, &log);
        restore_address_index_free(&memory, &index);
    }
    sidecar_log_close(&log);
    return outcome;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    load(data, size);
    return 0;
}

const char *fuzz_outcome(const uint8_t *data, size_t size)
{
    return load(data, size);
}

const char *fuzz_seed_outcome(const FuzzSeed *seed)
{
    return seed->load_outcome;
}

void fuzz_check_seed(const FuzzSeed *seed)
{
    (void)seed;
}
