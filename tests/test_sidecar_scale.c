// Scale test for the sidecar v1 live-state map (docs/DECISIONS.md D17): proof
// that the salted open-addressing hash table replacing the old linear scan is
// genuinely sub-quadratic, not just correct at small counts the way
// tests/test_sidecar_state.c's fixtures are.
//
// 50,000 entries are committed, then looked up in reverse insertion order (so
// a lookup pattern that happens to mirror insertion order can't hide a real
// O(n) scan behind a favourable cache/probe pattern). The assertion is on
// probe count, not wall-clock time, so the test stays deterministic across
// machines and load: linear work would cost O(n) probes total, quadratic
// work O(n^2) -- the two bounds checked below (a generous linear multiple,
// and a hard cutoff far under n^2) both fail loudly if the scan regresses,
// while an O(1)-amortized hash table lands nowhere near either ceiling.
//
// Probe counting only exists behind SIDECAR_STATE_TEST_HOOKS (D14: a
// test-only seam, never reachable from a release binary): this file links
// sidecar_state.c compiled with that flag defined (see the Makefile's
// separate sidecar_state_test.o target), not the same object every other
// sidecar test links.

#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sidecar.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

#define SCALE_ENTRY_COUNT 50000U

extern uint64_t sidecar_state_test_probe_count(void);
extern void sidecar_state_test_reset_probe_count(void);

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

static SidecarEntry make_entry(const char *root, const char *logical,
                               const char *physical, uint64_t size)
{
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = (SidecarBytes){ (const unsigned char *)root,
                                    strlen(root) };
    entry.logical_path = (SidecarBytes){ (const unsigned char *)logical,
                                         strlen(logical) };
    entry.physical_path = (SidecarBytes){ (const unsigned char *)physical,
                                          strlen(physical) };
    entry.kind = SIDECAR_KIND_REGULAR;
    entry.mode = 0644;
    entry.uid = 1000;
    entry.gid = 1000;
    entry.size = size;
    return entry;
}

int main(void)
{
    printf(BLUE "::" NC " salted live-state hash scale\n");
    char directory[] = "/tmp/migr_sidecar_scale_XXXXXX";
    if (mkdtemp(directory) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }

    int container_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container_fd < 0)
    {
        perror("open");
        rmdir(directory);
        return 1;
    }

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "large fixture creates a fresh sidecar");

    for (unsigned int index = 0; index < SCALE_ENTRY_COUNT && !failures;
         index++)
    {
        char root[32];
        char logical[48];
        char physical[64];
        int root_length = snprintf(root, sizeof(root), "root-%05u", index);
        int logical_length = snprintf(logical, sizeof(logical),
                                      "path-%05u", index);
        int physical_length = snprintf(physical, sizeof(physical),
                                       "payload/path-%05u", index);
        if (root_length < 0 || logical_length < 0 || physical_length < 0 ||
            (size_t)root_length >= sizeof(root) ||
            (size_t)logical_length >= sizeof(logical) ||
            (size_t)physical_length >= sizeof(physical))
        {
            check(0, "fixture key formatting fits its bounded buffers");
            break;
        }

        SidecarEntry entry = make_entry(root, logical, physical, index);
        if (sidecar_log_append_entry(&log, &entry) != SIDECAR_STATUS_OK ||
            sidecar_log_append_entry_commit(&log) != SIDECAR_STATUS_OK)
        {
            check(0, "50,000 entries append and commit");
            break;
        }
    }
    check(!failures && sidecar_log_live_count(&log) == SCALE_ENTRY_COUNT,
          "50,000 committed entries are live");

    sidecar_state_test_reset_probe_count();
    int all_found = 1;
    for (unsigned int index = SCALE_ENTRY_COUNT; index > 0; index--)
    {
        unsigned int expected = index - 1U;
        char root[32];
        char logical[48];
        int root_length = snprintf(root, sizeof(root), "root-%05u", expected);
        int logical_length = snprintf(logical, sizeof(logical),
                                      "path-%05u", expected);
        if (root_length < 0 || logical_length < 0 ||
            (size_t)root_length >= sizeof(root) ||
            (size_t)logical_length >= sizeof(logical))
        {
            all_found = 0;
            break;
        }
        SidecarLiveView view;
        int found = sidecar_log_find(
            &log,
            (SidecarBytes){ (const unsigned char *)root, strlen(root) },
            (SidecarBytes){ (const unsigned char *)logical, strlen(logical) },
            &view);
        if (found != 1 || view.entry == NULL || view.entry->size != expected)
        {
            all_found = 0;
            break;
        }
    }
    check(all_found, "reverse lookups find every live entry");

    uint64_t probes = sidecar_state_test_probe_count();
    uint64_t count = SCALE_ENTRY_COUNT;
    printf("  probes=%" PRIu64 " entries=%" PRIu64 "\n", probes, count);
    check(probes <= count * UINT64_C(32),
          "lookup probes remain bounded linearly");
    check(probes < (count * count) / UINT64_C(1000),
          "lookup probes are far below quadratic work");

    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "scale log closes cleanly");
    SidecarLog adopted = {0};
    check(sidecar_log_adopt_at(container_fd, &adopted) == SIDECAR_OPEN_RESUMABLE &&
          sidecar_log_live_count(&adopted) == SCALE_ENTRY_COUNT,
          "50,000-entry log is adoptable with its live map");
    SidecarLiveView edge_view;
    check(sidecar_log_find(
              &adopted,
              (SidecarBytes){ (const unsigned char *)"root-00000", 10 },
              (SidecarBytes){ (const unsigned char *)"path-00000", 10 },
              &edge_view) == 1 && edge_view.entry->size == 0,
          "adopted map retains its first key");
    check(sidecar_log_find(
              &adopted,
              (SidecarBytes){ (const unsigned char *)"root-49999", 10 },
              (SidecarBytes){ (const unsigned char *)"path-49999", 10 },
              &edge_view) == 1 && edge_view.entry->size == 49999,
          "adopted map retains its last key");
    check(sidecar_log_close(&adopted) == SIDECAR_STATUS_OK,
          "adopted scale log closes cleanly");
    unlinkat(container_fd, SIDECAR_SLOT_NAME, 0);
    close(container_fd);
    rmdir(directory);
    printf("sidecar scale tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
