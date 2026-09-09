// Scale test for the sidecar v4 live-state map (docs/DECISIONS.md D17/D39): proof
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

#include <errno.h>
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
extern size_t sidecar_state_test_entry_probe_index(const SidecarLog *log,
                                                   SidecarBytes root_id,
                                                   SidecarBytes logical_path);
extern uint64_t sidecar_state_test_entry_used_count(const SidecarLog *log);

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
    const char *slash = strrchr(physical, '/');
    const char *leaf = logical[0] == '\0' ? "" :
                       (slash == NULL ? physical : slash + 1);
    entry.physical_leaf = (SidecarBytes){ (const unsigned char *)leaf,
                                          strlen(leaf) };
    entry.kind = SIDECAR_KIND_REGULAR;
    entry.mode = 0644;
    entry.uid = 1000;
    entry.gid = 1000;
    entry.size = size;
    return entry;
}

static SidecarEntry make_entry_with_xattr(const char *root,
                                          const char *logical,
                                          const char *physical,
                                          uint64_t size)
{
    SidecarEntry entry = make_entry(root, logical, physical, size);
    entry.xattr_count = 1;
    return entry;
}

static SidecarXattr scale_xattr(void)
{
    static const unsigned char value[] = { 0x00, 0x31, 0xff, 0x00 };
    return (SidecarXattr){
        .name = { (const unsigned char *)"user.scale", 10 },
        .value = { value, sizeof(value) }
    };
}

static int bytes_match_text(SidecarBytes bytes, const char *text)
{
    size_t length = text == NULL ? 0 : strlen(text);
    return text != NULL && bytes.length == length &&
           (length == 0 || (bytes.data != NULL &&
                            memcmp(bytes.data, text, length) == 0));
}

static int deleted_view_matches(const SidecarLiveView *view,
                                uint64_t expected_size)
{
    SidecarXattr expected = scale_xattr();
    return view != NULL && view->entry != NULL &&
           bytes_match_text(view->entry->physical_leaf, "deleted") &&
           view->entry->size == expected_size && view->xattr_count == 1 &&
           view->xattrs != NULL &&
           bytes_match_text(view->xattrs[0].name, "user.scale") &&
           view->xattrs[0].value.data != NULL &&
           view->xattrs[0].value.length == expected.value.length &&
           memcmp(view->xattrs[0].value.data, expected.value.data,
                  expected.value.length) == 0 &&
           view->generation == 1;
}

static int reset_slot(int container_fd)
{
    if (unlinkat(container_fd, SIDECAR_SLOT_NAME, 0) != 0 && errno != ENOENT)
        return -1;
    return 0;
}

static int append_root_claim(SidecarLog *log, const char *root)
{
    SidecarClaim claim = {
        .root_id = { (const unsigned char *)root, strlen(root) },
        .logical_path = { NULL, 0 },
        .physical_leaf = { NULL, 0 },
        .kind = SIDECAR_KIND_DIRECTORY
    };
    return sidecar_log_append_claim(log, &claim) == SIDECAR_STATUS_OK ? 0 : -1;
}

static int append_claimed_entry(SidecarLog *log, const SidecarEntry *entry)
{
    if (log == NULL || entry == NULL || entry->xattr_count > 1)
        return -1;
    SidecarClaim claim = {
        .root_id = entry->root_id,
        .logical_path = entry->logical_path,
        .physical_leaf = entry->physical_leaf,
        .kind = entry->kind
    };
    if (sidecar_log_append_claim(log, &claim) != SIDECAR_STATUS_OK ||
        sidecar_log_append_entry(log, entry) != SIDECAR_STATUS_OK)
        return -1;
    if (entry->xattr_count != 0)
    {
        SidecarXattr xattr = scale_xattr();
        if (sidecar_log_append_xattr(log, &xattr) != SIDECAR_STATUS_OK)
            return -1;
    }
    return sidecar_log_append_entry_commit(log) == SIDECAR_STATUS_OK ? 0 : -1;
}

static int generated_key(const char *prefix, unsigned int index,
                         char *root, size_t root_size,
                         char *logical, size_t logical_size,
                         char *physical, size_t physical_size)
{
    int root_length = snprintf(root, root_size, "scale-%s-root", prefix);
    int logical_length = snprintf(logical, logical_size,
                                  "scale-%s-path-%05u", prefix, index);
    int physical_length = snprintf(physical, physical_size,
                                   "payload/%s/%05u", prefix, index);
    return root_length >= 0 && logical_length >= 0 && physical_length >= 0 &&
           (size_t)root_length < root_size &&
           (size_t)logical_length < logical_size &&
           (size_t)physical_length < physical_size;
}

static int append_generated_entry(SidecarLog *log, const char *prefix,
                                  unsigned int index)
{
    char root[64];
    char logical[64];
    char physical[96];
    if (!generated_key(prefix, index, root, sizeof(root), logical,
                       sizeof(logical), physical, sizeof(physical)))
        return -1;
    SidecarEntry entry = make_entry(root, logical, physical, index);
    return append_claimed_entry(log, &entry);
}

static int append_probe_collisions(SidecarLog *log, size_t target_probe,
                                   unsigned int wanted)
{
    unsigned int found = 0;
    for (unsigned int candidate = 0;
         candidate < 200000U && found < wanted; candidate++)
    {
        char root[64];
        char logical[64];
        char physical[96];
        if (!generated_key("collision", candidate, root, sizeof(root),
                           logical, sizeof(logical), physical,
                           sizeof(physical)))
            return -1;
        if (sidecar_state_test_entry_probe_index(
                log,
                (SidecarBytes){ (const unsigned char *)root, strlen(root) },
                (SidecarBytes){ (const unsigned char *)logical,
                                strlen(logical) }) != target_probe)
            continue;
        SidecarEntry entry = make_entry(root, logical, physical, candidate);
        if (append_claimed_entry(log, &entry) != 0)
            return -1;
        found++;
    }
    return found == wanted ? 0 : -1;
}

static void test_tombstone_collision_persistence(int container_fd)
{
    printf(BLUE "::" NC " entry tombstone collision persistence\n");
    check(reset_slot(container_fd) == 0, "collision fixture slot resets");

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              append_root_claim(&log, "TROOT") == 0 &&
              append_root_claim(&log, "scale-collision-root") == 0,
          "collision fixture creates the required v4 ancestry roots");
    SidecarEntry deleted = make_entry_with_xattr(
        "TROOT", "deleted", "payload/deleted", 17);
    check(append_claimed_entry(&log, &deleted) == 0,
          "collision fixture commits the entry later deleted");
    SidecarDelete deletion = {
        .root_id = deleted.root_id,
        .logical_path = deleted.logical_path
    };
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK,
          "collision fixture records the deletion");

    size_t target_probe = sidecar_state_test_entry_probe_index(
        &log, deleted.root_id, deleted.logical_path);
    check(target_probe != SIZE_MAX &&
              sidecar_state_test_entry_used_count(&log) == 1,
          "deleted entry retains one used entry-map slot");
    SidecarLiveView view = {0};
    check(sidecar_log_find_deleted(&log, deleted.root_id,
                                   deleted.logical_path, &view) == 1 &&
              deleted_view_matches(&view, 17),
          "deleted entry metadata is available before colliding inserts");
    check(append_probe_collisions(&log, target_probe, 3) == 0,
          "new keys with the tombstone probe index are committed");
    check(sidecar_log_find_deleted(&log, deleted.root_id,
                                   deleted.logical_path, &view) == 1 &&
              deleted_view_matches(&view, 17),
          "probe collisions do not reuse the deleted entry slot");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "collision fixture closes before adoption");

    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_find_deleted(&log, deleted.root_id,
                                       deleted.logical_path, &view) == 1 &&
              deleted_view_matches(&view, 17),
          "adoption preserves the colliding tombstone and its metadata");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "adopted collision fixture closes");
    check(reset_slot(container_fd) == 0, "collision fixture is removed");
}

static void test_tombstone_rehash_persistence(int container_fd)
{
    printf(BLUE "::" NC " entry tombstone rehash persistence\n");
    check(reset_slot(container_fd) == 0, "rehash fixture slot resets");

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              append_root_claim(&log, "RROOT") == 0 &&
              append_root_claim(&log, "scale-rehash-root") == 0,
          "rehash fixture creates the required v4 ancestry roots");
    SidecarEntry deleted = make_entry_with_xattr(
        "RROOT", "deleted", "payload/deleted", 23);
    check(append_claimed_entry(&log, &deleted) == 0,
          "rehash fixture commits the entry later deleted");
    SidecarDelete deletion = {
        .root_id = deleted.root_id,
        .logical_path = deleted.logical_path
    };
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK,
          "rehash fixture records the deletion");

    int rehash_ok = 1;
    for (unsigned int index = 0; index < 40U && rehash_ok; index++)
    {
        if (append_generated_entry(&log, "rehash", index) != 0)
            rehash_ok = 0;
    }
    check(rehash_ok, "40 new entries commit while deleted state remains stored");
    SidecarLiveView view = {0};
    check(sidecar_log_live_count(&log) == 40U &&
              sidecar_state_test_entry_used_count(&log) == 41U &&
              sidecar_log_find_deleted(&log, deleted.root_id,
                                       deleted.logical_path, &view) == 1 &&
              deleted_view_matches(&view, 23),
          "a capacity-growing rehash carries the deleted entry");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "rehash fixture closes before adoption");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_find_deleted(&log, deleted.root_id,
                                       deleted.logical_path, &view) == 1 &&
              deleted_view_matches(&view, 23),
          "adoption preserves the rehashed tombstone");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "adopted rehash fixture closes");
    check(reset_slot(container_fd) == 0, "rehash fixture is removed");
}

static void test_resurrection_and_used_count(int container_fd)
{
    printf(BLUE "::" NC " entry tombstone resurrection accounting\n");
    check(reset_slot(container_fd) == 0, "resurrection fixture slot resets");

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              append_root_claim(&log, "UROOT") == 0 &&
              append_root_claim(&log, "scale-resurrection-new-root") == 0,
          "resurrection fixture creates the required v4 ancestry roots");
    SidecarEntry original = make_entry(
        "UROOT", "file", "payload/original", 31);
    check(append_claimed_entry(&log, &original) == 0,
          "resurrection fixture commits the original entry");
    SidecarDelete deletion = {
        .root_id = original.root_id,
        .logical_path = original.logical_path
    };
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK,
          "resurrection fixture records the deletion");
    uint64_t used_before_resurrection =
        sidecar_state_test_entry_used_count(&log);

    SidecarEntry replacement = make_entry(
        "UROOT", "file", "payload/resurrected", 37);
    check(append_claimed_entry(&log, &replacement) == 0,
          "the deleted key is committed again");
    uint64_t used_after_resurrection =
        sidecar_state_test_entry_used_count(&log);
    SidecarLiveView view = {0};
    check(used_before_resurrection == 1 &&
              used_after_resurrection == used_before_resurrection &&
              sidecar_log_find(&log, replacement.root_id,
                               replacement.logical_path, &view) == 1 &&
              bytes_match_text(view.entry->physical_leaf, "resurrected") &&
              sidecar_log_find_deleted(&log, replacement.root_id,
                                       replacement.logical_path, &view) == 0,
          "resurrection restores live state without growing used count");

    uint64_t used_before_new = sidecar_state_test_entry_used_count(&log);
    check(append_generated_entry(&log, "resurrection-new", 0) == 0,
          "a genuinely new key commits after resurrection");
    uint64_t used_after_new = sidecar_state_test_entry_used_count(&log);
    check(used_after_new == used_before_new + 1U,
          "a genuinely new key grows the entry-map used count by one");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "resurrection fixture closes");
    check(reset_slot(container_fd) == 0, "resurrection fixture is removed");
}

static void test_probe_churn(int container_fd)
{
    enum { CHURN_ENTRY_COUNT = 512U };
    printf(BLUE "::" NC " entry-map churn probe bound\n");
    check(reset_slot(container_fd) == 0, "churn fixture slot resets");

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              append_root_claim(&log, "scale-churn-root") == 0,
          "churn fixture creates the required v4 ancestry root");
    sidecar_state_test_reset_probe_count();
    int churn_ok = 1;
    for (unsigned int index = 0;
         index < CHURN_ENTRY_COUNT && churn_ok; index++)
    {
        char root[64];
        char logical[64];
        char physical[96];
        if (!generated_key("churn", index, root, sizeof(root), logical,
                           sizeof(logical), physical, sizeof(physical)))
        {
            churn_ok = 0;
            break;
        }
        SidecarEntry entry = make_entry(root, logical, physical, index);
        SidecarDelete deletion = {
            .root_id = entry.root_id,
            .logical_path = entry.logical_path
        };
        if (append_claimed_entry(&log, &entry) != 0 ||
            sidecar_log_append_delete(&log, &deletion) != SIDECAR_STATUS_OK)
            churn_ok = 0;
    }
    uint64_t probes = sidecar_state_test_probe_count();
    uint64_t inputs = (uint64_t)CHURN_ENTRY_COUNT * 2U;
    printf("  churn probes=%" PRIu64 " inputs=%" PRIu64 "\n",
           probes, inputs);
    check(churn_ok && sidecar_log_live_count(&log) == 0,
          "commit-delete churn leaves no live entries");
    check(sidecar_state_test_entry_used_count(&log) == CHURN_ENTRY_COUNT,
          "commit-delete churn retains each distinct tombstone");
    check(probes <= inputs * UINT64_C(32),
          "churn probes remain bounded linearly");
    check(probes < (inputs * inputs) / UINT64_C(16),
          "churn probes remain far below quadratic work");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "churn fixture closes");
    check(reset_slot(container_fd) == 0, "churn fixture is removed");
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

static void test_state_map_key_contract(int container_fd)
{
    printf(BLUE "::" NC " state-map key remains root plus logical path\n");
    check(reset_slot(container_fd) == 0, "map-key fixture slot resets");

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              append_root_claim(&log, "ROOT-A") == 0 &&
              append_root_claim(&log, "ROOT-B") == 0,
          "map-key fixture creates two independent ancestry roots");
    SidecarEntry left = make_entry("ROOT-A", "same", "left", 11);
    SidecarEntry right = make_entry("ROOT-B", "same", "right", 22);
    check(append_claimed_entry(&log, &left) == 0 &&
              append_claimed_entry(&log, &right) == 0 &&
              sidecar_log_live_count(&log) == 2,
          "identical logical paths under different roots remain distinct keys");

    SidecarLiveView view = {0};
    check(sidecar_log_find(&log, left.root_id, left.logical_path, &view) == 1 &&
              view.entry != NULL && view.entry->size == 11 &&
              bytes_match_text(view.entry->physical_leaf, "left"),
          "first root/logical key retains its own leaf value");
    check(sidecar_log_find(&log, right.root_id, right.logical_path, &view) == 1 &&
              view.entry != NULL && view.entry->size == 22 &&
              bytes_match_text(view.entry->physical_leaf, "right"),
          "second root/logical key retains its independent leaf value");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "map-key fixture closes");
    check(reset_slot(container_fd) == 0, "map-key fixture is removed");
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

    test_live_entry_ceiling();
    test_state_map_key_contract(container_fd);
    test_tombstone_collision_persistence(container_fd);
    test_tombstone_rehash_persistence(container_fd);
    test_resurrection_and_used_count(container_fd);
    test_probe_churn(container_fd);

    check(reset_slot(container_fd) == 0,
          "large fixture starts with an absent sidecar");
    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              append_root_claim(&log, "scale-root") == 0,
          "large fixture creates a fresh sidecar with its v4 ancestry root");

    for (unsigned int index = 0; index < SCALE_ENTRY_COUNT && !failures;
         index++)
    {
        char logical[48];
        char physical[64];
        int logical_length = snprintf(logical, sizeof(logical),
                                      "path-%05u", index);
        int physical_length = snprintf(physical, sizeof(physical),
                                       "payload/path-%05u", index);
        if (logical_length < 0 || physical_length < 0 ||
            (size_t)logical_length >= sizeof(logical) ||
            (size_t)physical_length >= sizeof(physical))
        {
            check(0, "fixture key formatting fits its bounded buffers");
            break;
        }

        SidecarEntry entry = make_entry("scale-root", logical, physical, index);
        SidecarClaim claim = {
            .root_id = entry.root_id,
            .logical_path = entry.logical_path,
            .physical_leaf = entry.physical_leaf,
            .kind = entry.kind
        };
        if (sidecar_log_append_claim(&log, &claim) != SIDECAR_STATUS_OK ||
            sidecar_log_append_entry(&log, &entry) != SIDECAR_STATUS_OK ||
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
        char logical[48];
        int logical_length = snprintf(logical, sizeof(logical),
                                      "path-%05u", expected);
        if (logical_length < 0 ||
            (size_t)logical_length >= sizeof(logical))
        {
            all_found = 0;
            break;
        }
        SidecarLiveView view;
        int found = sidecar_log_find(
            &log,
            (SidecarBytes){ (const unsigned char *)"scale-root", 10 },
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
              (SidecarBytes){ (const unsigned char *)"scale-root", 10 },
              (SidecarBytes){ (const unsigned char *)"path-00000", 10 },
              &edge_view) == 1 && edge_view.entry->size == 0,
          "adopted map retains its first key");
    check(sidecar_log_find(
              &adopted,
              (SidecarBytes){ (const unsigned char *)"scale-root", 10 },
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
