// Focused invariants for D39 portable restore leaf authentication/addressing.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "portable_name.h"
#include "portable_restore_internal.h"
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

static SidecarBytes text_bytes(const char *text)
{
    return (SidecarBytes){
        .data = (const unsigned char *)text,
        .length = strlen(text)
    };
}

static SidecarEntry entry_for(const char *logical, const char *physical_leaf,
                              const char *suffix, SidecarObjectKind kind)
{
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = text_bytes("ROOT");
    entry.logical_path = text_bytes(logical);
    entry.physical_leaf = text_bytes(physical_leaf);
    entry.collision_suffix = text_bytes(suffix);
    entry.kind = kind;
    return entry;
}

static void test_ordinary_leaf_authentication(void)
{
    printf(BLUE "::" NC " canonical physical-leaf authentication\n");

    SidecarEntry ascii = entry_for("file.txt", "file.txt", "",
                                   SIDECAR_KIND_REGULAR);
    SidecarEntry punctuation = entry_for("a b:c", "a%20b%3Ac", "",
                                         SIDECAR_KIND_REGULAR);
    SidecarEntry trailing_dot = entry_for("notes.", "notes%2E", "",
                                          SIDECAR_KIND_REGULAR);
    SidecarEntry utf8 = entry_for("caf\xC3\xA9", "caf\xC3\xA9", "",
                                  SIDECAR_KIND_REGULAR);
    SidecarEntry suffixed = entry_for("file", "file%7E1", "%7E1",
                                      SIDECAR_KIND_REGULAR);

    check(restore_entry_physical_leaf_authentic(&ascii),
          "safe ASCII leaf authenticates");
    check(restore_entry_physical_leaf_authentic(&punctuation),
          "punctuation and spaces authenticate through component encoding");
    check(restore_entry_physical_leaf_authentic(&trailing_dot),
          "trailing dot authenticates through its canonical escape");
    check(restore_entry_physical_leaf_authentic(&utf8),
          "valid UTF-8 remains literal in the canonical leaf");
    check(restore_entry_physical_leaf_authentic(&suffixed),
          "canonical collision suffix authenticates through the mapper");

    SidecarEntry tampered = ascii;
    tampered.physical_leaf = text_bytes("file.txT");
    check(!restore_entry_physical_leaf_authentic(&tampered),
          "one-byte physical-leaf tampering is rejected");

    static const unsigned char invalid_utf8_logical[] = { 0xFF };
    SidecarEntry invalid_utf8 = entry_for("x", "%FF", "",
                                          SIDECAR_KIND_REGULAR);
    invalid_utf8.logical_path = (SidecarBytes){
        .data = invalid_utf8_logical,
        .length = sizeof(invalid_utf8_logical)
    };
    check(restore_entry_physical_leaf_authentic(&invalid_utf8),
          "invalid nonzero UTF-8 byte authenticates through %XX encoding");
}

static void build_repeated_escape_leaf(char out[NAME_MAX + 1U],
                                       const char *fingerprint)
{
    size_t offset = 0;
    for (size_t index = 0; index < 78U; index++)
    {
        memcpy(out + offset, "%21", 3U);
        offset += 3U;
    }
    int written = snprintf(out + offset, NAME_MAX + 1U - offset,
                           "%%7EH%s", fingerprint);
    if (written != 20)
        out[0] = '\0';
}

static void test_shortened_leaf_authentication(void)
{
    printf(BLUE "::" NC " shortened physical-leaf authentication\n");

    char logical[NAME_MAX + 1U];
    memset(logical, '!', NAME_MAX);
    logical[NAME_MAX] = '\0';
    char expected[NAME_MAX + 1U];
    build_repeated_escape_leaf(expected, "1B70C7FC136F8DD0");
    SidecarEntry entry = entry_for(logical, expected, "",
                                   SIDECAR_KIND_REGULAR);
    check(strlen(expected) == 254U &&
              restore_entry_physical_leaf_authentic(&entry),
          "hard-coded shortening vector authenticates exactly");

    char bad[NAME_MAX + 1U];
    memcpy(bad, expected, sizeof(bad));
    char *fingerprint = strstr(bad, "%7EH");
    if (fingerprint != NULL)
        fingerprint[4] = fingerprint[4] == '1' ? '2' : '1';
    entry.physical_leaf = text_bytes(bad);
    check(!restore_entry_physical_leaf_authentic(&entry),
          "tampered shortening fingerprint is rejected");

    PortablePhysicalName mapped;
    check(portable_physical_name_map(logical, 1U, &mapped) == 0 &&
              mapped.shortened && strcmp(mapped.collision_suffix, "%7E1") == 0,
          "mapper produces a suffix-bearing shortened vector");
    entry.physical_leaf = text_bytes(mapped.physical_leaf);
    entry.collision_suffix = text_bytes(mapped.collision_suffix);
    check(restore_entry_physical_leaf_authentic(&entry),
          "suffix-bearing shortened leaf authenticates with mapper rebudgeting");
}

static void test_root_and_suffix_semantics(void)
{
    printf(BLUE "::" NC " root and collision-suffix semantics\n");

    SidecarEntry root = entry_for("", "", "", SIDECAR_KIND_REGULAR);
    check(restore_entry_physical_leaf_authentic(&root),
          "root mapping permits a non-directory kind with empty leaf/suffix");
    root.physical_leaf = text_bytes("root");
    check(!restore_entry_physical_leaf_authentic(&root),
          "root with a physical leaf is rejected");
    root.physical_leaf = text_bytes("");
    root.collision_suffix = text_bytes("%7E1");
    check(!restore_entry_physical_leaf_authentic(&root),
          "root with a collision suffix is rejected");

    static const char *invalid_suffixes[] = {
        "%7E0", "%7E01", "%7E+1", "%7E 1", "%7e1", "%7E",
        "%7E18446744073709551616"
    };
    for (size_t index = 0;
         index < sizeof(invalid_suffixes) / sizeof(invalid_suffixes[0]);
         index++)
    {
        SidecarEntry suffix_entry = entry_for(
            "file", "file", invalid_suffixes[index], SIDECAR_KIND_REGULAR);
        check(!restore_entry_physical_leaf_authentic(&suffix_entry),
              "non-canonical collision suffix is rejected");
    }

    PortablePhysicalName large;
    check(portable_physical_name_map("file", UINT64_MAX, &large) == 0,
          "maximum uint64 collision suffix is representable");
    SidecarEntry entry = entry_for("file", large.physical_leaf,
                                   large.collision_suffix,
                                   SIDECAR_KIND_REGULAR);
    check(restore_entry_physical_leaf_authentic(&entry),
          "large canonical collision suffix authenticates");
}

static int build_index(const SidecarEntry *entries, size_t count,
                       RestoreAddressIndex *index, PreflightMemory *memory)
{
    memset(index, 0, sizeof(*index));
    memset(memory, 0, sizeof(*memory));
    return restore_address_index_build_from_entries_for_test(
        index, memory, entries, count);
}

static void test_parent_topology_and_order(void)
{
    printf(BLUE "::" NC " logical-parent topology is iteration-independent\n");

    SidecarEntry missing[] = {
        entry_for("dir/file", "file", "", SIDECAR_KIND_REGULAR)
    };
    RestoreAddressIndex index;
    PreflightMemory memory;
    check(build_index(missing, 1U, &index, &memory) != 0 && memory.bytes == 0,
          "non-root entry without its logical parent is rejected and cleaned up");

    SidecarEntry file_parent[] = {
        entry_for("", "", "", SIDECAR_KIND_DIRECTORY),
        entry_for("dir", "dir", "", SIDECAR_KIND_REGULAR),
        entry_for("dir/file", "file", "", SIDECAR_KIND_REGULAR)
    };
    check(build_index(file_parent, 3U, &index, &memory) != 0 &&
              memory.bytes == 0,
          "child beneath a non-directory logical parent is rejected");

    SidecarEntry reversed[] = {
        entry_for("dir/file", "file", "", SIDECAR_KIND_REGULAR),
        entry_for("dir", "dir", "", SIDECAR_KIND_DIRECTORY),
        entry_for("", "", "", SIDECAR_KIND_DIRECTORY)
    };
    int built = build_index(reversed, 3U, &index, &memory);
    size_t child = SIZE_MAX;
    int found = built == 0 ? restore_address_index_find_logical(
        &index, text_bytes("ROOT"), text_bytes("dir/file"), &child) : -1;
    check(built == 0 && found == 1 && child < index.count,
          "root-directory-child chain succeeds even when vector order is reversed");
    if (built == 0)
        restore_address_index_free(&memory, &index);
    check(memory.bytes == 0, "successful index teardown releases its full budget");
}

static void make_long_collision_names(char first[NAME_MAX + 1U],
                                      char second[NAME_MAX + 1U])
{
    memset(first, '!', NAME_MAX);
    memset(second, '!', NAME_MAX);
    first[NAME_MAX] = '\0';
    second[NAME_MAX] = '\0';
    second[NAME_MAX - 1U] = '#';
}

static void test_physical_sibling_uniqueness(void)
{
    printf(BLUE "::" NC " physical sibling ownership is parent-local\n");

    char first[NAME_MAX + 1U], second[NAME_MAX + 1U];
    make_long_collision_names(first, second);
    const uint64_t fingerprint = UINT64_C(0x0123456789ABCDEF);
    PortablePhysicalName first_mapped, second_mapped;
    check(portable_physical_name_map_with_fingerprint_for_test(
              first, 0, fingerprint, &first_mapped) == 0 &&
              portable_physical_name_map_with_fingerprint_for_test(
                  second, 0, fingerprint, &second_mapped) == 0 &&
              strcmp(first_mapped.physical_leaf,
                     second_mapped.physical_leaf) == 0,
          "forced fingerprint creates two individually canonical equal candidates");

    char first_under_a[PATH_MAX], second_under_a[PATH_MAX];
    char first_under_b[PATH_MAX];
    snprintf(first_under_a, sizeof(first_under_a), "A/%s", first);
    snprintf(second_under_a, sizeof(second_under_a), "A/%s", second);
    snprintf(first_under_b, sizeof(first_under_b), "B/%s", first);

    SidecarEntry same_parent[] = {
        entry_for("", "", "", SIDECAR_KIND_DIRECTORY),
        entry_for("A", "A", "", SIDECAR_KIND_DIRECTORY),
        entry_for(first_under_a, first_mapped.physical_leaf, "",
                  SIDECAR_KIND_REGULAR),
        entry_for(second_under_a, second_mapped.physical_leaf, "",
                  SIDECAR_KIND_REGULAR)
    };
    restore_address_test_force_name_fingerprint(fingerprint);
    RestoreAddressIndex index;
    PreflightMemory memory;
    check(build_index(same_parent, 4U, &index, &memory) != 0 &&
              memory.bytes == 0,
          "equal canonical physical leaves under one parent are rejected");

    SidecarEntry same_parent_reversed[] = {
        same_parent[3], same_parent[2], same_parent[1], same_parent[0]
    };
    check(build_index(same_parent_reversed, 4U, &index, &memory) != 0 &&
              memory.bytes == 0,
          "sibling ambiguity remains rejected when vector order is reversed");

    SidecarEntry different_parents[] = {
        entry_for(first_under_a, first_mapped.physical_leaf, "",
                  SIDECAR_KIND_REGULAR),
        entry_for(first_under_b, first_mapped.physical_leaf, "",
                  SIDECAR_KIND_REGULAR),
        entry_for("B", "B", "", SIDECAR_KIND_DIRECTORY),
        entry_for("A", "A", "", SIDECAR_KIND_DIRECTORY),
        entry_for("", "", "", SIDECAR_KIND_DIRECTORY)
    };
    int built = build_index(different_parents, 5U, &index, &memory);
    check(built == 0,
          "the same physical leaf may be reused beneath different logical parents");
    if (built == 0)
        restore_address_index_free(&memory, &index);
    check(memory.bytes == 0, "parent-local uniqueness test releases index storage");
    restore_address_test_clear_name_fingerprint();
}

static void test_invalid_vector_input(void)
{
    RestoreAddressIndex index = {0};
    PreflightMemory memory = {0};
    errno = 0;
    check(restore_address_index_build_from_entries_for_test(
              &index, &memory, NULL, 1U) != 0 && errno == EINVAL &&
              memory.bytes == 0,
          "invalid vector input fails without allocating index state");
}

static DestinationIdentityStatus add_destination_name(
    DestinationIdentityGraph *graph, int anchor_fd, const char *name,
    size_t owner, DestinationIdentityNameConflict *name_conflict)
{
    DestinationIdentityPlacement placement;
    size_t conflicting_owner;
    return destination_identity_graph_add(
        graph, anchor_fd, name, DESTINATION_IDENTITY_NON_DIRECTORY, owner,
        &placement, &conflicting_owner, name_conflict);
}

static void test_destination_casefold_index(void)
{
    printf(BLUE "::" NC " destination casefold lookup is folded-name indexed\n");

    char directory[] = "/tmp/migr_restore_identity_index_XXXXXX";
    char *created = mkdtemp(directory);
    check(created != NULL, "casefold-index fixture directory is created");
    if (created == NULL)
        return;

    int anchor_fd = open(created, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(anchor_fd >= 0, "casefold-index fixture directory opens as an anchor");
    if (anchor_fd < 0)
    {
        rmdir(created);
        return;
    }

    DestinationIdentityGraph graph;
    destination_identity_graph_init(&graph, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    DestinationIdentityStatus registered =
        destination_identity_graph_register_anchor(&graph, anchor_fd);
    check(registered == DESTINATION_IDENTITY_OK,
          "casefold-index graph registers its destination ancestry");
    if (registered != DESTINATION_IDENTITY_OK)
    {
        destination_identity_graph_free(&graph);
        close(anchor_fd);
        rmdir(created);
        return;
    }

    enum { UNIQUE_NAMES = 4096 };
    destination_identity_test_reset_name_probe_count();
    int unique_ok = 1;
    for (size_t index = 0; index < UNIQUE_NAMES; index++)
    {
        char name[32];
        int written = snprintf(name, sizeof(name), "item-%04zu", index);
        DestinationIdentityNameConflict conflict;
        if (written <= 0 || (size_t)written >= sizeof(name) ||
            add_destination_name(&graph, anchor_fd, name, index + 1U,
                                 &conflict) != DESTINATION_IDENTITY_OK)
        {
            unique_ok = 0;
            break;
        }
    }

    DestinationIdentityNameConflict conflict;
    int first_ok = add_destination_name(
        &graph, anchor_fd, "FoldTarget", UNIQUE_NAMES + 1U, &conflict) ==
        DESTINATION_IDENTITY_OK;
    destination_identity_test_force_casefold(1);
    DestinationIdentityStatus folded_status = add_destination_name(
        &graph, anchor_fd, "foldtarget", UNIQUE_NAMES + 2U, &conflict);
    destination_identity_test_force_casefold(0);
    size_t probes = destination_identity_test_name_probe_count();

    check(unique_ok && first_ok &&
              folded_status == DESTINATION_IDENTITY_NAME_EQUIVALENCE_ERROR &&
              conflict.failure == DESTINATION_NAME_FAILURE_CASEFOLD &&
              conflict.prior_component != NULL &&
              conflict.prior_component_length == strlen("FoldTarget") &&
              memcmp(conflict.prior_component, "FoldTarget",
                     conflict.prior_component_length) == 0,
          "folded-name index still identifies the real ASCII-case sibling conflict");
    check(probes <= UNIQUE_NAMES + 4U,
          "casefold conflict lookup examines only folded-name bucket members");

    int upper_fd = openat(anchor_fd, "Existing", O_WRONLY | O_CREAT | O_EXCL |
                                              O_CLOEXEC,
                          0600);
    int lower_fd = openat(anchor_fd, "existing", O_WRONLY | O_CREAT | O_EXCL |
                                              O_CLOEXEC,
                          0600);
    int existing_fixture_ok = upper_fd >= 0 && lower_fd >= 0;
    if (upper_fd >= 0)
        close(upper_fd);
    if (lower_fd >= 0)
        close(lower_fd);

    DestinationIdentityStatus upper_status = DESTINATION_IDENTITY_PATH_ERROR;
    DestinationIdentityStatus lower_status = DESTINATION_IDENTITY_PATH_ERROR;
    if (existing_fixture_ok)
    {
        destination_identity_test_force_casefold(1);
        upper_status = add_destination_name(
            &graph, anchor_fd, "Existing", UNIQUE_NAMES + 3U, &conflict);
        lower_status = add_destination_name(
            &graph, anchor_fd, "existing", UNIQUE_NAMES + 4U, &conflict);
        destination_identity_test_force_casefold(0);
    }
    check(existing_fixture_ok && upper_status == DESTINATION_IDENTITY_OK &&
              lower_status == DESTINATION_IDENTITY_OK,
          "two already-existing case variants retain the existing pair-skip semantics");

    destination_identity_test_force_casefold(0);
    destination_identity_graph_free(&graph);
    if (upper_fd >= 0)
        unlinkat(anchor_fd, "Existing", 0);
    if (lower_fd >= 0)
        unlinkat(anchor_fd, "existing", 0);
    check(close(anchor_fd) == 0, "casefold-index anchor closes cleanly");
    check(rmdir(created) == 0, "casefold-index fixture directory is removed");
}

int main(void)
{
    test_ordinary_leaf_authentication();
    test_shortened_leaf_authentication();
    test_root_and_suffix_semantics();
    test_parent_topology_and_order();
    test_physical_sibling_uniqueness();
    test_invalid_vector_input();
    test_destination_casefold_index();

    if (failures != 0)
        printf(RED "portable restore invariant failed: %d assertion(s)\n" NC,
               failures);
    else
        printf(GREEN "portable restore invariant passed\n" NC);
    return failures == 0 ? 0 : 1;
}
