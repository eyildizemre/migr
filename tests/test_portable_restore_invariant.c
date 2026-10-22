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
#include "xdg.h"

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

static DestinationIdentityStatus add_destination_path(
    DestinationIdentityGraph *graph, int anchor_fd, const char *path,
    DestinationIdentityClaim kind, size_t owner, size_t *conflicting_owner)
{
    DestinationIdentityPlacement placement;
    DestinationIdentityNameConflict name_conflict;
    *conflicting_owner = SIZE_MAX;
    errno = 0;
    return destination_identity_graph_add(graph, anchor_fd, path, kind, owner,
                                          &placement, conflicting_owner,
                                          &name_conflict);
}

static void test_destination_identity_collisions(void)
{
    printf(BLUE "::" NC " destination identity collisions\n");

    enum { EXISTING_FOLDERS = 40 };
    char directory[] = "/tmp/migr_restore_identity_collide_XXXXXX";
    char *created = mkdtemp(directory);
    check(created != NULL, "collision fixture directory is created");
    if (created == NULL)
        return;
    int anchor_fd = open(created, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int folders_ok = anchor_fd >= 0;
    for (int i = 0; folders_ok && i < EXISTING_FOLDERS; i++)
    {
        char name[16];
        snprintf(name, sizeof(name), "d%02d", i);
        folders_ok = mkdirat(anchor_fd, name, 0700) == 0;
    }
    check(folders_ok, "collision fixture folders are created");

    DestinationIdentityGraph graph;
    destination_identity_graph_init(&graph, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    size_t conflicting = SIZE_MAX;
    DestinationIdentityStatus folder = add_destination_path(
        &graph, anchor_fd, "kept", DESTINATION_IDENTITY_DIRECTORY, 1,
        &conflicting);
    DestinationIdentityStatus inner = add_destination_path(
        &graph, anchor_fd, "kept/inner", DESTINATION_IDENTITY_NON_DIRECTORY, 2,
        &conflicting);
    DestinationIdentityStatus file = add_destination_path(
        &graph, anchor_fd, "kept", DESTINATION_IDENTITY_NON_DIRECTORY, 3,
        &conflicting);
    check(folder == DESTINATION_IDENTITY_OK &&
              inner == DESTINATION_IDENTITY_OK &&
              file == DESTINATION_IDENTITY_COLLISION && errno == EEXIST &&
              conflicting == 1,
          "a file is refused where another entry restores a folder");

    // Every existing folder is one more node, enough to grow the tables
    // that find a folder again by its identity.
    int added_ok = folders_ok;
    for (int i = 0; added_ok && i < EXISTING_FOLDERS; i++)
    {
        char path[16];
        snprintf(path, sizeof(path), "d%02d/f", i);
        added_ok = add_destination_path(
                       &graph, anchor_fd, path,
                       DESTINATION_IDENTITY_NON_DIRECTORY, 10U + (size_t)i,
                       &conflicting) == DESTINATION_IDENTITY_OK;
    }
    DestinationIdentityStatus again = add_destination_path(
        &graph, anchor_fd, "d07/f", DESTINATION_IDENTITY_NON_DIRECTORY, 100,
        &conflicting);
    check(added_ok && again == DESTINATION_IDENTITY_COLLISION &&
              conflicting == 17 &&
              destination_identity_graph_finalize(&graph) ==
                  DESTINATION_IDENTITY_OK,
          "after the tables grow, a file restored twice is still refused");

    destination_identity_graph_free(&graph);
    for (int i = 0; anchor_fd >= 0 && i < EXISTING_FOLDERS; i++)
    {
        char name[16];
        snprintf(name, sizeof(name), "d%02d", i);
        unlinkat(anchor_fd, name, AT_REMOVEDIR);
    }
    if (anchor_fd >= 0)
        close(anchor_fd);
    check(rmdir(created) == 0, "collision fixture directory is removed");
}

static void test_shared_helpers_refuse_missing_arguments(void)
{
    PreflightMemory memory = {0};
    size_t capacity = 0;
    size_t index = 0;
    SidecarBytes name = { (const unsigned char *)"a", 1 };
    check(preflight_alloc(NULL, 1) == NULL &&
              preflight_realloc(NULL, NULL, 0, 1) == NULL &&
              preflight_array_reserve(NULL, NULL, &capacity, 0, 1, 1, 1, 1,
                                      0) == NULL &&
              preflight_array_reserve(&memory, NULL, NULL, 0, 1, 1, 1, 1,
                                      0) == NULL,
          "the preflight allocator needs its memory and capacity");
    check(!relative_path_valid(NULL, 1) && !manifest_text_valid(NULL, 4, 0) &&
              !restore_entry_physical_leaf_authentic(NULL) &&
              xdg_key_index(NULL) < 0,
          "the shared validators refuse a missing text or entry");

    RootMap map = {0};
    Manifest manifest = {0};
    root_map_free(NULL);
    check(root_map_build(NULL, &manifest) != 0 &&
              root_map_build(&map, NULL) != 0 &&
              root_map_find(NULL, &manifest, name) == SIZE_MAX &&
              root_map_find(&map, NULL, name) == SIZE_MAX,
          "a root map refuses a missing map or manifest");

    RestoreAddressIndex address = {0};
    restore_address_index_free(&memory, NULL);
    check(restore_address_index_find_logical(NULL, name, name, &index) == 0 &&
              restore_address_index_find_physical(NULL, name, name, name,
                                                  &index) == 0,
          "a missing address index finds nothing");
    check(restore_address_index_find_logical(&address, name, name,
                                             NULL) < 0 &&
              restore_address_index_find_physical(&address, name, name, name,
                                                  NULL) < 0 &&
              restore_address_index_entry_valid(&address, NULL, &index) < 0 &&
              restore_address_index_build(NULL, &memory, NULL, NULL) != 0,
          "an address index refuses a missing entry, output, or journal");

    ManifestRoot root = {0};
    char out[PATH_MAX];
    int fd = -1;
    check(!xdg_destination_valid(NULL, &root) &&
              destination_path_build(NULL, "a", NULL, out, sizeof(out)) != 0 &&
              destination_path_build(&root, NULL, NULL, out, sizeof(out)) != 0 &&
              destination_path_build(&root, "a", NULL, NULL, 0) != 0 &&
              destination_relative_path_build(NULL, "a", out, sizeof(out)) != 0 &&
              destination_relative_path_build("p", NULL, out, sizeof(out)) != 0 &&
              destination_relative_path_build("p", "a", NULL, 0) != 0 &&
              destination_absolute_path_build(&root, "a", NULL, NULL, out,
                                              sizeof(out)) != 0 &&
              open_xdg_destination_anchor(NULL, &fd, out, sizeof(out)) != 0 &&
              open_xdg_destination_anchor("/", NULL, out, sizeof(out)) != 0 &&
              open_xdg_destination_anchor("/", &fd, NULL, 0) != 0,
          "the destination path builders refuse a missing root, path, or "
          "buffer");
    check(sidecar_kind_to_type(SIDECAR_KIND_REGULAR, NULL) != 0 &&
              destination_symlink_target_matches(-1, NULL, name) < 0 &&
              payload_unrecorded_scan(-1, NULL, &address, NULL, NULL) != 0 &&
              payload_unrecorded_scan(-1, &manifest, NULL, NULL, NULL) != 0,
          "the payload and link checks refuse a missing argument");

    DestinationIdentityGraph graph;
    destination_identity_graph_init(NULL, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    destination_identity_graph_free(NULL);
    destination_identity_graph_init(&graph, DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    DestinationIdentityPlacement placement;
    size_t owner = 0;
    DestinationIdentityNameConflict conflict;
    int refused =
        destination_identity_graph_register_anchor(NULL, 0) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(NULL, 0, "a",
                                       DESTINATION_IDENTITY_DIRECTORY, 0,
                                       &placement, &owner, &conflict) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, -1, "a",
                                       DESTINATION_IDENTITY_DIRECTORY, 0,
                                       &placement, &owner, &conflict) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, 0, NULL,
                                       DESTINATION_IDENTITY_DIRECTORY, 0,
                                       &placement, &owner, &conflict) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, 0, "a",
                                       DESTINATION_IDENTITY_DIRECTORY, 0,
                                       NULL, &owner, &conflict) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, 0, "a",
                                       DESTINATION_IDENTITY_DIRECTORY, 0,
                                       &placement, NULL, &conflict) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, 0, "a",
                                       DESTINATION_IDENTITY_DIRECTORY, 0,
                                       &placement, &owner, NULL) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, 0, "a",
                                       DESTINATION_IDENTITY_DIRECTORY,
                                       SIZE_MAX, &placement, &owner,
                                       &conflict) != DESTINATION_IDENTITY_OK &&
        destination_identity_graph_add(&graph, 0, "a",
                                       (DestinationIdentityClaim)9, 0,
                                       &placement, &owner, &conflict) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_finalize(NULL) != DESTINATION_IDENTITY_OK &&
        destination_identity_graph_order(NULL, &placement, &index) != 0 &&
        destination_identity_graph_order(&graph, NULL, &index) != 0 &&
        destination_identity_graph_order(&graph, &placement, NULL) != 0;
    destination_identity_graph_free(&graph);
    check(refused, "the destination graph refuses a missing graph, path, "
                   "output, owner, or claim");
}

static void read_no_entry(void *context, size_t index,
                          DestinationIdentityEntryView *view)
{
    (void)context;
    (void)index;
    (void)view;
}

static void report_no_failure(void *context, size_t index)
{
    (void)context;
    (void)index;
}

static int report_no_node(void *context, int parent_fd, const char *name,
                          const char *path, const ManifestRoot *root,
                          const SidecarEntry *parent)
{
    (void)context;
    (void)parent_fd;
    (void)name;
    (void)path;
    (void)root;
    (void)parent;
    return 0;
}

static void test_shared_helpers_refuse_bad_arguments(void)
{
    printf(BLUE "::" NC " shared restore helpers refuse each bad argument\n");

    PreflightMemory memory = {0};
    PreflightMemory spent = { .bytes = SIDECAR_MAX_ALLOC_BUDGET };
    PreflightMemory overspent = { .bytes = SIDECAR_MAX_ALLOC_BUDGET + 1U };
    check(preflight_alloc(&memory, 0) == NULL &&
              preflight_alloc(&spent, 1) == NULL &&
              preflight_alloc(&overspent, 1) == NULL,
          "the preflight allocator refuses nothing to allocate, and past "
          "its budget");
    check(preflight_realloc(&memory, NULL, 0, 0) == NULL &&
              preflight_realloc(&memory, NULL, 8, 4) == NULL &&
              preflight_realloc(&spent, NULL, 0, 1) == NULL &&
              preflight_realloc(&overspent, NULL, 0, 1) == NULL,
          "growing refuses a zero or smaller size, and past the budget");
    PreflightMemory counted = { .bytes = 4 };
    preflight_free(NULL, malloc(1), 1);
    preflight_free(&counted, malloc(8), 8);
    check(counted.bytes == 4,
          "freeing more than was counted leaves the count alone");

    size_t capacity = 0;
    int reserve_refused =
        preflight_array_reserve(&memory, NULL, &capacity, 0, 0, 1, 1, 1,
                                0) == NULL &&
        preflight_array_reserve(&memory, NULL, &capacity, 0, 1, 0, 1, 1,
                                0) == NULL &&
        preflight_array_reserve(&memory, NULL, &capacity, 0, 1, 1, 0, 1,
                                0) == NULL &&
        preflight_array_reserve(&memory, NULL, &capacity, 0, 1, 1, 1, 0,
                                0) == NULL &&
        preflight_array_reserve(&memory, NULL, &capacity, 3, 1, 1, 1, 2,
                                0) == NULL &&
        preflight_array_reserve(&memory, NULL, &capacity, 1, 2, 1, 1, 2,
                                0) == NULL;
    capacity = SIZE_MAX / 2U + 1U;
    reserve_refused = reserve_refused &&
        preflight_array_reserve(&memory, NULL, &capacity, capacity, 1, 2, 1,
                                SIZE_MAX, 0) == NULL && errno == E2BIG;
    check(reserve_refused,
          "reserving refuses a zero size or limit, a count past the limit, "
          "and a size that overflows");
    capacity = 1;
    unsigned char *items = preflight_array_reserve(&memory, NULL, &capacity,
                                                   1, 5, 1, 1, 64, 1);
    check(items != NULL && capacity == 6,
          "reserving takes what is needed when doubling is not enough");
    unsigned char *grown = preflight_array_reserve(&memory, items, &capacity,
                                                   6, 1, 1, 1, 7, 1);
    check(grown != NULL && capacity == 7,
          "reserving stops at the limit rather than doubling past it");
    preflight_free(&memory, grown != NULL ? grown : items, capacity);

    char text[] = "a";
    SidecarBytes missing = { NULL, 1 };
    SidecarBytes name = { (const unsigned char *)"a", 1 };
    SidecarBytes empty = { (const unsigned char *)"", 0 };
    SidecarBytes dotdot = { (const unsigned char *)"..", 2 };
    char long_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 2U];
    memset(long_leaf, 'a', sizeof(long_leaf) - 1U);
    long_leaf[sizeof(long_leaf) - 1U] = '\0';
    SidecarBytes overlong = { (const unsigned char *)long_leaf,
                              SIDECAR_MAX_PHYSICAL_LEAF + 1U };
    SidecarEntry bad_path = { .logical_path = dotdot, .physical_leaf = name };
    SidecarEntry bad_leaf = { .logical_path = name, .physical_leaf = dotdot };
    check(!manifest_text_valid(text, 0, 0) && !sidecar_path_valid(missing, 1) &&
              !restore_entry_physical_leaf_authentic(&bad_path) &&
              !restore_entry_physical_leaf_authentic(&bad_leaf),
          "the validators refuse no room, a missing path, and a bad path or "
          "leaf");

    RootMap map = {0};
    ManifestRoot one_root = {0};
    Manifest negative = { .root_count = -1 };
    Manifest too_many = { .root_count = MANIFEST_MAX_ROOTS + 1 };
    Manifest no_roots = { .root_count = 1 };
    Manifest manifest = { .root_count = 1, .roots = &one_root };
    check(root_map_build(&map, &negative) != 0 &&
              root_map_build(&map, &too_many) != 0 &&
              root_map_build(&map, &no_roots) != 0,
          "a root map refuses a root count out of range or without roots");
    check(root_map_find(&map, &manifest, name) == SIZE_MAX,
          "an empty root map finds nothing");
    strcpy(one_root.id, "ROOT");
    check(root_map_build(&map, &manifest) == 0 &&
              root_map_find(&map, &manifest, empty) == SIZE_MAX &&
              root_map_find(&map, &manifest, missing) == SIZE_MAX,
          "a root map finds no root for an empty or missing id");
    root_map_free(&map);

    RestoreAddressIndex address = {0};
    size_t index = 0;
    check(restore_address_index_find_logical(&address, empty, name,
                                             &index) < 0 &&
              restore_address_index_find_logical(&address, name, dotdot,
                                                 &index) < 0 &&
              restore_address_index_find_logical(&address, name, name,
                                                 &index) == 0 &&
              index == SIZE_MAX,
          "a logical lookup refuses a bad root id or path, and an empty "
          "index finds nothing");
    check(restore_address_index_find_physical(&address, empty, empty, name,
                                              &index) < 0 &&
              restore_address_index_find_physical(&address, name, dotdot,
                                                  name, &index) < 0 &&
              restore_address_index_find_physical(&address, name, empty,
                                                  empty, &index) < 0 &&
              restore_address_index_find_physical(&address, name, empty,
                                                  overlong, &index) < 0 &&
              restore_address_index_find_physical(&address, name, empty,
                                                  missing, &index) < 0 &&
              restore_address_index_find_physical(&address, name, empty,
                                                  dotdot, &index) < 0 &&
              restore_address_index_find_physical(&address, name, empty,
                                                  name, &index) == 0 &&
              index == SIZE_MAX,
          "a physical lookup refuses each bad part of an address, and an "
          "empty index finds nothing");
    SidecarLog sidecar = {0};
    check(restore_address_index_entry_valid(&address, &bad_path, NULL) < 0 &&
              restore_address_index_build(&address, NULL, &sidecar, NULL) != 0 &&
              restore_address_index_build(&address, &memory, NULL, NULL) != 0 &&
              restore_address_index_build_from_entries_for_test(
                  NULL, &memory, NULL, 0) != 0 &&
              restore_address_index_build_from_entries_for_test(
                  &address, NULL, NULL, 0) != 0 &&
              restore_address_index_build_from_entries_for_test(
                  &address, &memory, NULL, 1) != 0,
          "an address index refuses a missing output, memory, or journal");

    const char *xdg_dirs[XDG_KEY_COUNT] = {0};
    char out[PATH_MAX];
    char long_home[PATH_MAX + 1];
    memset(long_home, 'a', sizeof(long_home) - 1U);
    long_home[0] = '/';
    long_home[sizeof(long_home) - 1U] = '\0';
    int fd = -1;
    check(!xdg_destination_valid(NULL, &one_root) &&
              destination_path_build(&one_root, "a", NULL, out, 0) != 0 &&
              destination_absolute_path_build(&one_root, "a", NULL, "home",
                                              out, sizeof(out)) != 0 &&
              destination_absolute_path_build(&one_root, "a", NULL,
                                              long_home, out,
                                              sizeof(out)) != 0 &&
              destination_relative_path_build("p", "a", out, 0) != 0 &&
              open_xdg_destination_anchor("/", &fd, out, 0) != 0 &&
              open_xdg_destination_anchor("tmp", &fd, out,
                                          sizeof(out)) != 0 &&
              open_xdg_destination_anchor(long_home, &fd, out,
                                          sizeof(out)) != 0,
          "the destination path builders refuse no room, a relative home, "
          "and a home past PATH_MAX");

    int anchor_fd = -1;
    char prefix[PATH_MAX];
    char relative[PATH_MAX];
    int route_refused =
        destination_identity_route(NULL, 0, "a", 0, xdg_dirs, &anchor_fd,
                                   &prefix, &fd, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, NULL, 0, xdg_dirs,
                                   &anchor_fd, &prefix, &fd, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", -1, xdg_dirs,
                                   &anchor_fd, &prefix, &fd, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", 0, NULL, &anchor_fd,
                                   &prefix, &fd, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", 0, xdg_dirs, NULL,
                                   &prefix, &fd, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", 0, xdg_dirs,
                                   &anchor_fd, NULL, &fd, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", 0, xdg_dirs,
                                   &anchor_fd, &prefix, NULL, relative,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", 0, xdg_dirs,
                                   &anchor_fd, &prefix, &fd, NULL,
                                   sizeof(relative)) != 0 &&
        destination_identity_route(&manifest, 0, "a", 0, xdg_dirs,
                                   &anchor_fd, &prefix, &fd, relative,
                                   0) != 0 &&
        destination_identity_route(&manifest, 1, "a", 0, xdg_dirs,
                                   &anchor_fd, &prefix, &fd, relative,
                                   sizeof(relative)) != 0;
    check(route_refused,
          "routing a destination refuses each missing argument and a root "
          "past the manifest's");

    DestinationIdentityGraph graph;
    destination_identity_graph_init(&graph,
                                    DESTINATION_IDENTITY_PORTABLE_BOUNDS);
    DestinationIdentityPlacement placement = { .node = 0 };
    size_t owner = 0;
    char marker = 0;
    int entries_refused =
        destination_identity_graph_register_anchor(&graph, -1) !=
            DESTINATION_IDENTITY_OK &&
        destination_identity_graph_order(&graph, &placement, &index) != 0;
    DestinationIdentityCollisionPolicy aggregate =
        DESTINATION_IDENTITY_AGGREGATE_COLLISIONS;
    const struct {
        DestinationIdentityGraph *graph;
        const Manifest *manifest;
        int home_fd;
        const char *const *xdg;
        int *anchor;
        char (*prefix)[PATH_MAX];
        DestinationIdentityEntryReader reader;
        DestinationIdentityFailureReporter report;
        void *context;
        DestinationIdentityCollisionPolicy policy;
    } bad_entries[] = {
        { NULL, &manifest, 0, xdg_dirs, &anchor_fd, &prefix, read_no_entry,
          report_no_failure, &marker, aggregate },
        { &graph, NULL, 0, xdg_dirs, &anchor_fd, &prefix, read_no_entry,
          report_no_failure, &marker, aggregate },
        { &graph, &manifest, -1, xdg_dirs, &anchor_fd, &prefix,
          read_no_entry, report_no_failure, &marker, aggregate },
        { &graph, &manifest, 0, NULL, &anchor_fd, &prefix, read_no_entry,
          report_no_failure, &marker, aggregate },
        { &graph, &manifest, 0, xdg_dirs, NULL, &prefix, read_no_entry,
          report_no_failure, &marker, aggregate },
        { &graph, &manifest, 0, xdg_dirs, &anchor_fd, NULL, read_no_entry,
          report_no_failure, &marker, aggregate },
        { &graph, &manifest, 0, xdg_dirs, &anchor_fd, &prefix, NULL,
          report_no_failure, &marker, aggregate },
        { &graph, &manifest, 0, xdg_dirs, &anchor_fd, &prefix,
          read_no_entry, NULL, &marker, aggregate },
        { &graph, &manifest, 0, xdg_dirs, &anchor_fd, &prefix,
          read_no_entry, report_no_failure, NULL, aggregate },
        { &graph, &manifest, 0, xdg_dirs, &anchor_fd, &prefix,
          read_no_entry, report_no_failure, &marker,
          (DestinationIdentityCollisionPolicy)9 },
    };
    for (size_t i = 0; i < sizeof(bad_entries) / sizeof(bad_entries[0]); i++)
        entries_refused = entries_refused &&
            destination_identity_graph_add_entries(
                bad_entries[i].graph, bad_entries[i].manifest, 0,
                bad_entries[i].home_fd, "/", bad_entries[i].xdg,
                bad_entries[i].anchor, bad_entries[i].prefix,
                bad_entries[i].reader, bad_entries[i].report, NULL,
                bad_entries[i].context, bad_entries[i].policy) != 0;
    check(entries_refused,
          "the destination graph refuses each missing argument, a bad "
          "policy, and an order before it is finalized");

    DestinationIdentityNameConflict conflict;
    int finalized =
        destination_identity_graph_finalize(&graph) == DESTINATION_IDENTITY_OK;
    placement.node = graph.node_count;
    check(finalized &&
              destination_identity_graph_finalize(&graph) !=
                  DESTINATION_IDENTITY_OK &&
              destination_identity_graph_register_anchor(&graph, 0) !=
                  DESTINATION_IDENTITY_OK &&
              destination_identity_graph_add(
                  &graph, 0, "a", DESTINATION_IDENTITY_DIRECTORY, 0,
                  &placement, &owner, &conflict) != DESTINATION_IDENTITY_OK &&
              destination_identity_graph_add_entries(
                  &graph, &manifest, 0, 0, "/", xdg_dirs, &anchor_fd, &prefix,
                  read_no_entry, report_no_failure, NULL, &marker,
                  aggregate) != 0 &&
              destination_identity_graph_order(&graph, &placement,
                                               &index) != 0,
          "a finalized graph takes nothing more and orders no node it "
          "lacks");
    destination_identity_graph_free(&graph);

    check(destination_symlink_target_matches(-1, "a", missing) < 0 &&
              payload_unrecorded_scan(-1, &manifest, &address, report_no_node,
                                      NULL) != 0 &&
              payload_unrecorded_scan(0, &manifest, NULL, report_no_node,
                                      NULL) != 0 &&
              payload_unrecorded_scan(0, &manifest, &address, NULL,
                                      NULL) != 0,
          "the link and payload checks refuse a missing target, folder, "
          "index, or report");
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
    test_destination_identity_collisions();
    test_shared_helpers_refuse_missing_arguments();
    test_shared_helpers_refuse_bad_arguments();

    if (failures != 0)
        printf(RED "portable restore invariant failed: %d assertion(s)\n" NC,
               failures);
    else
        printf(GREEN "portable restore invariant passed\n" NC);
    return failures == 0 ? 0 : 1;
}
