#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "portable_hashset_internal.h"
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

/* A table can report "full" (_locate returns -1) even though its own count
 * field says there is still room, if a future caller path ever bypasses the
 * normal insert helper or the load-factor check ever drifts by one. These
 * helpers force exactly that desynced state directly through the struct
 * (visible to this file via portable_hashset_internal.h) so the discovery
 * path never depends on actually reaching SIDECAR_MAX_LIVE_ENTRIES real
 * entries. */

static void fill_visited_slots_without_counting(PortableVisited *visited,
                                                 size_t capacity)
{
    visited->slots = calloc(capacity, sizeof(*visited->slots));
    visited->capacity = capacity;
    visited->count = 0;
    for (size_t i = 0; i < capacity; i++)
    {
        visited->slots[i].root_id = malloc(1);
        visited->slots[i].root_id[0] = '\0';
        visited->slots[i].logical_path = malloc(1);
        visited->slots[i].logical_path[0] = '\0';
    }
}

static void fill_prescan_inode_slots_without_counting(PrescanInodeSet *set,
                                                       size_t capacity)
{
    set->slots = calloc(capacity, sizeof(*set->slots));
    set->capacity = capacity;
    set->count = 0;
    for (size_t i = 0; i < capacity; i++)
        set->slots[i].used = 1;
}

static void fill_inode_map_slots_without_counting(PortableInodeMap *map,
                                                   size_t capacity)
{
    map->slots = calloc(capacity, sizeof(*map->slots));
    map->capacity = capacity;
    map->count = 0;
    for (size_t i = 0; i < capacity; i++)
    {
        map->slots[i].root_id = malloc(1);
        map->slots[i].root_id[0] = '\0';
        map->slots[i].logical_path = malloc(1);
        map->slots[i].logical_path[0] = '\0';
    }
}

static void test_visited_basic_insert_and_duplicate(void)
{
    PortableVisited visited = {0};
    check(visited_add(&visited, "root", "a/b") == 0,
          "visited_add inserts a new entry");
    check(visited_add(&visited, "root", "a/b") == 1,
          "visited_add reports a duplicate instead of reinserting");
    check(visited_contains(&visited, "root", "a/b") == 1,
          "visited_contains finds the inserted entry");
    visited_dispose(&visited);
}

static void test_visited_recovers_from_full_locate(void)
{
    PortableVisited visited = {0};
    fill_visited_slots_without_counting(&visited, VISITED_INITIAL_CAPACITY);

    int rc = visited_add(&visited, "root", "new/entry");
    check(rc == 0,
          "visited_add grows the table instead of failing when _locate "
          "reports full but count says there is room");
    check(visited.capacity > VISITED_INITIAL_CAPACITY,
          "visited_add actually grew the table's capacity");
    check(visited_contains(&visited, "root", "new/entry") == 1,
          "the recovered entry is actually findable afterward");

    visited_dispose(&visited);
}

static void test_visited_length_bound(void)
{
    char root_at_ceiling[SIDECAR_MAX_ROOT_ID + 1];
    memset(root_at_ceiling, 'r', SIDECAR_MAX_ROOT_ID);
    root_at_ceiling[SIDECAR_MAX_ROOT_ID] = '\0';

    char root_over_ceiling[SIDECAR_MAX_ROOT_ID + 2];
    memset(root_over_ceiling, 'r', SIDECAR_MAX_ROOT_ID + 1U);
    root_over_ceiling[SIDECAR_MAX_ROOT_ID + 1U] = '\0';

    char logical_at_ceiling[SIDECAR_MAX_PATH + 1];
    memset(logical_at_ceiling, 'l', SIDECAR_MAX_PATH);
    logical_at_ceiling[SIDECAR_MAX_PATH] = '\0';

    char logical_over_ceiling[SIDECAR_MAX_PATH + 2];
    memset(logical_over_ceiling, 'l', SIDECAR_MAX_PATH + 1U);
    logical_over_ceiling[SIDECAR_MAX_PATH + 1U] = '\0';

    PortableVisited visited = {0};
    check(visited_add(&visited, root_at_ceiling, "ok") == 0,
          "visited_add accepts a root_id exactly at SIDECAR_MAX_ROOT_ID");
    check(visited_add(&visited, "root", logical_at_ceiling) == 0,
          "visited_add accepts a logical path exactly at SIDECAR_MAX_PATH");
    check(visited_add(&visited, root_over_ceiling, "ok") == -1,
          "visited_add rejects a root_id one byte over SIDECAR_MAX_ROOT_ID, "
          "matching inode_map_find_or_insert's identical bound");
    check(visited_add(&visited, "root", logical_over_ceiling) == -1,
          "visited_add rejects a logical path one byte over SIDECAR_MAX_PATH, "
          "matching inode_map_find_or_insert's identical bound");
    visited_dispose(&visited);
}

static void test_prescan_inode_set_basic_insert_and_duplicate(void)
{
    PrescanInodeSet set = {0};
    check(prescan_inode_set_find_or_insert(&set, 1, 100) == 0,
          "prescan_inode_set_find_or_insert inserts a new inode");
    check(prescan_inode_set_find_or_insert(&set, 1, 100) == 1,
          "prescan_inode_set_find_or_insert reports a duplicate");
    free(set.slots);
}

static void test_prescan_inode_set_recovers_from_full_locate(void)
{
    PrescanInodeSet set = {0};
    fill_prescan_inode_slots_without_counting(&set, VISITED_INITIAL_CAPACITY);

    int rc = prescan_inode_set_find_or_insert(&set, 1, 999);
    check(rc == 0,
          "prescan_inode_set_find_or_insert grows the table instead of "
          "failing when _locate reports full but count says there is room");
    check(set.capacity > VISITED_INITIAL_CAPACITY,
          "prescan_inode_set_find_or_insert actually grew the table's "
          "capacity");
    check(prescan_inode_set_find_or_insert(&set, 1, 999) == 1,
          "the recovered inode is actually findable afterward");

    free(set.slots);
}

static void test_inode_map_basic_insert_and_duplicate(void)
{
    PortableInodeMap map = {0};
    const PortableInodeSlot *slot = NULL;
    check(inode_map_find_or_insert(&map, 1, 100, "root", "a/b", &slot) == 0 &&
          slot != NULL,
          "inode_map_find_or_insert inserts a new representative");
    check(inode_map_find_or_insert(&map, 1, 100, "root", "a/c", &slot) == 1 &&
          slot != NULL,
          "inode_map_find_or_insert reports a hardlink member");
    for (size_t i = 0; i < map.capacity; i++)
    {
        free(map.slots[i].root_id);
        free(map.slots[i].logical_path);
    }
    free(map.slots);
}

static void test_inode_map_recovers_from_full_locate(void)
{
    PortableInodeMap map = {0};
    fill_inode_map_slots_without_counting(&map, VISITED_INITIAL_CAPACITY);

    const PortableInodeSlot *slot = NULL;
    int rc = inode_map_find_or_insert(&map, 1, 999, "root", "new/entry",
                                      &slot);
    check(rc == 0 && slot != NULL,
          "inode_map_find_or_insert grows the table instead of failing "
          "when _locate reports full but count says there is room");
    check(map.capacity > VISITED_INITIAL_CAPACITY,
          "inode_map_find_or_insert actually grew the table's capacity");

    const PortableInodeSlot *found = NULL;
    check(inode_map_find_or_insert(&map, 1, 999, "root", "new/entry",
                                   &found) == 1 && found != NULL,
          "the recovered entry is actually findable afterward");

    for (size_t i = 0; i < map.capacity; i++)
    {
        free(map.slots[i].root_id);
        free(map.slots[i].logical_path);
    }
    free(map.slots);
}

static void test_tables_refuse_missing_arguments(void)
{
    PortableVisited visited = {0};
    PrescanInodeSet inodes = {0};
    PortableInodeMap map = {0};
    PortableCaseFoldSet folds = {0};
    const PortableInodeSlot *slot = NULL;
    size_t value = 0;
    char *logical = NULL;
    char folded[4] = "x";

    visited_dispose(NULL);
    visited_free(NULL);
    inode_map_free(NULL);
    case_fold_set_free(NULL);
    ascii_fold_copy(NULL, 4, "A");
    ascii_fold_copy(folded, 0, "A");
    check(strcmp(folded, "x") == 0 && visited_reset(NULL) < 0 &&
              visited_add(NULL, "root", "a") < 0 &&
              visited_add(&visited, NULL, "a") < 0 &&
              visited_add(&visited, "root", NULL) < 0 &&
              visited_contains(NULL, "root", "a") < 0 &&
              visited_contains(&visited, NULL, "a") < 0 &&
              visited_contains(&visited, "root", NULL) < 0,
          "the visited set refuses a missing set, root, or path");
    check(prescan_inode_set_rehash(NULL, 64) < 0 &&
              prescan_inode_set_rehash(&inodes, 63) < 0 &&
              prescan_inode_set_rehash(&inodes, SIZE_MAX / 2 + 1) < 0 &&
              prescan_inode_set_find_or_insert(NULL, 1, 1) < 0,
          "the inode set refuses a missing set or a bad capacity");
    check(inode_map_find_or_insert(NULL, 1, 1, "root", "a", &slot) < 0 &&
              inode_map_find_or_insert(&map, 1, 1, NULL, "a", &slot) < 0 &&
              inode_map_find_or_insert(&map, 1, 1, "root", NULL, &slot) < 0 &&
              inode_map_find_or_insert(&map, 1, 1, "root", "a", NULL) < 0,
          "the inode map refuses a missing map, root, path, or slot");
    check(case_fold_set_find_or_insert_value(NULL, "a", "A", 0, &value,
                                             &logical) < 0 &&
              case_fold_set_find_or_insert_value(&folds, NULL, "A", 0, &value,
                                                 &logical) < 0 &&
              case_fold_set_find_or_insert_value(&folds, "a", NULL, 0, &value,
                                                 &logical) < 0 &&
              case_fold_set_find_or_insert_value(&folds, "a", "A", 0, NULL,
                                                 &logical) < 0 &&
              case_fold_set_find_or_insert_value(&folds, "a", "A", 0, &value,
                                                 NULL) < 0 &&
              !case_fold_set_contains(NULL, "a") &&
              !case_fold_set_contains(&folds, NULL) &&
              !case_fold_set_contains(&folds, "a"),
          "the case-fold set refuses a missing set, key, or output");
}

int main(void)
{
    printf(BLUE "::" NC " portable_hashset (unit)\n");
    test_visited_basic_insert_and_duplicate();
    test_visited_recovers_from_full_locate();
    test_visited_length_bound();
    test_prescan_inode_set_basic_insert_and_duplicate();
    test_prescan_inode_set_recovers_from_full_locate();
    test_inode_map_basic_insert_and_duplicate();
    test_inode_map_recovers_from_full_locate();
    test_tables_refuse_missing_arguments();

    printf("portable_hashset tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
