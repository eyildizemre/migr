#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "metadata.h"

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

static struct stat make_stat(dev_t device, ino_t inode)
{
    struct stat st = {0};
    st.st_dev = device;
    st.st_ino = inode;
    st.st_size = (off_t)inode;
    return st;
}

static void test_record_and_find_round_trip(void)
{
    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);

    struct stat st = make_stat(1, 100);
    check(metadata_snapshot_record(&snapshots, &st) == 0,
          "recording a new object succeeds");
    const MetadataSnapshot *found = metadata_snapshot_find(&snapshots, &st);
    check(found != NULL && found->device == 1 && found->inode == 100,
          "lookup finds the recorded object by (dev, ino)");

    metadata_snapshots_free(&snapshots);
}

static void test_duplicate_record_is_idempotent(void)
{
    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);

    struct stat st = make_stat(1, 200);
    check(metadata_snapshot_record(&snapshots, &st) == 0,
          "first record of an object succeeds");
    check(metadata_snapshot_record(&snapshots, &st) == 0,
          "re-recording the same (dev, ino) succeeds without duplicating");
    check(snapshots.count == 1,
          "the array holds exactly one entry after a duplicate record");

    metadata_snapshots_free(&snapshots);
}

static void test_find_missing_returns_null(void)
{
    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);

    struct stat recorded = make_stat(1, 300);
    struct stat missing = make_stat(1, 301);
    check(metadata_snapshot_record(&snapshots, &recorded) == 0,
          "fixture: one object is recorded");
    check(metadata_snapshot_find(&snapshots, &missing) == NULL,
          "an object that was never recorded is not found");

    metadata_snapshots_free(&snapshots);
}

static void test_device_and_inode_both_distinguish_objects(void)
{
    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);

    struct stat a = make_stat(1, 400);
    struct stat b = make_stat(2, 400);
    struct stat c = make_stat(1, 401);
    check(metadata_snapshot_record(&snapshots, &a) == 0 &&
              metadata_snapshot_record(&snapshots, &b) == 0 &&
              metadata_snapshot_record(&snapshots, &c) == 0,
          "three objects sharing one half of the key each record separately");
    check(snapshots.count == 3,
          "all three are stored as distinct entries");

    const MetadataSnapshot *found_a = metadata_snapshot_find(&snapshots, &a);
    const MetadataSnapshot *found_b = metadata_snapshot_find(&snapshots, &b);
    const MetadataSnapshot *found_c = metadata_snapshot_find(&snapshots, &c);
    check(found_a != NULL && found_a->device == 1 && found_a->inode == 400,
          "(dev=1, ino=400) resolves to its own entry");
    check(found_b != NULL && found_b->device == 2 && found_b->inode == 400,
          "(dev=2, ino=400) is not confused with (dev=1, ino=400)");
    check(found_c != NULL && found_c->device == 1 && found_c->inode == 401,
          "(dev=1, ino=401) is not confused with (dev=1, ino=400)");

    metadata_snapshots_free(&snapshots);
}

static void test_many_distinct_objects_survive_growth(void)
{
    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);

    enum { OBJECT_COUNT = 500 };
    int record_ok = 1;
    for (ino_t i = 0; i < OBJECT_COUNT; i++)
    {
        struct stat st = make_stat(1, i + 1);
        if (metadata_snapshot_record(&snapshots, &st) != 0)
            record_ok = 0;
    }
    check(record_ok, "recording 500 distinct objects succeeds throughout growth");
    check(snapshots.count == OBJECT_COUNT,
          "the array holds exactly one entry per distinct object");

    int find_ok = 1;
    for (ino_t i = 0; i < OBJECT_COUNT; i++)
    {
        struct stat st = make_stat(1, i + 1);
        const MetadataSnapshot *found = metadata_snapshot_find(&snapshots, &st);
        if (found == NULL || found->inode != i + 1)
            find_ok = 0;
    }
    check(find_ok,
          "every object recorded before a rehash is still found correctly after it");

    metadata_snapshots_free(&snapshots);
}

static void test_null_arguments_are_rejected(void)
{
    MetadataSnapshots snapshots;
    metadata_snapshots_init(&snapshots);
    struct stat st = make_stat(1, 500);

    check(metadata_snapshot_record(NULL, &st) == -1,
          "record rejects a NULL snapshots pointer");
    check(metadata_snapshot_record(&snapshots, NULL) == -1,
          "record rejects a NULL stat pointer");
    check(metadata_snapshot_find(NULL, &st) == NULL,
          "find rejects a NULL snapshots pointer");
    check(metadata_snapshot_find(&snapshots, NULL) == NULL,
          "find rejects a NULL stat pointer");

    metadata_snapshots_free(&snapshots);
}

int main(void)
{
    printf(BLUE "::" NC " MetadataSnapshots (unit)\n");
    test_record_and_find_round_trip();
    test_duplicate_record_is_idempotent();
    test_find_missing_returns_null();
    test_device_and_inode_both_distinguish_objects();
    test_many_distinct_objects_survive_growth();
    test_null_arguments_are_rejected();

    printf("MetadataSnapshots tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
