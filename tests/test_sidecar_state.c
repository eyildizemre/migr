// Unit tests for the sidecar v3 state log (docs/DECISIONS.md D17/D21/D22/D25): the
// `(root_id, logical_path)`-keyed live-state map built on top of the sidecar
// codec's record framing, with last-committed-wins semantics, DELETE
// handling, the fd-anchored no-follow single-link slot, and adopt-time
// UNUSABLE vs. resumable classification. Still not wired into production
// capture/restore, and no payload or resume orchestration is exercised here.
//
// Slot classification is tested against every wrong thing that could occupy
// SIDECAR_SLOT_NAME: a symlink (refused without following it), a directory,
// a FIFO, a Unix socket, and -- the actual point of the single-link
// requirement -- a regular file hardlinked from outside the container,
// confirmed rejected without disturbing the file it is linked from. Tail
// recovery distinguishes a clean EOF mid-group (truncated, resumable) from
// interior corruption (unusable, left untouched) the same way the codec's
// own parser tests do, but exercised through the adopt path's own
// truncate-to-boundary behaviour rather than the bare parser.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

static int count_live_callback(const SidecarLiveView *view, void *context)
{
    size_t *count = context;
    if (view == NULL || view->entry == NULL || count == NULL)
        return -1;
    (*count)++;
    return 0;
}

static int write_all_test(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t written = 0;
    while (written < length)
    {
        ssize_t result = write(fd, bytes + written, length - written);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            return -1;
        written += (size_t)result;
    }
    return 0;
}

static int write_raw_field(int fd, const void *data, size_t length)
{
    unsigned char terminator = 0;
    return write_all_test(fd, data, length) == 0 &&
           write_all_test(fd, &terminator, sizeof(terminator)) == 0 ? 0 : -1;
}

static int write_raw_text_field(int fd, const char *text)
{
    return text == NULL ? -1 : write_raw_field(fd, text, strlen(text));
}

static int write_raw_hardlink_with_xattr(int fd)
{
    static const unsigned char value[] = { 0x00, 0x41, 0xff, 0x00 };
    return write_raw_text_field(fd, "ENTRY") == 0 &&
           write_raw_text_field(fd, "ROOT") == 0 &&
           write_raw_text_field(fd, "copy") == 0 &&
           write_raw_text_field(fd, "payload/copy") == 0 &&
           write_raw_text_field(fd, "") == 0 &&
           write_raw_text_field(fd, "hardlink") == 0 &&
           write_raw_text_field(fd, "416") == 0 &&
           write_raw_text_field(fd, "1000") == 0 &&
           write_raw_text_field(fd, "1001") == 0 &&
           write_raw_text_field(fd, "-3") == 0 &&
           write_raw_text_field(fd, "7") == 0 &&
           write_raw_text_field(fd, "42") == 0 &&
           write_raw_text_field(fd, "99") == 0 &&
           write_raw_text_field(fd, "0") == 0 &&
           write_raw_text_field(fd, "1") == 0 &&
           write_raw_text_field(fd, "ROOT") == 0 &&
           write_raw_text_field(fd, "file") == 0 &&
           write_raw_text_field(fd, "XATTR") == 0 &&
           write_raw_text_field(fd, "user.state") == 0 &&
           write_raw_text_field(fd, "4") == 0 &&
           write_all_test(fd, value, sizeof(value)) == 0 &&
           write_raw_text_field(fd, "ENTRY_COMMIT") == 0 ? 0 : -1;
}

static int slot_fd(int container_fd, int flags)
{
    return openat(container_fd, SIDECAR_SLOT_NAME, flags | O_CLOEXEC,
                  0600);
}

static int slot_size(int container_fd, uint64_t *out)
{
    struct stat st;
    if (out == NULL || fstatat(container_fd, SIDECAR_SLOT_NAME, &st, 0) != 0 ||
        st.st_size < 0)
        return -1;
    *out = (uint64_t)st.st_size;
    return 0;
}

static int reset_slot(int container_fd)
{
    if (unlinkat(container_fd, SIDECAR_SLOT_NAME, 0) != 0 && errno != ENOENT)
        return -1;
    return 0;
}

static SidecarEntry entry_for(const char *root, const char *logical,
                              const char *physical, uint64_t size,
                              uint32_t xattr_count)
{
    SidecarEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.root_id = (SidecarBytes){ (const unsigned char *)root, strlen(root) };
    entry.logical_path = (SidecarBytes){ (const unsigned char *)logical,
                                         strlen(logical) };
    entry.physical_path = (SidecarBytes){ (const unsigned char *)physical,
                                          strlen(physical) };
    entry.kind = SIDECAR_KIND_REGULAR;
    entry.mode = 0640;
    entry.uid = 1000;
    entry.gid = 1001;
    entry.atime_sec = -3;
    entry.atime_nsec = 7;
    entry.mtime_sec = 42;
    entry.mtime_nsec = 99;
    entry.size = size;
    entry.xattr_count = xattr_count;
    return entry;
}

static SidecarClaim claim_for(const char *root, const char *logical,
                              const char *physical, SidecarObjectKind kind)
{
    return (SidecarClaim){
        .root_id = { (const unsigned char *)root, strlen(root) },
        .logical_path = { (const unsigned char *)logical, strlen(logical) },
        .physical_path = { (const unsigned char *)physical, strlen(physical) },
        .kind = kind
    };
}

static SidecarXattr sample_xattr(void)
{
    static const unsigned char value[] = { 0x00, 0x41, 0xff, 0x00 };
    return (SidecarXattr){
        .name = { (const unsigned char *)"user.state", 10 },
        .value = { value, sizeof(value) }
    };
}

static void test_fresh_and_live_map(int container_fd)
{
    printf(BLUE "::" NC " fresh sidecar and committed live state\n");
    check(reset_slot(container_fd) == 0, "slot starts absent");

    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "fresh slot is created atomically");
    uint64_t header_size = 0;
    check(slot_size(container_fd, &header_size) == 0 && header_size > 0,
          "fresh log owns a regular fd at the header boundary");

    SidecarEntry entry = entry_for("ROOT", "file", "payload/file", 17, 1);
    SidecarClaim entry_claim = claim_for("ROOT", "file", "payload/file",
                                        SIDECAR_KIND_REGULAR);
    SidecarXattr xattr = sample_xattr();
    check(sidecar_log_append_claim(&log, &entry_claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &entry) == SIDECAR_STATUS_OK,
          "ENTRY opens a group");
    check(sidecar_log_append_xattr(&log, &xattr) == SIDECAR_STATUS_OK,
          "XATTR is appended to the open group");
    check(sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "ENTRY_COMMIT publishes the group");
    check(sidecar_log_live_count(&log) == 1,
          "one committed entry is live");

    SidecarLiveView view;
    int found = sidecar_log_find(&log,
                                 (SidecarBytes){ (const unsigned char *)"ROOT", 4 },
                                 (SidecarBytes){ (const unsigned char *)"file", 4 },
                                 &view);
    check(found == 1 && view.entry != NULL && view.xattr_count == 1 &&
          view.entry->size == 17 && view.xattrs[0].value.length == 4 &&
          view.xattrs[0].value.data[0] == 0 &&
          view.xattrs[0].value.data[2] == 0xff && view.generation == 1 &&
          view.entry->collision_suffix.length == 0,
          "lookup returns copied entry, empty suffix, xattr, and generation");

    SidecarEntry replacement = entry_for("ROOT", "file", "payload/new", 23, 0);
    SidecarDelete deletion = {
        .root_id = { (const unsigned char *)"ROOT", 4 },
        .logical_path = { (const unsigned char *)"file", 4 }
    };
    SidecarClaim replacement_claim = claim_for("ROOT", "file", "payload/new",
                                               SIDECAR_KIND_REGULAR);
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK &&
          sidecar_log_append_claim(&log, &replacement_claim) ==
              SIDECAR_STATUS_OK &&
          sidecar_log_append_entry(&log, &replacement) == SIDECAR_STATUS_OK &&
          sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "a later committed group replaces the previous key");
    found = sidecar_log_find(&log,
                             (SidecarBytes){ (const unsigned char *)"ROOT", 4 },
                             (SidecarBytes){ (const unsigned char *)"file", 4 },
                             &view);
    check(found == 1 && view.entry->size == 23 && view.xattr_count == 0 &&
          view.generation == 3,
          "last committed state removes old xattrs and wins");

    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK &&
          sidecar_log_live_count(&log) == 0,
          "DELETE removes the live key");
    check(sidecar_log_find(&log, deletion.root_id, deletion.logical_path,
                           &view) == 0,
          "deleted key is absent");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "fresh log closes cleanly");

    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
          sidecar_log_live_count(&log) == 0,
          "complete log is adoptable with its committed map");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "adopted log closes cleanly");
}

static void test_claim_replay_and_transitions(int container_fd)
{
    printf(BLUE "::" NC " CLAIM replay, consumption, and cancellation\n");
    check(reset_slot(container_fd) == 0, "claim slot starts absent");

    SidecarClaim claim = claim_for("ROOT", "file", "payload/file",
                                   SIDECAR_KIND_REGULAR);
    SidecarEntry entry = entry_for("ROOT", "file", "payload/file", 17, 0);
    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "claim fixture is created");
    check(sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK,
          "CLAIM appends before an entry group");

    SidecarClaimView claim_view;
    int claim_found = sidecar_log_find_claim(
        &log, claim.root_id, claim.logical_path, &claim_view);
    check(claim_found == 1 && claim_view.claim != NULL &&
              claim_view.claim->kind == SIDECAR_KIND_REGULAR &&
              claim_view.claim->physical_path.length == 12 &&
              memcmp(claim_view.claim->physical_path.data, "payload/file", 12) == 0 &&
              sidecar_log_live_count(&log) == 0,
          "outstanding CLAIM is queryable but not live state");
    size_t live_seen = 0;
    check(sidecar_log_foreach(&log, count_live_callback, &live_seen) ==
              SIDECAR_STATUS_OK && live_seen == 0,
          "outstanding CLAIM is excluded from live iteration");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "claim fixture closes before adoption");

    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE,
          "CLAIM-containing log is adoptable");
    claim_found = sidecar_log_find_claim(
        &log, claim.root_id, claim.logical_path, &claim_view);
    check(claim_found == 1 && claim_view.claim != NULL,
          "adoption rebuilds the outstanding CLAIM map");

    check(sidecar_log_append_entry(&log, &entry) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "matching ENTRY_COMMIT appends successfully");
    check(sidecar_log_find_claim(&log, claim.root_id, claim.logical_path,
                                 &claim_view) == 0 &&
              sidecar_log_live_count(&log) == 1,
          "matching ENTRY_COMMIT consumes the exact CLAIM");

    SidecarDelete deletion = {
        .root_id = claim.root_id,
        .logical_path = claim.logical_path
    };
    SidecarLiveView live_view;
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK &&
              sidecar_log_find(&log, deletion.root_id, deletion.logical_path,
                               &live_view) == 0 &&
              sidecar_log_find_deleted(&log, deletion.root_id,
                                       deletion.logical_path, &live_view) == 1,
          "DELETE leaves a tombstone after the committed entry");

    SidecarClaim replacement = claim_for("ROOT", "file", "payload/new",
                                         SIDECAR_KIND_REGULAR);
    check(sidecar_log_append_claim(&log, &replacement) == SIDECAR_STATUS_OK &&
              sidecar_log_find_deleted(&log, replacement.root_id,
                                       replacement.logical_path, &live_view) == 1 &&
              sidecar_log_find_claim(&log, replacement.root_id,
                                     replacement.logical_path,
                                     &claim_view) == 1,
          "a tombstone and an outstanding CLAIM coexist for one key");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "tombstone and claim fixture closes");

    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_find_deleted(&log, replacement.root_id,
                                       replacement.logical_path, &live_view) == 1 &&
              sidecar_log_find_claim(&log, replacement.root_id,
                                     replacement.logical_path,
                                     &claim_view) == 1,
          "adoption preserves tombstone and CLAIM independently");
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK &&
              sidecar_log_find_claim(&log, replacement.root_id,
                                     replacement.logical_path,
                                     &claim_view) == 0 &&
              sidecar_log_find_deleted(&log, replacement.root_id,
                                       replacement.logical_path, &live_view) == 1,
          "DELETE cancels the outstanding CLAIM and keeps its tombstone");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "claim transition log closes");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "claimless commit fixture is created");
    check(sidecar_log_append_entry(&log, &entry) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_CORRUPT,
          "claimless ENTRY_COMMIT is refused by the live state map");
    check(sidecar_log_live_count(&log) == 0,
          "claimless ENTRY_COMMIT leaves live state unchanged");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "claimless live fixture closes");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "mismatching commit fixture is created");
    SidecarEntry mismatching = entry_for("ROOT", "file", "payload/other",
                                         17, 0);
    check(sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &mismatching) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_CORRUPT,
          "mismatching ENTRY_COMMIT is refused by the live state map");
    live_seen = 0;
    check(sidecar_log_live_count(&log) == 0 &&
              sidecar_log_foreach(&log, count_live_callback, &live_seen) ==
                  SIDECAR_STATUS_OK && live_seen == 0 &&
              sidecar_log_find_claim(&log, claim.root_id, claim.logical_path,
                                     &claim_view) == 1,
          "mismatching ENTRY_COMMIT leaves only the outstanding CLAIM");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "mismatching live fixture closes");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
              sidecar_log_find_claim(&log, claim.root_id, claim.logical_path,
                                     &claim_view) == 1,
          "adoption preserves the claim after rejecting the mismatching tail");
    check(sidecar_log_append_delete(&log, &deletion) == SIDECAR_STATUS_OK &&
              sidecar_log_find_claim(&log, claim.root_id, claim.logical_path,
                                     &claim_view) == 0,
          "DELETE cancels the claim left by a mismatching commit");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "mismatching commit fixture closes");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "claimless adoption fixture is created");
    int fd = slot_fd(container_fd, O_WRONLY | O_APPEND);
    check(fd >= 0 && sidecar_write_entry(fd, &entry) == 0 &&
              sidecar_write_entry_commit(fd) == 0,
          "claimless ENTRY_COMMIT is written for adoption");
    if (fd >= 0)
        close(fd);
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "adoption rejects a claimless ENTRY_COMMIT");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "mismatching adoption fixture is created");
    fd = slot_fd(container_fd, O_WRONLY | O_APPEND);
    check(fd >= 0 && sidecar_write_claim(fd, &claim) == 0 &&
              sidecar_write_entry(fd, &mismatching) == 0 &&
              sidecar_write_entry_commit(fd) == 0,
          "mismatching ENTRY_COMMIT is written for adoption");
    if (fd >= 0)
        close(fd);
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "adoption rejects a mismatching ENTRY_COMMIT");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH &&
              sidecar_log_append_claim(&log, &claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_claim(&log, &claim) ==
                  SIDECAR_STATUS_INVALID_ARGUMENT,
          "public append rejects a duplicate outstanding CLAIM");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "duplicate guard log closes");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "raw duplicate fixture is created");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK, "raw fixture closes");
    fd = slot_fd(container_fd, O_WRONLY | O_APPEND);
    check(fd >= 0 && sidecar_write_claim(fd, &claim) == 0 &&
              sidecar_write_claim(fd, &claim) == 0,
          "identical duplicate CLAIM records are written");
    if (fd >= 0)
        close(fd);
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "identical duplicate CLAIMs are rejected at adoption");

    check(reset_slot(container_fd) == 0 &&
              sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "raw conflict fixture is created");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK, "conflict fixture closes");
    SidecarClaim conflict = claim_for("ROOT", "file", "payload/conflict",
                                      SIDECAR_KIND_REGULAR);
    fd = slot_fd(container_fd, O_WRONLY | O_APPEND);
    check(fd >= 0 && sidecar_write_claim(fd, &claim) == 0 &&
              sidecar_write_claim(fd, &conflict) == 0,
          "conflicting CLAIM records are written");
    if (fd >= 0)
        close(fd);
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "conflicting CLAIMs are rejected at adoption");
}

static void test_sequence_and_hardlink_guards(int container_fd)
{
    printf(BLUE "::" NC " append sequence and hardlink validation\n");
    check(reset_slot(container_fd) == 0, "old slot is removed");
    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "guard fixture is created");
    SidecarEntry entry = entry_for("ROOT", "file", "payload/file", 1, 1);
    SidecarClaim entry_claim = claim_for("ROOT", "file", "payload/file",
                                         SIDECAR_KIND_REGULAR);
    SidecarXattr xattr = sample_xattr();
    check(sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_INVALID_ARGUMENT,
          "commit without an entry is refused");
    check(sidecar_log_append_xattr(&log, &xattr) == SIDECAR_STATUS_INVALID_ARGUMENT,
          "xattr without an entry is refused");
    check(sidecar_log_append_claim(&log, &entry_claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &entry) == SIDECAR_STATUS_OK,
          "guard entry opens");
    check(sidecar_log_append_entry(&log, &entry) == SIDECAR_STATUS_INVALID_ARGUMENT,
          "a second entry cannot interrupt an open group");
    check(sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_INVALID_ARGUMENT,
          "missing xattr is refused at commit");
    check(sidecar_log_append_xattr(&log, &xattr) == SIDECAR_STATUS_OK &&
          sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "a complete group can be committed after the guard failures");

    SidecarEntry symlink = entry_for("ROOT", "link", "payload/link", 0, 0);
    static const unsigned char collision_suffix[] = "%7E1";
    symlink.kind = SIDECAR_KIND_SYMLINK;
    symlink.collision_suffix = (SidecarBytes){
        collision_suffix, sizeof(collision_suffix) - 1U
    };
    symlink.symlink_target = (SidecarBytes){
        (const unsigned char *)"target", 6
    };
    SidecarClaim symlink_claim = claim_for("ROOT", "link", "payload/link",
                                           SIDECAR_KIND_SYMLINK);
    check(sidecar_log_append_claim(&log, &symlink_claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &symlink) == SIDECAR_STATUS_OK,
          "well-formed symlink entry opens a group");
    check(sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "symlink entry commits");
    check(sidecar_log_live_count(&log) == 2,
          "committed symlink entry is live");

    SidecarLiveView view;
    check(sidecar_log_find(&log, symlink.root_id, symlink.logical_path, &view) == 1 &&
          view.entry != NULL && view.entry->kind == SIDECAR_KIND_SYMLINK &&
          view.entry->symlink_target.length == 6 &&
          memcmp(view.entry->symlink_target.data, "target", 6) == 0 &&
          view.entry->collision_suffix.length ==
              sizeof(collision_suffix) - 1U &&
          memcmp(view.entry->collision_suffix.data, collision_suffix,
                 sizeof(collision_suffix) - 1U) == 0,
          "live symlink target and collision suffix are copied into the state map");

    SidecarEntry hardlink = entry_for("ROOT", "copy", "payload/copy", 0, 0);
    hardlink.kind = SIDECAR_KIND_HARDLINK;
    hardlink.hardlink_root_id = hardlink.root_id;
    hardlink.hardlink_logical_path = entry.logical_path;
    SidecarClaim hardlink_claim = claim_for("ROOT", "copy", "payload/copy",
                                            SIDECAR_KIND_HARDLINK);
    check(sidecar_log_append_claim(&log, &hardlink_claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &hardlink) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "well-formed hardlink entry opens and commits");
    check(sidecar_log_live_count(&log) == 3,
          "committed hardlink entry is live");
    check(sidecar_log_find(&log, hardlink.root_id, hardlink.logical_path,
                           &view) == 1 && view.entry != NULL &&
          view.entry->kind == SIDECAR_KIND_HARDLINK &&
          view.entry->hardlink_root_id.length == 4 &&
          memcmp(view.entry->hardlink_root_id.data, "ROOT", 4) == 0 &&
          view.entry->hardlink_logical_path.length == 4 &&
          memcmp(view.entry->hardlink_logical_path.data, "file", 4) == 0,
          "hardlink reference fields are copied into the state map");

    SidecarEntry empty_logical = entry_for("ROOT", "copy2", "payload/copy2",
                                           0, 0);
    empty_logical.kind = SIDECAR_KIND_HARDLINK;
    empty_logical.hardlink_root_id = empty_logical.root_id;
    empty_logical.hardlink_logical_path = (SidecarBytes){ NULL, 0 };
    SidecarClaim empty_logical_claim = claim_for(
        "ROOT", "copy2", "payload/copy2", SIDECAR_KIND_HARDLINK);
    check(sidecar_log_append_claim(&log, &empty_logical_claim) ==
              SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &empty_logical) ==
                  SIDECAR_STATUS_OK &&
              sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "hardlink entry with empty logical reference is accepted by the state map");
    check(sidecar_log_find(&log, empty_logical.root_id,
                           empty_logical.logical_path, &view) == 1 &&
              view.entry != NULL &&
              view.entry->kind == SIDECAR_KIND_HARDLINK &&
              view.entry->hardlink_logical_path.length == 0,
          "empty hardlink logical reference is stored correctly");

    SidecarEntry invalid = hardlink;
    invalid.hardlink_root_id = (SidecarBytes){ NULL, 0 };
    check(sidecar_log_append_entry(&log, &invalid) ==
              SIDECAR_STATUS_INVALID_ARGUMENT,
          "hardlink missing root reference is refused by the state map");
    invalid = hardlink;
    invalid.xattr_count = 1;
    check(sidecar_log_append_entry(&log, &invalid) ==
              SIDECAR_STATUS_INVALID_ARGUMENT,
          "hardlink xattrs are refused by the state map");
    invalid = hardlink;
    invalid.symlink_target = (SidecarBytes){
        (const unsigned char *)"target", 6
    };
    check(sidecar_log_append_entry(&log, &invalid) ==
              SIDECAR_STATUS_INVALID_ARGUMENT,
          "hardlink symlink target is refused by the state map");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "guard log closes");

    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
          sidecar_log_live_count(&log) == 4,
          "adopted state retains symlink and hardlink entries");
    check(sidecar_log_find(&log, symlink.root_id, symlink.logical_path, &view) == 1 &&
          view.entry != NULL && view.entry->symlink_target.length == 6 &&
          memcmp(view.entry->symlink_target.data, "target", 6) == 0 &&
          view.entry->collision_suffix.length ==
              sizeof(collision_suffix) - 1U &&
          memcmp(view.entry->collision_suffix.data, collision_suffix,
                 sizeof(collision_suffix) - 1U) == 0,
          "adopted symlink target and collision suffix remain byte-exact");
    check(sidecar_log_find(&log, hardlink.root_id, hardlink.logical_path,
                           &view) == 1 && view.entry != NULL &&
          view.entry->kind == SIDECAR_KIND_HARDLINK &&
          view.entry->hardlink_root_id.length == 4 &&
          view.entry->hardlink_logical_path.length == 4 &&
          memcmp(view.entry->hardlink_logical_path.data, "file", 4) == 0,
          "adopted hardlink reference fields remain byte-exact");
    check(sidecar_log_find(&log, empty_logical.root_id,
                           empty_logical.logical_path, &view) == 1 &&
              view.entry != NULL &&
              view.entry->kind == SIDECAR_KIND_HARDLINK &&
              view.entry->hardlink_logical_path.length == 0,
          "adopted empty hardlink logical reference remains valid");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "adopted guard log closes");
}

static void test_hardlink_adopt_validation(int container_fd)
{
    printf(BLUE "::" NC " adopt validates hardlink records independently\n");
    check(reset_slot(container_fd) == 0, "adopt fixture slot is absent");
    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int written = fd >= 0 && sidecar_write_header(fd) == 0 &&
                  write_raw_hardlink_with_xattr(fd) == 0;
    check(written, "raw hardlink+xattr fixture bypasses the writer validator");
    if (fd >= 0)
        close(fd);

    SidecarLog log = {0};
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "adoption rejects hardlink xattrs through copy_entry");
    check(reset_slot(container_fd) == 0,
          "malformed adopt fixture is removed");
}

static void test_missing_and_slot_types(int container_fd)
{
    printf(BLUE "::" NC " slot classification and no-follow policy\n");
    SidecarLog log = {0};
    check(reset_slot(container_fd) == 0, "slot is absent for adoption");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_MISSING,
          "missing sidecar is distinguished from an unusable one");

    char target[] = "/tmp/migr_sidecar_target_XXXXXX";
    int target_fd = mkstemp(target);
    check(target_fd >= 0, "symlink target fixture is created");
    if (target_fd >= 0)
        close(target_fd);
    char slot_path[PATH_MAX];
    char fd_link[64];
    int link_length = snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d",
                               container_fd);
    char directory[PATH_MAX];
    ssize_t directory_length = -1;
    if (link_length > 0 && (size_t)link_length < sizeof(fd_link))
        directory_length = readlink(fd_link, directory, sizeof(directory) - 1U);
    if (directory_length >= 0)
        directory[directory_length] = '\0';
    int path_length = directory_length >= 0
        ? snprintf(slot_path, sizeof(slot_path), "%s/%s", directory,
                   SIDECAR_SLOT_NAME)
        : -1;
    check(path_length > 0 && (size_t)path_length < sizeof(slot_path) &&
          target_fd >= 0 && symlink(target, slot_path) == 0,
          "slot symlink fixture is created");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "slot symlink is refused without following it");
    unlink(slot_path);
    unlink(target);

    check(mkdirat(container_fd, SIDECAR_SLOT_NAME, 0700) == 0,
          "directory slot fixture is created");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "directory slot is unusable");
    check(unlinkat(container_fd, SIDECAR_SLOT_NAME, AT_REMOVEDIR) == 0,
          "directory slot is removed");

    check(mkfifo(slot_path, 0600) == 0,
          "FIFO slot fixture is created");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "FIFO slot is rejected without blocking");
    check(unlinkat(container_fd, SIDECAR_SLOT_NAME, 0) == 0,
          "FIFO slot is removed");

    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    check(socket_fd >= 0 && path_length > 0 &&
          (size_t)path_length < sizeof(address.sun_path),
          "socket slot fixture is allocatable");
    if (socket_fd >= 0 && path_length > 0 &&
        (size_t)path_length < sizeof(address.sun_path))
    {
        memcpy(address.sun_path, slot_path, (size_t)path_length + 1U);
        int bind_result = bind(socket_fd, (const struct sockaddr *)&address,
                               sizeof(address));
        if (bind_result == 0)
        {
            check(1, "socket slot fixture is bound");
            check(sidecar_log_adopt_at(container_fd, &log) ==
                      SIDECAR_OPEN_UNUSABLE,
                  "socket slot is refused");
            unlink(slot_path);
        }
        else
            check(errno == EPERM || errno == EACCES,
                  "restricted host reports socket fixture refusal");
    }
    if (socket_fd >= 0)
        close(socket_fd);
}

static void test_truncated_tail(int container_fd)
{
    printf(BLUE "::" NC " adoption truncates only an EOF tail\n");
    check(reset_slot(container_fd) == 0, "tail slot is absent");
    SidecarLog log = {0};
    check(sidecar_log_create_at(container_fd, &log) == SIDECAR_OPEN_FRESH,
          "tail log is created");
    SidecarEntry entry = entry_for("ROOT", "file", "payload/file", 4, 0);
    SidecarClaim entry_claim = claim_for("ROOT", "file", "payload/file",
                                         SIDECAR_KIND_REGULAR);
    check(sidecar_log_append_claim(&log, &entry_claim) == SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &entry) == SIDECAR_STATUS_OK &&
          sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK,
          "tail log receives a committed prefix");
    uint64_t boundary = 0;
    check(slot_size(container_fd, &boundary) == 0 && boundary > 0,
          "committed prefix boundary is statable");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK, "tail log closes");

    int fd = slot_fd(container_fd, O_WRONLY | O_APPEND);
    static const unsigned char tail[] = "DELETE\0ROOT\0partial";
    check(fd >= 0 && write_all_test(fd, tail, sizeof(tail) - 1U) == 0,
          "incomplete DELETE is appended");
    if (fd >= 0)
        close(fd);

    uint64_t adopted_boundary = 0;
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
          slot_size(container_fd, &adopted_boundary) == 0 &&
          adopted_boundary == boundary,
          "truncated tail is resumable at the last boundary");
    struct stat st;
    check(fstatat(container_fd, SIDECAR_SLOT_NAME, &st, 0) == 0 &&
          (uint64_t)st.st_size == boundary,
          "adoption truncates the incomplete tail");
    SidecarLiveView view;
    check(sidecar_log_find(&log,
                           (SidecarBytes){ (const unsigned char *)"ROOT", 4 },
                           (SidecarBytes){ (const unsigned char *)"file", 4 },
                           &view) == 1,
          "committed state survives tail recovery");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "recovered log closes");

    fd = slot_fd(container_fd, O_WRONLY | O_APPEND);
    SidecarEntry uncommitted = entry_for("ROOT", "tail", "payload/tail", 8, 0);
    check(fd >= 0 && sidecar_write_entry(fd, &uncommitted) == 0,
          "a complete but uncommitted group is appended");
    if (fd >= 0)
        close(fd);
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_RESUMABLE &&
          slot_size(container_fd, &adopted_boundary) == 0 &&
          adopted_boundary == boundary,
          "uncommitted group is discarded at adoption");
    SidecarClaim uncommitted_claim = claim_for("ROOT", "tail", "payload/tail",
                                               SIDECAR_KIND_REGULAR);
    check(sidecar_log_append_claim(&log, &uncommitted_claim) ==
              SIDECAR_STATUS_OK &&
              sidecar_log_append_entry(&log, &uncommitted) == SIDECAR_STATUS_OK &&
          sidecar_log_append_entry_commit(&log) == SIDECAR_STATUS_OK &&
          sidecar_log_live_count(&log) == 2,
          "adopted log accepts a new group after discarding the tail");
    check(sidecar_log_close(&log) == SIDECAR_STATUS_OK,
          "tail log closes after resumed append");
}

static void test_interior_corruption_and_hardlink(int container_fd)
{
    printf(BLUE "::" NC " unusable content and hardlink refusal\n");
    check(reset_slot(container_fd) == 0, "corruption slot is absent");
    int fd = openat(container_fd, SIDECAR_SLOT_NAME,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    static const unsigned char corrupt[] = SIDECAR_MAGIC "\0" "3\0UNKNOWN\0";
    check(fd >= 0 && write_all_test(fd, corrupt, sizeof(corrupt) - 1U) == 0,
          "interior corruption fixture is written");
    if (fd >= 0)
        close(fd);
    struct stat before;
    check(fstatat(container_fd, SIDECAR_SLOT_NAME, &before, 0) == 0,
          "corrupt fixture is statable");
    SidecarLog log = {0};
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "interior corruption is not resumable");
    struct stat after;
    check(fstatat(container_fd, SIDECAR_SLOT_NAME, &after, 0) == 0 &&
          after.st_size == before.st_size,
          "unusable content is not truncated");
    check(unlinkat(container_fd, SIDECAR_SLOT_NAME, 0) == 0,
          "corrupt fixture is removed");

    char outside[] = "/tmp/migr_sidecar_hardlink_XXXXXX";
    int outside_fd = mkstemp(outside);
    check(outside_fd >= 0, "hardlink sentinel is created");
    if (outside_fd >= 0)
        close(outside_fd);
    fd = open(outside, O_WRONLY | O_CLOEXEC);
    check(fd >= 0 && sidecar_write_header(fd) == 0,
          "hardlinked sidecar fixture is written");
    if (fd >= 0)
        close(fd);
    check(outside_fd >= 0 && linkat(AT_FDCWD, outside,
                                   container_fd, SIDECAR_SLOT_NAME, 0) == 0,
          "sidecar is hardlinked to the sentinel");
    struct stat sentinel_before;
    check(stat(outside, &sentinel_before) == 0 && sentinel_before.st_nlink == 2,
          "hardlink has two names");
    check(sidecar_log_adopt_at(container_fd, &log) == SIDECAR_OPEN_UNUSABLE,
          "hardlinked sidecar is rejected");
    struct stat sentinel_after;
    check(stat(outside, &sentinel_after) == 0 &&
          sentinel_after.st_nlink == sentinel_before.st_nlink &&
          sentinel_after.st_size == sentinel_before.st_size,
          "hardlink sentinel is left untouched");
    unlinkat(container_fd, SIDECAR_SLOT_NAME, 0);
    unlink(outside);
}

int main(void)
{
    char directory[] = "/tmp/migr_sidecar_state_XXXXXX";
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

    test_fresh_and_live_map(container_fd);
    test_claim_replay_and_transitions(container_fd);
    test_sequence_and_hardlink_guards(container_fd);
    test_hardlink_adopt_validation(container_fd);
    test_missing_and_slot_types(container_fd);
    test_truncated_tail(container_fd);
    test_interior_corruption_and_hardlink(container_fd);

    reset_slot(container_fd);
    close(container_fd);
    rmdir(directory);
    printf("sidecar state tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
