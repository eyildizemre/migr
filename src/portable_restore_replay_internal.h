#ifndef MIGR_PORTABLE_RESTORE_REPLAY_INTERNAL_H
#define MIGR_PORTABLE_RESTORE_REPLAY_INTERNAL_H

#include "metadata.h"
#include "portable_restore.h"

/* Shared between portable_restore_replay.c and
 * portable_restore_orchestrate.c. */
int replay_timestamp_policy(const PortableRestoreRequest *request,
                            MetadataTimestampPolicy *out);

/* Not called outside this file in production, but non-static so
 * tests/test_portable_restore_replay.c can unit-test them directly against
 * the linked object rather than only through the full replay path. */
int replay_entry_valid(const SidecarEntry *entry);
int replay_stat_from_entry(const SidecarEntry *entry, struct stat *desired);
int replay_hardlink_identity_matches(const struct stat *linked,
                                     const struct stat *reference);

#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
/* Fires inside replay_apply_hardlink(), after the pre-link reference
 * validation and immediately before linkat(), so a test can swap out the
 * reference target and prove the post-link identity check catches it. */
void portable_restore_replay_test_set_hardlink_race_hook(void (*hook)(void));
#endif

#endif
