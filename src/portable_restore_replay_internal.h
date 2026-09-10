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
const char *replay_failure_kind_text(SidecarObjectKind kind);
const char *replay_failure_step_text(PortableRestoreReplayFailureStep step);
int replay_failure_reason_format(const PortableRestoreReplayReport *report,
                                 char *out, size_t out_size);

#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
/* Fires inside replay_apply_hardlink(), after the pre-link reference
 * validation and immediately before linkat(), so a test can swap out the
 * reference target and prove the post-link identity check catches it. */
void portable_restore_replay_test_set_hardlink_race_hook(void (*hook)(void));

/* Fires after replay has finished mutating destination content and before the
 * post-copy verification pass starts. Tests use it to model corruption or a
 * pathname replacement in that exact boundary. */
void portable_restore_replay_test_set_before_content_verification_hook(
    void (*hook)(void));
void portable_restore_replay_test_set_after_apply_hook(void (*hook)(void));
void portable_restore_replay_test_set_verification_progress_enabled(int enabled);
void portable_restore_replay_test_reset_verification_regular_read_count(void);
size_t portable_restore_replay_test_verification_regular_read_count(void);
#endif

#endif
