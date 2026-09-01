#ifndef MIGR_PORTABLE_RESTORE_REPLAY_INTERNAL_H
#define MIGR_PORTABLE_RESTORE_REPLAY_INTERNAL_H

#include "metadata.h"
#include "portable_restore.h"

/* Shared between portable_restore_replay.c and
 * portable_restore_orchestrate.c. */
int replay_timestamp_policy(const PortableRestoreRequest *request,
                            MetadataTimestampPolicy *out);

#ifdef PORTABLE_RESTORE_REPLAY_TEST_HOOKS
/* Fires inside replay_apply_hardlink(), after the pre-link reference
 * validation and immediately before linkat(), so a test can swap out the
 * reference target and prove the post-link identity check catches it. */
void portable_restore_replay_test_set_hardlink_race_hook(void (*hook)(void));
#endif

#endif
