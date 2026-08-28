#ifndef MIGR_PORTABLE_RESTORE_REPLAY_INTERNAL_H
#define MIGR_PORTABLE_RESTORE_REPLAY_INTERNAL_H

#include "metadata.h"
#include "portable_restore.h"

/* Shared between portable_restore.c (today) / portable_restore_replay.c
 * (after step 7c) and portable_restore_orchestrate.c. */
int replay_timestamp_policy(const PortableRestoreRequest *request,
                            MetadataTimestampPolicy *out);

#endif
