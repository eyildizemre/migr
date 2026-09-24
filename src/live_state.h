#ifndef LIVE_STATE_H
#define LIVE_STATE_H

#include <stddef.h>

/**
 * @brief Reports whether a manifest root + logical path is confirmed live
 *        desktop state (docs/DECISIONS.md D44, D48, D55).
 *
 * These paths are rewritten by running services independently of migr:
 * restore does not read them back for verification, and backup tolerates
 * them changing, appearing, or disappearing during capture. A path matches
 * an entry exactly or below it on a path-component boundary; this is an
 * explicit, evidence-backed list, not a classifier for mutable files.
 */
int live_state_path(const char *root_id, size_t root_id_length,
                    const char *logical, size_t logical_length);

#endif
