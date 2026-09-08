#ifndef PORTABLE_NAME_H
#define PORTABLE_NAME_H

#include <limits.h>
#include <stdint.h>

#include "sidecar.h"

typedef struct {
    char physical_leaf[NAME_MAX + 1U];
    char collision_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U];
    int shortened;
} PortablePhysicalName;

/* Maps one logical filename component to its canonical portable physical leaf
 * under docs/DECISIONS.md D39 R-1. Collision uniqueness remains the caller's
 * responsibility under D21. */
int portable_physical_name_map(const char *logical_component,
                               uint64_t collision_number,
                               PortablePhysicalName *out);

#ifdef PORTABLE_NAME_TEST_HOOKS
int portable_physical_name_map_with_fingerprint_for_test(
    const char *logical_component,
    uint64_t collision_number,
    uint64_t fingerprint,
    PortablePhysicalName *out);
#endif

#endif
