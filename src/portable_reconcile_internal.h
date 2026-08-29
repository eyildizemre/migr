#ifndef MIGR_PORTABLE_RECONCILE_INTERNAL_H
#define MIGR_PORTABLE_RECONCILE_INTERNAL_H

#include "portable.h"
#include "sidecar.h"

#include <stddef.h>

typedef struct {
    char *root_id;
    char *physical_path;
    char *logical_path;
} PortableOwnedPath;

typedef struct {
    PortableOwnedPath *items;
    size_t count;
    size_t capacity;
    int sorted;
} PortableOwnedPaths;

typedef struct {
    char *root_id;
    char *physical_path;
    char *logical_path;
} PortableClaimedPath;

typedef struct {
    PortableClaimedPath *items;
    size_t count;
    size_t capacity;
    int sorted;
} PortableClaimedPaths;

/* Defined in portable.c, needed by portable_reconcile.c. */
int sidecar_bytes_equal(SidecarBytes left, SidecarBytes right);
int sidecar_bytes_to_text(SidecarBytes bytes, char **out);
void portable_owned_paths_free(PortableOwnedPaths *paths);
int portable_owned_paths_load(PortableOwnedPaths *paths, SidecarLog *sidecar);
const char *portable_owned_paths_owner(const PortableOwnedPaths *paths,
                                       const char *root_id,
                                       const char *physical_path);
void portable_claimed_paths_free(PortableClaimedPaths *paths);
int portable_claimed_paths_load(PortableClaimedPaths *paths,
                                SidecarLog *sidecar);
int tombstone_if_live(PortableCaptureContext *context, const char *root_id,
                      const char *logical);
int remove_payload_relative(int data_fd, const char *payload_root,
                            const char *physical);
void relocation_scan_count(void);
void relocation_remove_count(void);
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
void portable_test_interrupt_if(PortableTestInterruptPoint point);
#else
void portable_test_interrupt_if(int point);
#endif

/* Defined in portable_reconcile.c, needed by portable.c. */
int reconcile_root(PortableCaptureContext *context,
                   const PortableRootSpec *root);
int prepare_collision_relocations(PortableCaptureContext *context,
                                  const PortableRootSpec *root);
int reconcile_stale_claim(PortableCaptureContext *context,
                          const PortableRootSpec *root, const char *logical,
                          const SidecarClaim *claim);

#endif
