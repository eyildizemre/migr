#ifndef MIGR_PORTABLE_RECONCILE_INTERNAL_H
#define MIGR_PORTABLE_RECONCILE_INTERNAL_H

#include "portable.h"
#include "sidecar.h"

#include <stddef.h>

typedef enum {
    PORTABLE_OWNER_LIVE = 1,
    PORTABLE_OWNER_CLAIM = 2,
    PORTABLE_OWNER_TOMBSTONE = 3
} PortableOwnerState;

typedef struct {
    char *root_id;
    char *logical_parent;
    char *physical_leaf;
    char *logical_path;
    SidecarObjectKind kind;
    PortableOwnerState state;
} PortablePhysicalOwner;

typedef struct {
    PortablePhysicalOwner *items;
    size_t count;
    size_t capacity;
    int sorted;
    int allow_ambiguous;
} PortablePhysicalOwners;

/* Defined in portable.c, needed by portable_reconcile.c. */
int sidecar_bytes_equal(SidecarBytes left, SidecarBytes right);
int sidecar_bytes_to_text(SidecarBytes bytes, char **out);
int remove_payload_relative(int data_fd, const char *payload_root,
                            const char *physical);
void portable_physical_owners_free(PortablePhysicalOwners *owners);
int portable_active_owners_load(PortablePhysicalOwners *owners,
                                SidecarLog *sidecar);
int portable_tombstone_owners_load(PortablePhysicalOwners *owners,
                                   SidecarLog *sidecar);
int portable_capture_owners_reload(PortableCaptureContext *context);
int portable_physical_owners_find(const PortablePhysicalOwners *owners,
                                  const char *root_id,
                                  const char *logical_parent,
                                  const char *physical_leaf,
                                  const PortablePhysicalOwner **out);
int portable_physical_owner_for_node(
    const PortableCaptureContext *context,
    const PortablePhysicalOwners *owners, const char *root_id,
    const char *logical_parent, int parent_fd, const char *requested_leaf,
    const struct stat *requested_stat, const PortablePhysicalOwner **out);
int portable_current_assignment(
    const PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical,
    char physical_leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U],
    char collision_suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U]);
int portable_recorded_parent_open(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical, int allow_tombstone, int *parent_out,
    char leaf[SIDECAR_MAX_PHYSICAL_LEAF + 1U],
    SidecarObjectKind *kind_out, PortableOwnerState *state_out);
int portable_recorded_address_matches_current(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical);
int portable_tombstoned_address_matches_current(
    PortableCaptureContext *context, const PortableRootSpec *root,
    const char *logical);
int tombstone_if_live(PortableCaptureContext *context, const char *root_id,
                      const char *logical);
void relocation_scan_count(void);
void relocation_remove_count(void);
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
void portable_test_interrupt_if(PortableTestInterruptPoint point);
void portable_reconcile_test_vanish_descend_at(size_t call_index);
void portable_reconcile_test_vanish_child_named(const char *name);
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
int reconcile_stale_live(PortableCaptureContext *context,
                         const PortableRootSpec *root, const char *logical);
int reconcile_destination_children(PortableCaptureContext *context,
                                   const PortableRootSpec *root,
                                   const char *logical_parent,
                                   int parent_fd, const char *leaf);

#endif
