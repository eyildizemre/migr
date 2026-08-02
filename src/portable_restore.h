#ifndef PORTABLE_RESTORE_H
#define PORTABLE_RESTORE_H

#include <stddef.h>
#include <sys/types.h>

#include "manifest.h"
#include "metadata.h"

typedef struct {
    int source_container_fd;
    const Manifest *manifest;
    int destination_home_fd;
} PortableRestoreRequest;

typedef struct {
    char id[MANIFEST_ID_MAX];
    size_t live_count;
    size_t violation_count;
} PortableRestoreRootReport;

typedef struct {
    size_t live_count;
    size_t mapped_root_count;
    size_t violation_count;
    size_t root_count;
    PortableRestoreRootReport *roots;
    MetadataProfiles profiles;
} PortableRestorePreflightReport;

/* The caller initializes and releases the report around one preflight. */
void portable_restore_preflight_report_init(
    PortableRestorePreflightReport *report);
void portable_restore_preflight_report_free(
    PortableRestorePreflightReport *report);

/* Read-only seam (docs/DECISIONS.md D17); production restore() does not call this function. */
int portable_restore_preflight_at(
    const PortableRestoreRequest *request,
    PortableRestorePreflightReport *report);

#endif
