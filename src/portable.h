#ifndef PORTABLE_H
#define PORTABLE_H

#include <stddef.h>
#include <sys/types.h>

#include "manifest.h"
#include "sidecar.h"

/**
 * A source root and its container address for a portable capture.
 *
 * capture_path is opened as an absolute source path. The other fields are
 * copied into the fresh versioned manifest; payload_path is relative to the
 * container's data/ directory.
 */
typedef struct {
    const char *id;
    RootPolicy policy;
    const char *capture_path;
    const char *payload_path;
    const char *source_path;
    const char *restore_path;
    int has_restore_path;
} PortableRootSpec;

/**
 * Inputs for portable_capture_fresh_at(). The caller owns every pointer and
 * keeps it valid for the duration of the call.
 */
typedef struct {
    ManifestScope scope;
    int has_source_identity;
    const char *machine_id;
    uid_t source_uid;
    const PortableRootSpec *roots;
    size_t root_count;
    int nsec_exact;
} PortableCaptureRequest;

/**
 * State used by the direct portable capture seam. The data and sidecar
 * handles are borrowed; portable_capture_context_close() does not close them.
 */
typedef struct PortableCaptureContext {
    int data_fd;
    SidecarLog *sidecar;
    int nsec_exact;
    void *visited;
} PortableCaptureContext;

/**
 * Initializes a capture context over an already-created data directory and
 * fresh or adopted sidecar log.
 */
int portable_capture_context_init(PortableCaptureContext *context,
                                  int data_fd, SidecarLog *sidecar,
                                  int nsec_exact);

/** Releases allocations owned by a capture context without closing handles. */
void portable_capture_context_close(PortableCaptureContext *context);

/** Captures one regular-file or directory root into an existing context. */
int portable_capture_root(PortableCaptureContext *context,
                          const PortableRootSpec *root);

/**
 * Writes a portable v1 manifest, creates data/ and sidecar.migr, and captures
 * all roots into a fresh container directory. This direct API is intentionally
 * separate from production backup() dispatch.
 */
int portable_capture_fresh_at(int container_fd,
                              const PortableCaptureRequest *request);

#endif
