#ifndef PORTABLE_H
#define PORTABLE_H

#include <stddef.h>
#include <sys/types.h>

#include "manifest.h"
#include "sidecar.h"

typedef struct {
    SidecarXattr *items;
    size_t count;
    size_t capacity;
} PortableXattrs;

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
    int resume_mode;
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

/**
 * Resumes a portable capture in an existing versioned partial container.
 * The manifest must match request; it is never rewritten by this function.
 */
int portable_capture_resume_at(int container_fd,
                               const PortableCaptureRequest *request);

typedef enum {
    PORTABLE_TEST_INTERRUPT_NONE = 0,
    PORTABLE_TEST_AFTER_MANIFEST,
    PORTABLE_TEST_BEFORE_REPLACEMENT_DELETE,
    PORTABLE_TEST_AFTER_REPLACEMENT_DELETE,
    PORTABLE_TEST_BEFORE_PAYLOAD_REPLACE,
    PORTABLE_TEST_AFTER_PAYLOAD_REPLACE,
    PORTABLE_TEST_BEFORE_PAYLOAD_WRITE,
    PORTABLE_TEST_AFTER_PAYLOAD_WRITE,
    PORTABLE_TEST_BEFORE_PAYLOAD_CLOSE,
    PORTABLE_TEST_AFTER_PAYLOAD_CLOSE,
    PORTABLE_TEST_AFTER_STALE_DELETE,
    PORTABLE_TEST_BEFORE_STALE_UNLINK,
    PORTABLE_TEST_AFTER_STALE_UNLINK,
    PORTABLE_TEST_BEFORE_FINAL_INVENTORY
} PortableTestInterruptPoint;

/*
 * Unlike SidecarTestInterruptPoint, this enum stays visible in every build:
 * portable.c calls portable_test_interrupt_if() with these constants at
 * unconditional call sites (not wrapped in #ifdef), relying on it compiling
 * down to a real no-op stub when PORTABLE_CAPTURE_TEST_HOOKS is off. Only the
 * setter below is part of the D14 seam.
 */
#ifdef PORTABLE_CAPTURE_TEST_HOOKS
void portable_capture_test_set_interrupt(PortableTestInterruptPoint point);
#endif

#endif
