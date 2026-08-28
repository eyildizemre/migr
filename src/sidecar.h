#ifndef SIDECAR_H
#define SIDECAR_H

#include <stddef.h>
#include <stdint.h>

#define SIDECAR_MAGIC "MIGR_SIDECAR"
#define SIDECAR_VERSION 3
#define SIDECAR_SLOT_NAME "sidecar.migr"

#define SIDECAR_MAX_ROOT_ID 64U
#define SIDECAR_MAX_PATH 4096U
#define SIDECAR_MAX_COLLISION_SUFFIX 32U
#define SIDECAR_MAX_SYMLINK_TARGET 4096U
#define SIDECAR_MAX_XATTR_NAME 255U
#define SIDECAR_MAX_XATTR_VALUE 65536U
#define SIDECAR_MAX_XATTRS_PER_ENTRY 256U
#define SIDECAR_MAX_LIVE_ENTRIES (1U << 20)
#define SIDECAR_MAX_TOTAL_BYTES (UINT64_C(4) * UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024))
#define SIDECAR_MAX_ALLOC_BUDGET (UINT64_C(1) * UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024))
#define SIDECAR_MAX_UID_GID UINT32_MAX
#define SIDECAR_MAX_MODE 07777U
#define SIDECAR_MAX_NSEC 999999999U

typedef struct {
    const unsigned char *data;
    size_t length;
} SidecarBytes;

typedef enum {
    SIDECAR_KIND_REGULAR = 0,
    SIDECAR_KIND_DIRECTORY,
    SIDECAR_KIND_FIFO,
    SIDECAR_KIND_SYMLINK,
    SIDECAR_KIND_HARDLINK
} SidecarObjectKind;

typedef enum {
    SIDECAR_RECORD_ENTRY = 0,
    SIDECAR_RECORD_XATTR,
    SIDECAR_RECORD_ENTRY_COMMIT,
    SIDECAR_RECORD_DELETE,
    SIDECAR_RECORD_CLAIM
} SidecarRecordType;

typedef enum {
    SIDECAR_STATUS_OK = 0,
    SIDECAR_STATUS_TRUNCATED_TAIL,
    SIDECAR_STATUS_INVALID_ARGUMENT,
    SIDECAR_STATUS_IO_ERROR,
    SIDECAR_STATUS_CORRUPT,
    SIDECAR_STATUS_UNKNOWN_VERSION,
    SIDECAR_STATUS_LIMIT,
    SIDECAR_STATUS_ALLOCATION,
    SIDECAR_STATUS_UNSUPPORTED_KIND,
    SIDECAR_STATUS_CALLBACK
} SidecarStatus;

typedef enum {
    SIDECAR_OPEN_FRESH = 0,
    SIDECAR_OPEN_RESUMABLE,
    SIDECAR_OPEN_MISSING,
    SIDECAR_OPEN_EXISTS,
    SIDECAR_OPEN_UNUSABLE,
    SIDECAR_OPEN_IO_ERROR,
    SIDECAR_OPEN_ALLOCATION,
    SIDECAR_OPEN_INVALID_ARGUMENT
} SidecarOpenStatus;

typedef struct {
    SidecarBytes root_id;
    SidecarBytes logical_path;
    SidecarBytes physical_path;
    SidecarBytes collision_suffix;
    SidecarObjectKind kind;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    int64_t atime_sec;
    uint32_t atime_nsec;
    int64_t mtime_sec;
    uint32_t mtime_nsec;
    uint64_t size;
    uint32_t xattr_count;
    SidecarBytes symlink_target;
    SidecarBytes hardlink_root_id;
    SidecarBytes hardlink_logical_path;
} SidecarEntry;

typedef struct {
    SidecarBytes name;
    SidecarBytes value;
} SidecarXattr;

typedef struct {
    SidecarBytes root_id;
    SidecarBytes logical_path;
} SidecarDelete;

typedef struct {
    SidecarBytes root_id;
    SidecarBytes logical_path;
    SidecarBytes physical_path;
    SidecarObjectKind kind;
} SidecarClaim;

typedef struct {
    SidecarRecordType type;
    union {
        SidecarEntry entry;
        SidecarXattr xattr;
        SidecarDelete deletion;
        SidecarClaim claim;
    } value;
} SidecarRecord;

typedef int (*SidecarRecordCallback)(const SidecarRecord *record, void *context);

typedef struct {
    uint64_t bytes_read;
    uint64_t last_valid_boundary;
    uint64_t records_read;
    uint64_t allocation_peak;
} SidecarParseResult;

typedef struct SidecarLog {
    /* Zero-initialize before the first create/adopt call. */
    void *implementation;
} SidecarLog;

typedef struct {
    /* These pointers are borrowed until the next log mutation or close. */
    const SidecarEntry *entry;
    const SidecarXattr *xattrs;
    size_t xattr_count;
    uint64_t generation;
} SidecarLiveView;

typedef struct {
    /* The pointer is borrowed until the next log mutation or close. */
    const SidecarClaim *claim;
    uint64_t generation;
} SidecarClaimView;

typedef int (*SidecarLiveCallback)(const SidecarLiveView *view,
                                   void *context);
typedef int (*SidecarClaimCallback)(const SidecarClaimView *view,
                                    void *context);

/* Record fields passed to the callback are borrowed until it returns. */
int sidecar_live_entry_count_allowed(uint64_t count);

uint64_t sidecar_process_salt(void);

int sidecar_write_header(int fd);
int sidecar_write_entry(int fd, const SidecarEntry *entry);
int sidecar_write_xattr(int fd, const SidecarXattr *xattr);
int sidecar_write_entry_commit(int fd);
int sidecar_write_delete(int fd, const SidecarDelete *deletion);
int sidecar_write_claim(int fd, const SidecarClaim *claim);
int sidecar_claim_kind_valid(SidecarObjectKind kind);

/*
 * Parses a regular sidecar fd without changing its offset or contents. The
 * callback is invoked for complete records only. A truncated EOF tail is
 * reported separately from interior corruption; last_valid_boundary identifies
 * the header or latest complete ENTRY_COMMIT/DELETE boundary and is never a
 * request to truncate the fd.
 */
SidecarStatus sidecar_parse_fd(int fd, SidecarRecordCallback callback,
                               void *context, SidecarParseResult *result);

/* The container directory fd is borrowed; the returned log owns its slot fd. */
SidecarOpenStatus sidecar_log_create_at(int container_fd, SidecarLog *out);
SidecarOpenStatus sidecar_log_adopt_at(int container_fd, SidecarLog *out);
SidecarStatus sidecar_log_close(SidecarLog *log);

SidecarStatus sidecar_log_append_entry(SidecarLog *log,
                                       const SidecarEntry *entry);
SidecarStatus sidecar_log_append_xattr(SidecarLog *log,
                                       const SidecarXattr *xattr);
SidecarStatus sidecar_log_append_entry_commit(SidecarLog *log);
SidecarStatus sidecar_log_append_delete(SidecarLog *log,
                                        const SidecarDelete *deletion);
SidecarStatus sidecar_log_append_claim(SidecarLog *log,
                                       const SidecarClaim *claim);

size_t sidecar_log_live_count(const SidecarLog *log);
size_t sidecar_log_claim_count(const SidecarLog *log);
int sidecar_log_find(const SidecarLog *log, SidecarBytes root_id,
                     SidecarBytes logical_path, SidecarLiveView *out);
SidecarStatus sidecar_log_foreach(SidecarLog *log, SidecarLiveCallback callback,
                                   void *context);
SidecarStatus sidecar_log_claim_foreach(SidecarLog *log,
                                        SidecarClaimCallback callback,
                                        void *context);
int sidecar_log_find_deleted(const SidecarLog *log, SidecarBytes root_id,
                             SidecarBytes logical_path, SidecarLiveView *out);
int sidecar_log_find_claim(const SidecarLog *log, SidecarBytes root_id,
                           SidecarBytes logical_path, SidecarClaimView *out);

#ifdef SIDECAR_TEST_HOOKS
typedef enum {
    SIDECAR_TEST_INTERRUPT_NONE = 0,
    SIDECAR_TEST_BEFORE_ENTRY,
    SIDECAR_TEST_AFTER_ENTRY,
    SIDECAR_TEST_MID_ENTRY,
    SIDECAR_TEST_BEFORE_XATTR,
    SIDECAR_TEST_AFTER_XATTR,
    SIDECAR_TEST_MID_XATTR,
    SIDECAR_TEST_BEFORE_ENTRY_COMMIT,
    SIDECAR_TEST_AFTER_ENTRY_COMMIT,
    SIDECAR_TEST_MID_ENTRY_COMMIT,
    SIDECAR_TEST_BEFORE_DELETE,
    SIDECAR_TEST_AFTER_DELETE,
    SIDECAR_TEST_MID_DELETE,
    SIDECAR_TEST_BEFORE_CLAIM,
    SIDECAR_TEST_AFTER_CLAIM,
    SIDECAR_TEST_MID_CLAIM
} SidecarTestInterruptPoint;

void sidecar_test_set_interrupt(SidecarTestInterruptPoint point);
#endif

#endif
