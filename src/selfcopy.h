#ifndef SELFCOPY_H
#define SELFCOPY_H

#include <stddef.h>

#define MIGR_ARCH_MAX 16

typedef enum {
    MIGR_STATIC_OK = 0,
    MIGR_STATIC_NOT_FOUND,
    MIGR_STATIC_NOT_ELF,
    MIGR_STATIC_NOT_STATIC,
    MIGR_STATIC_UNKNOWN_ARCH,
    MIGR_STATIC_IO_ERROR
} MigrStaticStatus;

/*
 * Validates an already-open candidate without changing its file offset.
 * The descriptor remains owned by the caller on every return path.
 */
MigrStaticStatus migr_static_validate_fd(int fd, char *arch_out,
                                         size_t arch_size);

/*
 * Locates migr-static beside the running executable and validates it.
 * On success, *out_fd is an O_RDONLY descriptor owned by the caller and
 * arch_out contains a NUL-terminated architecture name. On failure,
 * *out_fd is -1 and no descriptor is left open.
 */
MigrStaticStatus migr_static_probe(int *out_fd, char *arch_out,
                                   size_t arch_size);

#endif
