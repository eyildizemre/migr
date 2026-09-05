#ifndef REPORT_H
#define REPORT_H

#include <stddef.h>

#include "backup.h"

typedef enum {
    REPORT_DEPTH_DEFAULT,
    REPORT_DEPTH_LIMITED
} ReportDepthKind;

typedef struct {
    ReportDepthKind kind;
    size_t value;
} ReportDepth;

/**
 * @brief Prints a formatted backup analysis report to stdout.
 *
 * Measures the roots returned by backup_plan_build() for the selected mode.
 * summary suppresses all presentation except the scoped total on one line.
 * A limited depth requests verbose breakdown output; the default depth is one
 * level when verbose output is enabled.
 *
 * @param mode            BACKUP_CRITICAL or BACKUP_COMPREHENSIVE.
 * @param summary         Whether to print only the scoped total.
 * @param depth           Report breakdown depth selected by the caller.
 * @return 0 on success, 1 if planning or measurement fails or HOME is unset.
 */
int report(BackupMode mode, int summary, ReportDepth depth);

#endif
