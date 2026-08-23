#ifndef REPORT_H
#define REPORT_H

#include "backup.h"

/**
 * @brief Prints a formatted backup analysis report to stdout.
 *
 * With scope_requested clear, preserves the legacy report: it scans HOME for
 * main user directories, dotfiles and config, developer tool caches, and
 * browser profiles, then prints the legacy critical estimate. With a scope
 * requested, measures the roots returned by backup_plan_build() for mode.
 * summary suppresses all presentation except the scoped total on one line.
 *
 * @param mode             BACKUP_CRITICAL or BACKUP_COMPREHENSIVE for scoped
 *                         reporting; ignored by the legacy path.
 * @param scope_requested Whether a backup scope was explicitly or implicitly
 *                         requested.
 * @param summary         Whether to print only the scoped total.
 * @return 0 on success, 1 if the HOME environment variable is not set.
 */
int report(BackupMode mode, int scope_requested, int summary);

#endif
