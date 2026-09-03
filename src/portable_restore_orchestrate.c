#define _GNU_SOURCE

#include "portable_restore_replay_internal.h"
#include "portable_restore.h"
#include "backup.h"
#include "fsprobe.h"
#include "metadata.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>

static void portable_restore_preview(
    const PortableRestorePreflightReport *report)
{
    if (report == NULL)
        return;
    printf("Portable restore dry run: %zu live entr%s would be applied\n",
           report->live_count, report->live_count == 1 ? "y" : "ies");
    if (report->profiles.security_xattr_entry_count != 0)
        printf("  %zu item(s) carry security.* attributes; whether they can "
               "be applied here is measured, not predicted, and is only "
               "found out on a live run\n",
               report->profiles.security_xattr_entry_count);
    for (size_t index = 0; index < report->root_count; index++)
        if (report->roots[index].live_count != 0)
            printf("  root %s: %zu live entr%s\n",
                   report->roots[index].id,
                   report->roots[index].live_count,
                   report->roots[index].live_count == 1 ? "y" : "ies");
}

static int portable_restore_confirm(size_t security_xattr_entries)
{
    const char *ordinary_message =
        "This will restore portable files to the destination. Continue?";
    if (security_xattr_entries == 0)
        return confirm_action(ordinary_message);

    char message[768];
    int length = snprintf(
        message, sizeof(message),
        "This restore includes %zu item(s) carrying security.* attributes "
        "(e.g. SELinux labels); if this destination or account cannot "
        "apply one, that item's other content and metadata will still be "
        "restored and only the attribute will be skipped. Continue?",
        security_xattr_entries);
    if (length < 0 || (size_t)length >= sizeof(message))
        return confirm_action(
            "This restore includes security.* attributes; an attribute "
            "that cannot be applied will be skipped while the item's other "
            "content and metadata are restored. Continue?");
    return confirm_action(message);
}

static PortableRestoreOutcome portable_restore_orchestrate_impl(
    const PortableRestoreRequest *request,
    PortableRestoreReplayReport *report,
    int measure_policy)
{
    portable_restore_replay_report_init(report);
    if (request == NULL || report == NULL || request->source_container_fd < 0 ||
        request->destination_home_fd < 0 || request->manifest == NULL)
    {
        errno = EINVAL;
        return PORTABLE_RESTORE_ERROR;
    }

    PortableRestoreRequest replay_request = *request;
    MetadataTimestampPolicy policy;
    if (!measure_policy && replay_timestamp_policy(request, &policy) != 0)
        return PORTABLE_RESTORE_ERROR;
    PortableRestorePreflightReport preflight;
    portable_restore_preflight_report_init(&preflight);
    int result = portable_restore_preflight_at(request, &preflight);
    if (result != 0)
    {
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_ERROR;
    }

    const char *destination_home = request->destination_home_path != NULL
        ? request->destination_home_path : "destination home";
    if (restore_space_preflight(request->destination_home_fd, destination_home,
                                preflight.estimated_bytes,
                                preflight.estimated_bytes < 0) != 0)
    {
        report->live_count = preflight.live_count;
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_ERROR;
    }

    if (dry_run)
    {
        report->live_count = preflight.live_count;
        portable_restore_preview(&preflight);
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_DRY_RUN;
    }

    metadata_profiles_report(&preflight.profiles);
    if (!portable_restore_confirm(
            preflight.profiles.security_xattr_entry_count))
    {
        printf("Cancelled.\n");
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_CANCELLED;
    }

    if (measure_policy)
    {
        int nsec_exact = 0;
        if (fsprobe_timestamps_fd(request->destination_home_fd,
                                  &nsec_exact) != 0)
        {
            report->live_count = preflight.live_count;
            fflush(stdout);
            print_error("Error: could not measure destination timestamp support; "
                   "no destination was changed\n");
            portable_restore_preflight_report_free(&preflight);
            return PORTABLE_RESTORE_ERROR;
        }
        policy = (MetadataTimestampPolicy){
            .nsec_exact = nsec_exact,
            .configured = 1
        };
        replay_request.destination_timestamp_policy = policy;
    }

    if (metadata_profiles_probe(&preflight.profiles, policy) != 0)
    {
        report->live_count = preflight.live_count;
        fflush(stdout);
        print_error("Error: portable metadata probe failed; no destination was changed\n");
        portable_restore_preflight_report_free(&preflight);
        return PORTABLE_RESTORE_ERROR;
    }

    result = portable_restore_replay_at(&replay_request, report);
    if (result != 0)
        printf("Portable restore stopped: %zu applied, %zu failed\n",
               report->applied_count, report->failed_count);
    portable_restore_preflight_report_free(&preflight);
    return result == 0 ? PORTABLE_RESTORE_COMPLETE : PORTABLE_RESTORE_ERROR;
}

PortableRestoreOutcome portable_restore_orchestrate_at(
    const PortableRestoreRequest *request,
    PortableRestoreReplayReport *report)
{
    return portable_restore_orchestrate_impl(request, report, 1);
}

int portable_restore_at(const PortableRestoreRequest *request,
                        PortableRestoreReplayReport *report)
{
    PortableRestoreOutcome outcome =
        portable_restore_orchestrate_impl(request, report, 0);
    if (outcome == PORTABLE_RESTORE_COMPLETE)
    {
        printf("Portable restore complete: %zu applied\n",
               report->applied_count);
        if (report->skipped_security_xattr_count != 0)
            printf("Portable restore skipped %zu security.* attribute(s) "
                   "that the destination could not apply\n",
                   report->skipped_security_xattr_count);
    }
    return outcome == PORTABLE_RESTORE_ERROR ? -1 : 0;
}
