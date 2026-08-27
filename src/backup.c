#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#include "backup.h"
#include "backup_plan.h"
#include "container.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "metadata.h"
#include "packages.h"
#include "portable.h"
#include "utils.h"

#ifdef BACKUP_TEST_HOOKS
static BackupTestInventoryHook backup_test_inventory_hook;
static void *backup_test_inventory_context;
static BackupTestFreeSpaceHook backup_test_free_space_hook;
static void *backup_test_free_space_context;
static BackupTestBlockSizeHook backup_test_block_size_hook;
static void *backup_test_block_size_context;
static BackupTestProgressHook backup_test_progress_hook;
static void *backup_test_progress_context;

void backup_test_set_inventory_hook(BackupTestInventoryHook hook,
                                    void *context)
{
    backup_test_inventory_hook = hook;
    backup_test_inventory_context = context;
}

void backup_test_set_free_space_hook(BackupTestFreeSpaceHook hook,
                                     void *context)
{
    backup_test_free_space_hook = hook;
    backup_test_free_space_context = context;
}

void backup_test_set_block_size_hook(BackupTestBlockSizeHook hook,
                                     void *context)
{
    backup_test_block_size_hook = hook;
    backup_test_block_size_context = context;
}

void backup_test_set_progress_hook(BackupTestProgressHook hook,
                                   void *context)
{
    backup_test_progress_hook = hook;
    backup_test_progress_context = context;
}

static void backup_test_before_source_open(const char *source_path)
{
    if (backup_test_inventory_hook != NULL)
        backup_test_inventory_hook(source_path, backup_test_inventory_context);
}
#endif

int destination_block_size(int dest_fd, off_t *block_size)
{
    if (dest_fd < 0 || block_size == NULL)
        return -1;

#ifdef BACKUP_TEST_HOOKS
    if (backup_test_block_size_hook != NULL)
    {
        *block_size = 0;
        backup_test_block_size_hook(block_size,
                                    backup_test_block_size_context);
        return 0;
    }
#endif

    struct statfs fs;
    if (fstatfs(dest_fd, &fs) != 0)
        return -1;

    uintmax_t selected = (uintmax_t)(fs.f_frsize != 0
                                         ? fs.f_frsize : fs.f_bsize);
    if (selected == 0 || selected > (uintmax_t)INTMAX_MAX)
        return -1;
    *block_size = (off_t)selected;
    return 0;
}

// Returns 1 when the destination has at least `needed` bytes available, 0
// when it clearly does not, and -1 when the filesystem space cannot be read.
// f_bavail is the space this unprivileged process can actually consume;
// f_bfree also includes blocks reserved for root.
int destination_has_space(int dest_fd, off_t needed, off_t *free_bytes)
{
    if (dest_fd < 0 || needed < 0 || free_bytes == NULL)
        return -1;

#ifdef BACKUP_TEST_HOOKS
    if (backup_test_free_space_hook != NULL)
    {
        *free_bytes = 0;
        backup_test_free_space_hook(needed, free_bytes,
                                    backup_test_free_space_context);
        if (*free_bytes < 0)
            return -1;
        return needed <= *free_bytes;
    }
#endif

    off_t block_size = 0;
    if (destination_block_size(dest_fd, &block_size) != 0 || block_size <= 0)
        return -1;

    struct statfs fs;
    if (fstatfs(dest_fd, &fs) != 0)
        return -1;

    uintmax_t blocks = (uintmax_t)fs.f_bavail;
    uintmax_t allocation_size = (uintmax_t)block_size;
    if (blocks > UINTMAX_MAX / allocation_size)
        return -1;

    uintmax_t available = blocks * allocation_size;
    *free_bytes = available > (uintmax_t)INTMAX_MAX
        ? (off_t)INTMAX_MAX
        : (off_t)available;
    return needed <= *free_bytes;
}

/* Reads only the destination's current free space -- the progress display's
 * use case, which has no "needed" amount to compare against.
 */
static int destination_free_bytes(int dest_fd, off_t *free_bytes)
{
    return destination_has_space(dest_fd, 0, free_bytes) < 0 ? -1 : 0;
}

/* Returns 0 to proceed (space is adequate, or an earlier probe/estimate
 * step failed and already printed its own warning), or -1 if the
 * destination does not have enough free space (having already printed the
 * shortfall error). The caller is responsible for its own cleanup and
 * return value in that case.
 */
static int backup_space_preflight(int dest_fd, off_t estimated_size,
                                  off_t raw_estimated_size,
                                  int estimate_had_error,
                                  int raw_estimate_had_error,
                                  const char *target)
{
    if (estimate_had_error || raw_estimate_had_error)
    {
        print_warning("Warning: could not fully estimate backup size; "
                      "skipping the free-space preflight check.\n");
        return 0;
    }

    off_t free_bytes = 0;
    int has_space = destination_has_space(dest_fd, estimated_size,
                                          &free_bytes);
    if (has_space < 0)
    {
        print_warning("Warning: could not determine destination free space; "
                      "skipping the free-space preflight check.\n");
        return 0;
    }

    char estimated_text[32];
    char free_text[32];
    format_size(raw_estimated_size, estimated_text, sizeof(estimated_text));
    format_size(free_bytes, free_text, sizeof(free_text));
    printf("Estimated backup size: %s\n", estimated_text);
    printf("Destination free space: %s\n", free_text);
    printf("\n");

    if (!has_space)
    {
        off_t shortfall = estimated_size - free_bytes;
        char shortfall_text[32];
        format_size(shortfall, shortfall_text, sizeof(shortfall_text));
        print_error("Error: not enough free space at %s (need %s more)\n",
                    target, shortfall_text);
        return -1;
    }
    return 0;
}

/* Returns 0 to proceed (*out_profile and *out_repr are set), or -1 if the
 * destination could not be probed or is not usable for backup (having already
 * printed the refusal error). The caller is responsible for its own cleanup
 * and return value in that case.
 */
static int backup_representation_preflight(int dest_fd, const char *target,
                                           FsCapabilityProfile *out_profile,
                                           CloneRepresentation *out_repr)
{
    const char *refusal = NULL;
    if (fsprobe_fd(dest_fd, out_profile) != 0)
        refusal = "could not probe the destination filesystem at";
    else if (select_representation(out_profile, out_repr) != 0)
        refusal = "the destination filesystem is not usable for backup at";

    if (refusal != NULL)
    {
        print_error("Error: %s %s\n", refusal, target);
        return -1;
    }
    return 0;
}

typedef struct {
    off_t estimated_total_bytes;
    int data_fd;
    int printed_anything;
    struct timespec started_at;
    struct timespec last_sample_time;
    off_t last_sample_bytes;
} BackupProgressDisplay;

static off_t progress_speed(off_t bytes_copied, off_t last_sample_bytes,
                            double sample_seconds)
{
    if (!isfinite(sample_seconds) || sample_seconds <= 0.0 ||
        bytes_copied <= last_sample_bytes)
        return 0;

    off_t delta = bytes_copied - last_sample_bytes;
    double speed = (double)delta / sample_seconds;
    if (!isfinite(speed) || speed <= 0.0)
        return 0;
    if (speed >= (double)INTMAX_MAX)
        return (off_t)INTMAX_MAX;
    return (off_t)speed;
}

static long progress_elapsed_whole_seconds(double elapsed_seconds)
{
    if (!isfinite(elapsed_seconds) || elapsed_seconds <= 0.0)
        return 0;
    if (elapsed_seconds >= (double)LONG_MAX)
        return LONG_MAX;
    return (long)elapsed_seconds;
}

static void backup_report_progress(off_t bytes_copied,
                                   const char *current_path,
                                   void *userdata)
{
    BackupProgressDisplay *display = userdata;
    if (display == NULL)
        return;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return;
    if (!display->printed_anything)
    {
        display->started_at = now;
        display->last_sample_time = now;
        display->last_sample_bytes = 0;
    }

    double elapsed_seconds = timespec_elapsed_seconds(&display->started_at,
                                                      &now);
    double sample_seconds = timespec_elapsed_seconds(
        &display->last_sample_time, &now);
    off_t speed_bytes = progress_speed(bytes_copied,
                                       display->last_sample_bytes,
                                       sample_seconds);

    char copied_text[32];
    char estimated_text[32];
    char free_text[32];
    char elapsed_text[32];
    char speed_text[32];
    format_size(bytes_copied, copied_text, sizeof(copied_text));
    if (display->estimated_total_bytes > 0)
        format_size(display->estimated_total_bytes, estimated_text,
                    sizeof(estimated_text));

    off_t free_bytes = 0;
    if (destination_free_bytes(display->data_fd, &free_bytes) == 0)
        format_size(free_bytes, free_text, sizeof(free_text));
    else
        snprintf(free_text, sizeof(free_text), "unknown");
    format_duration(progress_elapsed_whole_seconds(elapsed_seconds),
                    elapsed_text, sizeof(elapsed_text));
    format_size(speed_bytes, speed_text, sizeof(speed_text));
    const char *path_text = current_path != NULL && current_path[0] != '\0'
        ? current_path : "unknown";

    if (display->estimated_total_bytes > 0)
        printf("\rProgress: %s/%s copied, %s free, elapsed %s, speed %s/s, "
               "current: %s\033[K", copied_text, estimated_text, free_text,
               elapsed_text, speed_text, path_text);
    else
        printf("\rProgress: %s copied, %s free, elapsed %s, speed %s/s, "
               "current: %s\033[K", copied_text, free_text, elapsed_text,
               speed_text, path_text);

#ifdef BACKUP_TEST_HOOKS
    if (backup_test_progress_hook != NULL)
        backup_test_progress_hook(bytes_copied,
                                  display->estimated_total_bytes,
                                  current_path,
                                  backup_test_progress_context);
#endif
    fflush(stdout);
    display->last_sample_time = now;
    display->last_sample_bytes = bytes_copied;
    display->printed_anything = 1;
}

// Validate and, if needed, create the top-level backup destination.
// Sets *created only when THIS call made the directory, so a later refusal can
// roll back exactly what we created — never a pre-existing directory, and never
// one a racing process slipped in between our check and mkdir.
static int ensure_target_root(const char *path, int *created)
{
    *created = 0;

    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            print_error("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    if (errno != ENOENT)
    {
        // A real access failure (e.g. EACCES) must not masquerade as "absent";
        // otherwise dry-run would promise to create something it cannot reach.
        print_error("Error: Could not access %s\n", path);
        return 1;
    }

    if (dry_run)
    {
        printf("[dry-run] Would create directory: %s\n", path);
        return 0;
    }

    if (mkdir(path, 0755) == 0)
    {
        *created = 1;
        return 0;
    }
    if (errno == EEXIST)
    {
        // Lost a race: someone created the path between our stat and mkdir.
        // Accept it only if it is a directory, and never claim we made it.
        if (stat(path, &st) != 0)
        {
            print_error("Error: Could not access %s\n", path);
            return 1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            print_error("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    print_error("Error: Could not create directory %s\n", path);
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Source identity (docs/DECISIONS.md D15).                                  */
/* ------------------------------------------------------------------------- */

// Machine id plus uid is what proves two invocations are the same job, so an
// unreadable or malformed machine id is not fatal: the backup still runs, it
// just cannot adopt an existing partial, because a timestamp or scope label
// alone never proves identity. Anything the manifest writer would reject is
// treated as unavailable rather than written out and turned into a fatal
// manifest failure later.
static int read_machine_id(char *out, size_t out_size)
{
    static const char *const sources[] = {
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        NULL
    };

    for (int i = 0; sources[i] != NULL; i++)
    {
        FILE *f = fopen(sources[i], "r");
        if (f == NULL)
            continue;

        char line[MANIFEST_MACHINE_ID_MAX];
        char *read = fgets(line, sizeof(line), f);
        fclose(f);
        if (read == NULL)
            continue;

        line[strcspn(line, "\r\n")] = '\0';
        size_t len = strlen(line);
        if (len == 0 || len >= out_size)
            continue;

        int hex = 1;
        for (size_t c = 0; c < len; c++)
            if (!isxdigit((unsigned char)line[c]))
                hex = 0;
        if (!hex)
            continue;

        memcpy(out, line, len + 1);
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------------- */
/* Plan to manifest.                                                          */
/* ------------------------------------------------------------------------- */

// The manifest is production's resume identity, not a byproduct of it: this is
// the model container_adopt() matches against and the model that is written
// into the container. The root table is copied entry by entry into its own
// array — a BackupPlanRoot embeds a ManifestRoot but is larger, so the plan's
// roots are not a ManifestRoot[] and must never be handed to the manifest API
// as one.
static int manifest_from_plan(const BackupPlan *plan, Manifest *out)
{
    memset(out, 0, sizeof(*out));
    out->version = MANIFEST_CURRENT_VERSION;
    out->representation = CLONE_NATIVE_TREE; // replaced by the probe's verdict
    out->scope = plan->scope;
    out->sidecar_version = 0;
    out->root_count = plan->root_count;

    if (plan->root_count > 0)
    {
        out->roots = calloc((size_t)plan->root_count, sizeof(*out->roots));
        if (out->roots == NULL)
        {
            print_error("Error: out of memory building the backup manifest\n");
            return -1;
        }
        for (int i = 0; i < plan->root_count; i++)
            out->roots[i] = plan->roots[i].manifest_root;
    }

    char machine_id[MANIFEST_MACHINE_ID_MAX];
    if (read_machine_id(machine_id, sizeof(machine_id)) == 0)
    {
        memcpy(out->machine_id, machine_id, strlen(machine_id) + 1);
        out->source_uid = getuid();
        out->has_source_identity = 1;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Plan to portable capture request (docs/DECISIONS.md D24).                 */
/* ------------------------------------------------------------------------- */

// Mechanical field-by-field conversion: PortableRootSpec covers exactly what
// a BackupPlanRoot/ManifestRoot pair already carries. The returned entries
// borrow their strings from plan and remain valid while plan is unchanged.
static void portable_root_specs_from_plan(const BackupPlan *plan,
                                          PortableRootSpec *roots_out)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        roots_out[i] = (PortableRootSpec){
            .id = root->manifest_root.id,
            .policy = root->manifest_root.policy,
            .capture_path = root->capture_path,
            .payload_path = root->manifest_root.payload_path,
            .source_path = root->manifest_root.source_path,
            .restore_path = root->manifest_root.restore_path,
            .has_restore_path = root->manifest_root.has_restore_path
        };
    }
}

// The portable request mirrors manifest_from_plan()'s identity fields. All
// strings are borrowed from plan or machine_id and must outlive the request.
static int portable_capture_request_from_plan(
    const BackupPlan *plan, const char *machine_id, int has_machine_id,
    uid_t source_uid, int nsec_exact, int case_sensitive,
    PortableRootSpec *roots_storage, PortableCaptureRequest *out)
{
    if (plan == NULL || out == NULL ||
        (plan->root_count > 0 && roots_storage == NULL))
        return -1;

    if (plan->root_count > 0)
        portable_root_specs_from_plan(plan, roots_storage);
    *out = (PortableCaptureRequest){
        .scope = plan->scope,
        .has_source_identity = has_machine_id,
        .machine_id = has_machine_id ? machine_id : NULL,
        .source_uid = source_uid,
        .roots = plan->root_count > 0 ? roots_storage : NULL,
        .root_count = (size_t)plan->root_count,
        .nsec_exact = nsec_exact,
        .case_sensitive = case_sensitive
    };
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Container payload namespace.                                              */
/* ------------------------------------------------------------------------- */

// Every user-derived object lives below data/ (docs/DECISIONS.md D15), so the
// container root stays reserved for migr's own control artifacts. Opened with
// O_NOFOLLOW | O_DIRECTORY: in an adopted container this entry may already
// exist, and only a genuine directory is acceptable — a symlink there would
// otherwise place the whole payload outside the container.
static int open_data_dir(int container_fd)
{
    if (mkdirat(container_fd, "data", 0700) != 0 && errno != EEXIST)
        return -1;
    return openat(container_fd, "data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

/* ------------------------------------------------------------------------- */
/* Presentation.                                                              */
/* ------------------------------------------------------------------------- */

// Grouping is presentation only: it selects which heading a root prints under,
// never where its payload goes. That address is the manifest's payload_path.
static const struct {
    BackupRootGroup group;
    const char *heading;
} root_sections[] = {
    { BACKUP_ROOT_MAIN,     "Main Directories" },
    { BACKUP_ROOT_DOTFILE,  "Dotfiles" },
    { BACKUP_ROOT_BROWSER,  "Browser Profiles" },
    { BACKUP_ROOT_EXPLICIT, "Explicit Paths" },
};
enum { ROOT_SECTION_COUNT = sizeof(root_sections) / sizeof(root_sections[0]) };

static void preview_roots(const BackupPlan *plan, int *count)
{
    for (int s = 0; s < ROOT_SECTION_COUNT; s++)
    {
        int printed_heading = 0;
        for (int i = 0; i < plan->root_count; i++)
        {
            const BackupPlanRoot *root = &plan->roots[i];
            if (root->group != root_sections[s].group)
                continue;

            if (!printed_heading)
            {
                printf("\n%s\n", root_sections[s].heading);
                printed_heading = 1;
            }
            printf("  Would capture: %s -> data/%s\n",
                   root->capture_path, root->manifest_root.payload_path);
            (*count)++;
        }
    }
}

static void capture_roots(const CloneContext *ctx, const BackupPlan *plan, int data_fd,
                          int *count, int *had_error,
                          BackupCaptureReport *capture_report)
{
    for (int s = 0; s < ROOT_SECTION_COUNT; s++)
    {
        int printed_heading = 0;
        for (int i = 0; i < plan->root_count; i++)
        {
            const BackupPlanRoot *root = &plan->roots[i];
            if (root->group != root_sections[s].group)
                continue;

            if (!printed_heading)
            {
                printf("\n%s\n", root_sections[s].heading);
                printed_heading = 1;
            }
            if (verbose)
                printf("  Capturing: %s -> data/%s\n",
                       root->capture_path, root->manifest_root.payload_path);

            capture_report->failed_source_path[0] = '\0';
            BackupCaptureStatus capture_status = backup_capture_at_report_continue(
                ctx, root->capture_path, data_fd,
                root->manifest_root.payload_path, capture_report);
            if (capture_status != BACKUP_CAPTURE_OK)
            {
                if (capture_status == BACKUP_CAPTURE_SOURCE_SAFE_READ)
                {
                    const char *failed_source =
                        capture_report->failed_source_path[0] != '\0'
                            ? capture_report->failed_source_path
                            : root->capture_path;
                    print_source_safe_read_refusal(failed_source);
                }
                else
                    print_error("Error: Failed to capture %s\n", root->capture_path);
                *had_error = 1;
            }
            else
            {
                (*count)++;
            }
        }
    }
}

// A partial native capture may already contain one member of a hardlink group.
// Seed every existing, resume-matching destination before the live walk so the
// current root/readdir order cannot replace that earlier representative.
static int seed_native_hardlink_map(const CloneContext *ctx,
                                    const BackupPlan *plan, int data_fd)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        if (native_inode_map_seed_existing(ctx, root->capture_path, data_fd,
                                           root->manifest_root.payload_path) != 0)
            return -1;
    }
    return 0;
}

static void reconcile_roots(const void *visited, const BackupPlan *plan,
                            int data_fd, int *had_error)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        NativeReconcileReport report;
        if (native_reconcile_stale_at(
                visited, root->manifest_root.payload_path, data_fd,
                &report) != NATIVE_RECONCILE_OK)
        {
            if (report.failed_relative_path[0] != '\0')
                print_error("Error: Could not reconcile stale entries under data/%s (%s)\n",
                            root->manifest_root.payload_path,
                            report.failed_relative_path);
            else
                print_error("Error: Could not reconcile stale entries under data/%s\n",
                            root->manifest_root.payload_path);
            *had_error = 1;
        }
    }
}

static int metadata_existing_at(int root_fd, const char *rel,
                                struct stat *out, int *exists)
{
    *exists = 0;
    if (root_fd < 0)
        return 0;

    char copy[PATH_MAX];
    int n = snprintf(copy, sizeof(copy), "%s", rel);
    if (n < 0 || (size_t)n >= sizeof(copy))
        return -1;

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    char *component = copy;
    for (;;)
    {
        char *slash = strchr(component, '/');
        if (slash != NULL)
            *slash = '\0';
        if (component[0] == '\0' || strcmp(component, ".") == 0 ||
            strcmp(component, "..") == 0)
        {
            close(current);
            return -1;
        }

        int next = openat(current, component, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
        {
            int saved_errno = errno;
            close(current);
            if (saved_errno == ENOENT)
                return 0;
            errno = saved_errno;
            return -1;
        }
        close(current);
        if (slash == NULL)
        {
            int rc = fstat(next, out);
            int saved_errno = errno;
            close(next);
            if (rc != 0)
            {
                errno = saved_errno;
                return -1;
            }
            *exists = 1;
            return 0;
        }
        current = next;
        component = slash + 1;
    }
}

typedef struct {
    size_t refusal_count;
    size_t uninspected_subtree_count;
    size_t example_count;
    char examples[METADATA_MAX_PREFLIGHT_EXAMPLES][PATH_MAX];
} SourceReadRefusals;

static void source_read_refusals_init(SourceReadRefusals *refusals)
{
    if (refusals != NULL)
        memset(refusals, 0, sizeof(*refusals));
}

static void source_read_refusal_record(SourceReadRefusals *refusals,
                                       const char *source_path,
                                       int uninspected_subtree)
{
    if (refusals == NULL)
        return;
    if (refusals->refusal_count != SIZE_MAX)
        refusals->refusal_count++;
    if (uninspected_subtree &&
        refusals->uninspected_subtree_count != SIZE_MAX)
        refusals->uninspected_subtree_count++;
    if (source_path == NULL ||
        refusals->example_count >= METADATA_MAX_PREFLIGHT_EXAMPLES)
        return;

    int n = snprintf(refusals->examples[refusals->example_count],
                     sizeof(refusals->examples[0]), "%s", source_path);
    if (n >= 0 && (size_t)n < sizeof(refusals->examples[0]))
        refusals->example_count++;
}

static void source_read_refusals_report(const SourceReadRefusals *refusals)
{
    if (refusals == NULL || refusals->refusal_count == 0)
        return;

    print_error("Error: could not safely read %zu source object(s): the kernel "
           "refused the O_NOATIME open (ownership or CAP_FOWNER is "
           "required); no O_NOATIME-less retry was attempted.\n",
           refusals->refusal_count);
    for (size_t i = 0; i < refusals->example_count; i++)
        printf("  source-read example: %s\n", refusals->examples[i]);
    if (refusals->refusal_count > refusals->example_count)
        printf("  ... additional source-read refusals omitted\n");
    if (refusals->uninspected_subtree_count > 0)
        printf("  %zu source subtree(s) could not be inspected; their contents "
               "are unknown, not zero.\n",
               refusals->uninspected_subtree_count);
}

static int backup_metadata_inventory(const char *source_path, int anchor_fd,
                                     int destination_root_fd,
                                     const char *destination_rel,
                                     MetadataProfiles *profiles,
                                     SourceReadRefusals *refusals)
{
    struct stat source_st;
    if (lstat(source_path, &source_st) != 0)
        return -1;

    struct stat existing_st;
    int destination_exists = 0;
    if (metadata_existing_at(destination_root_fd, destination_rel,
                             &existing_st, &destination_exists) != 0)
        return -1;

    if (destination_exists &&
        ((S_ISDIR(source_st.st_mode) && !S_ISDIR(existing_st.st_mode)) ||
         (S_ISREG(source_st.st_mode) && !S_ISREG(existing_st.st_mode)) ||
         (S_ISFIFO(source_st.st_mode) && !S_ISFIFO(existing_st.st_mode))))
        return -1;

    if (!S_ISSOCK(source_st.st_mode) && !S_ISCHR(source_st.st_mode) &&
        !S_ISBLK(source_st.st_mode) &&
        metadata_profiles_add(profiles, anchor_fd, &source_st,
                              destination_exists ? &existing_st : NULL,
                              source_path) != 0)
        return -1;

    if (S_ISREG(source_st.st_mode))
    {
#ifdef BACKUP_TEST_HOOKS
        backup_test_before_source_open(source_path);
#endif
        int fd = open(source_path, O_RDONLY | O_NOFOLLOW | O_NOATIME |
                                      O_CLOEXEC);
        if (fd < 0)
        {
            if (errno == EPERM)
            {
                source_read_refusal_record(refusals, source_path, 0);
                return 0;
            }
            return -1;
        }
        struct stat opened;
        int failed = fstat(fd, &opened) != 0 ||
                     !metadata_source_unchanged(&source_st, &opened);
        if (close(fd) != 0)
            failed = 1;
        return failed ? -1 : 0;
    }

    if (!S_ISDIR(source_st.st_mode))
        return 0;

#ifdef BACKUP_TEST_HOOKS
    backup_test_before_source_open(source_path);
#endif
    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_NOATIME | O_CLOEXEC);
    if (source_fd < 0)
    {
        if (errno == EPERM)
        {
            source_read_refusal_record(refusals, source_path, 1);
            return 0;
        }
        return -1;
    }
    struct stat opened;
    if (fstat(source_fd, &opened) != 0 ||
        !metadata_source_unchanged(&source_st, &opened))
    {
        close(source_fd);
        return -1;
    }
    int scan_fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        close(source_fd);
        return -1;
    }

    int failed = 0;
    for (;;)
    {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
                failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char child_source[PATH_MAX];
        char child_destination[PATH_MAX];
        if (path_join(child_source, sizeof(child_source), source_path,
                      entry->d_name) != 0 ||
            path_join(child_destination, sizeof(child_destination),
                      destination_rel, entry->d_name) != 0 ||
            backup_metadata_inventory(child_source, anchor_fd,
                                      destination_root_fd, child_destination,
                                      profiles, refusals) != 0)
        {
            failed = 1;
            break;
        }
    }
    if (closedir(dir) != 0)
        failed = 1;
    if (!failed && (fstat(source_fd, &opened) != 0 ||
                    !metadata_source_unchanged(&source_st, &opened)))
        failed = 1;
    if (close(source_fd) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

static int backup_metadata_preflight(const BackupPlan *plan, int anchor_fd,
                                     int destination_root_fd,
                                     MetadataProfiles *profiles,
                                     SourceReadRefusals *refusals)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        if (backup_metadata_inventory(root->capture_path, anchor_fd,
                                      destination_root_fd,
                                      root->manifest_root.payload_path,
                                      profiles, refusals) != 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */

int backup(const char *target, BackupMode mode, char **paths)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        print_error("Error: Could not get HOME directory.\n");
        return 1;
    }

    // The plan is built before anything about the destination is even looked
    // at: it is read-only over the source side (never touches target, never
    // reads dry_run), so a rejected plan -- live or --dry-run alike -- never
    // creates or mutates anything (docs/DECISIONS.md D16).
    BackupPlan plan;
    if (backup_plan_build(home, mode, (const char *const *)paths, &plan) != 0)
        return 1;

    // Asked before the destination is created, probed or previewed, so a
    // destination inside a selected root is refused identically in a live run
    // and a dry run, with nothing written either way.
    if (backup_plan_destination_conflicts(&plan, target))
    {
        backup_plan_free(&plan);
        return 1;
    }

    Manifest manifest;
    if (manifest_from_plan(&plan, &manifest) != 0)
    {
        backup_plan_free(&plan);
        return 1;
    }

    off_t estimated_size = 0;
    int estimate_had_error = 0;
    off_t raw_estimated_size = 0;
    int raw_estimate_had_error = 0;

    int count = 0;

    if (dry_run)
    {
        // The destination is inspected exactly as a live run would inspect
        // it, including the real capability probe and portable pre-scan
        // (D24 I-6) -- but nothing beyond that: no container, no manifest,
        // no data/, no package export.
        int target_created = 0;
        if (ensure_target_root(target, &target_created) != 0)
        {
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }

        CloneRepresentation advisory_repr = CLONE_NATIVE_TREE;
        FsCapabilityProfile advisory_profile;
        MetadataProfiles advisory_profiles;
        metadata_profiles_init(&advisory_profiles);
        SourceReadRefusals advisory_refusals;
        source_read_refusals_init(&advisory_refusals);
        int advisory_fd = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int advisory_probe_failed = 0;
        if (advisory_fd >= 0)
        {
            off_t advisory_block_size = 0;
            (void)destination_block_size(advisory_fd, &advisory_block_size);
            backup_plan_estimate_size(&plan, advisory_block_size,
                                      &estimated_size, &estimate_had_error);
            backup_plan_estimate_size(&plan, 1, &raw_estimated_size,
                                      &raw_estimate_had_error);
            if (backup_space_preflight(advisory_fd, estimated_size,
                                       raw_estimated_size, estimate_had_error,
                                       raw_estimate_had_error, target) != 0)
            {
                close(advisory_fd);
                if (target_created)
                    rmdir(target);
                metadata_profiles_free(&advisory_profiles);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }

            advisory_probe_failed = backup_representation_preflight(
                advisory_fd, target, &advisory_profile, &advisory_repr) != 0;
        }
        if (advisory_probe_failed)
        {
            close(advisory_fd);
            if (target_created)
                rmdir(target);
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }

        if (advisory_fd >= 0)
        {
            int advisory_failed = backup_metadata_preflight(
                &plan, advisory_fd, -1, &advisory_profiles,
                &advisory_refusals) != 0;
            if (advisory_refusals.refusal_count > 0)
            {
                source_read_refusals_report(&advisory_refusals);
                print_error("Error: native metadata preflight refused the source; "
                       "no container was created\n");
                close(advisory_fd);
                metadata_profiles_free(&advisory_profiles);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }
            if (advisory_failed)
                print_warning("Warning: could not complete the read-only metadata preview; "
                       "the live backup will recheck it before writing.\n");
            else
            {
                metadata_profiles_report(&advisory_profiles);
                // The ownership probe is privilege-relevant and native-only;
                // portable capture has no analogous native ownership step.
                if (advisory_repr == CLONE_NATIVE_TREE &&
                    metadata_profiles_probe(
                        &advisory_profiles,
                        (MetadataTimestampPolicy){ .nsec_exact = 0,
                                                    .configured = 1 }) != 0)
                    print_warning("Warning: the ownership probe could not complete; "
                           "the live backup will recheck it before writing.\n");
            }
        }

        PortablePrescanReport advisory_prescan = {0};
        int has_advisory_prescan = 0;
        if (advisory_fd >= 0 && advisory_repr == CLONE_PORTABLE_SIDECAR)
        {
            PortableRootSpec *advisory_roots = plan.root_count > 0
                ? calloc((size_t)plan.root_count, sizeof(*advisory_roots))
                : NULL;
            if (plan.root_count > 0 && advisory_roots == NULL)
            {
                print_error("Error: out of memory building the portable capture preview\n");
                close(advisory_fd);
                metadata_profiles_free(&advisory_profiles);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }
            char advisory_machine_id[MANIFEST_MACHINE_ID_MAX];
            int advisory_has_machine_id = read_machine_id(
                advisory_machine_id, sizeof(advisory_machine_id)) == 0;
            PortableCaptureRequest advisory_request;
            int request_result = portable_capture_request_from_plan(
                &plan, advisory_machine_id, advisory_has_machine_id, getuid(),
                advisory_profile.nsec_exact,
                advisory_profile.capabilities[FS_CAP_CASE_SENSITIVE].status ==
                    FS_CAP_SUPPORTED,
                advisory_roots, &advisory_request);
            PortablePreparedCapture advisory_prepared = {0};
            int prepare_result = request_result == 0
                ? portable_capture_prepare(advisory_fd, &advisory_request,
                                            &advisory_prepared)
                : -1;
            free(advisory_roots);
            if (prepare_result != 0)
            {
                portable_prepared_capture_free(&advisory_prepared);
                print_error("Error: portable pre-scan failed or found an unresolvable "
                       "conflict at %s; nothing would be created\n", target);
                close(advisory_fd);
                metadata_profiles_free(&advisory_profiles);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }
            advisory_prescan = advisory_prepared.report;
            memset(&advisory_prepared.report, 0,
                   sizeof(advisory_prepared.report));
            has_advisory_prescan = 1;
            portable_prepared_capture_free(&advisory_prepared);
        }
        metadata_profiles_free(&advisory_profiles);
        if (advisory_fd >= 0)
            close(advisory_fd);

        printf("Dry run mode enabled. No changes will be made.\n\n");
        printf("Would create a versioned backup container under: %s\n", target);
        printf("  Its migr_backup_<timestamp> name is chosen when the backup actually runs.\n");

        preview_roots(&plan, &count);

        if (has_advisory_prescan)
        {
            printf("\nDestination cannot hold Linux metadata natively; a portable "
                   "sidecar representation would be used.\n");
            if (advisory_prescan.unresolved_count > 0)
                printf("  %zu naming conflict(s) found; the live run would refuse.\n",
                       advisory_prescan.unresolved_count);
            portable_prescan_report_free(&advisory_prescan);
        }

        printf("\nControls\n");
        printf("  Would write manifest.txt\n");
        if (mode != BACKUP_EXPLICIT_PATHS)
            printf("  Would export package list to packages.txt\n");

        printf("\n");
        printf("Dry run complete: %d items would be copied\n", count);

        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 0;
    }

    int target_created = 0;
    if (ensure_target_root(target, &target_created) != 0)
    {
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    int target_fd = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (target_fd < 0)
    {
        print_error("Error: Could not open backup destination %s\n", target);
        if (target_created) rmdir(target);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    off_t target_block_size = 0;
    (void)destination_block_size(target_fd, &target_block_size);
    backup_plan_estimate_size(&plan, target_block_size,
                              &estimated_size, &estimate_had_error);
    backup_plan_estimate_size(&plan, 1, &raw_estimated_size,
                              &raw_estimate_had_error);

    if (backup_space_preflight(target_fd, estimated_size, raw_estimated_size,
                               estimate_had_error, raw_estimate_had_error,
                               target) != 0)
    {
        close(target_fd);
        if (target_created)
            rmdir(target);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    // Probe the destination and choose a representation before any container
    // exists. An unreliable probe is fatal, never a silent fall-through. If we
    // created the destination root this run and then refuse, roll it back so a
    // rejected attempt leaves nothing behind.
    CloneRepresentation repr = CLONE_NATIVE_TREE;
    FsCapabilityProfile profile;
    if (backup_representation_preflight(target_fd, target, &profile, &repr) != 0)
    {
        close(target_fd);
        if (target_created) rmdir(target);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    // The representation is part of the resume identity, so it must be settled
    // before the manifest is matched against an existing partial.
    manifest.representation = repr;

    PortablePreparedCapture prepared = {0};
    PortableRootSpec *portable_roots = NULL;
    PortableCaptureRequest portable_request = {0};
    char portable_machine_id[MANIFEST_MACHINE_ID_MAX];
    if (repr == CLONE_PORTABLE_SIDECAR)
    {
        if (plan.root_count > 0)
        {
            portable_roots = calloc((size_t)plan.root_count,
                                    sizeof(*portable_roots));
            if (portable_roots == NULL)
            {
                print_error("Error: out of memory building the portable capture request\n");
                close(target_fd);
                if (target_created)
                    rmdir(target);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }
        }
        int has_machine_id = read_machine_id(portable_machine_id,
                                             sizeof(portable_machine_id)) == 0;
        if (portable_capture_request_from_plan(
                &plan, portable_machine_id, has_machine_id, getuid(),
                profile.nsec_exact,
                profile.capabilities[FS_CAP_CASE_SENSITIVE].status ==
                    FS_CAP_SUPPORTED,
                portable_roots, &portable_request) != 0 ||
            portable_capture_prepare(target_fd, &portable_request,
                                     &prepared) != 0)
        {
            int has_manual_native = 0;
            for (int i = 0; i < plan.root_count; i++)
                if (plan.roots[i].manifest_root.policy ==
                    ROOT_POLICY_MANUAL_NATIVE)
                    has_manual_native = 1;
            if (has_manual_native)
                print_error("Error: %s cannot hold Linux metadata natively, and portable "
                       "capture cannot carry an external (manual-native) root's "
                       "restore address; move or drop the external path(s) to "
                       "back up here.\n", target);
            else
                print_error("Error: portable pre-scan failed or found an unresolvable "
                       "conflict at %s; no container was created\n", target);
            portable_prepared_capture_free(&prepared);
            free(portable_roots);
            close(target_fd);
            if (target_created)
                rmdir(target);
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }
    }
    const Manifest *identity_manifest = repr == CLONE_PORTABLE_SIDECAR
        ? &prepared.manifest : &manifest;

    MetadataProfiles metadata_profiles;
    metadata_profiles_init(&metadata_profiles);
    SourceReadRefusals source_read_refusals;
    source_read_refusals_init(&source_read_refusals);
    BackupContainer container = {0};
    int adopted = 0;
    ContainerStatus adopt_status = container_adopt_fd(target_fd, identity_manifest,
                                                      &container);
    if (adopt_status == CONTAINER_OK)
    {
        adopted = 1;
        int adopted_data_fd = openat(container_root_fd(&container), "data",
                                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_CLOEXEC);
        int metadata_failed = 0;
        if (repr == CLONE_NATIVE_TREE)
        {
            metadata_failed = adopted_data_fd < 0;
            if (!metadata_failed)
                metadata_failed = backup_metadata_preflight(
                    &plan, adopted_data_fd, adopted_data_fd,
                    &metadata_profiles, &source_read_refusals) != 0;
            if (source_read_refusals.refusal_count > 0)
                metadata_failed = 1;
            if (!metadata_failed)
            {
                metadata_profiles_report(&metadata_profiles);
                metadata_failed = metadata_profiles_probe(
                    &metadata_profiles,
                    (MetadataTimestampPolicy){ .nsec_exact = 0,
                                                .configured = 1 }) != 0;
            }
            if (metadata_failed)
            {
                if (adopted_data_fd >= 0)
                    close(adopted_data_fd);
                if (source_read_refusals.refusal_count > 0)
                {
                    source_read_refusals_report(&source_read_refusals);
                    print_error("Error: native metadata preflight refused the source; "
                           "no payload was changed\n");
                }
                else
                    print_error("Error: native metadata preflight failed; no payload was changed\n");
                container_close(&container);
                metadata_profiles_free(&metadata_profiles);
                portable_prepared_capture_free(&prepared);
                free(portable_roots);
                close(target_fd);
                if (target_created)
                    rmdir(target);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }
        }
        if (adopted_data_fd >= 0)
            close(adopted_data_fd);
    }
    else if (adopt_status == CONTAINER_ERR_NO_MATCH)
    {
        int metadata_failed = 0;
        if (repr == CLONE_NATIVE_TREE)
        {
            metadata_failed = backup_metadata_preflight(
                &plan, target_fd, -1, &metadata_profiles,
                &source_read_refusals) != 0;
            if (source_read_refusals.refusal_count > 0)
                metadata_failed = 1;
            if (!metadata_failed)
            {
                metadata_profiles_report(&metadata_profiles);
                metadata_failed = metadata_profiles_probe(
                    &metadata_profiles,
                    (MetadataTimestampPolicy){ .nsec_exact = 0,
                                                .configured = 1 }) != 0;
            }
            if (metadata_failed)
            {
                if (source_read_refusals.refusal_count > 0)
                {
                    source_read_refusals_report(&source_read_refusals);
                    print_error("Error: native metadata preflight refused the source; "
                           "no container was created\n");
                }
                else
                    print_error("Error: native metadata preflight failed; no container was created\n");
                metadata_profiles_free(&metadata_profiles);
                portable_prepared_capture_free(&prepared);
                free(portable_roots);
                close(target_fd);
                if (target_created)
                    rmdir(target);
                manifest_free(&manifest);
                backup_plan_free(&plan);
                return 1;
            }
        }
        if (container_reserve_fd(target_fd, time(NULL), &container) != CONTAINER_OK)
        {
            print_error("Error: Could not create a backup container under %s\n", target);
            metadata_profiles_free(&metadata_profiles);
            portable_prepared_capture_free(&prepared);
            free(portable_roots);
            close(target_fd);
            if (target_created)
                rmdir(target);
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }
    }
    else
    {
        if (adopt_status == CONTAINER_ERR_AMBIGUOUS)
            print_error("Error: more than one interrupted backup under %s matches this job; "
                   "resuming would be a guess. Remove or move the ones you do not want.\n",
                   target);
        else
            print_error("Error: could not examine existing backups under %s\n", target);
        metadata_profiles_free(&metadata_profiles);
        portable_prepared_capture_free(&prepared);
        free(portable_roots);
        close(target_fd);
        if (target_created)
            rmdir(target);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }
    close(target_fd);

    int container_fd = container_root_fd(&container);
    int had_error = 0;
    // A partial is only worth resuming if its manifest proves which job it
    // belongs to. A fresh container whose manifest never got written can never
    // be adopted, so it must not be reported as resumable.
    int resumable = 1;

    // A fresh container gets its manifest before any payload: it is the format
    // discriminator, the representation record and the root table, so a
    // container without one is not a v1 container at all. An adopted one
    // already carries a manifest that was read back and matched during
    // adoption; rewriting it would truncate proven-good state for no gain.
    if (!adopted && repr == CLONE_NATIVE_TREE &&
        manifest_write_v1_at(container_fd, identity_manifest) != 0)
    {
        print_error("Error: Could not write manifest.txt into the backup container\n");
        had_error = 1;
        resumable = 0;
    }

    int data_fd = -1;
    if (!had_error)
    {
        data_fd = open_data_dir(container_fd);
        if (data_fd < 0)
        {
            print_error("Error: Could not open the container's data/ directory\n");
            had_error = 1;
        }
    }

    if (!had_error)
    {
        printf("Backing up to: %s/%s\n", target, container_current_name(&container));
        if (adopted)
            printf("Resuming an interrupted backup of the same job.\n");
        printf("\n");

        BackupCaptureReport capture_report;
        backup_capture_report_init(&capture_report);
        capture_report.sync_interval_bytes = BACKUP_SYNC_INTERVAL_BYTES;
        BackupProgressDisplay progress_display = {
            .estimated_total_bytes = estimate_had_error || raw_estimate_had_error
                ? 0 : raw_estimated_size,
            .data_fd = data_fd
        };
        int progress_installed = 0;
        int progress_force = 0;
#ifdef BACKUP_TEST_HOOKS
        progress_force = backup_test_progress_hook != NULL;
#endif
        if (!estimate_had_error && !raw_estimate_had_error &&
            (isatty(fileno(stdout)) || progress_force))
        {
            capture_report.progress_cb = backup_report_progress;
            capture_report.progress_userdata = &progress_display;
            capture_report.progress_unthrottled = progress_force;
            progress_installed = 1;
        }

        if (repr == CLONE_NATIVE_TREE)
        {
            CloneContext ctx = {
                .operation = CLONE_BACKUP,
                .representation = repr,
                .timestamp_policy_configured = 1,
                .nsec_exact = profile.nsec_exact,
                .metadata_preflight_done = 1,
                .inode_map = native_inode_map_create(),
                .visited = native_visited_create()
            };
            if (ctx.inode_map == NULL || ctx.visited == NULL)
            {
                print_error("Error: Could not initialize native hardlink/resume tracking\n");
                native_inode_map_free(ctx.inode_map);
                native_visited_free(ctx.visited);
                had_error = 1;
            }
            else
            {
                if (adopted && seed_native_hardlink_map(&ctx, &plan, data_fd) != 0)
                {
                    print_error("Error: Could not seed native hardlink/resume tracking\n");
                    had_error = 1;
                }
                if (!had_error)
                    capture_roots(&ctx, &plan, data_fd, &count, &had_error,
                                  &capture_report);
                if (!had_error)
                    reconcile_roots(ctx.visited, &plan, data_fd, &had_error);
                native_inode_map_free(ctx.inode_map);
                ctx.inode_map = NULL;
                native_visited_free(ctx.visited);
                ctx.visited = NULL;
            }
        }
        else
        {
            size_t live_count = 0;
            int capture_result = adopted
                ? portable_capture_resume_prepared_at(
                      container_fd, &portable_request, &prepared, &live_count,
                      &capture_report)
                : portable_capture_fresh_prepared_at(
                      container_fd, &portable_request, &prepared, &live_count,
                      &capture_report);
            if (capture_result != 0)
            {
                print_error("Error: portable capture failed\n");
                had_error = 1;
            }
            else
            {
                count = (int)live_count;
            }
        }

        if (progress_installed && progress_display.printed_anything)
        {
            capture_report.progress_cb(capture_report.bytes_copied,
                                       capture_report.current_path,
                                       capture_report.progress_userdata);
            putchar('\n');
            fflush(stdout);
        }
        close(data_fd);

        // packages.txt is a migr-owned control artifact, not a payload root, so
        // it stays at the container root. Restore acts on whichever one it
        // finds without re-deriving the backup's scope, so this slot must
        // always end up matching this invocation: a fresh list for a scope that
        // exports one, and demonstrably empty for a scope that does not.
        // Anything else -- a stale list inside an adopted container, or one
        // planted there -- would otherwise be published and later replayed.
        if (mode == BACKUP_EXPLICIT_PATHS)
        {
            if (packages_clear_at(container_fd, "packages.txt") != 0)
            {
                print_error("Error: could not clear packages.txt from the backup container\n");
                had_error = 1;
            }
        }
        else
        {
            printf("\nPackages\n");
            // A missing package list is tolerable and has always been a
            // warning; a control slot that could not be made safe is not.
            int pkg = packages_at(container_fd, "packages.txt");
            if (pkg < 0)
            {
                print_error("Error: could not clear packages.txt from the backup container\n");
                had_error = 1;
            }
            else if (pkg > 0)
            {
                print_warning("  Warning: no package list was written for this backup.\n");
            }
        }
    }

    printf("\n");

    if (had_error)
    {
        // Nothing is published: an incomplete container must never look
        // complete.
        printf("Backup finished with errors: %d items copied, some items failed\n", count);
        if (resumable)
            printf("Incomplete backup kept for resume: %s/%s\n",
                   target, container_current_name(&container));
        else
            printf("Unusable container left behind; it cannot be resumed, remove it: %s/%s\n",
                   target, container_current_name(&container));
        container_close(&container);
        metadata_profiles_free(&metadata_profiles);
        portable_prepared_capture_free(&prepared);
        free(portable_roots);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    printf("Finalizing (syncing to disk)...\n");
    ContainerStatus final_status = container_finalize(&container);
    if (final_status != CONTAINER_OK)
    {
        if (final_status == CONTAINER_ERR_FINAL_EXISTS)
            print_error("Error: a completed backup already occupies this container's final name\n");
        else if (final_status == CONTAINER_ERR_NOREPLACE)
            print_error("Error: %s does not support the atomic rename migr publishes backups with\n", target);
        else
            print_error("Error: Could not publish the completed backup container\n");

        printf("Incomplete backup kept for resume: %s/%s\n",
               target, container_current_name(&container));
        container_close(&container);
        metadata_profiles_free(&metadata_profiles);
        portable_prepared_capture_free(&prepared);
        free(portable_roots);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    print_success("Backup complete: %d items copied\n", count);
    printf("Location: %s/%s\n", target, container_current_name(&container));

    container_close(&container);
    metadata_profiles_free(&metadata_profiles);
    portable_prepared_capture_free(&prepared);
    free(portable_roots);
    manifest_free(&manifest);
    backup_plan_free(&plan);
    return 0;
}
