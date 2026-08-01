#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "backup.h"
#include "backup_plan.h"
#include "container.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "metadata.h"
#include "packages.h"
#include "utils.h"

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
            printf("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    if (errno != ENOENT)
    {
        // A real access failure (e.g. EACCES) must not masquerade as "absent";
        // otherwise dry-run would promise to create something it cannot reach.
        printf("Error: Could not access %s\n", path);
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
            printf("Error: Could not access %s\n", path);
            return 1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            printf("Error: %s exists but is not a directory\n", path);
            return 1;
        }
        return 0;
    }
    printf("Error: Could not create directory %s\n", path);
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
            printf("Error: out of memory building the backup manifest\n");
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
    { BACKUP_ROOT_MAIN,     "[Main Directories]" },
    { BACKUP_ROOT_DOTFILE,  "[Dotfiles]" },
    { BACKUP_ROOT_BROWSER,  "[Browser Profiles]" },
    { BACKUP_ROOT_EXPLICIT, "[Explicit Paths]" },
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
                          int *count, int *had_error)
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

            if (backup_capture_at(ctx, root->capture_path, data_fd,
                                  root->manifest_root.payload_path) != 0)
            {
                printf("Error: Failed to capture %s\n", root->capture_path);
                *had_error = 1;
            }
            else
            {
                (*count)++;
            }
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

static int backup_metadata_inventory(const char *source_path, int anchor_fd,
                                     int destination_root_fd,
                                     const char *destination_rel,
                                     MetadataProfiles *profiles)
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
        int fd = open(source_path, O_RDONLY | O_NOFOLLOW | O_NOATIME |
                                      O_CLOEXEC);
        if (fd < 0)
            return -1;
        struct stat opened;
        int failed = fstat(fd, &opened) != 0 ||
                     !metadata_source_unchanged(&source_st, &opened);
        if (close(fd) != 0)
            failed = 1;
        return failed ? -1 : 0;
    }

    if (!S_ISDIR(source_st.st_mode))
        return 0;

    int source_fd = open(source_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_NOATIME | O_CLOEXEC);
    if (source_fd < 0)
        return -1;
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
                                      profiles) != 0)
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
                                     MetadataProfiles *profiles)
{
    for (int i = 0; i < plan->root_count; i++)
    {
        const BackupPlanRoot *root = &plan->roots[i];
        if (backup_metadata_inventory(root->capture_path, anchor_fd,
                                      destination_root_fd,
                                      root->manifest_root.payload_path,
                                      profiles) != 0)
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
        printf("Error: Could not get HOME directory.\n");
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

    int count = 0;

    if (dry_run)
    {
        // The destination is inspected exactly as a live run would inspect it,
        // and nothing beyond that: no probe (it writes), no container, no
        // manifest, no data/, no package export.
        int target_created = 0;
        if (ensure_target_root(target, &target_created) != 0)
        {
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }

        MetadataProfiles advisory_profiles;
        metadata_profiles_init(&advisory_profiles);
        int advisory_fd = open(target, O_RDONLY | O_DIRECTORY |
                                        O_NOFOLLOW | O_CLOEXEC);
        if (advisory_fd >= 0)
        {
            if (backup_metadata_preflight(&plan, advisory_fd, -1,
                                          &advisory_profiles) != 0)
                printf("Warning: could not complete the read-only metadata preview; "
                       "the live backup will recheck it before writing.\n");
            else
                metadata_profiles_report(&advisory_profiles);
            close(advisory_fd);
        }
        metadata_profiles_free(&advisory_profiles);

        printf("Dry run mode enabled. No changes will be made.\n\n");
        printf("Would create a versioned backup container under: %s\n", target);
        printf("  Its migr_backup_<timestamp> name is chosen when the backup actually runs.\n");

        preview_roots(&plan, &count);

        printf("\n[Controls]\n");
        printf("  Would write manifest.txt\n");
        if (mode != BACKUP_EXPLICIT_PATHS)
            printf("  Would export package list to packages.txt\n");

        printf("\n===========================================================\n");
        printf("Dry run complete: %d items would be copied\n", count);
        printf("===========================================================\n");

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

    int target_fd = open(target, O_RDONLY | O_DIRECTORY |
                                  O_NOFOLLOW | O_CLOEXEC);
    if (target_fd < 0)
    {
        printf("Error: Could not open backup destination %s\n", target);
        if (target_created) rmdir(target);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    // Probe the destination and choose a representation before any container
    // exists. Portable is refused (not built yet); an unreliable probe is
    // fatal, never a silent fall-through. If we created the destination root
    // this run and then refuse, roll it back so a rejected attempt leaves
    // nothing behind.
    CloneRepresentation repr = CLONE_NATIVE_TREE;
    FsCapabilityProfile profile;
    const char *refusal = NULL;
    if (fsprobe(target, &profile) != 0)
        refusal = "could not probe the destination filesystem at";
    else if (select_representation(&profile, &repr) != 0)
        refusal = "the destination filesystem is not usable for backup at";
    else if (repr != CLONE_NATIVE_TREE)
        refusal = "portable representation is not implemented yet, so migr refuses "
                  "rather than lose Linux file metadata at";

    if (refusal != NULL)
    {
        printf("Error: %s %s\n", refusal, target);
        close(target_fd);
        if (target_created) rmdir(target);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    // The representation is part of the resume identity, so it must be settled
    // before the manifest is matched against an existing partial.
    manifest.representation = repr;

    MetadataProfiles metadata_profiles;
    metadata_profiles_init(&metadata_profiles);
    BackupContainer container = {0};
    int adopted = 0;
    ContainerStatus adopt_status = container_adopt(target, &manifest, &container);
    if (adopt_status == CONTAINER_OK)
    {
        adopted = 1;
        int adopted_data_fd = openat(container_root_fd(&container), "data",
                                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                     O_CLOEXEC);
        int metadata_failed = adopted_data_fd < 0;
        if (!metadata_failed)
            metadata_failed = backup_metadata_preflight(
                &plan, adopted_data_fd, adopted_data_fd,
                &metadata_profiles) != 0;
        if (!metadata_failed)
        {
            metadata_profiles_report(&metadata_profiles);
            metadata_failed = metadata_profiles_probe(
                &metadata_profiles,
                (MetadataTimestampPolicy){ .nsec_exact = 0, .configured = 1 }) != 0;
        }
        if (metadata_failed)
        {
            if (adopted_data_fd >= 0)
                close(adopted_data_fd);
            printf("Error: native metadata preflight failed; no payload was changed\n");
            container_close(&container);
            metadata_profiles_free(&metadata_profiles);
            close(target_fd);
            if (target_created) rmdir(target);
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }
        close(adopted_data_fd);
    }
    else if (adopt_status == CONTAINER_ERR_NO_MATCH)
    {
        int metadata_failed = backup_metadata_preflight(
            &plan, target_fd, -1, &metadata_profiles) != 0;
        if (!metadata_failed)
        {
            metadata_profiles_report(&metadata_profiles);
            metadata_failed = metadata_profiles_probe(
                &metadata_profiles,
                (MetadataTimestampPolicy){ .nsec_exact = 0, .configured = 1 }) != 0;
        }
        if (metadata_failed)
        {
            printf("Error: native metadata preflight failed; no container was created\n");
            metadata_profiles_free(&metadata_profiles);
            close(target_fd);
            if (target_created) rmdir(target);
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }
        if (container_reserve(target, time(NULL), &container) != CONTAINER_OK)
        {
            printf("Error: Could not create a backup container under %s\n", target);
            metadata_profiles_free(&metadata_profiles);
            close(target_fd);
            if (target_created) rmdir(target);
            manifest_free(&manifest);
            backup_plan_free(&plan);
            return 1;
        }
    }
    else
    {
        if (adopt_status == CONTAINER_ERR_AMBIGUOUS)
            printf("Error: more than one interrupted backup under %s matches this job; "
                   "resuming would be a guess. Remove or move the ones you do not want.\n",
                   target);
        else
            printf("Error: could not examine existing backups under %s\n", target);
        metadata_profiles_free(&metadata_profiles);
        close(target_fd);
        if (target_created) rmdir(target);
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
    if (!adopted && manifest_write_v1_at(container_fd, &manifest) != 0)
    {
        printf("Error: Could not write manifest.txt into the backup container\n");
        had_error = 1;
        resumable = 0;
    }

    int data_fd = -1;
    if (!had_error)
    {
        data_fd = open_data_dir(container_fd);
        if (data_fd < 0)
        {
            printf("Error: Could not open the container's data/ directory\n");
            had_error = 1;
        }
    }

    if (!had_error)
    {
        printf("Backing up to: %s/%s\n", target, container_current_name(&container));
        if (adopted)
            printf("Resuming an interrupted backup of the same job.\n");

        CloneContext ctx = {
            .operation = CLONE_BACKUP,
            .representation = repr,
            .timestamp_policy_configured = 1,
            .nsec_exact = profile.nsec_exact,
            .metadata_preflight_done = 1
        };
        capture_roots(&ctx, &plan, data_fd, &count, &had_error);
        close(data_fd);

        // packages.txt is a migr-owned control artifact, not a payload root, so
        // it stays at the container root. Restore acts on whichever one it
        // finds without re-deriving the backup's scope, so this slot must
        // always end up matching this invocation: a fresh list for a scope that
        // exports one, and demonstrably empty for a scope that does not.
        // Anything else -- a stale list inside an adopted container, or one
        // planted there -- would otherwise be published and later replayed.
        printf("\n[Packages]\n");
        if (mode == BACKUP_EXPLICIT_PATHS)
        {
            if (packages_clear_at(container_fd, "packages.txt") != 0)
            {
                printf("Error: could not clear packages.txt from the backup container\n");
                had_error = 1;
            }
            else
            {
                printf("  No package list: explicit paths are backed up exactly as given.\n");
            }
        }
        else
        {
            // A missing package list is tolerable and has always been a
            // warning; a control slot that could not be made safe is not.
            int pkg = packages_at(container_fd, "packages.txt");
            if (pkg < 0)
            {
                printf("Error: could not clear packages.txt from the backup container\n");
                had_error = 1;
            }
            else if (pkg > 0)
            {
                printf("  Warning: no package list was written for this backup.\n");
            }
        }
    }

    printf("\n===========================================================\n");

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
        printf("===========================================================\n");
        container_close(&container);
        metadata_profiles_free(&metadata_profiles);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    ContainerStatus final_status = container_finalize(&container);
    if (final_status != CONTAINER_OK)
    {
        if (final_status == CONTAINER_ERR_FINAL_EXISTS)
            printf("Error: a completed backup already occupies this container's final name\n");
        else if (final_status == CONTAINER_ERR_NOREPLACE)
            printf("Error: %s does not support the atomic rename migr publishes backups with\n", target);
        else
            printf("Error: Could not publish the completed backup container\n");

        printf("Incomplete backup kept for resume: %s/%s\n",
               target, container_current_name(&container));
        printf("===========================================================\n");
        container_close(&container);
        metadata_profiles_free(&metadata_profiles);
        manifest_free(&manifest);
        backup_plan_free(&plan);
        return 1;
    }

    printf("Backup complete: %d items copied\n", count);
    printf("Location: %s/%s\n", target, container_current_name(&container));
    printf("===========================================================\n");

    container_close(&container);
    metadata_profiles_free(&metadata_profiles);
    manifest_free(&manifest);
    backup_plan_free(&plan);
    return 0;
}
