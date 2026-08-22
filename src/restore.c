#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include "restore.h"
#include "container.h"
#include "detect.h"
#include "fileops.h"
#include "fsprobe.h"
#include "manifest.h"
#include "metadata.h"
#include "portable_restore.h"
#include "utils.h"
#include "xdg.h"

// The canonical XDG key/fallback table (xdg.h) is shared by both restore
// paths: legacy records them as "KEY=value" lines in an unversioned
// manifest.txt; a v1 manifest records them as root-table entries whose id is
// one of these same keys (docs/DECISIONS.md D16).
#define XDG_RESTORE_COUNT XDG_KEY_COUNT

static int xdg_key_index(const char *id)
{
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        if (strcmp(id, xdg_keys[i]) == 0)
            return i;
    return -1;
}

static void free_xdg_dirs(char **dirs)
{
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(dirs[i]);
}

typedef struct {
    dev_t device;
    ino_t inode;
    int fd;
    int nsec_exact;
} RestoreTimestampAnchor;

typedef struct {
    RestoreTimestampAnchor *items;
    size_t count;
    size_t capacity;
} RestoreTimestampAnchors;

static void restore_timestamp_anchors_init(RestoreTimestampAnchors *anchors)
{
    memset(anchors, 0, sizeof(*anchors));
}

static void restore_timestamp_anchors_free(RestoreTimestampAnchors *anchors)
{
    if (anchors == NULL)
        return;
    for (size_t i = 0; i < anchors->count; i++)
        close(anchors->items[i].fd);
    free(anchors->items);
    memset(anchors, 0, sizeof(*anchors));
}

// Find the directory whose filesystem permissions and timestamp behaviour
// govern a destination root. Existing directory roots use themselves; an
// absent leaf or intermediate uses the nearest existing parent. This mirrors
// the restore walk without treating a missing intermediate as a shorter path.
static int restore_destination_anchor_fd(int root_fd, const char *rel)
{
    if (root_fd < 0 || rel == NULL || rel[0] == '/')
        return -1;

    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0)
        return -1;
    if (rel[0] == '\0')
        return current;

    const char *p = rel;
    for (;;)
    {
        const char *slash = strchr(p, '/');
        size_t length = slash == NULL ? strlen(p) : (size_t)(slash - p);
        if (length == 0 || length > NAME_MAX ||
            (length == 1 && p[0] == '.') ||
            (length == 2 && p[0] == '.' && p[1] == '.'))
        {
            close(current);
            return -1;
        }

        if (slash == NULL)
        {
            struct stat final_st;
            if (fstatat(current, p, &final_st, AT_SYMLINK_NOFOLLOW) != 0)
            {
                if (errno == ENOENT)
                    return current;
                close(current);
                return -1;
            }
            if (!S_ISDIR(final_st.st_mode))
                return current;

            int final_fd = openat(current, p,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
            if (final_fd < 0)
            {
                close(current);
                return -1;
            }
            close(current);
            return final_fd;
        }

        char component[NAME_MAX + 1];
        memcpy(component, p, length);
        component[length] = '\0';
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
        {
            if (errno == ENOENT)
                return current;
            close(current);
            return -1;
        }
        close(current);
        current = next;
        p = slash + 1;
    }
}

static int restore_timestamp_anchor_add(RestoreTimestampAnchors *anchors,
                                         int fd)
{
    if (anchors == NULL || fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    for (size_t i = 0; i < anchors->count; i++)
        if (anchors->items[i].device == st.st_dev &&
            anchors->items[i].inode == st.st_ino)
            return 0;

    if (anchors->count == anchors->capacity)
    {
        size_t capacity = anchors->capacity == 0 ? 8 : anchors->capacity * 2;
        RestoreTimestampAnchor *items = realloc(anchors->items,
                                                capacity * sizeof(*items));
        if (items == NULL)
            return -1;
        anchors->items = items;
        anchors->capacity = capacity;
    }

    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0)
        return -1;
    anchors->items[anchors->count].device = st.st_dev;
    anchors->items[anchors->count].inode = st.st_ino;
    anchors->items[anchors->count].fd = copy;
    anchors->items[anchors->count].nsec_exact = 1;
    anchors->count++;
    return 0;
}

static int restore_timestamp_anchor_probe(RestoreTimestampAnchors *anchors)
{
    if (anchors == NULL)
        return -1;
    for (size_t i = 0; i < anchors->count; i++)
    {
        if (fsprobe_timestamps_fd(anchors->items[i].fd,
                                  &anchors->items[i].nsec_exact) != 0)
            return -1;
    }
    return 0;
}

static int restore_timestamp_anchor_policy(const RestoreTimestampAnchors *anchors,
                                            int fd, int *nsec_exact)
{
    if (anchors == NULL || fd < 0 || nsec_exact == NULL)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0)
        return -1;
    for (size_t i = 0; i < anchors->count; i++)
    {
        if (anchors->items[i].device == st.st_dev &&
            anchors->items[i].inode == st.st_ino)
        {
            *nsec_exact = anchors->items[i].nsec_exact;
            return 0;
        }
    }
    return -1;
}

// Reports the kernel's strict source-read refusal without suggesting an
// atime-changing fallback; a live replay also includes its partial counts.
static void report_source_safe_read_refusal(const char *label,
                                            const RestoreNativeReport *report)
{
    printf("Error: Could not safely read source for %s: the kernel refused "
           "the O_NOATIME open; an O_NOATIME-less retry was not attempted "
           "because it could change atime (ownership or CAP_FOWNER is "
           "required).\n", label);
    if (report != NULL && report->failed_count != 0)
        printf("Error: Native restore stopped at %s: %zu item(s) applied, "
               "%zu failed.\n",
               report->failed_logical_path[0] != '\0'
                   ? report->failed_logical_path : label,
               report->applied_count, report->failed_count);
}

static void restore_security_skipped_add(size_t *total, size_t count)
{
    if (total == NULL || count == 0 || *total == SIZE_MAX)
        return;
    if (count > SIZE_MAX - *total)
        *total = SIZE_MAX;
    else
        *total += count;
}

static void native_restore_security_dry_run_notice(size_t entries)
{
    if (entries != 0)
        printf("Security notice: %zu item(s) carry security.* attributes; "
               "whether they can be applied here is measured, not "
               "predicted, and is only found out on a live run.\n",
               entries);
}

static int native_restore_confirm(size_t security_xattr_entries)
{
    const char *ordinary_message =
        "This will restore files to your home directory. Continue?";
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

// Restores one item whose source and destination relative addresses may
// differ (e.g. a v1 root's "data/<payload>" source vs. its own restore
// address), sharing the exact same status/preflight/apply behavior for
// every caller so dry-run and live can never disagree. Prints only the
// shared error messages; the caller prints its own success/preview message
// when this returns > 0, since callers want different wording.
// Returns 1 if restored (or safely previewed), 0 if an optional source is
// absent, and -1 on an error or a missing required source.
static int restore_item_at(const CloneContext *ctx,
                           int source_root_fd, const char *source_rel,
                           int dest_root_fd, const char *dest_rel,
                           const char *label, int source_required,
                           const RestoreTimestampAnchors *timestamp_anchors,
                           size_t *skipped_security_xattrs)
{
    RestoreSourceStatus status = restore_native_source_status_at(source_root_fd, source_rel);
    if (status == RESTORE_SOURCE_MISSING)
    {
        if (source_required)
        {
            printf("Error: Manifest root %s is missing its declared payload\n", label);
            return -1;
        }
        return 0;
    }
    if (status == RESTORE_SOURCE_ERROR)
    {
        printf("Error: Failed to inspect %s\n", label);
        return -1;
    }

    CloneContext effective_ctx = *ctx;
    int policy_anchor_fd = restore_destination_anchor_fd(dest_root_fd, dest_rel);
    if (policy_anchor_fd < 0)
    {
        printf("Error: Failed to inspect restore destination for %s\n", label);
        return -1;
    }
    if (timestamp_anchors != NULL &&
        restore_timestamp_anchor_policy(timestamp_anchors, policy_anchor_fd,
                                        &effective_ctx.nsec_exact) != 0)
    {
        close(policy_anchor_fd);
        printf("Error: Restore destination was not covered by timestamp preflight for %s\n",
               label);
        return -1;
    }
    if (timestamp_anchors != NULL)
        effective_ctx.timestamp_policy_configured = 1;
    close(policy_anchor_fd);
    const CloneContext *run_ctx = &effective_ctx;

    if (dry_run)
    {
        RestoreNativeStatus native_status = restore_native_preflight_at(
            run_ctx, source_root_fd, source_rel, dest_root_fd, dest_rel);
        if (native_status != RESTORE_NATIVE_OK)
        {
            if (native_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                report_source_safe_read_refusal(label, NULL);
            else
                printf("Error: Failed to restore %s\n", label);
            return -1;
        }
        return 1;
    }

    if (verbose)
        printf("  Restoring: %s\n", label);

    RestoreNativeReport report;
    RestoreNativeStatus native_status = restore_native_at_report(
        run_ctx, source_root_fd, source_rel, dest_root_fd, dest_rel, &report);
    if (skipped_security_xattrs != NULL)
        restore_security_skipped_add(skipped_security_xattrs,
                                     report.skipped_security_xattr_count);
    if (native_status != RESTORE_NATIVE_OK)
    {
        if (native_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
            report_source_safe_read_refusal(label, &report);
        else
            printf("Error: Failed to restore %s\n", label);
        return -1;
    }
    return 1;
}

// A backup-relative path restored directly into home under the same name on
// both sides (legacy's Projects/dotfiles/browser-config items).
static int restore_home_item(const CloneContext *ctx, int source_root_fd,
                             int home_fd, const char *rel_path,
                             const RestoreTimestampAnchors *timestamp_anchors,
                             size_t *skipped_security_xattrs)
{
    int rc = restore_item_at(ctx, source_root_fd, rel_path, home_fd, rel_path,
                             rel_path, 0, timestamp_anchors,
                             skipped_security_xattrs);
    if (rc > 0 && dry_run)
        printf("  Would restore: %s\n", rel_path);
    return rc;
}

// Existing XDG destinations are caller-selected trust roots and may themselves
// be symlinks or live outside HOME. If only the final component is absent, its
// parent becomes the trust root and the fd-anchored core creates the leaf.
static int open_xdg_destination_anchor(const char *path, int *out_fd,
                                       char *out_rel, size_t rel_size)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0)
    {
        *out_fd = fd;
        out_rel[0] = '\0';
        return 0;
    }
    if (errno != ENOENT)
        return -1;

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    size_t len = strlen(copy);
    while (len > 1 && copy[len - 1] == '/')
        copy[--len] = '\0';

    char *slash = strrchr(copy, '/');
    const char *leaf = slash == NULL ? copy : slash + 1;
    size_t leaf_len = strlen(leaf);
    if (leaf_len == 0 || leaf_len >= rel_size)
    {
        free(copy);
        return -1;
    }
    memcpy(out_rel, leaf, leaf_len + 1);

    const char *parent;
    if (slash == NULL)
        parent = ".";
    else if (slash == copy)
    {
        slash[1] = '\0';
        parent = copy;
    }
    else
    {
        *slash = '\0';
        parent = copy;
    }

    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(copy);
    if (fd < 0)
        return -1;

    *out_fd = fd;
    return 0;
}

// Restores XDG main directories, Projects, dotfiles, and browser profiles
// from an unversioned or manifest-absent backup. This path preserves the
// legacy layout and its all-or-nothing XDG destination resolution.
static int restore_legacy(const char *source, int source_root_fd, const char *home, int home_fd,
                          const CloneContext *ctx, int *count, int *had_error,
                          const RestoreTimestampAnchors *timestamp_anchors,
                          size_t *skipped_security_xattrs)
{
    printf("[Main Directories]\n");
    char *xdg_dirs[XDG_RESTORE_COUNT];
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT) != 0)
    {
        printf("Error: HOME path too long to resolve user directories\n");
        free_xdg_dirs(xdg_dirs);
        *had_error = 1;
        return -1;
    }
    else
    {
        char *manifest_names[XDG_RESTORE_COUNT];
        int has_manifest = (legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT) == 0);

        for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        {
            // The manifest name locates the source-locale directory; xdg_dirs[i] is
            // the destination-locale path. Fall back to its basename if absent.
            const char *name;
            if (has_manifest && manifest_names[i] != NULL)
                name = manifest_names[i];
            else
            {
                const char *p = strrchr(xdg_dirs[i], '/');
                name = p ? p + 1 : xdg_dirs[i];
            }

            RestoreSourceStatus source_status = restore_native_source_status_at(source_root_fd, name);
            if (source_status == RESTORE_SOURCE_MISSING)
                continue;
            if (source_status == RESTORE_SOURCE_ERROR)
            {
                printf("Error: Failed to inspect %s\n", name);
                *had_error = 1;
                continue;
            }

            // xdg_dirs[i] may be any absolute path (see xdg_resolve()'s contract),
            // not necessarily under home: open (creating if needed) its own
            // directory fd and restore into it directly as the destination root
            // itself ("", docs/DECISIONS.md D16), rather than assuming it is
            // reachable via home_fd.
            int xdg_dest_fd;
            char destination_rel[NAME_MAX + 1];
            if (open_xdg_destination_anchor(xdg_dirs[i], &xdg_dest_fd, destination_rel, sizeof(destination_rel)) != 0)
            {
                printf("Error: Failed to restore %s\n", name);
                *had_error = 1;
                continue;
            }

            int rc = restore_item_at(ctx, source_root_fd, name, xdg_dest_fd,
                                     destination_rel, name, 0,
                                     timestamp_anchors,
                                     skipped_security_xattrs);
            if (rc > 0 && dry_run)
                printf("  Would restore: %s -> %s/\n", name, xdg_dirs[i]);
            if (rc > 0)
                (*count)++;
            else if (rc < 0)
                *had_error = 1;

            close(xdg_dest_fd);
        }

        if (has_manifest)
            for (int i = 0; i < XDG_RESTORE_COUNT; i++)
                free(manifest_names[i]);
        free_xdg_dirs(xdg_dirs);
    }

    // Projects is not a standard XDG directory
    int rc = restore_home_item(ctx, source_root_fd, home_fd, "Projects",
                               timestamp_anchors, skipped_security_xattrs);
    if (rc > 0)
        (*count)++;
    else if (rc < 0)
        *had_error = 1;

    const char *dotfiles[] = {".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile", NULL};
    printf("\n[Dotfiles]\n");
    for (int i = 0; dotfiles[i] != NULL; i++)
    {
        rc = restore_home_item(ctx, source_root_fd, home_fd, dotfiles[i],
                               timestamp_anchors, skipped_security_xattrs);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
    }

    const char *browser_configs[] = {
        ".mozilla",
        ".config/google-chrome",
        ".config/chromium",
        ".config/BraveSoftware",
        ".config/vivaldi",
        ".config/microsoft-edge",
        ".config/opera",
        NULL
    };
    printf("\n[Browser Profiles]\n");
    for (int i = 0; browser_configs[i] != NULL; i++)
    {
        rc = restore_home_item(ctx, source_root_fd, home_fd, browser_configs[i],
                               timestamp_anchors, skipped_security_xattrs);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
    }

    return 0;
}

static int v1_payload_rel(const ManifestRoot *root, char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "data/%s", root->payload_path);
    return n < 0 || (size_t)n >= out_size ? -1 : 0;
}

static int seed_native_restore_root(const CloneContext *ctx,
                                    const RestoreTimestampAnchors *anchors,
                                    const char *source,
                                    const char *source_rel,
                                    int destination_root_fd,
                                    const char *destination_rel)
{
    CloneContext effective_ctx = *ctx;
    int policy_anchor_fd = restore_destination_anchor_fd(destination_root_fd,
                                                         destination_rel);
    if (policy_anchor_fd < 0 ||
        restore_timestamp_anchor_policy(anchors, policy_anchor_fd,
                                        &effective_ctx.nsec_exact) != 0)
    {
        if (policy_anchor_fd >= 0)
            close(policy_anchor_fd);
        return -1;
    }
    effective_ctx.timestamp_policy_configured = 1;
    if (close(policy_anchor_fd) != 0)
        return -1;

    char source_path[PATH_MAX];
    if (source == NULL || source_rel == NULL || destination_rel == NULL)
        return -1;
    if (source_rel[0] == '\0')
    {
        int n = snprintf(source_path, sizeof(source_path), "%s", source);
        if (n < 0 || (size_t)n >= sizeof(source_path))
            return -1;
    }
    else if (path_join(source_path, sizeof(source_path), source,
                       source_rel) != 0)
        return -1;
    return native_inode_map_seed_existing(&effective_ctx, source_path,
                                          destination_root_fd,
                                          destination_rel);
}

static int seed_native_restore_v1_hardlink_map(
    const char *source, int source_root_fd, const char *home, int home_fd,
    const Manifest *m, const CloneContext *ctx,
    const RestoreTimestampAnchors *anchors)
{
    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    int xdg_ready = 0;
    int failed = 0;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue;

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0 ||
            restore_native_source_status_at(source_root_fd, source_rel) !=
                RESTORE_SOURCE_PRESENT)
        {
            failed = 1;
            continue;
        }

        int destination_fd = home_fd;
        int close_destination = 0;
        char destination_rel[PATH_MAX + 8];
        if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            int n = snprintf(destination_rel, sizeof(destination_rel), "%s",
                             root->restore_path);
            if (n < 0 || (size_t)n >= sizeof(destination_rel))
            {
                failed = 1;
                continue;
            }
        }
        else
        {
            if (!xdg_ready)
            {
                if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                                XDG_RESTORE_COUNT) != 0)
                {
                    free_xdg_dirs(xdg_dirs);
                    return -1;
                }
                xdg_ready = 1;
            }
            int index = xdg_key_index(root->id);
            if (index < 0 ||
                open_xdg_destination_anchor(xdg_dirs[index], &destination_fd,
                                             destination_rel,
                                             sizeof(destination_rel)) != 0)
            {
                failed = 1;
                continue;
            }
            close_destination = 1;
        }

        if (seed_native_restore_root(ctx, anchors, source, source_rel,
                                     destination_fd, destination_rel) != 0)
            failed = 1;
        if (close_destination && close(destination_fd) != 0)
            failed = 1;
    }

    if (xdg_ready)
        free_xdg_dirs(xdg_dirs);
    return failed ? -1 : 0;
}

static int seed_native_restore_legacy_hardlink_map(
    const char *source, int source_root_fd, const char *home, int home_fd,
    const CloneContext *ctx, const RestoreTimestampAnchors *anchors)
{
    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                    XDG_RESTORE_COUNT) != 0)
    {
        free_xdg_dirs(xdg_dirs);
        return -1;
    }

    char *manifest_names[XDG_RESTORE_COUNT] = {0};
    (void)legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT);
    int failed = 0;
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        const char *name = manifest_names[i];
        if (name == NULL)
        {
            const char *slash = strrchr(xdg_dirs[i], '/');
            name = slash == NULL ? xdg_dirs[i] : slash + 1;
        }

        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, name);
        if (status == RESTORE_SOURCE_MISSING)
            continue;
        if (status != RESTORE_SOURCE_PRESENT)
        {
            failed = 1;
            continue;
        }

        int destination_fd;
        char destination_rel[NAME_MAX + 1];
        if (open_xdg_destination_anchor(xdg_dirs[i], &destination_fd,
                                         destination_rel,
                                         sizeof(destination_rel)) != 0)
        {
            failed = 1;
            continue;
        }
        if (seed_native_restore_root(ctx, anchors, source, name,
                                     destination_fd, destination_rel) != 0)
            failed = 1;
        if (close(destination_fd) != 0)
            failed = 1;
    }

    const char *home_items[] = {
        "Projects", ".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile",
        ".mozilla", ".config/google-chrome", ".config/chromium",
        ".config/BraveSoftware", ".config/vivaldi",
        ".config/microsoft-edge", ".config/opera", NULL
    };
    for (int i = 0; home_items[i] != NULL; i++)
    {
        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, home_items[i]);
        if (status == RESTORE_SOURCE_MISSING)
            continue;
        if (status != RESTORE_SOURCE_PRESENT ||
            seed_native_restore_root(ctx, anchors, source, home_items[i],
                                     home_fd, home_items[i]) != 0)
            failed = 1;
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);
    free_xdg_dirs(xdg_dirs);
    return failed ? -1 : 0;
}

// A versioned root table is an inventory, not a list of optional probes. A
// finalized container missing any declared payload is corrupt and must be
// refused before confirmation or destination mutation.
static int validate_v1_payloads(int source_root_fd, const Manifest *m)
{
    int failed = 0;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            printf("Error: Manifest root %s has an invalid payload address\n",
                   root->id);
            failed = 1;
            continue;
        }

        RestoreSourceStatus status =
            restore_native_source_status_at(source_root_fd, source_rel);
        if (status == RESTORE_SOURCE_MISSING)
        {
            printf("Error: Manifest root %s is missing its declared payload\n",
                   root->id);
            failed = 1;
        }
        else if (status == RESTORE_SOURCE_ERROR)
        {
            printf("Error: Could not safely inspect payload for manifest root %s\n",
                   root->id);
            failed = 1;
        }
    }

    return failed ? -1 : 0;
}

static RestoreNativeStatus restore_metadata_item(
    const CloneContext *ctx, int source_root_fd, const char *source_rel,
    int destination_root_fd, const char *destination_rel, const char *label,
    int required, MetadataProfiles *profiles,
    RestoreTimestampAnchors *timestamp_anchors)
{
    RestoreSourceStatus status =
        restore_native_source_status_at(source_root_fd, source_rel);
    if (status == RESTORE_SOURCE_MISSING)
    {
        if (required)
            printf("Error: Manifest root %s is missing its declared payload\n",
                   label);
        return required ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK;
    }
    if (status == RESTORE_SOURCE_ERROR)
    {
        printf("Error: Failed to inspect %s\n", label);
        return RESTORE_NATIVE_ERROR;
    }
    int metadata_anchor_fd = restore_destination_anchor_fd(destination_root_fd,
                                                           destination_rel);
    if (metadata_anchor_fd < 0)
    {
        printf("Error: Failed to inspect restore destination for %s\n", label);
        return RESTORE_NATIVE_ERROR;
    }
    int anchor_failed = restore_timestamp_anchor_add(timestamp_anchors,
                                                      metadata_anchor_fd) != 0;
    if (close(metadata_anchor_fd) != 0)
        anchor_failed = 1;
    if (anchor_failed)
    {
        printf("Error: Failed to inspect restore destination for %s\n", label);
        return RESTORE_NATIVE_ERROR;
    }
    return restore_native_metadata_inventory_at(ctx, source_root_fd, source_rel,
                                                destination_root_fd,
                                                destination_rel, profiles);
}

static RestoreNativeStatus restore_legacy_metadata_inventory(
    const char *source, int source_root_fd, const char *home, int home_fd,
    const CloneContext *ctx, MetadataProfiles *profiles,
    RestoreTimestampAnchors *timestamp_anchors)
{
    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                    XDG_RESTORE_COUNT) != 0)
    {
        free_xdg_dirs(xdg_dirs);
        printf("Error: HOME path too long to resolve user directories\n");
        return -1;
    }

    char *manifest_names[XDG_RESTORE_COUNT] = {0};
    (void)legacy_manifest_read(source, manifest_names, XDG_RESTORE_COUNT);
    int failed = 0;
    RestoreNativeStatus result = RESTORE_NATIVE_OK;
    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
    {
        const char *name = manifest_names[i];
        if (name == NULL)
        {
            const char *slash = strrchr(xdg_dirs[i], '/');
            name = slash == NULL ? xdg_dirs[i] : slash + 1;
        }

        /* Legacy XDG roots are optional. Inspect the source first so a
         * missing source does not make an otherwise irrelevant destination
         * path fatal (the restore path has always skipped such roots). */
        RestoreSourceStatus source_status =
            restore_native_source_status_at(source_root_fd, name);
        if (source_status == RESTORE_SOURCE_MISSING)
            continue;
        if (source_status == RESTORE_SOURCE_ERROR)
        {
            printf("Error: Failed to inspect %s\n", name);
            failed = 1;
            continue;
        }

        int destination_fd = -1;
        char destination_rel[NAME_MAX + 1];
        if (open_xdg_destination_anchor(xdg_dirs[i], &destination_fd,
                                         destination_rel,
                                         sizeof(destination_rel)) != 0)
        {
            printf("Error: Failed to resolve restore destination %s\n",
                   xdg_dirs[i]);
            failed = 1;
            continue;
        }
        RestoreNativeStatus item_status = restore_metadata_item(
            ctx, source_root_fd, name, destination_fd, destination_rel, name,
            0, profiles, timestamp_anchors);
        if (item_status != RESTORE_NATIVE_OK)
        {
            failed = 1;
            if (item_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                result = RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (close(destination_fd) != 0)
            failed = 1;
    }

    const char *home_items[] = {
        "Projects", ".ssh", ".gnupg", ".gitconfig", ".bashrc", ".profile",
        ".mozilla", ".config/google-chrome", ".config/chromium",
        ".config/BraveSoftware", ".config/vivaldi",
        ".config/microsoft-edge", ".config/opera", NULL
    };
    for (int i = 0; home_items[i] != NULL; i++)
    {
        RestoreNativeStatus item_status = restore_metadata_item(
            ctx, source_root_fd, home_items[i], home_fd, home_items[i],
            home_items[i], 0, profiles, timestamp_anchors);
        if (item_status != RESTORE_NATIVE_OK)
        {
            failed = 1;
            if (item_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                result = RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
    }

    for (int i = 0; i < XDG_RESTORE_COUNT; i++)
        free(manifest_names[i]);
    free_xdg_dirs(xdg_dirs);
    return result != RESTORE_NATIVE_OK
        ? result : (failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK);
}

static RestoreNativeStatus restore_v1_metadata_inventory(
    int source_root_fd, const char *home, int home_fd, const Manifest *m,
    const CloneContext *ctx, MetadataProfiles *profiles,
    RestoreTimestampAnchors *timestamp_anchors)
{
    char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
    int xdg_ready = 0;
    int failed = 0;
    RestoreNativeStatus result = RESTORE_NATIVE_OK;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue;

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            printf("Error: Manifest root %s has an invalid payload address\n",
                   root->id);
            failed = 1;
            continue;
        }

        int destination_fd = home_fd;
        int close_destination = 0;
        char destination_rel[PATH_MAX + 8];
        if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            if (snprintf(destination_rel, sizeof(destination_rel), "%s",
                         root->restore_path) >= (int)sizeof(destination_rel))
            {
                failed = 1;
                continue;
            }
        }
        else
        {
            if (!xdg_ready)
            {
                if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                                XDG_RESTORE_COUNT) != 0)
                {
                    free_xdg_dirs(xdg_dirs);
                    printf("Error: HOME path too long to resolve user directories\n");
                    return -1;
                }
                xdg_ready = 1;
            }
            int idx = xdg_key_index(root->id);
            if (idx < 0 || open_xdg_destination_anchor(xdg_dirs[idx],
                                                        &destination_fd,
                                                        destination_rel,
                                                        sizeof(destination_rel)) != 0)
            {
                printf("Error: Failed to resolve restore destination %s\n",
                       root->id);
                failed = 1;
                continue;
            }
            close_destination = 1;
        }

        RestoreNativeStatus item_status = restore_metadata_item(
            ctx, source_root_fd, source_rel, destination_fd, destination_rel,
            root->id, 1, profiles, timestamp_anchors);
        if (item_status != RESTORE_NATIVE_OK)
        {
            failed = 1;
            if (item_status == RESTORE_NATIVE_SOURCE_SAFE_READ)
                result = RESTORE_NATIVE_SOURCE_SAFE_READ;
        }
        if (close_destination && close(destination_fd) != 0)
            failed = 1;
    }

    if (xdg_ready)
        free_xdg_dirs(xdg_dirs);
    return result != RESTORE_NATIVE_OK
        ? result : (failed ? RESTORE_NATIVE_ERROR : RESTORE_NATIVE_OK);
}

// Restores a valid native v1 manifest's root table (docs/DECISIONS.md D15,
// D16). HOME_RELATIVE roots restore beneath home, XDG roots map to the target
// locale, and MANUAL_NATIVE roots are reported without being auto-restored.
static void restore_v1(const char *source, int source_root_fd, const char *home, int home_fd,
                       const CloneContext *ctx, const Manifest *m, int *count,
                       int *had_error,
                       const RestoreTimestampAnchors *timestamp_anchors,
                       size_t *skipped_security_xattrs)
{
    printf("[Roots]\n");

    char *xdg_dirs[XDG_RESTORE_COUNT];
    int xdg_dirs_ready = 0;
    int xdg_dirs_failed = 0;

    for (int i = 0; i < m->root_count; i++)
    {
        const ManifestRoot *root = &m->roots[i];
        if (root->policy == ROOT_POLICY_MANUAL_NATIVE)
            continue; // reported separately below; never auto-restored

        char source_rel[PATH_MAX + 8];
        if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
        {
            printf("Error: Failed to restore %s\n", root->id);
            *had_error = 1;
            continue;
        }

        if (root->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            int rc = restore_item_at(ctx, source_root_fd, source_rel, home_fd,
                                     root->restore_path, root->id, 1,
                                     timestamp_anchors,
                                     skipped_security_xattrs);
            if (rc > 0 && dry_run)
            {
                if (root->restore_path[0] != '\0')
                    printf("  Would restore: %s -> ~/%s\n", root->id, root->restore_path);
                else
                    printf("  Would restore: %s -> ~\n", root->id);
            }
            if (rc > 0)
                (*count)++;
            else if (rc < 0)
                *had_error = 1;
            continue;
        }

        // ROOT_POLICY_XDG: resolved lazily, once, only if a manifest actually
        // has an XDG-policy root -- an EXPLICIT-scope backup may have none.
        if (!xdg_dirs_ready && !xdg_dirs_failed)
        {
            if (xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_RESTORE_COUNT) == 0)
                xdg_dirs_ready = 1;
            else
            {
                free_xdg_dirs(xdg_dirs);
                xdg_dirs_failed = 1;
                printf("Error: HOME path too long to resolve user directories\n");
            }
        }
        if (xdg_dirs_failed)
        {
            *had_error = 1;
            continue;
        }

        int idx = xdg_key_index(root->id);
        if (idx < 0)
        {
            printf("Error: Unrecognized XDG root id: %s\n", root->id);
            *had_error = 1;
            continue;
        }

        int xdg_dest_fd;
        char destination_rel[NAME_MAX + 1];
        if (open_xdg_destination_anchor(xdg_dirs[idx], &xdg_dest_fd, destination_rel, sizeof(destination_rel)) != 0)
        {
            printf("Error: Failed to restore %s\n", root->id);
            *had_error = 1;
            continue;
        }

        int rc = restore_item_at(ctx, source_root_fd, source_rel, xdg_dest_fd,
                                 destination_rel, root->id, 1,
                                 timestamp_anchors,
                                 skipped_security_xattrs);
        if (rc > 0 && dry_run)
            printf("  Would restore: %s -> %s/\n", root->id, xdg_dirs[idx]);
        if (rc > 0)
            (*count)++;
        else if (rc < 0)
            *had_error = 1;
        close(xdg_dest_fd);
    }

    if (xdg_dirs_ready)
        free_xdg_dirs(xdg_dirs);

    int manual_count = 0;
    for (int i = 0; i < m->root_count; i++)
        if (m->roots[i].policy == ROOT_POLICY_MANUAL_NATIVE)
            manual_count++;

    if (manual_count > 0)
    {
        printf("\n[Manual Roots]\n");
        printf("  Not restored automatically; recover these from the backup directly.\n");
        for (int i = 0; i < m->root_count; i++)
        {
            const ManifestRoot *root = &m->roots[i];
            if (root->policy != ROOT_POLICY_MANUAL_NATIVE)
                continue;

            char source_rel[PATH_MAX + 8];
            if (v1_payload_rel(root, source_rel, sizeof(source_rel)) != 0)
            {
                printf("Error: Manifest root %s has an invalid payload address\n",
                       root->id);
                *had_error = 1;
                continue;
            }
            RestoreSourceStatus status =
                restore_native_source_status_at(source_root_fd, source_rel);
            if (status != RESTORE_SOURCE_PRESENT)
            {
                printf("Error: Manifest root %s no longer has a readable payload\n",
                       root->id);
                *had_error = 1;
                continue;
            }

            printf("  %s\n", root->id);
            printf("    recorded source: %s\n", root->source_path);
            printf("    backup location: %s/data/%s\n", source, root->payload_path);
        }
    }
}

// Reads and processes packages.txt from the container root (never inside
// data/: it is a control artifact, not payload, in both legacy and v1
// layouts). Opened by directory fd with O_NOFOLLOW + O_NONBLOCK -- the same
// discipline manifest.c uses for manifest.txt: a symlinked packages.txt is
// never followed into an arbitrary location, and a FIFO there can never
// hang this call waiting for a writer that will never come.
static void restore_packages(int source_root_fd, const char *home, int *had_error)
{
    int fd = openat(source_root_fd, "packages.txt", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno == ENOENT)
            printf("\nNote: packages.txt not found, skipping package restore.\n");
        else
        {
            printf("Error: Could not read packages.txt\n");
            *had_error = 1;
        }
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        printf("Error: Could not inspect packages.txt\n");
        *had_error = 1;
        return;
    }
    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        printf("Warning: packages.txt is not a regular file, skipping package restore.\n");
        return;
    }

    FILE *pkg_file = fdopen(fd, "r");
    if (pkg_file == NULL)
    {
        close(fd);
        printf("Error: Could not read packages.txt\n");
        *had_error = 1;
        return;
    }

    printf("\n[Packages]\n");

    distro_t distro = detect_distro();

    if (distro == DISTRO_UNKNOWN)
    {
        printf("Warning: Unrecognized distro, skipping package install.\n");
        fclose(pkg_file);
        return;
    }
    if (dry_run)
    {
        printf("  Would install packages from packages.txt\n");
        fclose(pkg_file);
        return;
    }

    printf("Installing packages (this may take a while)...\n");

    int pkg_cap = 256;
    int pkg_count = 0;
    char **pkgs = malloc(pkg_cap * sizeof(char *));

    if (pkgs != NULL)
    {
        char line[512];
        char pkg_name[256];

        while (fgets(line, sizeof(line), pkg_file) != NULL)
        {
            if (sscanf(line, "%255s", pkg_name) != 1)
                continue;

            // Preserve compatibility with old dpkg "pkg\tstatus" backups by
            // skipping deinstall entries. Current backups contain plain names;
            // see docs/DECISIONS.md D12.
            char *tab = strchr(line, '\t');
            if (tab != NULL && strncmp(tab + 1, "install", 7) != 0)
                continue;

            if (pkg_count == pkg_cap)
            {
                pkg_cap *= 2;
                char **tmp = realloc(pkgs, pkg_cap * sizeof(char *));
                if (tmp == NULL) break;
                pkgs = tmp;
            }
            pkgs[pkg_count] = strdup(pkg_name);
            if (pkgs[pkg_count] != NULL)
                pkg_count++;
        }
    }
    fclose(pkg_file);

    char *batch_prefix[6];
    int prefix = 0;
    switch (distro)
    {
        case DISTRO_DEBIAN:
            batch_prefix[0] = "sudo";
            batch_prefix[1] = "apt-get";
            batch_prefix[2] = "install";
            batch_prefix[3] = "-y";
            batch_prefix[4] = "-m";
            prefix = 5;
            break;
        case DISTRO_FEDORA:
            batch_prefix[0] = "sudo";
            batch_prefix[1] = "dnf";
            batch_prefix[2] = "install";
            batch_prefix[3] = "-y";
            prefix = 4;
            break;
        case DISTRO_ARCH:
            batch_prefix[0] = "sudo";
            batch_prefix[1] = "pacman";
            batch_prefix[2] = "-S";
            batch_prefix[3] = "--needed";
            batch_prefix[4] = "--noconfirm";
            prefix = 5;
            break;
        default: break;
    }

    int installed = 0, skipped = 0;

    if (pkgs != NULL && pkg_count > 0 && prefix > 0)
    {
        // Try one batch first; fall back per package below.
        // See docs/DECISIONS.md D2.
        char **batch_argv = malloc((prefix + pkg_count + 1) * sizeof(char *));
        if (batch_argv != NULL)
        {
            for (int i = 0; i < prefix; i++)
                batch_argv[i] = batch_prefix[i];
            for (int i = 0; i < pkg_count; i++)
                batch_argv[prefix + i] = pkgs[i];
            batch_argv[prefix + pkg_count] = NULL;

            int rc = run_command((char *const *)batch_argv);
            free(batch_argv);

            if (rc == 0)
            {
                installed = pkg_count;
            }
            else
            {
                // Phase 2: per-package fallback, track failures
                char skipped_path[PATH_MAX];
                int can_write_skip_log =
                    path_join(skipped_path, sizeof(skipped_path), home,
                              "skipped-packages.txt") == 0;
                FILE *skipped_f = NULL;

                for (int i = 0; i < pkg_count; i++)
                {
                    char *install_cmd[8];
                    switch (distro)
                    {
                        case DISTRO_DEBIAN:
                            install_cmd[0] = "sudo";
                            install_cmd[1] = "apt-get";
                            install_cmd[2] = "install";
                            install_cmd[3] = "-y";
                            install_cmd[4] = "-m";
                            install_cmd[5] = pkgs[i];
                            install_cmd[6] = NULL;
                            break;
                        case DISTRO_FEDORA:
                            install_cmd[0] = "sudo";
                            install_cmd[1] = "dnf";
                            install_cmd[2] = "install";
                            install_cmd[3] = "-y";
                            install_cmd[4] = pkgs[i];
                            install_cmd[5] = NULL;
                            break;
                        case DISTRO_ARCH:
                            install_cmd[0] = "sudo";
                            install_cmd[1] = "pacman";
                            install_cmd[2] = "-S";
                            install_cmd[3] = "--needed";
                            install_cmd[4] = "--noconfirm";
                            install_cmd[5] = pkgs[i];
                            install_cmd[6] = NULL;
                            break;
                        default:
                            install_cmd[0] = NULL;
                            break;
                    }

                    if (install_cmd[0] == NULL) continue;

                    if (run_command((char *const *)install_cmd) != 0)
                    {
                        if (!can_write_skip_log)
                        {
                            if (skipped == 0)
                                printf("Error: Could not write skipped package log\n");
                            *had_error = 1;
                        }
                        else if (skipped_f == NULL)
                        {
                            skipped_f = fopen(skipped_path, "w");
                            if (skipped_f == NULL)
                            {
                                printf("Error: Could not write skipped package log\n");
                                can_write_skip_log = 0;
                                *had_error = 1;
                            }
                        }
                        if (skipped_f != NULL)
                            fprintf(skipped_f, "%s\n", pkgs[i]);
                        skipped++;
                    }
                    else
                    {
                        installed++;
                    }
                }

                if (skipped_f != NULL)
                {
                    fclose(skipped_f);
                    printf("  Skipped packages written to: %s\n", skipped_path);
                }
            }
        }
    }

    if (pkgs != NULL)
    {
        for (int i = 0; i < pkg_count; i++)
            free(pkgs[i]);
        free(pkgs);
    }

    printf("  %d installed, %d skipped.\n", installed, skipped);
}

int restore(const char *source)
{
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Error: Could not get HOME directory.\n");
        return 1;
    }

    struct stat st;
    if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        printf("Error: Source directory not found: %s\n", source);
        return 1;
    }

    // A live or abandoned ".partial" container (docs/DECISIONS.md D15) is
    // never a valid restore source: an interrupted backup may be incomplete,
    // and a still-active one may be locked by another process. Trailing
    // slashes are stripped first so they cannot hide the leaf name.
    char source_copy[PATH_MAX];
    if ((size_t)snprintf(source_copy, sizeof(source_copy), "%s", source) >= sizeof(source_copy))
    {
        printf("Error: Source path too long: %s\n", source);
        return 1;
    }
    size_t source_len = strlen(source_copy);
    while (source_len > 1 && source_copy[source_len - 1] == '/')
        source_copy[--source_len] = '\0';
    const char *source_leaf = strrchr(source_copy, '/');
    source_leaf = source_leaf ? source_leaf + 1 : source_copy;
    if (container_name_is_partial(source_leaf))
    {
        printf("Error: %s is an in-progress or abandoned backup container, not a finished one.\n", source);
        return 1;
    }
    int source_is_versioned_final = container_name_is_final(source_leaf);

    int source_root_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_root_fd < 0)
    {
        printf("Error: Could not open source directory: %s\n", source);
        return 1;
    }

    // Classified before any confirmation or filesystem mutation: an unknown
    // version or malformed manifest refuses the whole restore outright,
    // rather than guessing or partially proceeding.
    Manifest m;
    ManifestStatus mst = manifest_read_v1_at(source_root_fd, &m);
    if (mst == MANIFEST_STATUS_UNKNOWN_VERSION)
    {
        printf("Error: manifest.txt records a format version this build does not understand; refusing to guess.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_MALFORMED)
    {
        printf("Error: manifest.txt is malformed; refusing to restore.\n");
        close(source_root_fd);
        return 1;
    }
    if (mst == MANIFEST_STATUS_IO_ERROR)
    {
        printf("Error: Could not read manifest.txt.\n");
        close(source_root_fd);
        return 1;
    }
    // mst is now MISSING, LEGACY, or VALID.

    if (source_is_versioned_final && mst == MANIFEST_STATUS_MISSING)
    {
        printf("Error: A finalized versioned container is missing manifest.txt; refusing to treat it as a legacy backup.\n");
        close(source_root_fd);
        return 1;
    }
    if (source_is_versioned_final && mst == MANIFEST_STATUS_LEGACY)
    {
        printf("Error: A finalized versioned container carries a legacy manifest; refusing to guess its layout.\n");
        close(source_root_fd);
        return 1;
    }
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0)
    {
        if (errno == ENAMETOOLONG)
            printf("Error: HOME path too long to resolve user directories\n");
        else
            printf("Error: Could not open home directory: %s\n", home);
        if (mst == MANIFEST_STATUS_VALID)
            manifest_free(&m);
        close(source_root_fd);
        return 1;
    }

    if (mst == MANIFEST_STATUS_VALID &&
        m.representation == CLONE_PORTABLE_SIDECAR)
    {
        char *xdg_dirs[XDG_RESTORE_COUNT] = {0};
        int has_xdg_root = 0;
        for (int index = 0; index < m.root_count; index++)
            if (m.roots[index].policy == ROOT_POLICY_XDG)
            {
                has_xdg_root = 1;
                break;
            }
        if (has_xdg_root &&
            xdg_resolve(home, xdg_keys, xdg_fallbacks, xdg_dirs,
                        XDG_RESTORE_COUNT) != 0)
        {
            printf("Error: HOME path too long to resolve user directories\n");
            free_xdg_dirs(xdg_dirs);
            manifest_free(&m);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }

        PortableRestoreRequest request = {
            .source_container_fd = source_root_fd,
            .manifest = &m,
            .destination_home_fd = home_fd,
            .destination_timestamp_policy = {0}
        };
        for (int index = 0; index < XDG_RESTORE_COUNT; index++)
            request.destination_xdg_dirs[index] = xdg_dirs[index];
        PortableRestoreReplayReport report;
        PortableRestoreOutcome outcome =
            portable_restore_orchestrate_at(&request, &report);

        int had_portable_error = 0;
        if (outcome == PORTABLE_RESTORE_COMPLETE)
        {
            // Packages are published only after a fully successful replay.
            restore_packages(source_root_fd, home, &had_portable_error);
        }

        printf("\n===========================================================\n");
        switch (outcome)
        {
            case PORTABLE_RESTORE_COMPLETE:
                printf(had_portable_error
                    ? "Restore finished with errors: %zu item(s) restored, packages step failed\n"
                    : "Restore complete: %zu item(s) restored\n",
                    report.applied_count);
                break;
            case PORTABLE_RESTORE_DRY_RUN:
                printf("Dry run complete: %zu item(s) would be restored\n",
                       report.live_count);
                break;
            case PORTABLE_RESTORE_CANCELLED:
                printf("Cancelled.\n");
                break;
            case PORTABLE_RESTORE_ERROR:
            default:
                printf("Restore finished with errors: %zu applied, %zu failed\n",
                       report.applied_count, report.failed_count);
                break;
        }
        if (report.skipped_security_xattr_count != 0)
            printf("Skipped %zu security.* attribute(s) that the destination "
                   "could not apply.\n",
                   report.skipped_security_xattr_count);
        printf("===========================================================\n");

        free_xdg_dirs(xdg_dirs);
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return (outcome == PORTABLE_RESTORE_ERROR || had_portable_error) ? 1 : 0;
    }

    if (mst == MANIFEST_STATUS_VALID &&
        validate_v1_payloads(source_root_fd, &m) != 0)
    {
        manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return 1;
    }

    CloneContext ctx = {
        .operation = CLONE_RESTORE,
        .representation = CLONE_NATIVE_TREE
    };
    MetadataProfiles metadata_profiles;
    metadata_profiles_init(&metadata_profiles);
    RestoreTimestampAnchors timestamp_anchors;
    restore_timestamp_anchors_init(&timestamp_anchors);
    RestoreNativeStatus metadata_inventory_failed;
    if (mst == MANIFEST_STATUS_VALID)
        metadata_inventory_failed = restore_v1_metadata_inventory(
            source_root_fd, home, home_fd, &m, &ctx, &metadata_profiles,
            &timestamp_anchors);
    else
        metadata_inventory_failed = restore_legacy_metadata_inventory(
            source, source_root_fd, home, home_fd, &ctx, &metadata_profiles,
            &timestamp_anchors);
    if (metadata_inventory_failed != 0)
    {
        if (metadata_inventory_failed == RESTORE_NATIVE_SOURCE_SAFE_READ)
            report_source_safe_read_refusal("native restore payload", NULL);
        else
            printf("Error: native metadata preflight failed; no destination was changed\n");
        metadata_profiles_free(&metadata_profiles);
        restore_timestamp_anchors_free(&timestamp_anchors);
        if (mst == MANIFEST_STATUS_VALID)
            manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return 1;
    }
    metadata_profiles_report(&metadata_profiles);

    if (dry_run)
    {
        printf("Dry run mode enabled. No changes will be made.\n\n");
        native_restore_security_dry_run_notice(
            metadata_profiles.security_xattr_entry_count);
    }
    else if (!native_restore_confirm(
                 metadata_profiles.security_xattr_entry_count))
    {
        printf("Cancelled.\n");
        metadata_profiles_free(&metadata_profiles);
        restore_timestamp_anchors_free(&timestamp_anchors);
        if (mst == MANIFEST_STATUS_VALID)
            manifest_free(&m);
        close(home_fd);
        close(source_root_fd);
        return 0;
    }

    printf("Restoring from: %s\n\n", source);

    int count = 0;
    int had_error = 0;
    size_t skipped_security_xattrs = 0;

    if (!dry_run)
    {
        if (restore_timestamp_anchor_probe(&timestamp_anchors) != 0)
        {
            printf("Error: native timestamp preflight failed; no destination was changed\n");
            metadata_profiles_free(&metadata_profiles);
            restore_timestamp_anchors_free(&timestamp_anchors);
            if (mst == MANIFEST_STATUS_VALID)
                manifest_free(&m);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }
        // ctx's own timestamp_policy_configured/nsec_exact are never read for
        // an actual apply: restore_item_at() always builds its own
        // per-destination-anchor copy from timestamp_anchors before using it.
        if (metadata_profiles_probe(&metadata_profiles,
                                    (MetadataTimestampPolicy){
                                        .nsec_exact = 0,
                                        .configured = 1
                                    }) != 0)
        {
            printf("Error: native metadata preflight failed; no destination was changed\n");
            metadata_profiles_free(&metadata_profiles);
            restore_timestamp_anchors_free(&timestamp_anchors);
            if (mst == MANIFEST_STATUS_VALID)
                manifest_free(&m);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }
        ctx.metadata_preflight_done = 1;
        ctx.inode_map = native_inode_map_create();
        if (ctx.inode_map == NULL)
        {
            printf("Error: Could not initialize native hardlink restore tracking\n");
            metadata_profiles_free(&metadata_profiles);
            restore_timestamp_anchors_free(&timestamp_anchors);
            if (mst == MANIFEST_STATUS_VALID)
                manifest_free(&m);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }

        int seed_status = mst == MANIFEST_STATUS_VALID
            ? seed_native_restore_v1_hardlink_map(
                  source, source_root_fd, home, home_fd, &m, &ctx,
                  &timestamp_anchors)
            : seed_native_restore_legacy_hardlink_map(
                  source, source_root_fd, home, home_fd, &ctx,
                  &timestamp_anchors);
        if (seed_status != 0)
        {
            printf("Error: Could not seed native hardlink restore tracking\n");
            native_inode_map_free(ctx.inode_map);
            ctx.inode_map = NULL;
            metadata_profiles_free(&metadata_profiles);
            restore_timestamp_anchors_free(&timestamp_anchors);
            if (mst == MANIFEST_STATUS_VALID)
                manifest_free(&m);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }
    }

    if (mst == MANIFEST_STATUS_VALID)
    {
        restore_v1(source, source_root_fd, home, home_fd, &ctx, &m, &count,
                   &had_error, &timestamp_anchors,
                   &skipped_security_xattrs);
        manifest_free(&m);
    }
    else
    {
        if (restore_legacy(source, source_root_fd, home, home_fd, &ctx,
                           &count, &had_error, &timestamp_anchors,
                           &skipped_security_xattrs) != 0)
        {
            native_inode_map_free(ctx.inode_map);
            ctx.inode_map = NULL;
            metadata_profiles_free(&metadata_profiles);
            restore_timestamp_anchors_free(&timestamp_anchors);
            close(home_fd);
            close(source_root_fd);
            return 1;
        }
    }

    native_inode_map_free(ctx.inode_map);
    ctx.inode_map = NULL;

    restore_packages(source_root_fd, home, &had_error);

    printf("\n===========================================================\n");
    if (dry_run && had_error)
        printf("Dry run finished with errors: %d items would be restored, some items failed validation\n",
               count);
    else if (dry_run)
        printf("Dry run complete: %d items would be restored\n", count);
    else if (had_error)
        printf("Restore finished with errors: %d items restored, some items failed\n", count);
    else
        printf("Restore complete: %d items restored\n", count);
    if (skipped_security_xattrs != 0)
        printf("Skipped %zu security.* attribute(s) that the destination "
               "could not apply.\n", skipped_security_xattrs);
    printf("===========================================================\n");

    close(home_fd);
    close(source_root_fd);
    metadata_profiles_free(&metadata_profiles);
    restore_timestamp_anchors_free(&timestamp_anchors);
    return had_error ? 1 : 0;
}
