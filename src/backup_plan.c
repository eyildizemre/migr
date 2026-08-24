#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "backup_plan.h"
#include "fileops.h"
#include "utils.h" /* path_join, path_join_n */
#include "xdg.h"

/* ------------------------------------------------------------------------- */
/* Growable root array.                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    BackupPlanRoot *items;
    int count;
    int capacity;
} RootBuilder;

static int root_type_allowed(mode_t mode)
{
    return S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode) || S_ISFIFO(mode);
}

// Appends one fully-formed root. source_path is always a real string;
// restore_path may be NULL when has_restore_path is 0 (XDG and MANUAL_NATIVE
// roots have no restore_path at all -- they are never "reusing" source_path
// for it).
static int append_root(RootBuilder *rb, const char *id, RootPolicy policy,
                       const char *payload_path, const char *source_path,
                       const char *restore_path, int has_restore_path,
                       const char *capture_path, BackupRootGroup group)
{
    if (rb->count >= MANIFEST_MAX_ROOTS)
    {
        printf("Error: too many backup roots (limit %d)\n", MANIFEST_MAX_ROOTS);
        return -1;
    }
    if (rb->count == rb->capacity)
    {
        int new_cap = rb->capacity == 0 ? 16 : rb->capacity * 2;
        if (new_cap > MANIFEST_MAX_ROOTS)
            new_cap = MANIFEST_MAX_ROOTS;
        BackupPlanRoot *n = realloc(rb->items, (size_t)new_cap * sizeof(*n));
        if (n == NULL)
        {
            printf("Error: out of memory building backup plan\n");
            return -1;
        }
        rb->items = n;
        rb->capacity = new_cap;
    }

    BackupPlanRoot *r = &rb->items[rb->count];
    memset(r, 0, sizeof(*r));

    if (strlen(capture_path) >= sizeof(r->capture_path))
    {
        printf("Error: path too long: %s\n", capture_path);
        return -1;
    }
    strcpy(r->capture_path, capture_path);

    ManifestRoot *mr = &r->manifest_root;
    if (strlen(id) >= sizeof(mr->id))
    {
        printf("Error: root id too long: %s\n", id);
        return -1;
    }
    strcpy(mr->id, id);
    mr->policy = policy;

    if (strlen(payload_path) >= sizeof(mr->payload_path))
    {
        printf("Error: payload path too long for %s\n", id);
        return -1;
    }
    strcpy(mr->payload_path, payload_path);

    if (strlen(source_path) >= sizeof(mr->source_path))
    {
        printf("Error: source path too long: %s\n", source_path);
        return -1;
    }
    strcpy(mr->source_path, source_path);

    mr->has_restore_path = has_restore_path;
    if (has_restore_path)
    {
        if (strlen(restore_path) >= sizeof(mr->restore_path))
        {
            printf("Error: restore path too long for %s\n", id);
            return -1;
        }
        strcpy(mr->restore_path, restore_path);
    }

    r->group = group;
    rb->count++;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Built-in catalog (docs/DECISIONS.md D16): fixed, descriptive ids -- never  */
/* a slug/hash or an order-dependent HOME_n.                                 */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *id;
    const char *home_rel;
    BackupRootGroup group;
    int comprehensive_only;
} BuiltinHomeEntry;

static const BuiltinHomeEntry builtin_home_catalog[] = {
    { "BUILTIN_PROJECTS",              "Projects",              BACKUP_ROOT_MAIN,    1 },
    { "BUILTIN_DOT_SSH",                ".ssh",                 BACKUP_ROOT_DOTFILE, 0 },
    { "BUILTIN_DOT_GNUPG",              ".gnupg",               BACKUP_ROOT_DOTFILE, 0 },
    { "BUILTIN_DOT_GITCONFIG",          ".gitconfig",           BACKUP_ROOT_DOTFILE, 0 },
    { "BUILTIN_DOT_BASHRC",             ".bashrc",              BACKUP_ROOT_DOTFILE, 0 },
    { "BUILTIN_DOT_PROFILE",            ".profile",             BACKUP_ROOT_DOTFILE, 0 },
    { "BUILTIN_BROWSER_MOZILLA",        ".mozilla",             BACKUP_ROOT_BROWSER, 0 },
    { "BUILTIN_BROWSER_GOOGLE_CHROME",  ".config/google-chrome", BACKUP_ROOT_BROWSER, 0 },
    { "BUILTIN_BROWSER_CHROMIUM",       ".config/chromium",      BACKUP_ROOT_BROWSER, 0 },
    { "BUILTIN_BROWSER_BRAVE",          ".config/BraveSoftware", BACKUP_ROOT_BROWSER, 0 },
    { "BUILTIN_BROWSER_VIVALDI",        ".config/vivaldi",       BACKUP_ROOT_BROWSER, 0 },
    { "BUILTIN_BROWSER_MICROSOFT_EDGE", ".config/microsoft-edge", BACKUP_ROOT_BROWSER, 0 },
    { "BUILTIN_BROWSER_OPERA",          ".config/opera",         BACKUP_ROOT_BROWSER, 0 },
};
enum { BUILTIN_HOME_CATALOG_COUNT =
    sizeof(builtin_home_catalog) / sizeof(builtin_home_catalog[0]) };

/* ------------------------------------------------------------------------- */
/* Leaf-preserving path normalization (docs/DECISIONS.md D16).               */
/*                                                                           */
/* Shared by every root category -- built-in, XDG, and explicit alike -- so  */
/* capture_path is always canonical the same way: an ancestor symlink is     */
/* fully resolved (exactly as the kernel would for any other path), but the  */
/* final path component is never dereferenced, so a leaf symlink (dangling   */
/* or not) is captured/classified as itself, never as whatever it currently  */
/* points at. Without this shared step, two roots that are actually the     */
/* same object could compare unequal as strings (one string having taken an  */
/* ancestor symlink, the other not) and dodge duplicate/overlap detection.   */
/* ------------------------------------------------------------------------- */

// Joins parent + "/" + leaf[0..leaf_len) without ever producing "//leaf" when
// parent is exactly "/" -- a cosmetic difference that would otherwise make
// two identical objects compare unequal as strings.
static int join_leaf(char *out, size_t out_size, const char *parent,
                     const char *leaf, size_t leaf_len)
{
    if (leaf_len > INT_MAX)
        return -1;
    int n;
    if (strcmp(parent, "/") == 0)
        n = snprintf(out, out_size, "/%.*s", (int)leaf_len, leaf);
    else
        n = snprintf(out, out_size, "%s/%.*s", parent, (int)leaf_len, leaf);
    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

// Pure path algebra: only the parent directory is resolved through
// realpath(); the final path component is never dereferenced. "/", ".", and
// ".." are pure navigation, not object names, so a path whose final
// component is one of those is resolved as a whole instead (there is no leaf
// to protect there).
//
// Never checks whether the final object exists or what type it is -- every
// caller does that itself, since "missing" means different things to
// different callers (fatal for an explicit root, benign for an optional
// built-in). Returns 0 and fills capture_path on success; returns -1 with
// errno set by the failing realpath()/length check otherwise (ENAMETOOLONG
// for every internal length-overflow case, so a caller can tell an
// unresolvable-but-absent parent from a genuine access/other error the same
// way it would for any other path).
static int resolve_leaf_preserving(const char *raw, char *capture_path, size_t capture_size)
{
    if (raw == NULL || raw[0] == '\0')
    {
        errno = EINVAL;
        return -1;
    }

    char trimmed[PATH_MAX];
    size_t len = strlen(raw);
    if (len >= sizeof(trimmed))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(trimmed, raw, len + 1);
    while (len > 1 && trimmed[len - 1] == '/')
        trimmed[--len] = '\0';

    const char *end = trimmed + len;
    const char *start = end;
    while (start > trimmed && start[-1] != '/')
        start--;
    const char *leaf = start;
    size_t leaf_len = (size_t)(end - start);

    int whole_resolve = (strcmp(trimmed, "/") == 0) ||
                        (leaf_len == 1 && leaf[0] == '.') ||
                        (leaf_len == 2 && leaf[0] == '.' && leaf[1] == '.');

    if (whole_resolve)
    {
        char resolved[PATH_MAX];
        if (realpath(trimmed, resolved) == NULL)
            return -1;
        if (strlen(resolved) >= capture_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        strcpy(capture_path, resolved);
        return 0;
    }

    char parent[PATH_MAX];
    if (leaf == trimmed)
    {
        // No '/' anywhere: a bare relative name, accepted against the
        // invocation's current working directory.
        strcpy(parent, ".");
    }
    else if (leaf == trimmed + 1 && trimmed[0] == '/')
    {
        strcpy(parent, "/");
    }
    else
    {
        size_t parent_len = (size_t)(leaf - trimmed - 1);
        if (parent_len >= sizeof(parent))
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(parent, trimmed, parent_len);
        parent[parent_len] = '\0';
    }

    char parent_real[PATH_MAX];
    if (realpath(parent, parent_real) == NULL)
        return -1;

    if (join_leaf(capture_path, capture_size, parent_real, leaf, leaf_len) != 0)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

// Explicit-root wrapper: any failure at all -- unresolvable parent, missing
// or inaccessible final object, or an unsupported type -- rejects the whole
// explicit root; there is no "optional" outcome here.
static int normalize_explicit_path(const char *raw, char *capture_path, size_t capture_size)
{
    if (resolve_leaf_preserving(raw, capture_path, capture_size) != 0)
        return -1;
    struct stat st;
    if (lstat(capture_path, &st) != 0)
        return -1;
    if (!root_type_allowed(st.st_mode))
        return -1;
    return 0;
}

// Built-in/XDG wrapper: distinguishes "genuinely absent" (benign for an
// optional built-in) from a real error. Returns 1 with capture_path filled
// and the object's type already verified, 0 if the candidate is simply
// missing (safe to leave out of the plan), -1 on a real error the caller
// must abort the whole build on.
static int resolve_builtin_candidate(const char *raw, char *capture_path, size_t capture_size)
{
    if (resolve_leaf_preserving(raw, capture_path, capture_size) != 0)
        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -1;

    struct stat st;
    if (lstat(capture_path, &st) != 0)
        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -1;
    if (!root_type_allowed(st.st_mode))
        return -1;
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Built-in catalog resolution.                                              */
/* ------------------------------------------------------------------------- */

// A missing built-in (ENOENT/ENOTDIR, from resolve_builtin_candidate) is
// simply left out of the plan; any other resolution failure or an
// unsupported object type is a real error and aborts the whole build
// (docs/DECISIONS.md D16: every failure other than a genuinely
// missing optional root is fatal). Every capture_path here -- XDG included --
// goes through the same
// ancestor-symlink-resolving, leaf-preserving normalization explicit roots
// get, so two roots that are actually the same object can never dodge
// duplicate/overlap detection by virtue of one being built-in and the other
// explicit. XDG's source_path is the same normalized capture address (not
// the raw xdg_resolve() output); a HOME_RELATIVE built-in's source_path
// stays its fixed home-relative address, unaffected by this normalization.
static int build_builtin_roots(const char *home_real, BackupMode mode, RootBuilder *rb)
{
    int comprehensive = (mode == BACKUP_COMPREHENSIVE);

    // indices: 0=Documents 1=Downloads 2=Pictures 3=Desktop 4=Videos 5=Music.
    // The first three are always included; the rest only for --comprehensive
    // -- the same split backup.c used before this module existed.
    char *xdg_dirs[XDG_KEY_COUNT] = { NULL };
    if (xdg_resolve(home_real, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_KEY_COUNT) != 0)
    {
        printf("Error: HOME path too long to resolve user directories\n");
        for (int i = 0; i < XDG_KEY_COUNT; i++)
            free(xdg_dirs[i]);
        return -1;
    }

    int failed = 0;
    for (int i = 0; i < XDG_KEY_COUNT && !failed; i++)
    {
        if (!comprehensive && i >= 3)
            continue;

        char capture_path[PATH_MAX];
        int rc = resolve_builtin_candidate(xdg_dirs[i], capture_path, sizeof(capture_path));
        if (rc == 0)
            continue;
        if (rc < 0)
        {
            printf("Error: could not resolve %s\n", xdg_dirs[i]);
            failed = 1;
            break;
        }

        if (append_root(rb, xdg_keys[i], ROOT_POLICY_XDG, xdg_keys[i], capture_path,
                        NULL, 0, capture_path, BACKUP_ROOT_MAIN) != 0)
        {
            failed = 1;
            break;
        }
    }

    for (int i = 0; i < XDG_KEY_COUNT; i++)
        free(xdg_dirs[i]);

    if (failed)
        return -1;

    for (int i = 0; i < BUILTIN_HOME_CATALOG_COUNT; i++)
    {
        const BuiltinHomeEntry *e = &builtin_home_catalog[i];
        if (e->comprehensive_only && !comprehensive)
            continue;

        char raw[PATH_MAX];
        if (path_join(raw, sizeof(raw), home_real, e->home_rel) != 0)
        {
            printf("Error: HOME path too long to build %s\n", e->id);
            return -1;
        }

        char capture_path[PATH_MAX];
        int rc = resolve_builtin_candidate(raw, capture_path, sizeof(capture_path));
        if (rc == 0)
            continue;
        if (rc < 0)
        {
            printf("Error: could not resolve %s\n", raw);
            return -1;
        }

        if (append_root(rb, e->id, ROOT_POLICY_HOME_RELATIVE, e->id, e->home_rel,
                        e->home_rel, 1, capture_path, e->group) != 0)
            return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Explicit-path classification.                                             */
/* ------------------------------------------------------------------------- */

// Component-boundary HOME containment (docs/DECISIONS.md D16): a lexical
// prefix like "$HOME2" must never count as "under HOME", so the byte right
// after home_real in capture_path must be '/' exactly, or capture_path must
// equal home_real (the root is HOME itself, restore_rel ""). home_real == "/"
// is a special case: "/" already ends in the separator, so a descendant like
// "/etc/hosts" has no second '/' to require, and the home-relative address
// starts one byte earlier than the general case.
static int is_home_relative(const char *home_real, const char *capture_path,
                            const char **restore_rel)
{
    static const char empty[] = "";
    if (strcmp(capture_path, home_real) == 0)
    {
        *restore_rel = empty;
        return 1;
    }
    if (strcmp(home_real, "/") == 0)
    {
        *restore_rel = capture_path + 1; // capture_path is always absolute and != "/" here
        return 1;
    }
    size_t home_len = strlen(home_real);
    if (strncmp(capture_path, home_real, home_len) == 0 && capture_path[home_len] == '/')
    {
        *restore_rel = capture_path + home_len + 1;
        return 1;
    }
    return 0;
}

typedef struct {
    char capture_path[PATH_MAX];
} ExplicitTemp;

static int explicit_cmp(const void *a, const void *b)
{
    return strcmp(((const ExplicitTemp *)a)->capture_path,
                  ((const ExplicitTemp *)b)->capture_path);
}

// Explicit roots are normalized and classified up front, then sorted by
// normalized path before EXPLICIT_n ids are assigned -- so argv order can
// never change which root gets which id (docs/DECISIONS.md D16).
// A missing/unresolvable/wrong-type path rejects the whole call; two roots
// sharing a basename are distinct roots, each addressed by its own id rather
// than by that shared name.
static int build_explicit_roots(const char *home_real, const char *const *explicit_paths,
                                RootBuilder *rb)
{
    if (explicit_paths == NULL || explicit_paths[0] == NULL)
    {
        printf("Error: explicit-paths mode requires at least one path argument.\n");
        return -1;
    }

    int n = 0;
    while (explicit_paths[n] != NULL)
        n++;

    ExplicitTemp *tmp = malloc((size_t)n * sizeof(*tmp));
    if (tmp == NULL)
    {
        printf("Error: out of memory building backup plan\n");
        return -1;
    }

    for (int i = 0; i < n; i++)
    {
        if (normalize_explicit_path(explicit_paths[i], tmp[i].capture_path,
                                    sizeof(tmp[i].capture_path)) != 0)
        {
            printf("Error: could not resolve path: %s\n", explicit_paths[i]);
            free(tmp);
            return -1;
        }
    }

    qsort(tmp, (size_t)n, sizeof(*tmp), explicit_cmp);

    int failed = 0;
    for (int i = 0; i < n && !failed; i++)
    {
        char id[MANIFEST_ID_MAX];
        int idn = snprintf(id, sizeof(id), "EXPLICIT_%d", i);
        if (idn < 0 || (size_t)idn >= sizeof(id))
        {
            printf("Error: too many explicit roots to name\n");
            failed = 1;
            break;
        }

        const char *restore_rel;
        if (is_home_relative(home_real, tmp[i].capture_path, &restore_rel))
        {
            if (append_root(rb, id, ROOT_POLICY_HOME_RELATIVE, id, restore_rel,
                            restore_rel, 1, tmp[i].capture_path, BACKUP_ROOT_EXPLICIT) != 0)
                failed = 1;
        }
        else
        {
            if (append_root(rb, id, ROOT_POLICY_MANUAL_NATIVE, id, tmp[i].capture_path,
                            NULL, 0, tmp[i].capture_path, BACKUP_ROOT_EXPLICIT) != 0)
                failed = 1;
        }
    }

    free(tmp);
    return failed ? -1 : 0;
}

/* ------------------------------------------------------------------------- */
/* Whole-set duplicate/overlap validation.                                   */
/* ------------------------------------------------------------------------- */

// Whether directory root `a` properly contains `b`, compared on normalized
// capture_path strings at component boundaries (never lexically): "/" is
// the ancestor of everything else; a leaf-symlink root's own capture_path
// (never resolved to its target) is what participates here, so a symlink
// never manufactures a false overlap with whatever it points at.
static int is_ancestor(const char *a, const char *b)
{
    if (strcmp(a, "/") == 0)
        return strcmp(b, "/") != 0;
    size_t alen = strlen(a);
    if (strncmp(b, a, alen) != 0)
        return 0;
    return b[alen] == '/';
}

static int validate_no_duplicates_or_overlap(const BackupPlanRoot *roots, int count)
{
    for (int i = 0; i < count; i++)
    {
        for (int j = i + 1; j < count; j++)
        {
            const char *a = roots[i].capture_path;
            const char *b = roots[j].capture_path;
            if (strcmp(a, b) == 0)
            {
                printf("Error: duplicate backup root: %s\n", a);
                return -1;
            }
            if (is_ancestor(a, b) || is_ancestor(b, a))
            {
                printf("Error: backup roots overlap: %s and %s\n", a, b);
                return -1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Public API.                                                                */
/* ------------------------------------------------------------------------- */

int backup_plan_build(const char *home, BackupMode mode,
                      const char *const *explicit_paths, BackupPlan *out)
{
    if (out == NULL)
        return -1;

    out->scope = MANIFEST_SCOPE_CRITICAL;
    out->root_count = 0;
    out->roots = NULL;

    if (home == NULL || home[0] == '\0')
    {
        printf("Error: HOME is not set\n");
        return -1;
    }

    char home_real[PATH_MAX];
    if (realpath(home, home_real) == NULL)
    {
        // A HOME long enough to overflow PATH_MAX fails realpath() with
        // ENAMETOOLONG regardless of whether it exists -- report it with the
        // same wording xdg_resolve()'s own overflow check has always used,
        // since both are the same underlying condition from the caller's
        // point of view.
        if (errno == ENAMETOOLONG)
            printf("Error: HOME path too long to resolve user directories\n");
        else
            printf("Error: Could not resolve HOME directory: %s\n", home);
        return -1;
    }
    struct stat home_st;
    if (stat(home_real, &home_st) != 0 || !S_ISDIR(home_st.st_mode))
    {
        printf("Error: HOME is not a directory: %s\n", home_real);
        return -1;
    }

    RootBuilder rb = {0};
    int rc;
    if (mode == BACKUP_EXPLICIT_PATHS)
    {
        out->scope = MANIFEST_SCOPE_EXPLICIT;
        rc = build_explicit_roots(home_real, explicit_paths, &rb);
    }
    else
    {
        out->scope = (mode == BACKUP_COMPREHENSIVE) ? MANIFEST_SCOPE_COMPREHENSIVE
                                                    : MANIFEST_SCOPE_CRITICAL;
        rc = build_builtin_roots(home_real, mode, &rb);
    }

    if (rc == 0)
        rc = validate_no_duplicates_or_overlap(rb.items, rb.count);

    if (rc != 0)
    {
        free(rb.items);
        return -1;
    }

    out->roots = rb.items;
    out->root_count = rb.count;
    return 0;
}

void backup_plan_estimate_size(const BackupPlan *plan, off_t *total,
                               int *had_error)
{
    if (total == NULL || had_error == NULL)
        return;

    *total = 0;
    *had_error = 0;
    if (plan == NULL)
    {
        *had_error = 1;
        return;
    }

    for (int i = 0; i < plan->root_count; i++)
    {
        const char *path = plan->roots[i].capture_path;
        struct stat st;
        if (lstat(path, &st) != 0)
        {
            if (errno == ENOENT || errno == ENOTDIR)
                continue;
            *had_error = 1;
            continue;
        }

        off_t root_size = 0;
        errno = 0;
        if (get_dir_size(path, &root_size) != 0)
        {
            if (errno == ENOENT || errno == ENOTDIR)
                continue;
            *had_error = 1;
            continue;
        }
        *total += root_size;
    }
}

// The destination is resolved differently from a root, because it is used
// differently: a root is an object to *copy*, so a symlink named as a root is
// captured as itself and must not be dereferenced. A destination is a place to
// *write into*, so what matters is where the writes actually land -- a symlink
// pointing back into the source tree would otherwise slip past containment
// while the copy fed on itself.
//
// An existing destination is therefore resolved in full, final component
// included. One that does not exist yet has no target to follow, so its parent
// is canonicalized and the leaf appended -- the same algebra roots use, applied
// to the one component that is about to be created.
static int resolve_destination(const char *destination, char *out, size_t out_size)
{
    char resolved[PATH_MAX];
    if (realpath(destination, resolved) != NULL)
    {
        if (strlen(resolved) >= out_size)
            return -1;
        strcpy(out, resolved);
        return 0;
    }
    return resolve_leaf_preserving(destination, out, out_size);
}

int backup_plan_destination_conflicts(const BackupPlan *plan, const char *destination)
{
    if (plan == NULL || destination == NULL)
        return 0;

    // If neither the destination nor its parent can be resolved there is
    // nothing to compare and nothing to create either: a non-recursive mkdir of
    // that address fails on its own, without this check having to guess.
    char dest_real[PATH_MAX];
    if (resolve_destination(destination, dest_real, sizeof(dest_real)) != 0)
        return 0;

    for (int i = 0; i < plan->root_count; i++)
    {
        const char *root = plan->roots[i].capture_path;
        if (strcmp(root, dest_real) != 0 && !is_ancestor(root, dest_real))
            continue;

        printf("Error: the backup destination is inside %s, which this backup would "
               "capture.\n", root);
        printf("  Writing a backup into a tree it is copying makes the copy consume "
               "itself; choose a destination outside every selected root.\n");
        return 1;
    }
    return 0;
}

void backup_plan_free(BackupPlan *plan)
{
    if (plan == NULL)
        return;
    free(plan->roots);
    plan->roots = NULL;
    plan->root_count = 0;
}
