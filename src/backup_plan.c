#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>

#include "backup_plan.h"
#include "selection.h"
#include "hash.h"
#include "utils.h" /* path_join, path_join_n */
#include "xdg.h"

/* ------------------------------------------------------------------------- */
/* Growable root array.                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    BackupPlanRoot *items;
    int count;
    size_t capacity;
    int limit;
} RootBuilder;

static int root_type_allowed(mode_t mode)
{
    return S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode) || S_ISFIFO(mode);
}

static int copy_field(char *dest, size_t dest_size, const char *src,
                      const char *fmt, const char *fmt_arg)
{
    if (strlen(src) >= dest_size)
    {
        print_error(fmt, fmt_arg);
        return -1;
    }
    strcpy(dest, src);
    return 0;
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
    int limit = rb->limit ? rb->limit : MANIFEST_MAX_ROOTS;
    if (rb->count >= limit)
    {
        print_error("Error: too many backup roots (limit %d)\n", MANIFEST_MAX_ROOTS);
        return -1;
    }
    if ((size_t)rb->count == rb->capacity)
    {
        BackupPlanRoot *n = array_reserve(
            rb->items, &rb->capacity, (size_t)rb->count, 1U,
            sizeof(*n), 16U, (size_t)limit);
        if (n == NULL)
        {
            print_error("Error: out of memory building backup plan\n");
            return -1;
        }
        rb->items = n;
    }

    BackupPlanRoot *r = &rb->items[rb->count];
    memset(r, 0, sizeof(*r));

    if (copy_field(r->capture_path, sizeof(r->capture_path), capture_path,
                   "Error: path too long: %s\n", capture_path) != 0)
        return -1;

    ManifestRoot *mr = &r->manifest_root;
    if (copy_field(mr->id, sizeof(mr->id), id,
                   "Error: root id too long: %s\n", id) != 0)
        return -1;
    mr->policy = policy;

    if (copy_field(mr->payload_path, sizeof(mr->payload_path), payload_path,
                   "Error: payload path too long for %s\n", id) != 0)
        return -1;

    if (copy_field(mr->source_path, sizeof(mr->source_path), source_path,
                   "Error: source path too long: %s\n", source_path) != 0)
        return -1;

    mr->has_restore_path = has_restore_path;
    if (has_restore_path &&
        copy_field(mr->restore_path, sizeof(mr->restore_path), restore_path,
                   "Error: restore path too long for %s\n", id) != 0)
            return -1;

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

    if (path_join_n(capture_path, capture_size, parent_real, leaf, leaf_len) != 0)
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
static int selection_root_readable(const char *path, mode_t mode)
{
    if (!S_ISREG(mode) && !S_ISDIR(mode)) return 1;
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (S_ISDIR(mode)) flags |= O_DIRECTORY;
    int fd = open(path, flags);
    if (fd < 0) return 0;
    return close(fd) == 0;
}

static int resolve_selection_candidate(const char *home, const char *raw,
                                        const SelectionPaths *excludes,
                                        char capture_path[PATH_MAX])
{
    int rc = selection_normalize(home, raw, excludes, 0, capture_path);
    if (rc != 0) return rc == 1 || errno == ENOENT || errno == ENOTDIR ? 0 : -1;
    struct stat st;
    if (lstat(capture_path, &st) < 0)
        return errno == ENOENT || errno == ENOTDIR ? 0 : -1;
    // Only built-in roots resolve here (see build_builtin_roots below); a
    // built-in that exists but cannot be opened is still carried into the
    // plan (docs/DECISIONS.md D34: missing optional built-ins are skippable,
    // but D34 says nothing about an inaccessible one) and is left for the
    // metadata preflight, which already reports the specific object that
    // could not be read. Configured includes apply selection_root_readable()
    // themselves in selection_plan_build(), where an unreadable include must
    // fail the build.
    return root_type_allowed(st.st_mode) ? 1 : -1;
}

static int build_builtin_roots(const char *home_real, BackupMode mode, RootBuilder *rb,
                               const SelectionPaths *excludes)
{
    int comprehensive = (mode == BACKUP_COMPREHENSIVE);

    // indices: 0=Documents 1=Downloads 2=Pictures 3=Desktop 4=Videos 5=Music.
    // The first three are always included; the rest only for --comprehensive
    // -- the same split backup.c used before this module existed.
    char *xdg_dirs[XDG_KEY_COUNT] = { NULL };
    if (xdg_resolve(home_real, xdg_keys, xdg_fallbacks, xdg_dirs, XDG_KEY_COUNT) != 0)
    {
        print_error("Error: HOME path too long to resolve user directories\n");
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
        int rc = excludes ? resolve_selection_candidate(home_real, xdg_dirs[i], excludes, capture_path)
                          : resolve_builtin_candidate(xdg_dirs[i], capture_path, sizeof(capture_path));
        if (rc == 0)
            continue;
        if (rc < 0)
        {
            print_error("Error: could not resolve %s\n", xdg_dirs[i]);
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
            print_error("Error: HOME path too long to build %s\n", e->id);
            return -1;
        }

        char capture_path[PATH_MAX];
        int rc = excludes ? resolve_selection_candidate(home_real, raw, excludes, capture_path)
                          : resolve_builtin_candidate(raw, capture_path, sizeof(capture_path));
        if (rc == 0)
            continue;
        if (rc < 0)
        {
            print_error("Error: could not resolve %s\n", raw);
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

int backup_plan_home_relative(const char *home_real, const char *capture_path,
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
        print_error("Error: explicit-paths mode requires at least one path argument.\n");
        return -1;
    }

    int n = 0;
    while (explicit_paths[n] != NULL)
        n++;

    ExplicitTemp *tmp = malloc((size_t)n * sizeof(*tmp));
    if (tmp == NULL)
    {
        print_error("Error: out of memory building backup plan\n");
        return -1;
    }

    for (int i = 0; i < n; i++)
    {
        if (normalize_explicit_path(explicit_paths[i], tmp[i].capture_path,
                                    sizeof(tmp[i].capture_path)) != 0)
        {
            print_error("Error: could not resolve path: %s\n", explicit_paths[i]);
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
            print_error("Error: too many explicit roots to name\n");
            failed = 1;
            break;
        }

        const char *restore_rel;
        if (backup_plan_home_relative(home_real, tmp[i].capture_path,
                                      &restore_rel))
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
//
// This is path_covers() minus equality: for a == "/", path_covers(a, b) is
// true whenever b is absolute, and excluding b == "/" is exactly excluding
// a == b. For a != "/", path_covers(a, b) with a == b takes the equality
// branch, and with a != b takes the prefix branch, which already demands
// b[strlen(a)] == '/' -- the same condition this function checks directly.
// So strcmp(a, b) != 0 is the only extra test equality-exclusion needs.
static int is_ancestor(const char *a, const char *b)
{
    return path_covers(a, b) && strcmp(a, b) != 0;
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
                print_error("Error: duplicate backup root: %s\n", a);
                return -1;
            }
            if (is_ancestor(a, b) || is_ancestor(b, a))
            {
                print_error("Error: backup roots overlap: %s and %s\n", a, b);
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
        print_error("Error: HOME is not set\n");
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
            print_error("Error: HOME path too long to resolve user directories\n");
        else
            print_error("Error: Could not resolve HOME directory: %s\n", home);
        return -1;
    }
    struct stat home_st;
    if (stat(home_real, &home_st) != 0 || !S_ISDIR(home_st.st_mode))
    {
        print_error("Error: HOME is not a directory: %s\n", home_real);
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
        rc = build_builtin_roots(home_real, mode, &rb, NULL);
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

typedef struct {
    dev_t dev;
    ino_t ino;
} EstimateInode;

typedef struct {
    EstimateInode *items;
    size_t count;
    size_t items_capacity;
    size_t *slots;
    size_t capacity;
} EstimateSeen;

static uint64_t estimate_inode_hash(dev_t dev, ino_t ino)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    hash = hash_fnv1a_uint64(hash, (uint64_t)dev);
    return hash_fnv1a_uint64(hash, (uint64_t)ino);
}

static int estimate_seen_rehash(EstimateSeen *seen, size_t new_capacity)
{
    if (seen == NULL || new_capacity < 16U ||
        (new_capacity & (new_capacity - 1U)) != 0 ||
        new_capacity > SIZE_MAX / sizeof(*seen->slots))
        return -1;

    size_t *slots = calloc(new_capacity, sizeof(*slots));
    if (slots == NULL)
        return -1;

    for (size_t item_index = 0; item_index < seen->count; item_index++)
    {
        uint64_t hash = estimate_inode_hash(seen->items[item_index].dev,
                                            seen->items[item_index].ino);
        size_t index = (size_t)hash & (new_capacity - 1U);
        while (slots[index] != 0)
            index = (index + 1U) & (new_capacity - 1U);
        slots[index] = item_index + 1U;
    }

    free(seen->slots);
    seen->slots = slots;
    seen->capacity = new_capacity;
    return 0;
}

/* Returns 1 for a match, 0 for an insertion slot, or -1 if the table is full. */
static int estimate_seen_locate(const EstimateSeen *seen, dev_t dev,
                                ino_t ino, uint64_t hash, size_t *out_index)
{
    if (seen == NULL || out_index == NULL)
        return -1;
    if (seen->capacity == 0)
    {
        *out_index = SIZE_MAX;
        return 0;
    }

    size_t first_stale = SIZE_MAX;
    size_t index = (size_t)hash & (seen->capacity - 1U);
    for (size_t probes = 0; probes < seen->capacity; probes++)
    {
        size_t value = seen->slots[index];
        if (value == 0)
        {
            *out_index = first_stale == SIZE_MAX ? index : first_stale;
            return 0;
        }

        size_t item_index = value - 1U;
        if (item_index < seen->count)
        {
            const EstimateInode *item = &seen->items[item_index];
            if (item->dev == dev && item->ino == ino)
            {
                *out_index = index;
                return 1;
            }
        }
        else if (first_stale == SIZE_MAX)
            first_stale = index;

        index = (index + 1U) & (seen->capacity - 1U);
    }

    *out_index = first_stale;
    return first_stale == SIZE_MAX ? -1 : 0;
}

static int estimate_seen_contains(const EstimateSeen *seen, dev_t dev,
                                  ino_t ino)
{
    if (seen == NULL || seen->capacity == 0)
        return 0;

    size_t index = SIZE_MAX;
    return estimate_seen_locate(seen, dev, ino,
                                estimate_inode_hash(dev, ino), &index) == 1;
}

static int estimate_seen_add(EstimateSeen *seen, dev_t dev, ino_t ino)
{
    if (seen == NULL)
        return -1;

    uint64_t hash = estimate_inode_hash(dev, ino);
    if (seen->capacity == 0 &&
        estimate_seen_rehash(seen, 16U) != 0)
        return -1;

    size_t index = SIZE_MAX;
    int location = estimate_seen_locate(seen, dev, ino, hash, &index);
    if (location == 1)
        return 0;
    if (location < 0)
        return -1;

    if (seen->count == SIZE_MAX)
    {
        errno = EOVERFLOW;
        return -1;
    }
    if (seen->count + 1U > seen->capacity / 2U)
    {
        if (seen->capacity > SIZE_MAX / 2U ||
            estimate_seen_rehash(seen, seen->capacity * 2U) != 0)
            return -1;
        location = estimate_seen_locate(seen, dev, ino, hash, &index);
        if (location != 0)
            return -1;
    }

    if (seen->count == seen->items_capacity)
    {
        EstimateInode *items = array_reserve(
            seen->items, &seen->items_capacity, seen->count, 1U,
            sizeof(*items), 16U, SIZE_MAX / sizeof(*items));
        if (items == NULL)
            return -1;
        seen->items = items;
    }

    seen->items[seen->count] = (EstimateInode){ .dev = dev, .ino = ino };
    seen->slots[index] = seen->count + 1U;
    seen->count++;
    return 0;
}

static void estimate_seen_free(EstimateSeen *seen)
{
    if (seen == NULL)
        return;
    free(seen->items);
    free(seen->slots);
    *seen = (EstimateSeen){0};
}

static int estimate_add_size(off_t *size, off_t contribution)
{
    if (size == NULL || *size < 0 || contribution < 0 ||
        (uintmax_t)*size > (uintmax_t)INTMAX_MAX -
                               (uintmax_t)contribution)
    {
        errno = EOVERFLOW;
        return -1;
    }
    *size += contribution;
    return 0;
}

static int estimate_regular_size(const struct stat *st, off_t block_size,
                                 off_t *size)
{
    if (st == NULL || size == NULL || st->st_size < 0)
    {
        errno = EOVERFLOW;
        return -1;
    }

    *size = st->st_size;
    if (block_size <= 1)
        return 0;

    off_t remainder = st->st_size % block_size;
    if (remainder == 0)
        return 0;

    off_t increment = block_size - remainder;
    if ((uintmax_t)st->st_size >
        (uintmax_t)INTMAX_MAX - (uintmax_t)increment)
    {
        errno = EOVERFLOW;
        return -1;
    }
    *size = st->st_size + increment;
    return 0;
}

#ifdef BACKUP_PLAN_TEST_HOOKS
static BackupPlanTestDirOpenHook estimate_walk_test_dir_open_hook;

void backup_plan_test_set_dir_open_hook(BackupPlanTestDirOpenHook hook)
{
    estimate_walk_test_dir_open_hook = hook;
}
#endif

/*
 * parent_fd anchors name to the exact object a caller's own readdir()
 * already listed -- AT_FDCWD is a valid parent_fd for an absolute or
 * cwd-relative name (per openat()/fstatat(), a non-relative name ignores
 * the dirfd entirely), so the top-level root call below reuses this same
 * function instead of a separate path-based entry point.
 */
static int estimate_walk_fd(int parent_fd, const char *name, off_t block_size,
                            EstimateSeen *seen, off_t *size,
                            const SelectionRoot *selection, char *relative)
{
    if (selection)
    {
        int owned = selection_root_owns(selection, relative);
        if (owned <= 0) return owned;
    }
    struct stat st;
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;

    if (S_ISREG(st.st_mode))
    {
        if (st.st_nlink > 1 &&
            estimate_seen_contains(seen, st.st_dev, st.st_ino))
            return 0;

        off_t contribution = 0;
        if (estimate_regular_size(&st, block_size, &contribution) != 0)
            return -1;
        if (st.st_nlink > 1 &&
            estimate_seen_add(seen, st.st_dev, st.st_ino) != 0)
            return -1;
        return estimate_add_size(size, contribution);
    }

    if (S_ISLNK(st.st_mode))
        return estimate_add_size(size, st.st_size);

    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode) ||
        S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
        return 0;

    if (!S_ISDIR(st.st_mode))
    {
        errno = EINVAL;
        return -1;
    }

    if (estimate_add_size(size, st.st_size) != 0)
        return -1;

    int dir_fd = openat(parent_fd, name,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir_fd < 0)
        return -1;

#ifdef BACKUP_PLAN_TEST_HOOKS
    /*
     * Fires for every directory this walk opens, not just one -- unlike
     * this codebase's usual self-clearing hooks, since a test targeting one
     * specific directory by name needs to see every candidate to find it.
     * The hook itself disarms via backup_plan_test_set_dir_open_hook(NULL)
     * once it recognizes its target.
     */
    if (estimate_walk_test_dir_open_hook != NULL)
        estimate_walk_test_dir_open_hook(parent_fd, name);
#endif

    int scan_fd = dup_cloexec(dir_fd);
    DIR *dir = scan_fd < 0 ? NULL : fdopendir(scan_fd);
    if (dir == NULL)
    {
        if (scan_fd >= 0)
            close(scan_fd);
        close(dir_fd);
        return -1;
    }

    int saved_errno = 0;
    struct dirent *entry;
    for (;;)
    {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
        {
            if (errno != 0)
                saved_errno = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        size_t old_length = selection ? strlen(relative) : 0;
        if (selection)
        {
            size_t prefix = old_length + (old_length != 0);
            size_t name_length = strlen(entry->d_name);
            if (prefix + name_length >= PATH_MAX) { saved_errno = ENAMETOOLONG; break; }
            if (old_length) relative[old_length] = '/';
            memcpy(relative + prefix, entry->d_name, name_length + 1);
        }
        int rc = estimate_walk_fd(dir_fd, entry->d_name, block_size, seen, size, selection, relative);
        if (selection) relative[old_length] = 0;
        if (rc != 0)
        {
            saved_errno = errno != 0 ? errno : EIO;
            break;
        }
    }
    if (closedir(dir) != 0 && saved_errno == 0)
        saved_errno = errno != 0 ? errno : EIO;
    if (close(dir_fd) != 0 && saved_errno == 0)
        saved_errno = errno != 0 ? errno : EIO;
    if (saved_errno != 0)
    {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void estimate_plan(const BackupPlan *plan, const SelectionPlan *selection,
                           off_t block_size, off_t *total, int *had_error)
{
    if (total == NULL || had_error == NULL)
        return;

    *total = 0;
    *had_error = 0;
    if (plan == NULL && selection == NULL)
    {
        *had_error = 1;
        return;
    }

    EstimateSeen seen = {0};
    size_t count = selection ? selection->root_count : (size_t)plan->root_count;
    for (size_t i = 0; i < count; i++)
    {
        const SelectionRoot *filter = selection ? &selection->roots[i] : NULL;
        const char *path = filter ? filter->root.capture_path : plan->roots[i].capture_path;
        char relative[PATH_MAX] = "";
        off_t root_size = 0;
        size_t seen_before_root = seen.count;
        errno = 0;
        if (estimate_walk_fd(AT_FDCWD, path, block_size, &seen, &root_size, filter, relative) != 0)
        {
            int saved_errno = errno;
            seen.count = seen_before_root;
            if (saved_errno == ENOENT || saved_errno == ENOTDIR)
                continue;
            *had_error = 1;
            continue;
        }
        if (estimate_add_size(total, root_size) != 0)
        {
            seen.count = seen_before_root;
            *had_error = 1;
        }
    }
    estimate_seen_free(&seen);
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
        // Unreachable with today's one caller, which always passes a
        // PATH_MAX-sized out_size -- resolved can never exceed that. Kept
        // as a real bound check, not dead code: resolved is always a full
        // PATH_MAX buffer regardless of out_size, and strcpy() below has
        // no bounds checking of its own, so this is what protects any
        // future caller that passes a smaller out_size from an overflow.
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

        print_error("Error: the backup destination is inside %s, which this backup would "
                    "capture.\n"
                    "  Writing a backup into a tree it is copying makes the copy consume "
                    "itself; choose a destination outside every selected root.\n",
                    root);
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

/* Configured selection compilation (docs/DECISIONS.md D34). */
static int selection_xdg_rank(const BackupPlanRoot *root)
{
    for (int i = 0; i < XDG_KEY_COUNT; i++)
        if (!strcmp(root->manifest_root.id, xdg_keys[i])) return i;
    return XDG_KEY_COUNT;
}

static int selection_candidate_cmp(const void *a, const void *b)
{
    const BackupPlanRoot *ra = a, *rb = b;
    int cmp = strcmp(ra->capture_path, rb->capture_path);
    if (cmp) return cmp;
    int xa = selection_xdg_rank(ra), xb = selection_xdg_rank(rb);
    if (xa != xb) return xa < xb ? -1 : 1;
    /* Empty ids denote configured requests; existing identities win ties. */
    if (!!ra->manifest_root.id[0] != !!rb->manifest_root.id[0])
        return ra->manifest_root.id[0] ? -1 : 1;
    return strcmp(ra->manifest_root.id, rb->manifest_root.id);
}

static const char *selection_relative(const char *parent, const char *path)
{
    return path + strlen(parent) + (strcmp(parent, "/") != 0);
}

static void selection_set_mapping(const char *home, BackupPlanRoot *root)
{
    ManifestRoot *mr = &root->manifest_root;
    if (mr->id[0] && !(mr->policy == ROOT_POLICY_XDG && !strcmp(root->capture_path, home)))
        return;
    const char *relative;
    if (backup_plan_home_relative(home, root->capture_path, &relative))
    {
        mr->policy = ROOT_POLICY_HOME_RELATIVE;
        mr->has_restore_path = 1;
        strcpy(mr->source_path, relative);
        strcpy(mr->restore_path, relative);
    }
    else
    {
        mr->policy = ROOT_POLICY_MANUAL_NATIVE;
        mr->has_restore_path = 0;
        strcpy(mr->source_path, root->capture_path);
        mr->restore_path[0] = 0;
    }
}

static int selection_mapping_inherited(const BackupPlanRoot *parent,
                                       const BackupPlanRoot *child)
{
    if (!child->manifest_root.id[0]) return 1;
    const ManifestRoot *a = &parent->manifest_root, *b = &child->manifest_root;
    if (a->policy != b->policy || b->policy == ROOT_POLICY_XDG) return 0;
    if (b->policy == ROOT_POLICY_MANUAL_NATIVE) return 1;
    char mapped[PATH_MAX];
    const char *relative = selection_relative(parent->capture_path, child->capture_path);
    if (!a->restore_path[0]) return !strcmp(relative, b->restore_path);
    return path_join(mapped, sizeof(mapped), a->restore_path, relative) == 0 &&
           !strcmp(mapped, b->restore_path);
}

static int selection_active(const ConfigRule *rule, BackupMode mode)
{
    return rule->scope == CONFIG_CRITICAL || mode == BACKUP_COMPREHENSIVE;
}

int selection_plan_build(const char *home, BackupMode mode,
                         const Config *config, SelectionPlan *out)
{
    if (!out) return -1;
    *out = (SelectionPlan){0};
    SelectionPlan plan = {0};
    RootBuilder rb = {.limit = CONFIG_MAX_RULES + BUILTIN_HOME_CATALOG_COUNT + XDG_KEY_COUNT};
    const char *error = "invalid HOME, scope or config";
    struct stat st;
    if (!home || !realpath(home, plan.home) || stat(plan.home, &st) < 0 || !S_ISDIR(st.st_mode) ||
        (mode != BACKUP_CRITICAL && mode != BACKUP_COMPREHENSIVE) ||
        (config && (config->count > CONFIG_MAX_RULES || (config->count && !config->rules)))) goto fail;
    plan.scope = mode == BACKUP_CRITICAL ? MANIFEST_SCOPE_CRITICAL : MANIFEST_SCOPE_COMPREHENSIVE;
    size_t count = config ? config->count : 0;
    error = "invalid config rule";
    unsigned char pending[CONFIG_MAX_RULES] = {0};
    size_t remaining = 0;
    for (size_t i = 0; i < count; i++)
    {
        const ConfigRule *rule = &config->rules[i];
        if ((rule->scope != CONFIG_CRITICAL && rule->scope != CONFIG_COMPREHENSIVE) ||
            (rule->action != CONFIG_INCLUDE && rule->action != CONFIG_EXCLUDE) ||
            !rule->path || !*rule->path) goto fail;
        if (rule->action == CONFIG_EXCLUDE &&
            rule->scope == (mode == BACKUP_CRITICAL ? CONFIG_CRITICAL : CONFIG_COMPREHENSIVE))
        {
            pending[i] = 1;
            remaining++;
        }
    }
    /* A broader exclusion may make an inaccessible descendant irrelevant.
     * Retry unresolved rules after learning boundaries, independent of order. */
    while (remaining)
    {
        size_t before = remaining;
        for (size_t i = 0; i < count; i++)
        {
            if (!pending[i]) continue;
            char normalized[PATH_MAX];
            int rc = selection_normalize(plan.home, config->rules[i].path, &plan.excludes, 1, normalized);
            if (rc < 0) continue;
            if (!rc && selection_paths_add(&plan.excludes, normalized) < 0) goto fail;
            pending[i] = 0;
            remaining--;
        }
        if (remaining == before) goto fail;
    }
    selection_paths_reduce(&plan.excludes);
    error = "could not resolve built-in selection";
    if (build_builtin_roots(plan.home, mode, &rb, &plan.excludes) < 0) goto fail;
    error = "could not resolve included path";
    for (size_t i = 0; i < count; i++)
    {
        const ConfigRule *rule = &config->rules[i];
        if (rule->action != CONFIG_INCLUDE || !selection_active(rule, mode)) continue;
        char normalized[PATH_MAX];
        int rc = selection_normalize(plan.home, rule->path, &plan.excludes, 0, normalized);
        if (rc < 0) goto fail;
        if (rc == 1) continue;
        if (lstat(normalized, &st) < 0 || !root_type_allowed(st.st_mode) ||
            !selection_root_readable(normalized, st.st_mode)) goto fail;
        if (append_root(&rb, "", ROOT_POLICY_MANUAL_NATIVE, "", normalized, NULL, 0,
                        normalized, BACKUP_ROOT_EXPLICIT) < 0) goto fail;
    }
    for (int i = 0; i < rb.count; i++) selection_set_mapping(plan.home, &rb.items[i]);
    if (rb.count > 1) qsort(rb.items, (size_t)rb.count, sizeof(*rb.items), selection_candidate_cmp);
    error = "out of memory compiling source ownership";
    if (rb.count)
    {
        plan.roots = calloc((size_t)rb.count, sizeof(*plan.roots));
        if (!plan.roots) goto fail;
    }
    size_t configured = 0;
    for (int i = 0; i < rb.count; i++)
    {
        BackupPlanRoot *candidate = &rb.items[i];
        uint32_t aliases = 0;
        int rank = selection_xdg_rank(candidate);
        if (rank < XDG_KEY_COUNT) aliases |= UINT32_C(1) << rank;
        while (i + 1 < rb.count && !strcmp(candidate->capture_path, rb.items[i + 1].capture_path))
        {
            rank = selection_xdg_rank(&rb.items[++i]);
            if (rank < XDG_KEY_COUNT) aliases |= UINT32_C(1) << rank;
        }
        int parent = -1;
        for (size_t j = 0; j < plan.root_count; j++)
            if (is_ancestor(plan.roots[j].root.capture_path, candidate->capture_path)) parent = (int)j;
        /* Configured descendants inherit their owner; built-in restore mappings
         * survive when the ancestor would place their data elsewhere. */
        if (parent >= 0 && selection_mapping_inherited(&plan.roots[parent].root, candidate)) continue;
        SelectionRoot *root = &plan.roots[plan.root_count++];
        root->root = *candidate;
        root->parent = parent;
        root->xdg_aliases = aliases;
        if (!root->root.manifest_root.id[0])
        {
            snprintf(root->root.manifest_root.id, sizeof(root->root.manifest_root.id),
                     "CONFIG_%zu", configured++);
            strcpy(root->root.manifest_root.payload_path, root->root.manifest_root.id);
        }
        if (parent >= 0 && selection_paths_add(&plan.roots[parent].delegated,
            selection_relative(plan.roots[parent].root.capture_path, candidate->capture_path)) < 0) goto fail;
    }
    if (plan.root_count > MANIFEST_MAX_ROOTS) { error = "too many compiled roots"; goto fail; }
    for (size_t i = 0; i < plan.excludes.count; i++)
    {
        int owner = -1;
        for (size_t j = 0; j < plan.root_count; j++)
            if (is_ancestor(plan.roots[j].root.capture_path, plan.excludes.paths[i])) owner = (int)j;
        if (owner >= 0 && selection_paths_add(&plan.roots[owner].excluded,
            selection_relative(plan.roots[owner].root.capture_path, plan.excludes.paths[i])) < 0) goto fail;
    }
    error = "invalid compiled source ownership";
    if (selection_plan_validate(&plan) < 0) goto fail;
    free(rb.items);
    *out = plan;
    return 0;
fail:
    print_error("Error: %s\n", error);
    free(rb.items);
    selection_plan_free(&plan);
    return -1;
}

void backup_plan_estimate_size(const BackupPlan *plan, off_t block_size,
                               off_t *total, int *had_error)
{
    estimate_plan(plan, NULL, block_size, total, had_error);
}

void selection_plan_estimate_size(const SelectionPlan *plan, off_t block_size,
                                  off_t *total, int *had_error)
{
    if (!total || !had_error) return;
    if (selection_plan_validate(plan) < 0) { *total = 0; *had_error = 1; return; }
    estimate_plan(NULL, plan, block_size, total, had_error);
}
