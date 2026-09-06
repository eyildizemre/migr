#define _GNU_SOURCE
#include "selection.h"
#include "utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int selection_paths_add(SelectionPaths *paths, const char *path)
{
    if (paths->count >= CONFIG_MAX_RULES) return -1;
    char *copy = strdup(path);
    if (!copy) return -1;
    char **next = realloc(paths->paths, (paths->count + 1) * sizeof(*next));
    if (!next) { free(copy); return -1; }
    paths->paths = next;
    paths->paths[paths->count++] = copy;
    return 0;
}

void selection_paths_free(SelectionPaths *paths)
{
    for (size_t i = 0; i < paths->count; i++) free(paths->paths[i]);
    free(paths->paths);
    *paths = (SelectionPaths){0};
}

static int path_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void selection_paths_reduce(SelectionPaths *paths)
{
    if (paths->count > 1) qsort(paths->paths, paths->count, sizeof(char *), path_cmp);
    size_t kept = 0;
    for (size_t i = 0; i < paths->count; i++)
    {
        int covered = 0;
        for (size_t j = 0; j < kept; j++)
            if (selection_path_covers(paths->paths[j], paths->paths[i])) { covered = 1; break; }
        if (covered) free(paths->paths[i]);
        else paths->paths[kept++] = paths->paths[i];
    }
    paths->count = kept;
}

static int excluded_path(const SelectionPaths *excludes, const char *path)
{
    if (excludes)
        for (size_t i = 0; i < excludes->count; i++)
            if (selection_path_covers(excludes->paths[i], path)) return 1;
    return 0;
}

int selection_normalize(const char *home, const char *raw,
                        const SelectionPaths *excludes, int allow_missing, char out[PATH_MAX])
{
    if (!raw || !*raw || strlen(raw) >= PATH_MAX) { errno = EINVAL; return -1; }
    char absolute[PATH_MAX];
    if (*raw == '/') strcpy(absolute, raw);
    else
    {
        const char *relative = !strncmp(raw, "~/", 2) ? raw + 2 : raw;
        if (path_join(absolute, sizeof(absolute), home, relative) < 0) return -1;
    }
    /* Validate all components before pruning: exclusion cannot hide bad input. */
    for (const char *p = absolute; *p; )
    {
        if (*p == '/') { p++; continue; }
        size_t n = strcspn(p, "/");
        if (n > NAME_MAX) { errno = ENAMETOOLONG; return -1; }
        p += n;
    }
    strcpy(out, "/");
    char *save = NULL;
    char *part = strtok_r(absolute, "/", &save);
    int missing = 0, pruned = excluded_path(excludes, out);
    while (part)
    {
        char *next = strtok_r(NULL, "/", &save);
        if (!strcmp(part, ".")) { part = next; continue; }
        if (!strcmp(part, ".."))
        {
            if (pruned) { errno = EINVAL; return -1; }
            char *slash = strrchr(out, '/');
            if (slash == out) out[1] = 0; else *slash = 0;
        }
        else
        {
            char joined[PATH_MAX];
            if (path_join(joined, sizeof(joined), out, part) < 0) return -1;
            strcpy(out, joined);
        }
        pruned |= excluded_path(excludes, out);
        if (next && !pruned && !missing)
        {
            char resolved[PATH_MAX];
            if (!realpath(out, resolved))
            {
                if (errno != ENOENT || !allow_missing) return -1;
                missing = 1;
            }
            else
            {
                struct stat st;
                if (stat(resolved, &st) < 0 || !S_ISDIR(st.st_mode))
                { errno = ENOTDIR; return -1; }
                strcpy(out, resolved);
                pruned |= excluded_path(excludes, out);
            }
        }
        part = next;
    }
    return pruned ? 1 : 0;
}

void selection_plan_free(SelectionPlan *plan)
{
    if (!plan) return;
    for (size_t i = 0; i < plan->root_count; i++)
    {
        selection_paths_free(&plan->roots[i].excluded);
        selection_paths_free(&plan->roots[i].delegated);
    }
    free(plan->roots);
    selection_paths_free(&plan->excludes);
    *plan = (SelectionPlan){0};
}

int selection_destination_conflicts(const SelectionPlan *plan, const char *destination)
{
    if (!plan) return 0;
    for (size_t i = 0; i < plan->root_count; i++)
    {
        BackupPlanRoot root = plan->roots[i].root;
        BackupPlan single = {plan->scope, 1, &root};
        if (backup_plan_destination_conflicts(&single, destination)) return 1;
    }
    return 0;
}

static int canonical_relative(const char *path)
{
    SelectionRoot empty = {0};
    return selection_root_owns(&empty, path) == 1;
}

static int contains_exact(const SelectionPaths *paths, const char *path)
{
    for (size_t i = 0; i < paths->count; i++)
        if (!strcmp(paths->paths[i], path)) return 1;
    return 0;
}

static int valid_paths(const SelectionPaths *paths, int absolute)
{
    if (paths->count > CONFIG_MAX_RULES || (paths->count && !paths->paths)) return 0;
    for (size_t i = 0; i < paths->count; i++)
    {
        const char *p = paths->paths[i];
        if (!p || !*p || (i && strcmp(paths->paths[i - 1], p) >= 0) || (absolute && *p != '/') || !canonical_relative(p + absolute)) return 0;
        for (size_t j = 0; j < i; j++)
            if (selection_path_covers(paths->paths[j], p) ||
                selection_path_covers(p, paths->paths[j])) return 0;
    }
    return 1;
}

int selection_plan_validate(const SelectionPlan *plan)
{
    if (!plan || strnlen(plan->home, PATH_MAX) == PATH_MAX || plan->home[0] != '/' || !canonical_relative(plan->home + 1) ||
        (plan->scope != MANIFEST_SCOPE_CRITICAL && plan->scope != MANIFEST_SCOPE_COMPREHENSIVE) ||
        plan->root_count > MANIFEST_MAX_ROOTS || (plan->root_count && !plan->roots) ||
        !valid_paths(&plan->excludes, 1)) return -1;
    for (size_t i = 0; i < plan->root_count; i++)
    {
        const SelectionRoot *root = &plan->roots[i];
        const char *source = root->root.capture_path;
        const ManifestRoot *mr = &root->root.manifest_root;
        if (strnlen(source, PATH_MAX) == PATH_MAX ||
            strnlen(mr->id, sizeof(mr->id)) == sizeof(mr->id) ||
            strnlen(mr->payload_path, sizeof(mr->payload_path)) == sizeof(mr->payload_path) ||
            *source != '/' || !canonical_relative(source + 1) ||
            !mr->id[0] || strcmp(mr->id, mr->payload_path) ||
            !canonical_relative(mr->payload_path) || strchr(mr->payload_path, '/') ||
            !valid_paths(&root->excluded, 0) || !valid_paths(&root->delegated, 0) ||
            excluded_path(&plan->excludes, source)) return -1;
        int parent = -1;
        for (size_t j = 0; j < i; j++)
        {
            const SelectionRoot *earlier = &plan->roots[j];
            if (strcmp(earlier->root.capture_path, source) >= 0 ||
                !strcmp(earlier->root.manifest_root.payload_path, mr->payload_path)) return -1;
            if (selection_path_covers(earlier->root.capture_path, source)) parent = (int)j;
        }
        if (root->parent != parent) return -1;
        size_t children = 0;
        for (size_t j = i + 1; j < plan->root_count; j++)
        {
            if (plan->roots[j].parent != (int)i) continue;
            const char *child = plan->roots[j].root.capture_path;
            if (strnlen(child, PATH_MAX) == PATH_MAX || !strcmp(source, child) ||
                !selection_path_covers(source, child)) return -1;
            const char *rel = child + strlen(source) + (strcmp(source, "/") != 0);
            if (!contains_exact(&root->delegated, rel)) return -1;
            children++;
        }
        if (children != root->delegated.count) return -1;
        size_t excludes = 0;
        for (size_t j = 0; j < plan->excludes.count; j++)
        {
            const char *path = plan->excludes.paths[j];
            if (!selection_path_covers(source, path)) continue;
            const char *rel = path + strlen(source) + (strcmp(source, "/") != 0);
            if (excluded_path(&root->delegated, rel)) continue;
            if (!contains_exact(&root->excluded, rel)) return -1;
            excludes++;
        }
        if (excludes != root->excluded.count) return -1;
    }
    return 0;
}

int selection_plan_manifest(const SelectionPlan *plan, Manifest *out)
{
    if (!out) return -1;
    *out = (Manifest){0};
    if (selection_plan_validate(plan) < 0) return -1;
    Manifest m = {0};
    m.version = MANIFEST_CURRENT_VERSION;
    m.scope = plan->scope;
    m.representation = CLONE_NATIVE_TREE;
    for (size_t i = 0; i < plan->root_count; i++)
        if (plan->roots[i].parent >= 0) m.version = MANIFEST_SELECTION_VERSION;
    if (plan->excludes.count) m.version = MANIFEST_SELECTION_VERSION;
    m.root_count = (int)plan->root_count;
    if (m.root_count)
    {
        m.roots = calloc(plan->root_count, sizeof(*m.roots));
        if (!m.roots) goto fail;
    }
    if (m.version == MANIFEST_SELECTION_VERSION)
    {
        strcpy(m.source_home, plan->home);
        m.exclude_count = plan->excludes.count;
        if (m.exclude_count)
        {
            m.excludes = calloc(m.exclude_count, sizeof(*m.excludes));
            if (!m.excludes) goto fail;
        }
        for (size_t i = 0; i < m.exclude_count; i++)
        {
            m.excludes[i] = strdup(plan->excludes.paths[i]);
            if (!m.excludes[i]) goto fail;
        }
    }
    for (size_t i = 0; i < plan->root_count; i++)
    {
        m.roots[i] = plan->roots[i].root.manifest_root;
        if (m.version == MANIFEST_SELECTION_VERSION)
        {
            const char *source = plan->roots[i].root.capture_path;
            const char *relative;
            if (m.roots[i].policy == ROOT_POLICY_HOME_RELATIVE &&
                backup_plan_home_relative(plan->home, source, &relative)) source = relative;
            strcpy(m.roots[i].source_path, source);
        }
    }
    if (!manifest_selection_valid(&m)) goto fail;
    *out = m;
    return 0;
fail:
    manifest_free(&m);
    return -1;
}
