#define _GNU_SOURCE
#include "config.h"
#include "fileops.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int config_error(const char *source, size_t line, const char *message)
{
    fprintf(stderr, "Error: %s:%zu: %s\n", source, line, message);
    return -1;
}

void config_free(Config *config)
{
    for (size_t i = 0; i < config->count; i++)
        free(config->rules[i].path);
    free(config->rules);
    *config = (Config){0};
}

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_path(const char *start, const char *end, char path[PATH_MAX])
{
    size_t n = 0;
    int quoted = start < end && *start == '"';
    if (quoted) start++;
    int closed = !quoted;
    while (start < end)
    {
        unsigned char c = (unsigned char)*start++;
        if (quoted && c == '"')
        {
            closed = 1;
            if (start != end) return -1;
            break;
        }
        if (quoted && c == '\\')
        {
            if (start == end) return -1;
            c = (unsigned char)*start++;
            switch (c)
            {
                case '\\': case '"': break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'x':
                    if (end - start < 2) return -1;
                    int hi = hex_digit((unsigned char)start[0]);
                    int lo = hex_digit((unsigned char)start[1]);
                    if (hi < 0 || lo < 0) return -1;
                    c = (unsigned char)(hi * 16 + lo);
                    start += 2;
                    break;
                default: return -1;
            }
        }
        if (c == 0 || n == PATH_MAX - 1U) return -1;
        path[n++] = (char)c;
    }
    path[n] = '\0';
    return closed && n > 0 ? 0 : -1;
}

int config_parse(const char *data, size_t length, const char *source, Config *out)
{
    Config parsed = {0};
    if (length > CONFIG_MAX_BYTES)
        return config_error(source, 0, "config exceeds size limit");
    const char *nul = length ? memchr(data, 0, length) : NULL;
    if (nul)
    {
        size_t nul_line = 1;
        for (const char *p = data; p < nul; p++)
            if (*p == '\n') nul_line++;
        return config_error(source, nul_line, "config contains NUL");
    }
    size_t offset = 0, line = 0;
    int scope = -1, action = -1;
    unsigned int parents = 0, children[2] = {0, 0};
    const char *error = NULL;
    while (offset < length)
    {
        line++;
        size_t begin = offset;
        while (offset < length && data[offset] != '\n') offset++;
        const char *start = data + begin, *end = data + offset;
        if (offset < length) offset++;
        while (start < end && isspace((unsigned char)*start)) start++;
        while (end > start && isspace((unsigned char)end[-1])) end--;
        if (start == end || *start == '#') continue;
        if (*start == '[')
        {
            size_t n = (size_t)(end - start);
            int next_scope = n == 10 && memcmp(start, "[critical]", n) == 0 ? 0 :
                             n == 15 && memcmp(start, "[comprehensive]", n) == 0 ? 1 : -1;
            if (next_scope >= 0)
            {
                if (parents & (1U << next_scope)) { error = "repeated scope"; break; }
                parents |= 1U << next_scope;
                scope = next_scope;
                action = -1;
                continue;
            }
            int next_action = n == 9 && memcmp(start, "[include]", n) == 0 ? 0 :
                              n == 9 && memcmp(start, "[exclude]", n) == 0 ? 1 : -1;
            if (scope < 0 || next_action < 0) { error = "unknown or misplaced section"; break; }
            if (children[scope] & (1U << next_action)) { error = "repeated subsection"; break; }
            children[scope] |= 1U << next_action;
            action = next_action;
            continue;
        }
        if (action < 0) { error = "path outside include/exclude section"; break; }
        char path[PATH_MAX];
        if (decode_path(start, end, path) != 0) { error = "invalid or oversized path"; break; }
        if (parsed.count == CONFIG_MAX_RULES) { error = "too many rules"; break; }
        ConfigRule *rules = realloc(parsed.rules, (parsed.count + 1) * sizeof(*rules));
        if (!rules) { error = "out of memory"; break; }
        parsed.rules = rules;
        char *copy = strdup(path);
        if (!copy) { error = "out of memory"; break; }
        parsed.rules[parsed.count++] = (ConfigRule){(ConfigScope)scope,
                                                   (ConfigAction)action, copy, line};
    }
    if (error)
    {
        config_free(&parsed);
        return config_error(source, line, error);
    }
    *out = parsed;
    return 0;
}

int config_path(char **out)
{
    const char *base = getenv("XDG_CONFIG_HOME");
    const char *suffix = "/migr/migr.conf";
    if (!base || base[0] != '/')
    {
        base = getenv("HOME");
        suffix = "/.config/migr/migr.conf";
    }
    if (!base || base[0] != '/' || strlen(base) + strlen(suffix) >= PATH_MAX)
        return config_error("migr.conf", 0, "absolute HOME/config path required within PATH_MAX");
    if (asprintf(out, "%s%s", base, suffix) < 0)
    {
        *out = NULL;
        return config_error("migr.conf", 0, "out of memory");
    }
    return 0;
}

/* ENOENT through a dangling directory symlink is an error, not absent config. */
static int config_is_missing(const char *path)
{
    if (!*path || strlen(path) >= PATH_MAX) return 0;
    char prefix[PATH_MAX];
    strcpy(prefix, path);
    for (char *p = prefix + (prefix[0] == '/'); ; p++)
    {
        if (*p != '/' && *p != 0) continue;
        char saved = *p;
        *p = 0;
        struct stat st;
        if (lstat(prefix, &st) < 0) return errno == ENOENT;
        if (S_ISLNK(st.st_mode) && stat(prefix, &st) < 0) return 0;
        if (saved && !S_ISDIR(st.st_mode)) return 0;
        *p = saved;
        if (!saved) return 0;
    }
}

static int load_snapshot(const char *path, int missing_ok, Config *out)
{
    char resolved[PATH_MAX];
    if (!realpath(path, resolved))
    {
        if (errno == ENOENT && missing_ok && config_is_missing(path))
        {
            *out = (Config){0};
            return 0;
        }
        return config_error(path, 0, "cannot resolve config file");
    }
    int fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    if (fd < 0) return config_error(path, 0, "cannot open config file");
    struct stat before, after;
    char *data = NULL;
    int result = -1;
    const char *error = "cannot read regular config snapshot";
    if (fstat(fd, &before) < 0 || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || before.st_size > CONFIG_MAX_BYTES) goto done;
    data = malloc(CONFIG_MAX_BYTES + 1U);
    if (!data) goto done;
    size_t length = 0;
    for (;;)
    {
        ssize_t n = read(fd, data + length, CONFIG_MAX_BYTES + 1U - length);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (n == 0) break;
        length += (size_t)n;
        if (length > CONFIG_MAX_BYTES) goto done;
    }
    if (fstat(fd, &after) < 0) goto done;
    /* Atomic replacement can unlink the open old inode, changing only ctime
     * and link count. Its unchanged contents are still a valid snapshot. */
    if (before.st_size != after.st_size || (off_t)length != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        (before.st_nlink == after.st_nlink &&
         (before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
          before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)))
    {
        error = "config changed while reading";
        goto done;
    }
    result = config_parse(data, length, path, out);
    error = NULL;
done:
    free(data);
    if (close(fd) < 0 && result == 0)
    {
        config_free(out);
        error = "cannot close config snapshot";
        result = -1;
    }
    if (error) config_error(path, 0, error);
    return result;
}

int config_load(const char *path, Config *out)
{
    return load_snapshot(path, 1, out);
}

static const char template[] =
    "# Includes in critical also apply to comprehensive; do not repeat them.\n"
    "# Excludes apply only to their own scope. Repeat them to exclude from both.\n"
    "# Excludes win over includes. Paths are HOME-relative unless absolute.\n"
    "[critical]\n    [include]\n\n    [exclude]\n\n"
    "[comprehensive]\n    [include]\n\n    [exclude]\n";

static int create_template(const char *path)
{
    struct stat st;
    if (lstat(path, &st) == 0) return 0;
    if (errno != ENOENT) return -1;
    char parent[PATH_MAX];
    memcpy(parent, path, strlen(path) + 1);
    char *leaf = strrchr(parent, '/');
    if (!leaf) return -1;
    *leaf = 0;
    for (char *p = parent + 1; ; p++)
    {
        if (*p != '/' && *p != 0) continue;
        char saved = *p;
        *p = 0;
        int rc = mkdir(parent, 0700);
        if ((rc < 0 && errno != EEXIST) || stat(parent, &st) < 0 || !S_ISDIR(st.st_mode))
            return -1;
        *p = saved;
        if (!saved) break;
    }
    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s/.migr.conf-XXXXXX", parent);
    if (n < 0 || (size_t)n >= sizeof(temp)) return -1;
    int fd = mkostemp(temp, O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = -1;
    if (fchmod(fd, 0600) < 0) goto done;
    size_t offset = 0;
    while (offset < sizeof(template) - 1)
    {
        ssize_t written = write(fd, template + offset, sizeof(template) - 1 - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) goto done;
        offset += (size_t)written;
    }
    if (fsync(fd) < 0) goto done;
    /* link publishes the complete inode atomically without replacing a winner. */
    if (link(temp, path) < 0 && errno != EEXIST) goto done;
    rc = 0;
done:
    if (close(fd) < 0) rc = -1;
    if (unlink(temp) < 0) rc = -1;
    return rc;
}

/* Bounded shell-like quoting only; no shell evaluation. */
static int editor_argv(char *text, char **argv, size_t capacity, const char *path)
{
    char *readp = text, *writep = text;
    size_t count = 0;
    while (*readp)
    {
        while (isspace((unsigned char)*readp)) readp++;
        if (!*readp) break;
        if (count + 2 >= capacity) return -1;
        argv[count++] = writep;
        char quote = 0;
        while (*readp && (quote || !isspace((unsigned char)*readp)))
        {
            char c = *readp++;
            if (c == '\\' && quote != '\'')
            {
                if (!*readp) return -1;
                *writep++ = *readp++;
            }
            else if (c == quote) quote = 0;
            else if (!quote && (c == '\'' || c == '"')) quote = c;
            else *writep++ = c;
        }
        if (quote) return -1;
        while (isspace((unsigned char)*readp)) readp++;
        *writep++ = 0;
    }
    if (!count || !argv[0][0]) return -1;
    argv[count++] = (char *)path;
    argv[count] = NULL;
    return 0;
}

int config_edit(void)
{
    char *path = NULL;
    if (config_path(&path) < 0) return -1;
    int result = -1;
    char resolved[PATH_MAX];
    struct stat st;
    if (create_template(path) < 0 || !realpath(path, resolved) ||
        stat(resolved, &st) < 0 || !S_ISREG(st.st_mode))
    {
        config_error(path, 0, "cannot prepare regular config file");
        goto done;
    }
    const char *editor = getenv("EDITOR");
    if (!editor || !*editor) editor = getenv("VISUAL");
    if (!editor || !*editor) editor = "vi";
    if (strlen(editor) > 16384U)
    {
        config_error(path, 0, "editor command too long");
        goto done;
    }
    char *command = strdup(editor);
    if (!command) goto done;
    char *argv[128];
    if (editor_argv(command, argv, 128, resolved) < 0)
        config_error(path, 0, "invalid editor quoting or argument limit");
    else if (run_command(argv) != 0)
        config_error(path, 0, "editor failed");
    else
    {
        Config parsed = {0};
        if (stat(resolved, &st) < 0 || !S_ISREG(st.st_mode))
            config_error(path, 0, "editor removed the config or left a non-regular file");
        else
            result = load_snapshot(resolved, 0, &parsed);
        config_free(&parsed);
    }
    free(command);
done:
    free(path);
    return result;
}
