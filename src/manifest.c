#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manifest.h"
#include "utils.h" // path_join

/* ========================================================================= */
/* Legacy manifest — unchanged behaviour, renamed to make production's use   */
/* of it explicit now that a versioned model exists alongside it.           */
/* ========================================================================= */

const char * const legacy_manifest_keys[LEGACY_MANIFEST_XDG_COUNT] = {
    "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR", "XDG_PICTURES_DIR",
    "XDG_DESKTOP_DIR",   "XDG_VIDEOS_DIR",   "XDG_MUSIC_DIR"
};

int legacy_manifest_write(const char *backup_dir, const char * const *basenames, int n)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), backup_dir, "manifest.txt") != 0)
    {
        printf("Warning: Could not write manifest.txt\n");
        return 1;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf("Warning: Could not write manifest.txt\n");
        return 1;
    }

    for (int i = 0; i < n; i++)
    {
        // Write key-value pairs to manifest
        fprintf(f, "%s=%s\n", legacy_manifest_keys[i], basenames[i]);
    }

    fclose(f);
    return 0;
}

int legacy_manifest_read(const char *backup_dir, char **out, int n)
{
    for (int i = 0; i < n; i++)
        out[i] = NULL;

    char path[PATH_MAX];
    if (path_join(path, sizeof(path), backup_dir, "manifest.txt") != 0)
        return 1;

    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 1;

    char line[PATH_MAX + 32];
    while (fgets(line, sizeof(line), f) != NULL)
    {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        // Find the delimiter ('=')
        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;

        // Calculate key length using pointer arithmetic
        size_t key_len = (size_t)(eq - line);

        for (int i = 0; i < n; i++)
        {
            // Skip if already parsed
            if (out[i] != NULL)
                continue;

            // Optimization: Skip strncmp if lengths don't match
            if (strlen(legacy_manifest_keys[i]) != key_len)
                continue;

            // Match found
            if (strncmp(line, legacy_manifest_keys[i], key_len) != 0)
                continue;

            // Extract value starting right after '='
            char *val = eq + 1;
            size_t vlen = strlen(val);

            // Strip trailing newlines (CRLF/LF)
            while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r'))
                val[--vlen] = '\0';

            // Duplicate the string to heap and break inner loop
            out[i] = strdup(val);
            break;
        }
    }

    fclose(f);
    return 0;
}

/* ========================================================================= */
/* Versioned manifest (docs/DECISIONS.md D15, D16)                          */
/*                                                                           */
/* Grammar (v1), one field per line, fixed order, LF-terminated:            */
/*                                                                           */
/*   MIGR_MANIFEST                                                          */
/*   VERSION=1                                                              */
/*   REPRESENTATION=native|portable                                         */
/*   SCOPE=critical|comprehensive|explicit                                  */
/*   SIDECAR_VERSION=<uint>              (0 = no sidecar)                   */
/*   MACHINE_ID=<hex>                    (both lines present, or neither)   */
/*   SOURCE_UID=<uint>                                                      */
/*   ROOT_COUNT=<uint>                                                      */
/*   ROOT ID=<id> POLICY=<policy> PAYLOAD=<enc> SOURCE=<enc> [RESTORE=<enc>]*/
/*   ... exactly ROOT_COUNT such lines ...                                  */
/*                                                                           */
/* A field order is fixed because migr is the only writer and reader of     */
/* this file; a hand-edited, order-flexible format is not a goal here (that */
/* is what the future conf file is for). Every path-shaped value (PAYLOAD,  */
/* SOURCE, RESTORE) is percent-encoded byte-for-byte: a Linux path may      */
/* legally contain '=', '\n', '\t', a literal '%', or invalid UTF-8, none   */
/* of which may appear raw in this line-oriented format. RESTORE is present */
/* if and only if the root's policy is HOME_RELATIVE.                      */
/* ========================================================================= */

// Percent-encoded worst case is 3 bytes ("%XX") per source byte, plus NUL.
#define MANIFEST_ENC_MAX (3 * PATH_MAX + 1)
// A ROOT line carries up to three such encoded fields (PAYLOAD, SOURCE,
// RESTORE) plus ID/POLICY and their key labels; this bounds fgets() to a
// fixed stack buffer so a single read can never allocate without limit.
#define MANIFEST_MAX_LINE (3 * MANIFEST_ENC_MAX + 256)

static const char MANIFEST_MAGIC[] = "MIGR_MANIFEST";

static int is_id_safe_char(unsigned char c)
{
    return isalnum(c) || c == '_' || c == '-';
}

static int id_is_valid(const char *id)
{
    if (id == NULL || id[0] == '\0')
        return 0;
    size_t len = strlen(id);
    if (len >= MANIFEST_ID_MAX)
        return 0;
    for (size_t i = 0; i < len; i++)
        if (!is_id_safe_char((unsigned char)id[i]))
            return 0;
    return 1;
}

static int is_encode_safe_char(unsigned char c)
{
    return isalnum(c) || c == '.' || c == '_' || c == '/' || c == '-';
}

// Bytewise percent-encode: every byte outside the safe set becomes "%XX"
// (uppercase hex). Operates on raw is a NUL-terminated C string; paths never
// contain an embedded NUL at the syscall level, so treating it as a string
// (rather than requiring an explicit length) is sufficient here.
static int manifest_percent_encode(const char *raw, char *out, size_t out_size)
{
    if (raw == NULL || out == NULL || out_size == 0)
        return -1;

    size_t o = 0;
    for (size_t i = 0; raw[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)raw[i];
        if (is_encode_safe_char(c))
        {
            if (o + 1 >= out_size)
                return -1;
            out[o++] = (char)c;
        }
        else
        {
            if (o + 3 >= out_size)
                return -1;
            static const char hex[] = "0123456789ABCDEF";
            out[o++] = '%';
            out[o++] = hex[(c >> 4) & 0xF];
            out[o++] = hex[c & 0xF];
        }
    }
    out[o] = '\0';
    return 0;
}

static int hex_digit_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Decodes a manifest_percent_encode()-produced value. Fail-closed: any raw
// byte outside the safe set that is not part of a well-formed "%XX" escape is
// malformed input (our own writer never produces such a line), as is a "%" not
// followed by two valid hex digits or a result that would not fit out_size.
static int manifest_percent_decode(const char *encoded, char *out, size_t out_size)
{
    if (encoded == NULL || out == NULL || out_size == 0)
        return -1;

    size_t o = 0;
    for (size_t i = 0; encoded[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)encoded[i];
        int byte;
        if (c == '%')
        {
            int hi = hex_digit_value(encoded[i + 1] != '\0' ? encoded[i + 1] : '\0');
            int lo = hex_digit_value(encoded[i + 2] != '\0' ? encoded[i + 2] : '\0');
            if (hi < 0 || lo < 0)
                return -1;
            byte = (hi << 4) | lo;
            i += 2;
        }
        else if (is_encode_safe_char(c))
        {
            byte = c;
        }
        else
        {
            return -1; // raw byte our encoder would never emit unescaped
        }

        // A decoded NUL would silently truncate every C-string operation
        // downstream (strcmp/strlen/strcpy) at that point, hiding whatever
        // followed it. manifest_percent_encode() never produces "%00" for a
        // real path (paths cannot contain NUL at the syscall level), so this
        // can only be corruption or tampering -- refuse it, don't truncate.
        if (byte == 0)
            return -1;

        if (o + 1 >= out_size)
            return -1;
        out[o++] = (char)byte;
    }
    out[o] = '\0';
    return 0;
}

static const char *root_policy_to_string(RootPolicy p)
{
    switch (p)
    {
        case ROOT_POLICY_XDG:            return "XDG";
        case ROOT_POLICY_HOME_RELATIVE:  return "HOME_RELATIVE";
        case ROOT_POLICY_MANUAL_NATIVE:  return "MANUAL_NATIVE";
        default:                         return NULL; // fail closed on write, too
    }
}

static int root_policy_from_string(const char *s, RootPolicy *out)
{
    if (strcmp(s, "XDG") == 0)            { *out = ROOT_POLICY_XDG; return 0; }
    if (strcmp(s, "HOME_RELATIVE") == 0)  { *out = ROOT_POLICY_HOME_RELATIVE; return 0; }
    if (strcmp(s, "MANUAL_NATIVE") == 0)  { *out = ROOT_POLICY_MANUAL_NATIVE; return 0; }
    return -1;
}

static const char *representation_to_string(CloneRepresentation r)
{
    switch (r)
    {
        case CLONE_NATIVE_TREE:      return "native";
        case CLONE_PORTABLE_SIDECAR: return "portable";
        default:                     return NULL;
    }
}

static int representation_from_string(const char *s, CloneRepresentation *out)
{
    if (strcmp(s, "native") == 0)   { *out = CLONE_NATIVE_TREE; return 0; }
    if (strcmp(s, "portable") == 0) { *out = CLONE_PORTABLE_SIDECAR; return 0; }
    return -1;
}

static const char *scope_to_string(ManifestScope s)
{
    switch (s)
    {
        case MANIFEST_SCOPE_CRITICAL:      return "critical";
        case MANIFEST_SCOPE_COMPREHENSIVE: return "comprehensive";
        case MANIFEST_SCOPE_EXPLICIT:      return "explicit";
        default:                           return NULL;
    }
}

static int scope_from_string(const char *s, ManifestScope *out)
{
    if (strcmp(s, "critical") == 0)      { *out = MANIFEST_SCOPE_CRITICAL; return 0; }
    if (strcmp(s, "comprehensive") == 0) { *out = MANIFEST_SCOPE_COMPREHENSIVE; return 0; }
    if (strcmp(s, "explicit") == 0)      { *out = MANIFEST_SCOPE_EXPLICIT; return 0; }
    return -1;
}

// Parses a full non-negative integer with no trailing garbage, and rejects a
// value beyond max -- callers pass the true range of the field they intend to
// store the result in (e.g. INT_MAX for an int field, a uid_t-derived bound
// for source_uid), so a huge on-disk number is refused here rather than
// silently wrapping when later cast to that narrower type. uintmax_t is used
// rather than long: long's width varies by platform (e.g. a 32-bit build),
// while uintmax_t is guaranteed wide enough to hold the maximum value of any
// standard unsigned type, including uid_t's, without its own overflow.
// Rejects empty strings, leading whitespace/sign -- strtoumax() itself would
// otherwise accept a leading '-' and silently wrap it into a huge value --
// and anything left unconsumed as a "partial" match.
static int parse_uint_field(const char *s, uintmax_t max, uintmax_t *out)
{
    if (s == NULL || s[0] == '\0' || !isdigit((unsigned char)s[0]))
        return -1;
    char *end;
    errno = 0;
    uintmax_t v = strtoumax(s, &end, 10);
    if (errno != 0 || *end != '\0' || v > max)
        return -1;
    *out = v;
    return 0;
}

// uid_t's own maximum, derived rather than assumed -- uintmax_t can hold it
// exactly regardless of uid_t's or long's actual width on a given platform.
#define MANIFEST_UID_MAX ((uintmax_t)(uid_t)-1)

// Strips exactly one trailing "\r\n" or "\n", in place.
static void chomp(char *line)
{
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        line[--len] = '\0';
    if (len > 0 && line[len - 1] == '\r')
        line[--len] = '\0';
}

// Reads one line into a fixed buffer. Returns 1 on a normal line, 0 on a
// clean EOF with nothing read, -1 if the line did not fit (never grown to
// accommodate it -- the buffer is a fixed stack array, so a hostile huge line
// is rejected rather than allocated for), or -2 on a genuine stream read
// error (ferror), which is distinct from EOF: e.g. manifest.txt being a
// directory opens successfully but fails on the first read with EISDIR.
static int read_line(FILE *f, char *buf, size_t buf_size)
{
    if (fgets(buf, (int)buf_size, f) == NULL)
        return ferror(f) ? -2 : 0;
    size_t len = strlen(buf);
    if (len == buf_size - 1 && buf[len - 1] != '\n' && !feof(f))
        return -1; // line longer than our bound
    chomp(buf);
    return 1;
}

// Validates a MACHINE_ID value against the same rule on both read and write,
// so the writer can never produce a manifest the reader then rejects.
static int machine_id_is_valid(const char *s)
{
    if (s == NULL || s[0] == '\0' || strlen(s) >= MANIFEST_MACHINE_ID_MAX)
        return 0;
    for (size_t i = 0; s[i] != '\0'; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

// Matches "KEY=value": on success returns a pointer to value within line
// (line is mutated: the '=' becomes NUL) and stores the key length via
// key_len, so the caller can compare against several expected keys.
static char *split_kv(char *line, size_t *key_len)
{
    char *eq = strchr(line, '=');
    if (eq == NULL)
        return NULL;
    *key_len = (size_t)(eq - line);
    *eq = '\0';
    return eq + 1;
}

static int line_key_is(const char *line, const char *key, size_t key_len)
{
    return strlen(key) == key_len && strncmp(line, key, key_len) == 0;
}

// Reads one required line and, on a genuine stream fault (as opposed to EOF
// or an oversized line), promotes *fail_status to IO_ERROR so the caller's
// "goto fail" reports precisely why the parse stopped.
static int read_required_line(FILE *f, char *buf, size_t buf_size, ManifestStatus *fail_status)
{
    int rc = read_line(f, buf, buf_size);
    if (rc == -2)
        *fail_status = MANIFEST_STATUS_IO_ERROR;
    return rc;
}

// Parses one "ROOT ID=... POLICY=... PAYLOAD=... SOURCE=... [RESTORE=...]"
// line into root. line is mutated (tokenized in place via strtok_r).
static int parse_root_line(char *line, ManifestRoot *root)
{
    memset(root, 0, sizeof(*root));

    char *saveptr;
    char *tok = strtok_r(line, " \t", &saveptr);
    if (tok == NULL || strcmp(tok, "ROOT") != 0)
        return -1;

    int seen_id = 0, seen_policy = 0, seen_payload = 0, seen_source = 0, seen_restore = 0;

    while ((tok = strtok_r(NULL, " \t", &saveptr)) != NULL)
    {
        size_t key_len;
        char *value = split_kv(tok, &key_len);
        if (value == NULL)
            return -1;

        if (line_key_is(tok, "ID", key_len))
        {
            if (seen_id || !id_is_valid(value))
                return -1;
            strncpy(root->id, value, MANIFEST_ID_MAX - 1);
            root->id[MANIFEST_ID_MAX - 1] = '\0';
            seen_id = 1;
        }
        else if (line_key_is(tok, "POLICY", key_len))
        {
            if (seen_policy || root_policy_from_string(value, &root->policy) != 0)
                return -1;
            seen_policy = 1;
        }
        else if (line_key_is(tok, "PAYLOAD", key_len))
        {
            if (seen_payload || manifest_percent_decode(value, root->payload_path, sizeof(root->payload_path)) != 0)
                return -1;
            seen_payload = 1;
        }
        else if (line_key_is(tok, "SOURCE", key_len))
        {
            if (seen_source || manifest_percent_decode(value, root->source_path, sizeof(root->source_path)) != 0)
                return -1;
            seen_source = 1;
        }
        else if (line_key_is(tok, "RESTORE", key_len))
        {
            if (seen_restore || manifest_percent_decode(value, root->restore_path, sizeof(root->restore_path)) != 0)
                return -1;
            root->has_restore_path = 1;
            seen_restore = 1;
        }
        else
        {
            return -1; // unrecognized field
        }
    }

    if (!seen_id || !seen_policy || !seen_payload || !seen_source)
        return -1;

    // RESTORE is required for HOME_RELATIVE and forbidden for every other
    // policy — it is the one field whose presence is policy-conditioned.
    if (root->policy == ROOT_POLICY_HOME_RELATIVE && !seen_restore)
        return -1;
    if (root->policy != ROOT_POLICY_HOME_RELATIVE && seen_restore)
        return -1;

    return 0;
}

// Scans line1 (already read) and the remaining lines of f for at least one
// that matches a known legacy_manifest_keys[] "KEY=value" line. This is the
// only thing that makes manifest_read_v1() classify a non-magic file as
// LEGACY: content that is merely KEY=value-shaped but matches none of the six
// known keys -- including an empty file, or a corrupted/truncated attempt at
// our own magic that happens to leave a "VERSION=..."-looking line first --
// is ambiguous and must not be silently treated as "probably the old
// format". legacy_manifest_read() remains the actual legacy parser; this
// only decides whether to route there at all. Returns -1 on a stream error,
// 0 when no key is found, and 1 when a recognized key is found.
static int contains_legacy_key(const char *line1, FILE *f)
{
    char scratch[PATH_MAX + 32]; // legacy lines are always short: "XDG_KEY=basename"
    const char *cur = line1;

    for (;;)
    {
        const char *eq = strchr(cur, '=');
        if (eq != NULL)
        {
            size_t key_len = (size_t)(eq - cur);
            for (int i = 0; i < LEGACY_MANIFEST_XDG_COUNT; i++)
                if (strlen(legacy_manifest_keys[i]) == key_len &&
                    strncmp(cur, legacy_manifest_keys[i], key_len) == 0)
                    return 1;
        }
        if (fgets(scratch, sizeof(scratch), f) == NULL)
            return ferror(f) ? -1 : 0;
        cur = scratch;
    }
}

// Parses manifest.txt content from an already-open, readable stream -- shared
// by manifest_read_v1() (opens by path) and manifest_read_v1_at() (opens by
// directory fd), so the two can never classify the same magic/version/content
// differently. Always takes ownership of f: every return path fclose()s it.
static ManifestStatus manifest_parse_v1_body(FILE *f, Manifest *out)
{
    char line[MANIFEST_MAX_LINE];
    int rc = read_line(f, line, sizeof(line));
    if (rc == -2)
    {
        fclose(f);
        return MANIFEST_STATUS_IO_ERROR; // e.g. manifest.txt is a directory: opens, fails to read
    }
    if (rc != 1 || strcmp(line, MANIFEST_MAGIC) != 0)
    {
        // Not our magic (rc==0: empty file; rc==-1: unreadably long first
        // line; rc==1 but different content). Only genuinely legacy-shaped
        // content -- at least one recognized XDG key anywhere in the file --
        // is routed to the legacy path; see contains_legacy_key().
        int legacy_status = (rc == 1) ? contains_legacy_key(line, f) : 0;
        fclose(f);
        if (legacy_status < 0)
            return MANIFEST_STATUS_IO_ERROR;
        return legacy_status > 0 ? MANIFEST_STATUS_LEGACY : MANIFEST_STATUS_MALFORMED;
    }

    ManifestStatus fail_status = MANIFEST_STATUS_MALFORMED;
    Manifest m;
    memset(&m, 0, sizeof(m));

    // VERSION=<uint>
    size_t key_len = 0;
    char *value = NULL;
    uintmax_t n = 0;
    if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
    if ((value = split_kv(line, &key_len)) == NULL || !line_key_is(line, "VERSION", key_len)) goto fail;
    if (parse_uint_field(value, INT_MAX, &n) != 0) goto fail;
    if (n != MANIFEST_CURRENT_VERSION) { fail_status = MANIFEST_STATUS_UNKNOWN_VERSION; goto fail; }
    m.version = (int)n;

    // REPRESENTATION=native|portable
    if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
    if ((value = split_kv(line, &key_len)) == NULL || !line_key_is(line, "REPRESENTATION", key_len)) goto fail;
    if (representation_from_string(value, &m.representation) != 0) goto fail;

    // SCOPE=critical|comprehensive|explicit
    if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
    if ((value = split_kv(line, &key_len)) == NULL || !line_key_is(line, "SCOPE", key_len)) goto fail;
    if (scope_from_string(value, &m.scope) != 0) goto fail;

    // SIDECAR_VERSION=<uint>
    if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
    if ((value = split_kv(line, &key_len)) == NULL || !line_key_is(line, "SIDECAR_VERSION", key_len)) goto fail;
    if (parse_uint_field(value, INT_MAX, &n) != 0) goto fail;
    m.sidecar_version = (int)n;

    // Optional MACHINE_ID=<hex> / SOURCE_UID=<uint> pair — both or neither.
    if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
    if ((value = split_kv(line, &key_len)) == NULL) goto fail;
    if (line_key_is(line, "MACHINE_ID", key_len))
    {
        if (!machine_id_is_valid(value)) goto fail;
        strncpy(m.machine_id, value, MANIFEST_MACHINE_ID_MAX - 1);
        m.machine_id[MANIFEST_MACHINE_ID_MAX - 1] = '\0';

        if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
        if ((value = split_kv(line, &key_len)) == NULL || !line_key_is(line, "SOURCE_UID", key_len)) goto fail;
        if (parse_uint_field(value, MANIFEST_UID_MAX, &n) != 0) goto fail;
        m.source_uid = (uid_t)n;
        m.has_source_identity = 1;

        if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
        if ((value = split_kv(line, &key_len)) == NULL) goto fail;
    }
    // 'value'/'line' now holds whatever line follows the optional identity pair.

    // ROOT_COUNT=<uint>
    if (!line_key_is(line, "ROOT_COUNT", key_len)) goto fail;
    if (parse_uint_field(value, MANIFEST_MAX_ROOTS, &n) != 0) goto fail;
    m.root_count = (int)n;

    if (m.root_count > 0)
    {
        m.roots = calloc((size_t)m.root_count, sizeof(ManifestRoot));
        if (m.roots == NULL) { fail_status = MANIFEST_STATUS_IO_ERROR; goto fail; }
    }

    for (int i = 0; i < m.root_count; i++)
    {
        if (read_required_line(f, line, sizeof(line), &fail_status) <= 0) goto fail;
        if (parse_root_line(line, &m.roots[i]) != 0) goto fail;
        for (int j = 0; j < i; j++)
            if (strcmp(m.roots[j].id, m.roots[i].id) == 0) goto fail; // duplicate id
    }

    // No trailing content beyond the declared roots.
    {
        int trailing_rc = read_line(f, line, sizeof(line));
        if (trailing_rc == -2) { fail_status = MANIFEST_STATUS_IO_ERROR; goto fail; }
        if (trailing_rc != 0) goto fail;
    }

    fclose(f);
    *out = m;
    return MANIFEST_STATUS_VALID;

fail:
    fclose(f);
    free(m.roots);
    memset(out, 0, sizeof(*out));
    return fail_status;
}

ManifestStatus manifest_read_v1(const char *backup_dir, Manifest *out)
{
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    if (backup_dir == NULL || out == NULL)
        return MANIFEST_STATUS_IO_ERROR;

    char path[PATH_MAX];
    if (path_join(path, sizeof(path), backup_dir, "manifest.txt") != 0)
        return MANIFEST_STATUS_IO_ERROR;

    FILE *f = fopen(path, "r");
    if (f == NULL)
        return (errno == ENOENT) ? MANIFEST_STATUS_MISSING : MANIFEST_STATUS_IO_ERROR;

    return manifest_parse_v1_body(f, out);
}

ManifestStatus manifest_read_v1_at(int container_fd, Manifest *out)
{
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    if (out == NULL)
        return MANIFEST_STATUS_IO_ERROR;

    int fd = openat(container_fd, "manifest.txt", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        if (errno == ENOENT)
            return MANIFEST_STATUS_MISSING;
        // Two open()-time failures mean "this is a non-regular object", not
        // an operational error: O_NOFOLLOW makes a symlink fail with ELOOP
        // rather than being followed, and open() can never succeed on a Unix
        // domain socket at all -- it always fails ENXIO, regardless of flags,
        // so a socket never even reaches the fstat()+S_ISREG check below.
        if (errno == ELOOP || errno == ENXIO)
            return MANIFEST_STATUS_MALFORMED;
        return MANIFEST_STATUS_IO_ERROR;
    }

    // A FIFO/device opened O_NONBLOCK never blocks here even with no writer
    // on the other end. fstat() failing outright is a genuine operational
    // fault (IO_ERROR); fstat() succeeding but reporting a non-regular mode
    // (FIFO, device, directory) means "not adoptable" (MALFORMED) -- the two
    // must not be collapsed into one, or a real I/O fault would be silently
    // treated as just another non-regular candidate.
    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return MANIFEST_STATUS_IO_ERROR;
    }
    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        return MANIFEST_STATUS_MALFORMED;
    }

    FILE *f = fdopen(fd, "r");
    if (f == NULL)
    {
        close(fd);
        return MANIFEST_STATUS_IO_ERROR;
    }

    return manifest_parse_v1_body(f, out);
}

// Two roots are the same identity if every field the manifest actually
// records about them matches -- not just id, which by itself only proves
// they occupy the same slot, not that the slot means the same thing.
static int root_identity_equal(const ManifestRoot *a, const ManifestRoot *b)
{
    if (strcmp(a->id, b->id) != 0)
        return 0;
    if (a->policy != b->policy)
        return 0;
    if (strcmp(a->payload_path, b->payload_path) != 0)
        return 0;
    if (strcmp(a->source_path, b->source_path) != 0)
        return 0;
    if (a->has_restore_path != b->has_restore_path)
        return 0;
    if (a->has_restore_path && strcmp(a->restore_path, b->restore_path) != 0)
        return 0;
    return 1;
}

static int root_ptr_id_cmp(const void *pa, const void *pb)
{
    const ManifestRoot *a = *(const ManifestRoot * const *)pa;
    const ManifestRoot *b = *(const ManifestRoot * const *)pb;
    return strcmp(a->id, b->id);
}

ManifestIdentityComparison manifest_resume_identity_compare(const Manifest *a, const Manifest *b)
{
    if (a == NULL || b == NULL)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->version != b->version)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->representation != b->representation)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->scope != b->scope)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->sidecar_version != b->sidecar_version)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (!a->has_source_identity || !b->has_source_identity)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (strcmp(a->machine_id, b->machine_id) != 0)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->source_uid != b->source_uid)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->root_count != b->root_count)
        return MANIFEST_IDENTITY_DIFFERENT;
    if (a->root_count == 0)
        return MANIFEST_IDENTITY_EQUAL;
    if (a->roots == NULL || b->roots == NULL)
        return MANIFEST_IDENTITY_DIFFERENT;

    // Root sets are equal irrespective of on-disk/in-memory order: sort a
    // fresh array of pointers per side (never mutating the caller's roots)
    // by id, then compare pairwise.
    int n = a->root_count;
    ManifestIdentityComparison result;
    const ManifestRoot **sa = malloc((size_t)n * sizeof(*sa));
    const ManifestRoot **sb = malloc((size_t)n * sizeof(*sb));
    if (sa == NULL || sb == NULL)
    {
        // An allocation failure is an operational failure, not proof the two
        // manifests differ -- the caller must not treat this the same as a
        // genuine mismatch (see container_adopt(), docs/DECISIONS.md D15).
        result = MANIFEST_IDENTITY_ERROR;
        goto done;
    }

    for (int i = 0; i < n; i++)
    {
        sa[i] = &a->roots[i];
        sb[i] = &b->roots[i];
    }
    qsort(sa, (size_t)n, sizeof(*sa), root_ptr_id_cmp);
    qsort(sb, (size_t)n, sizeof(*sb), root_ptr_id_cmp);

    result = MANIFEST_IDENTITY_EQUAL;
    for (int i = 0; i < n; i++)
        if (!root_identity_equal(sa[i], sb[i]))
        {
            result = MANIFEST_IDENTITY_DIFFERENT;
            break;
        }

done:
    free(sa);
    free(sb);
    return result;
}

int manifest_write_v1(const char *backup_dir, const Manifest *m)
{
    if (backup_dir == NULL || m == NULL)
        return 1;

    // ---- Full validation pass, no filesystem access below this point. ----
    // fopen(path, "w") truncates immediately; validating the *entire* model
    // first guarantees this function either writes nothing at all, or writes
    // a file manifest_read_v1() is guaranteed to accept -- never a truncated
    // or content-invalid manifest.txt left behind by a failure discovered
    // partway through writing.

    if (m->version != MANIFEST_CURRENT_VERSION)
        return 1;

    const char *repr_str = representation_to_string(m->representation);
    const char *scope_str = scope_to_string(m->scope);
    if (repr_str == NULL || scope_str == NULL)
        return 1;

    if (m->sidecar_version < 0)
        return 1;

    if (m->has_source_identity && !machine_id_is_valid(m->machine_id))
        return 1;
    // source_uid is a uid_t: any value it can hold is in range for the type;
    // nothing further to validate there.

    if (m->root_count < 0 || m->root_count > MANIFEST_MAX_ROOTS)
        return 1;
    if (m->root_count > 0 && m->roots == NULL)
        return 1;

    {
        char scratch[MANIFEST_ENC_MAX];
        for (int i = 0; i < m->root_count; i++)
        {
            const ManifestRoot *r = &m->roots[i];
            if (!id_is_valid(r->id) || root_policy_to_string(r->policy) == NULL)
                return 1;
            if (manifest_percent_encode(r->payload_path, scratch, sizeof(scratch)) != 0)
                return 1;
            if (manifest_percent_encode(r->source_path, scratch, sizeof(scratch)) != 0)
                return 1;
            if (r->policy == ROOT_POLICY_HOME_RELATIVE)
            {
                if (!r->has_restore_path)
                    return 1;
                if (manifest_percent_encode(r->restore_path, scratch, sizeof(scratch)) != 0)
                    return 1;
            }
            else if (r->has_restore_path)
            {
                return 1;
            }
            // manifest_read_v1() refuses any two roots sharing an id; the
            // writer must refuse the same thing, or it can truncate an
            // existing valid manifest.txt with content the reader rejects.
            for (int j = 0; j < i; j++)
                if (strcmp(m->roots[j].id, r->id) == 0)
                    return 1;
        }
    }

    // ---- Every field is proven valid and reader-compatible; only now does
    // this function touch the filesystem. ----

    char path[PATH_MAX];
    if (path_join(path, sizeof(path), backup_dir, "manifest.txt") != 0)
        return 1;

    FILE *f = fopen(path, "w");
    if (f == NULL)
        return 1;

    int failed = 0;
    if (fprintf(f, "%s\n", MANIFEST_MAGIC) < 0) failed = 1;
    if (!failed && fprintf(f, "VERSION=%d\n", m->version) < 0) failed = 1;
    if (!failed && fprintf(f, "REPRESENTATION=%s\n", repr_str) < 0) failed = 1;
    if (!failed && fprintf(f, "SCOPE=%s\n", scope_str) < 0) failed = 1;
    if (!failed && fprintf(f, "SIDECAR_VERSION=%d\n", m->sidecar_version) < 0) failed = 1;

    if (!failed && m->has_source_identity)
    {
        if (fprintf(f, "MACHINE_ID=%s\n", m->machine_id) < 0) failed = 1;
        if (!failed && fprintf(f, "SOURCE_UID=%lu\n", (unsigned long)m->source_uid) < 0) failed = 1;
    }

    if (!failed && fprintf(f, "ROOT_COUNT=%d\n", m->root_count) < 0) failed = 1;

    char enc_payload[MANIFEST_ENC_MAX];
    char enc_source[MANIFEST_ENC_MAX];
    char enc_restore[MANIFEST_ENC_MAX];

    // Every field below was already proven valid in the pass above; these
    // encode calls and the enum-to-string lookup cannot fail here, but the
    // return values are still checked -- defense in depth costs nothing and
    // this codebase never assumes a call "cannot" fail.
    for (int i = 0; !failed && i < m->root_count; i++)
    {
        const ManifestRoot *r = &m->roots[i];
        const char *policy_str = root_policy_to_string(r->policy);
        if (policy_str == NULL) { failed = 1; break; }
        if (manifest_percent_encode(r->payload_path, enc_payload, sizeof(enc_payload)) != 0) { failed = 1; break; }
        if (manifest_percent_encode(r->source_path, enc_source, sizeof(enc_source)) != 0) { failed = 1; break; }

        if (r->policy == ROOT_POLICY_HOME_RELATIVE)
        {
            if (manifest_percent_encode(r->restore_path, enc_restore, sizeof(enc_restore)) != 0) { failed = 1; break; }
            if (fprintf(f, "ROOT ID=%s POLICY=%s PAYLOAD=%s SOURCE=%s RESTORE=%s\n",
                        r->id, policy_str, enc_payload, enc_source, enc_restore) < 0)
                failed = 1;
        }
        else
        {
            if (fprintf(f, "ROOT ID=%s POLICY=%s PAYLOAD=%s SOURCE=%s\n",
                        r->id, policy_str, enc_payload, enc_source) < 0)
                failed = 1;
        }
    }

    if (!failed && fflush(f) != 0) failed = 1;
    if (fclose(f) != 0) failed = 1;

    return failed ? 1 : 0;
}

void manifest_free(Manifest *m)
{
    if (m == NULL)
        return;
    free(m->roots);
    m->roots = NULL;
    m->root_count = 0;
}
