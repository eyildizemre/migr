// Unit tests for the versioned manifest model (docs/DECISIONS.md D15, D16) and for
// the legacy manifest, which is now read-only.
//
// Both public writers are covered: manifest_write_v1_at(), which is what
// production calls with the container's own directory fd, and the pathname
// entry that wraps it. They share one validator and one serializer, and the
// cases below assert that shared-ness directly rather than assuming it.
//
// manifest_percent_encode/decode are file-local to manifest.c and are proven
// here indirectly, through round trips carrying the exact problem bytes the
// format exists to survive.

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manifest.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static char test_dir[] = "/tmp/migr_manifest_XXXXXX";

static void write_raw(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "could not write fixture %s" NC "\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

// Like write_raw(), but writes an explicit byte range rather than a
// NUL-terminated C string, so the fixture can carry a raw embedded NUL
// byte -- something no strlen()/fputs()-based helper can represent.
static void write_raw_bytes(const char *path, const char *prefix,
                            const unsigned char *raw, size_t raw_len)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "could not write fixture %s" NC "\n", path);
        exit(1);
    }
    if (fputs(prefix, f) < 0 || fwrite(raw, 1, raw_len, f) != raw_len)
    {
        printf(RED "could not write fixture content %s" NC "\n", path);
        exit(1);
    }
    fclose(f);
}

static void remove_manifest(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", dir);
    unlink(path);
}

// ---- percent encode/decode, exercised through the public round-trip below ----
// (manifest_percent_encode/decode are file-local to manifest.c; they are proven
// here indirectly, through full manifest round trips that carry the exact
// problem bytes the format exists to survive: '=', '\n', '\t', '%', and a raw
// byte outside valid UTF-8.)

static void test_full_roundtrip_with_problem_bytes(void)
{
    printf(BLUE "::" NC " versioned manifest: full round trip\n");

    Manifest m;
    memset(&m, 0, sizeof(m));
    m.version = MANIFEST_CURRENT_VERSION;
    m.representation = CLONE_NATIVE_TREE;
    m.scope = MANIFEST_SCOPE_EXPLICIT;
    m.sidecar_version = 0;
    m.has_source_identity = 1;
    strcpy(m.machine_id, "deadbeefcafef00d0123456789abcdef");
    m.source_uid = 1000;

    ManifestRoot roots[2];
    memset(roots, 0, sizeof(roots));

    strcpy(roots[0].id, "EXPLICIT_0");
    roots[0].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[0].payload_path, "Projects/game");
    // Deliberately contains '=', a tab, a newline, a literal '%', and a raw
    // byte outside valid UTF-8 (0xFF) -- exactly what a raw KEY=value line
    // cannot carry, and exactly what percent-encoding must survive.
    strcpy(roots[0].source_path, "we\xFFird=name\twith%percent\nand-newline");
    strcpy(roots[0].restore_path, "Projects/game");
    roots[0].has_restore_path = 1;

    strcpy(roots[1].id, "EXPLICIT_1");
    roots[1].policy = ROOT_POLICY_MANUAL_NATIVE;
    strcpy(roots[1].payload_path, "EXPLICIT_1");
    strcpy(roots[1].source_path, "/mnt/data/external-project");
    roots[1].has_restore_path = 0;

    m.root_count = 2;
    m.roots = roots; // stack array: fine for manifest_write_v1, which does not take ownership

    check(manifest_write_v1(test_dir, &m) == 0, "manifest_write_v1 succeeds");

    Manifest read;
    ManifestStatus st = manifest_read_v1(test_dir, &read);
    check(st == MANIFEST_STATUS_VALID, "written manifest reads back as VALID");

    if (st == MANIFEST_STATUS_VALID)
    {
        check(read.version == MANIFEST_CURRENT_VERSION, "version round-trips");
        check(read.representation == CLONE_NATIVE_TREE, "representation round-trips");
        check(read.scope == MANIFEST_SCOPE_EXPLICIT, "scope round-trips");
        check(read.sidecar_version == 0, "sidecar_version round-trips");
        check(read.has_source_identity == 1, "source identity presence round-trips");
        check(strcmp(read.machine_id, m.machine_id) == 0, "machine_id round-trips");
        check(read.source_uid == 1000, "source_uid round-trips");
        check(read.root_count == 2, "root_count round-trips");

        if (read.root_count == 2)
        {
            check(strcmp(read.roots[0].id, "EXPLICIT_0") == 0, "root 0 id round-trips");
            check(read.roots[0].policy == ROOT_POLICY_HOME_RELATIVE, "root 0 policy round-trips");
            check(strcmp(read.roots[0].payload_path, "Projects/game") == 0,
                  "root 0 payload_path round-trips");
            check(strcmp(read.roots[0].source_path,
                         "we\xFFird=name\twith%percent\nand-newline") == 0,
                  "root 0 source_path survives '=', tab, newline, '%%', and a non-UTF-8 byte");
            check(read.roots[0].has_restore_path == 1 &&
                  strcmp(read.roots[0].restore_path, "Projects/game") == 0,
                  "root 0 restore_path round-trips");

            check(strcmp(read.roots[1].id, "EXPLICIT_1") == 0, "root 1 id round-trips");
            check(read.roots[1].policy == ROOT_POLICY_MANUAL_NATIVE, "root 1 policy round-trips");
            check(read.roots[1].has_restore_path == 0,
                  "MANUAL_NATIVE root carries no restore address");
        }

        manifest_free(&read); // heap-owned (calloc'd by manifest_read_v1) -- safe to free
    }

    remove_manifest(test_dir);
}

static void test_no_source_identity(void)
{
    printf(BLUE "::" NC " versioned manifest: no source identity\n");

    Manifest m;
    memset(&m, 0, sizeof(m));
    m.version = MANIFEST_CURRENT_VERSION;
    m.representation = CLONE_PORTABLE_SIDECAR;
    m.scope = MANIFEST_SCOPE_CRITICAL;
    m.sidecar_version = 1;
    m.has_source_identity = 0;
    m.root_count = 0;
    m.roots = NULL;

    check(manifest_write_v1(test_dir, &m) == 0, "zero-root manifest without identity writes");

    Manifest read;
    ManifestStatus st = manifest_read_v1(test_dir, &read);
    check(st == MANIFEST_STATUS_VALID, "reads back as VALID");
    check(read.has_source_identity == 0, "absent identity round-trips as absent");
    check(read.representation == CLONE_PORTABLE_SIDECAR, "portable representation round-trips");
    check(read.sidecar_version == 1, "non-zero sidecar_version round-trips");
    check(read.root_count == 0 && read.roots == NULL, "zero roots leaves roots NULL");
    manifest_free(&read);
    manifest_free(&read); // second call on an already-freed Manifest must not crash

    remove_manifest(test_dir);
}

static void test_missing(void)
{
    printf(BLUE "::" NC " versioned manifest: missing\n");

    remove_manifest(test_dir);
    Manifest m;
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MISSING,
          "no manifest.txt at all -> MISSING");
}

static void test_legacy_detection(void)
{
    printf(BLUE "::" NC " versioned manifest: legacy detection\n");

    // Production no longer writes this format at all, so the fixture is the
    // literal on-disk shape earlier versions of migr produced -- exactly what a
    // reader that must keep those backups restorable has to accept.
    const char *basenames[LEGACY_MANIFEST_XDG_COUNT] = {
        "Belgeler", "Indirilenler", "Resimler", "Masaustu", "Videolar", "Muzik"
    };
    char legacy_path[512];
    snprintf(legacy_path, sizeof(legacy_path), "%s/manifest.txt", test_dir);
    {
        FILE *f = fopen(legacy_path, "w");
        check(f != NULL, "fixture: an unversioned manifest.txt can be written");
        if (f != NULL)
        {
            for (int i = 0; i < LEGACY_MANIFEST_XDG_COUNT; i++)
                fprintf(f, "%s=%s\n", legacy_manifest_keys[i], basenames[i]);
            fclose(f);
        }
    }

    Manifest m;
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_LEGACY,
          "an unversioned XDG-key manifest -> LEGACY, not MALFORMED");

    char *out[LEGACY_MANIFEST_XDG_COUNT];
    check(legacy_manifest_read(test_dir, out, LEGACY_MANIFEST_XDG_COUNT) == 0,
          "legacy_manifest_read still parses its own output");
    check(out[0] != NULL && strcmp(out[0], "Belgeler") == 0,
          "legacy_manifest_read still recovers the source-locale basename");
    for (int i = 0; i < LEGACY_MANIFEST_XDG_COUNT; i++)
        free(out[i]);

    remove_manifest(test_dir);

    // The bar for LEGACY is "at least one recognized legacy key", not merely
    // "not our magic" -- these three must all fall to MALFORMED instead.
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);

    write_raw(path, "NOT_AN_XDG_KEY=value\n");
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
          "a KEY=value line whose key matches none of the six is MALFORMED, not LEGACY");
    remove_manifest(test_dir);

    write_raw(path, "VERSION=1\n");
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
          "a lone 'VERSION=1' (e.g. the magic line lost to corruption) is MALFORMED, not LEGACY");
    remove_manifest(test_dir);

    write_raw(path, "");
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
          "an empty existing manifest.txt is MALFORMED, not LEGACY");
    remove_manifest(test_dir);
}

static void test_unknown_version(void)
{
    printf(BLUE "::" NC " versioned manifest: unknown version\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
    write_raw(path,
        "MIGR_MANIFEST\n"
        "VERSION=999\n");

    Manifest m;
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_UNKNOWN_VERSION,
          "an unrecognized VERSION -> UNKNOWN_VERSION, not MALFORMED or MISSING");

    remove_manifest(test_dir);
}

// Writes a minimal, otherwise-valid header (magic..ROOT_COUNT), then whatever
// root_lines contains, and checks the resulting status.
static void check_malformed(const char *root_lines, const char *label)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);

    char content[8192];
    snprintf(content, sizeof(content),
        "MIGR_MANIFEST\n"
        "VERSION=1\n"
        "REPRESENTATION=native\n"
        "SCOPE=critical\n"
        "SIDECAR_VERSION=0\n"
        "ROOT_COUNT=1\n"
        "%s",
        root_lines);
    write_raw(path, content);

    Manifest m;
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED, label);
    remove_manifest(test_dir);
}

static void test_malformed_variants(void)
{
    printf(BLUE "::" NC " versioned manifest: malformed content is refused, never guessed\n");

    check_malformed("", "truncated: no root line at all where one was declared");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=NOT_A_POLICY PAYLOAD=a SOURCE=a\n",
        "unknown POLICY value");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=a SOURCE=a%ZZbad\n",
        "'%%' not followed by two hex digits");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=a SOURCE=a% RESTORE=a\n",
        "a trailing '%%' with no hex digits is refused");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=a SOURCE=a%4 RESTORE=a\n",
        "a trailing '%%' with only one hex digit is refused");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=a SOURCE=a%00hidden RESTORE=a\n",
        "'%%00' (an embedded NUL) is refused, not silently truncated");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=a SOURCE=a\n",
        "HOME_RELATIVE without a RESTORE field");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=a RESTORE=a\n",
        "MANUAL_NATIVE carrying a forbidden RESTORE field");

    check_malformed(
        "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=a\n"
        "TRAILING_GARBAGE=1\n",
        "trailing content after the declared root count");

    // Duplicate root id: declare two roots, both named the same.
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        write_raw(path,
            "MIGR_MANIFEST\n"
            "VERSION=1\n"
            "REPRESENTATION=native\n"
            "SCOPE=critical\n"
            "SIDECAR_VERSION=0\n"
            "ROOT_COUNT=2\n"
            "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=a\n"
            "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=b SOURCE=b\n");
        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "duplicate root id");
        remove_manifest(test_dir);
    }

    // MACHINE_ID present without a following SOURCE_UID.
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        write_raw(path,
            "MIGR_MANIFEST\n"
            "VERSION=1\n"
            "REPRESENTATION=native\n"
            "SCOPE=critical\n"
            "SIDECAR_VERSION=0\n"
            "MACHINE_ID=deadbeef\n"
            "ROOT_COUNT=0\n");
        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "MACHINE_ID without a paired SOURCE_UID");
        remove_manifest(test_dir);
    }

    // Root count exceeding the resource-exhaustion ceiling.
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        char content[256];
        snprintf(content, sizeof(content),
            "MIGR_MANIFEST\n"
            "VERSION=1\n"
            "REPRESENTATION=native\n"
            "SCOPE=critical\n"
            "SIDECAR_VERSION=0\n"
            "ROOT_COUNT=%d\n",
            MANIFEST_MAX_ROOTS + 1);
        write_raw(path, content);
        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "ROOT_COUNT beyond the resource-exhaustion ceiling");
        remove_manifest(test_dir);
    }

    // SIDECAR_VERSION beyond INT_MAX must be refused, not silently wrapped to
    // a negative int on cast.
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        write_raw(path,
            "MIGR_MANIFEST\n"
            "VERSION=1\n"
            "REPRESENTATION=native\n"
            "SCOPE=critical\n"
            "SIDECAR_VERSION=2147483648\n"
            "ROOT_COUNT=0\n");
        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "SIDECAR_VERSION beyond INT_MAX is refused, not wrapped negative");
        remove_manifest(test_dir);
    }

    // SOURCE_UID beyond uid_t's range must be refused, not silently wrapped
    // to 0 (root) on cast.
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        write_raw(path,
            "MIGR_MANIFEST\n"
            "VERSION=1\n"
            "REPRESENTATION=native\n"
            "SCOPE=critical\n"
            "SIDECAR_VERSION=0\n"
            "MACHINE_ID=deadbeef\n"
            "SOURCE_UID=4294967296\n"
            "ROOT_COUNT=0\n");
        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "SOURCE_UID beyond uid_t's range is refused, not wrapped to 0");
        remove_manifest(test_dir);
    }

    // Content that is neither our magic nor a legacy "KEY=value" line at all
    // -- must not be silently waved through as "probably the old format".
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        write_raw(path, "not-a-legacy-manifest\n");
        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "unrelated non-KEY=value content is refused, not classified LEGACY");
        remove_manifest(test_dir);
    }

    // A single line far longer than the bounded read buffer -- must be refused,
    // not grown into (there is no unbounded allocation to grow into: read_line
    // uses a fixed stack buffer).
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
        FILE *f = fopen(path, "w");
        if (f == NULL)
        {
            printf(RED "could not write fixture %s" NC "\n", path);
            exit(1);
        }
        fputs(
            "MIGR_MANIFEST\n"
            "VERSION=1\n"
            "REPRESENTATION=native\n"
            "SCOPE=critical\n"
            "SIDECAR_VERSION=0\n"
            "ROOT_COUNT=1\n"
            "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=", f);
        for (int i = 0; i < 100000; i++)
            fputc('a', f);
        fputc('\n', f);
        fclose(f);

        Manifest m;
        check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
              "a line far longer than the bounded read buffer");
        remove_manifest(test_dir);
    }
}

// A raw NUL byte in the line itself, as opposed to a percent-escaped "%00"
// in a value (test_malformed_variants already covers that -- it's
// decode_percent_escape()'s rejection, a completely different layer that
// runs after read_line() has already handed back a line). This exercises
// read_line()'s own fgets()-level handling: strlen() stops at the embedded
// NUL, and the fix must not let what's hidden past it be silently dropped.
static void test_embedded_nul_in_line_is_refused(void)
{
    printf(BLUE "::" NC " versioned manifest: a raw embedded NUL byte in a line is refused, not silently truncated\n");
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);

    // The embedded NUL sits well short of the bounded buffer's limit, with
    // real content (and the line's genuine trailing newline) hidden past it
    // -- proving this is caught even when the line is nowhere near "too long".
    static const unsigned char line[] =
        "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=a\0hidden-after-nul\n";
    write_raw_bytes(path,
        "MIGR_MANIFEST\n"
        "VERSION=1\n"
        "REPRESENTATION=native\n"
        "SCOPE=critical\n"
        "SIDECAR_VERSION=0\n"
        "ROOT_COUNT=1\n",
        line, sizeof(line) - 1);

    Manifest m;
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
          "an embedded NUL well short of the line-length bound is refused");
    remove_manifest(test_dir);
}

static void test_decode_overflow_is_refused(void)
{
    printf(BLUE "::" NC " versioned manifest: decoded path overflow is refused\n");

    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf(RED "could not write fixture %s" NC "\n", path);
        exit(1);
    }

    fputs(
        "MIGR_MANIFEST\n"
        "VERSION=1\n"
        "REPRESENTATION=native\n"
        "SCOPE=critical\n"
        "SIDECAR_VERSION=0\n"
        "ROOT_COUNT=1\n"
        "ROOT ID=EXPLICIT_0 POLICY=MANUAL_NATIVE PAYLOAD=a SOURCE=",
        f);

    // PATH_MAX repetitions decode to PATH_MAX bytes, which cannot fit in the
    // PATH_MAX-sized field (one byte is needed for the terminating NUL). The
    // encoded value is only 3 * PATH_MAX bytes, well below the manifest line
    // ceiling of roughly 9 * PATH_MAX bytes, so this isolates decode overflow.
    for (size_t i = 0; i < PATH_MAX; i++)
        fputs("%41", f);
    fputc('\n', f);
    fclose(f);

    Manifest m;
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_MALFORMED,
          "a decoded SOURCE reaching PATH_MAX is refused, not truncated");
    remove_manifest(test_dir);
}

static void test_io_error(void)
{
    printf(BLUE "::" NC " versioned manifest: IO error is distinct from missing/legacy\n");

    // A backup_dir long enough that appending "/manifest.txt" cannot fit in
    // PATH_MAX -- path_join refuses before any open() is attempted.
    char long_dir[PATH_MAX + 64];
    memset(long_dir, 'a', sizeof(long_dir) - 1);
    long_dir[sizeof(long_dir) - 1] = '\0';

    Manifest m;
    check(manifest_read_v1(long_dir, &m) == MANIFEST_STATUS_IO_ERROR,
          "a backup_dir too long to join -> IO_ERROR, not MISSING");

    // manifest.txt as a directory: fopen(..., "r") succeeds on Linux (a
    // directory can be opened for reading), but the first fgets() fails with
    // EISDIR -- a genuine stream fault, not "no manifest" and not "legacy".
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);
    check(mkdir(path, 0755) == 0, "fixture: create manifest.txt as a directory");
    check(manifest_read_v1(test_dir, &m) == MANIFEST_STATUS_IO_ERROR,
          "manifest.txt being a directory -> IO_ERROR, not LEGACY");
    check(rmdir(path) == 0, "fixture cleanup: remove the directory");
}

static void test_write_rejects_inconsistent_input(void)
{
    printf(BLUE "::" NC " versioned manifest: write refuses an inconsistent Manifest\n");

    Manifest m;
    memset(&m, 0, sizeof(m));
    m.version = MANIFEST_CURRENT_VERSION;
    m.representation = CLONE_NATIVE_TREE;
    m.scope = MANIFEST_SCOPE_CRITICAL;

    ManifestRoot bad;
    memset(&bad, 0, sizeof(bad));
    strcpy(bad.id, "EXPLICIT_0");
    bad.policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(bad.payload_path, "a");
    strcpy(bad.source_path, "a");
    bad.has_restore_path = 0; // HOME_RELATIVE without a restore path: contract violation

    m.root_count = 1;
    m.roots = &bad;

    check(manifest_write_v1(test_dir, &m) != 0,
          "a HOME_RELATIVE root without has_restore_path is refused, not written");
    remove_manifest(test_dir);

    // Two roots sharing an id must be refused: manifest_read_v1() rejects a
    // duplicate id, so the writer must never produce one in the first place.
    {
        Manifest dup;
        memset(&dup, 0, sizeof(dup));
        dup.version = MANIFEST_CURRENT_VERSION;
        dup.representation = CLONE_NATIVE_TREE;
        dup.scope = MANIFEST_SCOPE_EXPLICIT;

        ManifestRoot dup_roots[2];
        memset(dup_roots, 0, sizeof(dup_roots));
        strcpy(dup_roots[0].id, "EXPLICIT_0");
        dup_roots[0].policy = ROOT_POLICY_MANUAL_NATIVE;
        strcpy(dup_roots[0].payload_path, "a");
        strcpy(dup_roots[0].source_path, "a");
        strcpy(dup_roots[1].id, "EXPLICIT_0"); // same id as roots[0]
        dup_roots[1].policy = ROOT_POLICY_MANUAL_NATIVE;
        strcpy(dup_roots[1].payload_path, "b");
        strcpy(dup_roots[1].source_path, "b");

        dup.root_count = 2;
        dup.roots = dup_roots;

        check(manifest_write_v1(test_dir, &dup) != 0,
              "two roots sharing an id are refused, not written");
        remove_manifest(test_dir);
    }

    // A version other than MANIFEST_CURRENT_VERSION must be refused, not
    // silently written as v1 regardless of what the caller asked for.
    {
        Manifest bad_version;
        memset(&bad_version, 0, sizeof(bad_version));
        bad_version.version = 999;
        bad_version.representation = CLONE_NATIVE_TREE;
        bad_version.scope = MANIFEST_SCOPE_CRITICAL;
        check(manifest_write_v1(test_dir, &bad_version) != 0,
              "m.version != MANIFEST_CURRENT_VERSION is refused, not silently written as v1");
        remove_manifest(test_dir);
    }

    // An invalid machine_id must be refused, not written verbatim.
    {
        Manifest bad_machine;
        memset(&bad_machine, 0, sizeof(bad_machine));
        bad_machine.version = MANIFEST_CURRENT_VERSION;
        bad_machine.representation = CLONE_NATIVE_TREE;
        bad_machine.scope = MANIFEST_SCOPE_CRITICAL;
        bad_machine.has_source_identity = 1;
        strcpy(bad_machine.machine_id, "bad id"); // space: not valid hex
        bad_machine.source_uid = 1000;
        check(manifest_write_v1(test_dir, &bad_machine) != 0,
              "a non-hex machine_id is refused, not written verbatim");
        remove_manifest(test_dir);
    }

    // A negative sidecar_version must be refused.
    {
        Manifest bad_sidecar;
        memset(&bad_sidecar, 0, sizeof(bad_sidecar));
        bad_sidecar.version = MANIFEST_CURRENT_VERSION;
        bad_sidecar.representation = CLONE_NATIVE_TREE;
        bad_sidecar.scope = MANIFEST_SCOPE_CRITICAL;
        bad_sidecar.sidecar_version = -1;
        check(manifest_write_v1(test_dir, &bad_sidecar) != 0,
              "a negative sidecar_version is refused, not written as -1");
        remove_manifest(test_dir);
    }

    // The strongest form of "validate before touching the file": a valid,
    // pre-existing manifest.txt must survive byte-for-byte when a later
    // write attempt with an invalid model is refused -- fopen(..., "w")
    // must never have been reached.
    {
        Manifest good;
        memset(&good, 0, sizeof(good));
        good.version = MANIFEST_CURRENT_VERSION;
        good.representation = CLONE_NATIVE_TREE;
        good.scope = MANIFEST_SCOPE_CRITICAL;
        good.root_count = 0;
        check(manifest_write_v1(test_dir, &good) == 0,
              "fixture: a valid manifest writes successfully");

        Manifest invalid;
        memset(&invalid, 0, sizeof(invalid));
        invalid.version = 999; // invalid: triggers the write-time refusal
        invalid.representation = CLONE_NATIVE_TREE;
        invalid.scope = MANIFEST_SCOPE_CRITICAL;
        check(manifest_write_v1(test_dir, &invalid) != 0,
              "the invalid write attempt is refused");

        Manifest reread;
        check(manifest_read_v1(test_dir, &reread) == MANIFEST_STATUS_VALID,
              "the pre-existing valid manifest is untouched and still reads as VALID");
        manifest_free(&reread);
        remove_manifest(test_dir);
    }
}

// Reads a whole file into buf; returns its length, or -1.
static long slurp(const char *path, char *buf, size_t buf_size)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    size_t n = fread(buf, 1, buf_size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (long)n;
}

static void fill_reference_manifest(Manifest *m, ManifestRoot *roots)
{
    memset(m, 0, sizeof(*m));
    m->version = MANIFEST_CURRENT_VERSION;
    m->representation = CLONE_NATIVE_TREE;
    m->scope = MANIFEST_SCOPE_CRITICAL;
    m->sidecar_version = 0;
    m->has_source_identity = 1;
    strcpy(m->machine_id, "0123456789abcdef0123456789abcdef");
    m->source_uid = 1000;

    memset(roots, 0, 2 * sizeof(*roots));
    strcpy(roots[0].id, "XDG_DOCUMENTS_DIR");
    roots[0].policy = ROOT_POLICY_XDG;
    strcpy(roots[0].payload_path, "XDG_DOCUMENTS_DIR");
    strcpy(roots[0].source_path, "/home/u/Belgeler");

    strcpy(roots[1].id, "BUILTIN_DOT_SSH");
    roots[1].policy = ROOT_POLICY_HOME_RELATIVE;
    strcpy(roots[1].payload_path, "BUILTIN_DOT_SSH");
    strcpy(roots[1].source_path, ".ssh");
    strcpy(roots[1].restore_path, ".ssh");
    roots[1].has_restore_path = 1;

    m->root_count = 2;
    m->roots = roots;
}

static void test_fd_writer(void)
{
    printf(BLUE "::" NC " versioned manifest: fd-relative writer\n");

    Manifest m;
    ManifestRoot roots[2];
    fill_reference_manifest(&m, roots);

    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.txt", test_dir);

    remove_manifest(test_dir);
    int dir_fd = open(test_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(dir_fd >= 0, "fixture: the container directory opens");
    check(manifest_write_v1_at(dir_fd, &m) == 0, "manifest_write_v1_at succeeds");

    Manifest read;
    check(manifest_read_v1_at(dir_fd, &read) == MANIFEST_STATUS_VALID,
          "what it wrote reads back as VALID through the fd reader");
    check(read.root_count == 2 &&
          strcmp(read.roots[0].id, "XDG_DOCUMENTS_DIR") == 0 &&
          read.roots[0].policy == ROOT_POLICY_XDG &&
          strcmp(read.roots[1].restore_path, ".ssh") == 0,
          "the root table round-trips through the fd writer");
    manifest_free(&read);

    // Both entries must produce identical bytes: they are the same serializer
    // reached two ways, and a container's manifest must not depend on how the
    // caller happened to address it.
    char fd_bytes[4096];
    long fd_len = slurp(path, fd_bytes, sizeof(fd_bytes));
    remove_manifest(test_dir);
    check(manifest_write_v1(test_dir, &m) == 0, "manifest_write_v1 succeeds on the same model");
    char path_bytes[4096];
    long path_len = slurp(path, path_bytes, sizeof(path_bytes));
    check(fd_len > 0 && fd_len == path_len && memcmp(fd_bytes, path_bytes, (size_t)fd_len) == 0,
          "the fd and pathname writers produce byte-identical output");

    // A symlink standing where manifest.txt belongs must not be written
    // through: the format state would land wherever it points.
    remove_manifest(test_dir);
    char outside[512];
    snprintf(outside, sizeof(outside), "%s/outside.txt", test_dir);
    write_raw(outside, "untouched");
    check(symlink(outside, path) == 0, "fixture: manifest.txt is a symlink to another file");

    check(manifest_write_v1_at(dir_fd, &m) == 1,
          "manifest_write_v1_at refuses to write through a symlinked manifest.txt");
    char after[512];
    check(slurp(outside, after, sizeof(after)) == 9 && strcmp(after, "untouched") == 0,
          "the symlink's target is unchanged");
    check(manifest_write_v1(test_dir, &m) == 1,
          "the pathname writer refuses the same symlink");
    check(slurp(outside, after, sizeof(after)) == 9 && strcmp(after, "untouched") == 0,
          "the symlink's target is still unchanged");

    unlink(path);
    unlink(outside);
    close(dir_fd);

    check(manifest_write_v1_at(-1, &m) == 1, "an invalid container fd is refused");
    check(manifest_write_v1_at(0, NULL) == 1, "a NULL manifest is refused");
}

int main(void)
{
    printf(BLUE "::" NC " manifest (unit)\n");

    if (mkdtemp(test_dir) == NULL)
    {
        printf(RED "could not create a test directory" NC "\n");
        return 1;
    }

    test_missing();
    test_full_roundtrip_with_problem_bytes();
    test_no_source_identity();
    test_legacy_detection();
    test_unknown_version();
    test_malformed_variants();
    test_embedded_nul_in_line_is_refused();
    test_decode_overflow_is_refused();
    test_io_error();
    test_write_rejects_inconsistent_input();
    test_fd_writer();

    rmdir(test_dir);

    if (failures > 0)
    {
        printf(RED "%d manifest test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}
