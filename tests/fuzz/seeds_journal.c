// Generated seeds for the journal fuzzers: small journals written with the
// real writer and portable name map, the edge cases as edits of them, and one
// journal the real portable capture writes for a small tree, so they follow
// the format when its version changes. Each seed states the outcome every
// harness must report. The names are made up: a journal from a real backup
// holds a home's real file names and never becomes a seed.

#define _GNU_SOURCE

#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "fuzz.h"
#include "portable.h"
#include "portable_name.h"
#include "sidecar.h"

#define MAX_SEEDS 32U

typedef struct {
    FuzzSeed *seed;
    int fd;
} Builder;

typedef struct {
    const char *root;
    const char *path;
    SidecarObjectKind kind;
    uint64_t collision;
    // The symlink target, or the hardlink's logical path in link_root.
    const char *target;
    const char *link_root;
    int xattrs;
    int unclaimed;
    int uncommitted;
} Item;

// One value holds a NUL and one is empty: the edges of the one
// length-prefixed field.
static const SidecarXattr standard_xattrs[] = {
    { { (const unsigned char *)"user.a", 6 },
      { (const unsigned char *)"v\0w", 3 } },
    { { (const unsigned char *)"user.empty", 10 }, { NULL, 0 } }
};

static void die(const char *what)
{
    fprintf(stderr, "fuzz seeds: %s\n", what);
    abort();
}

static SidecarBytes text(const char *value)
{
    return (SidecarBytes){ (const unsigned char *)value, strlen(value) };
}

static void begin(Builder *builder, FuzzSeed *seed, const char *name,
                  const char *parse_outcome, const char *load_outcome,
                  const char *salvage_outcome)
{
    memset(seed, 0, sizeof(*seed));
    seed->name = name;
    seed->parse_outcome = parse_outcome;
    seed->load_outcome = load_outcome;
    seed->salvage_outcome = salvage_outcome;
    seed->writer_output = 1;
    builder->seed = seed;
    builder->fd = memfd_create("fuzz-seed", MFD_CLOEXEC);
    if (builder->fd < 0 || sidecar_write_header(builder->fd) != 0)
        die("cannot write a header");
}

static void mark_boundary(Builder *builder)
{
    FuzzSeed *seed = builder->seed;
    struct stat st;
    if (fstat(builder->fd, &st) != 0 ||
        seed->boundary_count == FUZZ_MAX_BOUNDARIES)
        die("cannot record a boundary");
    seed->boundaries[seed->boundary_count++] = (size_t)st.st_size;
}

static void fill_entry(const Item *item, PortablePhysicalName *name,
                       SidecarEntry *entry)
{
    const char *root = item->root != NULL ? item->root : "ROOT";
    const char *slash = strrchr(item->path, '/');
    const char *component = slash != NULL ? slash + 1 : item->path;
    memset(name, 0, sizeof(*name));
    if (item->path[0] != '\0' &&
        portable_physical_name_map(component, item->collision, name) != 0)
        die("cannot map a name");

    memset(entry, 0, sizeof(*entry));
    entry->root_id = text(root);
    entry->logical_path = text(item->path);
    entry->physical_leaf = text(name->physical_leaf);
    entry->collision_suffix = text(name->collision_suffix);
    entry->kind = item->kind;
    entry->mode = item->kind == SIDECAR_KIND_DIRECTORY ? 0755 : 0644;
    entry->uid = 1000;
    entry->gid = 1000;
    entry->atime_sec = 1700000000;
    entry->atime_nsec = 5;
    entry->mtime_sec = -1;
    entry->mtime_nsec = 999999999;
    if (item->kind == SIDECAR_KIND_REGULAR)
    {
        entry->size = 12;
        entry->content_digest = 0x1234;
    }
    else if (item->kind == SIDECAR_KIND_SYMLINK)
        entry->symlink_target = text(item->target);
    else if (item->kind == SIDECAR_KIND_HARDLINK)
    {
        entry->hardlink_root_id =
            text(item->link_root != NULL ? item->link_root : root);
        entry->hardlink_logical_path = text(item->target);
    }
    if (item->xattrs)
        entry->xattr_count = 2;
}

static void add(Builder *builder, Item item)
{
    PortablePhysicalName name;
    SidecarEntry entry;
    fill_entry(&item, &name, &entry);
    if (!item.unclaimed)
    {
        SidecarClaim claim = { entry.root_id, entry.logical_path,
                               entry.physical_leaf, entry.kind };
        if (sidecar_write_claim(builder->fd, &claim) != 0)
            die("cannot write a claim");
        mark_boundary(builder);
    }
    if (item.uncommitted)
    {
        if (sidecar_write_entry(builder->fd, &entry) != 0)
            die("cannot write an entry");
        return;
    }
    if (sidecar_write_entry_group(builder->fd, &entry,
                                  item.xattrs ? standard_xattrs : NULL) != 0)
        die("cannot write an entry group");
    mark_boundary(builder);
}

static void delete_item(Builder *builder, const char *path)
{
    SidecarDelete deletion = { text("ROOT"), text(path) };
    if (sidecar_write_delete(builder->fd, &deletion) != 0)
        die("cannot write a delete");
    mark_boundary(builder);
}

static void claim_only(Builder *builder, const char *path)
{
    SidecarClaim claim = { text("ROOT"), text(path), text(path),
                           SIDECAR_KIND_REGULAR };
    if (sidecar_write_claim(builder->fd, &claim) != 0)
        die("cannot write a claim");
    mark_boundary(builder);
}

static void finish(Builder *builder)
{
    FuzzSeed *seed = builder->seed;
    struct stat st;
    if (fstat(builder->fd, &st) != 0)
        die("cannot size a seed");
    seed->size = (size_t)st.st_size;
    seed->data = malloc(seed->size);
    if (seed->data == NULL ||
        pread(builder->fd, seed->data, seed->size, 0) != (ssize_t)seed->size)
        die("cannot read a seed back");
    close(builder->fd);
}

static void copy_seed(FuzzSeed *copy, const FuzzSeed *original,
                      const char *name, const char *parse_outcome,
                      const char *load_outcome, const char *salvage_outcome)
{
    memset(copy, 0, sizeof(*copy));
    copy->name = name;
    copy->parse_outcome = parse_outcome;
    copy->load_outcome = load_outcome;
    copy->salvage_outcome = salvage_outcome;
    copy->size = original->size;
    copy->data = malloc(original->size);
    if (copy->data == NULL)
        die("cannot copy a seed");
    memcpy(copy->data, original->data, original->size);
}

static void cut(FuzzSeed *seed, size_t size)
{
    if (size > seed->size)
        die("a cut past a seed's end");
    seed->size = size;
}

// Replaces the first occurrence of old with replacement. The result is no
// longer writer output.
static void replace(FuzzSeed *seed, const void *old, size_t old_length,
                    const void *replacement, size_t replacement_length)
{
    unsigned char *at = memmem(seed->data, seed->size, old, old_length);
    if (at == NULL)
        die("an edit finds nothing to replace");
    size_t offset = (size_t)(at - seed->data);
    size_t tail = seed->size - offset - old_length;
    size_t size = seed->size - old_length + replacement_length;
    unsigned char *data = malloc(size);
    if (data == NULL)
        die("cannot edit a seed");
    memcpy(data, seed->data, offset);
    memcpy(data + offset, replacement, replacement_length);
    memcpy(data + offset + replacement_length, at + old_length, tail);
    free(seed->data);
    seed->data = data;
    seed->size = size;
    seed->writer_output = 0;
    seed->boundary_count = 0;
}

// The header's version field, NUL-delimited on both sides, as written now
// and replaced by version.
static void replace_version(FuzzSeed *seed, const char *version)
{
    char current[32];
    char edited[32];
    int current_length = snprintf(current, sizeof(current), "%c%d%c", 0,
                                  SIDECAR_VERSION, 0);
    int edited_length = snprintf(edited, sizeof(edited), "%c%s%c", 0,
                                 version, 0);
    if (current_length <= 0 || edited_length <= 0 ||
        (size_t)edited_length >= sizeof(edited))
        die("cannot format a version");
    replace(seed, current, (size_t)current_length, edited,
            (size_t)edited_length);
}

static FuzzSeed *slot(FuzzSeed *seeds, size_t *count)
{
    if (*count == MAX_SEEDS)
        die("more seeds than MAX_SEEDS");
    return &seeds[(*count)++];
}

static void build_valid(FuzzSeed *seeds, size_t *count)
{
    Builder builder;

    begin(&builder, slot(seeds, count), "basic", "ok", "accepted", "intact");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "docs", .kind = SIDECAR_KIND_DIRECTORY,
                          .xattrs = 1 });
    add(&builder, (Item){ .path = "docs/notes.txt",
                          .kind = SIDECAR_KIND_REGULAR, .xattrs = 1 });
    add(&builder, (Item){ .path = "todo.txt", .kind = SIDECAR_KIND_REGULAR });
    finish(&builder);

    begin(&builder, slot(seeds, count), "kinds", "ok", "accepted", "intact");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "file", .kind = SIDECAR_KIND_REGULAR,
                          .xattrs = 1 });
    add(&builder, (Item){ .path = "link", .kind = SIDECAR_KIND_SYMLINK,
                          .target = "file" });
    add(&builder, (Item){ .path = "hard", .kind = SIDECAR_KIND_HARDLINK,
                          .target = "file" });
    add(&builder, (Item){ .path = "Dup", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "dup", .kind = SIDECAR_KIND_DIRECTORY,
                          .collision = 1 });
    add(&builder, (Item){ .path = "a:b?c.", .kind = SIDECAR_KIND_REGULAR });
    add(&builder, (Item){ .path = "gone.txt", .kind = SIDECAR_KIND_REGULAR });
    delete_item(&builder, "gone.txt");
    add(&builder, (Item){ .root = "XDG_DOCUMENTS_DIR", .path = "",
                          .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .root = "XDG_DOCUMENTS_DIR", .path = "report.txt",
                          .kind = SIDECAR_KIND_REGULAR });
    finish(&builder);

    begin(&builder, slot(seeds, count), "header-only", "ok", "accepted",
          "intact");
    finish(&builder);

    // A capture killed after claiming its next item.
    begin(&builder, slot(seeds, count), "pending-claim", "ok", "accepted",
          "intact");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "done.txt", .kind = SIDECAR_KIND_REGULAR });
    claim_only(&builder, "later.txt");
    finish(&builder);

    begin(&builder, slot(seeds, count), "entry-without-commit", "truncated",
          "unusable", "salvaged");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "file", .kind = SIDECAR_KIND_REGULAR,
                          .uncommitted = 1 });
    finish(&builder);

    // FIFO is a writer and parser kind, but claims exclude it.
    begin(&builder, slot(seeds, count), "fifo", "ok", "unusable", "salvaged");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "pipe", .kind = SIDECAR_KIND_FIFO,
                          .unclaimed = 1 });
    finish(&builder);

    // The parser stores logical paths as they are; the layers above it
    // refuse these.
    begin(&builder, slot(seeds, count), "orphan", "ok", "unusable",
          "salvaged");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "missing/file",
                          .kind = SIDECAR_KIND_REGULAR });
    finish(&builder);

    begin(&builder, slot(seeds, count), "dotdot-path", "ok", "unusable",
          "salvaged");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "../escape", .kind = SIDECAR_KIND_REGULAR });
    finish(&builder);

    begin(&builder, slot(seeds, count), "absolute-path", "ok", "unusable",
          "salvaged");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "/etc/passwd",
                          .kind = SIDECAR_KIND_REGULAR });
    finish(&builder);

    // Deleting a key with no live entry or claim is an idempotent no-op.
    begin(&builder, slot(seeds, count), "delete-unknown", "ok", "accepted",
          "intact");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    delete_item(&builder, "never.txt");
    finish(&builder);

    begin(&builder, slot(seeds, count), "hardlink-missing-root", "ok",
          "accepted", "intact");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    add(&builder, (Item){ .path = "hard", .kind = SIDECAR_KIND_HARDLINK,
                          .target = "file", .link_root = "NOPE" });
    finish(&builder);

    // Live claims just under half the claim map, then claims committed one
    // after another: the shape that once made the load quadratic. Small
    // maps show it already, as rehash work per claim.
    begin(&builder, slot(seeds, count), "claim-churn", "ok", "accepted",
          "intact");
    add(&builder, (Item){ .path = "", .kind = SIDECAR_KIND_DIRECTORY });
    char path[32];
    for (int index = 0; index < 14; index++)
    {
        snprintf(path, sizeof(path), "pending-%02d", index);
        claim_only(&builder, path);
    }
    for (int index = 0; index < 30; index++)
    {
        snprintf(path, sizeof(path), "file-%02d", index);
        add(&builder, (Item){ .path = path, .kind = SIDECAR_KIND_REGULAR });
    }
    finish(&builder);
}

static void build_edited(FuzzSeed *seeds, size_t *count)
{
    const FuzzSeed *basic = &seeds[0];
    const FuzzSeed *header_only = &seeds[2];
    Builder builder;
    FuzzSeed *seed;
    char version[32];

    seed = slot(seeds, count);
    copy_seed(seed, header_only, "empty", "corrupt", "unusable", "refused");
    cut(seed, 0);

    seed = slot(seeds, count);
    copy_seed(seed, header_only, "magic-only", "corrupt", "unusable",
              "refused");
    cut(seed, strlen(SIDECAR_MAGIC) + 1U);

    seed = slot(seeds, count);
    copy_seed(seed, header_only, "next-version", "unknown-version",
              "unusable", "refused");
    snprintf(version, sizeof(version), "%d", SIDECAR_VERSION + 1);
    replace_version(seed, version);

    seed = slot(seeds, count);
    copy_seed(seed, header_only, "version-too-long", "limit",
              "unusable", "refused");
    replace_version(seed, "12345678901234567");

    seed = slot(seeds, count);
    copy_seed(seed, header_only, "version-not-a-number", "corrupt",
              "unusable", "refused");
    replace_version(seed, "x5");

    seed = slot(seeds, count);
    copy_seed(seed, basic, "cut-inside-xattr", "truncated",
              "unusable", "salvaged");
    const unsigned char *xattr = memmem(basic->data, basic->size, "user.a", 6);
    if (xattr == NULL)
        die("the basic seed holds no xattr");
    cut(seed, (size_t)(xattr - basic->data) + 3U);

    seed = slot(seeds, count);
    begin(&builder, seed, "unknown-kind", "corrupt", "unusable", "salvaged");
    add(&builder, (Item){ .path = "file", .kind = SIDECAR_KIND_REGULAR,
                          .unclaimed = 1 });
    finish(&builder);
    replace(seed, "\0regular\0", 9, "\0socket\0", 8);

    // An xattr_count one past SIDECAR_MAX_XATTRS_PER_ENTRY; 255 is a number
    // no other field of this entry holds.
    seed = slot(seeds, count);
    begin(&builder, seed, "xattr-count-over-limit", "corrupt",
          "unusable", "salvaged");
    Item item = { .path = "file", .kind = SIDECAR_KIND_REGULAR,
                  .unclaimed = 1 };
    PortablePhysicalName name;
    SidecarEntry entry;
    fill_entry(&item, &name, &entry);
    entry.xattr_count = 255;
    if (sidecar_write_entry(builder.fd, &entry) != 0)
        die("cannot write an entry");
    finish(&builder);
    replace(seed, "\000255\000", 5, "\000257\000", 5);

    // A value one byte past SIDECAR_MAX_XATTR_VALUE, with the byte present.
    seed = slot(seeds, count);
    begin(&builder, seed, "xattr-value-over-limit", "corrupt",
          "unusable", "salvaged");
    static unsigned char value[SIDECAR_MAX_XATTR_VALUE + 1U];
    memset(value, 'v', sizeof(value));
    SidecarXattr big = { text("user.big"),
                         { value, SIDECAR_MAX_XATTR_VALUE } };
    item.xattrs = 0;
    fill_entry(&item, &name, &entry);
    entry.xattr_count = 1;
    if (sidecar_write_entry_group(builder.fd, &entry, &big) != 0)
        die("cannot write an entry group");
    finish(&builder);
    char length[32];
    char longer[32];
    int length_size = snprintf(length, sizeof(length), "%c%u%c", 0,
                               SIDECAR_MAX_XATTR_VALUE, 0);
    int longer_size = snprintf(longer, sizeof(longer), "%c%u%c", 0,
                               SIDECAR_MAX_XATTR_VALUE + 1U, 0);
    replace(seed, length, (size_t)length_size, longer,
            (size_t)longer_size);
    replace(seed, value, SIDECAR_MAX_XATTR_VALUE, value,
            sizeof(value));
}

static void make_directory(int base_fd, const char *path)
{
    if (mkdirat(base_fd, path, 0755) != 0)
        die("cannot create a source directory");
}

static int make_file(int base_fd, const char *path, const char *content)
{
    int fd = openat(base_fd, path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    0644);
    if (fd < 0 || write(fd, content, strlen(content)) < 0)
        die("cannot create a source file");
    return fd;
}

static int remove_path(const char *path, const struct stat *st, int type,
                       struct FTW *walk)
{
    (void)st;
    (void)type;
    (void)walk;
    return remove(path);
}

// The capture's own record order: claims before their groups, a collision
// suffix, a symlink, a hardlink, an xattr where the filesystem keeps one.
// Times and inode order change the bytes from run to run, not the outcomes.
static void build_captured(FuzzSeed *seeds, size_t *count)
{
    const char *temporary = getenv("TMPDIR");
    char base[PATH_MAX / 2];
    char source[PATH_MAX];
    char backup[PATH_MAX];
    snprintf(base, sizeof(base), "%s/migr-fuzz-seed-XXXXXX",
             temporary != NULL && temporary[0] != '\0' ? temporary : "/tmp");
    if (mkdtemp(base) == NULL)
        die("cannot create a capture directory");
    snprintf(source, sizeof(source), "%s/home", base);
    snprintf(backup, sizeof(backup), "%s/backup", base);
    if (mkdir(source, 0755) != 0)
        die("cannot create the capture source");

    int source_fd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0)
        die("cannot open the capture source");
    make_directory(source_fd, "docs");
    make_directory(source_fd, "empty");
    int notes = make_file(source_fd, "docs/notes.txt", "notes");
    // Not every filesystem $TMPDIR may be on keeps user xattrs; the seed is
    // still a capture without one.
    (void)fsetxattr(notes, "user.comment", "made up", 7, 0);
    close(notes);
    close(make_file(source_fd, "docs/Report.md", "first"));
    close(make_file(source_fd, "docs/report.md", "second"));
    close(make_file(source_fd, "a:b?c.txt", "portable escapes"));
    close(make_file(source_fd, "\xc3\xa7" "al" "\xc4\xb1" "\xc5\x9f" "ma.txt",
                    "utf-8"));
    if (linkat(source_fd, "docs/notes.txt", source_fd, "hard", 0) != 0 ||
        symlinkat("docs/notes.txt", source_fd, "link") != 0)
        die("cannot create a link");
    close(source_fd);

    PortableRootSpec root = {
        .id = "HOME",
        .policy = ROOT_POLICY_HOME_RELATIVE,
        .capture_path = source,
        .payload_path = "HOME",
        .source_path = source,
        .restore_path = "",
        .has_restore_path = 1
    };
    PortableCaptureRequest request = {
        .scope = MANIFEST_SCOPE_EXPLICIT,
        .has_source_identity = 1,
        .machine_id = "f022",
        .source_uid = getuid(),
        .roots = &root,
        .root_count = 1
    };
    if (mkdir(backup, 0700) != 0)
        die("cannot create the capture container");
    int container = open(backup, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (container < 0 || portable_capture_fresh_at(container, &request, NULL) != 0)
        die("the capture fails");

    FuzzSeed *seed = slot(seeds, count);
    memset(seed, 0, sizeof(*seed));
    seed->name = "captured";
    seed->parse_outcome = "ok";
    seed->load_outcome = "accepted";
    seed->salvage_outcome = "intact";
    seed->writer_output = 1;
    Builder builder = { seed, openat(container, SIDECAR_SLOT_NAME,
                                     O_RDONLY | O_CLOEXEC) };
    if (builder.fd < 0)
        die("cannot open the captured journal");
    finish(&builder);
    close(container);
    if (nftw(base, remove_path, 16, FTW_DEPTH | FTW_PHYS) != 0)
        die("cannot remove the capture directory");
}

void fuzz_seeds_build(FuzzSeed **seeds, size_t *count)
{
    *seeds = calloc(MAX_SEEDS, sizeof(**seeds));
    if (*seeds == NULL)
        die("cannot allocate the seeds");
    *count = 0;
    build_valid(*seeds, count);
    build_edited(*seeds, count);
    build_captured(*seeds, count);
}

void fuzz_seeds_free(FuzzSeed *seeds, size_t count)
{
    for (size_t index = 0; index < count; index++)
        free(seeds[index].data);
    free(seeds);
}
