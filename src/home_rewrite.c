#define _GNU_SOURCE
#include "home_rewrite.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hash.h"
#include "utils.h"

const char *const home_rewrite_files[HOME_REWRITE_FILE_COUNT] = {
    ".config/gtk-3.0/bookmarks",
    ".local/share/recently-used.xbel"
};

static const char file_uri[] = "file://";

// prefix is file_uri or shorter.
static int pair_set(HomeRewritePair *pair, const char *prefix,
                    const char *source_path, const char *destination_path)
{
    if (pair == NULL || source_path == NULL || source_path[0] == '\0' ||
        destination_path == NULL || destination_path[0] == '\0')
    {
        errno = EINVAL;
        return -1;
    }

    size_t source_length = strnlen(source_path, PATH_MAX);
    size_t destination_length = strnlen(destination_path, PATH_MAX);
    if (source_length == PATH_MAX || destination_length == PATH_MAX ||
        source_length > SIZE_MAX - HOME_REWRITE_URI_PREFIX_LENGTH - 1U ||
        destination_length > SIZE_MAX - HOME_REWRITE_URI_PREFIX_LENGTH - 1U)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    size_t prefix_length = strlen(prefix);
    memcpy(pair->source_uri, prefix, prefix_length);
    memcpy(pair->source_uri + prefix_length, source_path, source_length);
    pair->source_uri_length = prefix_length + source_length;
    pair->source_uri[pair->source_uri_length] = '\0';
    memcpy(pair->destination_uri, prefix, prefix_length);
    memcpy(pair->destination_uri + prefix_length, destination_path,
           destination_length);
    pair->destination_uri_length = prefix_length + destination_length;
    pair->destination_uri[pair->destination_uri_length] = '\0';
    return 0;
}

int home_rewrite_pairs_build(const Manifest *manifest,
                             const char *const *destination_xdg_dirs,
                             const char *destination_home,
                             HomeRewritePair pairs[], size_t *pair_count)
{
    if (manifest == NULL || pairs == NULL || pair_count == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    *pair_count = 0;
    if (manifest->source_home[0] == '\0' || destination_home == NULL ||
        destination_home[0] == '\0')
        return 0;

    for (int key = 0; key < XDG_KEY_COUNT; key++)
    {
        const ManifestRoot *root = NULL;
        for (int index = 0; index < manifest->root_count; index++)
            if (manifest->roots[index].policy == ROOT_POLICY_XDG &&
                strcmp(manifest->roots[index].id, xdg_keys[key]) == 0)
            {
                root = &manifest->roots[index];
                break;
            }
        if (root == NULL)
            continue;

        if (*pair_count >= HOME_REWRITE_MAX_PAIRS)
        {
            errno = EOVERFLOW;
            return -1;
        }
        char source_path[PATH_MAX];
        if (manifest_root_source_path(
                manifest, (int)(root - manifest->roots), source_path) != 0 ||
            pair_set(&pairs[*pair_count], file_uri, source_path,
                     destination_xdg_dirs == NULL
                         ? NULL : destination_xdg_dirs[key]) != 0)
            return -1;
        (*pair_count)++;
    }

    if (*pair_count >= HOME_REWRITE_MAX_PAIRS ||
        pair_set(&pairs[*pair_count], file_uri, manifest->source_home,
                 destination_home) != 0)
        return -1;
    (*pair_count)++;
    return 0;
}

int home_rewrite_dconf_pairs_build(const Manifest *manifest,
                                   const char *const *destination_xdg_dirs,
                                   const char *destination_home,
                                   HomeRewritePair pairs[], size_t *pair_count)
{
    HomeRewritePair uris[HOME_REWRITE_MAX_PAIRS];
    size_t uri_count = 0;
    if (pair_count == NULL ||
        home_rewrite_pairs_build(manifest, destination_xdg_dirs,
                                 destination_home, uris, &uri_count) != 0)
        return -1;
    static const char *const prefixes[] = { file_uri, "'", "\"" };
    *pair_count = 0;
    for (size_t index = 0; index < uri_count; index++)
        for (size_t form = 0; form < sizeof(prefixes) / sizeof(prefixes[0]);
             form++)
            if (pair_set(&pairs[(*pair_count)++], prefixes[form],
                         (const char *)uris[index].source_uri +
                             HOME_REWRITE_URI_PREFIX_LENGTH,
                         (const char *)uris[index].destination_uri +
                             HOME_REWRITE_URI_PREFIX_LENGTH) != 0)
                return -1;
    return 0;
}

static int write_all_hashed(int fd, const unsigned char *data, size_t length,
                            uint64_t *hash)
{
    if (write_all(fd, data, length) != 0)
        return -1;
    if (hash != NULL)
        *hash = hash_fnv1a_bytes(*hash, data, length);
    return 0;
}

static size_t bytes_find(const unsigned char *haystack,
                         size_t haystack_length, const unsigned char *needle,
                         size_t needle_length)
{
    if (needle_length == 0 || haystack_length < needle_length)
        return SIZE_MAX;
    size_t limit = haystack_length - needle_length;
    for (size_t index = 0; index <= limit; index++)
        if (haystack[index] == needle[0] &&
            memcmp(haystack + index, needle, needle_length) == 0)
            return index;
    return SIZE_MAX;
}

// A byte that may follow a rewritten prefix: the prefix then ends at a
// path component, not inside a longer name.
static int uri_boundary(unsigned char byte)
{
    return byte == '/' || byte == ' ' || byte == '\t' || byte == '\r' ||
           byte == '\n' || byte == '"' || byte == '\'';
}

/* Flushes every replacement whose trailing path-component boundary is already
 * known. On non-final chunks, at most one longest source URI remains buffered
 * so a match and its following boundary may straddle the next read. */
static int rewrite_flush(
    int destination_fd, const unsigned char *buffer, size_t length,
    const HomeRewritePair *pairs, size_t pair_count, int final,
    size_t *consumed_out, uint64_t *hash)
{
    if (destination_fd < 0 || buffer == NULL || pairs == NULL ||
        pair_count == 0 || consumed_out == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    size_t max_source_uri_length = 0;
    for (size_t index = 0; index < pair_count; index++)
        if (pairs[index].source_uri_length == 0 ||
            pairs[index].destination_uri_length == 0 ||
            pairs[index].source_uri_length >
                sizeof(pairs[index].source_uri) ||
            pairs[index].destination_uri_length >
                sizeof(pairs[index].destination_uri))
        {
            errno = EINVAL;
            return -1;
        }
        else if (pairs[index].source_uri_length > max_source_uri_length)
            max_source_uri_length = pairs[index].source_uri_length;

    size_t safe_start = final ? length :
        (length > max_source_uri_length ?
             length - max_source_uri_length : 0U);
    size_t cursor = 0;
    while (cursor < length)
    {
        size_t best_match = SIZE_MAX;
        size_t best_pair = SIZE_MAX;
        int best_boundary = 0;
        for (size_t index = 0; index < pair_count; index++)
        {
            const HomeRewritePair *pair = &pairs[index];
            size_t relative = bytes_find(
                buffer + cursor, length - cursor,
                pair->source_uri, pair->source_uri_length);
            if (relative == SIZE_MAX)
                continue;
            size_t match = cursor + relative;
            if (!final && match >= safe_start)
                continue;
            size_t after = match + pair->source_uri_length;
            int boundary = after < length
                ? uri_boundary(buffer[after]) : final;
            if (best_pair == SIZE_MAX || match < best_match ||
                (match == best_match &&
                 ((boundary && !best_boundary) ||
                  (boundary == best_boundary &&
                   pair->source_uri_length >
                       pairs[best_pair].source_uri_length))))
            {
                best_match = match;
                best_pair = index;
                best_boundary = boundary;
            }
        }
        if (best_pair == SIZE_MAX)
            break;

        const HomeRewritePair *pair = &pairs[best_pair];
        size_t after = best_match + pair->source_uri_length;
        if (best_boundary)
        {
            if (write_all_hashed(destination_fd, buffer + cursor,
                                 best_match - cursor, hash) != 0 ||
                write_all_hashed(destination_fd, pair->destination_uri,
                                 pair->destination_uri_length, hash) != 0)
                return -1;
            cursor = after;
        }
        else
        {
            /* Emit one byte, not the whole rejected candidate: a canonical
             * path can contain a later suffix that is also its own prefix. */
            if (write_all_hashed(destination_fd, buffer + cursor,
                                 best_match + 1U - cursor, hash) != 0)
                return -1;
            cursor = best_match + 1U;
        }
    }

    size_t flush_to = final ? length : safe_start;
    if (cursor < flush_to)
    {
        if (write_all_hashed(destination_fd, buffer + cursor,
                             flush_to - cursor, hash) != 0)
            return -1;
        cursor = flush_to;
    }
    *consumed_out = cursor;
    return 0;
}

int home_rewrite_copy(int source_fd, int destination_fd, off_t expected_size,
                      const HomeRewritePair *pairs, size_t pair_count,
                      BackupCaptureReport *report, uint64_t *digest,
                      uint64_t *source_digest)
{
    if (source_fd < 0 || destination_fd < 0 || expected_size < 0 ||
        pairs == NULL || pair_count == 0 || digest == NULL ||
        source_digest == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (ftruncate(destination_fd, 0) != 0)
        return -1;

    enum { REWRITE_READ_SIZE = 65536 };
    unsigned char buffer[REWRITE_READ_SIZE + PATH_MAX +
                         HOME_REWRITE_URI_PREFIX_LENGTH + 1U];
    size_t carried = 0;
    uint64_t copied = 0;
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
    uint64_t read_hash = HASH_FNV1A_OFFSET_BASIS;

    for (;;)
    {
        ssize_t received = read(source_fd, buffer + carried,
                                REWRITE_READ_SIZE);
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            return -1;
        if (received == 0)
        {
            size_t consumed = 0;
            if (rewrite_flush(
                    destination_fd, buffer, carried,
                    pairs, pair_count, 1, &consumed, &hash) != 0)
                return -1;
            if (consumed != carried)
            {
                errno = EIO;
                return -1;
            }
            break;
        }

        if ((uint64_t)received > UINT64_MAX - copied)
        {
            errno = EOVERFLOW;
            return -1;
        }
        copied += (uint64_t)received;
        read_hash = hash_fnv1a_bytes(read_hash, buffer + carried,
                                     (size_t)received);
        size_t total = carried + (size_t)received;
        size_t consumed = 0;
        if (rewrite_flush(
                destination_fd, buffer, total,
                pairs, pair_count, 0, &consumed, &hash) != 0)
            return -1;
        carried = total - consumed;
        if (carried > PATH_MAX + HOME_REWRITE_URI_PREFIX_LENGTH)
        {
            errno = EIO;
            return -1;
        }
        if (carried != 0)
            memmove(buffer, buffer + consumed, carried);
        if (backup_capture_report_tick(report, received, destination_fd) != 0)
            return -1;
    }

    if (copied != (uint64_t)expected_size)
    {
        errno = EIO;
        return -1;
    }
    *digest = hash;
    *source_digest = read_hash;
    return 0;
}

// Copies all of from_fd, from its start, over to_fd from its start.
static int copy_back(int from_fd, int to_fd)
{
    if (lseek(from_fd, 0, SEEK_SET) != 0 || lseek(to_fd, 0, SEEK_SET) != 0 ||
        ftruncate(to_fd, 0) != 0)
        return -1;
    unsigned char buffer[65536];
    for (;;)
    {
        ssize_t got = read(from_fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return -1;
        if (got == 0)
            return 0;
        if (write_all(to_fd, buffer, (size_t)got) != 0)
            return -1;
    }
}

char *home_rewrite_text(const char *text, const HomeRewritePair *pairs,
                        size_t pair_count)
{
    if (text == NULL)
    {
        errno = EINVAL;
        return NULL;
    }
    int fd = memfd_create("migr-home-rewrite", MFD_CLOEXEC);
    if (fd < 0)
        return NULL;
    char *rewritten = NULL;
    size_t consumed = 0;
    off_t length = -1;
    if (rewrite_flush(fd, (const unsigned char *)text, strlen(text), pairs,
                      pair_count, 1, &consumed, NULL) == 0 &&
        (length = lseek(fd, 0, SEEK_CUR)) >= 0 &&
        (rewritten = malloc((size_t)length + 1U)) != NULL)
    {
        if (pread(fd, rewritten, (size_t)length, 0) == length)
            rewritten[length] = '\0';
        else
        {
            free(rewritten);
            rewritten = NULL;
            errno = EIO;
        }
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return rewritten;
}

int home_rewrite_file_at(int dir_fd, const char *path,
                         const HomeRewritePair *pairs, size_t pair_count)
{
    int fd = openat(dir_fd, path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    int copy_fd = -1;
    uint64_t digest = 0, source_digest = 0;
    int failed = fstat(fd, &st) != 0;
    if (!failed && !S_ISREG(st.st_mode))
    {
        errno = EINVAL;
        failed = 1;
    }
    if (!failed)
    {
        copy_fd = memfd_create("migr-home-rewrite", MFD_CLOEXEC);
        failed = copy_fd < 0 ||
                 home_rewrite_copy(fd, copy_fd, st.st_size, pairs, pair_count,
                                   NULL, &digest, &source_digest) != 0;
    }
    // Written back through the same descriptor, the file stays what it was
    // but for its content; its times are put back after.
    if (!failed && digest != source_digest)
    {
        struct timespec times[2] = { st.st_atim, st.st_mtim };
        failed = copy_back(copy_fd, fd) != 0 || futimens(fd, times) != 0;
    }
    int saved = errno;
    if (copy_fd >= 0)
        close(copy_fd);
    if (close(fd) != 0 && !failed)
    {
        failed = 1;
        saved = errno;
    }
    errno = saved;
    return failed ? -1 : 0;
}

int home_rewrite_replace_at(int dir_fd, const char *path, int content_fd)
{
    int fd = openat(dir_fd, path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    int failed = fstat(fd, &st) != 0;
    if (!failed && !S_ISREG(st.st_mode))
    {
        errno = EINVAL;
        failed = 1;
    }
    if (!failed)
    {
        struct timespec times[2] = { st.st_atim, st.st_mtim };
        failed = copy_back(content_fd, fd) != 0 || futimens(fd, times) != 0;
    }
    int saved = errno;
    if (close(fd) != 0 && !failed)
    {
        failed = 1;
        saved = errno;
    }
    errno = saved;
    return failed ? -1 : 0;
}
