#ifndef HOME_REWRITE_H
#define HOME_REWRITE_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "fileops.h"
#include "manifest.h"
#include "xdg.h"

/**
 * The desktop-state files that store absolute file:// URIs, and the source
 * HOME and XDG folders in them, rewritten for the system a backup is restored
 * on (docs/DECISIONS.md D41, D47, D86). Paths are below HOME.
 */
#define HOME_REWRITE_FILE_COUNT 2
extern const char *const home_rewrite_files[HOME_REWRITE_FILE_COUNT];

enum {
    HOME_REWRITE_URI_PREFIX_LENGTH = 7, /* "file://" */
    HOME_REWRITE_MAX_PAIRS = XDG_KEY_COUNT + 1,
    /* Each path as a file:// URI and as a single- or double-quoted string. */
    HOME_REWRITE_DCONF_MAX_PAIRS = 3 * HOME_REWRITE_MAX_PAIRS
};

typedef struct {
    unsigned char source_uri[PATH_MAX + HOME_REWRITE_URI_PREFIX_LENGTH + 1U];
    unsigned char destination_uri[PATH_MAX + HOME_REWRITE_URI_PREFIX_LENGTH + 1U];
    size_t source_uri_length;
    size_t destination_uri_length;
} HomeRewritePair;

/* Builds the table from the manifest's SOURCE_HOME and XDG roots and the
 * destination's HOME and XDG folders (indexed like xdg_keys) as resolved when
 * the restore started, so a restored user-dirs.dirs cannot redirect it. A
 * manifest without SOURCE_HOME gives no pairs. */
int home_rewrite_pairs_build(const Manifest *manifest,
                             const char *const *destination_xdg_dirs,
                             const char *destination_home,
                             HomeRewritePair pairs[], size_t *pair_count);

/* Like home_rewrite_pairs_build(), for the text of `dconf dump`, where a
 * path is also the start of a quoted string ('/home/...). */
int home_rewrite_dconf_pairs_build(const Manifest *manifest,
                                   const char *const *destination_xdg_dirs,
                                   const char *destination_home,
                                   HomeRewritePair pairs[], size_t *pair_count);

/* Returns text with each source prefix replaced as home_rewrite_copy() does,
 * in a string the caller frees; NULL with errno set on failure. */
char *home_rewrite_text(const char *text, const HomeRewritePair *pairs,
                        size_t pair_count);

/* Copies expected_size bytes from source_fd to destination_fd, replacing
 * each source file:// prefix that ends at a path component. digest covers
 * the bytes written, source_digest the bytes read. report may be NULL. */
int home_rewrite_copy(int source_fd, int destination_fd, off_t expected_size,
                      const HomeRewritePair *pairs, size_t pair_count,
                      BackupCaptureReport *report, uint64_t *digest,
                      uint64_t *source_digest);

/* Rewrites the regular file at path below dir_fd in place: it keeps its
 * inode, owner, mode, extended attributes, and times. */
int home_rewrite_file_at(int dir_fd, const char *path,
                         const HomeRewritePair *pairs, size_t pair_count);

/* Replaces the content of the regular file at path below dir_fd with all of
 * content_fd's, keeping its inode, owner, mode, extended attributes, and
 * times. */
int home_rewrite_replace_at(int dir_fd, const char *path, int content_fd);

#endif
