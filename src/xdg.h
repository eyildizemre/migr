#ifndef XDG_H
#define XDG_H

/**
 * @brief The standard XDG "main directories" this codebase captures and
 * restores, in a single canonical order shared by every caller (backup's
 * root planner, legacy manifest read/write, and restore) so the key set is
 * never redefined more than once.
 *
 * Note: the XDG key for downloads is XDG_DOWNLOAD_DIR (singular).
 */
#define XDG_KEY_COUNT 6
extern const char * const xdg_keys[XDG_KEY_COUNT];
extern const char * const xdg_fallbacks[XDG_KEY_COUNT];

/**
 * @brief Parses ~/.config/user-dirs.dirs and resolves XDG directory keys in one pass.
 *
 * Searches the config file for each key in keys[] and expands the value:
 * "$HOME/path" prefixes are substituted with home, and absolute paths are
 * used as-is. The resolved absolute path is malloc'd and stored in out[i];
 * the caller is responsible for freeing every entry (freeing is safe even on
 * failure, since unresolved entries are left NULL). If the config file is
 * missing or a key is absent, out[i] falls back to home/<fallbacks[i]>.
 * A read or allocation failure while a present config file is being parsed is
 * reported as failure (return -1) rather than silently treated as an absent key
 * -- only a missing config file or a key that is genuinely never matched falls
 * back to home/<fallbacks[i]>.
 *
 * Every produced path is absolute. A relative fallback is never stored: a bare
 * name would make the caller act on the current working directory instead of
 * home. If HOME is so long that even a fallback path would overflow PATH_MAX,
 * that entry is left NULL and the function reports failure — the caller must
 * then abort rather than operate on a partial result.
 *
 * @param home      The user's home directory path.
 * @param keys      Array of n XDG key names to look up (e.g. "XDG_DOCUMENTS_DIR").
 * @param fallbacks Parallel array of n English fallback directory names (e.g. "Documents").
 * @param out       Caller-supplied array of n char* pointers; filled with malloc'd absolute paths.
 * @param n         Number of entries in keys, fallbacks, and out.
 * @return 0 if every entry resolved to an absolute path, -1 if any could not.
 */
int xdg_resolve(const char *home,
                const char * const *keys,
                const char * const *fallbacks,
                char **out,
                int n);

#endif
