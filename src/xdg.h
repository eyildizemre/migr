#ifndef XDG_H
#define XDG_H

/**
 * @brief Parses ~/.config/user-dirs.dirs and resolves XDG directory keys in one pass.
 *
 * Searches the config file for each key in keys[] and expands the value:
 * "$HOME/path" prefixes are substituted with home, and absolute paths are
 * used as-is. The resolved absolute path is malloc'd and stored in out[i];
 * the caller is responsible for freeing every entry. If the config file is
 * missing or a key is absent, out[i] is set to "$HOME/<fallbacks[i]>".
 *
 * @param home      The user's home directory path.
 * @param keys      Array of n XDG key names to look up (e.g. "XDG_DOCUMENTS_DIR").
 * @param fallbacks Parallel array of n English fallback directory names (e.g. "Documents").
 * @param out       Caller-supplied array of n char* pointers; filled with malloc'd absolute paths.
 * @param n         Number of entries in keys, fallbacks, and out.
 */
void xdg_resolve(const char *home,
                 const char * const *keys,
                 const char * const *fallbacks,
                 char **out,
                 int n);

#endif
