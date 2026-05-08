#ifndef XDG_H
#define XDG_H

// Parse ~/.config/user-dirs.dirs and resolve XDG directory keys in one pass.
//
// home      - the user's home directory
// keys      - array of n XDG key names  (e.g. "XDG_DOCUMENTS_DIR")
// fallbacks - parallel array of n English fallback names (e.g. "Documents")
// out       - caller-provided array of n char* pointers filled with malloc'd
//             absolute paths. Caller must free each entry.
// n         - number of entries
//
// If the config file is missing or a key is absent the corresponding out[]
// entry is silently set to "$HOME/<fallback>".
void xdg_resolve(const char *home,
                 const char * const *keys,
                 const char * const *fallbacks,
                 char **out,
                 int n);

#endif
