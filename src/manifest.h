#ifndef MANIFEST_H
#define MANIFEST_H

#define MANIFEST_XDG_COUNT 6

extern const char * const manifest_keys[MANIFEST_XDG_COUNT]; /**< Canonical XDG key names, parallel to the xdg_resolve arrays. */

/**
 * @brief Writes manifest.txt to backup_dir recording the XDG key-to-dirname mapping.
 *
 * Stores one "KEY=basename" line per entry so that restore can locate the
 * correct directories when the source and destination locales differ.
 *
 * @param backup_dir Directory in which manifest.txt is created.
 * @param basenames  Array of n directory basenames parallel to manifest_keys[].
 * @param n          Number of entries to write.
 * @return 0 on success, 1 if the file cannot be opened for writing.
 */
int manifest_write(const char *backup_dir, const char * const *basenames, int n);

/**
 * @brief Parses manifest.txt from backup_dir and extracts XDG directory basenames.
 *
 * Each out[i] is set to a strdup'd value matching manifest_keys[i], or left
 * NULL if the key is absent from the file. The caller must free every
 * non-NULL entry. Returns 1 without modifying out[] if the file does not exist,
 * allowing the caller to fall back to the target system's basename.
 *
 * @param backup_dir Directory from which manifest.txt is read.
 * @param out        Caller-supplied array of n char* pointers; filled with malloc'd values.
 * @param n          Number of entries to look up.
 * @return 0 if manifest.txt was found and parsed, 1 if the file does not exist.
 */
int manifest_read(const char *backup_dir, char **out, int n);

#endif
