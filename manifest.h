#ifndef MANIFEST_H
#define MANIFEST_H

#define MANIFEST_XDG_COUNT 6

extern const char * const manifest_keys[MANIFEST_XDG_COUNT];

/* Write manifest.txt to backup_dir mapping XDG keys to the basenames that were backed up. */
int manifest_write(const char *backup_dir, const char * const *basenames, int n);

/* Read manifest.txt from backup_dir. out[i] receives a strdup'd value for manifest_keys[i],
   or NULL if the key is absent. Returns 0 if the file was found, 1 if it was not. */
int manifest_read(const char *backup_dir, char **out, int n);

#endif
