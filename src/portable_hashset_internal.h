#ifndef MIGR_PORTABLE_HASHSET_INTERNAL_H
#define MIGR_PORTABLE_HASHSET_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Shared between portable.c and portable_hashset.c only. */

typedef struct {
    char *root_id;
    char *logical_path;
    size_t root_length;
    size_t logical_length;
    uint64_t hash;
} PortableVisitedSlot;

typedef struct {
    PortableVisitedSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} PortableVisited;

typedef struct {
    dev_t device;
    ino_t inode;
    uint64_t hash;
    int used;
} PrescanInodeSlot;

typedef struct {
    PrescanInodeSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} PrescanInodeSet;

typedef struct {
    dev_t device;
    ino_t inode;
    char *root_id;
    char *logical_path;
    size_t root_length;
    size_t logical_length;
    uint64_t hash;
} PortableInodeSlot;

typedef struct {
    PortableInodeSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} PortableInodeMap;

typedef struct {
    char *folded_key;
    char *logical_path;
    size_t key_length;
    uint64_t hash;
    size_t value_index;
} PortableCaseFoldSlot;

typedef struct {
    PortableCaseFoldSlot *slots;
    size_t count;
    size_t capacity;
    uint64_t hash_salt;
} PortableCaseFoldSet;

#define VISITED_INITIAL_CAPACITY 16U

/* Probe-count hooks (portable.c) -- needed by the hashset functions. */
void visited_count_probe(void);
void inode_map_count_probe(void);
void prescan_inode_count_probe(void);

/* Hash-table API (portable_hashset.c) -- needed by reconcile/prescan/
 * driver code still in portable.c. */
int visited_reset(PortableVisited *visited);
void visited_dispose(PortableVisited *visited);
void visited_free(PortableVisited *visited);
int visited_add(PortableVisited *visited, const char *root_id,
                const char *logical);
int visited_contains(const PortableVisited *visited, const char *root_id,
                     const char *logical);
int prescan_inode_set_rehash(PrescanInodeSet *set, size_t new_capacity);
int prescan_inode_set_find_or_insert(PrescanInodeSet *set, dev_t device,
                                     ino_t inode);
void prescan_inode_set_free(void *opaque);
int inode_map_find_or_insert(PortableInodeMap *map, dev_t device,
                             ino_t inode, const char *root_id,
                             const char *logical,
                             const PortableInodeSlot **out_slot);
void inode_map_free(PortableInodeMap *map);
int case_fold_set_find_or_insert_value(PortableCaseFoldSet *set,
                                       const char *folded_key,
                                       const char *logical_path,
                                       size_t value_index,
                                       size_t *out_value_index,
                                       char **out_logical_path);
int case_fold_set_contains(const PortableCaseFoldSet *set,
                           const char *key);
void ascii_fold_copy(char *destination, size_t destination_size,
                     const char *source);
int case_fold_set_find_or_insert(PortableCaseFoldSet *set,
                                 const char *folded_key,
                                 const char *logical_path,
                                 char **out_logical_path);
void case_fold_set_free(PortableCaseFoldSet *set);

#endif
