#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_FNV1A_OFFSET_BASIS UINT64_C(1469598103934665603)

uint64_t hash_fnv1a_bytes(uint64_t hash, const unsigned char *data,
                         size_t length);
uint64_t hash_fnv1a_uint64(uint64_t hash, uint64_t value);

/* splitmix64's finalizer: a bijection that spreads every input bit. */
uint64_t hash_mix64(uint64_t value);

/*
 * Hashes a pair of integers, such as a device and inode, for a table indexed
 * by the hash's low bits. FNV-1a alone leaves consecutive integers clustered
 * there, which with some salts builds long probe runs, so the result is
 * finalized with hash_mix64().
 */
uint64_t hash_uint64_pair(uint64_t salt, uint64_t first, uint64_t second);

#endif
