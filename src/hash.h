#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_FNV1A_OFFSET_BASIS UINT64_C(1469598103934665603)

uint64_t hash_fnv1a_bytes(uint64_t hash, const unsigned char *data,
                         size_t length);
uint64_t hash_fnv1a_uint64(uint64_t hash, uint64_t value);

#endif
