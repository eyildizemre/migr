#include "hash.h"

uint64_t hash_fnv1a_bytes(uint64_t hash, const unsigned char *data,
                         size_t length)
{
    for (size_t index = 0; index < length; index++)
    {
        hash ^= data[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

uint64_t hash_fnv1a_uint64(uint64_t hash, uint64_t value)
{
    for (size_t index = 0; index < sizeof(value); index++)
    {
        hash ^= (unsigned char)(value >> (index * 8U));
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

uint64_t hash_mix64(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

uint64_t hash_uint64_pair(uint64_t salt, uint64_t first, uint64_t second)
{
    uint64_t hash = HASH_FNV1A_OFFSET_BASIS ^ salt;
    hash = hash_fnv1a_uint64(hash, first);
    hash = hash_fnv1a_uint64(hash, second);
    return hash_mix64(hash);
}
