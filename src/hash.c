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
