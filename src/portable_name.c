#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encoding.h"
#include "hash.h"
#include "portable_name.h"

#define PORTABLE_SHORTENING_MARKER_LENGTH 20U
#define PORTABLE_ENCODED_COMPONENT_MAX (3U * NAME_MAX)

static int logical_component_length(const char *logical_component,
                                    size_t *length_out)
{
    if (logical_component == NULL || length_out == NULL)
        return -1;

    size_t length = 0;
    while (length <= NAME_MAX && logical_component[length] != '\0')
        length++;

    if (length == 0 || length > NAME_MAX ||
        (length == 1 && logical_component[0] == '.') ||
        (length == 2 && logical_component[0] == '.' &&
         logical_component[1] == '.') ||
        memchr(logical_component, '/', length) != NULL)
        return -1;

    *length_out = length;
    return 0;
}

static int format_collision_suffix(uint64_t collision_number,
                                   char suffix[SIDECAR_MAX_COLLISION_SUFFIX + 1U])
{
    if (collision_number == 0)
    {
        suffix[0] = '\0';
        return 0;
    }

    int written = snprintf(suffix, SIDECAR_MAX_COLLISION_SUFFIX + 1U,
                           "%%7E%" PRIu64, collision_number);
    if (written < 0 || (size_t)written > SIDECAR_MAX_COLLISION_SUFFIX)
        return -1;
    return 0;
}

static int format_shortening_marker(uint64_t fingerprint,
                                    char marker[PORTABLE_SHORTENING_MARKER_LENGTH + 1U])
{
    int written = snprintf(marker, PORTABLE_SHORTENING_MARKER_LENGTH + 1U,
                           "%%7EH%016" PRIX64, fingerprint);
    if (written != (int)PORTABLE_SHORTENING_MARKER_LENGTH)
        return -1;
    return 0;
}

static int is_continuation(unsigned char byte)
{
    return byte >= 0x80 && byte <= 0xBF;
}

/* Returns one complete unit from component encoder output. The encoder already
 * owns the byte-safe set; this only verifies the boundaries shortening may cut. */
static size_t encoded_unit_length(const unsigned char *bytes, size_t available)
{
    if (bytes == NULL || available == 0)
        return 0;

    if (bytes[0] == '%')
    {
        if (available < 3)
            return 0;
        for (size_t i = 1; i < 3; i++)
        {
            unsigned char c = bytes[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                return 0;
        }
        return 3;
    }

    if (bytes[0] < 0x80)
        return 1;

    if (bytes[0] >= 0xC2 && bytes[0] <= 0xDF)
        return available >= 2 && is_continuation(bytes[1]) ? 2 : 0;

    if (available < 3)
        return 0;
    if (bytes[0] == 0xE0)
        return bytes[1] >= 0xA0 && bytes[1] <= 0xBF &&
               is_continuation(bytes[2]) ? 3 : 0;
    if ((bytes[0] >= 0xE1 && bytes[0] <= 0xEC) ||
        (bytes[0] >= 0xEE && bytes[0] <= 0xEF))
        return is_continuation(bytes[1]) && is_continuation(bytes[2]) ? 3 : 0;
    if (bytes[0] == 0xED)
        return bytes[1] >= 0x80 && bytes[1] <= 0x9F &&
               is_continuation(bytes[2]) ? 3 : 0;

    if (available < 4)
        return 0;
    if (bytes[0] == 0xF0)
        return bytes[1] >= 0x90 && bytes[1] <= 0xBF &&
               is_continuation(bytes[2]) && is_continuation(bytes[3]) ? 4 : 0;
    if (bytes[0] >= 0xF1 && bytes[0] <= 0xF3)
        return is_continuation(bytes[1]) && is_continuation(bytes[2]) &&
               is_continuation(bytes[3]) ? 4 : 0;
    if (bytes[0] == 0xF4)
        return bytes[1] >= 0x80 && bytes[1] <= 0x8F &&
               is_continuation(bytes[2]) && is_continuation(bytes[3]) ? 4 : 0;

    return 0;
}

static int encoded_prefix_length(const char *encoded, size_t budget,
                                 size_t *prefix_length_out)
{
    if (encoded == NULL || prefix_length_out == NULL)
        return -1;

    size_t encoded_length = strlen(encoded);
    size_t offset = 0;
    size_t prefix_length = 0;
    while (offset < encoded_length)
    {
        size_t unit_length = encoded_unit_length(
            (const unsigned char *)encoded + offset, encoded_length - offset);
        if (unit_length == 0)
            return -1;
        if (offset <= budget && unit_length <= budget - offset)
            prefix_length = offset + unit_length;
        offset += unit_length;
    }

    *prefix_length_out = prefix_length;
    return 0;
}

static int portable_physical_name_map_internal(const char *logical_component,
                                               uint64_t collision_number,
                                               const uint64_t *forced_fingerprint,
                                               PortablePhysicalName *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    size_t logical_length;
    if (logical_component_length(logical_component, &logical_length) != 0)
        return -1;

    PortablePhysicalName result = {0};
    if (format_collision_suffix(collision_number, result.collision_suffix) != 0)
        return -1;

    char encoded[PORTABLE_ENCODED_COMPONENT_MAX + 1U];
    if (encoding_percent_encode(ENCODING_MODE_COMPONENT, logical_component,
                                encoded, sizeof(encoded)) != 0)
        return -1;

    size_t encoded_length = strlen(encoded);
    size_t suffix_length = strlen(result.collision_suffix);
    if (encoded_length <= NAME_MAX && suffix_length <= NAME_MAX - encoded_length)
    {
        memcpy(result.physical_leaf, encoded, encoded_length);
        memcpy(result.physical_leaf + encoded_length, result.collision_suffix,
               suffix_length + 1U);
        result.shortened = 0;
        *out = result;
        return 0;
    }

    if (PORTABLE_SHORTENING_MARKER_LENGTH > NAME_MAX ||
        suffix_length > NAME_MAX - PORTABLE_SHORTENING_MARKER_LENGTH)
        return -1;

    uint64_t fingerprint = forced_fingerprint != NULL
        ? *forced_fingerprint
        : hash_fnv1a_bytes(HASH_FNV1A_OFFSET_BASIS,
                           (const unsigned char *)logical_component,
                           logical_length);
    char marker[PORTABLE_SHORTENING_MARKER_LENGTH + 1U];
    if (format_shortening_marker(fingerprint, marker) != 0)
        return -1;

    size_t prefix_budget = NAME_MAX - PORTABLE_SHORTENING_MARKER_LENGTH -
                           suffix_length;
    size_t prefix_length;
    if (encoded_prefix_length(encoded, prefix_budget, &prefix_length) != 0)
        return -1;

    size_t total_length = prefix_length + PORTABLE_SHORTENING_MARKER_LENGTH +
                          suffix_length;
    if (total_length == 0 || total_length > NAME_MAX)
        return -1;

    size_t offset = 0;
    memcpy(result.physical_leaf + offset, encoded, prefix_length);
    offset += prefix_length;
    memcpy(result.physical_leaf + offset, marker,
           PORTABLE_SHORTENING_MARKER_LENGTH);
    offset += PORTABLE_SHORTENING_MARKER_LENGTH;
    memcpy(result.physical_leaf + offset, result.collision_suffix,
           suffix_length + 1U);
    result.shortened = 1;
    *out = result;
    return 0;
}

int portable_physical_name_map(const char *logical_component,
                               uint64_t collision_number,
                               PortablePhysicalName *out)
{
    return portable_physical_name_map_internal(logical_component,
                                               collision_number, NULL, out);
}

#ifdef PORTABLE_NAME_TEST_HOOKS
int portable_physical_name_map_with_fingerprint_for_test(
    const char *logical_component,
    uint64_t collision_number,
    uint64_t fingerprint,
    PortablePhysicalName *out)
{
    return portable_physical_name_map_internal(logical_component,
                                               collision_number,
                                               &fingerprint, out);
}
#endif
