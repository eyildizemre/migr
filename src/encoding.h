#ifndef ENCODING_H
#define ENCODING_H

#include <stddef.h>

typedef enum {
    ENCODING_MODE_MANIFEST_PATH,
    ENCODING_MODE_COMPONENT
} EncodingMode;

int encoding_percent_encode(EncodingMode mode, const char *raw,
                            char *out, size_t out_size);
/**
 * @brief Reverses encoding_percent_encode() for the given mode.
 *
 * Recovers the exact original bytes that were encoded -- this is a pure
 * mathematical inverse, not a filename-safety filter. In particular,
 * ENCODING_MODE_COMPONENT's decoded output can legitimately contain a '/'
 * or any other byte if the encoded input (e.g. externally supplied, rather
 * than round-tripped through this module's own encoder) decodes to one --
 * see docs/DECISIONS.md D19 N-1. A caller intending to use the result as a
 * single POSIX filename component must validate that itself (reject an
 * embedded '/') before passing it to openat()/mkdirat()/etc.
 */
int encoding_percent_decode(EncodingMode mode, const char *encoded,
                            char *out, size_t out_size);

#endif
