#ifndef ENCODING_H
#define ENCODING_H

#include <stddef.h>

typedef enum {
    ENCODING_MODE_MANIFEST_PATH,
    ENCODING_MODE_COMPONENT
} EncodingMode;

int encoding_percent_encode(EncodingMode mode, const char *raw,
                            char *out, size_t out_size);
int encoding_percent_decode(EncodingMode mode, const char *encoded,
                            char *out, size_t out_size);

#endif
