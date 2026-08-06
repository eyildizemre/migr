#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <stddef.h>

#include "encoding.h"

static int manifest_path_safe_char(unsigned char c)
{
    return isalnum(c) || c == '.' || c == '_' || c == '/' || c == '-';
}

// Bytewise percent-encode: every byte outside the safe set becomes "%XX"
// (uppercase hex). Operates on raw is a NUL-terminated C string; paths never
// contain an embedded NUL at the syscall level, so treating it as a string
// (rather than requiring an explicit length) is sufficient here.
static int manifest_path_percent_encode(const char *raw, char *out,
                                        size_t out_size)
{
    if (raw == NULL || out == NULL || out_size == 0)
        return -1;

    size_t o = 0;
    for (size_t i = 0; raw[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)raw[i];
        if (manifest_path_safe_char(c))
        {
            if (o + 1 >= out_size)
                return -1;
            out[o++] = (char)c;
        }
        else
        {
            if (o + 3 >= out_size)
                return -1;
            static const char hex[] = "0123456789ABCDEF";
            out[o++] = '%';
            out[o++] = hex[(c >> 4) & 0xF];
            out[o++] = hex[c & 0xF];
        }
    }
    out[o] = '\0';
    return 0;
}

static int hex_digit_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Decodes a manifest_path_percent_encode()-produced value. Fail-closed: any
// raw byte outside the safe set that is not part of a well-formed "%XX" escape
// is malformed input (our own writer never produces such a line), as is a "%"
// not followed by two valid hex digits or a result that would not fit out_size.
static int manifest_path_percent_decode(const char *encoded, char *out,
                                        size_t out_size)
{
    if (encoded == NULL || out == NULL || out_size == 0)
        return -1;

    size_t o = 0;
    for (size_t i = 0; encoded[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)encoded[i];
        int byte;
        if (c == '%')
        {
            int hi = hex_digit_value(encoded[i + 1] != '\0' ? encoded[i + 1] : '\0');
            int lo = hex_digit_value(encoded[i + 2] != '\0' ? encoded[i + 2] : '\0');
            if (hi < 0 || lo < 0)
                return -1;
            byte = (hi << 4) | lo;
            i += 2;
        }
        else if (manifest_path_safe_char(c))
        {
            byte = c;
        }
        else
        {
            return -1; // raw byte our encoder would never emit unescaped
        }

        // A decoded NUL would silently truncate every C-string operation
        // downstream (strcmp/strlen/strcpy) at that point, hiding whatever
        // followed it. manifest_path_percent_encode() never produces "%00" for
        // a real path (paths cannot contain NUL at the syscall level), so this
        // can only be corruption or tampering -- refuse it, don't truncate.
        if (byte == 0)
            return -1;

        if (o + 1 >= out_size)
            return -1;
        out[o++] = (char)byte;
    }
    out[o] = '\0';
    return 0;
}

int encoding_percent_encode(EncodingMode mode, const char *raw,
                            char *out, size_t out_size)
{
    switch (mode)
    {
        case ENCODING_MODE_MANIFEST_PATH:
            return manifest_path_percent_encode(raw, out, out_size);
        case ENCODING_MODE_COMPONENT:
            assert(0 && "component encoding is implemented in D.2b");
            return -1;
    }

    assert(0 && "unknown encoding mode");
    return -1;
}

int encoding_percent_decode(EncodingMode mode, const char *encoded,
                            char *out, size_t out_size)
{
    switch (mode)
    {
        case ENCODING_MODE_MANIFEST_PATH:
            return manifest_path_percent_decode(encoded, out, out_size);
        case ENCODING_MODE_COMPONENT:
            assert(0 && "component encoding is implemented in D.2b");
            return -1;
    }

    assert(0 && "unknown encoding mode");
    return -1;
}
