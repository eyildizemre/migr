#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "encoding.h"

static int manifest_path_safe_char(unsigned char c)
{
    return c < 0x80 &&
           (isalnum(c) || c == '.' || c == '_' || c == '/' || c == '-');
}

// Bytewise percent-encode: every byte outside the safe set becomes "%XX"
// (uppercase hex). Operates on a raw NUL-terminated C string; paths never
// contain an embedded NUL at the syscall level, so treating them as strings
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

static int decode_percent_escape(const char *encoded, unsigned char *out)
{
    if (encoded == NULL || encoded[0] != '%' ||
        encoded[1] == '\0' || encoded[2] == '\0')
        return -1;

    int hi = hex_digit_value(encoded[1]);
    int lo = hex_digit_value(encoded[2]);
    if (hi < 0 || lo < 0)
        return -1;

    int byte = (hi << 4) | lo;
    // A decoded NUL would truncate the path at the syscall boundary.
    if (byte == 0)
        return -1;

    *out = (unsigned char)byte;
    return 0;
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
            unsigned char decoded;
            if (decode_percent_escape(encoded + i, &decoded) != 0)
                return -1;
            byte = decoded;
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

        if (o + 1 >= out_size)
            return -1;
        out[o++] = (char)byte;
    }
    out[o] = '\0';
    return 0;
}

static int component_safe_char(unsigned char c)
{
    return c < 0x80 && (isalnum(c) || c == '.' || c == '_' || c == '-');
}

static int is_utf8_continuation(unsigned char c)
{
    return c >= 0x80 && c <= 0xBF;
}

// Returns the length of one shortest-form UTF-8 sequence, or zero when the
// lead byte or any required continuation byte is invalid.
static size_t utf8_valid_sequence_len(const unsigned char *bytes,
                                      size_t available)
{
    if (bytes == NULL || available < 2)
        return 0;

    unsigned char lead = bytes[0];
    unsigned char second = bytes[1];

    if (lead >= 0xC2 && lead <= 0xDF)
        return is_utf8_continuation(second) ? 2 : 0;

    if (available < 3)
        return 0;
    unsigned char third = bytes[2];

    if (lead == 0xE0)
        return second >= 0xA0 && second <= 0xBF &&
               is_utf8_continuation(third) ? 3 : 0;
    if (lead >= 0xE1 && lead <= 0xEC)
        return is_utf8_continuation(second) &&
               is_utf8_continuation(third) ? 3 : 0;
    if (lead == 0xED)
        return second >= 0x80 && second <= 0x9F &&
               is_utf8_continuation(third) ? 3 : 0;
    if (lead == 0xEE || lead == 0xEF)
        return is_utf8_continuation(second) &&
               is_utf8_continuation(third) ? 3 : 0;

    if (available < 4)
        return 0;
    unsigned char fourth = bytes[3];

    if (lead == 0xF0)
        return second >= 0x90 && second <= 0xBF &&
               is_utf8_continuation(third) &&
               is_utf8_continuation(fourth) ? 4 : 0;
    if (lead >= 0xF1 && lead <= 0xF3)
        return is_utf8_continuation(second) &&
               is_utf8_continuation(third) &&
               is_utf8_continuation(fourth) ? 4 : 0;
    if (lead == 0xF4)
        return second >= 0x80 && second <= 0x8F &&
               is_utf8_continuation(third) &&
               is_utf8_continuation(fourth) ? 4 : 0;

    return 0;
}

static int append_percent_escape(unsigned char byte, char *out, size_t *offset,
                                 size_t out_size)
{
    if (*offset > out_size || out_size - *offset < 4)
        return -1;

    static const char hex[] = "0123456789ABCDEF";
    out[(*offset)++] = '%';
    out[(*offset)++] = hex[(byte >> 4) & 0xF];
    out[(*offset)++] = hex[byte & 0xF];
    return 0;
}

static int component_percent_encode(const char *raw, char *out,
                                     size_t out_size)
{
    if (raw == NULL || out == NULL || out_size == 0)
        return -1;

    size_t raw_length = strlen(raw);
    size_t o = 0;
    for (size_t i = 0; i < raw_length; )
    {
        unsigned char c = (unsigned char)raw[i];
        if (c < 0x80)
        {
            if (component_safe_char(c) &&
                !(c == '.' && i + 1 == raw_length))
            {
                if (o >= out_size - 1)
                    return -1;
                out[o++] = (char)c;
                i++;
                continue;
            }

            if (append_percent_escape(c, out, &o, out_size) != 0)
                return -1;
            i++;
            continue;
        }

        size_t sequence_length = utf8_valid_sequence_len(
            (const unsigned char *)raw + i, raw_length - i);
        if (sequence_length != 0)
        {
            if (o > out_size || out_size - o < sequence_length + 1)
                return -1;
            memcpy(out + o, raw + i, sequence_length);
            o += sequence_length;
            i += sequence_length;
            continue;
        }

        if (append_percent_escape(c, out, &o, out_size) != 0)
            return -1;
        i++;
    }

    out[o] = '\0';
    return 0;
}

// No production code currently calls this (encoding_percent_decode() with
// ENCODING_MODE_COMPONENT) -- portable restore recovers original names from
// the sidecar log's stored logical path rather than reversing the physical
// encoding. This function is kept, and directly exercised by
// tests/test_encoding.c's round-trip and injectivity tests, because it is the
// verified inverse of component_percent_encode() (used in production by
// portable.c/portable_prescan.c/portable_restore_shared.c) and documents the
// encoding scheme's correctness contract (D19 N-1) even without a current
// caller.
static int component_percent_decode(const char *encoded, char *out,
                                     size_t out_size)
{
    if (encoded == NULL || out == NULL || out_size == 0)
        return -1;

    size_t encoded_length = strlen(encoded);
    size_t o = 0;
    for (size_t i = 0; i < encoded_length; )
    {
        unsigned char c = (unsigned char)encoded[i];
        if (c == '%')
        {
            unsigned char decoded;
            if (encoded_length - i < 3 ||
                decode_percent_escape(encoded + i, &decoded) != 0)
                return -1;
            if (o >= out_size - 1)
                return -1;
            out[o++] = (char)decoded;
            i += 3;
            continue;
        }

        if (c < 0x80)
        {
            if (!component_safe_char(c) || o >= out_size - 1)
                return -1;
            // component_percent_encode() always escapes a component's final
            // byte when it is '.' (-> "%2E"); a raw trailing '.' here is a
            // value our own encoder would never produce, exactly the same
            // fail-closed reasoning as any other byte outside the safe set.
            if (c == '.' && i + 1 == encoded_length)
                return -1;
            out[o++] = (char)c;
            i++;
            continue;
        }

        size_t sequence_length = utf8_valid_sequence_len(
            (const unsigned char *)encoded + i, encoded_length - i);
        if (sequence_length == 0 ||
            o > out_size || out_size - o < sequence_length + 1)
            return -1;
        memcpy(out + o, encoded + i, sequence_length);
        o += sequence_length;
        i += sequence_length;
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
            return component_percent_encode(raw, out, out_size);
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
            return component_percent_decode(encoded, out, out_size);
    }

    assert(0 && "unknown encoding mode");
    return -1;
}
