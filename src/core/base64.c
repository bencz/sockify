#include "sockify/base64.h"

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int sockify_base64_encode(const unsigned char *input,
                          size_t input_len,
                          char *output,
                          size_t output_size,
                          size_t *written)
{
    size_t encoded_len;
    size_t in;
    size_t out;

    if (written != 0) {
        *written = 0;
    }
    if (output == 0 || (input == 0 && input_len != 0)) {
        return SOCKIFY_ERR_INVALID;
    }

    encoded_len = ((input_len + 2U) / 3U) * 4U;
    if (output_size < encoded_len + 1U) {
        return SOCKIFY_ERR_OVERFLOW;
    }

    in = 0;
    out = 0;
    while (in + 3U <= input_len) {
        sockify_u32 triple;

        triple = ((sockify_u32)input[in] << 16) |
                 ((sockify_u32)input[in + 1U] << 8) |
                 (sockify_u32)input[in + 2U];
        output[out++] = base64_chars[(triple >> 18) & 0x3fU];
        output[out++] = base64_chars[(triple >> 12) & 0x3fU];
        output[out++] = base64_chars[(triple >> 6) & 0x3fU];
        output[out++] = base64_chars[triple & 0x3fU];
        in += 3U;
    }

    if (input_len - in == 1U) {
        sockify_u32 triple;

        triple = (sockify_u32)input[in] << 16;
        output[out++] = base64_chars[(triple >> 18) & 0x3fU];
        output[out++] = base64_chars[(triple >> 12) & 0x3fU];
        output[out++] = '=';
        output[out++] = '=';
    } else if (input_len - in == 2U) {
        sockify_u32 triple;

        triple = ((sockify_u32)input[in] << 16) |
                 ((sockify_u32)input[in + 1U] << 8);
        output[out++] = base64_chars[(triple >> 18) & 0x3fU];
        output[out++] = base64_chars[(triple >> 12) & 0x3fU];
        output[out++] = base64_chars[(triple >> 6) & 0x3fU];
        output[out++] = '=';
    }

    output[out] = '\0';
    if (written != 0) {
        *written = out;
    }
    return SOCKIFY_OK;
}
