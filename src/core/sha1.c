#include "sockify/sha1.h"

/*
 * Minimal SHA-1 (RFC 3174). Only used to derive the
 * Sec-WebSocket-Accept value during the handshake, so a simple
 * one-shot implementation is enough. Endian neutral: all word
 * access goes through explicit byte shifts.
 */

struct sha1_ctx {
    sockify_u32 state[5];
    sockify_u64 total_len;
    unsigned char block[64];
    size_t block_len;
};

static sockify_u32 rotl32(sockify_u32 value, unsigned int bits)
{
    return ((value << bits) | (value >> (32U - bits))) & 0xffffffffUL;
}

static void sha1_init(struct sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xefcdab89UL;
    ctx->state[2] = 0x98badcfeUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xc3d2e1f0UL;
    ctx->total_len = 0;
    ctx->block_len = 0;
}

static void sha1_process(struct sha1_ctx *ctx, const unsigned char *block)
{
    sockify_u32 w[80];
    sockify_u32 a;
    sockify_u32 b;
    sockify_u32 c;
    sockify_u32 d;
    sockify_u32 e;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((sockify_u32)block[i * 4] << 24) |
               ((sockify_u32)block[(i * 4) + 1] << 16) |
               ((sockify_u32)block[(i * 4) + 2] << 8) |
               (sockify_u32)block[(i * 4) + 3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1U);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        sockify_u32 f;
        sockify_u32 k;
        sockify_u32 temp;

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999UL;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1UL;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcUL;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6UL;
        }

        temp = (rotl32(a, 5U) + f + e + k + w[i]) & 0xffffffffUL;
        e = d;
        d = c;
        c = rotl32(b, 30U);
        b = a;
        a = temp;
    }

    ctx->state[0] = (ctx->state[0] + a) & 0xffffffffUL;
    ctx->state[1] = (ctx->state[1] + b) & 0xffffffffUL;
    ctx->state[2] = (ctx->state[2] + c) & 0xffffffffUL;
    ctx->state[3] = (ctx->state[3] + d) & 0xffffffffUL;
    ctx->state[4] = (ctx->state[4] + e) & 0xffffffffUL;
}

static void sha1_update(struct sha1_ctx *ctx,
                        const unsigned char *data,
                        size_t len)
{
    size_t i;

    ctx->total_len += (sockify_u64)len;
    for (i = 0; i < len; i++) {
        ctx->block[ctx->block_len++] = data[i];
        if (ctx->block_len == 64U) {
            sha1_process(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void sha1_final(struct sha1_ctx *ctx, unsigned char digest[20])
{
    sockify_u64 bit_len;
    unsigned char pad;
    int i;

    bit_len = ctx->total_len * 8U;

    pad = 0x80U;
    sha1_update(ctx, &pad, 1U);
    pad = 0x00U;
    while (ctx->block_len != 56U) {
        sha1_update(ctx, &pad, 1U);
    }

    for (i = 7; i >= 0; i--) {
        unsigned char byte;

        byte = (unsigned char)((bit_len >> (i * 8)) & 0xffU);
        sha1_update(ctx, &byte, 1U);
    }

    for (i = 0; i < 5; i++) {
        digest[i * 4] = (unsigned char)((ctx->state[i] >> 24) & 0xffU);
        digest[(i * 4) + 1] = (unsigned char)((ctx->state[i] >> 16) & 0xffU);
        digest[(i * 4) + 2] = (unsigned char)((ctx->state[i] >> 8) & 0xffU);
        digest[(i * 4) + 3] = (unsigned char)(ctx->state[i] & 0xffU);
    }
}

void sockify_sha1(const unsigned char *input, size_t input_len, unsigned char digest[20])
{
    struct sha1_ctx ctx;

    sha1_init(&ctx);
    if (input_len != 0) {
        sha1_update(&ctx, input, input_len);
    }
    sha1_final(&ctx, digest);
}
