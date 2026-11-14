#include "unitelem/crypto.h"

#include <string.h>

static const uint32_t blake2s_iv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static inline uint32_t rotr32(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

#define B2S_G(r, i, a, b, c, d)                                  \
    do {                                                         \
        a = a + b + m[blake2s_sigma[r][2 * (i)]];                \
        d = rotr32(d ^ a, 16);                                   \
        c = c + d;                                               \
        b = rotr32(b ^ c, 12);                                   \
        a = a + b + m[blake2s_sigma[r][2 * (i) + 1]];            \
        d = rotr32(d ^ a, 8);                                    \
        c = c + d;                                               \
        b = rotr32(b ^ c, 7);                                    \
    } while (0)

static void blake2s_compress(ut_blake2s_ctx_t *ctx, const uint8_t block[64]) {
    uint32_t m[16];
    uint32_t v[16];

    for (int i = 0; i < 16; ++i) {
        m[i] = load32_le(block + (size_t)i * 4u);
    }
    for (int i = 0; i < 8; ++i) {
        v[i] = ctx->h[i];
        v[i + 8] = blake2s_iv[i];
    }
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0];
    v[15] ^= ctx->f[1];

    for (int r = 0; r < 10; ++r) {
        B2S_G(r, 0, v[0], v[4], v[8],  v[12]);
        B2S_G(r, 1, v[1], v[5], v[9],  v[13]);
        B2S_G(r, 2, v[2], v[6], v[10], v[14]);
        B2S_G(r, 3, v[3], v[7], v[11], v[15]);
        B2S_G(r, 4, v[0], v[5], v[10], v[15]);
        B2S_G(r, 5, v[1], v[6], v[11], v[12]);
        B2S_G(r, 6, v[2], v[7], v[8],  v[13]);
        B2S_G(r, 7, v[3], v[4], v[9],  v[14]);
    }

    for (int i = 0; i < 8; ++i) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

ut_status_t ut_blake2s_init(ut_blake2s_ctx_t *ctx, size_t outlen) {
    if (!ctx || outlen == 0u || outlen > 32u) {
        return UT_ERR_INVALID_ARG;
    }
    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; ++i) {
        ctx->h[i] = blake2s_iv[i];
    }
    ctx->h[0] ^= 0x01010000u ^ (uint32_t)outlen;
    ctx->outlen = outlen;
    return UT_OK;
}

ut_status_t ut_blake2s_update(ut_blake2s_ctx_t *ctx, const uint8_t *in, size_t inlen) {
    if (!ctx || (!in && inlen > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    if (inlen == 0u) {
        return UT_OK;
    }

    size_t left = ctx->buflen;
    size_t fill = 64u - left;
    if (inlen > fill) {
        ctx->buflen = 0u;
        memcpy(ctx->buf + left, in, fill);
        ctx->t[0] += 64u;
        if (ctx->t[0] < 64u) {
            ctx->t[1] += 1u;
        }
        blake2s_compress(ctx, ctx->buf);
        in += fill;
        inlen -= fill;

        while (inlen > 64u) {
            ctx->t[0] += 64u;
            if (ctx->t[0] < 64u) {
                ctx->t[1] += 1u;
            }
            blake2s_compress(ctx, in);
            in += 64u;
            inlen -= 64u;
        }
    }

    memcpy(ctx->buf + ctx->buflen, in, inlen);
    ctx->buflen += inlen;
    return UT_OK;
}

ut_status_t ut_blake2s_final(ut_blake2s_ctx_t *ctx, uint8_t *out) {
    if (!ctx || !out || ctx->outlen == 0u || ctx->outlen > 32u) {
        return UT_ERR_INVALID_ARG;
    }
    ctx->t[0] += (uint32_t)ctx->buflen;
    if (ctx->t[0] < (uint32_t)ctx->buflen) {
        ctx->t[1] += 1u;
    }
    ctx->f[0] = 0xFFFFFFFFu;
    if (ctx->buflen < 64u) {
        memset(ctx->buf + ctx->buflen, 0, 64u - ctx->buflen);
    }
    blake2s_compress(ctx, ctx->buf);

    uint8_t digest[32];
    for (int i = 0; i < 8; ++i) {
        store32_le(digest + (size_t)i * 4u, ctx->h[i]);
    }
    memcpy(out, digest, ctx->outlen);
    memset(ctx, 0, sizeof(*ctx));
    return UT_OK;
}
