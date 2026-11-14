#include "unitelem/crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include <string.h>

static ut_status_t ossl_ed25519_keygen(
    uint8_t out_seed[UT_ED25519_SEED_SIZE],
    uint8_t out_pk[UT_ED25519_PK_SIZE]
) {
    if (!out_seed || !out_pk) {
        return UT_ERR_INVALID_ARG;
    }
    if (RAND_bytes(out_seed, UT_ED25519_SEED_SIZE) != 1) {
        return UT_ERR_CRYPTO;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, out_seed, UT_ED25519_SEED_SIZE);
    if (!pkey) {
        return UT_ERR_CRYPTO;
    }
    size_t pk_len = UT_ED25519_PK_SIZE;
    int ok = EVP_PKEY_get_raw_public_key(pkey, out_pk, &pk_len);
    EVP_PKEY_free(pkey);
    return (ok == 1 && pk_len == UT_ED25519_PK_SIZE) ? UT_OK : UT_ERR_CRYPTO;
}

static ut_status_t ossl_ed25519_pk_from_seed(
    const uint8_t seed[UT_ED25519_SEED_SIZE],
    uint8_t out_pk[UT_ED25519_PK_SIZE]
) {
    if (!seed || !out_pk) {
        return UT_ERR_INVALID_ARG;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, UT_ED25519_SEED_SIZE);
    if (!pkey) {
        return UT_ERR_CRYPTO;
    }
    size_t pk_len = UT_ED25519_PK_SIZE;
    int ok = EVP_PKEY_get_raw_public_key(pkey, out_pk, &pk_len);
    EVP_PKEY_free(pkey);
    return (ok == 1 && pk_len == UT_ED25519_PK_SIZE) ? UT_OK : UT_ERR_CRYPTO;
}

static ut_status_t ossl_ed25519_sign(
    const uint8_t seed[UT_ED25519_SEED_SIZE],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_sig[UT_ED25519_SIG_SIZE]
) {
    if (!seed || !out_sig || (!msg && msg_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, UT_ED25519_SEED_SIZE);
    if (!pkey) {
        return UT_ERR_CRYPTO;
    }
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) {
        EVP_PKEY_free(pkey);
        return UT_ERR_NO_MEMORY;
    }
    ut_status_t st = UT_ERR_CRYPTO;
    size_t sig_len = UT_ED25519_SIG_SIZE;
    if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(mctx, out_sig, &sig_len, msg, msg_len) == 1 &&
        sig_len == UT_ED25519_SIG_SIZE) {
        st = UT_OK;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return st;
}

static ut_status_t ossl_ed25519_verify(
    const uint8_t pk[UT_ED25519_PK_SIZE],
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t sig[UT_ED25519_SIG_SIZE]
) {
    if (!pk || !sig || (!msg && msg_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, UT_ED25519_PK_SIZE);
    if (!pkey) {
        return UT_ERR_BAD_SIG;
    }
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) {
        EVP_PKEY_free(pkey);
        return UT_ERR_NO_MEMORY;
    }
    ut_status_t st = UT_ERR_BAD_SIG;
    if (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(mctx, sig, UT_ED25519_SIG_SIZE, msg, msg_len) == 1) {
        st = UT_OK;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return st;
}

static ut_status_t portable_blake2s_128(
    const uint8_t *in,
    size_t in_len,
    uint8_t out[UT_DIGEST_SIZE]
) {
    if (!out || (!in && in_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    ut_blake2s_ctx_t ctx;
    ut_status_t st = ut_blake2s_init(&ctx, UT_DIGEST_SIZE);
    if (st != UT_OK) {
        return st;
    }
    st = ut_blake2s_update(&ctx, in, in_len);
    if (st != UT_OK) {
        return st;
    }
    return ut_blake2s_final(&ctx, out);
}

static ut_status_t ossl_sha256(
    const uint8_t *in,
    size_t in_len,
    uint8_t out[UT_SHA256_SIZE]
) {
    if (!out || (!in && in_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    unsigned int out_len = 0;
    if (EVP_Digest(in, in_len, out, &out_len, EVP_sha256(), NULL) != 1 ||
        out_len != UT_SHA256_SIZE) {
        return UT_ERR_CRYPTO;
    }
    return UT_OK;
}

static const ut_crypto_backend_t g_openssl_backend = {
    .name = "openssl",
    .ed25519_keygen = ossl_ed25519_keygen,
    .ed25519_pk_from_seed = ossl_ed25519_pk_from_seed,
    .ed25519_sign = ossl_ed25519_sign,
    .ed25519_verify = ossl_ed25519_verify,
    .blake2s_128 = portable_blake2s_128,
    .sha256 = ossl_sha256
};

static _Atomic(const ut_crypto_backend_t *) g_active_backend = &g_openssl_backend;

const ut_crypto_backend_t *ut_crypto_openssl_backend(void) {
    return &g_openssl_backend;
}

const ut_crypto_backend_t *ut_crypto_get_backend(void) {
    return atomic_load_explicit(&g_active_backend, memory_order_acquire);
}

ut_status_t ut_crypto_set_backend(const ut_crypto_backend_t *backend) {
    if (!backend || !backend->ed25519_keygen || !backend->ed25519_pk_from_seed ||
        !backend->ed25519_sign || !backend->ed25519_verify ||
        !backend->blake2s_128 || !backend->sha256) {
        return UT_ERR_INVALID_ARG;
    }
    atomic_store_explicit(&g_active_backend, backend, memory_order_release);
    return UT_OK;
}

ut_status_t ut_ed25519_keygen(uint8_t out_seed[UT_ED25519_SEED_SIZE],
                              uint8_t out_pk[UT_ED25519_PK_SIZE]) {
    return ut_crypto_get_backend()->ed25519_keygen(out_seed, out_pk);
}

ut_status_t ut_ed25519_pk_from_seed(const uint8_t seed[UT_ED25519_SEED_SIZE],
                                    uint8_t out_pk[UT_ED25519_PK_SIZE]) {
    return ut_crypto_get_backend()->ed25519_pk_from_seed(seed, out_pk);
}

ut_status_t ut_ed25519_sign(const uint8_t seed[UT_ED25519_SEED_SIZE],
                            const uint8_t *msg, size_t msg_len,
                            uint8_t out_sig[UT_ED25519_SIG_SIZE]) {
    return ut_crypto_get_backend()->ed25519_sign(seed, msg, msg_len, out_sig);
}

ut_status_t ut_ed25519_verify(const uint8_t pk[UT_ED25519_PK_SIZE],
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t sig[UT_ED25519_SIG_SIZE]) {
    return ut_crypto_get_backend()->ed25519_verify(pk, msg, msg_len, sig);
}

ut_status_t ut_blake2s_128(const uint8_t *in, size_t in_len,
                           uint8_t out[UT_DIGEST_SIZE]) {
    return ut_crypto_get_backend()->blake2s_128(in, in_len, out);
}

ut_status_t ut_sha256(const uint8_t *in, size_t in_len,
                      uint8_t out[UT_SHA256_SIZE]) {
    return ut_crypto_get_backend()->sha256(in, in_len, out);
}

ut_status_t ut_hex_encode(const uint8_t *in, size_t in_len,
                          char *out_hex, size_t out_cap) {
    static const char hex_chars[] = "0123456789abcdef";
    if (!out_hex || (!in && in_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    if (out_cap < in_len * 2u + 1u) {
        return UT_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < in_len; ++i) {
        out_hex[i * 2u]     = hex_chars[(in[i] >> 4) & 0x0Fu];
        out_hex[i * 2u + 1] = hex_chars[in[i] & 0x0Fu];
    }
    out_hex[in_len * 2u] = '\0';
    return UT_OK;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

ut_status_t ut_hex_decode(const char *hex, size_t hex_len,
                          uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!hex || !out || (hex_len % 2u) != 0u) {
        return UT_ERR_INVALID_ARG;
    }
    size_t needed = hex_len / 2u;
    if (out_cap < needed) {
        if (out_len) {
            *out_len = needed;
        }
        return UT_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < needed; ++i) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return UT_ERR_MALFORMED;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len) {
        *out_len = needed;
    }
    return UT_OK;
}
