#ifndef UNITELEM_CRYPTO_H
#define UNITELEM_CRYPTO_H

#include "unitelem/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ut_crypto_backend {
    const char *name;
    ut_status_t (*ed25519_keygen)(uint8_t out_seed[UT_ED25519_SEED_SIZE],
                                  uint8_t out_pk[UT_ED25519_PK_SIZE]);
    ut_status_t (*ed25519_pk_from_seed)(const uint8_t seed[UT_ED25519_SEED_SIZE],
                                        uint8_t out_pk[UT_ED25519_PK_SIZE]);
    ut_status_t (*ed25519_sign)(const uint8_t seed[UT_ED25519_SEED_SIZE],
                                const uint8_t *msg, size_t msg_len,
                                uint8_t out_sig[UT_ED25519_SIG_SIZE]);
    ut_status_t (*ed25519_verify)(const uint8_t pk[UT_ED25519_PK_SIZE],
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t sig[UT_ED25519_SIG_SIZE]);
    ut_status_t (*blake2s_128)(const uint8_t *in, size_t in_len,
                               uint8_t out[UT_DIGEST_SIZE]);
    ut_status_t (*sha256)(const uint8_t *in, size_t in_len,
                          uint8_t out[UT_SHA256_SIZE]);
} ut_crypto_backend_t;

/* Pluggable backend registry */
const ut_crypto_backend_t *ut_crypto_get_backend(void);
ut_status_t ut_crypto_set_backend(const ut_crypto_backend_t *backend);
const ut_crypto_backend_t *ut_crypto_openssl_backend(void);

/* Streaming BLAKE2s-128 (RFC 7693, digest_size=16) */
typedef struct ut_blake2s_ctx {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[64];
    size_t buflen;
    size_t outlen;
} ut_blake2s_ctx_t;

ut_status_t ut_blake2s_init(ut_blake2s_ctx_t *ctx, size_t outlen);
ut_status_t ut_blake2s_update(ut_blake2s_ctx_t *ctx, const uint8_t *in, size_t inlen);
ut_status_t ut_blake2s_final(ut_blake2s_ctx_t *ctx, uint8_t *out);

/* High-level helpers dispatching through active backend */
ut_status_t ut_ed25519_keygen(uint8_t out_seed[UT_ED25519_SEED_SIZE],
                              uint8_t out_pk[UT_ED25519_PK_SIZE]);
ut_status_t ut_ed25519_pk_from_seed(const uint8_t seed[UT_ED25519_SEED_SIZE],
                                    uint8_t out_pk[UT_ED25519_PK_SIZE]);
ut_status_t ut_ed25519_sign(const uint8_t seed[UT_ED25519_SEED_SIZE],
                            const uint8_t *msg, size_t msg_len,
                            uint8_t out_sig[UT_ED25519_SIG_SIZE]);
ut_status_t ut_ed25519_verify(const uint8_t pk[UT_ED25519_PK_SIZE],
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t sig[UT_ED25519_SIG_SIZE]);
ut_status_t ut_blake2s_128(const uint8_t *in, size_t in_len,
                           uint8_t out[UT_DIGEST_SIZE]);
ut_status_t ut_sha256(const uint8_t *in, size_t in_len,
                      uint8_t out[UT_SHA256_SIZE]);

/* Hex utilities */
ut_status_t ut_hex_encode(const uint8_t *in, size_t in_len,
                          char *out_hex, size_t out_cap);
ut_status_t ut_hex_decode(const char *hex, size_t hex_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_CRYPTO_H */
