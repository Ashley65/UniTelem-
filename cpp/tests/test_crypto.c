#include "unitelem/crypto.h"
#include "unitelem/hash_chain.h"
#include "unitelem/merkle_tree.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_blake2s_128_vector(void) {
    /* Verified against Python hashlib.blake2s(b"abc", digest_size=16).hexdigest() */
    const char *expected_hex = "aa4938119b1dc7b87cbad0ffd200d0ae";
    uint8_t out[UT_DIGEST_SIZE];
    assert(ut_blake2s_128((const uint8_t *)"abc", 3, out) == UT_OK);
    char hex[UT_DIGEST_SIZE * 2 + 1];
    assert(ut_hex_encode(out, UT_DIGEST_SIZE, hex, sizeof(hex)) == UT_OK);
    assert(strcmp(hex, expected_hex) == 0);
}

static void test_ed25519_rfc8032_and_roundtrip(void) {
    /* RFC 8032 Section 7.1 TEST 1 */
    const char *seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const char *pk_hex   = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char *sig_hex  =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    uint8_t seed[UT_ED25519_SEED_SIZE];
    uint8_t expected_pk[UT_ED25519_PK_SIZE];
    uint8_t expected_sig[UT_ED25519_SIG_SIZE];
    size_t n = 0;
    assert(ut_hex_decode(seed_hex, strlen(seed_hex), seed, sizeof(seed), &n) == UT_OK);
    assert(ut_hex_decode(pk_hex, strlen(pk_hex), expected_pk, sizeof(expected_pk), &n) == UT_OK);
    assert(ut_hex_decode(sig_hex, strlen(sig_hex), expected_sig, sizeof(expected_sig), &n) == UT_OK);

    uint8_t pk[UT_ED25519_PK_SIZE];
    assert(ut_ed25519_pk_from_seed(seed, pk) == UT_OK);
    assert(memcmp(pk, expected_pk, UT_ED25519_PK_SIZE) == 0);

    uint8_t sig[UT_ED25519_SIG_SIZE];
    assert(ut_ed25519_sign(seed, (const uint8_t *)"", 0, sig) == UT_OK);
    assert(memcmp(sig, expected_sig, UT_ED25519_SIG_SIZE) == 0);
    assert(ut_ed25519_verify(pk, (const uint8_t *)"", 0, sig) == UT_OK);

    uint8_t bad_msg = 0x42;
    assert(ut_ed25519_verify(pk, &bad_msg, 1, sig) != UT_OK);
}

static void test_micro_ledger_past_16k_and_peer_tracker(void) {
    ut_micro_ledger_t ledger;
    assert(ut_micro_ledger_init(&ledger, "node_a", 64) == UT_OK);

    ut_peer_ledger_tracker_t tracker;
    assert(ut_peer_ledger_tracker_init(&tracker) == UT_OK);

    /* Run 16,405 frames to verify zero breakage across the 14-bit 16,384 wrap boundary */
    for (uint64_t i = 1; i <= 16405; ++i) {
        uint8_t payload[8];
        memcpy(payload, &i, sizeof(i));
        uint64_t seq = 0;
        uint8_t prev[UT_DIGEST_SIZE], dig[UT_DIGEST_SIZE];
        uint64_t ts = 1000000ULL + i;
        assert(ut_micro_ledger_append(&ledger, ts, payload, sizeof(payload), &seq, prev, dig) == UT_OK);
        assert(seq == i);

        ut_ledger_result_t r = ut_peer_ledger_record_incoming(
            &tracker, "node_a", seq, ts, prev, dig, payload, sizeof(payload), NULL);
        assert(r == UT_LEDGER_OK);
    }

    assert(ut_micro_ledger_verify_local(&ledger));

    /* Gap detection */
    uint8_t last_dig[UT_DIGEST_SIZE];
    ut_micro_ledger_last_digest(&ledger, last_dig);
    uint8_t gap_dig[UT_DIGEST_SIZE];
    uint8_t p = 7;
    assert(ut_compute_digest(last_dig, 16410, 2000000ULL, &p, 1, gap_dig) == UT_OK);
    uint64_t gap = 0;
    assert(ut_peer_ledger_record_incoming(
        &tracker, "node_a", 16410, 2000000ULL, last_dig, gap_dig, &p, 1, &gap) == UT_LEDGER_GAP);
    assert(gap == 4);

    /* Tamper / fork detection on contiguous seq 16411 with wrong prev_digest */
    uint8_t wrong_prev[UT_DIGEST_SIZE] = {0x11};
    uint8_t fork_dig[UT_DIGEST_SIZE];
    assert(ut_compute_digest(wrong_prev, 16411, 2000001ULL, &p, 1, fork_dig) == UT_OK);
    assert(ut_peer_ledger_record_incoming(
        &tracker, "node_a", 16411, 2000001ULL, wrong_prev, fork_dig, &p, 1, NULL) == UT_LEDGER_FORK_OR_TAMPER);

    ut_peer_ledger_tracker_destroy(&tracker);
    ut_micro_ledger_destroy(&ledger);
}

static void test_merkle_tree_canonical(void) {
    ut_merkle_tree_t t1, t2;
    assert(ut_merkle_tree_init(&t1) == UT_OK);
    assert(ut_merkle_tree_init(&t2) == UT_OK);

    const char *v1 = "{\"b\":2,\"a\":1}";
    const char *v2 = "true";
    const char *v3 = "42.0";

    ut_merkle_leaf_input_t in1[] = {
        {"n1", "t/obj",  (const uint8_t *)v1, strlen(v1), true, 3},
        {"n1", "t/bool", (const uint8_t *)v2, strlen(v2), true, 1},
        {"n2", "t/num",  (const uint8_t *)v3, strlen(v3), true, 2},
    };
    ut_merkle_leaf_input_t in2[] = {
        {"n2", "t/num",  (const uint8_t *)v3, strlen(v3), true, 2},
        {"n1", "t/obj",  (const uint8_t *)v1, strlen(v1), true, 3},
        {"n1", "t/bool", (const uint8_t *)v2, strlen(v2), true, 1},
    };

    assert(ut_merkle_tree_update(&t1, in1, 3) == UT_OK);
    assert(ut_merkle_tree_update(&t2, in2, 3) == UT_OK);
    assert(memcmp(t1.root, t2.root, UT_SHA256_SIZE) == 0);

    char *s = NULL;
    assert(ut_merkle_canonical_val_str((const uint8_t *)v1, strlen(v1), true, &s, NULL) == UT_OK);
    assert(strcmp(s, "{\"a\": 1, \"b\": 2}") == 0);
    free(s);

    assert(ut_merkle_canonical_val_str((const uint8_t *)v2, strlen(v2), true, &s, NULL) == UT_OK);
    assert(strcmp(s, "True") == 0);
    free(s);

    assert(ut_merkle_canonical_val_str((const uint8_t *)v3, strlen(v3), true, &s, NULL) == UT_OK);
    assert(strcmp(s, "42.0") == 0);
    free(s);

    ut_merkle_tree_destroy(&t1);
    ut_merkle_tree_destroy(&t2);
}

int main(void) {
    test_blake2s_128_vector();
    test_ed25519_rfc8032_and_roundtrip();
    test_micro_ledger_past_16k_and_peer_tracker();
    test_merkle_tree_canonical();
    printf("test_crypto passed\n");
    return 0;
}
