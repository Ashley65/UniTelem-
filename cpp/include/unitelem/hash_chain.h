#ifndef UNITELEM_HASH_CHAIN_H
#define UNITELEM_HASH_CHAIN_H

#include "unitelem/types.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ut_ledger_entry {
    uint64_t seq;
    uint64_t timestamp_ns;
    uint8_t prev_digest[UT_DIGEST_SIZE];
    uint8_t digest[UT_DIGEST_SIZE];
    uint8_t *payload;
    size_t payload_len;
} ut_ledger_entry_t;

typedef struct ut_micro_ledger {
    char node_id[UT_NODE_ID_MAX + 1];
    uint64_t seq;
    uint8_t last_digest[UT_DIGEST_SIZE];
    ut_ledger_entry_t *ring;
    size_t max_history;
    size_t head;
    size_t count;
    pthread_mutex_t lock;
} ut_micro_ledger_t;

typedef enum ut_ledger_result {
    UT_LEDGER_OK = 0,
    UT_LEDGER_OUT_OF_ORDER = 1,
    UT_LEDGER_GAP = 2,
    UT_LEDGER_CORRUPTED_DIGEST = -1,
    UT_LEDGER_FORK_OR_TAMPER = -2
} ut_ledger_result_t;

typedef struct ut_peer_ledger_state {
    char peer_id[UT_NODE_ID_MAX + 1];
    uint64_t last_seq;
    uint8_t last_digest[UT_DIGEST_SIZE];
} ut_peer_ledger_state_t;

typedef struct ut_peer_ledger_tracker {
    ut_peer_ledger_state_t *peers;
    size_t count;
    size_t capacity;
    pthread_mutex_t lock;
} ut_peer_ledger_tracker_t;

ut_status_t ut_compute_digest(
    const uint8_t prev_digest[UT_DIGEST_SIZE],
    uint64_t seq,
    uint64_t timestamp_ns,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t out_digest[UT_DIGEST_SIZE]
);

ut_status_t ut_micro_ledger_init(ut_micro_ledger_t *ledger, const char *node_id, size_t max_history);
void ut_micro_ledger_destroy(ut_micro_ledger_t *ledger);

ut_status_t ut_micro_ledger_append(
    ut_micro_ledger_t *ledger,
    uint64_t timestamp_ns,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t *out_seq,
    uint8_t out_prev_digest[UT_DIGEST_SIZE],
    uint8_t out_digest[UT_DIGEST_SIZE]
);

uint64_t ut_micro_ledger_seq(ut_micro_ledger_t *ledger);
void ut_micro_ledger_last_digest(ut_micro_ledger_t *ledger, uint8_t out_digest[UT_DIGEST_SIZE]);
bool ut_micro_ledger_verify_local(ut_micro_ledger_t *ledger);

ut_status_t ut_peer_ledger_tracker_init(ut_peer_ledger_tracker_t *tracker);
void ut_peer_ledger_tracker_destroy(ut_peer_ledger_tracker_t *tracker);

ut_ledger_result_t ut_peer_ledger_record_incoming(
    ut_peer_ledger_tracker_t *tracker,
    const char *peer_id,
    uint64_t seq,
    uint64_t timestamp_ns,
    const uint8_t prev_digest[UT_DIGEST_SIZE],
    const uint8_t digest[UT_DIGEST_SIZE],
    const uint8_t *payload,
    size_t payload_len,
    uint64_t *out_gap_count
);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_HASH_CHAIN_H */
