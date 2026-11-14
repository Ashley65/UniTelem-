#ifndef UNITELEM_TRANSPORT_H
#define UNITELEM_TRANSPORT_H

#include "unitelem/discovery.h"
#include "unitelem/hash_chain.h"
#include "unitelem/merkle_tree.h"
#include "unitelem/ring_buffer.h"
#include "unitelem/state_crdt.h"
#include "unitelem/types.h"

#include <pthread.h>
#ifdef __cplusplus
#include <atomic>
#else
#include <stdatomic.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define UT_INLINE_TOPIC_MAX   128u
#define UT_INLINE_PAYLOAD_MAX 1400u

typedef struct ut_pub_item {
    char topic[UT_INLINE_TOPIC_MAX];
    char *heap_topic;
    uint8_t inline_payload[UT_INLINE_PAYLOAD_MAX];
    uint8_t *heap_payload;
    size_t payload_len;
    uint64_t lamport_time;
    bool is_json;
} ut_pub_item_t;

typedef void (*ut_topic_callback_fn)(
    const char *topic,
    const uint8_t *value,
    size_t value_len,
    bool is_json,
    const char *sender_node_id,
    void *user_ctx
);

typedef void (*ut_packet_tap_fn)(
    const char *src_ip,
    uint16_t src_port,
    const char *dst_ip,
    uint16_t dst_port,
    const uint8_t *wire_bytes,
    size_t wire_len,
    double timestamp_s,
    void *user_ctx
);

typedef struct ut_trust_entry {
    char node_id[UT_NODE_ID_MAX + 1];
    uint8_t pub_key[UT_ED25519_PK_SIZE];
} ut_trust_entry_t;

typedef struct ut_direct_peer {
    char node_id[UT_NODE_ID_MAX + 1];
    char ip[64];
    uint16_t port;
} ut_direct_peer_t;

typedef struct ut_sub_entry {
    char *pattern;
    ut_topic_callback_fn cb;
    void *ctx;
} ut_sub_entry_t;

typedef struct ut_tap_entry {
    ut_packet_tap_fn cb;
    void *ctx;
} ut_tap_entry_t;

typedef struct ut_transport {
    char node_id[UT_NODE_ID_MAX + 1];
    char swarm_id[128];
    uint16_t swarm_hash;
    uint16_t port;

    bool enable_crypto;
    bool require_pinned_keys;
    uint8_t private_seed[UT_ED25519_SEED_SIZE];
    uint8_t public_key[UT_ED25519_PK_SIZE];

    ut_ringbuf_t *ring_buffer;
    ut_swarm_state_t *state_store;
    ut_micro_ledger_t *ledger;
    ut_discovery_t *discovery;
    ut_merkle_tree_t *merkle_tree;
    ut_peer_ledger_tracker_t peer_tracker;

    bool enable_anti_entropy;
    double anti_entropy_interval_s;

    ut_trust_entry_t *trust_store;
    size_t trust_count;
    size_t trust_cap;

    ut_direct_peer_t *direct_peers;
    size_t direct_count;
    size_t direct_cap;

    ut_sub_entry_t *subs;
    size_t sub_count;
    size_t sub_cap;

    ut_tap_entry_t *taps;
    size_t tap_count;
    size_t tap_cap;

    int sock_fd;
#ifdef __cplusplus
    std::atomic<bool> running;
#else
    atomic_bool running;
#endif
    bool threads_started;
    pthread_t tx_thread;
    pthread_t rx_thread;
    pthread_t ae_thread;
    pthread_mutex_t lock;
} ut_transport_t;

void ut_pub_item_free(ut_pub_item_t *item);

ut_status_t ut_transport_init(
    ut_transport_t *tr,
    const char *node_id,
    const char *swarm_id,
    uint16_t port,
    ut_ringbuf_t *ring_buffer,
    ut_swarm_state_t *state_store,
    ut_micro_ledger_t *ledger,
    bool enable_crypto,
    const uint8_t private_seed[UT_ED25519_SEED_SIZE],
    ut_discovery_t *discovery,
    ut_merkle_tree_t *merkle_tree,
    bool enable_anti_entropy,
    double anti_entropy_interval_s
);

void ut_transport_destroy(ut_transport_t *tr);
ut_status_t ut_transport_start(ut_transport_t *tr);
void ut_transport_stop(ut_transport_t *tr);

ut_status_t ut_transport_register_peer_key(
    ut_transport_t *tr,
    const char *peer_id,
    const char *pub_key_hex
);

ut_status_t ut_transport_add_direct_peer(
    ut_transport_t *tr,
    const char *peer_id,
    const char *ip,
    uint16_t port,
    const char *pub_key_hex
);

ut_status_t ut_transport_subscribe(
    ut_transport_t *tr,
    const char *topic_pattern,
    ut_topic_callback_fn cb,
    void *user_ctx
);

ut_status_t ut_transport_add_packet_tap(
    ut_transport_t *tr,
    ut_packet_tap_fn cb,
    void *user_ctx
);

void ut_transport_trigger_repair(ut_transport_t *tr);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_TRANSPORT_H */
