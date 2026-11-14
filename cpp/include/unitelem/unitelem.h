#ifndef UNITELEM_H
#define UNITELEM_H

#include "unitelem/ccsds.h"
#include "unitelem/crc16.h"
#include "unitelem/crypto.h"
#include "unitelem/discovery.h"
#include "unitelem/hash_chain.h"
#include "unitelem/merkle_tree.h"
#include "unitelem/ring_buffer.h"
#include "unitelem/state_crdt.h"
#include "unitelem/transport.h"
#include "unitelem/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ut_node ut_node_t;

typedef struct ut_node_config {
    const char *node_id;
    const char *swarm_id;
    uint16_t port;
    bool enable_crypto;
    bool require_pinned_keys;
    const char *private_key_hex;
    bool auto_start;
    bool enable_discovery;
    bool enable_anti_entropy;
    double anti_entropy_interval_s;
    size_t ring_capacity;
    bool ring_auto_expand;
    size_t ledger_history;
} ut_node_config_t;

ut_node_config_t ut_node_config_default(const char *node_id);

ut_node_t *ut_node_create(const ut_node_config_t *config, ut_status_t *out_status);
void ut_node_destroy(ut_node_t *node);

ut_status_t ut_node_start(ut_node_t *node);
void ut_node_stop(ut_node_t *node);

const char *ut_node_id(const ut_node_t *node);
uint16_t ut_node_port(const ut_node_t *node);
const char *ut_node_public_key_hex(const ut_node_t *node);
uint64_t ut_node_sequence_number(ut_node_t *node);

ut_status_t ut_node_publish(
    ut_node_t *node,
    const char *topic,
    const uint8_t *data,
    size_t len,
    bool is_json
);

ut_status_t ut_node_publish_json(ut_node_t *node, const char *topic, const char *json_str);

ut_status_t ut_node_subscribe(
    ut_node_t *node,
    const char *topic_pattern,
    ut_topic_callback_fn callback,
    void *user_ctx
);

ut_status_t ut_node_get_latest(
    ut_node_t *node,
    const char *path,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len,
    bool *out_is_json
);

ut_status_t ut_node_get_swarm_state_json(ut_node_t *node, char **out_json, size_t *out_len);
ut_status_t ut_node_get_merkle_root(ut_node_t *node, uint8_t out_root[UT_SHA256_SIZE]);
void ut_node_trigger_repair(ut_node_t *node);
bool ut_node_verify_chain(ut_node_t *node);

ut_status_t ut_node_add_peer(
    ut_node_t *node,
    const char *peer_id,
    const char *ip,
    uint16_t port,
    const char *pub_key_hex
);

ut_status_t ut_node_attach_packet_tap(ut_node_t *node, ut_packet_tap_fn cb, void *user_ctx);
size_t ut_node_ring_dropped_count(ut_node_t *node);

void ut_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_H */
