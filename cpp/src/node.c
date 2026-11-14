#include "unitelem/unitelem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ut_node {
    char node_id[UT_NODE_ID_MAX + 1];
    char swarm_id[128];
    char pub_key_hex[UT_ED25519_PK_SIZE * 2 + 1];
    bool enable_discovery;
    bool running;

    ut_swarm_state_t state;
    ut_micro_ledger_t ledger;
    ut_merkle_tree_t merkle_tree;
    ut_ringbuf_t ring;
    ut_discovery_t discovery;
    ut_transport_t transport;
};

static void on_peer_discovered(
    const char *peer_id,
    const char *ip,
    uint16_t port,
    const char *pub_key_hex,
    void *user_ctx
) {
    (void)ip;
    (void)port;
    ut_node_t *node = (ut_node_t *)user_ctx;
    if (node && pub_key_hex && pub_key_hex[0] != '\0' && !node->transport.require_pinned_keys) {
        ut_transport_register_peer_key(&node->transport, peer_id, pub_key_hex);
    }
}

ut_node_config_t ut_node_config_default(const char *node_id) {
    ut_node_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.node_id = node_id;
    cfg.swarm_id = "default";
    cfg.port = 8900u;
    cfg.enable_crypto = true;
    cfg.require_pinned_keys = false;
    cfg.private_key_hex = NULL;
    cfg.auto_start = true;
    cfg.enable_discovery = true;
    cfg.enable_anti_entropy = true;
    cfg.anti_entropy_interval_s = 0.5;
    cfg.ring_capacity = 32768u;
    cfg.ring_auto_expand = false;
    cfg.ledger_history = 10000u;
    return cfg;
}

ut_node_t *ut_node_create(const ut_node_config_t *config, ut_status_t *out_status) {
    if (!config || !config->node_id || config->node_id[0] == '\0') {
        if (out_status) *out_status = UT_ERR_INVALID_ARG;
        return NULL;
    }

    ut_node_t *node = (ut_node_t *)calloc(1, sizeof(ut_node_t));
    if (!node) {
        if (out_status) *out_status = UT_ERR_NO_MEMORY;
        return NULL;
    }

    size_t nid_len = strnlen(config->node_id, UT_NODE_ID_MAX);
    memcpy(node->node_id, config->node_id, nid_len);
    const char *swarm = (config->swarm_id && config->swarm_id[0] != '\0') ? config->swarm_id : "default";
    snprintf(node->swarm_id, sizeof(node->swarm_id), "%s", swarm);
    node->enable_discovery = config->enable_discovery;

    uint8_t seed_buf[UT_ED25519_SEED_SIZE];
    const uint8_t *seed_ptr = NULL;
    if (config->enable_crypto && config->private_key_hex && config->private_key_hex[0] != '\0') {
        size_t decoded_len = 0u;
        ut_status_t st = ut_hex_decode(config->private_key_hex, strlen(config->private_key_hex),
                                       seed_buf, sizeof(seed_buf), &decoded_len);
        if (st != UT_OK || decoded_len != UT_ED25519_SEED_SIZE) {
            if (out_status) *out_status = UT_ERR_MALFORMED;
            free(node);
            return NULL;
        }
        seed_ptr = seed_buf;
    }

    ut_status_t st = ut_swarm_state_init(&node->state, node->node_id);
    if (st != UT_OK) goto fail_state;

    size_t ledger_hist = (config->ledger_history > 0u) ? config->ledger_history : 10000u;
    st = ut_micro_ledger_init(&node->ledger, node->node_id, ledger_hist);
    if (st != UT_OK) goto fail_ledger;

    st = ut_merkle_tree_init(&node->merkle_tree);
    if (st != UT_OK) goto fail_merkle;

    size_t ring_cap = (config->ring_capacity > 0u) ? config->ring_capacity : 32768u;
    st = ut_ringbuf_init(&node->ring, ring_cap, sizeof(ut_pub_item_t),
                         config->ring_auto_expand, NULL, NULL);
    if (st != UT_OK) goto fail_ring;

    st = ut_transport_init(
        &node->transport,
        node->node_id,
        node->swarm_id,
        config->port,
        &node->ring,
        &node->state,
        &node->ledger,
        config->enable_crypto,
        seed_ptr,
        config->enable_discovery ? &node->discovery : NULL,
        &node->merkle_tree,
        config->enable_anti_entropy,
        config->anti_entropy_interval_s
    );
    if (st != UT_OK) goto fail_transport;
    node->transport.require_pinned_keys = config->require_pinned_keys;

    if (config->enable_crypto) {
        ut_hex_encode(node->transport.public_key, UT_ED25519_PK_SIZE,
                      node->pub_key_hex, sizeof(node->pub_key_hex));
    }

    st = ut_discovery_init(
        &node->discovery,
        node->node_id,
        node->swarm_id,
        config->port,
        node->pub_key_hex,
        on_peer_discovered,
        node
    );
    if (st != UT_OK) goto fail_discovery;

    if (config->auto_start) {
        st = ut_node_start(node);
        if (st != UT_OK) goto fail_start;
    }

    if (out_status) *out_status = UT_OK;
    return node;

fail_start:
    ut_discovery_destroy(&node->discovery);
fail_discovery:
    ut_transport_destroy(&node->transport);
fail_transport:
    ut_ringbuf_destroy(&node->ring);
fail_ring:
    ut_merkle_tree_destroy(&node->merkle_tree);
fail_merkle:
    ut_micro_ledger_destroy(&node->ledger);
fail_ledger:
    ut_swarm_state_destroy(&node->state);
fail_state:
    free(node);
    if (out_status) *out_status = st;
    return NULL;
}

void ut_node_destroy(ut_node_t *node) {
    if (!node) return;
    ut_node_stop(node);
    ut_discovery_destroy(&node->discovery);
    ut_transport_destroy(&node->transport);
    ut_ringbuf_destroy(&node->ring);
    ut_merkle_tree_destroy(&node->merkle_tree);
    ut_micro_ledger_destroy(&node->ledger);
    ut_swarm_state_destroy(&node->state);
    free(node);
}

ut_status_t ut_node_start(ut_node_t *node) {
    if (!node) return UT_ERR_INVALID_ARG;
    if (node->running) return UT_OK;

    ut_status_t st = ut_transport_start(&node->transport);
    if (st != UT_OK) return st;

    node->discovery.data_port = node->transport.port;
    if (node->enable_discovery) {
        st = ut_discovery_start(&node->discovery);
        if (st != UT_OK) {
            ut_transport_stop(&node->transport);
            return st;
        }
    }
    node->running = true;
    return UT_OK;
}

void ut_node_stop(ut_node_t *node) {
    if (!node || !node->running) return;
    node->running = false;
    if (node->enable_discovery) {
        ut_discovery_stop(&node->discovery);
    }
    ut_transport_stop(&node->transport);
}

const char *ut_node_id(const ut_node_t *node) {
    return node ? node->node_id : "";
}

uint16_t ut_node_port(const ut_node_t *node) {
    return node ? node->transport.port : 0u;
}

const char *ut_node_public_key_hex(const ut_node_t *node) {
    return node ? node->pub_key_hex : "";
}

uint64_t ut_node_sequence_number(ut_node_t *node) {
    return node ? ut_micro_ledger_seq(&node->ledger) : 0u;
}

ut_status_t ut_node_publish(
    ut_node_t *node,
    const char *topic,
    const uint8_t *data,
    size_t len,
    bool is_json
) {
    if (!node || !topic || (!data && len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }

    uint64_t lamport = 0u;
    ut_status_t st = ut_swarm_state_update_local(&node->state, topic, data, len, is_json, &lamport, NULL);
    if (st != UT_OK) return st;

    ut_pub_item_t item;
    memset(&item, 0, sizeof(item));
    item.lamport_time = lamport;
    item.is_json = is_json;
    item.payload_len = len;

    size_t tlen = strlen(topic);
    if (tlen < UT_INLINE_TOPIC_MAX) {
        memcpy(item.topic, topic, tlen + 1u);
    } else {
        item.heap_topic = (char *)malloc(tlen + 1u);
        if (!item.heap_topic) return UT_ERR_NO_MEMORY;
        memcpy(item.heap_topic, topic, tlen + 1u);
    }

    if (len > 0u) {
        if (len <= UT_INLINE_PAYLOAD_MAX) {
            memcpy(item.inline_payload, data, len);
        } else {
            item.heap_payload = (uint8_t *)malloc(len);
            if (!item.heap_payload) {
                free(item.heap_topic);
                return UT_ERR_NO_MEMORY;
            }
            memcpy(item.heap_payload, data, len);
        }
    }

    st = ut_ringbuf_push(&node->ring, &item);
    if (st != UT_OK) {
        ut_pub_item_free(&item);
    }
    return st;
}

ut_status_t ut_node_publish_json(ut_node_t *node, const char *topic, const char *json_str) {
    if (!json_str) return UT_ERR_INVALID_ARG;
    return ut_node_publish(node, topic, (const uint8_t *)json_str, strlen(json_str), true);
}

ut_status_t ut_node_subscribe(
    ut_node_t *node,
    const char *topic_pattern,
    ut_topic_callback_fn callback,
    void *user_ctx
) {
    if (!node) return UT_ERR_INVALID_ARG;
    return ut_transport_subscribe(&node->transport, topic_pattern, callback, user_ctx);
}

ut_status_t ut_node_get_latest(
    ut_node_t *node,
    const char *path,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len,
    bool *out_is_json
) {
    if (!node) return UT_ERR_INVALID_ARG;
    return ut_swarm_state_get_value(&node->state, path, out_buf, out_cap, out_len, out_is_json);
}

ut_status_t ut_node_get_swarm_state_json(ut_node_t *node, char **out_json, size_t *out_len) {
    if (!node) return UT_ERR_INVALID_ARG;
    return ut_swarm_state_snapshot_json(&node->state, out_json, out_len);
}

ut_status_t ut_node_get_merkle_root(ut_node_t *node, uint8_t out_root[UT_SHA256_SIZE]) {
    if (!node || !out_root) return UT_ERR_INVALID_ARG;
    ut_merkle_tree_t tmp;
    ut_status_t st = ut_merkle_tree_init(&tmp);
    if (st != UT_OK) return st;
    st = ut_swarm_state_compute_merkle(&node->state, &tmp);
    if (st == UT_OK) {
        memcpy(out_root, tmp.root, UT_SHA256_SIZE);
    }
    ut_merkle_tree_destroy(&tmp);
    return st;
}

void ut_node_trigger_repair(ut_node_t *node) {
    if (!node) return;
    ut_transport_trigger_repair(&node->transport);
}

bool ut_node_verify_chain(ut_node_t *node) {
    if (!node) return false;
    return ut_micro_ledger_verify_local(&node->ledger);
}

ut_status_t ut_node_add_peer(
    ut_node_t *node,
    const char *peer_id,
    const char *ip,
    uint16_t port,
    const char *pub_key_hex
) {
    if (!node) return UT_ERR_INVALID_ARG;
    return ut_transport_add_direct_peer(&node->transport, peer_id, ip, port, pub_key_hex);
}

ut_status_t ut_node_attach_packet_tap(ut_node_t *node, ut_packet_tap_fn cb, void *user_ctx) {
    if (!node) return UT_ERR_INVALID_ARG;
    return ut_transport_add_packet_tap(&node->transport, cb, user_ctx);
}

size_t ut_node_ring_dropped_count(ut_node_t *node) {
    if (!node) return 0u;
    return ut_ringbuf_dropped_count(&node->ring);
}

void ut_free(void *ptr) {
    free(ptr);
}
