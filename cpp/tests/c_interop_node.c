#include "unitelem/unitelem.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct cb_state {
    atomic_int rx_count;
    char last_topic[128];
    char last_payload[512];
} cb_state_t;

static void on_topic(
    const char *topic,
    const uint8_t *value,
    size_t value_len,
    bool is_json,
    const char *sender_node_id,
    void *user_ctx
) {
    (void)is_json;
    cb_state_t *st = (cb_state_t *)user_ctx;
    int idx = atomic_fetch_add(&st->rx_count, 1) + 1;
    size_t tlen = strlen(topic);
    if (tlen >= sizeof(st->last_topic)) tlen = sizeof(st->last_topic) - 1u;
    memcpy(st->last_topic, topic, tlen);
    st->last_topic[tlen] = '\0';

    size_t plen = value_len;
    if (plen >= sizeof(st->last_payload)) plen = sizeof(st->last_payload) - 1u;
    if (value && plen > 0u) memcpy(st->last_payload, value, plen);
    st->last_payload[plen] = '\0';

    printf("C_RX [%d] from=%s topic=%s payload=%s\n", idx, sender_node_id, st->last_topic, st->last_payload);
    fflush(stdout);
}

static void sleep_ms(long ms) {
    struct timespec req = {
        .tv_sec = ms / 1000L,
        .tv_nsec = (ms % 1000L) * 1000000L
    };
    nanosleep(&req, NULL);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: c_interop_node <direct|discovery> ...\n");
        return 2;
    }

    const char *mode = argv[1];
    bool use_discovery = (strcmp(mode, "discovery") == 0);

    ut_node_config_t cfg = ut_node_config_default("c_node");
    cfg.swarm_id = use_discovery ? "disc_swarm" : "c_py_swarm";
    cfg.port = 0; /* ephemeral */
    cfg.enable_crypto = true;
    cfg.enable_discovery = use_discovery;
    cfg.enable_anti_entropy = true;
    cfg.anti_entropy_interval_s = 0.15;
    cfg.auto_start = false;

    ut_status_t st = UT_OK;
    ut_node_t *node = ut_node_create(&cfg, &st);
    if (!node) {
        fprintf(stderr, "ut_node_create failed: %s\n", ut_status_str(st));
        return 1;
    }

    cb_state_t cb_st;
    memset(&cb_st, 0, sizeof(cb_st));
    atomic_init(&cb_st.rx_count, 0);
    ut_node_subscribe(node, "*", on_topic, &cb_st);

    /* Publish one register BEFORE start/peering to exercise Anti-Entropy repair */
    ut_node_publish_json(node, "c/boot", "{\"phase\":\"pre_peer\",\"ready\":true}");

    st = ut_node_start(node);
    if (st != UT_OK) {
        fprintf(stderr, "ut_node_start failed: %s\n", ut_status_str(st));
        ut_node_destroy(node);
        return 1;
    }

    printf("READY %u %s\n", (unsigned)ut_node_port(node), ut_node_public_key_hex(node));
    fflush(stdout);

    if (!use_discovery) {
        if (argc < 5) {
            fprintf(stderr, "direct mode requires <py_id> <py_port> <py_pk_hex>\n");
            ut_node_destroy(node);
            return 2;
        }
        ut_node_add_peer(node, argv[2], "127.0.0.1", (uint16_t)atoi(argv[3]), argv[4]);
    } else {
        /* Wait for discovery to find py_node */
        sleep_ms(1800);
    }

    /* Publish live telemetry from C11 */
    ut_node_publish_json(node, "c/telemetry", "{\"alt\":42.5,\"ok\":true}");

    /* Wait for Python's ping + pre-peer repair */
    char buf[512];
    size_t out_len = 0;
    int waited = 0;
    while (waited < 6000) {
        if (atomic_load(&cb_st.rx_count) >= 1 &&
            ut_node_get_latest(node, "py_node/py/pre_peer", (uint8_t *)buf, sizeof(buf), &out_len, NULL) == UT_OK &&
            ut_node_get_latest(node, "py_node/py/telemetry", (uint8_t *)buf, sizeof(buf), &out_len, NULL) == UT_OK) {
            break;
        }
        sleep_ms(50);
        waited += 50;
    }

    if (ut_node_get_latest(node, "py_node/py/telemetry", (uint8_t *)buf, sizeof(buf), &out_len, NULL) != UT_OK) {
        fprintf(stderr, "C node missed py_node/py/telemetry\n");
        ut_node_destroy(node);
        return 1;
    }
    printf("C_STATE py/telemetry=%s\n", buf);

    if (ut_node_get_latest(node, "py_node/py/pre_peer", (uint8_t *)buf, sizeof(buf), &out_len, NULL) != UT_OK) {
        fprintf(stderr, "C node missed py_node/py/pre_peer (AE repair)\n");
        ut_node_destroy(node);
        return 1;
    }
    printf("C_STATE py/pre_peer=%s\n", buf);

    /* Wait briefly for AE Merkle root convergence */
    sleep_ms(450);

    uint8_t root[UT_SHA256_SIZE];
    ut_node_get_merkle_root(node, root);
    char root_hex[UT_SHA256_SIZE * 2 + 1];
    ut_hex_encode(root, UT_SHA256_SIZE, root_hex, sizeof(root_hex));
    printf("C_MERKLE %s\n", root_hex);
    printf("C_CHAIN_VALID %d seq=%llu\n",
           ut_node_verify_chain(node) ? 1 : 0,
           (unsigned long long)ut_node_sequence_number(node));
    fflush(stdout);

    ut_node_destroy(node);
    return 0;
}
