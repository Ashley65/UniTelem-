#ifndef UNITELEM_DISCOVERY_H
#define UNITELEM_DISCOVERY_H

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

typedef void (*ut_peer_found_fn)(
    const char *node_id,
    const char *ip,
    uint16_t port,
    const char *pub_key_hex,
    void *user_ctx
);

typedef struct ut_peer_info {
    char node_id[UT_NODE_ID_MAX + 1];
    char ip[64];
    uint16_t port;
    char pub_key_hex[UT_ED25519_PK_SIZE * 2 + 1];
    double last_seen;
} ut_peer_info_t;

typedef struct ut_discovery {
    char node_id[UT_NODE_ID_MAX + 1];
    char swarm_id[128];
    uint16_t data_port;
    char pub_key_hex[UT_ED25519_PK_SIZE * 2 + 1];

    ut_peer_found_fn on_peer_found;
    void *on_peer_found_ctx;

    ut_peer_info_t *peers;
    size_t peer_count;
    size_t peer_capacity;

#ifdef __cplusplus
    std::atomic<bool> running;
#else
    atomic_bool running;
#endif
    int listen_fd;
    pthread_t beacon_thread;
    pthread_t listen_thread;
    bool threads_started;
    pthread_mutex_t lock;
} ut_discovery_t;

ut_status_t ut_discovery_init(
    ut_discovery_t *disc,
    const char *node_id,
    const char *swarm_id,
    uint16_t data_port,
    const char *pub_key_hex,
    ut_peer_found_fn on_peer_found,
    void *user_ctx
);

void ut_discovery_destroy(ut_discovery_t *disc);
ut_status_t ut_discovery_start(ut_discovery_t *disc);
void ut_discovery_stop(ut_discovery_t *disc);

size_t ut_discovery_get_active_peers(
    ut_discovery_t *disc,
    double timeout_s,
    ut_peer_info_t *out_peers,
    size_t max_peers
);

bool ut_discovery_get_peer_key(
    ut_discovery_t *disc,
    const char *peer_id,
    char *out_hex,
    size_t out_cap
);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_DISCOVERY_H */
