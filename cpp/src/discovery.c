#include "unitelem/discovery.h"
#include "yyjson.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double mono_now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double wall_now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *beacon_loop(void *arg) {
    ut_discovery_t *disc = (ut_discovery_t *)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return NULL;
    }

    int ttl = 2;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    int loop = 1;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    struct sockaddr_in mcast_addr;
    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_port = htons(UT_DISCOVERY_PORT);
    inet_pton(AF_INET, UT_MULTICAST_GROUP, &mcast_addr.sin_addr);

    struct sockaddr_in lo_addr;
    memset(&lo_addr, 0, sizeof(lo_addr));
    lo_addr.sin_family = AF_INET;
    lo_addr.sin_port = htons(UT_DISCOVERY_PORT);
    inet_pton(AF_INET, "127.0.0.1", &lo_addr.sin_addr);

    while (atomic_load(&disc->running)) {
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
        if (doc) {
            yyjson_mut_val *root = yyjson_mut_obj(doc);
            yyjson_mut_doc_set_root(doc, root);
            yyjson_mut_obj_add_strcpy(doc, root, "node_id", disc->node_id);
            yyjson_mut_obj_add_strcpy(doc, root, "swarm_id", disc->swarm_id);
            yyjson_mut_obj_add_uint(doc, root, "port", disc->data_port);
            yyjson_mut_obj_add_strcpy(doc, root, "pub_key", disc->pub_key_hex);

            size_t len = 0u;
            char *json = yyjson_mut_write(doc, 0, &len);
            yyjson_mut_doc_free(doc);
            if (json) {
                sendto(sock, json, len, 0, (struct sockaddr *)&mcast_addr, sizeof(mcast_addr));
                sendto(sock, json, len, 0, (struct sockaddr *)&lo_addr, sizeof(lo_addr));
                free(json);
            }
        }

        double deadline = mono_now_sec() + 1.5;
        while (atomic_load(&disc->running) && mono_now_sec() < deadline) {
            struct timespec req = { .tv_sec = 0, .tv_nsec = 50000000L }; /* 50ms */
            nanosleep(&req, NULL);
        }
    }

    close(sock);
    return NULL;
}

static void *listen_loop(void *arg) {
    ut_discovery_t *disc = (ut_discovery_t *)arg;
    int sock = disc->listen_fd;
    if (sock < 0) {
        return NULL;
    }

    char buf[2048];
    while (atomic_load(&disc->running)) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) {
            continue;
        }
        if (!(pfd.revents & POLLIN)) {
            continue;
        }

        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1u, 0,
                             (struct sockaddr *)&sender, &sender_len);
        if (n <= 0) {
            continue;
        }
        buf[n] = '\0';

        yyjson_doc *doc = yyjson_read(buf, (size_t)n, 0);
        if (!doc) {
            continue;
        }
        yyjson_val *root = yyjson_doc_get_root(doc);
        yyjson_val *v_swarm = yyjson_obj_get(root, "swarm_id");
        yyjson_val *v_nid   = yyjson_obj_get(root, "node_id");
        yyjson_val *v_port  = yyjson_obj_get(root, "port");
        yyjson_val *v_pk    = yyjson_obj_get(root, "pub_key");

        if (!yyjson_is_str(v_swarm) || !yyjson_is_str(v_nid) || !yyjson_is_uint(v_port)) {
            yyjson_doc_free(doc);
            continue;
        }

        const char *swarm_id = yyjson_get_str(v_swarm);
        const char *node_id  = yyjson_get_str(v_nid);
        uint64_t port64      = yyjson_get_uint(v_port);
        const char *pub_key  = yyjson_is_str(v_pk) ? yyjson_get_str(v_pk) : "";

        if (strcmp(swarm_id, disc->swarm_id) != 0 ||
            node_id[0] == '\0' ||
            strncmp(node_id, disc->node_id, UT_NODE_ID_MAX) == 0 ||
            port64 == 0u || port64 > 65535u) {
            yyjson_doc_free(doc);
            continue;
        }

        char ip_str[64] = {0};
        inet_ntop(AF_INET, &sender.sin_addr, ip_str, sizeof(ip_str));
        if (strcmp(ip_str, "0.0.0.0") == 0) {
            strcpy(ip_str, "127.0.0.1");
        }

        bool is_new = false;
        ut_peer_found_fn cb = NULL;
        void *cb_ctx = NULL;
        char nid_copy[UT_NODE_ID_MAX + 1] = {0};
        char pk_copy[UT_ED25519_PK_SIZE * 2 + 1] = {0};

        size_t nid_len = strnlen(node_id, UT_NODE_ID_MAX);
        memcpy(nid_copy, node_id, nid_len);
        size_t pk_len = strnlen(pub_key, sizeof(pk_copy) - 1u);
        memcpy(pk_copy, pub_key, pk_len);

        pthread_mutex_lock(&disc->lock);
        ut_peer_info_t *found = NULL;
        for (size_t i = 0u; i < disc->peer_count; ++i) {
            if (strcmp(disc->peers[i].node_id, nid_copy) == 0) {
                found = &disc->peers[i];
                break;
            }
        }
        if (!found) {
            is_new = true;
            if (disc->peer_count == disc->peer_capacity) {
                size_t new_cap = (disc->peer_capacity == 0u) ? 16u : disc->peer_capacity * 2u;
                ut_peer_info_t *grown = (ut_peer_info_t *)realloc(
                    disc->peers, new_cap * sizeof(ut_peer_info_t));
                if (grown) {
                    disc->peers = grown;
                    disc->peer_capacity = new_cap;
                }
            }
            if (disc->peer_count < disc->peer_capacity) {
                found = &disc->peers[disc->peer_count++];
                memset(found, 0, sizeof(*found));
            }
        }
        if (found) {
            strcpy(found->node_id, nid_copy);
            snprintf(found->ip, sizeof(found->ip), "%s", ip_str);
            found->port = (uint16_t)port64;
            strcpy(found->pub_key_hex, pk_copy);
            found->last_seen = wall_now_sec();
        }
        cb = disc->on_peer_found;
        cb_ctx = disc->on_peer_found_ctx;
        pthread_mutex_unlock(&disc->lock);

        yyjson_doc_free(doc);

        if (is_new && cb) {
            cb(nid_copy, ip_str, (uint16_t)port64, pk_copy, cb_ctx);
        }
    }
    return NULL;
}

ut_status_t ut_discovery_init(
    ut_discovery_t *disc,
    const char *node_id,
    const char *swarm_id,
    uint16_t data_port,
    const char *pub_key_hex,
    ut_peer_found_fn on_peer_found,
    void *user_ctx
) {
    if (!disc || !node_id || !swarm_id) return UT_ERR_INVALID_ARG;
    memset(disc, 0, sizeof(*disc));
    size_t nid_len = strnlen(node_id, UT_NODE_ID_MAX);
    memcpy(disc->node_id, node_id, nid_len);
    snprintf(disc->swarm_id, sizeof(disc->swarm_id), "%s", swarm_id);
    disc->data_port = data_port;
    if (pub_key_hex) {
        snprintf(disc->pub_key_hex, sizeof(disc->pub_key_hex), "%s", pub_key_hex);
    }
    disc->on_peer_found = on_peer_found;
    disc->on_peer_found_ctx = user_ctx;
    disc->listen_fd = -1;
    atomic_init(&disc->running, false);
    if (pthread_mutex_init(&disc->lock, NULL) != 0) {
        return UT_ERR_IO;
    }
    return UT_OK;
}

void ut_discovery_destroy(ut_discovery_t *disc) {
    if (!disc) return;
    ut_discovery_stop(disc);
    free(disc->peers);
    disc->peers = NULL;
    disc->peer_count = 0u;
    disc->peer_capacity = 0u;
    pthread_mutex_destroy(&disc->lock);
}

ut_status_t ut_discovery_start(ut_discovery_t *disc) {
    if (!disc) return UT_ERR_INVALID_ARG;
    if (atomic_load(&disc->running)) return UT_OK;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock >= 0) {
        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(UT_DISCOVERY_PORT);
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0) {
            struct ip_mreq mreq;
            memset(&mreq, 0, sizeof(mreq));
            inet_pton(AF_INET, UT_MULTICAST_GROUP, &mreq.imr_multiaddr);
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
            disc->listen_fd = sock;
        } else {
            close(sock);
            disc->listen_fd = -1;
        }
    }

    atomic_store(&disc->running, true);
    if (pthread_create(&disc->beacon_thread, NULL, beacon_loop, disc) != 0) {
        atomic_store(&disc->running, false);
        if (disc->listen_fd >= 0) {
            close(disc->listen_fd);
            disc->listen_fd = -1;
        }
        return UT_ERR_IO;
    }
    if (pthread_create(&disc->listen_thread, NULL, listen_loop, disc) != 0) {
        atomic_store(&disc->running, false);
        pthread_join(disc->beacon_thread, NULL);
        if (disc->listen_fd >= 0) {
            close(disc->listen_fd);
            disc->listen_fd = -1;
        }
        return UT_ERR_IO;
    }
    disc->threads_started = true;
    return UT_OK;
}

void ut_discovery_stop(ut_discovery_t *disc) {
    if (!disc) return;
    if (!atomic_exchange(&disc->running, false)) {
        if (disc->listen_fd >= 0) {
            close(disc->listen_fd);
            disc->listen_fd = -1;
        }
        return;
    }
    if (disc->threads_started) {
        pthread_join(disc->beacon_thread, NULL);
        pthread_join(disc->listen_thread, NULL);
        disc->threads_started = false;
    }
    if (disc->listen_fd >= 0) {
        close(disc->listen_fd);
        disc->listen_fd = -1;
    }
}

size_t ut_discovery_get_active_peers(
    ut_discovery_t *disc,
    double timeout_s,
    ut_peer_info_t *out_peers,
    size_t max_peers
) {
    if (!disc || !out_peers || max_peers == 0u) return 0u;
    double now = wall_now_sec();
    size_t n = 0u;
    pthread_mutex_lock(&disc->lock);
    for (size_t i = 0u; i < disc->peer_count && n < max_peers; ++i) {
        if (now - disc->peers[i].last_seen <= timeout_s) {
            out_peers[n++] = disc->peers[i];
        }
    }
    pthread_mutex_unlock(&disc->lock);
    return n;
}

bool ut_discovery_get_peer_key(
    ut_discovery_t *disc,
    const char *peer_id,
    char *out_hex,
    size_t out_cap
) {
    if (!disc || !peer_id || !out_hex || out_cap == 0u) return false;
    bool found = false;
    pthread_mutex_lock(&disc->lock);
    for (size_t i = 0u; i < disc->peer_count; ++i) {
        if (strcmp(disc->peers[i].node_id, peer_id) == 0 &&
            disc->peers[i].pub_key_hex[0] != '\0') {
            snprintf(out_hex, out_cap, "%s", disc->peers[i].pub_key_hex);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&disc->lock);
    return found;
}
