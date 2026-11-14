#include "unitelem/transport.h"
#include "unitelem/ccsds.h"
#include "unitelem/crypto.h"
#include "yyjson.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double mono_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static char *ut_cstrdup(const char *s) {
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1u);
    if (p) memcpy(p, s, n + 1u);
    return p;
}

void ut_pub_item_free(ut_pub_item_t *item) {
    if (!item) return;
    free(item->heap_topic);
    item->heap_topic = NULL;
    free(item->heap_payload);
    item->heap_payload = NULL;
}

static void ring_overflow_cleanup(const void *evicted_item, void *user_ctx) {
    (void)user_ctx;
    if (!evicted_item) return;
    const ut_pub_item_t *c = (const ut_pub_item_t *)evicted_item;
    free(c->heap_topic);
    free(c->heap_payload);
}

static size_t collect_target_peers(ut_transport_t *tr, ut_direct_peer_t *out, size_t max_peers) {
    size_t n = 0u;
    pthread_mutex_lock(&tr->lock);
    for (size_t i = 0u; i < tr->direct_count && n < max_peers; ++i) {
        out[n++] = tr->direct_peers[i];
    }
    pthread_mutex_unlock(&tr->lock);

    if (tr->discovery && n < max_peers) {
        ut_peer_info_t disc_peers[128];
        size_t dc = ut_discovery_get_active_peers(tr->discovery, 15.0, disc_peers, 128u);
        for (size_t i = 0u; i < dc; ++i) {
            bool replaced = false;
            for (size_t j = 0u; j < n; ++j) {
                if (strcmp(out[j].node_id, disc_peers[i].node_id) == 0) {
                    snprintf(out[j].ip, sizeof(out[j].ip), "%s", disc_peers[i].ip);
                    out[j].port = disc_peers[i].port;
                    replaced = true;
                    break;
                }
            }
            if (!replaced && n < max_peers) {
                memset(&out[n], 0, sizeof(out[n]));
                strcpy(out[n].node_id, disc_peers[i].node_id);
                snprintf(out[n].ip, sizeof(out[n].ip), "%s", disc_peers[i].ip);
                out[n].port = disc_peers[i].port;
                n += 1u;
            }
        }
    }
    return n;
}

static void transmit_raw(
    ut_transport_t *tr,
    const char *target_ip,
    uint16_t target_port,
    const uint8_t *wire_packet,
    size_t wire_len
) {
    double ts = now_sec();

    ut_tap_entry_t taps_local[16];
    size_t tap_n = 0u;
    pthread_mutex_lock(&tr->lock);
    for (size_t i = 0u; i < tr->tap_count && i < 16u; ++i) {
        taps_local[tap_n++] = tr->taps[i];
    }
    int fd = tr->sock_fd;
    uint16_t src_port = tr->port;
    pthread_mutex_unlock(&tr->lock);

    for (size_t i = 0u; i < tap_n; ++i) {
        taps_local[i].cb("127.0.0.1", src_port, target_ip, target_port,
                         wire_packet, wire_len, ts, taps_local[i].ctx);
    }

    if (fd >= 0) {
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(target_port);
        if (inet_pton(AF_INET, target_ip, &dst.sin_addr) == 1) {
            sendto(fd, wire_packet, wire_len, 0, (struct sockaddr *)&dst, sizeof(dst));
        }
    }
}

static ut_status_t sign_and_pack_frame(
    ut_transport_t *tr,
    ut_ccsds_frame_t *frame,
    uint8_t *wire_buf,
    size_t wire_cap,
    size_t *out_wire_len
) {
    if (tr->enable_crypto) {
        uint8_t *sign_buf = (uint8_t *)malloc(frame->topic_len + frame->payload_len + 128u);
        if (!sign_buf) return UT_ERR_NO_MEMORY;
        size_t sign_len = 0u;
        ut_status_t st = ut_ccsds_signable_bytes(
            frame, sign_buf, frame->topic_len + frame->payload_len + 128u, &sign_len);
        if (st == UT_OK) {
            st = ut_ed25519_sign(tr->private_seed, sign_buf, sign_len, frame->signature);
        }
        free(sign_buf);
        if (st != UT_OK) return st;
    }
    return ut_ccsds_pack(frame, wire_buf, wire_cap, out_wire_len);
}

static void send_frame(
    ut_transport_t *tr,
    ut_ccsds_frame_t *frame,
    const char *target_ip,
    uint16_t target_port
) {
    uint8_t *wire_buf = (uint8_t *)malloc(UT_CCSDS_MAX_WIRE_SIZE);
    if (!wire_buf) return;
    size_t wire_len = 0u;
    if (sign_and_pack_frame(tr, frame, wire_buf, UT_CCSDS_MAX_WIRE_SIZE, &wire_len) == UT_OK) {
        transmit_raw(tr, target_ip, target_port, wire_buf, wire_len);
    }
    free(wire_buf);
}

static void broadcast_ae_digest(ut_transport_t *tr) {
    ut_direct_peer_t peers[256];
    size_t peer_n = collect_target_peers(tr, peers, 256u);
    if (peer_n == 0u) return;

    char *summary_json = NULL;
    size_t summary_len = 0u;
    pthread_mutex_lock(&tr->lock);
    ut_status_t st = ut_swarm_state_compute_merkle(tr->state_store, tr->merkle_tree);
    if (st == UT_OK) {
        st = ut_merkle_tree_summary_json(tr->merkle_tree, &summary_json, &summary_len);
    }
    pthread_mutex_unlock(&tr->lock);

    if (st != UT_OK || !summary_json) {
        free(summary_json);
        return;
    }

    ut_ccsds_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.apid = UT_APID_AE_DIGEST;
    frame.seq = ut_micro_ledger_seq(tr->ledger);
    frame.swarm_hash = tr->swarm_hash;
    strcpy(frame.node_id, tr->node_id);
    frame.timestamp_ns = now_ns();
    ut_micro_ledger_last_digest(tr->ledger, frame.prev_hash);
    frame.lamport_time = ut_swarm_state_clock(tr->state_store);
    frame.topic = "__sys/ae_digest";
    frame.topic_len = strlen(frame.topic);
    frame.payload = (const uint8_t *)summary_json;
    frame.payload_len = summary_len;

    uint8_t *wire_buf = (uint8_t *)malloc(UT_CCSDS_MAX_WIRE_SIZE);
    if (wire_buf) {
        size_t wire_len = 0u;
        if (sign_and_pack_frame(tr, &frame, wire_buf, UT_CCSDS_MAX_WIRE_SIZE, &wire_len) == UT_OK) {
            for (size_t i = 0u; i < peer_n; ++i) {
                transmit_raw(tr, peers[i].ip, peers[i].port, wire_buf, wire_len);
            }
        }
        free(wire_buf);
    }
    free(summary_json);
}

static bool pattern_matches(const char *pattern, const char *topic) {
    if (strcmp(pattern, "*") == 0 || strcmp(pattern, topic) == 0) {
        return true;
    }
    size_t plen = strlen(pattern);
    if (plen > 0u && pattern[plen - 1u] == '*') {
        return strncmp(topic, pattern, plen - 1u) == 0;
    }
    return false;
}

static void dispatch_callbacks(
    ut_transport_t *tr,
    const char *topic,
    const uint8_t *val,
    size_t val_len,
    bool is_json,
    const char *sender_node_id
) {
    ut_sub_entry_t matched[64];
    size_t m_count = 0u;
    pthread_mutex_lock(&tr->lock);
    for (size_t i = 0u; i < tr->sub_count && m_count < 64u; ++i) {
        if (pattern_matches(tr->subs[i].pattern, topic)) {
            matched[m_count++] = tr->subs[i];
        }
    }
    pthread_mutex_unlock(&tr->lock);

    for (size_t i = 0u; i < m_count; ++i) {
        matched[i].cb(topic, val, val_len, is_json, sender_node_id, matched[i].ctx);
    }
}

static void handle_ae_digest(
    ut_transport_t *tr,
    const ut_ccsds_frame_t *frame,
    const char *sender_ip,
    uint16_t sender_port
) {
    if (!frame->payload || frame->payload_len == 0u) return;

    char remote_root_hex[UT_SHA256_SIZE * 2u + 1u] = {0};
    char local_root_hex[UT_SHA256_SIZE * 2u + 1u] = {0};
    char **div_keys = NULL;
    size_t div_count = 0u;

    pthread_mutex_lock(&tr->lock);
    ut_status_t st = ut_swarm_state_compute_merkle(tr->state_store, tr->merkle_tree);
    if (st == UT_OK) {
        ut_hex_encode(tr->merkle_tree->root, UT_SHA256_SIZE, local_root_hex, sizeof(local_root_hex));
        st = ut_merkle_tree_divergent_keys(
            tr->merkle_tree,
            (const char *)frame->payload,
            frame->payload_len,
            &div_keys,
            &div_count,
            remote_root_hex,
            sizeof(remote_root_hex)
        );
    }
    pthread_mutex_unlock(&tr->lock);

    if (st != UT_OK || strcmp(remote_root_hex, local_root_hex) == 0 || div_count == 0u) {
        ut_merkle_free_keys(div_keys, div_count);
        return;
    }

    /* Send local registers for divergent keys */
    char *records_json = NULL;
    size_t records_len = 0u;
    if (ut_swarm_state_export_registers_json(
            tr->state_store, (const char *const *)div_keys, div_count,
            &records_json, &records_len) == UT_OK && records_json && records_len > 2u) {
        ut_ccsds_frame_t resp;
        memset(&resp, 0, sizeof(resp));
        resp.apid = UT_APID_AE_RESPONSE;
        resp.swarm_hash = tr->swarm_hash;
        strcpy(resp.node_id, tr->node_id);
        resp.timestamp_ns = now_ns();
        resp.lamport_time = ut_swarm_state_clock(tr->state_store);
        resp.topic = "__sys/ae_response";
        resp.topic_len = strlen(resp.topic);
        resp.payload = (const uint8_t *)records_json;
        resp.payload_len = records_len;
        send_frame(tr, &resp, sender_ip, sender_port);
    }
    free(records_json);

    /* Request keys that exist in remote_leaves */
    yyjson_doc *rdoc = yyjson_read((const char *)frame->payload, frame->payload_len, 0);
    if (rdoc) {
        yyjson_val *r_leaves = yyjson_obj_get(yyjson_doc_get_root(rdoc), "leaves");
        if (yyjson_is_obj(r_leaves)) {
            yyjson_mut_doc *req_doc = yyjson_mut_doc_new(NULL);
            if (req_doc) {
                yyjson_mut_val *req_arr = yyjson_mut_arr(req_doc);
                yyjson_mut_doc_set_root(req_doc, req_arr);
                size_t missing_n = 0u;
                for (size_t i = 0u; i < div_count; ++i) {
                    if (yyjson_obj_get(r_leaves, div_keys[i]) != NULL) {
                        yyjson_mut_arr_add_strcpy(req_doc, req_arr, div_keys[i]);
                        missing_n += 1u;
                    }
                }
                if (missing_n > 0u) {
                    size_t req_len = 0u;
                    char *req_json = yyjson_mut_write(req_doc, 0, &req_len);
                    if (req_json) {
                        ut_ccsds_frame_t req;
                        memset(&req, 0, sizeof(req));
                        req.apid = UT_APID_AE_REQUEST;
                        req.swarm_hash = tr->swarm_hash;
                        strcpy(req.node_id, tr->node_id);
                        req.timestamp_ns = now_ns();
                        req.lamport_time = ut_swarm_state_clock(tr->state_store);
                        req.topic = "__sys/ae_request";
                        req.topic_len = strlen(req.topic);
                        req.payload = (const uint8_t *)req_json;
                        req.payload_len = req_len;
                        send_frame(tr, &req, sender_ip, sender_port);
                        free(req_json);
                    }
                }
                yyjson_mut_doc_free(req_doc);
            }
        }
        yyjson_doc_free(rdoc);
    }

    ut_merkle_free_keys(div_keys, div_count);
}

static void handle_ae_request(
    ut_transport_t *tr,
    const ut_ccsds_frame_t *frame,
    const char *sender_ip,
    uint16_t sender_port
) {
    if (!frame->payload || frame->payload_len == 0u) return;
    yyjson_doc *doc = yyjson_read((const char *)frame->payload, frame->payload_len, 0);
    if (!doc) return;
    yyjson_val *arr = yyjson_doc_get_root(doc);
    if (!yyjson_is_arr(arr)) {
        yyjson_doc_free(doc);
        return;
    }

    size_t n = yyjson_arr_size(arr);
    if (n > 0u) {
        const char **keys = (const char **)calloc(n, sizeof(const char *));
        if (keys) {
            size_t k_count = 0u;
            size_t idx = 0u, max = 0u;
            yyjson_val *el = NULL;
            yyjson_arr_foreach(arr, idx, max, el) {
                if (yyjson_is_str(el)) {
                    keys[k_count++] = yyjson_get_str(el);
                }
            }
            char *records_json = NULL;
            size_t records_len = 0u;
            if (k_count > 0u &&
                ut_swarm_state_export_registers_json(
                    tr->state_store, keys, k_count, &records_json, &records_len) == UT_OK &&
                records_json && records_len > 2u) {
                ut_ccsds_frame_t resp;
                memset(&resp, 0, sizeof(resp));
                resp.apid = UT_APID_AE_RESPONSE;
                resp.swarm_hash = tr->swarm_hash;
                strcpy(resp.node_id, tr->node_id);
                resp.timestamp_ns = now_ns();
                resp.lamport_time = ut_swarm_state_clock(tr->state_store);
                resp.topic = "__sys/ae_response";
                resp.topic_len = strlen(resp.topic);
                resp.payload = (const uint8_t *)records_json;
                resp.payload_len = records_len;
                send_frame(tr, &resp, sender_ip, sender_port);
            }
            free(records_json);
            free(keys);
        }
    }
    yyjson_doc_free(doc);
}

static void handle_ae_response(ut_transport_t *tr, const ut_ccsds_frame_t *frame) {
    if (!frame->payload || frame->payload_len == 0u) return;
    size_t updated = 0u;
    if (ut_swarm_state_merge_batch_json(
            tr->state_store, (const char *)frame->payload, frame->payload_len, &updated) == UT_OK &&
        updated > 0u) {
        pthread_mutex_lock(&tr->lock);
        ut_swarm_state_compute_merkle(tr->state_store, tr->merkle_tree);
        pthread_mutex_unlock(&tr->lock);
    }
}

static void *tx_worker(void *arg) {
    ut_transport_t *tr = (ut_transport_t *)arg;
    ut_pub_item_t batch[128];
    uint8_t *wire_buf = (uint8_t *)malloc(UT_CCSDS_MAX_WIRE_SIZE);
    if (!wire_buf) return NULL;

    while (atomic_load(&tr->running)) {
        size_t n = ut_ringbuf_pop_batch(tr->ring_buffer, batch, 128u);
        if (n == 0u) {
            struct timespec req = { .tv_sec = 0, .tv_nsec = 1000000L }; /* 1ms */
            nanosleep(&req, NULL);
            continue;
        }

        ut_direct_peer_t peers[256];
        size_t peer_n = collect_target_peers(tr, peers, 256u);

        for (size_t i = 0u; i < n; ++i) {
            ut_pub_item_t *it = &batch[i];
            if (peer_n > 0u) {
                const char *topic = it->heap_topic ? it->heap_topic : it->topic;
                const uint8_t *payload = it->heap_payload ? it->heap_payload : it->inline_payload;
                uint64_t ts_ns = now_ns();

                uint64_t seq = 0u;
                uint8_t prev_digest[UT_DIGEST_SIZE];
                if (ut_micro_ledger_append(tr->ledger, ts_ns, payload, it->payload_len,
                                           &seq, prev_digest, NULL) == UT_OK) {
                    ut_ccsds_frame_t frame;
                    memset(&frame, 0, sizeof(frame));
                    frame.apid = UT_APID_TELEMETRY;
                    frame.seq = seq;
                    frame.swarm_hash = tr->swarm_hash;
                    strcpy(frame.node_id, tr->node_id);
                    frame.timestamp_ns = ts_ns;
                    memcpy(frame.prev_hash, prev_digest, UT_DIGEST_SIZE);
                    frame.lamport_time = it->lamport_time;
                    frame.topic = topic;
                    frame.topic_len = strlen(topic);
                    frame.payload = payload;
                    frame.payload_len = it->payload_len;

                    size_t wire_len = 0u;
                    if (sign_and_pack_frame(tr, &frame, wire_buf, UT_CCSDS_MAX_WIRE_SIZE, &wire_len) == UT_OK) {
                        for (size_t p = 0u; p < peer_n; ++p) {
                            transmit_raw(tr, peers[p].ip, peers[p].port, wire_buf, wire_len);
                        }
                    }
                }
            }
            ut_pub_item_free(it);
        }
    }

    free(wire_buf);
    return NULL;
}

static bool lookup_peer_pubkey(ut_transport_t *tr, const char *node_id, uint8_t out_pk[UT_ED25519_PK_SIZE]) {
    bool found = false;
    pthread_mutex_lock(&tr->lock);
    for (size_t i = 0u; i < tr->trust_count; ++i) {
        if (strcmp(tr->trust_store[i].node_id, node_id) == 0) {
            memcpy(out_pk, tr->trust_store[i].pub_key, UT_ED25519_PK_SIZE);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&tr->lock);

    if (!found && !tr->require_pinned_keys && tr->discovery) {
        char hex[UT_ED25519_PK_SIZE * 2 + 1];
        if (ut_discovery_get_peer_key(tr->discovery, node_id, hex, sizeof(hex))) {
            if (ut_transport_register_peer_key(tr, node_id, hex) == UT_OK) {
                size_t decoded_len = 0u;
                if (ut_hex_decode(hex, strlen(hex), out_pk, UT_ED25519_PK_SIZE, &decoded_len) == UT_OK &&
                    decoded_len == UT_ED25519_PK_SIZE) {
                    found = true;
                }
            }
        }
    }
    return found;
}

static void *rx_worker(void *arg) {
    ut_transport_t *tr = (ut_transport_t *)arg;
    uint8_t *raw = (uint8_t *)malloc(UT_CCSDS_MAX_WIRE_SIZE);
    uint8_t *sign_buf = (uint8_t *)malloc(UT_CCSDS_MAX_WIRE_SIZE);
    if (!raw || !sign_buf) {
        free(raw);
        free(sign_buf);
        return NULL;
    }

    while (atomic_load(&tr->running)) {
        struct pollfd pfd = { .fd = tr->sock_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);
        ssize_t n = recvfrom(tr->sock_fd, raw, UT_CCSDS_MAX_WIRE_SIZE, 0,
                             (struct sockaddr *)&sender, &slen);
        if (n <= 0) {
            continue;
        }

        ut_ccsds_frame_t frame;
        if (ut_ccsds_unpack(raw, (size_t)n, &frame) != UT_OK) {
            continue;
        }
        if (strcmp(frame.node_id, tr->node_id) == 0) {
            continue;
        }
        if (frame.swarm_hash != tr->swarm_hash) {
            continue;
        }

        if (tr->enable_crypto) {
            uint8_t peer_pk[UT_ED25519_PK_SIZE];
            if (!lookup_peer_pubkey(tr, frame.node_id, peer_pk)) {
                continue;
            }
            size_t sign_len = 0u;
            if (ut_ccsds_signable_bytes(&frame, sign_buf, UT_CCSDS_MAX_WIRE_SIZE, &sign_len) != UT_OK ||
                ut_ed25519_verify(peer_pk, sign_buf, sign_len, frame.signature) != UT_OK) {
                continue;
            }
        }

        char sender_ip[64] = {0};
        inet_ntop(AF_INET, &sender.sin_addr, sender_ip, sizeof(sender_ip));
        uint16_t sender_port = ntohs(sender.sin_port);

        if (frame.apid == UT_APID_TELEMETRY) {
            uint8_t frame_digest[UT_DIGEST_SIZE];
            if (ut_compute_digest(frame.prev_hash, frame.seq, frame.timestamp_ns,
                                  frame.payload, frame.payload_len, frame_digest) != UT_OK) {
                continue;
            }
            ut_ledger_result_t lres = ut_peer_ledger_record_incoming(
                &tr->peer_tracker,
                frame.node_id,
                frame.seq,
                frame.timestamp_ns,
                frame.prev_hash,
                frame_digest,
                frame.payload,
                frame.payload_len,
                NULL
            );
            if (lres < 0) {
                continue;
            }

            char *topic_cstr = (char *)malloc(frame.topic_len + 1u);
            if (!topic_cstr) continue;
            memcpy(topic_cstr, frame.topic, frame.topic_len);
            topic_cstr[frame.topic_len] = '\0';

            bool is_json = false;
            if (frame.payload && frame.payload_len > 0u) {
                yyjson_doc *jdoc = yyjson_read((const char *)frame.payload, frame.payload_len, 0);
                if (jdoc) {
                    is_json = true;
                    yyjson_doc_free(jdoc);
                }
            }

            double w_ts = (double)frame.timestamp_ns / 1e9;
            ut_swarm_state_merge_remote(
                tr->state_store,
                frame.node_id,
                topic_cstr,
                frame.payload,
                frame.payload_len,
                is_json,
                frame.lamport_time,
                w_ts,
                NULL
            );

            dispatch_callbacks(tr, topic_cstr, frame.payload, frame.payload_len, is_json, frame.node_id);
            free(topic_cstr);
        } else if (frame.apid == UT_APID_AE_DIGEST) {
            handle_ae_digest(tr, &frame, sender_ip, sender_port);
        } else if (frame.apid == UT_APID_AE_REQUEST) {
            handle_ae_request(tr, &frame, sender_ip, sender_port);
        } else if (frame.apid == UT_APID_AE_RESPONSE) {
            handle_ae_response(tr, &frame);
        }
    }

    free(raw);
    free(sign_buf);
    return NULL;
}

static void *ae_worker(void *arg) {
    ut_transport_t *tr = (ut_transport_t *)arg;
    while (atomic_load(&tr->running)) {
        double deadline = mono_sec() + tr->anti_entropy_interval_s;
        while (atomic_load(&tr->running) && mono_sec() < deadline) {
            struct timespec req = { .tv_sec = 0, .tv_nsec = 50000000L }; /* 50ms */
            nanosleep(&req, NULL);
        }
        if (!atomic_load(&tr->running)) break;
        broadcast_ae_digest(tr);
    }
    return NULL;
}

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
) {
    if (!tr || !node_id || !swarm_id || !ring_buffer || !state_store || !ledger || !merkle_tree) {
        return UT_ERR_INVALID_ARG;
    }
    memset(tr, 0, sizeof(*tr));
    size_t nid_len = strnlen(node_id, UT_NODE_ID_MAX);
    memcpy(tr->node_id, node_id, nid_len);
    snprintf(tr->swarm_id, sizeof(tr->swarm_id), "%s", swarm_id);
    tr->swarm_hash = ut_ccsds_swarm_hash(swarm_id, strlen(swarm_id));
    tr->port = port;
    tr->enable_crypto = enable_crypto;
    tr->ring_buffer = ring_buffer;
    tr->state_store = state_store;
    tr->ledger = ledger;
    tr->discovery = discovery;
    tr->merkle_tree = merkle_tree;
    tr->enable_anti_entropy = enable_anti_entropy;
    tr->anti_entropy_interval_s = (anti_entropy_interval_s > 0.0) ? anti_entropy_interval_s : 0.5;
    tr->sock_fd = -1;
    atomic_init(&tr->running, false);

    ut_ringbuf_set_overflow_handler(ring_buffer, ring_overflow_cleanup, NULL);

    if (enable_crypto) {
        ut_status_t st;
        if (private_seed) {
            memcpy(tr->private_seed, private_seed, UT_ED25519_SEED_SIZE);
            st = ut_ed25519_pk_from_seed(tr->private_seed, tr->public_key);
        } else {
            st = ut_ed25519_keygen(tr->private_seed, tr->public_key);
        }
        if (st != UT_OK) return st;
    }

    if (ut_peer_ledger_tracker_init(&tr->peer_tracker) != UT_OK) {
        return UT_ERR_IO;
    }
    if (pthread_mutex_init(&tr->lock, NULL) != 0) {
        ut_peer_ledger_tracker_destroy(&tr->peer_tracker);
        return UT_ERR_IO;
    }
    return UT_OK;
}

void ut_transport_destroy(ut_transport_t *tr) {
    if (!tr) return;
    ut_transport_stop(tr);

    ut_pub_item_t item;
    while (ut_ringbuf_pop(tr->ring_buffer, &item) == UT_OK) {
        ut_pub_item_free(&item);
    }

    free(tr->trust_store);
    free(tr->direct_peers);
    for (size_t i = 0u; i < tr->sub_count; ++i) {
        free(tr->subs[i].pattern);
    }
    free(tr->subs);
    free(tr->taps);
    ut_peer_ledger_tracker_destroy(&tr->peer_tracker);
    pthread_mutex_destroy(&tr->lock);
}

ut_status_t ut_transport_start(ut_transport_t *tr) {
    if (!tr) return UT_ERR_INVALID_ARG;
    if (atomic_load(&tr->running)) return UT_OK;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return UT_ERR_IO;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int buf_sz = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(tr->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return UT_ERR_IO;
    }

    if (tr->port == 0u) {
        socklen_t len = sizeof(addr);
        if (getsockname(sock, (struct sockaddr *)&addr, &len) == 0) {
            tr->port = ntohs(addr.sin_port);
            if (tr->discovery) {
                tr->discovery->data_port = tr->port;
            }
        }
    }

    tr->sock_fd = sock;
    atomic_store(&tr->running, true);

    if (pthread_create(&tr->tx_thread, NULL, tx_worker, tr) != 0) {
        atomic_store(&tr->running, false);
        close(sock);
        tr->sock_fd = -1;
        return UT_ERR_IO;
    }
    if (pthread_create(&tr->rx_thread, NULL, rx_worker, tr) != 0) {
        atomic_store(&tr->running, false);
        pthread_join(tr->tx_thread, NULL);
        close(sock);
        tr->sock_fd = -1;
        return UT_ERR_IO;
    }
    if (tr->enable_anti_entropy) {
        if (pthread_create(&tr->ae_thread, NULL, ae_worker, tr) != 0) {
            atomic_store(&tr->running, false);
            pthread_join(tr->tx_thread, NULL);
            pthread_join(tr->rx_thread, NULL);
            close(sock);
            tr->sock_fd = -1;
            return UT_ERR_IO;
        }
    }
    tr->threads_started = true;
    return UT_OK;
}

void ut_transport_stop(ut_transport_t *tr) {
    if (!tr) return;
    if (!atomic_exchange(&tr->running, false)) {
        if (tr->sock_fd >= 0) {
            close(tr->sock_fd);
            tr->sock_fd = -1;
        }
        return;
    }
    if (tr->threads_started) {
        pthread_join(tr->tx_thread, NULL);
        pthread_join(tr->rx_thread, NULL);
        if (tr->enable_anti_entropy) {
            pthread_join(tr->ae_thread, NULL);
        }
        tr->threads_started = false;
    }
    if (tr->sock_fd >= 0) {
        close(tr->sock_fd);
        tr->sock_fd = -1;
    }
}

ut_status_t ut_transport_register_peer_key(
    ut_transport_t *tr,
    const char *peer_id,
    const char *pub_key_hex
) {
    if (!tr || !peer_id || !pub_key_hex) return UT_ERR_INVALID_ARG;
    uint8_t pk[UT_ED25519_PK_SIZE];
    size_t out_len = 0u;
    ut_status_t st = ut_hex_decode(pub_key_hex, strlen(pub_key_hex), pk, sizeof(pk), &out_len);
    if (st != UT_OK || out_len != UT_ED25519_PK_SIZE) {
        return UT_ERR_MALFORMED;
    }

    pthread_mutex_lock(&tr->lock);
    for (size_t i = 0u; i < tr->trust_count; ++i) {
        if (strncmp(tr->trust_store[i].node_id, peer_id, UT_NODE_ID_MAX) == 0) {
            memcpy(tr->trust_store[i].pub_key, pk, UT_ED25519_PK_SIZE);
            pthread_mutex_unlock(&tr->lock);
            return UT_OK;
        }
    }
    if (tr->trust_count == tr->trust_cap) {
        size_t new_cap = (tr->trust_cap == 0u) ? 16u : tr->trust_cap * 2u;
        ut_trust_entry_t *grown = (ut_trust_entry_t *)realloc(
            tr->trust_store, new_cap * sizeof(ut_trust_entry_t));
        if (!grown) {
            pthread_mutex_unlock(&tr->lock);
            return UT_ERR_NO_MEMORY;
        }
        tr->trust_store = grown;
        tr->trust_cap = new_cap;
    }
    ut_trust_entry_t *e = &tr->trust_store[tr->trust_count++];
    memset(e, 0, sizeof(*e));
    size_t len = strnlen(peer_id, UT_NODE_ID_MAX);
    memcpy(e->node_id, peer_id, len);
    memcpy(e->pub_key, pk, UT_ED25519_PK_SIZE);
    pthread_mutex_unlock(&tr->lock);
    return UT_OK;
}

ut_status_t ut_transport_add_direct_peer(
    ut_transport_t *tr,
    const char *peer_id,
    const char *ip,
    uint16_t port,
    const char *pub_key_hex
) {
    if (!tr || !peer_id || !ip || port == 0u) return UT_ERR_INVALID_ARG;
    pthread_mutex_lock(&tr->lock);
    ut_direct_peer_t *slot = NULL;
    for (size_t i = 0u; i < tr->direct_count; ++i) {
        if (strncmp(tr->direct_peers[i].node_id, peer_id, UT_NODE_ID_MAX) == 0) {
            slot = &tr->direct_peers[i];
            break;
        }
    }
    if (!slot) {
        if (tr->direct_count == tr->direct_cap) {
            size_t new_cap = (tr->direct_cap == 0u) ? 16u : tr->direct_cap * 2u;
            ut_direct_peer_t *grown = (ut_direct_peer_t *)realloc(
                tr->direct_peers, new_cap * sizeof(ut_direct_peer_t));
            if (!grown) {
                pthread_mutex_unlock(&tr->lock);
                return UT_ERR_NO_MEMORY;
            }
            tr->direct_peers = grown;
            tr->direct_cap = new_cap;
        }
        slot = &tr->direct_peers[tr->direct_count++];
        memset(slot, 0, sizeof(*slot));
        size_t len = strnlen(peer_id, UT_NODE_ID_MAX);
        memcpy(slot->node_id, peer_id, len);
    }
    snprintf(slot->ip, sizeof(slot->ip), "%s", ip);
    slot->port = port;
    pthread_mutex_unlock(&tr->lock);

    if (pub_key_hex && pub_key_hex[0] != '\0') {
        return ut_transport_register_peer_key(tr, peer_id, pub_key_hex);
    }
    return UT_OK;
}

ut_status_t ut_transport_subscribe(
    ut_transport_t *tr,
    const char *topic_pattern,
    ut_topic_callback_fn cb,
    void *user_ctx
) {
    if (!tr || !topic_pattern || !cb) return UT_ERR_INVALID_ARG;
    char *pat_copy = ut_cstrdup(topic_pattern);
    if (!pat_copy) return UT_ERR_NO_MEMORY;

    pthread_mutex_lock(&tr->lock);
    if (tr->sub_count == tr->sub_cap) {
        size_t new_cap = (tr->sub_cap == 0u) ? 16u : tr->sub_cap * 2u;
        ut_sub_entry_t *grown = (ut_sub_entry_t *)realloc(
            tr->subs, new_cap * sizeof(ut_sub_entry_t));
        if (!grown) {
            pthread_mutex_unlock(&tr->lock);
            free(pat_copy);
            return UT_ERR_NO_MEMORY;
        }
        tr->subs = grown;
        tr->sub_cap = new_cap;
    }
    tr->subs[tr->sub_count].pattern = pat_copy;
    tr->subs[tr->sub_count].cb = cb;
    tr->subs[tr->sub_count].ctx = user_ctx;
    tr->sub_count += 1u;
    pthread_mutex_unlock(&tr->lock);
    return UT_OK;
}

ut_status_t ut_transport_add_packet_tap(
    ut_transport_t *tr,
    ut_packet_tap_fn cb,
    void *user_ctx
) {
    if (!tr || !cb) return UT_ERR_INVALID_ARG;
    pthread_mutex_lock(&tr->lock);
    if (tr->tap_count == tr->tap_cap) {
        size_t new_cap = (tr->tap_cap == 0u) ? 8u : tr->tap_cap * 2u;
        ut_tap_entry_t *grown = (ut_tap_entry_t *)realloc(
            tr->taps, new_cap * sizeof(ut_tap_entry_t));
        if (!grown) {
            pthread_mutex_unlock(&tr->lock);
            return UT_ERR_NO_MEMORY;
        }
        tr->taps = grown;
        tr->tap_cap = new_cap;
    }
    tr->taps[tr->tap_count].cb = cb;
    tr->taps[tr->tap_count].ctx = user_ctx;
    tr->tap_count += 1u;
    pthread_mutex_unlock(&tr->lock);
    return UT_OK;
}

void ut_transport_trigger_repair(ut_transport_t *tr) {
    if (!tr) return;
    broadcast_ae_digest(tr);
}
