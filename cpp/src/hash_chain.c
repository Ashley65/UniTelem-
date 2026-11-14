#include "unitelem/hash_chain.h"
#include "unitelem/crypto.h"

#include <stdlib.h>
#include <string.h>

static inline void write_u64_be(uint8_t *dst, uint64_t v) {
    dst[0] = (uint8_t)((v >> 56) & 0xFFu);
    dst[1] = (uint8_t)((v >> 48) & 0xFFu);
    dst[2] = (uint8_t)((v >> 40) & 0xFFu);
    dst[3] = (uint8_t)((v >> 32) & 0xFFu);
    dst[4] = (uint8_t)((v >> 24) & 0xFFu);
    dst[5] = (uint8_t)((v >> 16) & 0xFFu);
    dst[6] = (uint8_t)((v >> 8) & 0xFFu);
    dst[7] = (uint8_t)(v & 0xFFu);
}

ut_status_t ut_compute_digest(
    const uint8_t prev_digest[UT_DIGEST_SIZE],
    uint64_t seq,
    uint64_t timestamp_ns,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t out_digest[UT_DIGEST_SIZE]
) {
    if (!prev_digest || !out_digest || (!payload && payload_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }

    ut_blake2s_ctx_t ctx;
    ut_status_t st = ut_blake2s_init(&ctx, UT_DIGEST_SIZE);
    if (st != UT_OK) {
        return st;
    }

    uint8_t header[UT_DIGEST_SIZE + 16u];
    memcpy(header, prev_digest, UT_DIGEST_SIZE);
    write_u64_be(header + UT_DIGEST_SIZE, seq);
    write_u64_be(header + UT_DIGEST_SIZE + 8u, timestamp_ns);

    st = ut_blake2s_update(&ctx, header, sizeof(header));
    if (st != UT_OK) {
        return st;
    }
    if (payload_len > 0u) {
        st = ut_blake2s_update(&ctx, payload, payload_len);
        if (st != UT_OK) {
            return st;
        }
    }
    return ut_blake2s_final(&ctx, out_digest);
}

ut_status_t ut_micro_ledger_init(ut_micro_ledger_t *ledger, const char *node_id, size_t max_history) {
    if (!ledger || !node_id) {
        return UT_ERR_INVALID_ARG;
    }
    memset(ledger, 0, sizeof(*ledger));
    size_t id_len = strnlen(node_id, UT_NODE_ID_MAX);
    memcpy(ledger->node_id, node_id, id_len);
    ledger->node_id[id_len] = '\0';
    ledger->max_history = max_history;

    if (max_history > 0u) {
        ledger->ring = (ut_ledger_entry_t *)calloc(max_history, sizeof(ut_ledger_entry_t));
        if (!ledger->ring) {
            return UT_ERR_NO_MEMORY;
        }
    }
    if (pthread_mutex_init(&ledger->lock, NULL) != 0) {
        free(ledger->ring);
        ledger->ring = NULL;
        return UT_ERR_IO;
    }
    return UT_OK;
}

void ut_micro_ledger_destroy(ut_micro_ledger_t *ledger) {
    if (!ledger) {
        return;
    }
    if (ledger->ring) {
        for (size_t i = 0; i < ledger->count; ++i) {
            size_t idx = (ledger->head + i) % ledger->max_history;
            free(ledger->ring[idx].payload);
            ledger->ring[idx].payload = NULL;
        }
        free(ledger->ring);
        ledger->ring = NULL;
    }
    pthread_mutex_destroy(&ledger->lock);
}

ut_status_t ut_micro_ledger_append(
    ut_micro_ledger_t *ledger,
    uint64_t timestamp_ns,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t *out_seq,
    uint8_t out_prev_digest[UT_DIGEST_SIZE],
    uint8_t out_digest[UT_DIGEST_SIZE]
) {
    if (!ledger || (!payload && payload_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }

    pthread_mutex_lock(&ledger->lock);

    uint64_t next_seq = ledger->seq + 1u;
    uint8_t prev[UT_DIGEST_SIZE];
    memcpy(prev, ledger->last_digest, UT_DIGEST_SIZE);

    uint8_t digest[UT_DIGEST_SIZE];
    ut_status_t st = ut_compute_digest(prev, next_seq, timestamp_ns, payload, payload_len, digest);
    if (st != UT_OK) {
        pthread_mutex_unlock(&ledger->lock);
        return st;
    }

    if (ledger->max_history > 0u && ledger->ring) {
        uint8_t *copy = NULL;
        if (payload_len > 0u) {
            copy = (uint8_t *)malloc(payload_len);
            if (!copy) {
                pthread_mutex_unlock(&ledger->lock);
                return UT_ERR_NO_MEMORY;
            }
            memcpy(copy, payload, payload_len);
        }

        size_t slot;
        if (ledger->count == ledger->max_history) {
            slot = ledger->head;
            free(ledger->ring[slot].payload);
            ledger->ring[slot].payload = NULL;
            ledger->head = (ledger->head + 1u) % ledger->max_history;
        } else {
            slot = (ledger->head + ledger->count) % ledger->max_history;
            ledger->count += 1u;
        }

        ledger->ring[slot].seq = next_seq;
        ledger->ring[slot].timestamp_ns = timestamp_ns;
        memcpy(ledger->ring[slot].prev_digest, prev, UT_DIGEST_SIZE);
        memcpy(ledger->ring[slot].digest, digest, UT_DIGEST_SIZE);
        ledger->ring[slot].payload = copy;
        ledger->ring[slot].payload_len = payload_len;
    }

    ledger->seq = next_seq;
    memcpy(ledger->last_digest, digest, UT_DIGEST_SIZE);

    if (out_seq) {
        *out_seq = next_seq;
    }
    if (out_prev_digest) {
        memcpy(out_prev_digest, prev, UT_DIGEST_SIZE);
    }
    if (out_digest) {
        memcpy(out_digest, digest, UT_DIGEST_SIZE);
    }

    pthread_mutex_unlock(&ledger->lock);
    return UT_OK;
}

uint64_t ut_micro_ledger_seq(ut_micro_ledger_t *ledger) {
    if (!ledger) {
        return 0u;
    }
    pthread_mutex_lock(&ledger->lock);
    uint64_t s = ledger->seq;
    pthread_mutex_unlock(&ledger->lock);
    return s;
}

void ut_micro_ledger_last_digest(ut_micro_ledger_t *ledger, uint8_t out_digest[UT_DIGEST_SIZE]) {
    if (!ledger || !out_digest) {
        return;
    }
    pthread_mutex_lock(&ledger->lock);
    memcpy(out_digest, ledger->last_digest, UT_DIGEST_SIZE);
    pthread_mutex_unlock(&ledger->lock);
}

bool ut_micro_ledger_verify_local(ut_micro_ledger_t *ledger) {
    if (!ledger) {
        return false;
    }
    pthread_mutex_lock(&ledger->lock);
    if (ledger->count == 0u || !ledger->ring) {
        pthread_mutex_unlock(&ledger->lock);
        return true;
    }

    const ut_ledger_entry_t *first = &ledger->ring[ledger->head];
    static const uint8_t genesis[UT_DIGEST_SIZE] = {0};
    if (first->seq == 1u && memcmp(first->prev_digest, genesis, UT_DIGEST_SIZE) != 0) {
        pthread_mutex_unlock(&ledger->lock);
        return false;
    }

    uint8_t current_prev[UT_DIGEST_SIZE];
    memcpy(current_prev, first->prev_digest, UT_DIGEST_SIZE);
    uint64_t expected_seq = first->seq;

    for (size_t i = 0; i < ledger->count; ++i) {
        size_t idx = (ledger->head + i) % ledger->max_history;
        const ut_ledger_entry_t *e = &ledger->ring[idx];
        if (e->seq != expected_seq || memcmp(e->prev_digest, current_prev, UT_DIGEST_SIZE) != 0) {
            pthread_mutex_unlock(&ledger->lock);
            return false;
        }
        uint8_t expected[UT_DIGEST_SIZE];
        if (ut_compute_digest(e->prev_digest, e->seq, e->timestamp_ns,
                              e->payload, e->payload_len, expected) != UT_OK ||
            memcmp(e->digest, expected, UT_DIGEST_SIZE) != 0) {
            pthread_mutex_unlock(&ledger->lock);
            return false;
        }
        memcpy(current_prev, e->digest, UT_DIGEST_SIZE);
        expected_seq += 1u;
    }

    pthread_mutex_unlock(&ledger->lock);
    return true;
}

ut_status_t ut_peer_ledger_tracker_init(ut_peer_ledger_tracker_t *tracker) {
    if (!tracker) {
        return UT_ERR_INVALID_ARG;
    }
    memset(tracker, 0, sizeof(*tracker));
    if (pthread_mutex_init(&tracker->lock, NULL) != 0) {
        return UT_ERR_IO;
    }
    return UT_OK;
}

void ut_peer_ledger_tracker_destroy(ut_peer_ledger_tracker_t *tracker) {
    if (!tracker) {
        return;
    }
    free(tracker->peers);
    tracker->peers = NULL;
    tracker->count = 0u;
    tracker->capacity = 0u;
    pthread_mutex_destroy(&tracker->lock);
}

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
) {
    if (out_gap_count) {
        *out_gap_count = 0u;
    }
    if (!tracker || !peer_id || !prev_digest || !digest) {
        return UT_LEDGER_CORRUPTED_DIGEST;
    }

    uint8_t expected_digest[UT_DIGEST_SIZE];
    if (ut_compute_digest(prev_digest, seq, timestamp_ns, payload, payload_len, expected_digest) != UT_OK ||
        memcmp(digest, expected_digest, UT_DIGEST_SIZE) != 0) {
        return UT_LEDGER_CORRUPTED_DIGEST;
    }

    pthread_mutex_lock(&tracker->lock);
    ut_peer_ledger_state_t *found = NULL;
    for (size_t i = 0; i < tracker->count; ++i) {
        if (strncmp(tracker->peers[i].peer_id, peer_id, UT_NODE_ID_MAX) == 0) {
            found = &tracker->peers[i];
            break;
        }
    }

    if (!found) {
        if (tracker->count == tracker->capacity) {
            size_t new_cap = (tracker->capacity == 0u) ? 16u : tracker->capacity * 2u;
            ut_peer_ledger_state_t *grown = (ut_peer_ledger_state_t *)realloc(
                tracker->peers, new_cap * sizeof(ut_peer_ledger_state_t));
            if (!grown) {
                pthread_mutex_unlock(&tracker->lock);
                return UT_LEDGER_CORRUPTED_DIGEST;
            }
            tracker->peers = grown;
            tracker->capacity = new_cap;
        }
        ut_peer_ledger_state_t *st = &tracker->peers[tracker->count++];
        memset(st, 0, sizeof(*st));
        size_t len = strnlen(peer_id, UT_NODE_ID_MAX);
        memcpy(st->peer_id, peer_id, len);
        st->peer_id[len] = '\0';
        st->last_seq = seq;
        memcpy(st->last_digest, digest, UT_DIGEST_SIZE);
        pthread_mutex_unlock(&tracker->lock);
        return UT_LEDGER_OK;
    }

    if (seq <= found->last_seq) {
        pthread_mutex_unlock(&tracker->lock);
        return UT_LEDGER_OUT_OF_ORDER;
    }

    if (seq == found->last_seq + 1u) {
        if (memcmp(prev_digest, found->last_digest, UT_DIGEST_SIZE) != 0) {
            pthread_mutex_unlock(&tracker->lock);
            return UT_LEDGER_FORK_OR_TAMPER;
        }
        found->last_seq = seq;
        memcpy(found->last_digest, digest, UT_DIGEST_SIZE);
        pthread_mutex_unlock(&tracker->lock);
        return UT_LEDGER_OK;
    }

    if (out_gap_count) {
        *out_gap_count = seq - found->last_seq - 1u;
    }
    found->last_seq = seq;
    memcpy(found->last_digest, digest, UT_DIGEST_SIZE);
    pthread_mutex_unlock(&tracker->lock);
    return UT_LEDGER_GAP;
}
