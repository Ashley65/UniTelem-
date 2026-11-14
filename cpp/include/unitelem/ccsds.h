#ifndef UNITELEM_CCSDS_H
#define UNITELEM_CCSDS_H

#include "unitelem/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ut_ccsds_frame {
    uint16_t apid;
    uint64_t seq;
    uint16_t swarm_hash;
    char node_id[UT_NODE_ID_MAX + 1];
    uint64_t timestamp_ns;
    uint8_t prev_hash[UT_DIGEST_SIZE];
    uint8_t signature[UT_ED25519_SIG_SIZE];
    uint64_t lamport_time;
    const char *topic;
    size_t topic_len;
    const uint8_t *payload;
    size_t payload_len;
} ut_ccsds_frame_t;

uint16_t ut_ccsds_swarm_hash(const char *swarm_id, size_t swarm_id_len);

ut_status_t ut_ccsds_signable_bytes(
    const ut_ccsds_frame_t *frame,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len
);

ut_status_t ut_ccsds_pack(
    const ut_ccsds_frame_t *frame,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len
);

/**
 * Unpacks raw_bytes into out_frame.
 * Note: out_frame->topic and out_frame->payload point directly into raw_bytes
 * for zero-copy decoding; caller must keep raw_bytes valid while reading them.
 */
ut_status_t ut_ccsds_unpack(
    const uint8_t *raw_bytes,
    size_t raw_len,
    ut_ccsds_frame_t *out_frame
);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_CCSDS_H */
