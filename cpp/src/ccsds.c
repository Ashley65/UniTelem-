#include "unitelem/ccsds.h"
#include "unitelem/crc16.h"

#include <string.h>

static inline void write_u16_be(uint8_t *dst, uint16_t v) {
    dst[0] = (uint8_t)((v >> 8) & 0xFFu);
    dst[1] = (uint8_t)(v & 0xFFu);
}

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

static inline uint16_t read_u16_be(const uint8_t *src) {
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static inline uint64_t read_u64_be(const uint8_t *src) {
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  |
           ((uint64_t)src[7]);
}

static void encode_node_id_16b(const char *node_id, uint8_t out16[UT_NODE_ID_MAX]) {
    memset(out16, 0, UT_NODE_ID_MAX);
    if (!node_id) {
        return;
    }
    size_t len = strnlen(node_id, UT_NODE_ID_MAX);
    memcpy(out16, node_id, len);
}

uint16_t ut_ccsds_swarm_hash(const char *swarm_id, size_t swarm_id_len) {
    if (!swarm_id && swarm_id_len > 0) {
        return 0xFFFFu;
    }
    return ut_crc16_compute((const uint8_t *)swarm_id, swarm_id_len);
}

ut_status_t ut_ccsds_signable_bytes(
    const ut_ccsds_frame_t *frame,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len
) {
    if (!frame || !out_buf) {
        return UT_ERR_INVALID_ARG;
    }
    if (frame->topic_len > 0xFFFFu || (!frame->topic && frame->topic_len > 0) ||
        (!frame->payload && frame->payload_len > 0)) {
        return UT_ERR_INVALID_ARG;
    }

    size_t needed = 2u + 8u + 2u + UT_NODE_ID_MAX + 8u + UT_DIGEST_SIZE + 8u + 2u +
                    frame->topic_len + frame->payload_len;
    if (out_cap < needed) {
        if (out_len) {
            *out_len = needed;
        }
        return UT_ERR_BUFFER_TOO_SMALL;
    }

    size_t off = 0u;
    write_u16_be(out_buf + off, frame->apid);
    off += 2u;
    write_u64_be(out_buf + off, frame->seq);
    off += 8u;
    write_u16_be(out_buf + off, frame->swarm_hash);
    off += 2u;
    encode_node_id_16b(frame->node_id, out_buf + off);
    off += UT_NODE_ID_MAX;
    write_u64_be(out_buf + off, frame->timestamp_ns);
    off += 8u;
    memcpy(out_buf + off, frame->prev_hash, UT_DIGEST_SIZE);
    off += UT_DIGEST_SIZE;
    write_u64_be(out_buf + off, frame->lamport_time);
    off += 8u;
    write_u16_be(out_buf + off, (uint16_t)frame->topic_len);
    off += 2u;
    if (frame->topic_len > 0u) {
        memcpy(out_buf + off, frame->topic, frame->topic_len);
        off += frame->topic_len;
    }
    if (frame->payload_len > 0u) {
        memcpy(out_buf + off, frame->payload, frame->payload_len);
        off += frame->payload_len;
    }

    if (out_len) {
        *out_len = off;
    }
    return UT_OK;
}

ut_status_t ut_ccsds_pack(
    const ut_ccsds_frame_t *frame,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len
) {
    if (!frame || !out_buf) {
        return UT_ERR_INVALID_ARG;
    }
    if (frame->topic_len > 0xFFFFu || (!frame->topic && frame->topic_len > 0) ||
        (!frame->payload && frame->payload_len > 0)) {
        return UT_ERR_INVALID_ARG;
    }

    size_t sec_hdr_len = 2u + UT_NODE_ID_MAX + 8u + UT_DIGEST_SIZE + UT_ED25519_SIG_SIZE +
                         8u + 8u + 2u + frame->topic_len;
    size_t packet_data_len = sec_hdr_len + frame->payload_len;
    if (packet_data_len == 0u || packet_data_len > UT_CCSDS_MAX_PACKET_DATA) {
        return UT_ERR_INVALID_ARG;
    }

    size_t total_len = 6u + packet_data_len + 2u;
    if (out_cap < total_len) {
        if (out_len) {
            *out_len = total_len;
        }
        return UT_ERR_BUFFER_TOO_SMALL;
    }

    uint16_t w1 = (uint16_t)(((UT_CCSDS_VERSION & 0x07u) << 13) |
                             ((UT_CCSDS_TYPE_TELEMETRY & 0x01u) << 12) |
                             ((UT_CCSDS_SEC_HDR_PRESENT & 0x01u) << 11) |
                             (frame->apid & 0x07FFu));
    uint16_t w2 = (uint16_t)(((UT_CCSDS_SEQ_UNSEGMENTED & 0x03u) << 14) |
                             ((uint16_t)(frame->seq & 0x3FFFu)));
    uint16_t w3 = (uint16_t)(packet_data_len - 1u);

    size_t off = 0u;
    write_u16_be(out_buf + off, w1);
    off += 2u;
    write_u16_be(out_buf + off, w2);
    off += 2u;
    write_u16_be(out_buf + off, w3);
    off += 2u;

    write_u16_be(out_buf + off, frame->swarm_hash);
    off += 2u;
    encode_node_id_16b(frame->node_id, out_buf + off);
    off += UT_NODE_ID_MAX;
    write_u64_be(out_buf + off, frame->timestamp_ns);
    off += 8u;
    memcpy(out_buf + off, frame->prev_hash, UT_DIGEST_SIZE);
    off += UT_DIGEST_SIZE;
    memcpy(out_buf + off, frame->signature, UT_ED25519_SIG_SIZE);
    off += UT_ED25519_SIG_SIZE;
    write_u64_be(out_buf + off, frame->lamport_time);
    off += 8u;
    write_u64_be(out_buf + off, frame->seq);
    off += 8u;
    write_u16_be(out_buf + off, (uint16_t)frame->topic_len);
    off += 2u;

    if (frame->topic_len > 0u) {
        memcpy(out_buf + off, frame->topic, frame->topic_len);
        off += frame->topic_len;
    }
    if (frame->payload_len > 0u) {
        memcpy(out_buf + off, frame->payload, frame->payload_len);
        off += frame->payload_len;
    }

    return ut_crc16_append(out_buf, off, out_cap, out_len);
}

ut_status_t ut_ccsds_unpack(
    const uint8_t *raw_bytes,
    size_t raw_len,
    ut_ccsds_frame_t *out_frame
) {
    if (!raw_bytes || !out_frame) {
        return UT_ERR_INVALID_ARG;
    }
    if (raw_len < UT_CCSDS_MIN_FRAME_SIZE) {
        return UT_ERR_MALFORMED;
    }
    if (!ut_crc16_verify(raw_bytes, raw_len)) {
        return UT_ERR_BAD_CRC;
    }

    size_t data_len = raw_len - 2u;
    uint16_t w1 = read_u16_be(raw_bytes + 0u);
    uint16_t w2 = read_u16_be(raw_bytes + 2u);
    uint16_t w3 = read_u16_be(raw_bytes + 4u);

    if ((size_t)w3 + 1u != data_len - 6u) {
        return UT_ERR_MALFORMED;
    }

    uint16_t version = (uint16_t)((w1 >> 13) & 0x07u);
    uint16_t type = (uint16_t)((w1 >> 12) & 0x01u);
    uint16_t sec_hdr = (uint16_t)((w1 >> 11) & 0x01u);
    if (version != UT_CCSDS_VERSION || type != UT_CCSDS_TYPE_TELEMETRY || sec_hdr != UT_CCSDS_SEC_HDR_PRESENT) {
        return UT_ERR_MALFORMED;
    }

    memset(out_frame, 0, sizeof(*out_frame));
    out_frame->apid = (uint16_t)(w1 & 0x07FFu);
    uint16_t seq14 = (uint16_t)(w2 & 0x3FFFu);

    size_t off = 6u;
    out_frame->swarm_hash = read_u16_be(raw_bytes + off);
    off += 2u;

    /* Copy node_id and strip trailing NUL padding */
    memcpy(out_frame->node_id, raw_bytes + off, UT_NODE_ID_MAX);
    out_frame->node_id[UT_NODE_ID_MAX] = '\0';
    for (int i = (int)UT_NODE_ID_MAX - 1; i >= 0; --i) {
        if (out_frame->node_id[i] == '\0') {
            continue;
        }
        break;
    }
    off += UT_NODE_ID_MAX;

    out_frame->timestamp_ns = read_u64_be(raw_bytes + off);
    off += 8u;

    memcpy(out_frame->prev_hash, raw_bytes + off, UT_DIGEST_SIZE);
    off += UT_DIGEST_SIZE;

    memcpy(out_frame->signature, raw_bytes + off, UT_ED25519_SIG_SIZE);
    off += UT_ED25519_SIG_SIZE;

    out_frame->lamport_time = read_u64_be(raw_bytes + off);
    off += 8u;

    out_frame->seq = read_u64_be(raw_bytes + off);
    off += 8u;

    if ((uint16_t)(out_frame->seq & 0x3FFFu) != seq14) {
        return UT_ERR_MALFORMED;
    }

    uint16_t topic_len = read_u16_be(raw_bytes + off);
    off += 2u;

    if (data_len < off + (size_t)topic_len) {
        return UT_ERR_MALFORMED;
    }

    out_frame->topic_len = (size_t)topic_len;
    out_frame->topic = (topic_len > 0u) ? (const char *)(raw_bytes + off) : "";
    off += (size_t)topic_len;

    out_frame->payload_len = data_len - off;
    out_frame->payload = (out_frame->payload_len > 0u) ? (raw_bytes + off) : NULL;

    return UT_OK;
}
