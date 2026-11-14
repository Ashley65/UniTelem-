#ifndef UNITELEM_TYPES_H
#define UNITELEM_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol constants (SPEC-UNITELEM-2026-V1) */
#define UT_CCSDS_VERSION          0u
#define UT_CCSDS_TYPE_TELEMETRY   0u
#define UT_CCSDS_SEC_HDR_PRESENT  1u
#define UT_CCSDS_SEQ_UNSEGMENTED  3u

#define UT_APID_TELEMETRY         0x0100u
#define UT_APID_AE_DIGEST         0x0110u
#define UT_APID_AE_REQUEST        0x0111u
#define UT_APID_AE_RESPONSE       0x0112u

#define UT_NODE_ID_MAX            16u
#define UT_DIGEST_SIZE            16u
#define UT_SHA256_SIZE            32u
#define UT_ED25519_SEED_SIZE      32u
#define UT_ED25519_PK_SIZE        32u
#define UT_ED25519_SIG_SIZE       64u

/* 6B primary + 2B swarm_hash + 16B node_id + 8B ts + 16B prev_hash
 * + 64B sig + 8B lamport + 8B seq64 + 2B topic_len + 2B crc16 = 132B */
#define UT_CCSDS_MIN_FRAME_SIZE   132u
#define UT_CCSDS_MAX_PACKET_DATA  65536u
#define UT_CCSDS_MAX_WIRE_SIZE    (6u + UT_CCSDS_MAX_PACKET_DATA + 2u)

#define UT_MULTICAST_GROUP        "239.255.42.99"
#define UT_DISCOVERY_PORT         9999u

typedef enum ut_status {
    UT_OK = 0,
    UT_ERR_INVALID_ARG = -1,
    UT_ERR_BUFFER_TOO_SMALL = -2,
    UT_ERR_MALFORMED = -3,
    UT_ERR_BAD_CRC = -4,
    UT_ERR_BAD_SIG = -5,
    UT_ERR_CRYPTO = -6,
    UT_ERR_NO_MEMORY = -7,
    UT_ERR_FULL = -8,
    UT_ERR_EMPTY = -9,
    UT_ERR_NOT_FOUND = -10,
    UT_ERR_IO = -11
} ut_status_t;

const char *ut_status_str(ut_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_TYPES_H */
