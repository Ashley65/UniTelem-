#include "unitelem/ccsds.h"
#include "unitelem/crc16.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_crc16_vectors(void) {
    const uint8_t msg[] = "123456789";
    uint16_t crc = ut_crc16_compute(msg, 9);
    assert(crc == 0x29B1u);

    uint8_t buf[16];
    memcpy(buf, msg, 9);
    size_t out_len = 0;
    assert(ut_crc16_append(buf, 9, sizeof(buf), &out_len) == UT_OK);
    assert(out_len == 11);
    assert(ut_crc16_verify(buf, out_len));

    buf[3] ^= 0x01u;
    assert(!ut_crc16_verify(buf, out_len));
}

static void test_ccsds_roundtrip_and_64bit_seq(void) {
    uint64_t seqs[] = { 0ULL, 1ULL, 16383ULL, 16384ULL, 50000ULL, 0x123456789ABCDEF0ULL };
    const char *topic = "sensors/imu/accel";
    const char *payload = "{\"ax\":0.1,\"ay\":-0.2,\"az\":9.81}";

    for (size_t i = 0; i < sizeof(seqs) / sizeof(seqs[0]); ++i) {
        ut_ccsds_frame_t in;
        memset(&in, 0, sizeof(in));
        in.apid = UT_APID_TELEMETRY;
        in.seq = seqs[i];
        in.swarm_hash = ut_ccsds_swarm_hash("alpha-swarm", strlen("alpha-swarm"));
        strcpy(in.node_id, "drone_alpha_01");
        in.timestamp_ns = 1700000000123456789ULL + i;
        memset(in.prev_hash, 0xA5, UT_DIGEST_SIZE);
        memset(in.signature, 0x5A, UT_ED25519_SIG_SIZE);
        in.lamport_time = 999ULL + i;
        in.topic = topic;
        in.topic_len = strlen(topic);
        in.payload = (const uint8_t *)payload;
        in.payload_len = strlen(payload);

        uint8_t wire[1024];
        size_t wire_len = 0;
        assert(ut_ccsds_pack(&in, wire, sizeof(wire), &wire_len) == UT_OK);
        assert(wire_len >= UT_CCSDS_MIN_FRAME_SIZE);

        /* Primary header w2 carries 14-bit wrapped sequence */
        uint16_t w2 = (uint16_t)(((uint16_t)wire[2] << 8) | wire[3]);
        assert((w2 & 0x3FFFu) == (uint16_t)(seqs[i] & 0x3FFFu));

        ut_ccsds_frame_t out;
        assert(ut_ccsds_unpack(wire, wire_len, &out) == UT_OK);
        assert(out.apid == in.apid);
        assert(out.seq == in.seq);
        assert(out.swarm_hash == in.swarm_hash);
        assert(strcmp(out.node_id, in.node_id) == 0);
        assert(out.timestamp_ns == in.timestamp_ns);
        assert(memcmp(out.prev_hash, in.prev_hash, UT_DIGEST_SIZE) == 0);
        assert(memcmp(out.signature, in.signature, UT_ED25519_SIG_SIZE) == 0);
        assert(out.lamport_time == in.lamport_time);
        assert(out.topic_len == in.topic_len);
        assert(memcmp(out.topic, in.topic, out.topic_len) == 0);
        assert(out.payload_len == in.payload_len);
        assert(memcmp(out.payload, in.payload, out.payload_len) == 0);

        /* Corrupt payload -> CRC failure */
        wire[wire_len - 5] ^= 0xFFu;
        assert(ut_ccsds_unpack(wire, wire_len, &out) == UT_ERR_BAD_CRC);
    }
}

static void test_ccsds_malformed(void) {
    uint8_t tiny[32] = {0};
    ut_ccsds_frame_t out;
    assert(ut_ccsds_unpack(tiny, sizeof(tiny), &out) == UT_ERR_MALFORMED);
}

int main(void) {
    test_crc16_vectors();
    test_ccsds_roundtrip_and_64bit_seq();
    test_ccsds_malformed();
    printf("test_protocol passed\n");
    return 0;
}
