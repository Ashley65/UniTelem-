#include "unitelem/crc16.h"

const char *ut_status_str(ut_status_t status) {
    switch (status) {
        case UT_OK:                   return "UT_OK";
        case UT_ERR_INVALID_ARG:      return "UT_ERR_INVALID_ARG";
        case UT_ERR_BUFFER_TOO_SMALL: return "UT_ERR_BUFFER_TOO_SMALL";
        case UT_ERR_MALFORMED:        return "UT_ERR_MALFORMED";
        case UT_ERR_BAD_CRC:          return "UT_ERR_BAD_CRC";
        case UT_ERR_BAD_SIG:          return "UT_ERR_BAD_SIG";
        case UT_ERR_CRYPTO:           return "UT_ERR_CRYPTO";
        case UT_ERR_NO_MEMORY:        return "UT_ERR_NO_MEMORY";
        case UT_ERR_FULL:             return "UT_ERR_FULL";
        case UT_ERR_EMPTY:            return "UT_ERR_EMPTY";
        case UT_ERR_NOT_FOUND:        return "UT_ERR_NOT_FOUND";
        case UT_ERR_IO:               return "UT_ERR_IO";
        default:                      return "UT_ERR_UNKNOWN";
    }
}

#include <stdatomic.h>

static uint16_t crc16_table[256];
static atomic_int crc16_state = 0; /* 0=uninit, 1=initing, 2=ready */

static void init_crc16_table(void) {
    if (atomic_load_explicit(&crc16_state, memory_order_acquire) == 2) {
        return;
    }
    int expected = 0;
    if (atomic_compare_exchange_strong(&crc16_state, &expected, 1)) {
        for (uint32_t i = 0; i < 256u; ++i) {
            uint16_t curr = (uint16_t)(i << 8);
            for (int b = 0; b < 8; ++b) {
                if (curr & 0x8000u) {
                    curr = (uint16_t)((curr << 1) ^ 0x1021u);
                } else {
                    curr = (uint16_t)(curr << 1);
                }
            }
            crc16_table[i] = curr;
        }
        atomic_store_explicit(&crc16_state, 2, memory_order_release);
    } else {
        while (atomic_load_explicit(&crc16_state, memory_order_acquire) != 2) {
            /* spin briefly while initializing */
        }
    }
}

uint16_t ut_crc16_compute(const uint8_t *data, size_t len) {
    init_crc16_table();
    uint16_t crc = 0xFFFFu;
    if (!data && len > 0) {
        return crc;
    }
    for (size_t i = 0; i < len; ++i) {
        uint8_t idx = (uint8_t)((crc >> 8) ^ data[i]);
        crc = (uint16_t)((crc << 8) ^ crc16_table[idx]);
    }
    return crc;
}

ut_status_t ut_crc16_append(uint8_t *buf, size_t data_len, size_t buf_cap, size_t *out_len) {
    if (!buf || buf_cap < data_len + 2u) {
        return UT_ERR_BUFFER_TOO_SMALL;
    }
    uint16_t crc = ut_crc16_compute(buf, data_len);
    buf[data_len]     = (uint8_t)((crc >> 8) & 0xFFu);
    buf[data_len + 1] = (uint8_t)(crc & 0xFFu);
    if (out_len) {
        *out_len = data_len + 2u;
    }
    return UT_OK;
}

bool ut_crc16_verify(const uint8_t *frame_with_crc, size_t len) {
    if (!frame_with_crc || len < 2u) {
        return false;
    }
    size_t payload_len = len - 2u;
    uint16_t expected = (uint16_t)(((uint16_t)frame_with_crc[payload_len] << 8) |
                                   (uint16_t)frame_with_crc[payload_len + 1u]);
    uint16_t actual = ut_crc16_compute(frame_with_crc, payload_len);
    return actual == expected;
}
