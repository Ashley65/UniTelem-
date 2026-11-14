#ifndef UNITELEM_CRC16_H
#define UNITELEM_CRC16_H

#include "unitelem/types.h"

#ifdef __cplusplus
extern "C" {
#endif

uint16_t ut_crc16_compute(const uint8_t *data, size_t len);
ut_status_t ut_crc16_append(uint8_t *buf, size_t data_len, size_t buf_cap, size_t *out_len);
bool ut_crc16_verify(const uint8_t *frame_with_crc, size_t len);

#ifdef __cplusplus
}
#endif

#endif
