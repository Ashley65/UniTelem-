"""
Hardware-Equivalent Table-Driven CRC-16-CCITT Implementation.

Polynomial: 0x1021 (X^16 + X^12 + X^5 + 1)
Initial Value: 0xFFFF
Rejection: Instantly rejects corrupted radio packets before signature/cryptographic processing.
"""

# Precomputed CRC-16-CCITT (0x1021) lookup table
_CRC16_TABLE = []
for i in range(256):
    curr = i << 8
    for _ in range(8):
        if (curr & 0x8000) != 0:
            curr = ((curr << 1) ^ 0x1021) & 0xFFFF
        else:
            curr = (curr << 1) & 0xFFFF
    _CRC16_TABLE.append(curr)


def compute_crc16(data: bytes) -> int:
    """Computes a 16-bit unsigned integer CRC-16-CCITT checksum."""
    crc = 0xFFFF
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TABLE[(crc >> 8) ^ byte]
    return crc


def append_crc16(frame: bytes) -> bytes:
    """Computes CRC-16 of the input frame and appends it as 2 big-endian bytes."""
    crc = compute_crc16(frame)
    return frame + crc.to_bytes(2, byteorder="big")


def verify_crc16(frame_with_crc: bytes) -> bool:
    """
    Verifies the trailing 2-byte CRC-16-CCITT on a frame.
    Returns True if the checksum matches, False if corrupted.
    """
    if len(frame_with_crc) < 2:
        return False
    payload = frame_with_crc[:-2]
    expected_crc = int.from_bytes(frame_with_crc[-2:], byteorder="big")
    actual_crc = compute_crc16(payload)
    return actual_crc == expected_crc
