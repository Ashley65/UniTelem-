import unittest
import time

from unitelem.protocol.crc16 import compute_crc16, append_crc16, verify_crc16
from unitelem.protocol.ccsds import CCSDSFrame


class TestCRC16(unittest.TestCase):
    def test_crc16_correctness(self):
        data = b"123456789"
        # Standard CRC-16-CCITT for "123456789" is 0x29B1
        self.assertEqual(compute_crc16(data), 0x29B1)

    def test_append_and_verify(self):
        frame = b"TELEMETRY_PACKET_HEADER_DATA_123456"
        frame_with_crc = append_crc16(frame)
        self.assertEqual(len(frame_with_crc), len(frame) + 2)
        self.assertTrue(verify_crc16(frame_with_crc))

    def test_corrupted_frame_rejected(self):
        frame = b"CRITICAL_THRUSTER_DATA"
        frame_with_crc = append_crc16(frame)
        # Corrupt 1 byte
        corrupted = bytearray(frame_with_crc)
        corrupted[4] ^= 0xFF
        self.assertFalse(verify_crc16(bytes(corrupted)))


class TestCCSDS(unittest.TestCase):
    def test_ccsds_pack_unpack_roundtrip(self):
        payload = b'{"pos_x": 102.5, "pos_y": -45.2}'
        frame = CCSDSFrame(
            node_id="craft_a",
            topic="nav/pos",
            payload=payload,
            seq=42,
            swarm_id="alpha_mesh",
            timestamp_ns=1700000000000000000,
            prev_hash=b"\x01" * 16,
            signature=b"\x02" * 64,
            lamport_time=5,
        )

        wire_bytes = frame.pack()
        self.assertTrue(verify_crc16(wire_bytes))

        unpacked = CCSDSFrame.unpack(wire_bytes)
        self.assertIsNotNone(unpacked)
        self.assertEqual(unpacked.node_id, "craft_a")
        self.assertEqual(unpacked.topic, "nav/pos")
        self.assertEqual(unpacked.payload, payload)
        self.assertEqual(unpacked.seq, 42)
        self.assertEqual(unpacked.timestamp_ns, 1700000000000000000)
        self.assertEqual(unpacked.prev_hash, b"\x01" * 16)
        self.assertEqual(unpacked.signature, b"\x02" * 64)
        self.assertEqual(unpacked.lamport_time, 5)

        json_val = unpacked.payload_as_json()
        self.assertEqual(json_val["pos_x"], 102.5)


if __name__ == "__main__":
    unittest.main()
