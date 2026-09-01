"""
CCSDS Space Packet Binary Framing & Universal JSON Serialization (SPEC-UNITELEM-2026-V1 Section 2).

Profile A: Aerospace Binary CCSDS Extended Frame (with Ed25519 signature & CRC-16).
Profile B: Universal JSON-Schema for rapid prototyping, simulation visualization, and web HUDs.
"""

import json
import struct
import time
from typing import Optional, Tuple, Any

from .crc16 import append_crc16, verify_crc16, compute_crc16


# CCSDS Profile A Magic & Constants
CCSDS_VERSION = 0
CCSDS_TYPE_TELEMETRY = 0
CCSDS_SEC_HDR_PRESENT = 1
CCSDS_SEQ_UNSEGMENTED = 3

# Application Process IDs (APIDs)
APID_TELEMETRY = 0x100      # Real-time streaming telemetry
APID_AE_DIGEST = 0x110      # Anti-Entropy Merkle Root & Leaf summary
APID_AE_REQUEST = 0x111     # Anti-Entropy Targeted repair request
APID_AE_RESPONSE = 0x112    # Anti-Entropy Targeted state repair batch


class CCSDSFrame:
    """
    Represents a decoded UniTelem telemetry frame.
    """
    __slots__ = (
        "apid",
        "seq",
        "swarm_id",
        "swarm_hash",
        "node_id",
        "timestamp_ns",
        "prev_hash",
        "signature",
        "topic",
        "payload",
        "lamport_time",
    )

    def __init__(
        self,
        node_id: str,
        topic: str,
        payload: bytes,
        seq: int = 0,
        swarm_id: str = "default",
        swarm_hash: Optional[int] = None,
        timestamp_ns: int = 0,
        prev_hash: bytes = b"\x00" * 16,
        signature: bytes = b"\x00" * 64,
        apid: int = APID_TELEMETRY,
        lamport_time: int = 0,
    ):
        self.node_id = node_id
        self.topic = topic
        self.payload = payload
        self.seq = seq
        self.swarm_id = swarm_id
        self.swarm_hash = swarm_hash if swarm_hash is not None else (compute_crc16(swarm_id.encode("utf-8")) & 0xFFFF)
        self.timestamp_ns = timestamp_ns or time.time_ns()
        self.prev_hash = prev_hash
        self.signature = signature
        self.apid = apid
        self.lamport_time = lamport_time

    def signable_bytes(self) -> bytes:
        """Returns the deterministic byte sequence covered by the Ed25519 signature."""
        node_id_16b = self.node_id.encode("utf-8")[:16].ljust(16, b"\x00")
        swarm_hash_2b = self.swarm_hash.to_bytes(2, byteorder="big")
        topic_bytes = self.topic.encode("utf-8")
        return (
            struct.pack(">HH", self.apid, self.seq & 0x3FFF)
            + swarm_hash_2b
            + node_id_16b
            + struct.pack(">Q", self.timestamp_ns)
            + self.prev_hash
            + struct.pack(">Q", self.lamport_time)
            + struct.pack(">H", len(topic_bytes))
            + topic_bytes
            + self.payload
        )

    def pack(self) -> bytes:
        """
        Packs this frame into a binary CCSDS extended packet with CRC-16 checksum.
        """
        # 1. Primary Header (6 bytes)
        # Word 1: Version (3b), Type (1b), SecHdr (1b), APID (11b)
        w1 = ((CCSDS_VERSION & 0x07) << 13) | ((CCSDS_TYPE_TELEMETRY & 0x01) << 12) | ((CCSDS_SEC_HDR_PRESENT & 0x01) << 11) | (self.apid & 0x07FF)
        # Word 2: Seq Flags (2b), Seq Count (14b)
        w2 = ((CCSDS_SEQ_UNSEGMENTED & 0x03) << 14) | (self.seq & 0x3FFF)
        
        node_id_16b = self.node_id.encode("utf-8")[:16].ljust(16, b"\x00")
        swarm_hash_2b = self.swarm_hash
        topic_bytes = self.topic.encode("utf-8")
        
        # Extended Header Payload
        sec_header = (
            struct.pack(">H", swarm_hash_2b)
            + node_id_16b
            + struct.pack(">Q", self.timestamp_ns)
            + (self.prev_hash[:16].ljust(16, b"\x00"))
            + (self.signature[:64].ljust(64, b"\x00"))
            + struct.pack(">Q", self.lamport_time)
            + struct.pack(">H", len(topic_bytes))
            + topic_bytes
        )
        
        packet_data = sec_header + self.payload
        # Word 3: Packet Data Length (Total Data Bytes - 1)
        w3 = len(packet_data) - 1
        
        primary_header = struct.pack(">HHH", w1, w2, w3)
        raw_frame = primary_header + packet_data
        
        # Append CRC-16 Checksum (2 bytes)
        return append_crc16(raw_frame)

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> Optional["CCSDSFrame"]:
        """
        Unpacks and validates a binary CCSDS frame with CRC-16 verification.
        Returns None if CRC fails or frame is malformed.
        """
        if len(raw_bytes) < 6 + 2 + 16 + 8 + 16 + 64 + 8 + 2 + 2:  # Min length with CRC
            return None
            
        if not verify_crc16(raw_bytes):
            return None

        data = raw_bytes[:-2]  # Strip CRC
        
        w1, w2, w3 = struct.unpack(">HHH", data[:6])
        apid = w1 & 0x07FF
        seq = w2 & 0x3FFF
        
        offset = 6
        swarm_hash_2b = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        
        node_id_16b = data[offset : offset + 16].rstrip(b"\x00").decode("utf-8", errors="replace")
        offset += 16
        
        timestamp_ns = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        
        prev_hash = data[offset : offset + 16]
        offset += 16
        
        signature = data[offset : offset + 64]
        offset += 64
        
        lamport_time = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        
        topic_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        
        if len(data) < offset + topic_len:
            return None
            
        topic = data[offset : offset + topic_len].decode("utf-8", errors="replace")
        offset += topic_len
        
        payload = data[offset:]
        
        return cls(
            node_id=node_id_16b,
            topic=topic,
            payload=payload,
            seq=seq,
            swarm_hash=swarm_hash_2b,
            timestamp_ns=timestamp_ns,
            prev_hash=prev_hash,
            signature=signature,
            apid=apid,
            lamport_time=lamport_time,
        )

    def payload_as_json(self) -> Any:
        """Parses the payload bytes as JSON if possible."""
        try:
            return json.loads(self.payload.decode("utf-8"))
        except Exception:
            return self.payload
