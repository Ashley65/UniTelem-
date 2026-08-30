"""
Micro-Ledger Hash Chain Engine (SPEC-UNITELEM-2026-V1 Section 3.1).

Maintains an unbroken sequence of historical state commitments:
    Digest_k = Hash(Digest_{k-1} || Seq_k || Timestamp_k || Payload_k)

Provides:
- Tamper-evident flight black-box logging.
- Instant O(1) packet gap / dropped range detection.
- Complete cryptographic chain audit & verification.
"""

import hashlib
import struct
from typing import List, Tuple, Optional, Dict


def compute_digest(prev_digest: bytes, seq: int, timestamp_ns: int, payload: bytes) -> bytes:
    """Computes a 16-byte (128-bit truncated) cryptographic commitment."""
    # Uses BLAKE2s (16-byte digest) from Python's standard library hashlib
    h = hashlib.blake2s(digest_size=16)
    h.update(prev_digest)
    h.update(struct.pack(">QQ", seq, timestamp_ns))
    h.update(payload)
    return h.digest()


class MicroLedgerEntry:
    __slots__ = ("seq", "timestamp_ns", "prev_digest", "digest", "payload")

    def __init__(self, seq: int, timestamp_ns: int, prev_digest: bytes, digest: bytes, payload: bytes):
        self.seq = seq
        self.timestamp_ns = timestamp_ns
        self.prev_digest = prev_digest
        self.digest = digest
        self.payload = payload

    def __repr__(self) -> str:
        return f"<LedgerEntry seq={self.seq} hash={self.digest.hex()[:8]}>"


class MicroLedger:
    """Tamper-evident hash-chained micro-ledger for local telemetry output."""

    GENESIS_HASH = b"\x00" * 16

    def __init__(self, node_id: str, max_history: int = 100_000):
        self.node_id = node_id
        self._max_history = max_history
        self._seq = 0
        self._last_digest = self.GENESIS_HASH
        self._history: List[MicroLedgerEntry] = []

    @property
    def sequence_number(self) -> int:
        return self._seq

    @property
    def last_digest(self) -> bytes:
        return self._last_digest

    def append(self, timestamp_ns: int, payload: bytes) -> MicroLedgerEntry:
        """Appends a new payload to the micro-ledger and advances the cryptographic hash chain."""
        self._seq += 1
        digest = compute_digest(self._last_digest, self._seq, timestamp_ns, payload)
        entry = MicroLedgerEntry(
            seq=self._seq,
            timestamp_ns=timestamp_ns,
            prev_digest=self._last_digest,
            digest=digest,
            payload=payload,
        )
        self._last_digest = digest
        self._history.append(entry)
        if len(self._history) > self._max_history:
            self._history.pop(0)
        return entry

    def get_history(self) -> List[MicroLedgerEntry]:
        return list(self._history)

    def verify_local_integrity(self) -> bool:
        """Verifies the complete internal chain history from genesis."""
        current_prev = self.GENESIS_HASH
        for entry in self._history:
            if entry.prev_digest != current_prev:
                return False
            expected = compute_digest(entry.prev_digest, entry.seq, entry.timestamp_ns, entry.payload)
            if entry.digest != expected:
                return False
            current_prev = entry.digest
        return True


class PeerLedgerTracker:
    """Tracks and verifies the remote micro-ledger hash chains of incoming peers."""

    def __init__(self):
        # peer_id -> {"last_seq": int, "last_digest": bytes}
        self._peer_state: Dict[str, Dict[str, object]] = {}

    def record_incoming(self, peer_id: str, seq: int, timestamp_ns: int, prev_digest: bytes, digest: bytes, payload: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validates an incoming packet against the tracked peer micro-ledger.
        Returns (is_valid, gap_or_error_message).
        """
        # 1. Verify self-consistency of the incoming frame digest
        expected_digest = compute_digest(prev_digest, seq, timestamp_ns, payload)
        if digest != expected_digest:
            return False, "CORRUPTED_DIGEST: frame digest does not match hash(prev || seq || ts || payload)"

        state = self._peer_state.get(peer_id)
        if state is None:
            # First packet seen from peer - accept and initialize tracker
            self._peer_state[peer_id] = {"last_seq": seq, "last_digest": digest}
            return True, None

        last_seq = int(state["last_seq"])
        last_digest = bytes(state["last_digest"])

        if seq <= last_seq:
            # Duplicate or out-of-order packet
            return True, "OUT_OF_ORDER_OR_DUPLICATE"

        if seq == last_seq + 1:
            # Perfect contiguous link
            if prev_digest != last_digest:
                return False, f"FORK_OR_TAMPER_DETECTED: peer {peer_id} prev_digest does not match last seen digest"
            self._peer_state[peer_id] = {"last_seq": seq, "last_digest": digest}
            return True, None

        # Gap detected (e.g. lost packets between last_seq and seq)
        gap_count = seq - last_seq - 1
        self._peer_state[peer_id] = {"last_seq": seq, "last_digest": digest}
        return True, f"GAP_DETECTED: missed {gap_count} packets between seq {last_seq} and {seq}"

    def get_peer_last_digest(self, peer_id: str) -> Optional[bytes]:
        state = self._peer_state.get(peer_id)
        return bytes(state["last_digest"]) if state else None
