"""
Decentralized P2P Mesh Transport Layer (SPEC-UNITELEM-2026-V1 Section 1 & Section 4).

Manages non-blocking asynchronous transmission and zero-trust packet ingestion over UDP mesh.
"""

import json
import socket
import threading
import time
from typing import Dict, Tuple, Optional, Callable, List, Any

from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..crypto.hash_chain import MicroLedger, PeerLedgerTracker, compute_digest
from ..protocol.ccsds import CCSDSFrame
from ..ring_buffer import FastRingBuffer
from ..state_crdt import SwarmState
from .discovery import PeerDiscovery


class MeshTransport:
    """
    Asynchronous P2P Mesh Transport with integrated cryptographic verification.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str,
        port: int,
        ring_buffer: FastRingBuffer,
        state_store: SwarmState,
        ledger: MicroLedger,
        signer: Optional[Ed25519PrivateKey] = None,
        discovery: Optional[PeerDiscovery] = None,
    ):
        self.node_id = node_id
        self.swarm_id = swarm_id
        self.port = port
        self.ring_buffer = ring_buffer
        self.state_store = state_store
        self.ledger = ledger
        self.signer = signer
        self.discovery = discovery

        # Trust store: node_id -> Ed25519PublicKey
        self.trust_store: Dict[str, Ed25519PublicKey] = {}
        self.peer_tracker = PeerLedgerTracker()
        
        # Direct static peers: node_id -> (ip, port)
        self.direct_peers: Dict[str, Tuple[str, int]] = {}
        self._callbacks: Dict[str, List[Callable[[str, Any, str], None]]] = {}  # topic -> [fn(topic, val, node_id)]
        
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def register_peer_key(self, peer_id: str, pub_key_hex: str):
        """Manually registers an authorised peer public key in the zero-trust store."""
        try:
            pk = Ed25519PublicKey.from_hex(pub_key_hex)
            with self._lock:
                self.trust_store[peer_id] = pk
        except Exception:
            pass

    def add_direct_peer(self, peer_id: str, ip: str, port: int, pub_key_hex: str = ""):
        """Adds a direct static peer address (useful when multicast is disabled)."""
        with self._lock:
            self.direct_peers[peer_id] = (ip, port)
        if pub_key_hex:
            self.register_peer_key(peer_id, pub_key_hex)

    def subscribe(self, topic: str, callback: Callable[[str, Any, str], None]):
        """Registers a callback for updates on a specific topic or '*' for all topics."""
        with self._lock:
            self._callbacks.setdefault(topic, []).append(callback)

    def start(self):
        """Starts network socket, transmitter, and receiver workers."""
        if self._running:
            return
        self._running = True

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.port))
        self._sock.settimeout(0.2)

        self._tx_thread = threading.Thread(target=self._tx_worker, name=f"Mesh-TX-{self.node_id}", daemon=True)
        self._rx_thread = threading.Thread(target=self._rx_worker, name=f"Mesh-RX-{self.node_id}", daemon=True)

        self._tx_thread.start()
        self._rx_thread.start()

    def stop(self):
        """Cleanly stops transport threads and closes sockets."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _get_target_peers(self) -> Dict[str, Tuple[str, int]]:
        """Returns union of dynamically discovered peers and static peers."""
        peers = dict(self.direct_peers)
        if self.discovery:
            discovered = self.discovery.get_active_peers()
            peers.update(discovered)
        return peers

    def _tx_worker(self):
        """
        Background Transmit Worker:
        1. Pops batch from FastRingBuffer.
        2. Advances MicroLedger hash chain.
        3. Signs frame with an Ed25519 private key.
        4. Packs CCSDS 56-byte header + CRC-16.
        5. Sends it to all mesh peer endpoints.
        """
        while self._running:
            batch = self.ring_buffer.pop_batch(max_items=128)
            if not batch:
                time.sleep(0.001)
                continue

            target_peers = self._get_target_peers()
            if not target_peers:
                continue

            for item in batch:
                if len(item) == 3:
                    topic, raw_val, lamport_time = item
                elif len(item) == 2:
                    topic, raw_val = item
                    lamport_time = 0
                else:
                    continue

                ts_ns = time.time_ns()
                
                # Payload bytes serialization
                if isinstance(raw_val, bytes):
                    payload_bytes = raw_val
                elif isinstance(raw_val, str):
                    payload_bytes = raw_val.encode("utf-8")
                else:
                    payload_bytes = json.dumps(raw_val).encode("utf-8")

                # Advance cryptographic hash chain
                prev_digest = self.ledger.last_digest
                ledger_entry = self.ledger.append(ts_ns, payload_bytes)
                
                # Build CCSDS frame
                frame = CCSDSFrame(
                    node_id=self.node_id,
                    topic=topic,
                    payload=payload_bytes,
                    seq=ledger_entry.seq,
                    swarm_id=self.swarm_id,
                    timestamp_ns=ts_ns,
                    prev_hash=prev_digest,
                    lamport_time=lamport_time,
                )

                # Sign signable bytes if cryptographic signer is active
                if self.signer:
                    frame.signature = self.signer.sign(frame.signable_bytes())

                # Pack with CRC-16
                wire_packet = frame.pack()

                # Broadcast to mesh peers
                for peer_id, (ip, port) in target_peers.items():
                    try:
                        self._sock.sendto(wire_packet, (ip, port))
                    except Exception:
                        pass

    def _rx_worker(self):
        """
        Background Receive Worker (Zero-Trust Ingestion Pipeline):
        1. Verifies CRC-16 (drops corrupted frames immediately).
        2. Verifies Ed25519 signature against trusted peer key.
        3. Verifies MicroLedger continuity (detects forks / packet drops).
        4. Ingests into SwarmState CRDT.
        5. Dispatches subscription callbacks.
        """
        while self._running:
            try:
                raw_bytes, (sender_ip, _) = self._sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            except Exception:
                break

            # 1. Unpack & Validate CRC-16
            frame = CCSDSFrame.unpack(raw_bytes)
            if not frame or frame.node_id == self.node_id:
                continue

            # 2. Cryptographic Signature Verification (Zero-Trust)
            if self.signer:
                # Look up public key in trust store or discovery cache
                peer_key = None
                with self._lock:
                    peer_key = self.trust_store.get(frame.node_id)
                if not peer_key and self.discovery:
                    hex_key = self.discovery.get_peer_key(frame.node_id)
                    if hex_key:
                        try:
                            peer_key = Ed25519PublicKey.from_hex(hex_key)
                            with self._lock:
                                self.trust_store[frame.node_id] = peer_key
                        except Exception:
                            pass

                if not peer_key or not peer_key.verify(frame.signature, frame.signable_bytes()):
                    # Drop spoofed / untrusted packets immediately
                    continue

            # 3. MicroLedger Hash Chain Validation & Gap Detection
            frame_digest = compute_digest(frame.prev_hash, frame.seq, frame.timestamp_ns, frame.payload)
            is_valid_ledger, gap_msg = self.peer_tracker.record_incoming(
                peer_id=frame.node_id,
                seq=frame.seq,
                timestamp_ns=frame.timestamp_ns,
                prev_digest=frame.prev_hash,
                digest=frame_digest,
                payload=frame.payload,
            )
            if not is_valid_ledger:
                continue

            # 4. Decode payload value
            try:
                val = json.loads(frame.payload.decode("utf-8"))
            except Exception:
                val = frame.payload

            # 5. Ingest into SwarmState CRDT
            wall_time = frame.timestamp_ns / 1_000_000_000.0
            self.state_store.merge_remote(
                node_id=frame.node_id,
                topic=frame.topic,
                value=val,
                lamport_time=frame.lamport_time,
                wall_time=wall_time,
            )

            # 6. Dispatch reactive event subscriptions
            self._dispatch_callbacks(frame.topic, val, frame.node_id)

    def _dispatch_callbacks(self, topic: str, value: Any, node_id: str):
        callbacks_to_fire = []
        with self._lock:
            if topic in self._callbacks:
                callbacks_to_fire.extend(self._callbacks[topic])
            if "*" in self._callbacks:
                callbacks_to_fire.extend(self._callbacks["*"])

        for cb in callbacks_to_fire:
            try:
                cb(topic, value, node_id)
            except Exception:
                pass
