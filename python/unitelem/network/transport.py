"""
Decentralized P2P Mesh Transport Layer with Anti-Entropy Gossip Repair.
(SPEC-UNITELEM-2026-V1 Section 1, Section 3.3, and Section 4).

Features:
- High-throughput asynchronous non-blocking TX worker.
- Zero-trust packet verification pipeline (CRC-16 + Ed25519 + Micro-Ledger).
- 4 MB OS socket buffer tuning to eliminate burst drop.
- Background Anti-Entropy Merkle Gossip Daemon for loss-tolerant eventual consistency.
"""

import json
import socket
import threading
import time
from typing import Dict, Tuple, Optional, Callable, List, Any

from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..crypto.hash_chain import MicroLedger, PeerLedgerTracker, compute_digest
from ..crypto.merkle_tree import StateMerkleTree
from ..protocol.ccsds import (
    CCSDSFrame,
    APID_TELEMETRY,
    APID_AE_DIGEST,
    APID_AE_REQUEST,
    APID_AE_RESPONSE,
)
from ..ring_buffer import FastRingBuffer
from ..state_crdt import SwarmState
from .discovery import PeerDiscovery


class MeshTransport:
    """
    Asynchronous P2P Mesh Transport with integrated zero-trust security and anti-entropy repair.
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
        merkle_tree: Optional[StateMerkleTree] = None,
        enable_anti_entropy: bool = True,
        anti_entropy_interval_s: float = 0.5,
    ):
        self.node_id = node_id
        self.swarm_id = swarm_id
        self.port = port
        self.ring_buffer = ring_buffer
        self.state_store = state_store
        self.ledger = ledger
        self.signer = signer
        self.discovery = discovery
        self.merkle_tree = merkle_tree or StateMerkleTree()
        self.enable_anti_entropy = enable_anti_entropy
        self.anti_entropy_interval_s = anti_entropy_interval_s

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
        self._ae_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def register_peer_key(self, peer_id: str, pub_key_hex: str):
        """Manually registers an authorized peer public key in the zero-trust store."""
        try:
            pk = Ed25519PublicKey.from_hex(pub_key_hex)
            with self._lock:
                self.trust_store[peer_id] = pk
        except Exception:
            pass

    def add_direct_peer(self, peer_id: str, ip: str, port: int, pub_key_hex: str = ""):
        """Adds a direct static peer address."""
        with self._lock:
            self.direct_peers[peer_id] = (ip, port)
        if pub_key_hex:
            self.register_peer_key(peer_id, pub_key_hex)

    def subscribe(self, topic: str, callback: Callable[[str, Any, str], None]):
        """Registers a callback for updates on a specific topic or '*' for all topics."""
        with self._lock:
            self._callbacks.setdefault(topic, []).append(callback)

    def start(self):
        """Starts network socket, transmitter, receiver, and anti-entropy workers."""
        if self._running:
            return
        self._running = True

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Expand OS buffers to 4 MB to eliminate kernel-level packet drops under heavy load
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except Exception:
            pass

        self._sock.bind(("0.0.0.0", self.port))
        self._sock.settimeout(0.2)

        self._tx_thread = threading.Thread(target=self._tx_worker, name=f"Mesh-TX-{self.node_id}", daemon=True)
        self._rx_thread = threading.Thread(target=self._rx_worker, name=f"Mesh-RX-{self.node_id}", daemon=True)

        self._tx_thread.start()
        self._rx_thread.start()

        if self.enable_anti_entropy:
            self._ae_thread = threading.Thread(target=self._ae_worker, name=f"Mesh-AE-{self.node_id}", daemon=True)
            self._ae_thread.start()

    def stop(self):
        """Cleanly stops transport threads and closes sockets."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def trigger_repair(self):
        """Immediately broadcasts an Anti-Entropy digest to trigger peer reconciliation."""
        self._broadcast_anti_entropy_digest()

    def _get_target_peers(self) -> Dict[str, Tuple[str, int]]:
        """Returns union of dynamically discovered peers and static peers."""
        peers = dict(self.direct_peers)
        if self.discovery:
            discovered = self.discovery.get_active_peers()
            peers.update(discovered)
        return peers

    def _send_frame(self, frame: CCSDSFrame, target_ip: str, target_port: int):
        """Signs and transmits a single frame over UDP."""
        if self.signer:
            frame.signature = self.signer.sign(frame.signable_bytes())
        wire_packet = frame.pack()
        try:
            self._sock.sendto(wire_packet, (target_ip, target_port))
        except Exception:
            pass

    def _broadcast_anti_entropy_digest(self):
        """Computes local Merkle tree summary and broadcasts an APID_AE_DIGEST frame."""
        target_peers = self._get_target_peers()
        if not target_peers:
            return

        with self._lock:
            self.merkle_tree.update_from_state(
                self.state_store.snapshot(),
                self.state_store.get_clocks_snapshot(),
            )
            summary = self.merkle_tree.get_summary()

        payload_bytes = json.dumps(summary).encode("utf-8")
        ts_ns = time.time_ns()

        frame = CCSDSFrame(
            node_id=self.node_id,
            topic="__sys/ae_digest",
            payload=payload_bytes,
            seq=self.ledger.sequence_number,
            swarm_id=self.swarm_id,
            timestamp_ns=ts_ns,
            prev_hash=self.ledger.last_digest,
            apid=APID_AE_DIGEST,
            lamport_time=self.state_store.clock,
        )

        for peer_id, (ip, port) in target_peers.items():
            self._send_frame(frame, ip, port)

    def _ae_worker(self):
        """Background Anti-Entropy Gossip Worker: Periodically triggers state reconciliation."""
        while self._running:
            time.sleep(self.anti_entropy_interval_s)
            if not self._running:
                break
            try:
                self._broadcast_anti_entropy_digest()
            except Exception:
                pass

    def _tx_worker(self):
        """
        Background Transmit Worker for real-time telemetry frames.
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
                    apid=APID_TELEMETRY,
                    lamport_time=lamport_time,
                )

                if self.signer:
                    frame.signature = self.signer.sign(frame.signable_bytes())

                wire_packet = frame.pack()

                for peer_id, (ip, port) in target_peers.items():
                    try:
                        self._sock.sendto(wire_packet, (ip, port))
                    except Exception:
                        pass

    def _rx_worker(self):
        """
        Background Receive Worker (Zero-Trust Ingestion & Anti-Entropy Repair Router).
        """
        while self._running:
            try:
                raw_bytes, (sender_ip, sender_port) = self._sock.recvfrom(65535)
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
                    # Drop unauthorized / forged packet
                    continue

            # -------------------------------------------------------------
            # Route by APID
            # -------------------------------------------------------------
            if frame.apid == APID_TELEMETRY:
                # 3. MicroLedger Hash Chain Validation
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

            elif frame.apid == APID_AE_DIGEST:
                # Handle Merkle Anti-Entropy Digest
                self._handle_ae_digest(frame, sender_ip, sender_port)

            elif frame.apid == APID_AE_REQUEST:
                # Handle Targeted Repair Request
                self._handle_ae_request(frame, sender_ip, sender_port)

            elif frame.apid == APID_AE_RESPONSE:
                # Handle Inbound State Repair Batch
                self._handle_ae_response(frame)

    def _handle_ae_digest(self, frame: CCSDSFrame, sender_ip: str, sender_port: int):
        """Processes remote Merkle digest and reconciles state divergence."""
        try:
            remote_summary = json.loads(frame.payload.decode("utf-8"))
            remote_root = remote_summary.get("root")
            remote_leaves = remote_summary.get("leaves", {})

            with self._lock:
                self.merkle_tree.update_from_state(
                    self.state_store.snapshot(),
                    self.state_store.get_clocks_snapshot(),
                )
                local_root = self.merkle_tree.root.hex()

            # 1. If roots match, state is 100% identical (O(1) fast path)
            if remote_root == local_root:
                return

            # 2. Pinpoint divergent topic keys
            divergent_keys = self.merkle_tree.get_divergent_keys(remote_leaves)
            if not divergent_keys:
                return

            # 3. Two-way repair:
            # - Send records local currently holds for divergent keys to repair the peer
            local_records = self.state_store.get_registers_for_keys(divergent_keys)
            if local_records:
                resp_frame = CCSDSFrame(
                    node_id=self.node_id,
                    topic="__sys/ae_response",
                    payload=json.dumps(local_records).encode("utf-8"),
                    swarm_id=self.swarm_id,
                    apid=APID_AE_RESPONSE,
                    lamport_time=self.state_store.clock,
                )
                self._send_frame(resp_frame, sender_ip, sender_port)

            # - Request keys that local might be missing
            missing_keys = [k for k in divergent_keys if k not in self.merkle_tree._leaves]
            if missing_keys:
                req_frame = CCSDSFrame(
                    node_id=self.node_id,
                    topic="__sys/ae_request",
                    payload=json.dumps(missing_keys).encode("utf-8"),
                    swarm_id=self.swarm_id,
                    apid=APID_AE_REQUEST,
                    lamport_time=self.state_store.clock,
                )
                self._send_frame(req_frame, sender_ip, sender_port)

        except Exception:
            pass

    def _handle_ae_request(self, frame: CCSDSFrame, sender_ip: str, sender_port: int):
        """Processes request for specific topic keys and replies with LWWRegisters."""
        try:
            requested_keys = json.loads(frame.payload.decode("utf-8"))
            records = self.state_store.get_registers_for_keys(requested_keys)
            if records:
                resp_frame = CCSDSFrame(
                    node_id=self.node_id,
                    topic="__sys/ae_response",
                    payload=json.dumps(records).encode("utf-8"),
                    swarm_id=self.swarm_id,
                    apid=APID_AE_RESPONSE,
                    lamport_time=self.state_store.clock,
                )
                self._send_frame(resp_frame, sender_ip, sender_port)
        except Exception:
            pass

    def _handle_ae_response(self, frame: CCSDSFrame):
        """Batch merges repaired registers into local SwarmState."""
        try:
            records = json.loads(frame.payload.decode("utf-8"))
            if isinstance(records, list) and records:
                self.state_store.merge_batch(records)
                # Recompute local Merkle Tree
                with self._lock:
                    self.merkle_tree.update_from_state(
                        self.state_store.snapshot(),
                        self.state_store.get_clocks_snapshot(),
                    )
        except Exception:
            pass

    def _dispatch_callbacks(self, topic: str, value: Any, node_id: str):
        callbacks_to_fire = []
        with self._lock:
            for pattern, cb_list in self._callbacks.items():
                if pattern == "*" or pattern == topic:
                    callbacks_to_fire.extend(cb_list)
                elif pattern.endswith("*") and topic.startswith(pattern[:-1]):
                    callbacks_to_fire.extend(cb_list)

        for cb in callbacks_to_fire:
            try:
                cb(topic, value, node_id)
            except Exception:
                pass
