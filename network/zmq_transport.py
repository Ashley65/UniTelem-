"""
High-Throughput ZeroMQ Mesh Transport Layer with Anti-Entropy Gossip Repair.
Drop-in replacement for MeshTransport to eliminate UDP kernel buffer drop under saturation.
"""
import json
import threading
import time
from typing import Dict, Tuple, Optional, Callable, List, Any, Set
try:
    import zmq
except ImportError:
    zmq = None
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



class ZMQTransport:
    """
    ZeroMQ-based Mesh Transport implementing the exact duck-typed interface of MeshTransport.
    Utilizes a meshed PUB/SUB topology over TCP with in-memory HWM buffering.
    """

    def __init__(self,  node_id: str,
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
        hwm: int = 65536):

        if zmq is None:
            raise ImportError("pyzmq is required for ZMQTransport but is not installed.")

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
        self.hwm = hwm

        # Trust store: node_id -> Ed25519PublicKey
        self.trust_store: Dict[str, Ed25519PublicKey] = {}
        self.peer_tracker = PeerLedgerTracker()

        # Peer tracking
        self.direct_peers: Dict[str, Tuple[str, int]] = {}
        self._connected_endpoints: Set[str] = set()
        self._callbacks: Dict[str, List[Callable[[str, Any, str], None]]] = {}
        self._running = False
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # ZMQ Context & Sockets
        self._ctx: Optional[zmq.Context] = None
        self._pub_sock: Optional[zmq.Socket] = None
        self._sub_sock: Optional[zmq.Socket] = None
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._ae_thread: Optional[threading.Thread] = None


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

    def _connect_to_peer(self, ip: str, port: int):
        endpoint = f"tcp://{ip}:{port}"
        with self._lock:
            if endpoint not in self._connected_endpoints:
                try:
                    self._sub_sock.connect(endpoint)
                    self._connected_endpoints.add(endpoint)
                except Exception:
                    pass

    def start(self):
        """Starts network socket, transmitter, receiver, and anti-entropy workers."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._ctx = zmq.Context()
        # 1. Setup Egress (PUB)
        self._pub_sock = self._ctx.socket(zmq.PUB)
        self._pub_sock.setsockopt(zmq.SNDHWM, self.hwm)
        self._pub_sock.setsockopt(zmq.LINGER, 0)
        self._pub_sock.bind(f"tcp://0.0.0.0:{self.port}")
        # 2. Setup Ingress (SUB)
        self._sub_sock = self._ctx.socket(zmq.SUB)
        self._sub_sock.setsockopt(zmq.RCVHWM, self.hwm)
        self._sub_sock.setsockopt(zmq.LINGER, 0)
        self._sub_sock.setsockopt_string(zmq.SUBSCRIBE, "")  # Ingest all mesh topics
        # Connect to any already-registered direct peers
        with self._lock:
            for _, (ip, port) in self.direct_peers.items():
                self._connect_to_peer(ip, port)
        self._tx_thread = threading.Thread(target=self._tx_worker, name=f"ZMQ-TX-{self.node_id}", daemon=True)
        self._rx_thread = threading.Thread(target=self._rx_worker, name=f"ZMQ-RX-{self.node_id}", daemon=True)
        self._tx_thread.start()
        self._rx_thread.start()
        if self.enable_anti_entropy:
            self._ae_thread = threading.Thread(target=self._ae_worker, name=f"ZMQ-AE-{self.node_id}", daemon=True)
            self._ae_thread.start()


    def stop(self):
        """Stop network socket, transmitter, receiver, and anti-entropy workers."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        for sock in (self._pub_sock, self._sub_sock):
            if sock:
                try:
                    sock.close(linger=0)
                except Exception:
                    pass
        if self._ctx:
            try:
                self._ctx.term()
            except Exception:
                pass
        for t in (self._tx_thread, self._rx_thread, self._ae_thread):
            if t and t.is_alive() and t != threading.current_thread():
                t.join(timeout=1.0)
        self._tx_thread = None
        self._rx_thread = None
        self._ae_thread = None
        self._ctx = None

    def trigger_repair(self):
        """Broadcasts an Anti-Entropy digest to trigger peer reconciliation."""
        self._broadcast_anti_entropy_digest()

    def _sync_discovered_peers(self):
        """Queries PeerDiscovery and connects SUB socket to newly discovered peers."""
        if not self.discovery:
            return
        discovered = self.discovery.get_active_peers()
        for _, (ip, port) in discovered.items():
            self._connect_to_peer(ip, port)

    def _send_frame(self, frame: CCSDSFrame):
        """Signs and publishes a frame over the ZMQ PUB socket."""
        if self.signer:
            frame.signature = self.signer.sign(frame.signable_bytes())
        wire_packet = frame.pack()
        topic_bytes = frame.topic.encode("utf-8")
        try:
            self._pub_sock.send_multipart([topic_bytes, wire_packet], flags=zmq.NOBLOCK)
        except zmq.ZMQError:
            pass

    def _broadcast_anti_entropy_digest(self):
        """Computes local Merkle tree summary and broadcasts an APID_AE_DIGEST frame."""
        self._sync_discovered_peers()
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
        self._send_frame(frame)

    def _ae_worker(self):
        """Background worker for periodic anti-entropy reconciliation."""
        while self._running:
            if self._stop_event.wait(self.anti_entropy_interval_s):
                break
            if not self._running:
                break
            try:
                self._broadcast_anti_entropy_digest()
            except Exception:
                pass

    def _tx_worker(self):
        """Pulls batches from FastRingBuffer, updates MicroLedger, and publishes frames."""
        while self._running:
            self._sync_discovered_peers()
            batch = self.ring_buffer.pop_batch(max_items=256)
            if not batch:
                time.sleep(0.001)
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
                payload_bytes = raw_val if isinstance(raw_val, bytes) else json.dumps(raw_val).encode("utf-8")
                prev_digest = self.ledger.last_digest
                ledger_entry = self.ledger.append(ts_ns, payload_bytes)
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
                self._send_frame(frame)

    def _rx_worker(self):
        """Ingests frames from ZMQ SUB socket, runs verification pipeline, and merges CRDT state."""
        poller = zmq.Poller()
        poller.register(self._sub_sock, zmq.POLLIN)
        while self._running:
            try:
                events = dict(poller.poll(timeout=200))
            except zmq.ZMQError:
                break
            if self._sub_sock not in events:
                continue
            try:
                frames = self._sub_sock.recv_multipart(flags=zmq.NOBLOCK)
                if len(frames) != 2:
                    continue
                _, raw_bytes = frames
            except (zmq.ZMQError, OSError):
                continue
            # 1. Unpack & Validate CRC-16
            frame = CCSDSFrame.unpack(raw_bytes)
            if not frame or frame.node_id == self.node_id:
                continue
            # 2. Zero-Trust Ed25519 Signature Verification
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
                    continue
            # 3. Route by APID
            if frame.apid == APID_TELEMETRY:
                frame_digest = compute_digest(frame.prev_hash, frame.seq, frame.timestamp_ns, frame.payload)
                is_valid_ledger, _ = self.peer_tracker.record_incoming(
                    peer_id=frame.node_id,
                    seq=frame.seq,
                    timestamp_ns=frame.timestamp_ns,
                    prev_digest=frame.prev_hash,
                    digest=frame_digest,
                    payload=frame.payload,
                )
                if not is_valid_ledger:
                    continue
                try:
                    val = json.loads(frame.payload.decode("utf-8"))
                except Exception:
                    val = frame.payload
                wall_time = frame.timestamp_ns / 1_000_000_000.0
                self.state_store.merge_remote(
                    node_id=frame.node_id,
                    topic=frame.topic,
                    value=val,
                    lamport_time=frame.lamport_time,
                    wall_time=wall_time,
                )
                self._dispatch_callbacks(frame.topic, val, frame.node_id)
            elif frame.apid == APID_AE_DIGEST:
                self._handle_ae_digest(frame)
            elif frame.apid == APID_AE_REQUEST:
                self._handle_ae_request(frame)
            elif frame.apid == APID_AE_RESPONSE:
                self._handle_ae_response(frame)

    def _handle_ae_digest(self, frame: CCSDSFrame):
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
            if remote_root == local_root:
                return
            divergent_keys = self.merkle_tree.get_divergent_keys(remote_leaves)
            if not divergent_keys:
                return
            # Send registers local holds for divergent keys
            local_records = self.state_store.get_registers_for_keys(divergent_keys)
            if local_records:
                resp_frame = CCSDSFrame(
                    node_id=self.node_id,
                    topic=f"__sys/ae_response/{frame.node_id}",
                    payload=json.dumps(local_records).encode("utf-8"),
                    swarm_id=self.swarm_id,
                    apid=APID_AE_RESPONSE,
                    lamport_time=self.state_store.clock,
                )
                self._send_frame(resp_frame)
            # Request keys missing or newer on remote
            missing_keys = [k for k in divergent_keys if k in remote_leaves]
            if missing_keys:
                req_frame = CCSDSFrame(
                    node_id=self.node_id,
                    topic=f"__sys/ae_request/{frame.node_id}",
                    payload=json.dumps(missing_keys).encode("utf-8"),
                    swarm_id=self.swarm_id,
                    apid=APID_AE_REQUEST,
                    lamport_time=self.state_store.clock,
                )
                self._send_frame(req_frame)
        except Exception:
            pass

    def _handle_ae_request(self, frame: CCSDSFrame):
        """Replies to a repair request with the requested registers."""
        if frame.topic.endswith(f"/{self.node_id}") or frame.topic == "__sys/ae_request":
            try:
                requested_keys = json.loads(frame.payload.decode("utf-8"))
                records = self.state_store.get_registers_for_keys(requested_keys)
                if records:
                    resp_frame = CCSDSFrame(
                        node_id=self.node_id,
                        topic=f"__sys/ae_response/{frame.node_id}",
                        payload=json.dumps(records).encode("utf-8"),
                        swarm_id=self.swarm_id,
                        apid=APID_AE_RESPONSE,
                        lamport_time=self.state_store.clock,
                    )
                    self._send_frame(resp_frame)
            except Exception:
                pass

    def _handle_ae_response(self, frame: CCSDSFrame):
        """Batch merges repaired registers into local SwarmState."""
        if frame.topic.endswith(f"/{self.node_id}") or frame.topic == "__sys/ae_response":
            try:
                records = json.loads(frame.payload.decode("utf-8"))
                if isinstance(records, list) and records:
                    self.state_store.merge_batch(records)
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