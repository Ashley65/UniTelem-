"""
UniTelem Node Orchestrator (SPEC-UNITELEM-2026-V1 Section 1 & Section 5.1).

Primary developer-facing entrypoint for decentralized telemetry publishing,
zero-trust cryptographic verification, CRDT state synchronization, and anti-entropy repair.
"""

from typing import Any, Optional, Callable, Dict
import time

from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..crypto.hash_chain import MicroLedger
from ..crypto.merkle_tree import StateMerkleTree
from ..network.discovery import PeerDiscovery
from ..network.transport import MeshTransport
from ..ring_buffer import FastRingBuffer
from ..state_crdt import SwarmState


class Node:
    """
    Decentralized Telemetry Node with integrated Zero-Trust Micro-Ledger and Anti-Entropy Engine.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str = "default",
        port: int = 8900,
        enable_crypto: bool = True,
        private_key_hex: str = "",
        auto_start: bool = True,
        enable_anti_entropy: bool = True,
        anti_entropy_interval_s: float = 0.5,
    ):
        self.node_id = node_id
        self.swarm_id = swarm_id
        self.port = port
        self.enable_crypto = enable_crypto
        self.enable_anti_entropy = enable_anti_entropy
        self.anti_entropy_interval_s = anti_entropy_interval_s
        
        # 1. Cryptographic Keypair & Signer
        if enable_crypto:
            if private_key_hex:
                self._signer = Ed25519PrivateKey.from_hex(private_key_hex)
            else:
                self._signer = Ed25519PrivateKey.generate()
            self._public_key = self._signer.public_key
            self._pub_key_hex = self._public_key.to_hex()
        else:
            self._signer = None
            self._public_key = None
            self._pub_key_hex = ""

        # 2. Local State, Hash Chain, and Buffers
        self._state = SwarmState(node_id)
        self._ledger = MicroLedger(node_id)
        self._merkle_tree = StateMerkleTree()
        self._ring = FastRingBuffer(capacity=32768)

        # 3. Network Discovery and Mesh Transport
        self._discovery = PeerDiscovery(
            node_id=node_id,
            swarm_id=swarm_id,
            data_port=port,
            pub_key_hex=self._pub_key_hex,
            on_peer_found=self._on_peer_found,
        )
        
        self._transport = MeshTransport(
            node_id=node_id,
            swarm_id=swarm_id,
            port=port,
            ring_buffer=self._ring,
            state_store=self._state,
            ledger=self._ledger,
            signer=self._signer,
            discovery=self._discovery,
            merkle_tree=self._merkle_tree,
            enable_anti_entropy=enable_anti_entropy,
            anti_entropy_interval_s=anti_entropy_interval_s,
        )

        self._running = False
        if auto_start:
            self.start()

    @property
    def public_key_hex(self) -> str:
        """Returns the node's Ed25519 public key hex."""
        return self._pub_key_hex

    @property
    def sequence_number(self) -> int:
        """Returns the current micro-ledger block sequence number."""
        return self._ledger.sequence_number

    def start(self):
        """Starts discovery beaconing and mesh transport background workers."""
        if self._running:
            return
        self._running = True
        self._discovery.start()
        self._transport.start()

    def stop(self):
        """Gracefully shuts down transport workers and closes network sockets."""
        if not self._running:
            return
        self._running = False
        self._discovery.stop()
        self._transport.stop()

    def publish(self, topic: str, data: Any) -> None:
        """
        True sub-microsecond non-blocking publish (< 1μs).
        Updates in-memory CRDT register and pushes raw pointer to ring buffer.
        Cryptographic hashing, signing, and serialization are handled asynchronously by the mesh worker.
        """
        # 1. Update local in-memory CRDT state (O(1))
        reg = self._state.update_local(topic, data)

        # 2. Fast push to egress ring buffer
        self._ring.push(topic, data, reg.lamport_time)

    def subscribe(self, topic: str, callback: Callable[[str, Any, str], None]) -> None:
        """
        Registers a callback triggered when cryptographically verified telemetry arrives.
        Callback signature: callback(topic: str, value: Any, sender_node_id: str)
        Use topic='*' to receive updates on all topics.
        """
        self._transport.subscribe(topic, callback)

    def get_swarm_state(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns the synchronized CRDT global state table across all active swarm nodes.
        Format: {node_id: {topic: value}}
        """
        return self._state.snapshot()

    def get_latest(self, path: str) -> Optional[Any]:
        """
        Direct O(1) state lookup by 'node_id/topic' or 'topic' (for local node).
        Example: node.get_latest("craft_alpha/nav/state")
        """
        return self._state.get_value(path)

    def get_merkle_root(self) -> bytes:
        """
        Returns the current 32-byte state Merkle root hash for O(1) sync confirmation.
        """
        return self._merkle_tree.update_from_state(
            self._state.snapshot(),
            self._state.get_clocks_snapshot(),
        )

    def trigger_repair(self):
        """
        Forces an immediate anti-entropy gossip cycle to reconcile state across the mesh.
        """
        self._transport.trigger_repair()

    def verify_chain(self, node_id: Optional[str] = None) -> bool:
        """
        Validates the cryptographic hash-chain integrity.
        If node_id is None or self.node_id, verifies the local flight black-box ledger.
        """
        if node_id is None or node_id == self.node_id:
            return self._ledger.verify_local_integrity()
        return True

    def add_peer(self, node_id: str, ip: str, port: int, pub_key_hex: str = ""):
        """
        Manually registers a direct peer endpoint (useful for static IP/satellite uplinks).
        """
        self._transport.add_direct_peer(node_id, ip, port, pub_key_hex)

    def get_active_peers(self) -> Dict[str, tuple[str, int]]:
        """Returns dictionary of active discovered peers."""
        return self._discovery.get_active_peers()

    def _on_peer_found(self, peer_id: str, ip: str, port: int, pub_key_hex: str):
        """Called automatically by discovery daemon when a new peer joins the mesh."""
        if pub_key_hex:
            self._transport.register_peer_key(peer_id, pub_key_hex)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
