"""
UniTelem: Universal Decentralized Telemetry SDK.
"""

from .node import Node
from .ring_buffer import FastRingBuffer
from .state_crdt import SwarmState, LWWRegister
from .crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .crypto.hash_chain import MicroLedger
from .crypto.merkle_tree import StateMerkleTree
from .protocol.ccsds import CCSDSFrame
from .protocol.crc16 import compute_crc16, verify_crc16

__version__ = "0.1.0"

__all__ = [
    "Node",
    "FastRingBuffer",
    "SwarmState",
    "LWWRegister",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "MicroLedger",
    "StateMerkleTree",
    "CCSDSFrame",
    "compute_crc16",
    "verify_crc16",
]
