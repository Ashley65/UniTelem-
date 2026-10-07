"""
UniTelem: Universal Decentralized Telemetry SDK.
"""

from .Nodes.node import Node
from .Nodes.processorNode import ProcessorNode
from .Nodes.AI import AINode, AIAssignmentNode, AISafetySupervisorNode
from .ring_buffer import FastRingBuffer
from .EventThresholdFilter import EventThresholdFilter
from .state_crdt import SwarmState, LWWRegister
from .crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .crypto.hash_chain import MicroLedger
from .crypto.merkle_tree import StateMerkleTree
from .protocol.ccsds import CCSDSFrame
from .protocol.crc16 import compute_crc16, verify_crc16
from .network.pcap import (
    PcapWriter,
    PcapReader,
    PcapAnalyzer,
    PcapRecorder,
    PcapPacket,
    ConnectionFlow,
)

from .ai import (
    BaseModelRunner,
    FunctionModelRunner,
    ONNXModelRunner,
    create_model_runner,
    SafetyEnvelope,
    SimplexArbiter,
    VetoReason,
)

__version__ = "0.1.0"

__all__ = [
    "Node",
    "ProcessorNode",
    "AINode",
    "AIAssignmentNode",
    "AISafetySupervisorNode",
    "FastRingBuffer",
    "EventThresholdFilter",
    "SwarmState",
    "LWWRegister",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "MicroLedger",
    "StateMerkleTree",
    "CCSDSFrame",
    "compute_crc16",
    "verify_crc16",
    "SafetyEnvelope",
    "SimplexArbiter",
    "VetoReason",
    "BaseModelRunner",
    "FunctionModelRunner",
    "ONNXModelRunner",
    "create_model_runner",
    "PcapWriter",
    "PcapReader",
    "PcapAnalyzer",
    "PcapRecorder",
    "PcapPacket",
    "ConnectionFlow",
]
