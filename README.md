# UniTelem: Universal Decentralized Telemetry SDK
[![Language](https://img.shields.io/badge/Language-C%2B%2B20%20%7C%20Python%203.10%2B%20%7C%20Ada%202012-blue.svg)](#)
[![P2P Mesh](https://img.shields.io/badge/Network-ZeroMQ%20%2F%20UDP%20P2P-orange.svg)](#)


> **A drop-in, zero-friction, decentralized telemetry and state-sharing library designed to be placed in any robotics, simulation, AI agent, or game engine project without worries.**>

---

##  Why UniTelem?
Most telemetry and state-sharing tools require external servers (Redis, MQTT brokers, databases) or introduce blocking latency that degrades real-time physics loops and AI inference.
`UniTelem` is designed around **three zero-worry guarantees**:
1. **Zero External Infrastructure:** Fully brokenness P2P mesh network with automatic peer discovery on `localhost` or LAN.
2. **Zero Performance Hit:** Lock-free, non-blocking ring buffer architecture (1 μs publish latency).
3. **Zero Crash Vulnerability:** Hardened against network splits, packet drops, and malformed inputs with CRC-16 checks and Conflict-Free Replicated Data Types (**CvRDT**).


```
   Your Game / Sim (C++/CUDA)       AI Agent (Python)        Firmware / Drone (Ada)
               │                            │                           │
               │ node.publish(...)          │ node.subscribe(...)       │ node.publish(...)
               ▼                            ▼                           ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                           `UniTelem` Engine Core                            │
  │  ┌─────────────────────────┐               ┌─────────────────────────────┐  │
  │  │ Lock-Free Circular Ring │  (Non-block)  │ Peer Auto-Discovery Daemon  │  │
  │  │ Buffer (< 1μs publish)  │──────────────►│ (UDP Multicast / ZeroMQ)    │  │
  │  └─────────────────────────┘               └──────────────┬──────────────┘  │
  └───────────────────────────────────────────────────────────┼─────────────────┘
                                                              ▼ (P2P Mesh)
                                                   [ Local Network / Mesh ]
```
---

## Features
* **Multi-Protocol Serialization:** Supports both human-readable JSON (for rapid prototyping/debugging) and binary **CCSDS Space Packet Protocol** with CRC-16 (for high-efficiency bandwidth-constrained links).
* **Automatic Peer Discovery:** Zero manual IP configuration. Nodes discover each other via UDP multicast beacons or ZeroMQ ad-hoc discovery.
* **Eventual Consistency via CRDTs:** State-based Conflict-Free Replicated Data Types automatically resolve out-of-order delivery and network reconnects without centralized master nodes.
* **Embedded Live Web Dashboard:** Start a real-time web telemetry inspector with one line:
  ```python
  node.start_dashboard(port=8080)
  ```
  Open `http://localhost:8080` in any browser to inspect live graphs, node heartbeats, and latency metrics.
---
