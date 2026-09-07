"""
Conflict-Free Replicated Data Types (CvRDT) State Store (SPEC-UNITELEM-2026-V1 Section 4.2).

Implements Last-Write-Wins Multi-Value Register (LWW-Register) with Lamport Logical Clocks.
Guarantees mathematical eventual consistency across partitioned, asynchronous peer meshes.
"""

import threading
import time
from typing import Dict, Any, Optional, List


class LWWRegister:
    """Last-Write-Wins Register with Lamport and Wall clock tie-breakers."""

    __slots__ = ("value", "lamport_time", "wall_time")

    def __init__(self, value: Any = None, lamport_time: int = 0, wall_time: float = 0.0):
        self.value = value
        self.lamport_time = lamport_time
        self.wall_time = wall_time

    def merge(self, other: "LWWRegister") -> bool:
        """
        Deterministically merge conflicting state updates.
        Returns True if the register was updated with newer state.
        """
        if (other.lamport_time, other.wall_time) > (self.lamport_time, self.wall_time):
            self.value = other.value
            self.lamport_time = other.lamport_time
            self.wall_time = other.wall_time
            return True
        return False

    def __repr__(self) -> str:
        return f"<LWWRegister val={self.value!r} l_ts={self.lamport_time}>"


class SwarmState:
    """
    Thread-safe, decentralized Swarm State store backed by LWW-Registers.
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self._state: Dict[str, Dict[str, LWWRegister]] = {}  # {node_id: {topic: LWWRegister}}
        self._clock = 0
        self._lock = threading.Lock()

    @property
    def clock(self) -> int:
        with self._lock:
            return self._clock

    def update_local(self, topic: str, value: Any) -> LWWRegister:
        """
        Updates local state register with an incremented Lamport timestamp.
        Returns the updated LWWRegister.
        """
        with self._lock:
            self._clock += 1
            now_wall = time.time()
            reg = LWWRegister(value=value, lamport_time=self._clock, wall_time=now_wall)
            self._state.setdefault(self.node_id, {})[topic] = reg
            return reg

    def merge_remote(self, node_id: str, topic: str, value: Any, lamport_time: int, wall_time: float = 0.0) -> bool:
        """
        Merges an incoming remote state update into the local state table.
        Returns True if local state was created or updated with a strictly newer value.
        """
        with self._lock:
            self._clock = max(self._clock, lamport_time) + 1
            remote_reg = LWWRegister(value=value, lamport_time=lamport_time, wall_time=wall_time)
            node_topics = self._state.setdefault(node_id, {})
            
            if topic not in node_topics:
                node_topics[topic] = remote_reg
                return True
            else:
                return node_topics[topic].merge(remote_reg)

    def merge_batch(self, records: List[Dict[str, Any]]) -> int:
        """
        Merges a batch of state records (used during Anti-Entropy repair).
        Returns the number of registers updated.
        """
        updated_count = 0
        with self._lock:
            for rec in records:
                node_id = rec["node_id"]
                topic = rec["topic"]
                val = rec["value"]
                l_ts = rec["lamport_time"]
                w_ts = rec.get("wall_time", 0.0)

                self._clock = max(self._clock, l_ts) + 1
                remote_reg = LWWRegister(value=val, lamport_time=l_ts, wall_time=w_ts)
                node_topics = self._state.setdefault(node_id, {})

                if topic not in node_topics:
                    node_topics[topic] = remote_reg
                    updated_count += 1
                elif node_topics[topic].merge(remote_reg):
                    updated_count += 1
        return updated_count

    def get_registers_for_keys(self, keys: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieves full register data for requested keys formatted as 'node_id:topic'.
        """
        results = []
        with self._lock:
            for key in keys:
                if ":" in key:
                    node_id, topic = key.split(":", 1)
                elif "/" in key:
                    node_id, topic = key.split("/", 1)
                else:
                    node_id, topic = self.node_id, key

                node_topics = self._state.get(node_id)
                if node_topics and topic in node_topics:
                    reg = node_topics[topic]
                    results.append({
                        "node_id": node_id,
                        "topic": topic,
                        "value": reg.value,
                        "lamport_time": reg.lamport_time,
                        "wall_time": reg.wall_time,
                    })
        return results

    def get_value(self, path: str) -> Optional[Any]:
        """
        Direct O(1) state lookup.
        Supports both 'node_id/topic/subtopic' or 'topic/subtopic' (for local node).
        """
        with self._lock:
            # 1. Check if path starts with a known remote node_id
            if "/" in path:
                parts = path.split("/", 1)
                potential_node = parts[0]
                potential_topic = parts[1]
                if potential_node in self._state and potential_topic in self._state[potential_node]:
                    return self._state[potential_node][potential_topic].value

            # 2. Check local node topics
            local_state = self._state.get(self.node_id)
            if local_state and path in local_state:
                return local_state[path].value

            # 3. Fallback: check if entire path exists as a key in any node
            if "/" in path:
                potential_node, potential_topic = path.split("/", 1)
                if potential_node in self._state and path in self._state[potential_node]:
                    return self._state[potential_node][path].value

            return None

    def get_register(self, node_id: str, topic: str) -> Optional[LWWRegister]:
        """Returns a copy of the LWWRegister for a specific node and topic."""
        with self._lock:
            node_state = self._state.get(node_id)
            if node_state and topic in node_state:
                reg = node_state[topic]
                return LWWRegister(reg.value, reg.lamport_time, reg.wall_time)
            return None

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns a complete copy of the synchronized global swarm view.
        """
        with self._lock:
            return {
                nid: {k: reg.value for k, reg in topics.items()}
                for nid, topics in self._state.items()
            }

    def get_clocks_snapshot(self) -> Dict[str, Dict[str, int]]:
        """Returns a snapshot of Lamport timestamps for Merkle tree calculation."""
        with self._lock:
            return {
                nid: {k: reg.lamport_time for k, reg in topics.items()}
                for nid, topics in self._state.items()
            }