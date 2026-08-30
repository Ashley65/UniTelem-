"""
UDP Multicast Peer Auto-Discovery Daemon (SPEC-UNITELEM-2026-V1 Section 4.1).

Discovers neighbouring swarm nodes on localhost / LAN and exchanges Ed25519 public keys
without requiring central brokers or manual IP configuration.
"""

import json
import socket
import struct
import threading
import time
from typing import Dict, Tuple, Optional, Callable

MULTICAST_GROUP = "239.255.42.99"
DISCOVERY_PORT = 9999


class PeerDiscovery:
    """
    Automatic brokerless peer discovery using UDP Multicast beaconing.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str,
        data_port: int,
        pub_key_hex: str = "",
        on_peer_found: Optional[Callable[[str, str, int, str], None]] = None,
    ):
        self.node_id = node_id
        self.swarm_id = swarm_id
        self.data_port = data_port
        self.pub_key_hex = pub_key_hex
        self.on_peer_found = on_peer_found
        
        # node_id -> {"ip": str, "port": int, "pub_key": str, "last_seen": float}
        self.active_peers: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._running = False
        self._threads = []
        self._listen_sock: Optional[socket.socket] = None

    def start(self):
        """Starts background beacon broadcaster and listener daemon threads."""
        if self._running:
            return
        self._running = True
        
        t_beacon = threading.Thread(target=self._beacon_loop, name=f"Discovery-Beacon-{self.node_id}", daemon=True)
        t_listen = threading.Thread(target=self._listen_loop, name=f"Discovery-Listen-{self.node_id}", daemon=True)
        
        self._threads = [t_beacon, t_listen]
        t_beacon.start()
        t_listen.start()

    def stop(self):
        """Stops discovery loops and releases multicast sockets."""
        self._running = False
        if self._listen_sock:
            try:
                self._listen_sock.close()
            except Exception:
                pass

    def get_active_peers(self, timeout_s: float = 15.0) -> Dict[str, Tuple[str, int]]:
        """Returns currently active peers {node_id: (ip, port)} that have sent a heartbeat recently."""
        now = time.time()
        active = {}
        with self._lock:
            for peer_id, info in list(self.active_peers.items()):
                if now - info["last_seen"] <= timeout_s:
                    active[peer_id] = (info["ip"], info["port"])
        return active

    def get_peer_key(self, peer_id: str) -> Optional[str]:
        """Returns the stored Ed25519 public key hex for a discovered peer."""
        with self._lock:
            info = self.active_peers.get(peer_id)
            return info.get("pub_key") if info else None

    def _beacon_loop(self):
        """Broadcasts presence beacon every 1.5 seconds."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except Exception:
            pass

        while self._running:
            beacon_data = json.dumps({
                "node_id": self.node_id,
                "swarm_id": self.swarm_id,
                "port": self.data_port,
                "pub_key": self.pub_key_hex,
            }).encode("utf-8")
            
            try:
                sock.sendto(beacon_data, (MULTICAST_GROUP, DISCOVERY_PORT))
                # Also send to localhost broadcast fallback for isolated environments
                sock.sendto(beacon_data, ("127.0.0.1", DISCOVERY_PORT))
            except Exception:
                pass
            
            time.sleep(1.5)
        
        sock.close()

    def _listen_loop(self):
        """Listens for multicast beacons from other swarm nodes."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(("", DISCOVERY_PORT))
        except Exception:
            try:
                sock.bind(("0.0.0.0", DISCOVERY_PORT))
            except Exception:
                return

        # Join Multicast group
        try:
            mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception:
            pass

        sock.settimeout(1.0)
        self._listen_sock = sock

        while self._running:
            try:
                data, (sender_ip, _) = sock.recvfrom(2048)
                msg = json.loads(data.decode("utf-8"))
                
                swarm_id = msg.get("swarm_id")
                node_id = msg.get("node_id")
                port = int(msg.get("port", 0))
                pub_key = msg.get("pub_key", "")

                if swarm_id == self.swarm_id and node_id and node_id != self.node_id and port > 0:
                    effective_ip = "127.0.0.1" if sender_ip in ("0.0.0.0", "127.0.0.1") else sender_ip
                    is_new = False
                    with self._lock:
                        if node_id not in self.active_peers:
                            is_new = True
                        self.active_peers[node_id] = {
                            "ip": effective_ip,
                            "port": port,
                            "pub_key": pub_key,
                            "last_seen": time.time(),
                        }
                    if is_new and self.on_peer_found:
                        self.on_peer_found(node_id, effective_ip, port, pub_key)
            except socket.timeout:
                continue
            except Exception:
                continue

        try:
            sock.close()
        except Exception:
            pass