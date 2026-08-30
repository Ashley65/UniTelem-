import unittest
import time
import socket

from ..node import Node


class TestNodeIntegration(unittest.TestCase):
    def test_node_local_operations(self):
        with Node(node_id="craft_alpha", port=18901, auto_start=False) as node:
            node.publish("nav/state", {"x": 10.0, "y": 20.0, "fuel": 0.95})
            
            # Direct O(1) read
            val = node.get_latest("nav/state")
            self.assertIsNotNone(val)
            self.assertEqual(val["fuel"], 0.95)

            # Swarm state snapshot
            swarm = node.get_swarm_state()
            self.assertIn("craft_alpha", swarm)
            self.assertIn("nav/state", swarm["craft_alpha"])

            # Merkle root calculation
            m_root = node.get_merkle_root()
            self.assertEqual(len(m_root), 32)

            # Local ledger integrity check
            self.assertTrue(node.verify_chain())

    def test_p2p_mesh_cryptographic_sync(self):
        # Spin up two nodes with direct peer linkage
        port1 = 18910
        port2 = 18911

        node1 = Node(node_id="craft_1", swarm_id="mesh_test", port=port1, enable_crypto=True, auto_start=True)
        node2 = Node(node_id="craft_2", swarm_id="mesh_test", port=port2, enable_crypto=True, auto_start=True)

        try:
            # Pair them as direct peers with their public keys
            node1.add_peer("craft_2", "127.0.0.1", port2, node2.public_key_hex)
            node2.add_peer("craft_1", "127.0.0.1", port1, node1.public_key_hex)

            received_events = []
            def on_nav(topic, data, sender):
                received_events.append((topic, data, sender))

            node2.subscribe("nav/heading", on_nav)

            # Publish from node1
            node1.publish("nav/heading", {"yaw": 182.4, "speed": 12.5})

            # Give worker thread time to process and transmit over UDP
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if node2.get_latest("craft_1/nav/heading") is not None:
                    break
                time.sleep(0.02)

            # Verify Node2 received and merged Node1's cryptographically verified telemetry
            node2_view = node2.get_latest("craft_1/nav/heading")
            self.assertIsNotNone(node2_view, "Node2 did not receive telemetry from Node1")
            self.assertEqual(node2_view["yaw"], 182.4)
            self.assertEqual(node2_view["speed"], 12.5)

            # Verify callback fired
            self.assertTrue(len(received_events) > 0)
            self.assertEqual(received_events[0][0], "nav/heading")
            self.assertEqual(received_events[0][2], "craft_1")

        finally:
            node1.stop()
            node2.stop()


if __name__ == "__main__":
    unittest.main()
