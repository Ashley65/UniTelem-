import unittest
import time

from unitelem.node import Node


class TestAntiEntropyGossip(unittest.TestCase):
    def test_quiet_topic_dropped_packet_healing(self):
        """
        Simulates 100% loss of initial broadcast for a quiet topic.
        Verifies that Anti-Entropy Merkle gossip recovers the missing state.
        """
        port1 = 19101
        port2 = 19102

        node_a = Node(node_id="craft_a", swarm_id="ae_test", port=port1, enable_crypto=True, anti_entropy_interval_s=0.2)
        node_b = Node(node_id="craft_b", swarm_id="ae_test", port=port2, enable_crypto=True, anti_entropy_interval_s=0.2)

        try:
            node_a.add_peer("craft_b", "127.0.0.1", port2, node_b.public_key_hex)
            node_b.add_peer("craft_a", "127.0.0.1", port1, node_a.public_key_hex)

            # Manually inject state on Node A (simulating that the initial publish broadcast was dropped on wire)
            node_a._state.update_local("mission/abort_code", 999)
            
            # Verify Node B does not have it yet
            self.assertIsNone(node_b.get_latest("craft_a/mission/abort_code"))
            self.assertNotEqual(node_a.get_merkle_root(), node_b.get_merkle_root())

            # Trigger Anti-Entropy Gossip repair
            node_a.trigger_repair()

            # Wait for anti-entropy digest exchange and register merge
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if node_b.get_latest("craft_a/mission/abort_code") == 999:
                    break
                time.sleep(0.05)

            # Verify Node B successfully healed the missing state
            recovered_val = node_b.get_latest("craft_a/mission/abort_code")
            self.assertEqual(recovered_val, 999, "Anti-Entropy failed to heal dropped state on Node B")

            # Verify Merkle roots now match 100%
            self.assertEqual(node_a.get_merkle_root(), node_b.get_merkle_root())

        finally:
            node_a.stop()
            node_b.stop()

    def test_two_way_asymmetric_divergence_reconciliation(self):
        """
        Node A has unique state X, Node B has unique state Y.
        Anti-Entropy should reconcile both directions simultaneously.
        """
        port1 = 19103
        port2 = 19104

        node_a = Node(node_id="rover_1", swarm_id="ae_mesh", port=port1, enable_crypto=True, anti_entropy_interval_s=0.2)
        node_b = Node(node_id="rover_2", swarm_id="ae_mesh", port=port2, enable_crypto=True, anti_entropy_interval_s=0.2)

        try:
            node_a.add_peer("rover_2", "127.0.0.1", port2, node_b.public_key_hex)
            node_b.add_peer("rover_1", "127.0.0.1", port1, node_a.public_key_hex)

            # Node A updates local state
            node_a._state.update_local("sensors/lidar", {"obstacles": 2})
            # Node B updates local state
            node_b._state.update_local("sensors/radar", {"range_m": 45.0})

            # Force anti-entropy gossip repair
            node_a.trigger_repair()
            node_b.trigger_repair()

            deadline = time.time() + 2.5
            while time.time() < deadline:
                a_has_b = node_a.get_latest("rover_2/sensors/radar") is not None
                b_has_a = node_b.get_latest("rover_1/sensors/lidar") is not None
                if a_has_b and b_has_a:
                    break
                time.sleep(0.05)

            self.assertEqual(node_a.get_latest("rover_2/sensors/radar")["range_m"], 45.0)
            self.assertEqual(node_b.get_latest("rover_1/sensors/lidar")["obstacles"], 2)
            self.assertEqual(node_a.get_merkle_root(), node_b.get_merkle_root())

        finally:
            node_a.stop()
            node_b.stop()


if __name__ == "__main__":
    unittest.main()
