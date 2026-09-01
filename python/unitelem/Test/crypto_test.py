import unittest
import os
import time

from unitelem.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from unitelem.crypto.hash_chain import MicroLedger, PeerLedgerTracker, compute_digest
from unitelem.crypto.merkle_tree import StateMerkleTree


class TestEd25519(unittest.TestCase):
    def test_keypair_generation(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key
        self.assertEqual(len(priv.private_bytes()), 32)
        self.assertEqual(len(pub.public_bytes()), 32)

    def test_sign_and_verify_success(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key
        msg = b"Telecommand: Ignition sequence start"
        sig = priv.sign(msg)
        self.assertEqual(len(sig), 64)
        self.assertTrue(pub.verify(sig, msg))

    def test_tampered_message_rejected(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key
        msg = b"Altitude: 450.0m"
        sig = priv.sign(msg)
        tampered_msg = b"Altitude: 950.0m"
        self.assertFalse(pub.verify(sig, tampered_msg))

    def test_wrong_key_rejected(self):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        msg = b"Heartbeat"
        sig = priv1.sign(msg)
        self.assertFalse(priv2.public_key.verify(sig, msg))

    def test_hex_serialization_roundtrip(self):
        priv = Ed25519PrivateKey.generate()
        hex_priv = priv.to_hex()
        priv_restored = Ed25519PrivateKey.from_hex(hex_priv)
        self.assertEqual(priv.public_key.to_hex(), priv_restored.public_key.to_hex())


class TestMicroLedger(unittest.TestCase):
    def test_ledger_advancement(self):
        ledger = MicroLedger("craft_alpha")
        self.assertEqual(ledger.sequence_number, 0)
        self.assertEqual(ledger.last_digest, MicroLedger.GENESIS_HASH)

        e1 = ledger.append(1000, b'{"nav": 1}')
        self.assertEqual(e1.seq, 1)
        self.assertEqual(e1.prev_digest, MicroLedger.GENESIS_HASH)
        self.assertNotEqual(e1.digest, MicroLedger.GENESIS_HASH)

        e2 = ledger.append(2000, b'{"nav": 2}')
        self.assertEqual(e2.seq, 2)
        self.assertEqual(e2.prev_digest, e1.digest)

        self.assertTrue(ledger.verify_local_integrity())

    def test_peer_ledger_tracker_gap_detection(self):
        tracker = PeerLedgerTracker()
        peer_id = "drone_1"

        # Frame 1
        d0 = MicroLedger.GENESIS_HASH
        d1 = compute_digest(d0, 1, 1000, b"p1")
        ok, msg = tracker.record_incoming(peer_id, 1, 1000, d0, d1, b"p1")
        self.assertTrue(ok)
        self.assertIsNone(msg)

        # Skip Frame 2, send Frame 3
        d2 = compute_digest(d1, 2, 2000, b"p2")
        d3 = compute_digest(d2, 3, 3000, b"p3")
        ok, msg = tracker.record_incoming(peer_id, 3, 3000, d2, d3, b"p3")
        self.assertTrue(ok)
        self.assertIn("GAP_DETECTED", msg)


class TestMerkleTree(unittest.TestCase):
    def test_merkle_root_deterministic(self):
        tree1 = StateMerkleTree()
        tree2 = StateMerkleTree()

        state = {
            "node_1": {"battery": 98.5, "temp": 24.1},
            "node_2": {"fuel": 0.85},
        }

        r1 = tree1.update_from_state(state)
        r2 = tree2.update_from_state(state)
        self.assertEqual(r1, r2)
        self.assertEqual(len(r1), 32)

    def test_merkle_root_divergence(self):
        tree1 = StateMerkleTree()
        tree2 = StateMerkleTree()

        state1 = {"node_1": {"battery": 98.5}}
        state2 = {"node_1": {"battery": 50.0}}

        r1 = tree1.update_from_state(state1)
        r2 = tree2.update_from_state(state2)
        self.assertNotEqual(r1, r2)


if __name__ == "__main__":
    unittest.main()
