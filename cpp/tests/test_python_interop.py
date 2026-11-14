import os
import subprocess
import sys
import time
import types

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PY_ROOT = os.path.join(REPO_ROOT, "python")

# Register package namespace without executing python/__init__.py (which references missing network.pcap)
pkg = types.ModuleType("unitelem_py")
pkg.__path__ = [PY_ROOT]
sys.modules["unitelem_py"] = pkg

from unitelem_py.crypto.ed25519 import Ed25519PrivateKey
from unitelem_py.crypto.hash_chain import compute_digest
from unitelem_py.crypto.merkle_tree import StateMerkleTree
from unitelem_py.protocol.ccsds import CCSDSFrame, APID_TELEMETRY
from unitelem_py.Nodes.node import Node


def test_python_to_cpp_frame(helper: str) -> None:
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key.to_hex()
    prev = bytes(range(16))
    payload = b'{"altitude":123.5}'
    seq = 20000  # > 16383 to exercise 64-bit seq across 14-bit wrap boundary
    ts_ns = 1700000000999888777

    frame = CCSDSFrame(
        node_id="py_drone_1",
        topic="nav/alt",
        payload=payload,
        seq=seq,
        swarm_id="interop_swarm",
        timestamp_ns=ts_ns,
        prev_hash=prev,
        apid=APID_TELEMETRY,
        lamport_time=42,
    )
    frame.signature = sk.sign(frame.signable_bytes())
    wire = frame.pack()
    digest = compute_digest(prev, seq, ts_ns, payload)

    out = subprocess.check_output(
        [helper, "verify_frame", wire.hex(), pk_hex, digest.hex()],
        text=True,
    ).strip()
    assert out == f"{seq}|nav/alt|{payload.decode('utf-8')}", f"Unexpected output: {out}"


def test_cpp_to_python_frame(helper: str) -> None:
    sk = Ed25519PrivateKey.generate()
    out = subprocess.check_output(
        [
            helper,
            "make_frame",
            sk.to_hex(),
            "50000",
            "interop_swarm",
            "cpp_drone_1",
            "imu/gyro",
            '{"gx":0.5}',
        ],
        text=True,
    ).strip()
    wire_hex, exp_dig_hex = out.split("|")
    wire = bytes.fromhex(wire_hex)

    frame = CCSDSFrame.unpack(wire)
    assert frame is not None, "CCSDSFrame.unpack failed on C++ frame"
    assert frame.seq == 50000
    assert frame.node_id == "cpp_drone_1"
    assert frame.topic == "imu/gyro"
    assert frame.payload == b'{"gx":0.5}'
    assert sk.public_key.verify(frame.signature, frame.signable_bytes()), "Ed25519 verify failed"

    dig = compute_digest(frame.prev_hash, frame.seq, frame.timestamp_ns, frame.payload)
    assert dig.hex() == exp_dig_hex


def test_merkle_root_parity(helper: str) -> None:
    cpp_root = subprocess.check_output([helper, "merkle_test"], text=True).strip()
    tree = StateMerkleTree()
    snap = {
        "n1": {"cfg": {"z": 10, "a": [1, True, "hi"]}, "flag": True},
        "n2": {"val": 3.5, "msg": "hello"},
    }
    clocks = {
        "n1": {"cfg": 4, "flag": 2},
        "n2": {"val": 9, "msg": 1},
    }
    py_root = tree.update_from_state(snap, clocks).hex()
    assert cpp_root == py_root, f"Merkle mismatch: cpp={cpp_root} py={py_root}"


def test_live_udp_interop(helper: str) -> None:
    py_node = Node(
        node_id="py_node",
        swarm_id="interop_swarm",
        port=19871,
        enable_crypto=True,
        auto_start=False,
        enable_anti_entropy=True,
        anti_entropy_interval_s=0.15,
    )
    py_node._discovery.stop()
    py_node._transport.start()
    py_node._running = True

    proc = subprocess.Popen(
        [helper, "live_node", "19872", "py_node", "19871", py_node.public_key_hex],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready_line = proc.stdout.readline().strip()
        assert ready_line.startswith("READY "), f"Expected READY, got {ready_line!r}"
        _, cpp_port_s, cpp_pk_hex = ready_line.split()
        cpp_port = int(cpp_port_s)

        py_node.add_peer("cpp_node", "127.0.0.1", cpp_port, cpp_pk_hex)
        py_node.publish("py/ping", {"hello": "cpp", "n": 123})

        got_line = proc.stdout.readline().strip()
        assert got_line.startswith("GOT "), f"Expected GOT, got {got_line!r}"

        # Wait for C++ status to reach Python
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if py_node.get_latest("cpp_node/cpp/status") is not None:
                break
            time.sleep(0.05)

        cpp_status = py_node.get_latest("cpp_node/cpp/status")
        assert cpp_status == {"ok": True, "id": 7}, f"Unexpected cpp_status: {cpp_status!r}"

        root_line = proc.stdout.readline().strip()
        assert root_line.startswith("ROOT "), f"Expected ROOT, got {root_line!r}"
        cpp_root = root_line.split()[1]
        py_root = py_node.get_merkle_root().hex()
        assert cpp_root == py_root, f"Live Merkle root mismatch: cpp={cpp_root} py={py_root}"

        rc = proc.wait(timeout=3.0)
        assert rc == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        py_node._transport.stop()


def test_c11_live_interop(c_bin: str) -> None:
    py_node = Node(
        node_id="py_node",
        swarm_id="c_py_swarm",
        port=19873,
        enable_crypto=True,
        auto_start=False,
        enable_anti_entropy=True,
        anti_entropy_interval_s=0.15,
    )
    py_rx = []
    py_node.subscribe("c/*", lambda topic, val, sender: py_rx.append((topic, val, sender)))
    # Publish pre-peer state so Anti-Entropy must repair it to C11 node
    py_node.publish("py/pre_peer", {"source": "python", "seq_check": True})
    py_node._transport.start()
    py_node._running = True

    proc = subprocess.Popen(
        [c_bin, "direct", "py_node", "19873", py_node.public_key_hex],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready_line = proc.stdout.readline().strip()
        assert ready_line.startswith("READY "), f"Expected READY, got {ready_line!r}"
        _, c_port_s, c_pk_hex = ready_line.split()
        c_port = int(c_port_s)

        py_node.add_peer("c_node", "127.0.0.1", c_port, c_pk_hex)
        py_node.publish("py/telemetry", {"temp": 36.5, "ok": True})

        out, err = proc.communicate(timeout=8.0)
        assert proc.returncode == 0, f"c_interop_node failed (rc={proc.returncode}):\n{out}\n{err}"
        print(out.strip())

        # Verify Python received both C11 pre-peer boot state and live telemetry
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if (
                py_node.get_latest("c_node/c/boot") is not None
                and py_node.get_latest("c_node/c/telemetry") is not None
            ):
                break
            time.sleep(0.05)

        assert py_node.get_latest("c_node/c/boot") == {"phase": "pre_peer", "ready": True}
        assert py_node.get_latest("c_node/c/telemetry") == {"alt": 42.5, "ok": True}

        merkle_lines = [ln for ln in out.splitlines() if ln.startswith("C_MERKLE ")]
        assert merkle_lines, f"Missing C_MERKLE in output:\n{out}"
        c_merkle = merkle_lines[0].split()[1]
        py_merkle = py_node.get_merkle_root().hex()
        assert c_merkle == py_merkle, f"C11 <-> Python Merkle mismatch: c={c_merkle} py={py_merkle}"
        assert "C_CHAIN_VALID 1" in out
    finally:
        if proc.poll() is None:
            proc.kill()
        py_node._transport.stop()


def main() -> None:
    helper = sys.argv[1]
    c_bin = sys.argv[2] if len(sys.argv) > 2 else None
    test_python_to_cpp_frame(helper)
    test_cpp_to_python_frame(helper)
    test_merkle_root_parity(helper)
    test_live_udp_interop(helper)
    if c_bin:
        test_c11_live_interop(c_bin)
    print("test_python_interop passed")


if __name__ == "__main__":
    main()

