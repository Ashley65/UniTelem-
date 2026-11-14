#include "unitelem/unitelem.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

static std::vector<std::uint8_t> hex_to_bytes(const std::string &hex) {
    std::vector<std::uint8_t> out(hex.size() / 2);
    std::size_t n = 0;
    if (ut_hex_decode(hex.c_str(), hex.size(), out.data(), out.size(), &n) != UT_OK) {
        throw std::runtime_error("invalid hex");
    }
    out.resize(n);
    return out;
}

static std::string bytes_to_hex(const std::uint8_t *data, std::size_t len) {
    std::string out(len * 2 + 1, '\0');
    ut_hex_encode(data, len, out.data(), out.size());
    out.pop_back();
    return out;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: interop_helper <mode> ...\n";
        return 2;
    }
    std::string mode = argv[1];

    if (mode == "verify_frame") {
        // args: <wire_hex> <pk_hex> <expected_digest_hex>
        auto wire = hex_to_bytes(argv[2]);
        auto pk   = hex_to_bytes(argv[3]);
        auto exp_dig = hex_to_bytes(argv[4]);

        ut_ccsds_frame_t frame{};
        if (ut_ccsds_unpack(wire.data(), wire.size(), &frame) != UT_OK) {
            std::cerr << "ut_ccsds_unpack failed\n";
            return 1;
        }
        std::vector<std::uint8_t> sign_buf(frame.topic_len + frame.payload_len + 128);
        std::size_t sign_len = 0;
        if (ut_ccsds_signable_bytes(&frame, sign_buf.data(), sign_buf.size(), &sign_len) != UT_OK) {
            std::cerr << "signable_bytes failed\n";
            return 1;
        }
        if (ut_ed25519_verify(pk.data(), sign_buf.data(), sign_len, frame.signature) != UT_OK) {
            std::cerr << "ed25519_verify failed\n";
            return 1;
        }
        std::uint8_t dig[UT_DIGEST_SIZE];
        if (ut_compute_digest(frame.prev_hash, frame.seq, frame.timestamp_ns,
                              frame.payload, frame.payload_len, dig) != UT_OK) {
            std::cerr << "compute_digest failed\n";
            return 1;
        }
        if (std::memcmp(dig, exp_dig.data(), UT_DIGEST_SIZE) != 0) {
            std::cerr << "digest mismatch\n";
            return 1;
        }
        std::cout << frame.seq << "|" << std::string(frame.topic, frame.topic_len) << "|"
                  << std::string(reinterpret_cast<const char *>(frame.payload), frame.payload_len)
                  << "\n";
        return 0;
    }

    if (mode == "make_frame") {
        // args: <seed_hex> <seq> <swarm_id> <node_id> <topic> <payload>
        auto seed = hex_to_bytes(argv[2]);
        std::uint64_t seq = std::stoull(argv[3]);
        std::string swarm_id = argv[4];
        std::string node_id = argv[5];
        std::string topic = argv[6];
        std::string payload = argv[7];

        ut_ccsds_frame_t frame{};
        frame.apid = UT_APID_TELEMETRY;
        frame.seq = seq;
        frame.swarm_hash = ut_ccsds_swarm_hash(swarm_id.c_str(), swarm_id.size());
        std::strncpy(frame.node_id, node_id.c_str(), UT_NODE_ID_MAX);
        frame.timestamp_ns = 1700000000123456789ULL;
        std::memset(frame.prev_hash, 0x22, UT_DIGEST_SIZE);
        frame.lamport_time = 77;
        frame.topic = topic.c_str();
        frame.topic_len = topic.size();
        frame.payload = reinterpret_cast<const std::uint8_t *>(payload.data());
        frame.payload_len = payload.size();

        std::vector<std::uint8_t> sign_buf(topic.size() + payload.size() + 128);
        std::size_t sign_len = 0;
        if (ut_ccsds_signable_bytes(&frame, sign_buf.data(), sign_buf.size(), &sign_len) != UT_OK ||
            ut_ed25519_sign(seed.data(), sign_buf.data(), sign_len, frame.signature) != UT_OK) {
            return 1;
        }
        std::vector<std::uint8_t> wire(topic.size() + payload.size() + 256);
        std::size_t wire_len = 0;
        if (ut_ccsds_pack(&frame, wire.data(), wire.size(), &wire_len) != UT_OK) {
            return 1;
        }
        std::uint8_t dig[UT_DIGEST_SIZE];
        if (ut_compute_digest(frame.prev_hash, frame.seq, frame.timestamp_ns,
                              frame.payload, frame.payload_len, dig) != UT_OK) {
            return 1;
        }
        std::cout << bytes_to_hex(wire.data(), wire_len) << "|"
                  << bytes_to_hex(dig, UT_DIGEST_SIZE) << "\n";
        return 0;
    }

    if (mode == "merkle_test") {
        // Builds fixed test state and prints Merkle root hex
        ut_swarm_state_t st;
        ut_swarm_state_init(&st, "n1");
        bool upd = false;
        const char *v1 = R"({"z": 10, "a": [1, true, "hi"]})";
        const char *v2 = "true";
        const char *v3 = "3.5";
        const char *v4 = "\"hello\"";
        ut_swarm_state_merge_remote(&st, "n1", "cfg", reinterpret_cast<const std::uint8_t *>(v1),
                                    std::strlen(v1), true, 4, 1.0, &upd);
        ut_swarm_state_merge_remote(&st, "n1", "flag", reinterpret_cast<const std::uint8_t *>(v2),
                                    std::strlen(v2), true, 2, 1.0, &upd);
        ut_swarm_state_merge_remote(&st, "n2", "val", reinterpret_cast<const std::uint8_t *>(v3),
                                    std::strlen(v3), true, 9, 1.0, &upd);
        ut_swarm_state_merge_remote(&st, "n2", "msg", reinterpret_cast<const std::uint8_t *>(v4),
                                    std::strlen(v4), true, 1, 1.0, &upd);

        ut_merkle_tree_t tree;
        ut_merkle_tree_init(&tree);
        ut_swarm_state_compute_merkle(&st, &tree);
        std::cout << bytes_to_hex(tree.root, UT_SHA256_SIZE) << "\n";
        ut_merkle_tree_destroy(&tree);
        ut_swarm_state_destroy(&st);
        return 0;
    }

    if (mode == "live_node") {
        // args: <cpp_port> <py_node_id> <py_port> <py_pk_hex>
        std::uint16_t cpp_port = static_cast<std::uint16_t>(std::stoi(argv[2]));
        std::string py_id = argv[3];
        std::uint16_t py_port = static_cast<std::uint16_t>(std::stoi(argv[4]));
        std::string py_pk = argv[5];

        unitelem::NodeOptions opts;
        opts.swarm_id = "interop_swarm";
        opts.port = cpp_port;
        opts.enable_crypto = true;
        opts.enable_discovery = false;
        opts.enable_anti_entropy = true;
        opts.anti_entropy_interval_s = 0.15;

        unitelem::Node node("cpp_node", opts);
        node.add_peer(py_id, "127.0.0.1", py_port, py_pk);

        std::cout << "READY " << node.port() << " " << node.public_key_hex() << std::endl;

        node.publish_json("cpp/status", R"({"ok":true,"id":7})");

        for (int i = 0; i < 60; ++i) {
            auto py_val = node.get_latest(py_id + "/py/ping");
            if (py_val.has_value()) {
                std::cout << "GOT " << *py_val << std::endl;
                // Wait briefly so AE converges both directions
                std::this_thread::sleep_for(std::chrono::milliseconds(400));
                auto root = node.get_merkle_root();
                std::cout << "ROOT " << bytes_to_hex(root.data(), root.size()) << std::endl;
                return 0;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        std::cerr << "Timeout waiting for Python telemetry\n";
        return 1;
    }

    return 2;
}
