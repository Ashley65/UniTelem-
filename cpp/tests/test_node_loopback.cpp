#include "unitelem/unitelem.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

int main() {
    unitelem::NodeOptions opts_a;
    opts_a.swarm_id = "loopback_test";
    opts_a.port = 0; /* ephemeral */
    opts_a.enable_crypto = true;
    opts_a.enable_discovery = false;
    opts_a.enable_anti_entropy = true;
    opts_a.anti_entropy_interval_s = 0.15;

    unitelem::NodeOptions opts_b = opts_a;

    unitelem::Node node_a("node_alpha", opts_a);
    unitelem::Node node_b("node_beta", opts_b);

    std::atomic<int> recv_count{0};
    std::string last_val;
    node_b.subscribe("sensors/*", [&](std::string_view topic, std::span<const std::uint8_t> payload,
                                      bool is_json, std::string_view sender) {
        (void)is_json;
        if (topic == "sensors/temp" && sender == "node_alpha") {
            last_val.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
            recv_count.fetch_add(1);
        }
    });

    /* Publish state BEFORE peering so anti-entropy must repair node_b */
    node_a.publish_json("state/boot", R"({"ok":true})");

    node_a.add_peer("node_beta", "127.0.0.1", node_b.port(), node_b.public_key_hex());
    node_b.add_peer("node_alpha", "127.0.0.1", node_a.port(), node_a.public_key_hex());

    /* Live telemetry frame */
    node_a.publish_json("sensors/temp", "24.75");

    for (int i = 0; i < 40; ++i) {
        if (recv_count.load() >= 1 &&
            node_b.get_latest("node_alpha/state/boot").has_value() &&
            node_a.get_merkle_root() == node_b.get_merkle_root()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    assert(recv_count.load() >= 1);
    assert(last_val == "24.75");
    auto b_temp = node_b.get_latest("node_alpha/sensors/temp");
    assert(b_temp.has_value() && *b_temp == "24.75");
    auto b_boot = node_b.get_latest("node_alpha/state/boot");
    assert(b_boot.has_value());
    assert(node_a.get_merkle_root() == node_b.get_merkle_root());
    assert(node_a.verify_chain());
    assert(node_b.verify_chain());

    std::printf("test_node_loopback passed\n");
    return 0;
}
