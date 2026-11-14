#pragma once

#include "unitelem/ring_buffer.hpp"
#include "unitelem/unitelem.h"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace unitelem {

struct NodeOptions {
    std::string swarm_id = "default";
    std::uint16_t port = 8900;
    bool enable_crypto = true;
    bool require_pinned_keys = false;
    std::string private_key_hex;
    bool auto_start = true;
    bool enable_discovery = true;
    bool enable_anti_entropy = true;
    double anti_entropy_interval_s = 0.5;
    std::size_t ring_capacity = 32768;
    bool ring_auto_expand = false;
    std::size_t ledger_history = 10000;
};

class Node {
public:
    using SubscribeCallback = std::function<void(
        std::string_view topic,
        std::span<const std::uint8_t> payload,
        bool is_json,
        std::string_view sender_node_id
    )>;

    explicit Node(std::string_view node_id, const NodeOptions &opts = {}) {
        std::string nid(node_id);
        ut_node_config_t cfg = ut_node_config_default(nid.c_str());
        cfg.swarm_id = opts.swarm_id.c_str();
        cfg.port = opts.port;
        cfg.enable_crypto = opts.enable_crypto;
        cfg.require_pinned_keys = opts.require_pinned_keys;
        cfg.private_key_hex = opts.private_key_hex.empty() ? nullptr : opts.private_key_hex.c_str();
        cfg.auto_start = opts.auto_start;
        cfg.enable_discovery = opts.enable_discovery;
        cfg.enable_anti_entropy = opts.enable_anti_entropy;
        cfg.anti_entropy_interval_s = opts.anti_entropy_interval_s;
        cfg.ring_capacity = opts.ring_capacity;
        cfg.ring_auto_expand = opts.ring_auto_expand;
        cfg.ledger_history = opts.ledger_history;

        ut_status_t st = UT_OK;
        handle_ = ut_node_create(&cfg, &st);
        if (!handle_) {
            throw std::runtime_error(std::string("ut_node_create failed: ") + ut_status_str(st));
        }
    }

    ~Node() {
        if (handle_) {
            ut_node_destroy(handle_);
            handle_ = nullptr;
        }
    }

    Node(const Node &) = delete;
    Node &operator=(const Node &) = delete;

    Node(Node &&other) noexcept
        : handle_(other.handle_), callbacks_(std::move(other.callbacks_)) {
        other.handle_ = nullptr;
    }

    Node &operator=(Node &&other) noexcept {
        if (this != &other) {
            if (handle_) ut_node_destroy(handle_);
            handle_ = other.handle_;
            callbacks_ = std::move(other.callbacks_);
            other.handle_ = nullptr;
        }
        return *this;
    }

    void start() {
        ut_status_t st = ut_node_start(handle_);
        if (st != UT_OK) {
            throw std::runtime_error(std::string("ut_node_start failed: ") + ut_status_str(st));
        }
    }

    void stop() noexcept {
        if (handle_) ut_node_stop(handle_);
    }

    std::string_view node_id() const noexcept { return ut_node_id(handle_); }
    std::uint16_t port() const noexcept { return ut_node_port(handle_); }
    std::string_view public_key_hex() const noexcept { return ut_node_public_key_hex(handle_); }
    std::uint64_t sequence_number() const noexcept { return ut_node_sequence_number(handle_); }

    void publish(std::string_view topic, std::span<const std::uint8_t> bytes, bool is_json = false) {
        std::string t(topic);
        ut_status_t st = ut_node_publish(handle_, t.c_str(), bytes.data(), bytes.size(), is_json);
        if (st != UT_OK) {
            throw std::runtime_error(std::string("publish failed: ") + ut_status_str(st));
        }
    }

    void publish_json(std::string_view topic, std::string_view json_payload) {
        std::string t(topic);
        ut_status_t st = ut_node_publish(
            handle_, t.c_str(),
            reinterpret_cast<const std::uint8_t *>(json_payload.data()),
            json_payload.size(),
            true
        );
        if (st != UT_OK) {
            throw std::runtime_error(std::string("publish_json failed: ") + ut_status_str(st));
        }
    }

    void subscribe(std::string_view topic_pattern, SubscribeCallback cb) {
        auto holder = std::make_unique<SubscribeCallback>(std::move(cb));
        std::string pat(topic_pattern);
        ut_status_t st = ut_node_subscribe(
            handle_,
            pat.c_str(),
            &Node::trampoline,
            holder.get()
        );
        if (st != UT_OK) {
            throw std::runtime_error(std::string("subscribe failed: ") + ut_status_str(st));
        }
        callbacks_.push_back(std::move(holder));
    }

    std::optional<std::string> get_latest(std::string_view path) const {
        std::string p(path);
        std::array<std::uint8_t, 4096> stack_buf{};
        std::size_t out_len = 0;
        ut_status_t st = ut_node_get_latest(
            handle_, p.c_str(), stack_buf.data(), stack_buf.size(), &out_len, nullptr);
        if (st == UT_ERR_NOT_FOUND) {
            return std::nullopt;
        }
        if (st == UT_ERR_BUFFER_TOO_SMALL) {
            std::vector<std::uint8_t> heap_buf(out_len);
            st = ut_node_get_latest(handle_, p.c_str(), heap_buf.data(), heap_buf.size(), &out_len, nullptr);
            if (st != UT_OK) return std::nullopt;
            return std::string(reinterpret_cast<const char *>(heap_buf.data()), out_len);
        }
        if (st != UT_OK) return std::nullopt;
        return std::string(reinterpret_cast<const char *>(stack_buf.data()), out_len);
    }

    std::string get_swarm_state_json() const {
        char *raw = nullptr;
        std::size_t len = 0;
        ut_status_t st = ut_node_get_swarm_state_json(handle_, &raw, &len);
        if (st != UT_OK || !raw) {
            throw std::runtime_error("get_swarm_state_json failed");
        }
        std::string res(raw, len);
        ut_free(raw);
        return res;
    }

    std::array<std::uint8_t, UT_SHA256_SIZE> get_merkle_root() const {
        std::array<std::uint8_t, UT_SHA256_SIZE> root{};
        ut_status_t st = ut_node_get_merkle_root(handle_, root.data());
        if (st != UT_OK) {
            throw std::runtime_error("get_merkle_root failed");
        }
        return root;
    }

    void trigger_repair() noexcept { ut_node_trigger_repair(handle_); }
    bool verify_chain() const noexcept { return ut_node_verify_chain(handle_); }

    void add_peer(std::string_view peer_id, std::string_view ip, std::uint16_t port,
                  std::string_view pub_key_hex = {}) {
        std::string pid(peer_id);
        std::string addr(ip);
        std::string pk(pub_key_hex);
        ut_status_t st = ut_node_add_peer(
            handle_, pid.c_str(), addr.c_str(), port, pk.empty() ? nullptr : pk.c_str());
        if (st != UT_OK) {
            throw std::runtime_error(std::string("add_peer failed: ") + ut_status_str(st));
        }
    }

    std::size_t ring_dropped_count() const noexcept {
        return ut_node_ring_dropped_count(handle_);
    }

    ut_node_t *raw_handle() noexcept { return handle_; }

private:
    static void trampoline(
        const char *topic,
        const std::uint8_t *value,
        std::size_t value_len,
        bool is_json,
        const char *sender_node_id,
        void *user_ctx
    ) {
        auto *fn = static_cast<SubscribeCallback *>(user_ctx);
        if (fn && *fn) {
            (*fn)(
                topic ? std::string_view(topic) : std::string_view{},
                std::span<const std::uint8_t>(value, value_len),
                is_json,
                sender_node_id ? std::string_view(sender_node_id) : std::string_view{}
            );
        }
    }

    ut_node_t *handle_ = nullptr;
    std::vector<std::unique_ptr<SubscribeCallback>> callbacks_;
};

} // namespace unitelem
