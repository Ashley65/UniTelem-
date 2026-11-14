#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace unitelem {

inline constexpr std::size_t DEFAULT_RING_BUFFER_SIZE = 64u * 1024u;

template <typename T>
class RingBuffer {
public:
    using OverflowHandler = std::function<void(T evicted_item)>;

    explicit RingBuffer(
        std::size_t capacity = DEFAULT_RING_BUFFER_SIZE,
        bool auto_expand = false,
        OverflowHandler handler = nullptr
    )
        : capacity_(capacity),
          head_(0),
          tail_(0),
          size_(0),
          dropped_count_(0),
          auto_expand_(auto_expand),
          overflow_handler_(std::move(handler)) {
        if (capacity == 0) {
            throw std::invalid_argument("Capacity must be greater than 0");
        }
        buffer_.resize(capacity);
    }

    void set_auto_expand(bool enable) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto_expand_ = enable;
    }

    void set_overflow_handler(OverflowHandler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        overflow_handler_ = std::move(handler);
    }

    std::size_t capacity() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return capacity_;
    }

    std::size_t dropped_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dropped_count_;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_;
    }

    bool is_empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_ == 0;
    }

    bool is_full() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_ == capacity_;
    }

    bool push(T item) {
        std::optional<T> evicted;
        OverflowHandler handler_to_run;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (size_ == capacity_) {
                if (auto_expand_) {
                    grow_internal(capacity_ * 2);
                } else {
                    if (overflow_handler_) {
                        evicted = std::move(buffer_[head_]);
                    }
                    head_ = (head_ + 1) % capacity_;
                    ++dropped_count_;
                    --size_;
                }
            }
            buffer_[tail_] = std::move(item);
            tail_ = (tail_ + 1) % capacity_;
            ++size_;
            handler_to_run = overflow_handler_;
        }
        if (evicted.has_value() && handler_to_run) {
            handler_to_run(std::move(*evicted));
        }
        return true;
    }

    std::size_t push_batch(std::vector<T> items) {
        if (items.empty()) {
            return 0;
        }

        std::vector<T> evicted_items;
        OverflowHandler handler_to_run;
        const std::size_t count = items.size();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (auto_expand_ && (size_ + count > capacity_)) {
                std::size_t new_cap = capacity_ * 2;
                while (new_cap < size_ + count) {
                    new_cap *= 2;
                }
                grow_internal(new_cap);
            }
            handler_to_run = overflow_handler_;
            if (handler_to_run && !auto_expand_ && (size_ + count > capacity_)) {
                evicted_items.reserve((size_ + count) - capacity_);
            }
            for (auto &item : items) {
                if (size_ == capacity_) {
                    if (handler_to_run) {
                        evicted_items.push_back(std::move(buffer_[head_]));
                    }
                    head_ = (head_ + 1) % capacity_;
                    ++dropped_count_;
                    --size_;
                }
                buffer_[tail_] = std::move(item);
                tail_ = (tail_ + 1) % capacity_;
                ++size_;
            }
        }

        if (handler_to_run) {
            for (auto &evicted : evicted_items) {
                handler_to_run(std::move(evicted));
            }
        }
        return count;
    }

    std::optional<T> pop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (size_ == 0) {
            return std::nullopt;
        }
        T item = std::move(buffer_[head_]);
        head_ = (head_ + 1) % capacity_;
        --size_;
        return item;
    }

    std::vector<T> pop_batch(std::size_t max_items = 256) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (size_ == 0) {
            return {};
        }
        const std::size_t count = std::min(size_, max_items);
        std::vector<T> result;
        result.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            result.push_back(std::move(buffer_[head_]));
            head_ = (head_ + 1) % capacity_;
            --size_;
        }
        return result;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        head_ = 0;
        tail_ = 0;
        size_ = 0;
    }

private:
    void grow_internal(std::size_t new_capacity) {
        std::vector<T> new_buffer(new_capacity);
        for (std::size_t i = 0; i < size_; ++i) {
            new_buffer[i] = std::move(buffer_[(head_ + i) % capacity_]);
        }
        buffer_ = std::move(new_buffer);
        head_ = 0;
        tail_ = size_;
        capacity_ = new_capacity;
    }

    std::size_t capacity_;
    std::vector<T> buffer_;
    std::size_t head_;
    std::size_t tail_;
    std::size_t size_;
    std::size_t dropped_count_;
    bool auto_expand_;
    OverflowHandler overflow_handler_;
    mutable std::mutex mutex_;
};

} // namespace unitelem
