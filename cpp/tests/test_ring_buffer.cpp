#include "unitelem/ring_buffer.h"
#include "unitelem/ring_buffer.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

struct OverflowState {
    std::vector<int> evicted;
    ut_ringbuf_t *rb = nullptr;
    size_t observed_size_in_handler = 0;
};

static void c_overflow_cb(const void *evicted_item, void *user_ctx) {
    auto *st = static_cast<OverflowState *>(user_ctx);
    st->evicted.push_back(*static_cast<const int *>(evicted_item));
    /* Must NOT deadlock when calling ring buffer API from overflow handler */
    st->observed_size_in_handler = ut_ringbuf_size(st->rb);
}

static void test_c11_ringbuf(void) {
    ut_ringbuf_t rb;
    OverflowState ost;
    ost.rb = &rb;
    assert(ut_ringbuf_init(&rb, 4, sizeof(int), false, c_overflow_cb, &ost) == UT_OK);

    for (int i = 1; i <= 6; ++i) {
        assert(ut_ringbuf_push(&rb, &i) == UT_OK);
    }
    assert(ut_ringbuf_size(&rb) == 4);
    assert(ut_ringbuf_dropped_count(&rb) == 2);
    assert(ost.evicted.size() == 2 && ost.evicted[0] == 1 && ost.evicted[1] == 2);
    assert(ost.observed_size_in_handler == 4);

    int batch[4] = {0};
    assert(ut_ringbuf_pop_batch(&rb, batch, 4) == 4);
    assert(batch[0] == 3 && batch[1] == 4 && batch[2] == 5 && batch[3] == 6);
    assert(ut_ringbuf_is_empty(&rb));

    /* Batch push + auto_expand */
    ut_ringbuf_set_auto_expand(&rb, true);
    int items[10] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
    assert(ut_ringbuf_push_batch(&rb, items, 10) == 10);
    assert(ut_ringbuf_capacity(&rb) >= 10);
    assert(ut_ringbuf_size(&rb) == 10);

    ut_ringbuf_destroy(&rb);
}

static void test_cpp_ringbuf(void) {
    std::vector<int> evicted;
    unitelem::RingBuffer<int> rb(4, false);
    rb.set_overflow_handler([&](int item) {
        evicted.push_back(item);
        (void)rb.size(); /* post-unlock callback safety */
    });

    for (int i = 1; i <= 6; ++i) {
        rb.push(i);
    }
    assert(rb.size() == 4);
    assert(rb.dropped_count() == 2);
    assert(evicted.size() == 2 && evicted[0] == 1 && evicted[1] == 2);

    auto drained = rb.pop_batch(4);
    assert(drained.size() == 4);
    assert(drained[0] == 3 && drained[3] == 6);

    /* Concurrent producer/consumer stress */
    unitelem::RingBuffer<int> mt_rb(1024, false);
    std::atomic<bool> done{false};
    std::atomic<int> consumed{0};

    std::thread prod([&] {
        for (int i = 1; i <= 50000; ++i) {
            mt_rb.push(i);
        }
        done.store(true);
    });
    std::thread cons([&] {
        while (!done.load() || !mt_rb.is_empty()) {
            auto batch = mt_rb.pop_batch(64);
            consumed += static_cast<int>(batch.size());
        }
    });
    prod.join();
    cons.join();
    assert(consumed + static_cast<int>(mt_rb.dropped_count()) == 50000);
}

int main() {
    test_c11_ringbuf();
    test_cpp_ringbuf();
    std::printf("test_ring_buffer passed\n");
    return 0;
}
