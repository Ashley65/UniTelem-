"""
Stress and correctness test suite for FastRingBuffer.
Compatible with standard unittest and pytest.
"""

import gc
import random
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed

from unitelem.ring_buffer import FastRingBuffer


def make_item(i: int) -> tuple:
    return (f"topic-{i % 8}", f"payload-{i}".encode())


def drain_all(rb: FastRingBuffer, batch_size: int = 512) -> list:
    """Pop everything currently in the buffer."""
    out = []
    while True:
        batch = rb.pop_batch(batch_size=batch_size)
        if not batch:
            break
        out.extend(batch)
    return out


class TestBasicCorrectness(unittest.TestCase):
    def test_empty_on_creation(self):
        rb = FastRingBuffer(capacity=10)
        self.assertTrue(rb.is_empty())
        self.assertFalse(rb.is_full())
        self.assertEqual(len(rb), 0)
        self.assertFalse(bool(rb))
        self.assertIsNone(rb.pop())

    def test_invalid_capacity_raises(self):
        with self.assertRaises(ValueError):
            FastRingBuffer(capacity=0)
        with self.assertRaises(ValueError):
            FastRingBuffer(capacity=-5)

    def test_fifo_ordering_single_push(self):
        rb = FastRingBuffer(capacity=100)
        for i in range(50):
            rb.push(*make_item(i))
        out = drain_all(rb)
        self.assertEqual(out, [make_item(i) for i in range(50)])

    def test_fifo_ordering_batch_push(self):
        rb = FastRingBuffer(capacity=100)
        items = [make_item(i) for i in range(50)]
        pushed = rb.push_batch(items)
        self.assertEqual(pushed, 50)
        self.assertEqual(drain_all(rb), items)

    def test_len_tracks_contents(self):
        rb = FastRingBuffer(capacity=10)
        for i in range(5):
            rb.push(*make_item(i))
        self.assertEqual(len(rb), 5)
        rb.pop()
        self.assertEqual(len(rb), 4)

    def test_is_full_true_at_capacity(self):
        rb = FastRingBuffer(capacity=5)
        for i in range(5):
            rb.push(*make_item(i))
        self.assertTrue(rb.is_full())
        self.assertFalse(rb.is_empty())

    def test_repr_contains_size_and_capacity(self):
        rb = FastRingBuffer(capacity=5)
        rb.push(*make_item(0))
        r = repr(rb)
        self.assertIn("1/5", r)

    def test_clear_empties_buffer_but_not_dropped_count(self):
        rb = FastRingBuffer(capacity=3)
        rb.push_batch([make_item(i) for i in range(6)])
        dropped_before = rb.dropped_count
        self.assertGreater(dropped_before, 0)
        rb.clear()
        self.assertTrue(rb.is_empty())
        self.assertEqual(rb.dropped_count, dropped_before)


class TestDroppedCountAccuracy(unittest.TestCase):
    def test_push_batch_reports_drops_correctly(self):
        rb = FastRingBuffer(capacity=3)
        pushed = rb.push_batch([make_item(i) for i in range(10)])
        self.assertEqual(pushed, 10)
        self.assertEqual(len(rb), 3)
        self.assertEqual(rb.dropped_count, 7)

    def test_push_batch_no_overflow_no_drops(self):
        rb = FastRingBuffer(capacity=10)
        rb.push_batch([make_item(i) for i in range(5)])
        self.assertEqual(rb.dropped_count, 0)

    def test_single_push_overflow_tracked(self):
        rb = FastRingBuffer(capacity=3)
        for i in range(10):
            rb.push(*make_item(i))
        self.assertEqual(len(rb), 3)
        self.assertEqual(rb.dropped_count, 7)

    def test_single_push_and_batch_push_consistency(self):
        items = [make_item(i) for i in range(20)]

        rb_single = FastRingBuffer(capacity=4)
        for it in items:
            rb_single.push(*it)

        rb_batch = FastRingBuffer(capacity=4)
        rb_batch.push_batch(items)

        self.assertEqual(list(rb_single._buffer), list(rb_batch._buffer))
        self.assertEqual(rb_single.dropped_count, 16)
        self.assertEqual(rb_batch.dropped_count, 16)


class TestBatchOperations(unittest.TestCase):
    def test_push_batch_empty_iterable(self):
        rb = FastRingBuffer(capacity=10)
        self.assertEqual(rb.push_batch([]), 0)
        self.assertEqual(len(rb), 0)
        self.assertEqual(rb.dropped_count, 0)

    def test_push_batch_accepts_generator(self):
        rb = FastRingBuffer(capacity=10)
        gen = (make_item(i) for i in range(5))
        self.assertEqual(rb.push_batch(gen), 5)
        self.assertEqual(len(rb), 5)

    def test_push_batch_larger_than_capacity_in_one_call(self):
        rb = FastRingBuffer(capacity=5)
        pushed = rb.push_batch([make_item(i) for i in range(100)])
        self.assertEqual(pushed, 100)
        self.assertEqual(len(rb), 5)
        self.assertEqual(rb.dropped_count, 95)
        self.assertEqual(list(rb._buffer), [make_item(i) for i in range(95, 100)])

    def test_pop_batch_default_size(self):
        rb = FastRingBuffer(capacity=1000)
        rb.push_batch([make_item(i) for i in range(1000)])
        batch = rb.pop_batch(max_items=256)
        self.assertEqual(len(batch), 256)
        self.assertEqual(len(rb), 744)


class TestConcurrencyStress(unittest.TestCase):
    def test_concurrent_push_never_exceeds_capacity(self):
        capacity = 500
        rb = FastRingBuffer(capacity=capacity)
        n_threads = 16
        items_per_thread = 1000

        def producer(tid: int):
            for i in range(items_per_thread):
                rb.push(f"t{tid}", str(i).encode())

        threads = [threading.Thread(target=producer, args=(t,)) for t in range(n_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertLessEqual(len(rb), capacity)
        self.assertLessEqual(len(rb._buffer), capacity)


if __name__ == "__main__":
    unittest.main()