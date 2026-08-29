from ring_buffer import FastRingBuffer


def test_pop_empty_returns_none_and_batch_empty_returns_list():
    rb = FastRingBuffer(capacity=4)

    assert rb.pop() is None
    assert rb.pop_batch() == []
    assert len(rb) == 0


def test_push_pop_fifo_order_and_len_tracking():
    rb = FastRingBuffer(capacity=4)

    assert rb.push("a", b"1") is True
    assert rb.push("b", b"2") is True
    assert len(rb) == 2

    assert rb.pop() == ("a", b"1")
    assert rb.pop() == ("b", b"2")
    assert rb.pop() is None
    assert len(rb) == 0


def test_pop_batch_respects_batch_size_and_order():
    rb = FastRingBuffer(capacity=10)
    items = [("t1", b"a"), ("t2", b"b"), ("t3", b"c")]

    for topic, payload in items:
        rb.push(topic, payload)

    batch = rb.pop_batch(batch_size=2)
    assert batch == items[:2]
    assert len(rb) == 1

    batch2 = rb.pop_batch(batch_size=10)
    assert batch2 == items[2:]
    assert len(rb) == 0


def test_capacity_overwrites_oldest_items():
    rb = FastRingBuffer(capacity=3)

    rb.push("t1", b"1")
    rb.push("t2", b"2")
    rb.push("t3", b"3")
    rb.push("t4", b"4")  # overwrites oldest (t1, b"1")

    assert len(rb) == 3
    assert rb.pop_batch(batch_size=10) == [
        ("t2", b"2"),
        ("t3", b"3"),
        ("t4", b"4"),
    ]


def test_pop_batch_default_drains_small_buffer():
    rb = FastRingBuffer(capacity=8)

    rb.push("x", b"1")
    rb.push("y", b"2")

    # default batch_size is 256, so small buffers are fully drained
    assert rb.pop_batch() == [("x", b"1"), ("y", b"2")]
    assert rb.pop_batch() == []
    assert len(rb) == 0


def __main__():
    test_pop_empty_returns_none_and_batch_empty_returns_list()
    test_push_pop_fifo_order_and_len_tracking()
    test_pop_batch_respects_batch_size_and_order()
    test_capacity_overwrites_oldest_items()
    test_pop_batch_default_drains_small_buffer()
    print("All tests passed!")

if __name__ == "__main__":
    __main__()