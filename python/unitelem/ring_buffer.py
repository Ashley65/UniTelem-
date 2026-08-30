from collections import deque
import threading
from typing import Optional, List, Tuple, TypeVar, Generic, Iterable, Any

T = TypeVar("T")

class FastRingBuffer(Generic[T]):
    """
    Fixed capacity, thread-safe circular ring buffer.
    Overwrites oldest items on overflow to guarantee non-blocking writes (< 1μs).
    """
    def __init__(self, capacity: int = 16384):
        if capacity <= 0:
            raise ValueError("Capacity must be a positive integer.")
        self._capacity = capacity
        self._buffer: deque = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._dropped_count = 0

    @property
    def capacity(self) -> int:
        """Maximum number of items the buffer can hold."""
        return self._capacity

    @property
    def dropped_count(self) -> int:
        """The total number of items dropped due to capacity overflow."""
        with self._lock:
            return self._dropped_count

    def is_empty(self) -> bool:
        """Check if the buffer is empty."""
        with self._lock:
            return len(self._buffer) == 0

    def is_full(self) -> bool:
        """Check if the buffer has reached capacity."""
        with self._lock:
            return len(self._buffer) == self._capacity

    def push(self, topic_or_item: Any, payload: Any = None, lamport_time: int = 0) -> bool:
        """
        Fast non-blocking push.
        Supports push(topic, payload), push(topic, payload, lamport_time), or push(item).
        """
        if payload is not None:
            if lamport_time > 0:
                item = (topic_or_item, payload, lamport_time)
            else:
                item = (topic_or_item, payload)
        else:
            item = topic_or_item

        with self._lock:
            was_full = len(self._buffer) == self._capacity
            self._buffer.append(item)
            if was_full:
                self._dropped_count += 1
        return True

    def push_batch(self, items: Iterable[Any]) -> int:
        """
        Batch push items under a single lock acquisition.
        Returns the number of items successfully pushed.
        """
        item_list = list(items)
        if not item_list:
            return 0
        with self._lock:
            overflow = (len(self._buffer) + len(item_list)) - self._capacity
            if overflow > 0:
                self._dropped_count += min(overflow, len(self._buffer) + len(item_list))
            self._buffer.extend(item_list)
        return len(item_list)

    def pop(self) -> Optional[Any]:
        """Non-blocking pop."""
        with self._lock:
            if not self._buffer:
                return None
            return self._buffer.popleft()

    def pop_batch(self, max_items: int = 256, batch_size: Optional[int] = None) -> List[Any]:
        """Batch pop to reduce lock contention for high-throughput network threads."""
        limit = batch_size if batch_size is not None else max_items
        with self._lock:
            if not self._buffer:
                return []
            count = min(len(self._buffer), limit)
            return [self._buffer.popleft() for _ in range(count)]

    def clear(self) -> None:
        """Clear all elements from the buffer."""
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._buffer)

    def __repr__(self) -> str:
        return f"<FastRingBuffer size={len(self)}/{self._capacity}>"
