from collections import deque
import threading
from typing import Optional, List, Tuple, TypeVar, Generic, Iterable

T = TypeVar("T", bound=Tuple[str, bytes])

class FastRingBuffer(Generic[T]):
    """
    Fixed capacity, thread safe circular ring buffer.

    """
    def __init__(self, capacity: int = 16384):
        if capacity <= 0:
            raise ValueError("Capacity must be a positive integer.")
        self._capacity = capacity
        self._buffer: deque[T] = deque(maxlen=capacity)
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

    def push(self, topic: str, payload: bytes) -> bool:
        with self._lock:
            was_full = len(self._buffer) == self._capacity
            self._buffer.append((topic, payload))
            if was_full:
                self._dropped_count += 1
        return True

    def push_batch(self, items: Iterable[Tuple[str, bytes]]) -> int:
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
            self._buffer.extend(item_list)  # type: ignore[arg-type]
        return len(item_list)

    def pop(self) -> Optional[tuple[str, bytes]]:
        """Non-blocking pop."""
        with self._lock:
            if not self._buffer:
                return None
            return self._buffer.popleft()

    def pop_batch(self, batch_size: int = 256) -> List[tuple[str, bytes]]:
        """Batch pop to reduce lock contention for high-throughput network threads."""
        with self._lock:
            if not self._buffer:
                return []
            count = min(len(self._buffer), batch_size)
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
