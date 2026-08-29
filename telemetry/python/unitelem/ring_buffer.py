from collections import deque
import threading
from typing import Optional, List, Tuple


class FastRingBuffer:
    """
    Fixed capacity, thread safe circular ring buffer.

    """
    def __init__(self, capacity: int = 16384):
        self._capacity = capacity
        self._buffer = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def push(self, topic: str, payload: bytes) -> bool:
        """Non-blocking push."""
        with self._lock:
            self._buffer.append((topic, payload))
        return True

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


    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)
