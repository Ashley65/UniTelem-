import time
from typing import Any, Callable, Dict, Optional, Tuple, Union

try:
    from .ring_buffer import FastRingBuffer
except ImportError:
    from ring_buffer import FastRingBuffer


class EventThresholdFilter:
    """
    A High-throughput event filter for the UniTelem mesh network.

    Filters events based on:
        1. Min/Max payload thresholds
        2. Deadband absolute delta thresholds (change-only reporting)
        3. Rate limiting / minimal latency between events
        4. Custom predicate functions
        5. Supports both scalar numbers and dict payloads (with optional key extraction)
    """

    def __init__(
        self,
        ring_buffer: Optional[FastRingBuffer] = None,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        deadband: Optional[float] = None,
        min_interval_sec: Optional[float] = None,
        key: Optional[str] = None,
        predicate: Optional[Callable[[Any, Any, int], bool]] = None,
    ):
        self.ring_buffer = ring_buffer
        self.min_value = min_value
        self.max_value = max_value
        self.deadband = deadband
        self.min_interval_sec = min_interval_sec
        self.key = key
        self.predicate = predicate

        # Per-topic state tracking for deadband & rate limiting
        self._last_values: Dict[Any, float] = {}
        self._last_timestamps: Dict[Any, float] = {}

    def _extract_numeric(self, payload: Any) -> Optional[float]:
        """Extracts a numeric value from payload, supporting float/int or dicts."""
        if isinstance(payload, (int, float)):
            return float(payload)
        if isinstance(payload, dict):
            if self.key and self.key in payload:
                val = payload[self.key]
                if isinstance(val, (int, float)):
                    return float(val)
            elif "value" in payload and isinstance(payload["value"], (int, float)):
                return float(payload["value"])
            elif len(payload) == 1:
                first_val = list(payload.values())[0]
                if isinstance(first_val, (int, float)):
                    return float(first_val)
        return None

    def should_pass(self, topic: Any, payload: Any = None, lamport_time: int = 0) -> bool:
        """Evaluates whether an event meets all configured thresholds."""
        if self.predicate and not self.predicate(topic, payload, lamport_time):
            return False

        val_source = payload if payload is not None else topic
        m_topic = topic if payload is not None else "__default__"
        num_val = self._extract_numeric(val_source)

        staged_last_value = None
        if num_val is not None:
            if self.min_value is not None and num_val < self.min_value:
                return False
            if self.max_value is not None and num_val > self.max_value:
                return False

            if self.deadband is not None:
                last_val = self._last_values.get(m_topic)
                if last_val is not None and abs(num_val - last_val) < self.deadband:
                    return False
                staged_last_value = num_val

        staged_timestamp = None
        if self.min_interval_sec is not None:
            now = time.monotonic()
            last_time = self._last_timestamps.get(topic, 0.0)
            if (now - last_time) < self.min_interval_sec:
                return False
            staged_timestamp = now

        # Only commit state if all threshold conditions passed
        if staged_last_value is not None:
            self._last_values[m_topic] = staged_last_value
        if staged_timestamp is not None:
            self._last_timestamps[topic] = staged_timestamp

        return True

    def push(self, topic: Any, payload: Any = None, lamport_time: int = 0) -> bool:
        """Filters event; pushes to the attached ring buffer only if the threshold is met."""
        if not self.should_pass(topic, payload, lamport_time):
            return False

        if self.ring_buffer is not None:
            return self.ring_buffer.push(topic, payload, lamport_time)
        return True

    def reset_state(self, topic: Optional[Any] = None) -> None:
        """Resets per-topic state for deadband and rate limiting."""
        if topic is not None:
            self._last_values.pop(topic, None)
            self._last_timestamps.pop(topic, None)
        else:
            self._last_values.clear()
            self._last_timestamps.clear()