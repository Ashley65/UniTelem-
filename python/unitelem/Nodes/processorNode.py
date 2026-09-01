"""
UniTelem Processor Node

A specialized node that can process telemetry data or other types of data.
Acts as a processing unit in a decentralized telemetry network, where it can
receive data from other nodes, perform computations or transformations, and
publish the results back to the network without blocking the network RX thread.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple
import queue
import threading
import time

from node import Node


class ProcessorNode(Node):
    """
    A specialized node that processes telemetry data or other data types asynchronously.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str = "default",
        port: int = 8900,
        enable_crypto: bool = True,
        private_key_hex: str = "",
        auto_start: bool = True,
        enable_anti_entropy: bool = True,
        anti_entropy_interval_s: float = 0.5,
        num_workers: int = 4,
        max_queue_size: int = 10000,
    ):
        # 1. Initialize Processor data structures BEFORE super().__init__
        self._processing_callbacks: Dict[str, Callable[[str, Any, str], Any]] = {}
        self._task_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._workers: List[threading.Thread] = []
        self._num_workers = num_workers
        self._processor_running = False

        # 2. Initialize parent Node with auto_start=False to avoid race condition
        super().__init__(
            node_id=node_id,
            swarm_id=swarm_id,
            port=port,
            enable_crypto=enable_crypto,
            private_key_hex=private_key_hex,
            auto_start=False,
            enable_anti_entropy=enable_anti_entropy,
            anti_entropy_interval_s=anti_entropy_interval_s,
        )

        if auto_start:
            self.start()

    def register_handler(self, topic: str, handler_func: Callable[[str, Any, str], Optional[Tuple[str, Any]]]):
        """
        Registers a processing handler function for a specific topic or wildcard '*'.
        Handler signature: handler_func(topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]
        If handler returns (output_topic, output_data), it is published back to the mesh.
        """
        self._processing_callbacks[topic] = handler_func
        self.subscribe(topic, self._enqueue_incoming)

    def _enqueue_incoming(self, topic: str, payload: Any, sender: str):
        """
        Non-blocking enqueue called by the network receiver thread.
        Never blocks the UDP socket ingestion pipeline.
        """
        try:
            self._task_queue.put_nowait((topic, payload, sender))
        except queue.Full:
            pass  # Drop if workers are completely saturated

    def start(self):
        """Starts the underlying Node and compute worker threads."""
        super().start()
        if self._processor_running:
            return
        self._processor_running = True

        for i in range(self._num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"ProcessorWorker-{self.node_id}-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)

    def stop(self):
        """Stops the processor workers and the underlying mesh node."""
        self._processor_running = False
        super().stop()

    def _worker_loop(self):
        """Worker thread loop for processing incoming telemetry data."""
        while self._processor_running:
            try:
                topic, payload, sender = self._task_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            # Look up handler for specific topic or wildcard '*' fallback
            handler = self._processing_callbacks.get(topic) or self._processing_callbacks.get("*")
            if handler:
                try:
                    output = handler(topic, payload, sender)
                    if isinstance(output, tuple) and len(output) == 2:
                        out_topic, out_data = output
                        if out_topic and out_data is not None:
                            self.publish(out_topic, out_data)
                except Exception as e:
                    print(f"[{self.node_id}] Handler error on topic '{topic}': {e}")

            self._task_queue.task_done()