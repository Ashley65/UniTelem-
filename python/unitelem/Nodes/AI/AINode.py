"""
UniTelem AI Node.

A specialized node extending ProcessorNode that integrates AI models,
heuristic inference, and automated swarm event handling.
Supports pluggable model runners (such as ONNX and custom callables).
"""

from typing import Any, Callable, Dict, Optional, Tuple

try:
    from ..processorNode import ProcessorNode
except ImportError:
    from ..processorNode import ProcessorNode

try:
    from ...ai.runner import BaseModelRunner, create_model_runner
except (ImportError, ValueError):
    try:
        from unitelem.ai.runner import BaseModelRunner, create_model_runner
    except ImportError:
        BaseModelRunner = None
        create_model_runner = None


class AINode(ProcessorNode):
    """
    Specialized Node type for running AI-driven inference, anomaly assessment,
    and decision policies across the decentralized telemetry mesh.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str = "default",
        private_key: Optional[str] = None,
        model: Optional[Any] = None,
        **kwargs,
    ):
        # Map private_key if provided to private_key_hex for parent Node
        if private_key and "private_key_hex" not in kwargs:
            kwargs["private_key_hex"] = private_key

        super().__init__(node_id=node_id, swarm_id=swarm_id, **kwargs)

        # Wrap model with pluggable runner if factory available
        if create_model_runner is not None and model is not None:
            self.model = create_model_runner(model)
        else:
            self.model = model

        self.memory: Dict[str, Any] = {}
        self.policy: Dict[str, Any] = {}

        # Register default handlers for telemetry and alerts
        self.register_handler("telemetry/*", self.on_telemetry)
        self.register_handler("alerts/*", self.on_alert)

    def on_telemetry(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Default handler for incoming telemetry streams.
        Stores state into working memory and publishes insights to 'ai/insights'.
        """
        self.memory[f"{sender}/{topic}"] = payload
        return ("ai/insights", {"source": sender, "topic": topic, "payload": payload})

    def on_alert(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Default handler for incoming swarm alert events.
        Acknowledges alert and publishes reaction to 'ai/actions'.
        """
        self.memory[f"alert/{sender}/{topic}"] = payload
        return ("ai/actions", {"alert_source": sender, "topic": topic, "alert": payload, "status": "acknowledged"})

    def predict(self, inputs: Any, **kwargs) -> Any:
        """
        Runs model inference through the configured runner or callable.
        """
        if self.model is None:
            raise RuntimeError(f"[{self.node_id}] No model configured on this AINode.")
        if hasattr(self.model, "predict"):
            return self.model.predict(inputs, **kwargs)
        elif callable(self.model):
            return self.model(inputs, **kwargs)
        raise TypeError(f"[{self.node_id}] Model {type(self.model)} does not support predict().")

    def ask(self, prompt: str, context: Optional[Any] = None) -> Any:
        """
        Queries the underlying model with a prompt and optional context.
        """
        if self.model is None:
            raise RuntimeError(f"[{self.node_id}] No model configured on this AINode.")
        if callable(self.model):
            try:
                return self.model(prompt, context)
            except TypeError:
                return self.model(prompt)
        elif hasattr(self.model, "generate"):
            return self.model.generate(prompt, context=context)
        elif hasattr(self.model, "predict"):
            return self.model.predict({"prompt": prompt, "context": context} if context is not None else prompt)
        else:
            raise TypeError(f"[{self.node_id}] Model {type(self.model)} is neither callable nor provides predict/generate.")