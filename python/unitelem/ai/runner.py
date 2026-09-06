"""
UniTelem Pluggable Model Runners.

Provides lightweight, decoupled model inference adapters for AINode.
Supports ONNX models via onnxruntime (optional dependency) and custom Python callables.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
import os


class BaseModelRunner(ABC):
    """
    Abstract base class for all UniTelem model runners.
    """

    @abstractmethod
    def predict(self, inputs: Any, **kwargs) -> Any:
        """Runs model inference on inputs and returns predictions."""
        pass

    def __call__(self, *args, **kwargs) -> Any:
        if args and len(args) == 1 and not kwargs:
            return self.predict(args[0])
        elif args:
            return self.predict(args, **kwargs)
        return self.predict(kwargs)


class FunctionModelRunner(BaseModelRunner):
    """
    Wraps standard Python callables, functions, or heuristic rule engines.
    """

    def __init__(self, func: Any):
        if not callable(func):
            raise TypeError(f"FunctionModelRunner expects a callable, got {type(func)}")
        self._func = func

    def predict(self, inputs: Any, **kwargs) -> Any:
        try:
            return self._func(inputs, **kwargs)
        except TypeError:
            # Fallback for functions with single positional argument
            return self._func(inputs)


class ONNXModelRunner(BaseModelRunner):
    """
    Inference runner for ONNX (.onnx) models via ONNX Runtime.
    Lazily imports onnxruntime so base telemetry remains zero-dependency.
    """

    def __init__(
        self,
        model_path: str,
        providers: Optional[List[str]] = None,
        session_options: Optional[Any] = None,
    ):
        self.model_path = model_path
        self.providers = providers
        self.session_options = session_options
        self._session = None
        self._input_names: List[str] = []
        self._output_names: List[str] = []

    def _ensure_session(self):
        """Initializes the onnxruntime InferenceSession lazily on first access."""
        if self._session is not None:
            return

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"ONNX model file not found: {self.model_path}")

        try:
            import onnxruntime as ort
        except ImportError as err:
            raise ImportError(
                "ONNX Runtime is required to run .onnx models in UniTelem. "
                "Install it with: pip install 'unitelem[ai]' or pip install onnxruntime"
            ) from err

        available_providers = ort.get_available_providers()
        chosen_providers = self.providers
        if chosen_providers is None:
            # Default to CPU unless CUDA/DirectML/TensorRT available and not excluded
            chosen_providers = [p for p in ["CUDAExecutionProvider", "DmlExecutionProvider", "CPUExecutionProvider"] if p in available_providers]
            if not chosen_providers:
                chosen_providers = available_providers

        self._session = ort.InferenceSession(
            self.model_path,
            sess_options=self.session_options,
            providers=chosen_providers,
        )
        self._input_names = [inp.name for inp in self._session.get_inputs()]
        self._output_names = [out.name for out in self._session.get_outputs()]

    @property
    def input_names(self) -> List[str]:
        self._ensure_session()
        return self._input_names

    @property
    def output_names(self) -> List[str]:
        self._ensure_session()
        return self._output_names

    def predict(self, inputs: Any, **kwargs) -> Any:
        """
        Executes model inference.
        Accepts:
        - dict of {input_name: numpy_array}
        - single array/list/value (mapped to the first model input)
        """
        self._ensure_session()

        try:
            import numpy as np
        except ImportError as err:
            raise ImportError("NumPy is required for ONNX model inference. Install via pip install numpy.") from err

        feed_dict: Dict[str, Any] = {}

        if isinstance(inputs, dict):
            for k, v in inputs.items():
                feed_dict[k] = v if isinstance(v, np.ndarray) else np.array(v)
        else:
            first_input = self._input_names[0] if self._input_names else "input"
            feed_dict[first_input] = inputs if isinstance(inputs, np.ndarray) else np.array(inputs)

        outputs = self._session.run(self._output_names or None, feed_dict)

        # Return single output directly if only one output tensor exists
        if outputs and len(outputs) == 1:
            return outputs[0]
        return outputs


def create_model_runner(model_or_path: Any, **kwargs) -> Optional[BaseModelRunner]:
    """
    Factory function to resolve any model input into a BaseModelRunner.
    - If None -> returns None
    - If already a BaseModelRunner -> returns as is
    - If string ending with .onnx -> returns ONNXModelRunner
    - If callable -> returns FunctionModelRunner
    """
    if model_or_path is None:
        return None
    if isinstance(model_or_path, BaseModelRunner):
        return model_or_path
    if isinstance(model_or_path, str) and model_or_path.lower().endswith(".onnx"):
        return ONNXModelRunner(model_or_path, **kwargs)
    if callable(model_or_path):
        return FunctionModelRunner(model_or_path)
    
    # Generic object with predict or generate method
    if hasattr(model_or_path, "predict"):
        return FunctionModelRunner(model_or_path.predict)
    if hasattr(model_or_path, "generate"):
        return FunctionModelRunner(model_or_path.generate)

    raise TypeError(
        f"Unsupported model type: {type(model_or_path)}. Expected .onnx file path, callable, or BaseModelRunner."
    )
