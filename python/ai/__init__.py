"""
UniTelem AI Subsystem: Model Runners, Inference, Auctions, Spatial, and Simplex Safety.
"""

from .runner import (
    BaseModelRunner,
    FunctionModelRunner,
    ONNXModelRunner,
    create_model_runner,
)
from .auction import (
    Job,
    Bid,
    BidEvaluator,
    Auction,
)
from .spatial import (
    VoronoiPartitioner,
)
from .simplex import (
    SafetyEnvelope,
    SimplexArbiter,
    VetoReason,
)
from .anomaly import (
    AnomalyType,
    AnomalySeverity,
    QuorumStatus,
    AnomalyReport,
    QuorumProposal,
    AnomalyConfig,
    WelfordTracker,
    CUSUMTracker,
    DriftDetector,
    TamperDetector,
    ByzantineQuorumVoting,
    ByzantineQuorumArbiter,
)

__all__ = [
    "BaseModelRunner",
    "FunctionModelRunner",
    "ONNXModelRunner",
    "create_model_runner",
    "Job",
    "Bid",
    "BidEvaluator",
    "Auction",
    "VoronoiPartitioner",
    "SafetyEnvelope",
    "SimplexArbiter",
    "VetoReason",
    "AnomalyType",
    "AnomalySeverity",
    "QuorumStatus",
    "AnomalyReport",
    "QuorumProposal",
    "AnomalyConfig",
    "WelfordTracker",
    "CUSUMTracker",
    "DriftDetector",
    "TamperDetector",
    "ByzantineQuorumVoting",
    "ByzantineQuorumArbiter",
]
