"""
Unitelem Anomaly Detection Module

Core algorithmic engines for detecting anomalies in telemetry data.
Utilising Drift, Tamper, and Byzantine Quorum Voting techniques to ensure robust detection and response across decentralized nodes.

"""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import math
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple


class AnomalyType(str, Enum):
    STATISTICAL_DRIFT = "statistical_drift"
    TELEMETRY_OUTLIER = "telemetry_outlier"
    SENSOR_FREEZE = "sensor_freeze"
    BATTERY_IMBALANCE = "battery_imbalance"
    MOTOR_DEGRADATION = "motor_degradation"
    OPTICAL_OCCLUSION = "optical_occlusion"
    SPRAY_PAINT = "spray_paint"
    ANGLE_SHIFT = "angle_shift"
    IR_FAILURE = "ir_failure"


class AnomalySeverity(str, Enum):
    NONE = "none"
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        _order = {
            "none": 0, "trace": 1, "debug": 2, "info": 3,
            "unknown": 4, "low": 5, "medium": 6, "high": 7, "critical": 8
        }
        return _order.get(self.value, 0)

    def __ge__(self, other: "AnomalySeverity") -> bool:
        if isinstance(other, AnomalySeverity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: "AnomalySeverity") -> bool:
        if isinstance(other, AnomalySeverity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: "AnomalySeverity") -> bool:
        if isinstance(other, AnomalySeverity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: "AnomalySeverity") -> bool:
        if isinstance(other, AnomalySeverity):
            return self.rank < other.rank
        return NotImplemented


class QuorumStatus(str, Enum):
    PROPOSED = "proposed"
    VOTING = "voting"
    COMMITTED = "committed"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class AnomalyReport:
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    source_node_id: str
    metric: str
    value: float
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QuorumProposal:
    incident_id: str
    proposer: str
    anomaly_type: AnomalyType
    target_action: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    votes: Dict[str, bool] = field(default_factory=dict)  # node_id -> approve (True/False)
    status: QuorumStatus = QuorumStatus.PROPOSED
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    total_nodes: int = 1

    @property
    def approve_count(self) -> int:
        return sum(1 for vote in self.votes.values() if vote is True)

    @property
    def reject_count(self) -> int:
        return sum(1 for vote in self.votes.values() if vote is False)


@dataclass
class AnomalyConfig:
    """Configuration thresholds for statistical drift, tamper, and quorum voting."""
    # Outlier & statistical drift
    z_score_threshold: float = 3.5
    cusum_threshold: float = 5.0
    cusum_slack: float = 0.5
    min_samples_for_zscore: int = 10

    # Sensor freeze detection
    freeze_window_samples: int = 10
    freeze_epsilon: float = 1e-6

    # Hardware & electrical telemetry
    battery_imbalance_max_delta_v: float = 0.15  # 150mV cell spread threshold
    motor_deviation_threshold_pct: float = 0.25  # 25% divergence from motor array mean

    # CCTV & physical mount tamper
    occlusion_luminance_threshold: float = 12.0   # Low luminance optical blockage (0-255 scale)
    spray_blur_laplacian_threshold: float = 20.0  # Edge variance drop indicating blur/spray
    angle_shift_threshold_deg: float = 12.0       # Abrupt orientation shift
    mount_jerk_threshold_mps2: float = 15.0       # Physical impact / strike
    ir_failure_expected_contrast: float = 25.0    # Minimum contrast expected under IR illumination

    # Byzantine Quorum
    quorum_fraction: float = 0.67                 # 2/3 supermajority requirement
    voting_timeout_s: float = 5.0                 # Proposal expiration window


class WelfordTracker:
    """
    Computes online running mean and variance using Welford's algorithm (O(1) memory).
    """

    def __init__(self):
        self.count: int = 0
        self.mean: float = 0.0
        self._m2: float = 0.0

    def update(self, value: float) -> Tuple[float, float]:
        """
        Updates running statistics with a new sample.
        Returns:
            (running_mean, running_std)
        """
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self._m2 += delta * delta2
        return self.mean, self.std

    @property
    def variance(self) -> float:
        return self._m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(max(0.0, self.variance))

    def z_score(self, value: float) -> float:
        """Computes standard score of value relative to current sample distribution."""
        std = self.std
        if std < 1e-9:
            return 0.0
        return (value - self.mean) / std


class CUSUMTracker:
    """
    Two-sided Cumulative Sum (CUSUM) control chart for detecting persistent drift.
    """

    def __init__(self, threshold: float = 5.0, slack: float = 0.5):
        self.threshold = threshold
        self.slack = slack
        self.s_high: float = 0.0
        self.s_low: float = 0.0

    def update(self, value: float, mean: float, std: float) -> Tuple[bool, str]:
        """
        Updates CUSUM with normalized observation.
        Returns:
            (has_drifted, direction_str)
        """
        if std < 1e-9:
            return False, "none"

        z = (value - mean) / std
        self.s_high = max(0.0, self.s_high + z - self.slack)
        self.s_low = max(0.0, self.s_low - z - self.slack)

        if self.s_high > self.threshold:
            self.s_high = 0.0  # Reset on alarm
            return True, "high"
        if self.s_low > self.threshold:
            self.s_low = 0.0  # Reset on alarm
            return True, "low"

        return False, "none"

    def reset(self):
        self.s_high = 0.0
        self.s_low = 0.0


class DriftDetector:
    """
    Monitors telemetry streams for statistical drift, single-point outliers,
    zero-variance sensor freezes, and electrical/kinematic degradation.
    """

    def __init__(self, config: Optional[AnomalyConfig] = None):
        self.config = config or AnomalyConfig()
        self.welford_trackers: Dict[str, WelfordTracker] = {}
        self.cusum_trackers: Dict[str, CUSUMTracker] = {}
        self.freeze_buffers: Dict[str, Deque[float]] = {}

    def update(
        self,
        metric: str,
        value: float,
        source_node_id: str = "local",
        timestamp: Optional[float] = None,
    ) -> List[AnomalyReport]:
        """
        Evaluates a single telemetry sample for freeze, outlier, and CUSUM drift.
        """
        now = timestamp if timestamp is not None else time.time()
        reports: List[AnomalyReport] = []

        # 1. Sensor Freeze Check (zero variance / static output)
        if metric not in self.freeze_buffers:
            self.freeze_buffers[metric] = deque(maxlen=self.config.freeze_window_samples)
        buf = self.freeze_buffers[metric]
        buf.append(value)

        if len(buf) >= self.config.freeze_window_samples:
            value_span = max(buf) - min(buf)
            if value_span < self.config.freeze_epsilon:
                reports.append(
                    AnomalyReport(
                        anomaly_type=AnomalyType.SENSOR_FREEZE,
                        severity=AnomalySeverity.HIGH,
                        source_node_id=source_node_id,
                        metric=metric,
                        value=value,
                        confidence=0.95,
                        timestamp=now,
                        details={
                            "window_size": len(buf),
                            "value_span": value_span,
                            "frozen_value": value,
                        },
                    )
                )

        # 2. Online Welford Z-Score (Outlier Detection)
        if metric not in self.welford_trackers:
            self.welford_trackers[metric] = WelfordTracker()
        welford = self.welford_trackers[metric]

        if welford.count >= self.config.min_samples_for_zscore:
            z = abs(welford.z_score(value))
            if z > self.config.z_score_threshold:
                severity = AnomalySeverity.CRITICAL if z > (self.config.z_score_threshold * 1.5) else AnomalySeverity.HIGH
                reports.append(
                    AnomalyReport(
                        anomaly_type=AnomalyType.TELEMETRY_OUTLIER,
                        severity=severity,
                        source_node_id=source_node_id,
                        metric=metric,
                        value=value,
                        confidence=min(1.0, z / (self.config.z_score_threshold * 1.5)),
                        timestamp=now,
                        details={
                            "z_score": round(z, 3),
                            "mean": round(welford.mean, 3),
                            "std": round(welford.std, 3),
                            "threshold": self.config.z_score_threshold,
                        },
                    )
                )

        # 3. CUSUM Tracking (Cumulative Drift)
        if metric not in self.cusum_trackers:
            self.cusum_trackers[metric] = CUSUMTracker(
                threshold=self.config.cusum_threshold,
                slack=self.config.cusum_slack,
            )
        cusum = self.cusum_trackers[metric]

        if welford.count >= self.config.min_samples_for_zscore:
            drifted, direction = cusum.update(value, welford.mean, welford.std)
            if drifted:
                reports.append(
                    AnomalyReport(
                        anomaly_type=AnomalyType.STATISTICAL_DRIFT,
                        severity=AnomalySeverity.MEDIUM,
                        source_node_id=source_node_id,
                        metric=metric,
                        value=value,
                        confidence=0.85,
                        timestamp=now,
                        details={
                            "direction": direction,
                            "mean": round(welford.mean, 3),
                            "std": round(welford.std, 3),
                            "cusum_threshold": self.config.cusum_threshold,
                        },
                    )
                )

        # Update distribution tracker
        welford.update(value)
        return reports

    def evaluate_battery_cells(
        self,
        cells: List[float],
        source_node_id: str = "local",
        timestamp: Optional[float] = None,
    ) -> Optional[AnomalyReport]:
        """
        Monitors individual cell voltages for cell imbalance.
        """
        if not cells or len(cells) < 2:
            return None

        now = timestamp if timestamp is not None else time.time()
        max_v = max(cells)
        min_v = min(cells)
        delta_v = max_v - min_v

        if delta_v > self.config.battery_imbalance_max_delta_v:
            severity = AnomalySeverity.CRITICAL if delta_v > (self.config.battery_imbalance_max_delta_v * 2.0) else AnomalySeverity.HIGH
            return AnomalyReport(
                anomaly_type=AnomalyType.BATTERY_IMBALANCE,
                severity=severity,
                source_node_id=source_node_id,
                metric="battery_cell_spread",
                value=delta_v,
                confidence=min(1.0, delta_v / (self.config.battery_imbalance_max_delta_v * 1.5)),
                timestamp=now,
                details={
                    "cell_voltages": cells,
                    "delta_v": round(delta_v, 4),
                    "max_cell": round(max_v, 4),
                    "min_cell": round(min_v, 4),
                    "threshold": self.config.battery_imbalance_max_delta_v,
                },
            )
        return None

    def evaluate_motor_array(
        self,
        motor_readings: List[float],
        source_node_id: str = "local",
        metric_name: str = "motor_current",
        timestamp: Optional[float] = None,
    ) -> Optional[AnomalyReport]:
        """
        Monitors multi-rotor/actuator arrays for single-motor degradation or asymmetric load.
        """
        if not motor_readings or len(motor_readings) < 2:
            return None

        now = timestamp if timestamp is not None else time.time()
        mean_val = sum(motor_readings) / len(motor_readings)
        if mean_val < 1e-4:
            return None

        # Check maximum relative divergence from average
        max_deviation = max(abs(m - mean_val) for m in motor_readings)
        deviation_pct = max_deviation / mean_val

        if deviation_pct > self.config.motor_deviation_threshold_pct:
            return AnomalyReport(
                anomaly_type=AnomalyType.MOTOR_DEGRADATION,
                severity=AnomalySeverity.HIGH,
                source_node_id=source_node_id,
                metric=metric_name,
                value=deviation_pct,
                confidence=min(1.0, deviation_pct / (self.config.motor_deviation_threshold_pct * 1.5)),
                timestamp=now,
                details={
                    "motor_readings": motor_readings,
                    "mean_load": round(mean_val, 3),
                    "max_deviation": round(max_deviation, 3),
                    "deviation_pct": round(deviation_pct, 3),
                    "threshold": self.config.motor_deviation_threshold_pct,
                },
            )
        return None


class TamperDetector:
    """
    Evaluates CCTV camera diagnostics and physical mount sensor telemetry to detect:
    - Optical occlusion (covered camera / dark bag)
    - Spray-paint / sudden defocus (Laplacian edge variance collapse)
    - Physical angle shift or mounting shock (IMU jerk / tilt)
    - IR emitter failure
    """

    def __init__(self, config: Optional[AnomalyConfig] = None):
        self.config = config or AnomalyConfig()

    def evaluate_cctv(
        self,
        frame_stats: Dict[str, Any],
        source_node_id: str = "local",
        timestamp: Optional[float] = None,
    ) -> List[AnomalyReport]:
        """
        Evaluates frame diagnostic metrics.
        Expected keys in frame_stats:
            - 'mean_luminance': float (0.0 to 255.0)
            - 'laplacian_var': float (edge variance / sharpness)
            - 'tilt_angle_deg': Optional[float]
            - 'gyro_jerk_mps2': Optional[float]
            - 'ir_active': Optional[bool]
            - 'contrast': Optional[float]
        """
        now = timestamp if timestamp is not None else time.time()
        reports: List[AnomalyReport] = []

        mean_lum = frame_stats.get("mean_luminance")
        laplacian_var = frame_stats.get("laplacian_var")
        tilt_angle = frame_stats.get("tilt_angle_deg")
        gyro_jerk = frame_stats.get("gyro_jerk_mps2")
        ir_active = frame_stats.get("ir_active", False)
        contrast = frame_stats.get("contrast")

        # 1. Optical Occlusion (lens covered or dark cap)
        if mean_lum is not None and mean_lum < self.config.occlusion_luminance_threshold:
            # If IR is active or ambient is expected to have light, very low luminance indicates occlusion
            reports.append(
                AnomalyReport(
                    anomaly_type=AnomalyType.OPTICAL_OCCLUSION,
                    severity=AnomalySeverity.HIGH,
                    source_node_id=source_node_id,
                    metric="mean_luminance",
                    value=float(mean_lum),
                    confidence=0.92,
                    timestamp=now,
                    details={
                        "mean_luminance": mean_lum,
                        "threshold": self.config.occlusion_luminance_threshold,
                    },
                )
            )

        # 2. Spray-Paint / Severe Defocus (edge variance collapse while light exists)
        if laplacian_var is not None and mean_lum is not None:
            if laplacian_var < self.config.spray_blur_laplacian_threshold and mean_lum >= self.config.occlusion_luminance_threshold:
                reports.append(
                    AnomalyReport(
                        anomaly_type=AnomalyType.SPRAY_PAINT,
                        severity=AnomalySeverity.CRITICAL,
                        source_node_id=source_node_id,
                        metric="laplacian_var",
                        value=float(laplacian_var),
                        confidence=0.90,
                        timestamp=now,
                        details={
                            "laplacian_var": laplacian_var,
                            "mean_luminance": mean_lum,
                            "threshold": self.config.spray_blur_laplacian_threshold,
                        },
                    )
                )

        # 3. Angle Shift / Physical Mounting Shock
        if tilt_angle is not None and abs(tilt_angle) > self.config.angle_shift_threshold_deg:
            reports.append(
                AnomalyReport(
                    anomaly_type=AnomalyType.ANGLE_SHIFT,
                    severity=AnomalySeverity.HIGH,
                    source_node_id=source_node_id,
                    metric="tilt_angle_deg",
                    value=float(tilt_angle),
                    confidence=0.88,
                    timestamp=now,
                    details={
                        "tilt_angle_deg": tilt_angle,
                        "threshold": self.config.angle_shift_threshold_deg,
                    },
                )
            )
        elif gyro_jerk is not None and abs(gyro_jerk) > self.config.mount_jerk_threshold_mps2:
            reports.append(
                AnomalyReport(
                    anomaly_type=AnomalyType.ANGLE_SHIFT,
                    severity=AnomalySeverity.HIGH,
                    source_node_id=source_node_id,
                    metric="gyro_jerk_mps2",
                    value=float(gyro_jerk),
                    confidence=0.85,
                    timestamp=now,
                    details={
                        "gyro_jerk_mps2": gyro_jerk,
                        "threshold": self.config.mount_jerk_threshold_mps2,
                    },
                )
            )

        # 4. IR Emitter Failure (IR toggled ON but scene contrast or brightness fails to rise)
        if ir_active and contrast is not None and contrast < self.config.ir_failure_expected_contrast:
            reports.append(
                AnomalyReport(
                    anomaly_type=AnomalyType.IR_FAILURE,
                    severity=AnomalySeverity.MEDIUM,
                    source_node_id=source_node_id,
                    metric="contrast",
                    value=float(contrast),
                    confidence=0.80,
                    timestamp=now,
                    details={
                        "contrast": contrast,
                        "ir_active": ir_active,
                        "threshold": self.config.ir_failure_expected_contrast,
                    },
                )
            )

        return reports


class ByzantineQuorumVoting:
    """
    Byzantine Fault-Tolerant Quorum Arbiter.
    Manages proposal creation, peer ballot aggregation, and 2/3 supermajority consensus
    before triggering high-consequence physical actuator responses (lockdowns, sirens).
    """

    def __init__(self, config: Optional[AnomalyConfig] = None):
        self.config = config or AnomalyConfig()
        self.proposals: Dict[str, QuorumProposal] = {}

    def propose(
        self,
        incident_id: str,
        proposer: str,
        anomaly_type: AnomalyType,
        target_action: str,
        evidence: Optional[Dict[str, Any]] = None,
        total_nodes: int = 1,
        auto_vote: bool = True,
    ) -> QuorumProposal:
        """
        Creates a new quorum proposal and opens voting.
        """
        now = time.time()
        proposal = QuorumProposal(
            incident_id=incident_id,
            proposer=proposer,
            anomaly_type=anomaly_type,
            target_action=target_action,
            evidence=evidence or {},
            votes={},
            status=QuorumStatus.VOTING,
            created_at=now,
            expires_at=now + self.config.voting_timeout_s,
            total_nodes=max(1, total_nodes),
        )
        if auto_vote:
            proposal.votes[proposer] = True

        self.proposals[incident_id] = proposal
        self._evaluate_quorum(proposal)
        return proposal

    def vote(
        self,
        incident_id: str,
        voter_id: str,
        approve: bool,
        total_nodes: Optional[int] = None,
    ) -> Tuple[QuorumStatus, QuorumProposal]:
        """
        Records a vote from a distinct peer node and re-evaluates consensus status.
        Returns:
            (current_status, proposal)
        """
        if incident_id not in self.proposals:
            raise KeyError(f"Quorum proposal '{incident_id}' not found.")

        proposal = self.proposals[incident_id]
        if total_nodes is not None and total_nodes > 0:
            proposal.total_nodes = total_nodes

        # Check if expired
        if time.time() > proposal.expires_at and proposal.status == QuorumStatus.VOTING:
            proposal.status = QuorumStatus.EXPIRED
            return proposal.status, proposal

        if proposal.status != QuorumStatus.VOTING:
            return proposal.status, proposal

        # Record vote
        proposal.votes[voter_id] = bool(approve)
        self._evaluate_quorum(proposal)
        return proposal.status, proposal

    def _evaluate_quorum(self, proposal: QuorumProposal):
        """
        Evaluates whether proposal has achieved supermajority or is mathematically impossible.
        """
        n = max(1, proposal.total_nodes)
        required_approvals = max(1, math.floor(n * self.config.quorum_fraction) + 1)
        max_possible_approvals = n - proposal.reject_count

        if proposal.approve_count >= required_approvals:
            proposal.status = QuorumStatus.COMMITTED
        elif max_possible_approvals < required_approvals:
            proposal.status = QuorumStatus.REJECTED

    def check_expirations(self) -> List[QuorumProposal]:
        """
        Scans active proposals and transitions overdue ones to EXPIRED.
        """
        now = time.time()
        expired: List[QuorumProposal] = []
        for prop in self.proposals.values():
            if prop.status == QuorumStatus.VOTING and now > prop.expires_at:
                prop.status = QuorumStatus.EXPIRED
                expired.append(prop)
        return expired

    def get_proposal(self, incident_id: str) -> Optional[QuorumProposal]:
        return self.proposals.get(incident_id)


# Alias for architectural naming consistency
ByzantineQuorumArbiter = ByzantineQuorumVoting
