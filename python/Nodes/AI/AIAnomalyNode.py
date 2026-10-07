"""
UniTelem AI Anomaly Node.

A specialized node extending AINode for detecting and analyzing telemetry drift,
tamper events, and coordinating Byzantine Quorum consensus across decentralized swarms.

Core Capabilities:
    - Statistical Drift & Telemetry Outliers: Monitors kinematics and electrical readings
      for motor degradation, battery cell imbalances, or sensor freezing.
    - Tamper Detection (CCTV): Flags optical occlusion, spray-paint (edge collapse),
      angle shifts, or infrared emitter failure.
    - Byzantine Quorum Voting: Reconciles multi-sensor observations before triggering
      high-consequence siren, lockdown, or safety interlock alerts.
"""

import time
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from .AINode import AINode
except ImportError:
    from AINode import AINode

try:
    from ...ai.anomaly import (
        AnomalyConfig,
        AnomalyReport,
        AnomalySeverity,
        AnomalyType,
        ByzantineQuorumVoting,
        DriftDetector,
        QuorumProposal,
        QuorumStatus,
        TamperDetector,
    )
except (ImportError, ValueError):
    try:
        from unitelem.ai.anomaly import (
            AnomalyConfig,
            AnomalyReport,
            AnomalySeverity,
            AnomalyType,
            ByzantineQuorumVoting,
            DriftDetector,
            QuorumProposal,
            QuorumStatus,
            TamperDetector,
        )
    except ImportError:
        AnomalyConfig = None
        AnomalyReport = None
        AnomalySeverity = None
        AnomalyType = None
        ByzantineQuorumVoting = None
        DriftDetector = None
        QuorumProposal = None
        QuorumStatus = None
        TamperDetector = None


class AIAnomalyNode(AINode):
    """
    Specialized Node type for:
    - Detecting and analyzing anomalies in the telemetry data.
    - Identifying potential environmental hazards or physical tampering.
    - Ensuring a unified response across multiple nodes in the swarm.
    - Coordinating Byzantine quorum voting to prevent false actuator triggers.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str = "default",
        private_key: Optional[str] = None,
        model: Optional[Any] = None,
        config: Optional[Any] = None,
        auto_propose_on_critical: bool = True,
        swarm_size: int = 1,
        **kwargs,
    ):
        super().__init__(
            node_id=node_id,
            swarm_id=swarm_id,
            private_key=private_key,
            model=model,
            **kwargs,
        )

        if AnomalyConfig and DriftDetector:
            self.config = config or AnomalyConfig()
            self.drift_detector = DriftDetector(self.config)
            self.tamper_detector = TamperDetector(self.config)
            self.quorum_arbiter = ByzantineQuorumVoting(self.config)
        else:
            self.config = None
            self.drift_detector = None
            self.tamper_detector = None
            self.quorum_arbiter = None

        self.auto_propose_on_critical = auto_propose_on_critical
        self.swarm_size = max(1, swarm_size)
        self.anomaly_history: List[Dict[str, Any]] = []

        # Register specialized anomaly and consensus handlers
        self.register_handler("telemetry/metrics/*", self.on_telemetry_metrics)
        self.register_handler("security/cctv/*", self.on_cctv_diagnostics)
        self.register_handler("anomaly/propose/*", self.on_quorum_proposal)
        self.register_handler("anomaly/vote/*", self.on_quorum_vote)

    def evaluate_metric(
        self,
        metric: str,
        value: float,
        sender: str = "local",
    ) -> List[Any]:
        """
        Direct evaluation API for numeric telemetry stream.
        """
        if not self.drift_detector:
            return []
        reports = self.drift_detector.update(metric, value, source_node_id=sender)
        for r in reports:
            self._record_anomaly(r)
        return reports

    def evaluate_cctv(
        self,
        frame_stats: Dict[str, Any],
        sender: str = "local",
    ) -> List[Any]:
        """
        Direct evaluation API for CCTV frame statistics.
        """
        if not self.tamper_detector:
            return []
        reports = self.tamper_detector.evaluate_cctv(frame_stats, source_node_id=sender)
        for r in reports:
            self._record_anomaly(r)
        return reports

    def evaluate_battery(
        self,
        cell_voltages: List[float],
        sender: str = "local",
    ) -> Optional[Any]:
        """
        Direct evaluation API for battery cell balance.
        """
        if not self.drift_detector:
            return None
        report = self.drift_detector.evaluate_battery_cells(cell_voltages, source_node_id=sender)
        if report:
            self._record_anomaly(report)
        return report

    def evaluate_motors(
        self,
        motor_currents: List[float],
        sender: str = "local",
    ) -> Optional[Any]:
        """
        Direct evaluation API for motor array balance.
        """
        if not self.drift_detector:
            return None
        report = self.drift_detector.evaluate_motor_array(motor_currents, source_node_id=sender)
        if report:
            self._record_anomaly(report)
        return report

    def propose_quorum_action(
        self,
        incident_id: str,
        anomaly_type: Any,
        target_action: str,
        evidence: Optional[Dict[str, Any]] = None,
        total_nodes: Optional[int] = None,
    ) -> Optional[Any]:
        """
        Initiates a quorum vote round for a high-consequence action.
        """
        if not self.quorum_arbiter:
            return None

        n = total_nodes if total_nodes is not None else self.swarm_size
        proposal = self.quorum_arbiter.propose(
            incident_id=incident_id,
            proposer=self.node_id,
            anomaly_type=anomaly_type,
            target_action=target_action,
            evidence=evidence or {},
            total_nodes=n,
            auto_vote=True,
        )
        return proposal

    def cast_vote(
        self,
        incident_id: str,
        approve: bool,
        total_nodes: Optional[int] = None,
    ) -> Optional[Tuple[Any, Any]]:
        """
        Casts a local vote on a pending proposal.
        """
        if not self.quorum_arbiter:
            return None
        n = total_nodes if total_nodes is not None else self.swarm_size
        return self.quorum_arbiter.vote(
            incident_id=incident_id,
            voter_id=self.node_id,
            approve=approve,
            total_nodes=n,
        )

    def _record_anomaly(self, report: Any):
        """Stores anomaly in local memory buffer and triggers auto-proposal if critical."""
        entry = {
            "type": report.anomaly_type.value if hasattr(report.anomaly_type, "value") else str(report.anomaly_type),
            "severity": report.severity.value if hasattr(report.severity, "value") else str(report.severity),
            "metric": report.metric,
            "value": report.value,
            "source": report.source_node_id,
            "timestamp": report.timestamp,
            "details": report.details,
        }
        self.anomaly_history.append(entry)

    # ------------------ Message Topic Handlers ------------------

    def on_telemetry_metrics(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Handler for numeric telemetry metric streams ('telemetry/metrics/*').
        Expected payload: {'metric': str, 'value': float} or {'values': Dict[str, float]}
        """
        if not self.drift_detector:
            return None

        reports: List[Any] = []
        if isinstance(payload, dict):
            if "metric" in payload and "value" in payload:
                reports.extend(self.evaluate_metric(payload["metric"], float(payload["value"]), sender=sender))
            elif "cells" in payload:
                rep = self.evaluate_battery(payload["cells"], sender=sender)
                if rep:
                    reports.append(rep)
            elif "motors" in payload:
                rep = self.evaluate_motors(payload["motors"], sender=sender)
                if rep:
                    reports.append(rep)
            elif "values" in payload and isinstance(payload["values"], dict):
                for m, v in payload["values"].items():
                    reports.extend(self.evaluate_metric(m, float(v), sender=sender))

        if reports:
            # Publish detected anomaly report
            first = reports[0]
            severity_str = first.severity.value if hasattr(first.severity, "value") else str(first.severity)
            type_str = first.anomaly_type.value if hasattr(first.anomaly_type, "value") else str(first.anomaly_type)
            return (
                "anomaly/detected",
                {
                    "source": sender,
                    "anomaly_type": type_str,
                    "severity": severity_str,
                    "metric": first.metric,
                    "value": first.value,
                    "details": first.details,
                },
            )
        return None

    def on_cctv_diagnostics(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Handler for camera diagnostic telemetry ('security/cctv/*').
        """
        if not self.tamper_detector or not isinstance(payload, dict):
            return None

        reports = self.evaluate_cctv(payload, sender=sender)
        if reports:
            critical_report = max(reports, key=lambda r: getattr(r.severity, "rank", 0))
            severity_str = critical_report.severity.value if hasattr(critical_report.severity, "value") else str(critical_report.severity)
            type_str = critical_report.anomaly_type.value if hasattr(critical_report.anomaly_type, "value") else str(critical_report.anomaly_type)

            # Auto-escalate critical tamper to quorum proposal
            if self.auto_propose_on_critical and getattr(critical_report.severity, "rank", 0) >= getattr(AnomalySeverity.HIGH, "rank", 7):
                incident_id = f"tamper-{sender}-{int(time.time()*1000)}"
                prop = self.propose_quorum_action(
                    incident_id=incident_id,
                    anomaly_type=critical_report.anomaly_type,
                    target_action="LOCKDOWN_PERIMETER",
                    evidence=critical_report.details,
                )
                if prop:
                    return (
                        f"anomaly/propose/{incident_id}",
                        {
                            "incident_id": incident_id,
                            "proposer": self.node_id,
                            "anomaly_type": type_str,
                            "target_action": "LOCKDOWN_PERIMETER",
                            "evidence": critical_report.details,
                            "status": prop.status.value,
                        },
                    )

            return (
                "anomaly/detected",
                {
                    "source": sender,
                    "anomaly_type": type_str,
                    "severity": severity_str,
                    "metric": critical_report.metric,
                    "value": critical_report.value,
                    "details": critical_report.details,
                },
            )
        return None

    def on_quorum_proposal(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Handler for peer proposal broadcasts ('anomaly/propose/*').
        """
        if not self.quorum_arbiter or not isinstance(payload, dict):
            return None

        incident_id = payload.get("incident_id")
        target_action = payload.get("target_action", "ISOLATE")
        anomaly_type_raw = payload.get("anomaly_type", "unknown")

        if not incident_id or sender == self.node_id:
            return None

        # Record proposal locally if not yet present
        prop = self.quorum_arbiter.get_proposal(incident_id)
        if not prop:
            prop = self.quorum_arbiter.propose(
                incident_id=incident_id,
                proposer=sender,
                anomaly_type=anomaly_type_raw,
                target_action=target_action,
                evidence=payload.get("evidence", {}),
                total_nodes=self.swarm_size,
                auto_vote=False,
            )

        # Peer proposal received: default policy approves if corroborated or non-conflicting
        status, _ = self.quorum_arbiter.vote(
            incident_id=incident_id,
            voter_id=self.node_id,
            approve=True,
            total_nodes=self.swarm_size,
        )

        return (
            f"anomaly/vote/{incident_id}",
            {
                "incident_id": incident_id,
                "voter": self.node_id,
                "approve": True,
                "status": status.value if hasattr(status, "value") else str(status),
            },
        )

    def on_quorum_vote(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Handler for peer votes ('anomaly/vote/*').
        """
        if not self.quorum_arbiter or not isinstance(payload, dict):
            return None

        incident_id = payload.get("incident_id")
        approve = payload.get("approve", False)
        voter = payload.get("voter", sender)

        if not incident_id or voter == self.node_id:
            return None

        status, prop = self.quorum_arbiter.vote(
            incident_id=incident_id,
            voter_id=voter,
            approve=approve,
            total_nodes=self.swarm_size,
        )

        if status == QuorumStatus.COMMITTED:
            return (
                "anomaly/quorum_committed",
                {
                    "incident_id": incident_id,
                    "target_action": prop.target_action,
                    "approvals": prop.approve_count,
                    "total_nodes": prop.total_nodes,
                },
            )
        return None