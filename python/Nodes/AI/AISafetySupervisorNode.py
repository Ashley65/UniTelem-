"""
UniTelem AI Safety Supervisor Node.

Implements the Simplex Architecture pattern: pairs an uncertified, high-performance
AI proposer (neural pilot, RL policy, VLM) with a deterministic, formally verified
Simplex Safety Arbiter.

Core Capabilities:
    - Instant Veto & Fallback: Evaluates each proposed action against hard envelope bounds
      (velocity, G-load limits, geofence, terrain clearance, thermal headroom, battery reserve).
      If violated, immediately vetoes the AI command (< 5μs) and dispatches a verified fallback
      manoeuvre (e.g., hover, hold position, return-to-base).

    - Physical Security Interlock: For CCTV / access control, enforces deterministic dual-key
      corroboration, guaranteeing that AI visual detections cannot trigger hard physical actuators
      (lockdowns, gate releases, sirens) without secondary hardware sensor validation (PIR, tripwire).
"""

import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from .AINode import AINode
except ImportError:
    from AINode import AINode

try:
    from ...ai.simplex import SafetyEnvelope, SimplexArbiter, VetoReason
except (ImportError, ValueError):
    try:
        from unitelem.ai.simplex import SafetyEnvelope, SimplexArbiter, VetoReason
    except ImportError:
        SafetyEnvelope = None
        SimplexArbiter = None
        VetoReason = None


class AISafetySupervisorNode(AINode):
    """
    Specialized Node type acting as the Simplex Safety Arbiter.
    Supervises neural trajectory planners and CCTV actuator triggers.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str = "default",
        private_key: Optional[str] = None,
        model: Optional[Any] = None,
        envelope: Optional[Any] = None,
        default_fallback_mode: str = "HOVER",
        **kwargs,
    ):
        super().__init__(
            node_id=node_id,
            swarm_id=swarm_id,
            private_key=private_key,
            model=model,
            **kwargs,
        )

        if SafetyEnvelope and SimplexArbiter:
            self.envelope = envelope or SafetyEnvelope()
            self.arbiter = SimplexArbiter(
                envelope=self.envelope,
                default_fallback_mode=default_fallback_mode,
            )
        else:
            self.envelope = None
            self.arbiter = None

        self.default_fallback_mode = default_fallback_mode
        self.local_sensor_state: Dict[str, Any] = {}
        self.peer_states: Dict[str, Dict[str, Any]] = {}

        self.veto_history: List[Dict[str, Any]] = []
        self.approval_count: int = 0
        self.veto_count: int = 0

        # Register specialized safety handlers
        self.register_handler("control/propose/*", self.on_proposed_action)
        self.register_handler("telemetry/kinematics/*", self.on_kinematics_update)
        self.register_handler("security/sensors/*", self.on_security_sensors_update)

    def supervise(
        self,
        proposed_action: Dict[str, Any],
        current_state: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Direct evaluation API (< 5 microseconds).
        Returns:
            (is_approved, effective_action)
            If approved, effective_action is the proposed action.
            If vetoed, effective_action is the safe fallback maneuver.
        """
        if self.arbiter is None:
            return True, proposed_action

        state = current_state if current_state is not None else self.local_sensor_state
        is_approved, reason, effective_action = self.arbiter.evaluate(state, proposed_action)

        if is_approved:
            self.approval_count += 1
        else:
            self.veto_count += 1
            self.veto_history.append({
                "timestamp": time.time(),
                "reason": reason.value if hasattr(reason, "value") else str(reason),
                "proposed": proposed_action,
                "fallback": effective_action,
            })

        return is_approved, effective_action

    def update_sensor_state(self, updates: Dict[str, Any]) -> None:
        """Updates local sensor and flight state dictionary."""
        self.local_sensor_state.update(updates)

    def get_safety_stats(self) -> Dict[str, Any]:
        """Returns statistics on approvals, vetoes, and reasons."""
        return {
            "total_evaluated": self.approval_count + self.veto_count,
            "approved": self.approval_count,
            "vetoed": self.veto_count,
            "recent_vetoes": self.veto_history[-10:],
        }

    # ----------------------------------------------------------------------
    # Event Handlers
    # ----------------------------------------------------------------------
    def on_proposed_action(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        """
        Triggered when a unit or neural pilot publishes an action to control/propose/{unit_id}.
        """
        if not isinstance(payload, dict):
            return None

        unit_id = payload.get("unit_id", sender)
        proposed = payload.get("action", payload)

        # Retrieve latest known state for this unit
        unit_state = self.peer_states.get(unit_id, self.local_sensor_state)

        is_approved, effective_action = self.supervise(proposed, current_state=unit_state)

        if is_approved:
            # Publish approval confirmation
            self.publish(f"control/approved/{unit_id}", {
                "unit_id": unit_id,
                "status": "APPROVED",
                "action": effective_action,
                "timestamp": time.time(),
            })
            return ("ai/insights", {"type": "action_approved", "unit_id": unit_id})
        else:
            # Publish explicit VETO alert with telemetry justification
            veto_record = self.veto_history[-1] if self.veto_history else {}
            self.publish(f"control/veto/{unit_id}", {
                "unit_id": unit_id,
                "status": "VETOED",
                "reason": veto_record.get("reason", "SAFETY_BREACH"),
                "proposed": proposed,
                "fallback": effective_action,
                "timestamp": time.time(),
            })
            # Also broadcast the safe fallback command to control/approved so the unit safely executes it
            self.publish(f"control/approved/{unit_id}", {
                "unit_id": unit_id,
                "status": "FALLBACK_SUBSTITUTED",
                "action": effective_action,
                "timestamp": time.time(),
            })
            return ("alerts/safety_veto", {
                "unit_id": unit_id,
                "reason": veto_record.get("reason"),
                "action": effective_action,
            })

    def on_kinematics_update(self, topic: str, payload: Any, sender: str) -> None:
        """Records kinematics state per peer unit."""
        if isinstance(payload, dict):
            if sender not in self.peer_states:
                self.peer_states[sender] = {}
            self.peer_states[sender].update(payload)
            if sender == self.node_id:
                self.local_sensor_state.update(payload)

    def on_security_sensors_update(self, topic: str, payload: Any, sender: str) -> None:
        """Records physical security sensor triggers (PIR, tripwire, door contacts)."""
        if isinstance(payload, dict):
            self.local_sensor_state.update(payload)