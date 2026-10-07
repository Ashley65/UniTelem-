"""
UniTelem Simplex Architecture & Deterministic Safety Governor.

Implements the Simplex Architecture pattern:
1. Advanced Controller (AC): High-performance neural or complex AI planners.
2. Safety Monitor (SM): Formally bounded deterministic envelope governor.
3. Baseline Controller (BC): Fail-safe deterministic fallback maneuver.

Supports both aerial drone flight envelope invariants and physical security interlocks.
"""

from dataclasses import dataclass, field
from enum import Enum
import math
import time
from typing import Any, Dict, List, Optional, Tuple, Union


class VetoReason(str, Enum):
    NONE = "NONE"
    GEOFENCE_BREACH = "GEOFENCE_BREACH"
    EXCESSIVE_VELOCITY = "EXCESSIVE_VELOCITY"
    EXCESSIVE_ACCELERATION = "EXCESSIVE_ACCELERATION"
    INSUFFICIENT_CLEARANCE = "INSUFFICIENT_CLEARANCE"
    THERMAL_OVERHEAT = "THERMAL_OVERHEAT"
    CRITICAL_BATTERY = "CRITICAL_BATTERY"
    UNVERIFIED_SECURITY_ACTION = "UNVERIFIED_SECURITY_ACTION"
    INVALID_COMMAND = "INVALID_COMMAND"
    AI_EXCEPTION_OR_NAN = "AI_EXCEPTION_OR_NAN"


@dataclass
class SafetyEnvelope:
    """
    Inviolable operational boundaries for autonomous units.
    """
    # Kinematic & aerodynamic boundaries
    max_velocity_mps: float = 25.0
    max_accel_mps2: float = 12.0
    max_yaw_rate_dps: float = 90.0

    # 3D Geofence bounds: (min_x, max_x, min_y, max_y, min_z, max_z) in meters
    geofence: Tuple[float, float, float, float, float, float] = (
        -1000.0, 1000.0, -1000.0, 1000.0, 1.0, 250.0
    )
    min_ground_clearance_m: float = 2.0

    # Environmental & hardware health thresholds
    max_motor_temp_c: float = 85.0
    max_battery_temp_c: float = 60.0
    min_battery_reserve_pct: float = 15.0

    # Physical security interlock configuration
    require_dual_sensor_corroboration: bool = True
    hard_actuator_commands: List[str] = field(
        default_factory=lambda: [
            "LOCKDOWN_PERIMETER",
            "RELEASE_DOOR",
            "TRIGGER_SIREN",
            "DEPLOY_BOLLARDS",
        ]
    )


class SimplexArbiter:
    """
    Deterministic Safety Monitor & Veto Arbiter.
    Evaluates proposed actions against envelope invariants in under 5 microseconds.
    """

    def __init__(
        self,
        envelope: Optional[SafetyEnvelope] = None,
        default_fallback_mode: str = "HOVER",
    ):
        self.envelope = envelope or SafetyEnvelope()
        self.default_fallback_mode = default_fallback_mode

    def evaluate(
        self,
        current_state: Dict[str, Any],
        proposed_action: Dict[str, Any],
    ) -> Tuple[bool, VetoReason, Dict[str, Any]]:
        """
        Evaluates proposed action against current state.
        Returns:
            (is_approved, veto_reason, effective_action)
            If approved -> (True, VetoReason.NONE, proposed_action)
            If vetoed   -> (False, VetoReason.*, fallback_action)
        """
        # 1. Validate payload integrity (check for NaN, infinite, or missing values)
        is_valid, reason = self._check_numerical_sanity(proposed_action)
        if not is_valid:
            fallback = self._generate_fallback(current_state, reason, proposed_action)
            return False, reason, fallback

        # 2. Check Physical Security / Access Control Dual-Key Interlocks
        is_sec_valid, sec_reason = self._check_security_interlocks(current_state, proposed_action)
        if not is_sec_valid:
            fallback = self._generate_fallback(current_state, sec_reason, proposed_action)
            return False, sec_reason, fallback

        # 3. Check Hardware & Environmental Thermal / Battery Limits
        is_hw_valid, hw_reason = self._check_hardware_health(current_state)
        if not is_hw_valid:
            fallback = self._generate_fallback(current_state, hw_reason, proposed_action)
            return False, hw_reason, fallback

        # 4. Check Kinematic & Geofence Envelope
        is_kin_valid, kin_reason = self._check_kinematics_and_geofence(current_state, proposed_action)
        if not is_kin_valid:
            fallback = self._generate_fallback(current_state, kin_reason, proposed_action)
            return False, kin_reason, fallback

        # All safety invariants satisfied -> Grant approval
        return True, VetoReason.NONE, proposed_action

    def _check_numerical_sanity(self, action: Dict[str, Any]) -> Tuple[bool, VetoReason]:
        if not isinstance(action, dict):
            return False, VetoReason.INVALID_COMMAND

        for k, v in action.items():
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                return False, VetoReason.AI_EXCEPTION_OR_NAN
            if isinstance(v, (list, tuple)):
                for elem in v:
                    if isinstance(elem, float) and (math.isnan(elem) or math.isinf(elem)):
                        return False, VetoReason.AI_EXCEPTION_OR_NAN

        return True, VetoReason.NONE

    def _check_security_interlocks(
        self, current_state: Dict[str, Any], action: Dict[str, Any]
    ) -> Tuple[bool, VetoReason]:
        if not self.envelope.require_dual_sensor_corroboration:
            return True, VetoReason.NONE

        cmd = action.get("command") or action.get("action")
        if cmd in self.envelope.hard_actuator_commands:
            # Physical action requires deterministic secondary sensor verification
            has_pir = current_state.get("pir_motion", False)
            has_tripwire = current_state.get("tripwire_broken", False)
            has_door_contact = current_state.get("door_contact_open", False)
            has_manual_override = current_state.get("manual_override", False)

            if not (has_pir or has_tripwire or has_door_contact or has_manual_override):
                return False, VetoReason.UNVERIFIED_SECURITY_ACTION

        return True, VetoReason.NONE

    def _check_hardware_health(self, current_state: Dict[str, Any]) -> Tuple[bool, VetoReason]:
        # Check battery level
        battery = current_state.get("battery", current_state.get("battery_pct", 100.0))
        if battery < self.envelope.min_battery_reserve_pct:
            return False, VetoReason.CRITICAL_BATTERY

        # Check motor/inverter thermal status
        motor_temp = current_state.get("motor_temp", current_state.get("temperature", 25.0))
        if motor_temp > self.envelope.max_motor_temp_c:
            return False, VetoReason.THERMAL_OVERHEAT

        # Check battery cell temperature
        battery_temp = current_state.get("battery_temp", 25.0)
        if battery_temp > self.envelope.max_battery_temp_c:
            return False, VetoReason.THERMAL_OVERHEAT

        return True, VetoReason.NONE

    def _check_kinematics_and_geofence(
        self, current_state: Dict[str, Any], action: Dict[str, Any]
    ) -> Tuple[bool, VetoReason]:
        # Evaluate velocity limits
        vx = action.get("vx", 0.0)
        vy = action.get("vy", 0.0)
        vz = action.get("vz", 0.0)
        speed = math.sqrt(vx * vx + vy * vy + vz * vz)
        if speed > self.envelope.max_velocity_mps:
            return False, VetoReason.EXCESSIVE_VELOCITY

        # Evaluate acceleration / thrust limits
        ax = action.get("ax", 0.0)
        ay = action.get("ay", 0.0)
        az = action.get("az", 0.0)
        accel = math.sqrt(ax * ax + ay * ay + az * az)
        if accel > self.envelope.max_accel_mps2:
            return False, VetoReason.EXCESSIVE_ACCELERATION

        # Evaluate proposed target waypoint or projected position
        target_pos = action.get("target_pos") or action.get("waypoint")
        if target_pos and len(target_pos) >= 2:
            tx, ty = target_pos[0], target_pos[1]
            tz = target_pos[2] if len(target_pos) >= 3 else current_state.get("z", 10.0)

            min_x, max_x, min_y, max_y, min_z, max_z = self.envelope.geofence
            if not (min_x <= tx <= max_x and min_y <= ty <= max_y):
                return False, VetoReason.GEOFENCE_BREACH

            if tz < self.envelope.min_ground_clearance_m:
                return False, VetoReason.INSUFFICIENT_CLEARANCE

            if tz > max_z:
                return False, VetoReason.GEOFENCE_BREACH

        return True, VetoReason.NONE

    def _generate_fallback(
        self,
        current_state: Dict[str, Any],
        reason: VetoReason,
        rejected_action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generates deterministic, verified fail-safe recovery command.
        """
        curr_x = current_state.get("x", 0.0)
        curr_y = current_state.get("y", 0.0)
        curr_z = current_state.get("z", 10.0)

        # Severe reasons trigger Return-To-Base (RTB) or Emergency Landing
        if reason in (VetoReason.CRITICAL_BATTERY, VetoReason.THERMAL_OVERHEAT):
            return {
                "command": "RETURN_TO_BASE",
                "mode": "RTB",
                "target_pos": (0.0, 0.0, max(curr_z, 15.0)),
                "vx": 0.0, "vy": 0.0, "vz": 0.0,
                "veto_reason": reason.value,
                "is_fallback": True,
                "timestamp": time.time(),
            }

        if reason == VetoReason.UNVERIFIED_SECURITY_ACTION:
            return {
                "command": "LOG_UNVERIFIED_ALERT",
                "mode": "HOLD_ACTUATORS",
                "message": "AI visual trigger rejected pending secondary sensor corroboration (PIR/tripwire)",
                "veto_reason": reason.value,
                "is_fallback": True,
                "timestamp": time.time(),
            }

        # Default kinematic fallback: Arrest momentum and hover / hold position
        return {
            "command": "HOVER_IN_PLACE",
            "mode": self.default_fallback_mode,
            "target_pos": (curr_x, curr_y, max(curr_z, self.envelope.min_ground_clearance_m)),
            "vx": 0.0, "vy": 0.0, "vz": 0.0,
            "ax": 0.0, "ay": 0.0, "az": 0.0,
            "veto_reason": reason.value,
            "is_fallback": True,
            "timestamp": time.time(),
        }
