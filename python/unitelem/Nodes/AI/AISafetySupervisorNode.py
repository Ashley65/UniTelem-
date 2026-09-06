"""
UniTelem AI Safety Supervisor Node.

Optional node pairing a neural path/policy proposer with a deterministic, formally verified Simplex safety veto.

Core Capabilities:
    - Instant Veto & Fallback: Evaluates each proposed action against hard envelope bounds (G-load limits, geofence, terrain clearance,
      thermal headroom). If violated, immediately vetoes the AI command and dispatches a verified fallback manoeuvre (e.g., hover, hold position, return-to-base).

    - Physical Security Interlock: For CCTV/access control, ensures AI visual detections cannot trigger hard physical actuators (lockdowns, gate releases)
      without deterministic multi-sensor validation (tripwire, PIR).

"""