"""
UniTelem AI Vision Node.

Optional specialized node for soft-biometric POI matching, natural-language visual querying, and cross-camera tracking handovers.

Core Capabilities:
    - Soft-Biometric Classification: Connects to ONNX vision backends to extract upper/lower clothing colours,
      types, and accessories without facial recognition.

    - Cross-Camera Trajectory Hand-off: Extrapolates pedestrian movement vectors and gossips search profiles (vision/handoff)
      to adjacent camera nodes in the mesh.

    - Zero-Shot Natural Language Search: Resolves operator queries ("find person in red jacket with backpack") across decentralized mesh detections.

"""