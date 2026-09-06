"""
UniTelem Dynamic Spatial Partitioning & Smart Spacing Engine.

Provides discrete 2D Voronoi territory slicing, blind-spot healing,
and collision-prevention spacing vectors for drone swarms and camera networks.
"""

import math
from typing import Any, Dict, List, Optional, Tuple


class VoronoiPartitioner:
    """
    Computes dynamic territory partitions and centroids across active mesh nodes.
    Pure Python with zero external dependencies.
    """

    def __init__(self, bounds: Tuple[float, float, float, float] = (0.0, 1000.0, 0.0, 1000.0)):
        # (min_x, max_x, min_y, max_y)
        self.min_x, self.max_x, self.min_y, self.max_y = bounds
        self.width = max(1.0, self.max_x - self.min_x)
        self.height = max(1.0, self.max_y - self.min_y)

    def partition(
        self,
        node_positions: Dict[str, Tuple[float, float]],
        grid_res: int = 40,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Partitions the search area among active nodes.
        Returns for each node:
          - 'Area_pct': Percentage of total area claimed
          - 'Centroid': (cx, cy) centre of gravity of claimed cell
          - 'Point_count': Number of discrete grid points owned
        """
        if not node_positions:
            return {}

        nodes = list(node_positions.items())
        point_counts: Dict[str, int] = {node_id: 0 for node_id, _ in nodes}
        sum_x: Dict[str, float] = {node_id: 0.0 for node_id, _ in nodes}
        sum_y: Dict[str, float] = {node_id: 0.0 for node_id, _ in nodes}

        dx = self.width / grid_res
        dy = self.height / grid_res
        total_points = grid_res * grid_res

        for i in range(grid_res):
            gx = self.min_x + (i + 0.5) * dx
            for j in range(grid_res):
                gy = self.min_y + (j + 0.5) * dy

                # Find closest node
                best_node = None
                best_dist_sq = float("inf")
                for node_id, (nx, ny) in nodes:
                    dist_sq = (gx - nx) ** 2 + (gy - ny) ** 2
                    if dist_sq < best_dist_sq:
                        best_dist_sq = dist_sq
                        best_node = node_id

                if best_node:
                    point_counts[best_node] += 1
                    sum_x[best_node] += gx
                    sum_y[best_node] += gy

        results: Dict[str, Dict[str, Any]] = {}
        for node_id in point_counts:
            cnt = point_counts[node_id]
            pct = (cnt / total_points) * 100.0 if total_points > 0 else 0.0
            cx = (sum_x[node_id] / cnt) if cnt > 0 else node_positions[node_id][0]
            cy = (sum_y[node_id] / cnt) if cnt > 0 else node_positions[node_id][1]

            results[node_id] = {
                "area_pct": round(pct, 2),
                "centroid": (round(cx, 2), round(cy, 2)),
                "point_count": cnt,
            }

        return results

    def compute_spacing_repulsion(
        self,
        node_id: str,
        node_positions: Dict[str, Tuple[float, float]],
        min_safe_distance: float = 20.0,
    ) -> Tuple[float, float]:
        """
        Computes an anti-collision repulsive force vector away from neighbours
        that violate the minimum safety distance.
        Returns: (force_x, force_y)
        """
        if node_id not in node_positions:
            return (0.0, 0.0)

        my_pos = node_positions[node_id]
        fx, fy = 0.0, 0.0

        for peer_id, peer_pos in node_positions.items():
            if peer_id == node_id:
                continue
            dx = my_pos[0] - peer_pos[0]
            dy = my_pos[1] - peer_pos[1]
            dist = math.sqrt(dx * dx + dy * dy)

            if 0.001 < dist < min_safe_distance:
                # Strong inverse-square repulsion
                strength = (min_safe_distance - dist) / dist
                fx += (dx / dist) * strength
                fy += (dy / dist) * strength

        return (round(fx, 4), round(fy, 4))
