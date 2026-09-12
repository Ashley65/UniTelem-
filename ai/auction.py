"""
UniTelem Market-Based Decentralised Job Auction Engine.

Provides automated job announcements, cost bidding, and winner settlement
for autonomous drone tasks and CCTV PTZ camera handovers.
"""

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Job:
    """Represents a task open for bidding in the mesh."""
    job_id: str
    task_type: str  # e.g., 'waypoint_inspect', 'poi_track', 'perimeter_sweep'
    location: Tuple[float, float]  # (x, y) coordinates
    deadline_s: float = 2.0  # Bidding window duration in seconds
    priority: int = 1  # Higher number = higher priority
    requirements: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class Bid:
    """Represents a node's bid on an advertised job."""
    job_id: str
    bidder_id: str
    cost: float
    distance: float
    battery_pct: float
    health_pct: float = 100.0
    position: Tuple[float, float] = (0.0, 0.0)
    timestamp: float = field(default_factory=time.time)


class BidEvaluator:
    """
    Computes operational cost for a node to take on a job.
    Lower cost = higher likelihood of winning the job.
    """

    def __init__(
        self,
        weight_distance: float = 1.0,
        weight_battery: float = 2.0,
        weight_health: float = 3.0,
    ):
        self.w_dist = weight_distance
        self.w_batt = weight_battery
        self.w_health = weight_health

    def calculate_cost(
        self,
        node_pos: Tuple[float, float],
        job_pos: Tuple[float, float],
        battery_pct: float,
        health_pct: float = 100.0,
    ) -> Tuple[float, float]:
        """
        Calculates total cost and Euclidean distance to job location.
        Formula:
          Cost = w_dist * dist + w_batt * (100 - battery) + w_health * (100 - health)
        """
        dx = node_pos[0] - job_pos[0]
        dy = node_pos[1] - job_pos[1]
        dist = math.sqrt(dx * dx + dy * dy)

        batt_penalty = max(0.0, 100.0 - battery_pct)
        health_penalty = max(0.0, 100.0 - health_pct)

        # Severe exponential penalty if battery is critically low (< 20%)
        if battery_pct < 20.0:
            batt_penalty *= 5.0

        cost = (self.w_dist * dist) + (self.w_batt * batt_penalty) + (self.w_health * health_penalty)
        return cost, dist


class Auction:
    """Tracks bids and determines the winner for a single job."""

    def __init__(self, job: Job):
        self.job = job
        self.bids: Dict[str, Bid] = {}
        self.settled: bool = False
        self.winner_id: Optional[str] = None
        self.winning_bid: Optional[Bid] = None

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.job.created_at) >= self.job.deadline_s

    def add_bid(self, bid: Bid) -> bool:
        if self.settled:
            return False
        # If node already bid, replace only if cheaper
        if bid.bidder_id in self.bids:
            if bid.cost < self.bids[bid.bidder_id].cost:
                self.bids[bid.bidder_id] = bid
        else:
            self.bids[bid.bidder_id] = bid
        return True

    def settle(self) -> Optional[Tuple[str, Bid]]:
        """
        Settles the auction. The lowest operational cost wins.
        Returns (winner_node_id, winning_bid) or None if no bids.
        """
        self.settled = True
        if not self.bids:
            return None

        # Lowest cost bid wins
        sorted_bids = sorted(self.bids.values(), key=lambda b: b.cost)
        self.winning_bid = sorted_bids[0]
        self.winner_id = self.winning_bid.bidder_id
        return self.winner_id, self.winning_bid
