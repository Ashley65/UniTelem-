"""
UniTelem AI Assignment Node.

Specialized Node extending AINode for decentralized market-based job auctions
and dynamic Voronoi territory partitioning across drone swarms and CCTV meshes.

Core Capabilities:
  - Job Auction Engine: Broadcasts task announcements (e.g. auction/announce).
    Listens for signed bids from candidate nodes based on operational cost.
  - Auction Settlement: Selects the lowest-cost bid and issues
    a contract grant (auction/settle).
  - Dynamic Voronoi Boundary Mapping: Continuously computes spatial Voronoi partitions for area surveillance/search,
    automatically expanding coverage if a peer recharges or drops out.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from .AINode import AINode
except ImportError:
    from AINode import AINode

try:
    from ...ai.auction import Auction, Bid, BidEvaluator, Job
    from ...ai.spatial import VoronoiPartitioner
except (ImportError, ValueError):
    try:
        from unitelem.ai.auction import Auction, Bid, BidEvaluator, Job
        from unitelem.ai.spatial import VoronoiPartitioner
    except ImportError:
        Auction = None
        Bid = None
        BidEvaluator = None
        Job = None
        VoronoiPartitioner = None


class AIAssignmentNode(AINode):
    """
    Specialized Node type for:
    1. Internal Job Auctions: Advertising tasks, calculating operational bids,
       and settling contracts with the lowest-cost candidate.
    2. Dynamic Voronoi Partitioning: Smart spacing, blind-spot healing,
       and territorial coverage management.
    """

    def __init__(
        self,
        node_id: str,
        swarm_id: str = "default",
        private_key: Optional[str] = None,
        model: Optional[Any] = None,
        search_bounds: Tuple[float, float, float, float] = (0.0, 1000.0, 0.0, 1000.0),
        auto_bid: bool = True,
        initial_position: Tuple[float, float] = (0.0, 0.0),
        initial_battery: float = 100.0,
        **kwargs,
    ):
        super().__init__(
            node_id=node_id,
            swarm_id=swarm_id,
            private_key=private_key,
            model=model,
            **kwargs,
        )

        self.search_bounds = search_bounds
        self.auto_bid = auto_bid
        self.local_position = initial_position
        self.local_battery = initial_battery
        self.local_health = 100.0

        self.evaluator = BidEvaluator() if BidEvaluator else None
        self.partitioner = VoronoiPartitioner(search_bounds) if VoronoiPartitioner else None

        self.active_auctions: Dict[str, Any] = {}
        self.settled_jobs: Dict[str, str] = {}  # job_id -> winner_node_id
        self.node_positions: Dict[str, Tuple[float, float]] = {node_id: initial_position}
        self.node_telemetry: Dict[str, Dict[str, Any]] = {}

        # Register specialized handlers
        self.register_handler("auction/announce/*", self.on_auction_announce)
        self.register_handler("auction/bid/*", self.on_auction_bid)
        self.register_handler("auction/settle/*", self.on_auction_settle)
        self.register_handler("telemetry/position", self.on_position_update)
        self.register_handler("telemetry/status", self.on_status_update)

    def announce_job(
        self,
        job_id: str,
        task_type: str,
        location: Tuple[float, float],
        deadline_s: float = 1.5,
        priority: int = 1,
        requirements: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Creates an auction for a new task and broadcasts it to the mesh.
        """
        if Job is None or Auction is None:
            raise RuntimeError("Auction subsystem not available.")

        job = Job(
            job_id=job_id,
            task_type=task_type,
            location=location,
            deadline_s=deadline_s,
            priority=priority,
            requirements=requirements or {},
        )
        auction = Auction(job)
        self.active_auctions[job_id] = auction

        payload = {
            "job_id": job.job_id,
            "task_type": job.task_type,
            "location": job.location,
            "deadline_s": job.deadline_s,
            "priority": job.priority,
            "requirements": job.requirements,
            "created_at": job.created_at,
        }
        self.publish(f"auction/announce/{job_id}", payload)
        return auction

    def submit_bid(
        self,
        job_id: str,
        job_location: Tuple[float, float],
        custom_cost: Optional[float] = None,
    ) -> Optional[Any]:
        """
        Computes operational cost and submits an Ed25519-signed bid to the mesh.
        """
        if Bid is None or self.evaluator is None:
            return None

        if custom_cost is not None:
            cost = custom_cost
            dist = 0.0
        else:
            cost, dist = self.evaluator.calculate_cost(
                node_pos=self.local_position,
                job_pos=job_location,
                battery_pct=self.local_battery,
                health_pct=self.local_health,
            )

        bid = Bid(
            job_id=job_id,
            bidder_id=self.node_id,
            cost=round(cost, 2),
            distance=round(dist, 2),
            battery_pct=round(self.local_battery, 1),
            health_pct=round(self.local_health, 1),
            position=self.local_position,
        )

        # Store locally if we host this auction
        if job_id in self.active_auctions:
            self.active_auctions[job_id].add_bid(bid)

        payload = {
            "job_id": bid.job_id,
            "bidder_id": bid.bidder_id,
            "cost": bid.cost,
            "distance": bid.distance,
            "battery_pct": bid.battery_pct,
            "health_pct": bid.health_pct,
            "position": list(bid.position),
            "timestamp": bid.timestamp,
        }
        self.publish(f"auction/bid/{job_id}", payload)
        return bid

    def settle_auction(self, job_id: str) -> Optional[Tuple[str, Any]]:
        """
        Settles the specified auction, picking the lowest-cost bidder.
        Publishes the award notice to the mesh.
        """
        auction = self.active_auctions.get(job_id)
        if not auction:
            return None

        settlement = auction.settle()
        if not settlement:
            return None

        winner_id, winning_bid = settlement
        self.settled_jobs[job_id] = winner_id

        payload = {
            "job_id": job_id,
            "winner_id": winner_id,
            "winning_cost": winning_bid.cost,
            "distance": winning_bid.distance,
            "battery_pct": winning_bid.battery_pct,
        }
        self.publish(f"auction/settle/{job_id}", payload)
        return winner_id, winning_bid

    def update_position(self, x: float, y: float) -> None:
        """Updates this node's local position and broadcasts it."""
        self.local_position = (x, y)
        self.node_positions[self.node_id] = (x, y)
        self.publish("telemetry/position", {"x": x, "y": y})

    def update_battery(self, battery_pct: float) -> None:
        """Updates this node's local battery and broadcasts status."""
        self.local_battery = battery_pct
        self.publish("telemetry/status", {"battery": battery_pct, "health": self.local_health})

    def compute_territories(self, grid_res: int = 30) -> Dict[str, Dict[str, Any]]:
        """
        Runs Voronoi partitioning across all known active node positions.
        """
        if not self.partitioner:
            return {}
        return self.partitioner.partition(self.node_positions, grid_res=grid_res)

    def get_anti_collision_vector(self, min_safe_distance: float = 20.0) -> Tuple[float, float]:
        """
        Calculates repulsive vector away from neighboring nodes violating safe spacing.
        """
        if not self.partitioner:
            return (0.0, 0.0)
        return self.partitioner.compute_spacing_repulsion(
            self.node_id, self.node_positions, min_safe_distance=min_safe_distance
        )

    # ----------------------------------------------------------------------
    # Event Handlers
    # ----------------------------------------------------------------------
    def on_auction_announce(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        job_id = payload.get("job_id")
        location = tuple(payload.get("location", (0.0, 0.0)))

        # If we didn't originate the job, register in tracking table
        if job_id and job_id not in self.active_auctions and Job and Auction:
            job = Job(
                job_id=job_id,
                task_type=payload.get("task_type", "generic"),
                location=location,
                deadline_s=payload.get("deadline_s", 2.0),
                priority=payload.get("priority", 1),
            )
            self.active_auctions[job_id] = Auction(job)

        # Auto-bid if enabled and not our own announcement
        if self.auto_bid and sender != self.node_id and job_id:
            self.submit_bid(job_id, location)

        return ("ai/insights", {"type": "job_announced", "job_id": job_id, "from": sender})

    def on_auction_bid(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        job_id = payload.get("job_id")
        auction = self.active_auctions.get(job_id)
        bidder = payload.get("bidder_id", sender)
        pos = tuple(payload.get("position", (0.0, 0.0)))
        if "position" in payload:
            self.node_positions[bidder] = pos

        if auction and Bid:
            bid = Bid(
                job_id=job_id,
                bidder_id=bidder,
                cost=payload.get("cost", 999.0),
                distance=payload.get("distance", 0.0),
                battery_pct=payload.get("battery_pct", 100.0),
                health_pct=payload.get("health_pct", 100.0),
                position=pos,
                timestamp=payload.get("timestamp", time.time()),
            )
            auction.add_bid(bid)
        return None

    def on_auction_settle(self, topic: str, payload: Any, sender: str) -> Optional[Tuple[str, Any]]:
        job_id = payload.get("job_id")
        winner_id = payload.get("winner_id")
        if job_id and winner_id:
            self.settled_jobs[job_id] = winner_id
            if job_id in self.active_auctions:
                self.active_auctions[job_id].settled = True
                self.active_auctions[job_id].winner_id = winner_id
        return ("ai/insights", {"type": "job_settled", "job_id": job_id, "winner": winner_id})

    def on_position_update(self, topic: str, payload: Any, sender: str) -> None:
        if isinstance(payload, dict) and "x" in payload and "y" in payload:
            self.node_positions[sender] = (float(payload["x"]), float(payload["y"]))

    def on_status_update(self, topic: str, payload: Any, sender: str) -> None:
        if isinstance(payload, dict):
            self.node_telemetry[sender] = payload