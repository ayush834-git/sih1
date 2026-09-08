"""Blast Radius Assessment Engine (SIH 26153 Task 19).

Computes structural downstream dependency exposure from an affected root service node
based on the known service topology graph established in Task 18.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Structural dependency analysis, NOT attack-propagation probability.
2. Root node is strictly excluded from downstream dependent sets.
3. Explicit KNOWN / PARTIAL / UNAVAILABLE / ROOT_NOT_FOUND semantics.
4. UNAVAILABLE topology means UNKNOWN structural impact, NEVER zero impact.
5. Zero hard-coded arbitrary coverage numbers for PARTIAL topology.
6. Weighted impact score handles zero denominator safely and is explicitly a heuristic.
7. Safe on cyclic topologies; deterministic ordering and SHA-256 provenance.
"""
from __future__ import annotations

from collections import deque
from typing import Mapping, Sequence

from core.blastradius.models import BlastRadiusAssessment, BlastRadiusStatus
from core.contracts import new_id
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import CriticalityLevel, TopologyAvailability


class BlastRadiusEngine:
    """
    Evaluates downstream structural impact across a ServiceTopologyGraph.
    """

    def assess(
        self,
        topology: ServiceTopologyGraph,
        root_node_id: str,
        snapshot_id: str | None = None,
    ) -> BlastRadiusAssessment:
        """
        Evaluate structural blast radius for the specified root service node.

        Returns an immutable BlastRadiusAssessment with full provenance audit trail.
        """
        a_id = new_id("blast")
        snap_id = snapshot_id or (
            topology.to_snapshot().snapshot_id if hasattr(topology, "to_snapshot") else "snap-dynamic"
        )

        # 1. Handle Explicit UNAVAILABLE Topology
        # Mandatory Anti-Fabrication Rule: Do not invent graphs when telemetry lacks topology.
        if topology.availability == TopologyAvailability.UNAVAILABLE:
            return BlastRadiusAssessment(
                assessment_id=a_id,
                root_node_id=root_node_id,
                topology_snapshot_id=snap_id,
                topology_availability=TopologyAvailability.UNAVAILABLE,
                status=BlastRadiusStatus.UNAVAILABLE,
                direct_dependent_ids=(),
                transitive_dependent_ids=(),
                affected_node_ids=(),
                affected_node_count=0,
                node_depths={},
                maximum_dependency_depth=0,
                critical_affected_node_ids=(),
                high_criticality_affected_node_ids=(),
                weighted_impact_score=0.0,
                coverage_ratio=0.0,
                is_complete=False,
                explanation=(
                    "Structural blast radius cannot be determined because topology telemetry is UNAVAILABLE "
                    "(anti-fabrication mandate). This represents an UNKNOWN structural impact, NOT a zero impact."
                ),
            )

        # 2. Handle Root Node Not Found
        # Explicit resolution failure without node fabrication.
        if not topology.has_node(root_node_id):
            return BlastRadiusAssessment(
                assessment_id=a_id,
                root_node_id=root_node_id,
                topology_snapshot_id=snap_id,
                topology_availability=topology.availability,
                status=BlastRadiusStatus.ROOT_NOT_FOUND,
                direct_dependent_ids=(),
                transitive_dependent_ids=(),
                affected_node_ids=(),
                affected_node_count=0,
                node_depths={},
                maximum_dependency_depth=0,
                critical_affected_node_ids=(),
                high_criticality_affected_node_ids=(),
                weighted_impact_score=0.0,
                coverage_ratio=0.0,
                is_complete=False,
                explanation=(
                    f"Root service '{root_node_id}' was not found in the topology graph. "
                    "Cannot determine downstream dependents without an identified root asset."
                ),
            )

        # 3. Direct Downstream Dependents (Incoming edges to root_node_id)
        # Immediate services whose operational capability directly depends on root_node_id.
        direct_raw = topology.get_dependents(root_node_id)
        # Exclude root_node_id from its own direct dependents if self-loop exists
        direct_dependents = tuple(sorted(d for d in direct_raw if d != root_node_id))

        # 4. Multi-hop Transitive Dependents & Shortest Dependency Depth via BFS
        # Breadth-First Search following incoming edges guarantees shortest path distance.
        depths: dict[str, int] = {}
        transitive_ordered: list[str] = []
        visited: set[str] = {root_node_id}
        queue: deque[tuple[str, int]] = deque([(root_node_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()
            for dep in topology.get_dependents(current_id):
                if dep not in visited:
                    visited.add(dep)
                    depths[dep] = current_depth + 1
                    transitive_ordered.append(dep)
                    queue.append((dep, current_depth + 1))

        transitive_dependents = tuple(transitive_ordered)
        affected_nodes = transitive_dependents
        affected_count = len(affected_nodes)
        max_depth = max(depths.values()) if depths else 0

        # 5. Criticality Breakdown of Affected Nodes
        critical_list: list[str] = []
        high_crit_list: list[str] = []

        for node_id in affected_nodes:
            node = topology.get_node(node_id)
            if node is not None:
                if node.criticality_level == CriticalityLevel.CRITICAL or node.criticality >= 0.85:
                    critical_list.append(node_id)
                elif node.criticality_level == CriticalityLevel.HIGH or node.criticality >= 0.65:
                    high_crit_list.append(node_id)

        # 6. Weighted Structural Impact Score (Heuristic)
        # Explicit heuristic formula strictly handling zero denominator safely:
        # weighted_impact = sum(crit(v) for v in affected) / sum(crit(u) for u in V \ {root})
        if affected_count == 0:
            weighted_impact = 0.0
        else:
            affected_crit_sum = sum(
                topology.get_node(nid).criticality
                for nid in affected_nodes
                if topology.get_node(nid) is not None
            )
            # Sum of criticality across all other nodes in the graph
            all_other_nodes = [
                n for n in topology.get_all_nodes() if n.node_id != root_node_id
            ]
            max_possible_crit = sum(n.criticality for n in all_other_nodes)

            if max_possible_crit <= 1e-9:
                weighted_impact = 0.0
            else:
                weighted_impact = min(1.0, max(0.0, round(affected_crit_sum / max_possible_crit, 4)))

        # 7. Coverage Ratio & Status
        if topology.availability == TopologyAvailability.KNOWN:
            status = BlastRadiusStatus.COMPLETE
            coverage_ratio: float | None = 1.0
            is_complete = True
            cov_notice = "Topology is fully KNOWN (complete graph coverage)."
        elif topology.availability == TopologyAvailability.PARTIAL:
            status = BlastRadiusStatus.PARTIAL
            # Indeterminate coverage: Do not hardcode or invent synthetic coverage numbers
            coverage_ratio = None
            is_complete = False
            cov_notice = (
                "Topology coverage is PARTIAL; numerical coverage is indeterminate. "
                "Additional undiscovered dependencies may exist."
            )
        else:
            status = BlastRadiusStatus.UNAVAILABLE
            coverage_ratio = 0.0
            is_complete = False
            cov_notice = "Topology coverage is UNAVAILABLE."

        # 8. Human-Readable Audit Explanation
        root_node = topology.get_node(root_node_id)
        root_name = root_node.name if root_node is not None else root_node_id
        explanation = (
            f"Structural blast radius assessment for root '{root_name}' ({root_node_id}): "
            f"{affected_count} downstream dependent services exposed across maximum dependency depth {max_depth}. "
            f"Direct dependents: {len(direct_dependents)}; Critical dependents: {len(critical_list)}. "
            f"Weighted structural impact heuristic: {weighted_impact:.4f}. {cov_notice} "
            "NOTE: This metric represents structural dependency reachability, "
            "NOT an attack-propagation probability or economic loss estimate."
        )

        return BlastRadiusAssessment(
            assessment_id=a_id,
            root_node_id=root_node_id,
            topology_snapshot_id=snap_id,
            topology_availability=topology.availability,
            status=status,
            direct_dependent_ids=direct_dependents,
            transitive_dependent_ids=transitive_dependents,
            affected_node_ids=affected_nodes,
            affected_node_count=affected_count,
            node_depths=depths,
            maximum_dependency_depth=max_depth,
            critical_affected_node_ids=tuple(critical_list),
            high_criticality_affected_node_ids=tuple(high_crit_list),
            weighted_impact_score=weighted_impact,
            coverage_ratio=coverage_ratio,
            is_complete=is_complete,
            explanation=explanation,
        )
