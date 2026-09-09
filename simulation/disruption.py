"""Disruption Estimator for Phase 3B (SIH 26153).

Estimates operational disruption J_disrupt(a, G) using the Phase 2 formalization:
    J_disrupt(a, G) = Aggressiveness(a) * [omega_direct * DirectCost(a) + omega_cascade * CascadeCost(a, G)] * TTL_factor(a)

CRITICAL INVARIANTS:
1. Reuses existing ServiceTopologyGraph (core/topology/graph.py) and BlastRadiusEngine (core/blastradius/engine.py).
2. DO_NOTHING has strictly zero disruption (J_disrupt = 0.0).
3. If topology is UNAVAILABLE for an endpoint/topology-dependent action, disruption CANNOT be fabricated as zero;
   it returns None and flags the decision as unresolved.
4. All weights and costs are configurable INITIAL DESIGN PARAMETERS.
"""
from __future__ import annotations

from typing import Any, Mapping
from core.blastradius.engine import BlastRadiusEngine
from core.blastradius.models import BlastRadiusAssessment, BlastRadiusStatus
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability
from simulation.decision_models import DisruptionParameters
from simulation.models import AssumptionClassification, AssumptionRecord, InterventionType


class DisruptionEstimator:
    """
    Evaluates operational disruption for candidate defensive interventions.
    """

    def __init__(
        self,
        blast_radius_engine: BlastRadiusEngine | None = None,
        params: DisruptionParameters | None = None,
    ) -> None:
        self.blast_engine = blast_radius_engine if blast_radius_engine is not None else BlastRadiusEngine()
        self.params = params if params is not None else DisruptionParameters()

    def estimate_disruption(
        self,
        action: InterventionType,
        topology: ServiceTopologyGraph | None = None,
        target_entity: str = "",
        ttl_seconds: float | None = None,
    ) -> tuple[float | None, dict[str, float], BlastRadiusStatus | None, float | None, list[AssumptionRecord], list[str]]:
        """
        Estimate operational disruption score J_disrupt(a, G).

        Returns:
            - disruption_score: float in [0, 1] or None if topology is required but unavailable
            - breakdown: dictionary of intermediate component scores
            - blast_status: BlastRadiusStatus if assessed, else None
            - blast_impact: weighted structural impact score if assessed, else None
            - assumptions: list of AssumptionRecords
            - warnings: list of warning strings
        """
        assumptions: list[AssumptionRecord] = []
        warnings: list[str] = []

        # ── 1. DO_NOTHING: Identical to Baseline, Zero Operational Disruption ──
        if action == InterventionType.DO_NOTHING:
            return (
                0.0,
                {
                    "aggressiveness": 0.0,
                    "direct_cost": 0.0,
                    "cascade_cost": 0.0,
                    "ttl_factor": 0.0,
                    "total_disruption": 0.0,
                },
                None,
                None,
                [],
                [],
            )

        # ── 2. Aggressiveness & TTL Factor ──
        aggressiveness = self.params.aggressiveness_map.get(action, 0.50)
        actual_ttl = ttl_seconds if ttl_seconds is not None else self.params.default_ttl_seconds
        ttl_factor = min(1.0, max(0.1, actual_ttl / self.params.ttl_reference_seconds))

        assumptions.append(
            AssumptionRecord(
                parameter_name="action_aggressiveness",
                parameter_value=aggressiveness,
                classification=AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
                description=f"INITIAL DESIGN PARAMETER: Action '{action.value}' aggressiveness assigned {aggressiveness:.2f}.",
                features_affected=(),
            )
        )

        # ── 3. Topology Dependency & Fail-Closed Semantics ──
        # ISOLATE_SERVICE_ENDPOINT strictly requires service topology context
        is_endpoint_action = (action == InterventionType.ISOLATE_SERVICE_ENDPOINT)

        if is_endpoint_action:
            if topology is None or topology.availability == TopologyAvailability.UNAVAILABLE:
                warning_msg = (
                    f"Disruption cannot be defensibly estimated for '{action.value}': "
                    f"Service topology is UNAVAILABLE. Under the anti-fabrication mandate, "
                    f"zero disruption is not assumed. Disruption remains indeterminate."
                )
                warnings.append(warning_msg)
                return (
                    None,
                    {"aggressiveness": aggressiveness, "ttl_factor": ttl_factor},
                    BlastRadiusStatus.UNAVAILABLE,
                    None,
                    assumptions,
                    warnings,
                )

        # ── 4. Direct Cost & Cascade Cost via BlastRadiusEngine ──
        direct_cost = 0.0
        cascade_cost = 0.0
        blast_status: BlastRadiusStatus | None = None
        blast_impact: float | None = None

        if topology is not None and topology.availability in (TopologyAvailability.KNOWN, TopologyAvailability.PARTIAL):
            # Check if target entity corresponds to a known node in the topology
            if target_entity and topology.has_node(target_entity):
                node = topology.get_node(target_entity)
                direct_cost = node.criticality if node is not None else self.params.default_endpoint_direct_cost

                # Structural cascade evaluation via existing BlastRadiusEngine
                blast_assessment: BlastRadiusAssessment = self.blast_engine.assess(topology, target_entity)
                blast_status = blast_assessment.status
                blast_impact = blast_assessment.weighted_impact_score
                cascade_cost = blast_impact
            else:
                # Target is an external entity or not explicitly mapped in graph
                if is_endpoint_action:
                    direct_cost = self.params.default_endpoint_direct_cost
                    cascade_cost = 0.50  # Unmapped service assumption
                else:
                    direct_cost = (
                        self.params.default_ip_direct_cost * 2.0
                        if action == InterventionType.TEMPORARY_BLOCK_IP
                        else self.params.default_ip_direct_cost
                    )
                    cascade_cost = 0.0  # External IP has no internal downstream dependents
        else:
            # Topology is not available; applicable only for non-endpoint IP actions
            direct_cost = (
                self.params.default_ip_direct_cost * 2.0
                if action == InterventionType.TEMPORARY_BLOCK_IP
                else self.params.default_ip_direct_cost
            )
            cascade_cost = 0.0

        # ── 5. Total Disruption Formulation ──
        raw_disruption = (
            aggressiveness
            * (self.params.omega_direct * direct_cost + self.params.omega_cascade * cascade_cost)
            * ttl_factor
        )
        disruption_score = max(0.0, min(1.0, float(raw_disruption)))

        breakdown = {
            "aggressiveness": aggressiveness,
            "direct_cost": direct_cost,
            "cascade_cost": cascade_cost,
            "ttl_factor": ttl_factor,
            "omega_direct": self.params.omega_direct,
            "omega_cascade": self.params.omega_cascade,
            "total_disruption": disruption_score,
        }

        return (
            disruption_score,
            breakdown,
            blast_status,
            blast_impact,
            assumptions,
            warnings,
        )
