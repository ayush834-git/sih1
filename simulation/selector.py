"""Minimum-Sufficient Intervention Selector for Phase 3B (SIH 26153).

Implements the constrained optimization:
    minimize J_disrupt(a, G)
    subject to:
        J_risk(a) <= R_target
        R_max(a) <= R_peak_ceiling

CRITICAL SCIENTIFIC PRINCIPLES:
1. Sufficiency First, Disruption Second:
   We do NOT select the strongest intervention or the one with the lowest risk.
   We select the LEAST DISRUPTIVE intervention among those that satisfy the safety envelope.
2. DO_NOTHING Wins When Safe:
   If DO_NOTHING satisfies the safety constraints, it wins because its disruption is strictly 0.0.
3. Fail-Closed on Topology:
   If topology is UNAVAILABLE when estimating disruption, we do not fabricate zero disruption;
   the decision is marked UNRESOLVED and escalated.
4. No Automated Execution:
   The output is a RECOMMENDATION ONLY. No firewall or adapter commands are executed.
"""
from __future__ import annotations

import hashlib
from typing import Mapping, Sequence

import numpy as np

from core.contracts import NetworkState, TrustAssessment
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability
from simulation.decision_models import (
    ActionEvaluation,
    DecisionResult,
    DisruptionParameters,
    RecommendationStatus,
    RiskConstraintParameters,
)
from simulation.disruption import DisruptionEstimator
from simulation.engine import InterventionSimulator
from simulation.models import (
    AssumptionClassification,
    AssumptionRecord,
    InterventionParameters,
    InterventionStatus,
    InterventionType,
    SimulationResult,
)


CANONICAL_ACTION_ORDER = {
    InterventionType.DO_NOTHING: 0,
    InterventionType.RATE_LIMIT_IP: 1,
    InterventionType.TEMPORARY_BLOCK_IP: 2,
    InterventionType.ISOLATE_SERVICE_ENDPOINT: 3,
}


class MinimumSufficientSelector:
    """
    Constrained decision-support engine selecting the minimum-sufficient intervention
    relative to a configured future-risk safety envelope.
    """

    def __init__(
        self,
        simulator: InterventionSimulator | None = None,
        disruption_estimator: DisruptionEstimator | None = None,
    ) -> None:
        self.simulator = simulator if simulator is not None else InterventionSimulator()
        self.disruption_estimator = disruption_estimator if disruption_estimator is not None else DisruptionEstimator()

    def select(
        self,
        current_state: NetworkState,
        candidate_actions: Sequence[InterventionType] | None = None,
        simulation_params_map: Mapping[InterventionType, InterventionParameters] | None = None,
        risk_constraints: RiskConstraintParameters | None = None,
        disruption_params: DisruptionParameters | None = None,
        topology: ServiceTopologyGraph | None = None,
        target_entity_map: Mapping[InterventionType, str] | None = None,
        baseline_deltas: np.ndarray | None = None,
        history_deltas: np.ndarray | None = None,
        trust_assessment: TrustAssessment | None = None,
        max_horizon: int = 3,
    ) -> DecisionResult:
        """
        Evaluate candidate interventions and select the minimum-sufficient intervention.
        """
        if candidate_actions is None:
            candidate_actions = (
                InterventionType.DO_NOTHING,
                InterventionType.RATE_LIMIT_IP,
                InterventionType.TEMPORARY_BLOCK_IP,
                InterventionType.ISOLATE_SERVICE_ENDPOINT,
            )

        if risk_constraints is None:
            risk_constraints = RiskConstraintParameters()

        if disruption_params is not None:
            # Override disruption estimator parameters if supplied
            self.disruption_estimator.params = disruption_params

        sim_params = dict(simulation_params_map or {})
        targets = dict(target_entity_map or {})

        action_evaluations: dict[str, ActionEvaluation] = {}
        all_assumptions: list[AssumptionRecord] = []
        all_warnings: list[str] = []

        # Record top-level constraint design parameters
        all_assumptions.append(
            AssumptionRecord(
                parameter_name="target_risk",
                parameter_value=risk_constraints.target_risk,
                classification=AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
                description=f"INITIAL DESIGN PARAMETER: Target future aggregate risk threshold set to {risk_constraints.target_risk:.2f}.",
                features_affected=(),
            )
        )
        all_assumptions.append(
            AssumptionRecord(
                parameter_name="peak_risk_ceiling",
                parameter_value=risk_constraints.peak_risk_ceiling,
                classification=AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
                description=f"INITIAL DESIGN PARAMETER: Peak future risk ceiling threshold set to {risk_constraints.peak_risk_ceiling:.2f}.",
                features_affected=(),
            )
        )

        # ── 1. Evaluate Every Candidate Action ──
        for action in candidate_actions:
            params = sim_params.get(action, InterventionParameters())
            target_entity = targets.get(action, params.target_entity)

            # A. Phase 3A Forward Simulation
            sim_res: SimulationResult = self.simulator.simulate(
                current_state=current_state,
                action=action,
                params=params,
                history_deltas=history_deltas,
                baseline_deltas=baseline_deltas,
                trust_assessment=trust_assessment,
                max_horizon=max_horizon,
            )

            all_assumptions.extend(sim_res.assumptions)
            all_warnings.extend(sim_res.warnings)

            rejection_reasons: list[str] = []

            # Check for unsupported simulation
            if sim_res.status == InterventionStatus.UNSUPPORTED:
                rejection_reasons.append(
                    f"Action '{action.value}' simulation is UNSUPPORTED in current state representation."
                )

            # B. Compute Aggregate Risk J_risk(a) and Peak Risk R_max(a)
            # Derived strictly from existing SecurityRiskEngine outputs
            future_scores = {fr.horizon_step: fr.score for fr in sim_res.intervention_risk.future_risks}
            j_risk = 0.0
            for h_step, weight in risk_constraints.horizon_weights.items():
                j_risk += weight * future_scores.get(h_step, 0.0)

            # Peak future risk over lookahead horizons h >= 1
            r_max = max(future_scores.values()) if future_scores else 0.0

            # C. Check Constraints
            risk_target_satisfied = (j_risk <= risk_constraints.target_risk)
            peak_ceiling_satisfied = (r_max <= risk_constraints.peak_risk_ceiling)
            is_sufficient = (
                risk_target_satisfied
                and peak_ceiling_satisfied
                and sim_res.status != InterventionStatus.UNSUPPORTED
            )

            if not risk_target_satisfied:
                rejection_reasons.append(
                    f"Aggregate future risk J_risk ({j_risk:.3f}) exceeds target threshold ({risk_constraints.target_risk:.3f})."
                )
            if not peak_ceiling_satisfied:
                rejection_reasons.append(
                    f"Peak future risk R_max ({r_max:.3f}) exceeds ceiling threshold ({risk_constraints.peak_risk_ceiling:.3f})."
                )

            # D. Estimate Operational Disruption J_disrupt(a, G)
            (
                disruption_score,
                breakdown,
                blast_status,
                blast_impact,
                d_assump,
                d_warn,
            ) = self.disruption_estimator.estimate_disruption(
                action=action,
                topology=topology,
                target_entity=target_entity,
            )
            all_assumptions.extend(d_assump)
            all_warnings.extend(d_warn)

            if disruption_score is None:
                rejection_reasons.append(
                    "Operational disruption cannot be estimated due to UNAVAILABLE topology."
                )

            action_eval = ActionEvaluation(
                action=action,
                simulation_status=sim_res.status,
                aggregate_risk=j_risk,
                peak_risk=r_max,
                risk_target_satisfied=risk_target_satisfied,
                peak_ceiling_satisfied=peak_ceiling_satisfied,
                is_sufficient=is_sufficient,
                disruption_estimate=disruption_score,
                disruption_breakdown=breakdown,
                blast_radius_status=blast_status,
                blast_radius_impact=blast_impact,
                assumptions=tuple(sim_res.assumptions + tuple(d_assump)),
                warnings=tuple(sim_res.warnings + tuple(d_warn)),
                rejection_reasons=tuple(rejection_reasons),
                simulation_result=sim_res,
            )
            action_evaluations[action.value] = action_eval

        # ── 2. Identify Sufficient Candidates ──
        sufficient_candidates: list[InterventionType] = []
        rejected_candidates: list[InterventionType] = []
        topology_unresolved_actions: list[InterventionType] = []

        for action in candidate_actions:
            ev = action_evaluations[action.value]
            if ev.disruption_estimate is None:
                topology_unresolved_actions.append(action)
                rejected_candidates.append(action)
            elif ev.is_sufficient:
                sufficient_candidates.append(action)
            else:
                rejected_candidates.append(action)

        # ── 3. Constrained Minimum-Sufficient Selection ──
        recommended_action: InterventionType | None = None
        recommendation_status: RecommendationStatus
        unresolved_reason: str | None = None
        selected_risk: float | None = None
        selected_peak_risk: float | None = None
        selected_disruption: float | None = None

        # Lowest-risk candidate identification for human review
        evaluable_actions = [
            a for a in candidate_actions
            if action_evaluations[a.value].simulation_status != InterventionStatus.UNSUPPORTED
        ]
        lowest_risk_candidate = (
            min(evaluable_actions, key=lambda a: action_evaluations[a.value].aggregate_risk)
            if evaluable_actions else None
        )

        if sufficient_candidates:
            # Sort sufficient candidates by:
            # 1. Disruption ascending (PRIMARY: minimum disruption)
            # 2. Aggregate risk ascending (tie-breaker 1)
            # 3. Peak risk ascending (tie-breaker 2)
            # 4. Canonical order ascending (tie-breaker 3: deterministic)
            def _sort_key(act: InterventionType) -> tuple[float, float, float, int]:
                e = action_evaluations[act.value]
                d = e.disruption_estimate if e.disruption_estimate is not None else 1.0
                return (
                    round(d, 6),
                    round(e.aggregate_risk, 6),
                    round(e.peak_risk, 6),
                    CANONICAL_ACTION_ORDER.get(act, 99),
                )

            sorted_candidates = sorted(sufficient_candidates, key=_sort_key)
            recommended_action = sorted_candidates[0]
            recommendation_status = RecommendationStatus.RECOMMENDED

            sel_eval = action_evaluations[recommended_action.value]
            selected_risk = sel_eval.aggregate_risk
            selected_peak_risk = sel_eval.peak_risk
            selected_disruption = sel_eval.disruption_estimate

        else:
            # Check if failure was caused by unavailable topology
            if topology_unresolved_actions and (
                topology is None or topology.availability == TopologyAvailability.UNAVAILABLE
            ):
                recommendation_status = RecommendationStatus.UNRESOLVED
                unresolved_reason = (
                    "Service topology context is UNAVAILABLE. Under the anti-fabrication mandate, "
                    "operational disruption cannot be calculated and candidate sufficiency cannot be established."
                )
            else:
                recommendation_status = RecommendationStatus.NO_SUFFICIENT_ACTION
                unresolved_reason = (
                    f"No candidate intervention satisfies both aggregate future risk (<= {risk_constraints.target_risk:.2f}) "
                    f"and peak risk ceiling (<= {risk_constraints.peak_risk_ceiling:.2f}). "
                    f"Lowest-risk alternative is '{lowest_risk_candidate.value if lowest_risk_candidate else 'None'}' "
                    "retained for human operator review."
                )

        # ── 4. Provenance Hash ──
        disrupt_str = f"{selected_disruption:.4f}" if selected_disruption is not None else "NONE"
        hash_payload = (
            f"{current_state.window_id}:"
            f"{recommended_action.value if recommended_action else 'NONE'}:"
            f"{recommendation_status.value}:"
            f"{disrupt_str}:"
            f"{risk_constraints.target_risk:.4f}:{risk_constraints.peak_risk_ceiling:.4f}"
        )
        prov_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        return DecisionResult(
            recommended_action=recommended_action,
            recommendation_status=recommendation_status,
            sufficient_candidates=tuple(sufficient_candidates),
            rejected_candidates=tuple(rejected_candidates),
            action_evaluations=action_evaluations,
            selected_risk=selected_risk,
            selected_peak_risk=selected_peak_risk,
            selected_disruption=selected_disruption,
            lowest_risk_candidate=lowest_risk_candidate,
            target_risk=risk_constraints.target_risk,
            peak_risk_ceiling=risk_constraints.peak_risk_ceiling,
            unresolved_reason=unresolved_reason,
            assumptions=tuple(all_assumptions),
            warnings=tuple(all_warnings),
            provenance_hash=prov_hash,
        )
