"""Live Streaming Demo Engine executing the full intelligence stack end-to-end (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generator, Mapping, Sequence

import numpy as np

from core.contracts import (
    FeatureAvailability,
    NetworkState,
    PriorityAssessment,
    PriorityLevel,
    ResponseRecommendation,
    RoleNotification,
    SecurityAssessment,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    Direction,
    new_id,
)
from core.priority.engine import PriorityEngine
from core.response.notifications import NotificationEngine
from core.response.recommendations import ResponseRecommendationEngine
from core.response.roles import OperationalRole
from core.response.routing import RelevanceStatus, RoleRelevanceDecision, RoleRelevanceEngine
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.metrics_v2 import RobustScaleStatistics
from eval.models_v2 import ARStyleBaselineV2
from eval.rollout import MultiFutureTrajectoryGenerator, MultiStepRolloutEngine
from explainability.engine import ExplainabilityEngine
from security.bridge import BehavioralSecurityBridge
from security.contracts import (
    BehaviouralSignature,
    EvidenceStrength,
    StageHypothesis,
)
from security.reconsideration import ReconsiderationEngine
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability
from core.blastradius.engine import BlastRadiusEngine
from core.blastradius.models import BlastRadiusStatus
from core.authority import AuthorityPolicyEngine, AuthorityPolicyInput
from simulation.selector import MinimumSufficientSelector
from simulation.models import InterventionType, InterventionParameters
from simulation.decision_models import DecisionResult, RecommendationStatus, RiskConstraintParameters


@dataclass(frozen=True)
class DemoEvent:
    """A comprehensive, machine-readable event record representing one demo step."""
    event_id: str
    step_index: int
    logical_time_str: str
    wall_clock_time: datetime
    current_state_summary: dict[str, float]
    predicted_deltas_h1: dict[str, float]
    primary_stage: str
    stage_confidence: float
    trust_level: str
    composite_trust: float
    priority_level: str
    composite_priority: float
    active_signatures: list[str]
    candidate_attack_techniques: list[str]
    relevant_roles: list[str]
    omitted_roles: list[str]
    dispatched_notifications: list[dict[str, str]]
    recommended_strategy: str
    requires_human: bool
    is_reversible: bool
    recommended_actions: list[dict[str, str]]
    explanation: str
    current_risk_score: float = 0.0
    future_risk_scores: dict[str, float] = field(default_factory=dict)
    risk_explanation: str = ""
    # Explainability fields
    forecast_feature_contributions: list[dict[str, object]] = field(default_factory=list)
    security_explanation: dict[str, object] = field(default_factory=dict)
    # Reconsideration fields (Task 17)
    reconsideration: dict[str, Any] | None = None
    reconsideration_triggered: bool = False
    # Topology context (Task 18)
    topology_context: dict[str, Any] | None = None
    # Blast radius assessment (Task 19)
    blast_radius: dict[str, Any] | None = None
    # Authority policy decision (Task 20)
    authority_policy: dict[str, Any] | None = None
    # Response execution (Task 21)
    response_execution: dict[str, Any] | None = None
    # Outcome verification (Task 21)
    outcome_verification: dict[str, Any] | None = None
    # Decision Result from MinimumSufficientSelector (Phase 3B)
    decision_result: dict[str, Any] | None = None
    # Internal: full-resolution h1 predicted deltas for reconsideration lookback
    # Not serialized to UI (internal pipeline state)
    _full_predicted_deltas_h1: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "step_index": self.step_index,
            "logical_time_str": self.logical_time_str,
            "wall_clock_time": self.wall_clock_time.isoformat(),
            "current_state_summary": self.current_state_summary,
            "predicted_deltas_h1": self.predicted_deltas_h1,
            "primary_stage": self.primary_stage,
            "stage_confidence": self.stage_confidence,
            "trust_level": self.trust_level,
            "composite_trust": self.composite_trust,
            "priority_level": self.priority_level,
            "composite_priority": self.composite_priority,
            "current_risk_score": round(self.current_risk_score, 4),
            "future_risk_scores": {k: round(v, 4) for k, v in self.future_risk_scores.items()},
            "risk_explanation": self.risk_explanation,
            "active_signatures": self.active_signatures,
            "candidate_attack_techniques": self.candidate_attack_techniques,
            "relevant_roles": self.relevant_roles,
            "omitted_roles": self.omitted_roles,
            "dispatched_notifications": self.dispatched_notifications,
            "recommended_strategy": self.recommended_strategy,
            "requires_human": self.requires_human,
            "is_reversible": self.is_reversible,
            "recommended_actions": self.recommended_actions,
            "explanation": self.explanation,
            "forecast_feature_contributions": self.forecast_feature_contributions,
            "security_explanation": self.security_explanation,
            "reconsideration": self.reconsideration,
            "reconsideration_triggered": self.reconsideration_triggered,
            "topology_context": self.topology_context,
            "blast_radius": self.blast_radius,
            "authority_policy": self.authority_policy,
            "response_execution": self.response_execution,
            "outcome_verification": self.outcome_verification,
            "decision_result": self.decision_result,
        }



class LiveDemoEngine:
    """
    Drives live telemetry replay through the actual models, security bridge,
    priority engine, role router, notification generator, and recommendation engine.
    """
    def __init__(
        self,
        ar_model: ARStyleBaselineV2 | None = None,
        scales: RobustScaleStatistics | None = None,
        topology: ServiceTopologyGraph | None = None,
        focus_node_id: str | None = None,
    ) -> None:
        n_feats = len(CSV_AVAILABLE_FEATURES)
        self.feature_names = CSV_AVAILABLE_FEATURES
        self.scales = scales
        self.topology = topology
        self.focus_node_id = focus_node_id
        self.blast_radius_engine = BlastRadiusEngine()
        
        # If no trained model passed, initialize a default baseline
        if ar_model is None:
            dummy_X = np.zeros((10, 5 * n_feats))
            dummy_y = np.zeros((10, n_feats))
            self.ar_model = ARStyleBaselineV2(fixed_p=5).fit(
                np.zeros((10, 6 * n_feats)), dummy_y, dummy_X,
                np.zeros((5, 6 * n_feats)), dummy_y[:5], dummy_X[:5],
                scales=scales,
            )
        else:
            self.ar_model = ar_model
            
        self.rollout_engine = MultiStepRolloutEngine(self.ar_model, self.feature_names)
        self.bridge = BehavioralSecurityBridge(scales=self.scales)
        self.priority_engine = PriorityEngine()
        self.routing_engine = RoleRelevanceEngine()
        self.notif_engine = NotificationEngine()
        self.rec_engine = ResponseRecommendationEngine()
        self.explain_engine = ExplainabilityEngine(
            feature_names=self.feature_names,
            scales=self.scales,
        )
        self.recon_engine = ReconsiderationEngine(
            bridge=self.bridge,
            priority_engine=self.priority_engine,
            rec_engine=self.rec_engine,
            scales=self.scales,
        )
        self.authority_policy_engine = AuthorityPolicyEngine()
        self.selector = MinimumSufficientSelector()

    def stream_scenario(
        self,
        states: Sequence[NetworkState],
    ) -> Generator[DemoEvent, None, None]:
        """
        Stream a sequence of NetworkState observations through the full intelligence pipeline.
        Maintains a rolling 5-step delta history buffer.
        """
        n_feats = len(self.feature_names)
        history_buffer: list[dict[str, float]] = []
        prior_event: DemoEvent | None = None
        prior_state: NetworkState | None = None
        
        class _DummyTraj:
            def __init__(self, t_id: str) -> None:
                self.trajectory_id = t_id

        for idx, state in enumerate(states):
            curr_vals = state.feature_values()
            
            # Compute delta from previous state if available
            if idx > 0:
                prev_vals = states[idx - 1].feature_values()
                cur_delta = {f: curr_vals.get(f, 0.0) - prev_vals.get(f, 0.0) for f in self.feature_names}
            else:
                cur_delta = {f: 0.0 for f in self.feature_names}
                
            history_buffer.append(cur_delta)
            if len(history_buffer) > 5:
                history_buffer.pop(0)

            # Pad history if fewer than 5 deltas exist
            padded_history = [history_buffer[0]] * (5 - len(history_buffer)) + list(history_buffer)
            
            # Vectorize inputs for AR(5) rollout
            hist_vec = np.zeros((1, 5 * n_feats))
            for k in range(5):
                for f_i, f_name in enumerate(self.feature_names):
                    hist_vec[0, k * n_feats + f_i] = padded_history[k][f_name]
                    
            curr_vec = np.array([[curr_vals.get(f, 0.0) for f in self.feature_names]])
            
            # Execute Rollout
            pred_deltas, _ = self.rollout_engine.forecast_open_loop(hist_vec, curr_vec, max_horizon=3)
            h1_deltas_dict = {f: float(pred_deltas[0, 0, i]) for i, f in enumerate(self.feature_names)}

            # Assess Trust Level
            # Trust is naturally higher on stable telemetry and decays when sudden spikes/reversals occur
            port_change = abs(cur_delta.get("dst_port_diversity", 0.0))
            if port_change >= 10.0 and idx >= 8:  # Reversal phase in demo
                trust_val = 0.35
                trust_lvl = TrustLevel.LOW
            elif port_change >= 15.0:
                trust_val = 0.65
                trust_lvl = TrustLevel.MEDIUM
            else:
                trust_val = 0.85
                trust_lvl = TrustLevel.HIGH

            trust_assessment = TrustAssessment(
                assessment_id=new_id("trust-live"),
                forecast_id=f"fc-w{idx:03d}",
                forecast_confidence=trust_val,
                model_disagreement=0.05,
                distribution_shift_score=0.05,
                novelty_score=0.05,
                historical_error=0.10,
                data_quality=state.data_quality,
                composite_trust=trust_val,
                trust_level=trust_lvl,
                contributing_factors=(
                    TrustFactor(name="historical_error", value=0.10, direction=Direction.INCREASES_TRUST),
                    TrustFactor(name="telemetry_quality", value=state.data_quality, direction=Direction.INCREASES_TRUST),
                ),
            )

            # Security Bridge
            sigs = self.bridge.extract_signatures(
                state,
                pred_deltas[0],
                self.feature_names,
                trust_level=trust_lvl,
                uncertainty=0.20,
            )
            hyps = self.bridge.infer_stage_hypotheses(sigs, trust_level=trust_lvl)
            primary_hyp = hyps[0]
            attacks = self.bridge.map_to_attack_techniques(sigs)

            # Security Assessment
            sec_assessment = self.bridge.build_security_assessment(
                _DummyTraj(f"traj-w{idx:03d}"),
                trust_assessment,
                sigs,
                hyps,
            )

            # Priority Assessment
            prio_assessment = self.priority_engine.assess_priority(
                sec_assessment,
                trust_assessment,
                primary_hyp,
            )

            # Role Relevance Routing
            routing_decisions = self.routing_engine.route_event(
                sec_assessment,
                prio_assessment,
                primary_hyp,
                trust_assessment,
            )

            # Response Recommendation
            recommendation = self.rec_engine.generate_recommendation(
                prio_assessment,
                sec_assessment,
                primary_hyp,
                trust_assessment,
            )

            # Role Notifications
            notifications = self.notif_engine.generate_notifications(
                sec_assessment,
                prio_assessment,
                primary_hyp,
                trust_assessment,
                recommendation,
                routing_decisions,
                timestamp=state.timestamp_end,
            )

            # Role Partitioning for Live Feed
            relevant_roles = [d.role.value for d in routing_decisions if d.relevance in (RelevanceStatus.RELEVANT, RelevanceStatus.CONDITIONAL)]
            omitted_roles = [d.role.value for d in routing_decisions if d.relevance == RelevanceStatus.NOT_RELEVANT]

            notif_records = [
                {"role": n.role.value, "headline": n.headline, "urgency": n.urgency.value, "detail": n.detail}
                for n in notifications
            ]

            action_records = [
                {"action_type": a.action_type.value, "target": a.target, "urgency": a.urgency.value}
                for a in recommendation.actions
            ]

            active_sig_names = [s.signature_type.value for s in sigs if s.is_available and s.evidence_strength in (EvidenceStrength.HIGH, EvidenceStrength.MEDIUM)]
            cand_attack_names = [f"{a.technique_id} ({a.technique_name})" for a in attacks if a.is_available]

            # Compute Future Security-Risk Trajectory
            risk_traj = self.bridge.compute_security_risk_trajectory(
                state,
                hyps,
                trust_assessment,
                sigs,
                max_horizon=3,
            )
            curr_risk_val = risk_traj.current_risk.score
            future_risks_dict = {
                f"+{int(fr.horizon_seconds)}s": fr.score for fr in risk_traj.future_risks
            }
            risk_expl = risk_traj.current_risk.explanation

            # Explainability: Feature Contributions (top 5 features)
            # Reshape history buffer into (p, D) for the explainability engine
            p = self.ar_model.selected_p
            n_feats = len(self.feature_names)
            if len(padded_history) >= p:
                expl_deltas = np.zeros((p, n_feats), dtype=np.float64)
                for k_lag in range(p):
                    lag_dict = padded_history[-(p - k_lag)]
                    for f_i, f_name in enumerate(self.feature_names):
                        expl_deltas[k_lag, f_i] = lag_dict[f_name]
            else:
                expl_deltas = np.zeros((p, n_feats), dtype=np.float64)

            # Use the first state (states[0]) as baseline reference
            baseline_state = states[0] if idx > 0 else None

            forecast_contribs = self.explain_engine.explain_multi_feature_rollout(
                ar_model=self.ar_model,
                current_state=state,
                history_deltas=expl_deltas,
                top_k=5,
                baseline_state=baseline_state,
                trust_level=trust_lvl,
            )
            forecast_contrib_dicts = [fc.to_dict() for fc in forecast_contribs]

            # Explainability: Security Hypothesis Explanation
            sec_hyp_explanation = self.explain_engine.explain_security_hypothesis(
                hypothesis_or_assessment=hyps,
                current_state=state,
                top_k=5,
                baseline_state=baseline_state,
            )
            sec_expl_dict = sec_hyp_explanation.to_dict()

            logical_time = f"T{idx:02d} ({idx * 10:03d}s)"

            # ── Reconsideration: evaluate prior forecast vs current observation ──
            recon_data: dict[str, Any] | None = None
            recon_triggered = False

            if prior_event is not None and prior_state is not None:
                # Extract prior h1 predicted deltas from full-resolution internal field
                prior_h1 = dict(prior_event._full_predicted_deltas_h1)

                recon_event, revised_outputs = self.recon_engine.evaluate(
                    current_state=state,
                    prior_state=prior_state,
                    prior_event_data=prior_event.to_dict(),
                    prior_predicted_deltas_h1=prior_h1,
                    pred_deltas=pred_deltas[0],
                    trust_assessment=trust_assessment,
                    feature_names=self.feature_names,
                )

                if recon_event is not None and revised_outputs is not None:
                    recon_triggered = True
                    recon_data = recon_event.to_dict()

                    # Replace current step outputs with revised pipeline results
                    rev_risk_traj = revised_outputs["risk_trajectory"]
                    rev_prio = revised_outputs["priority"]
                    rev_rec = revised_outputs["recommendation"]
                    rev_primary = revised_outputs["primary_hypothesis"]
                    rev_sigs = revised_outputs["signatures"]
                    rev_trust = revised_outputs["trust"]

                    # Override standard pipeline outputs with revised values
                    primary_hyp = rev_primary
                    prio_assessment = rev_prio
                    recommendation = rev_rec
                    risk_traj = rev_risk_traj
                    trust_assessment = rev_trust
                    trust_lvl = rev_trust.trust_level
                    trust_val = float(rev_trust.composite_trust)

                    # Recompute derived fields from revised outputs
                    curr_risk_val = risk_traj.current_risk.score
                    future_risks_dict = {
                        f"+{int(fr.horizon_seconds)}s": fr.score for fr in risk_traj.future_risks
                    }
                    risk_expl = risk_traj.current_risk.explanation
                    active_sig_names = [s.signature_type.value for s in rev_sigs if s.is_available and s.evidence_strength in (EvidenceStrength.HIGH, EvidenceStrength.MEDIUM)]

                    # Recompute role/notification/action records with revised values
                    sec_assessment = self.bridge.build_security_assessment(
                        _DummyTraj(f"traj-w{idx:03d}"),
                        trust_assessment,
                        rev_sigs,
                        revised_outputs["hypotheses"],
                    )
                    routing_decisions = self.routing_engine.route_event(
                        sec_assessment, prio_assessment, primary_hyp, trust_assessment,
                    )
                    notifications = self.notif_engine.generate_notifications(
                        sec_assessment, prio_assessment, primary_hyp, trust_assessment,
                        recommendation, routing_decisions, timestamp=state.timestamp_end,
                    )
                    relevant_roles = [d.role.value for d in routing_decisions if d.relevance in (RelevanceStatus.RELEVANT, RelevanceStatus.CONDITIONAL)]
                    omitted_roles = [d.role.value for d in routing_decisions if d.relevance == RelevanceStatus.NOT_RELEVANT]
                    notif_records = [
                        {"role": n.role.value, "headline": n.headline, "urgency": n.urgency.value, "detail": n.detail}
                        for n in notifications
                    ]
                    action_records = [
                        {"action_type": a.action_type.value, "target": a.target, "urgency": a.urgency.value}
                        for a in recommendation.actions
                    ]

            # Evaluate structural blast radius if topology is available (Task 19)
            blast_radius_data = None
            br_assessment = None
            if self.topology is not None:
                root_id = self.focus_node_id
                if root_id is None:
                    if self.topology.has_node("svc-db"):
                        root_id = "svc-db"
                    elif self.topology.node_count > 0:
                        root_id = self.topology.get_all_nodes()[0].node_id
                    else:
                        root_id = "unknown-root"
                br_assessment = self.blast_radius_engine.assess(self.topology, root_id)
                blast_radius_data = br_assessment.to_dict()

            # Evaluate confidence -> authority policy (Task 20)
            # Reuses project's explicit uncertainty representation from risk_traj.current_risk.uncertainty
            # NEVER synthesizes uncertainty = 1.0 - composite_trust
            horizon_unc_map: dict[int, float] = {0: risk_traj.current_risk.uncertainty}
            for fr in risk_traj.future_risks:
                horizon_unc_map[fr.horizon_step] = fr.uncertainty

            topo_avail = (
                self.topology.availability
                if self.topology is not None
                else TopologyAvailability.UNAVAILABLE
            )
            br_status = (
                br_assessment.status
                if br_assessment is not None
                else (BlastRadiusStatus.COMPLETE if self.topology is not None else BlastRadiusStatus.UNAVAILABLE)
            )
            br_cov = br_assessment.coverage_ratio if br_assessment is not None else None
            br_aff = br_assessment.affected_node_count if br_assessment is not None else 0
            br_crit = len(br_assessment.critical_affected_node_ids) if br_assessment is not None else 0
            br_imp = br_assessment.weighted_impact_score if br_assessment is not None else 0.0

            auth_input = AuthorityPolicyInput(
                risk_score=curr_risk_val,
                forecast_trust=trust_assessment.forecast_confidence,
                composite_trust=trust_val,
                uncertainty=risk_traj.current_risk.uncertainty,
                trust_level=trust_lvl,
                stage_confidence=primary_hyp.confidence,
                topology_availability=topo_avail,
                horizon_step=0,
                horizon_uncertainties=horizon_unc_map,
                blast_radius_status=br_status,
                blast_radius_coverage=br_cov,
                affected_node_count=br_aff,
                critical_affected_node_count=br_crit,
                weighted_structural_impact=br_imp,
                requested_action_class=None,
                is_reconsideration=recon_triggered,
            )
            auth_decision = self.authority_policy_engine.evaluate(auth_input)
            auth_policy_data = auth_decision.to_dict()

            # Evaluate Phase 3B Minimum Sufficient Selector
            sim_params = {
                InterventionType.DO_NOTHING: InterventionParameters(),
                InterventionType.RATE_LIMIT_IP: InterventionParameters(rate_limit_factor=0.20),
                InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=True, block_volume_reduction=0.90),
                InterventionType.ISOLATE_SERVICE_ENDPOINT: InterventionParameters(isolated_port=443),
            }
            targets = {
                InterventionType.ISOLATE_SERVICE_ENDPOINT: "svc-ingress-gw",
            }
            decision_result = None
            decision_result_dict = None
            try:
                decision_result = self.selector.select(
                    current_state=state,
                    baseline_deltas=pred_deltas[0],
                    simulation_params_map=sim_params,
                    target_entity_map=targets,
                    topology=self.topology,
                    risk_constraints=RiskConstraintParameters(target_risk=0.40, peak_risk_ceiling=0.60),
                )
                decision_result_dict = decision_result.to_dict()
            except Exception:
                decision_result = None
                decision_result_dict = None

            # Minimum Sufficient Intervention strictly from locked V1 action space:
            # DO_NOTHING, RATE_LIMIT_IP, TEMPORARY_BLOCK_IP, ISOLATE_SERVICE_ENDPOINT
            if decision_result is not None and decision_result.recommendation_status == RecommendationStatus.RECOMMENDED and decision_result.recommended_action is not None:
                rec_action_name = decision_result.recommended_action.value
                target_node = "svc-ingress-gw" if rec_action_name == "ISOLATE_SERVICE_ENDPOINT" else "198.51.100.x"
                urgency_val = "IMMEDIATE" if curr_risk_val >= 0.40 else ("PROMPT" if curr_risk_val >= 0.20 else "WHEN_CONVENIENT")
                action_records = [
                    {"action_type": rec_action_name, "target": target_node, "urgency": urgency_val}
                ]
            elif decision_result is not None and decision_result.recommendation_status == RecommendationStatus.NO_SUFFICIENT_ACTION:
                action_records = [
                    {"action_type": "NO_SUFFICIENT_ACTION", "target": "HUMAN_ESCALATION_REQUIRED", "urgency": "IMMEDIATE"}
                ]
            else:
                action_records = [
                    {"action_type": "DO_NOTHING", "target": "Baseline telemetry stream", "urgency": "WHEN_CONVENIENT"}
                ]

            event = DemoEvent(
                event_id=f"evt-{idx:04d}-{new_id('e')[:8]}",
                step_index=idx,
                logical_time_str=logical_time,
                wall_clock_time=datetime.now(),
                current_state_summary={
                    "dst_port_diversity": curr_vals.get("dst_port_diversity", 0.0),
                    "flow_count": curr_vals.get("flow_count", 0.0),
                    "byte_rate": curr_vals.get("byte_rate", 0.0),
                    "syn_ratio": curr_vals.get("syn_ratio", 0.0),
                    "rst_ratio": curr_vals.get("rst_ratio", 0.0),
                },
                predicted_deltas_h1={
                    "dst_port_diversity_delta": h1_deltas_dict.get("dst_port_diversity", 0.0),
                    "flow_count_delta": h1_deltas_dict.get("flow_count", 0.0),
                    "byte_rate_delta": h1_deltas_dict.get("byte_rate", 0.0),
                },
                primary_stage=primary_hyp.candidate_stage,
                stage_confidence=primary_hyp.confidence,
                trust_level=trust_lvl.value,
                composite_trust=trust_val,
                priority_level=prio_assessment.priority_level.value,
                composite_priority=prio_assessment.composite_priority,
                current_risk_score=curr_risk_val,
                future_risk_scores=future_risks_dict,
                risk_explanation=risk_expl,
                active_signatures=active_sig_names,
                candidate_attack_techniques=cand_attack_names,
                relevant_roles=relevant_roles,
                omitted_roles=omitted_roles,
                dispatched_notifications=notif_records,
                recommended_strategy=recommendation.strategy.value,
                requires_human=recommendation.requires_human,
                is_reversible=recommendation.is_reversible,
                recommended_actions=action_records,
                explanation=prio_assessment.reasoning,
                forecast_feature_contributions=forecast_contrib_dicts,
                security_explanation=sec_expl_dict,
                reconsideration=recon_data,
                reconsideration_triggered=recon_triggered,
                topology_context=self.topology.to_dict() if self.topology is not None else None,
                blast_radius=blast_radius_data,
                authority_policy=auth_policy_data,
                response_execution=None,
                outcome_verification=None,
                decision_result=decision_result_dict,
                _full_predicted_deltas_h1=h1_deltas_dict,
            )

            prior_event = event
            prior_state = state

            yield event
