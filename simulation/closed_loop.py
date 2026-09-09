"""Closed-Loop Verification Coordinator (SIH 26153 Phase 3D).

Coordinates post-action multi-horizon trajectory verification against Phase 3A
simulation expectations and triggers human-gated reconsideration when model mismatch
is detected.

CORE ARCHITECTURE:
    Approved Execution
           ↓
    Observe Telemetry across discrete windows (W_{exec+1}, W_{exec+2}, W_{exec+3})
           ↓
    Verify Trajectory (Risk ceiling + feature tolerance cone + persistence filter)
           ↓
    If VERIFIED_MISMATCH:
           ↓
    Reconsideration (Downwards trust adjustment + pipeline re-execution via Selector)
           ↓
    NEW ApprovalRequest (approval_required = True)
           ↓
    Awaits Human Approval (ZERO autonomous second execution)

NON-NEGOTIABLE SAFETY INVARIANTS:
1. Reconsideration NEVER autonomously executes a second response. It strictly creates
   a new unapproved ApprovalRequest.
2. Divergence is classified non-causally as MODEL_MISMATCH / VERIFIED_MISMATCH, not
   intervention failure.
3. Telemetry past active action TTL is treated as post-expiration recovery and fails closed.
4. Missing, unmeasured, or empty telemetry NEVER implies success (fails closed to INSUFFICIENT_EVIDENCE).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence
import numpy as np

from core.contracts import (
    Direction,
    NetworkState,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from core.response_execution.models import ResponseAction
from core.response_execution.verification import (
    OutcomeVerifier,
    TrajectoryOutcomeExpectation,
    TrajectoryVerificationConfig,
    TrajectoryVerificationResult,
    VerificationStatus,
)
from simulation.approval_gate import HumanApprovalGate
from simulation.approval_models import ApprovalRequest
from simulation.decision_models import DecisionResult, RecommendationStatus
from simulation.selector import MinimumSufficientSelector


class ClosedLoopCoordinator:
    """
    Coordinates closed-loop trajectory verification and human-gated reconsideration.
    """

    def __init__(
        self,
        verifier: OutcomeVerifier | None = None,
        config: TrajectoryVerificationConfig | None = None,
    ) -> None:
        self.verifier = verifier or OutcomeVerifier()
        self.config = config or TrajectoryVerificationConfig()

    def build_trajectory_expectation(
        self,
        action: ResponseAction,
        decision_result: DecisionResult,
        baseline_state: NetworkState,
        execution_window_id: str,
        execution_timestamp_end: datetime | None = None,
        action_ttl_seconds: float = 30.0,
        target_features: Sequence[str] = ("byte_rate", "packet_rate", "flow_count", "syn_ratio"),
    ) -> TrajectoryOutcomeExpectation:
        """
        Construct a TrajectoryOutcomeExpectation binding the executed action to its
        Phase 3A simulation trajectory and Phase 3B safety envelope.
        """
        exec_end = execution_timestamp_end or baseline_state.timestamp_end

        # Find corresponding ActionEvaluation if available
        pred_traj = None
        pred_risk_traj = None
        rec_act_name = decision_result.recommended_action.value if decision_result.recommended_action else action.action_type.value

        for act_key, eval_record in decision_result.action_evaluations.items():
            if act_key == rec_act_name or act_key == action.action_type.value:
                sim_res = getattr(eval_record, "simulation_result", None)
                if sim_res is not None:
                    pred_traj = getattr(sim_res, "intervention_trajectory", None)
                    pred_risk_traj = getattr(sim_res, "intervention_risk", None)
                else:
                    pred_traj = getattr(eval_record, "predicted_trajectory", None)
                    pred_risk_traj = getattr(eval_record, "predicted_risk_trajectory", None)
                break

        target = getattr(action, "target_node_id", None) or getattr(action, "target_entity", "")
        return TrajectoryOutcomeExpectation(
            action_id=action.action_id,
            recommended_action=rec_act_name,
            target_entity=target,
            baseline_state=baseline_state,
            predicted_trajectory=pred_traj,
            predicted_risk_trajectory=pred_risk_traj,
            risk_ceiling=decision_result.peak_risk_ceiling,
            action_ttl_seconds=action_ttl_seconds,
            execution_window_id=execution_window_id,
            execution_timestamp_end=exec_end,
            target_features=tuple(target_features),
        )

    def evaluate_closed_loop(
        self,
        action: ResponseAction,
        expectation: TrajectoryOutcomeExpectation,
        observed_states: Sequence[NetworkState] | NetworkState,
        risk_engine: Any = None,
        bridge: Any = None,
        config: TrajectoryVerificationConfig | None = None,
    ) -> TrajectoryVerificationResult:
        """
        Evaluate observed post-action telemetry against the simulated intervention expectation.
        Delegates directly to OutcomeVerifier.verify_trajectory.
        """
        cfg = config or self.config
        return self.verifier.verify_trajectory(
            action=action,
            expectation=expectation,
            observed_states=observed_states,
            risk_engine=risk_engine,
            bridge=bridge,
            config=cfg,
        )

    def trigger_reconsideration_if_mismatch(
        self,
        verification_result: TrajectoryVerificationResult,
        current_state: NetworkState,
        history_deltas: np.ndarray,
        prior_trust: TrustAssessment,
        selector: MinimumSufficientSelector,
        approval_gate: HumanApprovalGate,
        target_entity: str,
        baseline_deltas: np.ndarray | None = None,
    ) -> ApprovalRequest | None:
        """
        Trigger closed-loop reconsideration if and only if trajectory verification
        detects VERIFIED_MISMATCH.

        CRITICAL SAFETY INVARIANT:
        This method re-runs MinimumSufficientSelector with an adjusted, penalized TrustAssessment,
        generates an updated DecisionResult, and packages it into a NEW ApprovalRequest.
        Under NO circumstances does it automatically dispatch execution.
        The returned ApprovalRequest has approval_required=True and awaits human review.
        """
        if verification_result.status != VerificationStatus.VERIFIED_MISMATCH:
            return None

        # 1. Compute empirical forecast error penalty reusing established reconsideration formula
        deviations: list[float] = []
        for step_info in verification_result.step_evaluations.values():
            if step_info.get("step_mismatch"):
                base = float(step_info.get("baseline_value", 1.0))
                obs = float(step_info.get("observed_value", base))
                dev = abs(obs - base) / max(1.0, abs(base))
                deviations.append(dev)

        mean_dev = float(np.mean(deviations)) if deviations else 1.0
        forecast_error_penalty = min(0.30, mean_dev * 0.10)
        adjusted_trust_val = max(0.05, float(prior_trust.composite_trust) - forecast_error_penalty)

        if adjusted_trust_val >= 0.70:
            adjusted_trust_level = TrustLevel.HIGH
        elif adjusted_trust_val >= 0.45:
            adjusted_trust_level = TrustLevel.MEDIUM
        elif adjusted_trust_val >= 0.20:
            adjusted_trust_level = TrustLevel.LOW
        else:
            adjusted_trust_level = TrustLevel.INSUFFICIENT

        adjusted_trust = TrustAssessment(
            assessment_id=new_id("trust-recon-traj"),
            forecast_id=prior_trust.forecast_id,
            forecast_confidence=adjusted_trust_val,
            model_disagreement=prior_trust.model_disagreement,
            distribution_shift_score=prior_trust.distribution_shift_score,
            novelty_score=prior_trust.novelty_score,
            historical_error=prior_trust.historical_error,
            data_quality=prior_trust.data_quality,
            composite_trust=adjusted_trust_val,
            trust_level=adjusted_trust_level,
            contributing_factors=(
                TrustFactor(
                    name="trajectory_verification_mismatch",
                    value=forecast_error_penalty,
                    direction=Direction.DECREASES_TRUST,
                ),
            ),
        )

        # 2. Re-run MinimumSufficientSelector with lowered trust
        revised_decision = selector.select(
            current_state=current_state,
            baseline_deltas=baseline_deltas,
            history_deltas=history_deltas,
            trust_assessment=adjusted_trust,
        )

        # 3. Create a NEW ApprovalRequest for human review
        rationale = (
            f"RECONSIDERATION TRIGGERED: Trajectory verification detected model mismatch "
            f"({verification_result.explanation}). Trust downgraded from {prior_trust.composite_trust:.2f} "
            f"to {adjusted_trust_val:.2f} (penalty: {forecast_error_penalty:.4f}). "
            f"Revised recommendation: {revised_decision.recommended_action.value if revised_decision.recommended_action else 'NONE'}."
        )

        new_request = approval_gate.create_request(
            decision_result=revised_decision,
            target_entity=target_entity,
            evidence_window_id=current_state.window_id,
            rationale=rationale,
        )

        # Ensure invariant: approval_required is ALWAYS True
        assert new_request.approval_required is True, "Reconsideration request must require approval"

        return new_request
