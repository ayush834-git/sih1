"""First-Class Reconsideration & Trajectory Revision Engine (SIH 26153, Task 17).

Evaluates new telemetry for consistency with prior forecasts.
When evidence conflicts, re-runs the existing pipeline with adjusted trust
to produce a genuinely revised assessment. Records the prior-vs-revised delta
as an auditable ReconsiderationEvent.

The system evaluates new telemetry for consistency with its prior forecast
and revises downstream assessments via pipeline re-execution when evidence
conflicts. This is not autonomous intelligence; it is a closed-loop
evidence-consistency check.

Safety invariants:
- requires_human is ALWAYS True on every ReconsiderationEvent
- No destructive actions are ever autonomous
- Reconsideration adjusts trust input only; all downstream values come from
  actual pipeline re-execution through the same BehavioralSecurityBridge,
  SecurityRiskEngine, PriorityEngine, and ResponseRecommendationEngine
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Sequence

import numpy as np

from core.contracts import (
    Direction,
    NetworkState,
    PriorityAssessment,
    ResponseRecommendation,
    SecurityAssessment,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from eval.metrics_v2 import RobustScaleStatistics
from security.contracts import (
    BehaviouralSignature,
    EvidenceStrength,
    SecurityRiskTrajectory,
    StageHypothesis,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ConflictType(str, Enum):
    """Classification of the relationship between prior forecast and new observation."""
    CONFIRMING = "CONFIRMING"           # New observation is consistent with prior forecast
    CONTRADICTORY = "CONTRADICTORY"     # New observation significantly conflicts with prior forecast
    MIXED = "MIXED"                     # Some features confirm, others contradict
    INSUFFICIENT = "INSUFFICIENT"       # Not enough data to assess conflict (first step, missing features)


class DeviationDirection(str, Enum):
    """Direction of a single feature's deviation from prior prediction."""
    ESCALATION_MISSED = "ESCALATION_MISSED"     # Predicted low/stable but observed significant escalation
    FALSE_ESCALATION = "FALSE_ESCALATION"        # Predicted escalation but observed stability/decline
    MAGNITUDE_SHIFT = "MAGNITUDE_SHIFT"          # Direction correct but magnitude significantly off


class RevisionType(str, Enum):
    """How the revised assessment compares to the prior assessment."""
    DOWNGRADE = "DOWNGRADE"         # Revised assessment is less severe than prior
    UPGRADE = "UPGRADE"             # Revised assessment is more severe than prior
    LATERAL_SHIFT = "LATERAL_SHIFT" # Stage changed but severity is similar
    NO_CHANGE = "NO_CHANGE"         # Pipeline re-execution produced materially same result


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceConflict:
    """A single detected conflict between a prior forecast and the current observation."""
    conflict_id: str
    feature_name: str
    prior_predicted_delta: float      # What the prior forecast predicted as delta for this feature
    actual_observed_delta: float      # What was actually observed as delta
    scaled_deviation: float           # |actual - predicted| / robust_scale
    deviation_direction: str          # DeviationDirection value
    prior_forecast_id: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "feature_name": self.feature_name,
            "prior_predicted_delta": round(self.prior_predicted_delta, 4),
            "actual_observed_delta": round(self.actual_observed_delta, 4),
            "scaled_deviation": round(self.scaled_deviation, 4),
            "deviation_direction": self.deviation_direction,
            "prior_forecast_id": self.prior_forecast_id,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class ReconsiderationEvent:
    """An auditable record of a closed-loop revision triggered by conflicting evidence.

    The revised_* fields are produced by actual pipeline re-execution through
    BehavioralSecurityBridge, SecurityRiskEngine, PriorityEngine, and
    ResponseRecommendationEngine -- never fabricated from conflict type alone.
    """
    event_id: str
    trigger_window_id: str            # Current NetworkState window that triggered reconsideration
    prior_window_id: str              # Prior window whose assessment is being reconsidered
    prior_forecast_id: str
    conflict_type: str                # ConflictType value
    conflicts: tuple[EvidenceConflict, ...]

    # Prior assessment snapshot (captured from the prior step)
    prior_stage: str
    prior_stage_confidence: float
    prior_risk_score: float
    prior_priority_level: str
    prior_strategy: str
    prior_trust_level: str
    prior_composite_trust: float

    # Revised assessment (produced by actual pipeline re-execution)
    revised_stage: str
    revised_stage_confidence: float
    revised_risk_score: float
    revised_priority_level: str
    revised_strategy: str
    revised_trust_level: str
    revised_composite_trust: float

    # Revision characterization
    revision_type: str                # RevisionType value
    revision_magnitude: float         # |revised_risk - prior_risk|, bounded [0, 1]
    revision_reason: str              # Human-readable explanation of why the revision occurred
    provenance_hash: str              # SHA-256(prior_window_id + trigger_window_id + conflict_hashes)
    created_at: datetime

    # Safety invariant: ALWAYS True -- reconsideration never bypasses human approval
    requires_human: bool = True

    def __post_init__(self) -> None:
        if not self.requires_human:
            raise ValueError("ReconsiderationEvent.requires_human must always be True")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "trigger_window_id": self.trigger_window_id,
            "prior_window_id": self.prior_window_id,
            "prior_forecast_id": self.prior_forecast_id,
            "conflict_type": self.conflict_type,
            "conflicts": [c.to_dict() for c in self.conflicts],
            "prior_stage": self.prior_stage,
            "prior_stage_confidence": round(self.prior_stage_confidence, 4),
            "prior_risk_score": round(self.prior_risk_score, 4),
            "prior_priority_level": self.prior_priority_level,
            "prior_strategy": self.prior_strategy,
            "prior_trust_level": self.prior_trust_level,
            "prior_composite_trust": round(self.prior_composite_trust, 4),
            "revised_stage": self.revised_stage,
            "revised_stage_confidence": round(self.revised_stage_confidence, 4),
            "revised_risk_score": round(self.revised_risk_score, 4),
            "revised_priority_level": self.revised_priority_level,
            "revised_strategy": self.revised_strategy,
            "revised_trust_level": self.revised_trust_level,
            "revised_composite_trust": round(self.revised_composite_trust, 4),
            "revision_type": self.revision_type,
            "revision_magnitude": round(self.revision_magnitude, 4),
            "revision_reason": self.revision_reason,
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
            "requires_human": self.requires_human,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ReconsiderationEngine:
    """Evaluates new telemetry for consistency with prior forecasts.

    When evidence conflicts, re-runs the existing pipeline with adjusted trust
    to produce a genuinely revised assessment. The only synthetic input is a
    trust adjustment reflecting empirical forecast error; all downstream values
    (signatures, hypotheses, risk, priority, response) are produced by the
    standard pipeline components.
    """

    def __init__(
        self,
        bridge: Any,               # BehavioralSecurityBridge (Any to avoid circular import at type level)
        priority_engine: Any,       # PriorityEngine
        rec_engine: Any,            # ResponseRecommendationEngine
        scales: RobustScaleStatistics | None = None,
        conflict_threshold: float = 1.5,
        lookback_depth: int = 1,
    ) -> None:
        self.bridge = bridge
        self.priority_engine = priority_engine
        self.rec_engine = rec_engine
        self.scales = scales
        self.conflict_threshold = float(conflict_threshold)
        self.lookback_depth = int(lookback_depth)

    def assess_conflict(
        self,
        prior_predicted_deltas_h1: dict[str, float],
        current_state: NetworkState,
        prior_state: NetworkState,
        feature_names: Sequence[str],
        prior_forecast_id: str = "",
    ) -> tuple[ConflictType, list[EvidenceConflict]]:
        """Phase 1: Detect and characterize conflicts between prior prediction and observation.

        Compares the prior step's h=1 forecast deltas against the actual observed delta
        (current - prior state values). Returns conflict classification and individual
        feature conflicts. Does NOT produce any revised assessment values.
        """
        prior_vals = prior_state.feature_values()
        curr_vals = current_state.feature_values()

        # Compute actual observed deltas
        actual_deltas: dict[str, float] = {}
        for f in feature_names:
            if f in curr_vals and f in prior_vals:
                actual_deltas[f] = curr_vals[f] - prior_vals[f]

        if not actual_deltas:
            return ConflictType.INSUFFICIENT, []

        # Compute per-feature scaled deviations
        conflicts: list[EvidenceConflict] = []
        confirming_count = 0
        conflicting_count = 0

        for f_name in feature_names:
            if f_name not in actual_deltas or f_name not in prior_predicted_deltas_h1:
                continue

            predicted_delta = prior_predicted_deltas_h1.get(f_name, 0.0)
            actual_delta = actual_deltas[f_name]
            raw_deviation = abs(actual_delta - predicted_delta)

            # Scale by robust scale statistics if available, otherwise use unit scale
            if self.scales is not None and f_name in self.scales.feature_names:
                f_idx = self.scales.feature_names.index(f_name)
                scale = max(1e-9, float(self.scales.effective_scales[f_idx]))
            else:
                # Conservative fallback: unit scale. Deviation is measured in
                # raw absolute units. This means the conflict_threshold acts
                # as a raw absolute threshold (default 1.5 units).
                scale = 1.0

            scaled_dev = raw_deviation / scale

            if scaled_dev >= self.conflict_threshold:
                conflicting_count += 1

                # Classify deviation direction
                if predicted_delta <= 0.5 * scale and actual_delta > self.conflict_threshold * scale:
                    dev_dir = DeviationDirection.ESCALATION_MISSED.value
                    expl = (f"Feature '{f_name}': predicted delta={predicted_delta:.2f} (stable/low) "
                            f"but observed delta={actual_delta:.2f} (significant escalation). "
                            f"Scaled deviation: {scaled_dev:.2f}.")
                elif predicted_delta > 0.5 * scale and actual_delta < predicted_delta * 0.3:
                    dev_dir = DeviationDirection.FALSE_ESCALATION.value
                    expl = (f"Feature '{f_name}': predicted delta={predicted_delta:.2f} (escalation) "
                            f"but observed delta={actual_delta:.2f} (stable/decline). "
                            f"Scaled deviation: {scaled_dev:.2f}.")
                else:
                    dev_dir = DeviationDirection.MAGNITUDE_SHIFT.value
                    expl = (f"Feature '{f_name}': predicted delta={predicted_delta:.2f} "
                            f"but observed delta={actual_delta:.2f}. Direction may match but "
                            f"magnitude differs significantly. Scaled deviation: {scaled_dev:.2f}.")

                conflicts.append(EvidenceConflict(
                    conflict_id=new_id("conflict"),
                    feature_name=f_name,
                    prior_predicted_delta=predicted_delta,
                    actual_observed_delta=actual_delta,
                    scaled_deviation=scaled_dev,
                    deviation_direction=dev_dir,
                    prior_forecast_id=prior_forecast_id,
                    explanation=expl,
                ))
            else:
                confirming_count += 1

        # Classify overall conflict
        total_assessed = confirming_count + conflicting_count
        if total_assessed == 0:
            return ConflictType.INSUFFICIENT, []
        elif conflicting_count == 0:
            return ConflictType.CONFIRMING, []
        elif confirming_count == 0:
            return ConflictType.CONTRADICTORY, conflicts
        else:
            return ConflictType.MIXED, conflicts

    def execute_revision(
        self,
        conflict_type: ConflictType,
        conflicts: list[EvidenceConflict],
        current_state: NetworkState,
        prior_event_data: dict[str, Any],
        # Standard pipeline inputs for re-execution
        pred_deltas: np.ndarray,        # Shape: (H, n_features)
        trust_assessment: TrustAssessment,
        feature_names: Sequence[str],
    ) -> tuple | None:
        """Phase 2: If conflict warrants revision, re-run the existing pipeline.

        Returns None if no revision is warranted (CONFIRMING, INSUFFICIENT).

        When warranted (CONTRADICTORY, qualifying MIXED):
        1. Adjust trust based on empirical forecast error
        2. Re-run BehavioralSecurityBridge.extract_signatures()
        3. Re-run BehavioralSecurityBridge.infer_stage_hypotheses()
        4. Re-run BehavioralSecurityBridge.compute_security_risk_trajectory()
        5. Re-run PriorityEngine.assess_priority()
        6. Re-run ResponseRecommendationEngine.generate_recommendation()
        7. Compare prior vs newly computed assessment
        8. Record the ReconsiderationEvent

        Returns a tuple of:
            (ReconsiderationEvent, risk_trajectory, priority, recommendation,
             primary_hypothesis, signatures, hypotheses, adjusted_trust)
        """
        # Gate: decide if revision is warranted
        if conflict_type == ConflictType.CONFIRMING:
            return None
        if conflict_type == ConflictType.INSUFFICIENT:
            return None
        # MIXED requires at least one significant conflict
        if conflict_type == ConflictType.MIXED and len(conflicts) == 0:
            return None

        # ── Compute trust adjustment from empirical forecast error ──
        mean_scaled_dev = float(np.mean([c.scaled_deviation for c in conflicts])) if conflicts else 0.0
        forecast_error_penalty = min(0.30, mean_scaled_dev * 0.10)
        adjusted_trust_val = max(0.05, float(trust_assessment.composite_trust) - forecast_error_penalty)

        # Determine adjusted trust level from adjusted value
        if adjusted_trust_val >= 0.70:
            adjusted_trust_level = TrustLevel.HIGH
        elif adjusted_trust_val >= 0.45:
            adjusted_trust_level = TrustLevel.MEDIUM
        elif adjusted_trust_val >= 0.20:
            adjusted_trust_level = TrustLevel.LOW
        else:
            adjusted_trust_level = TrustLevel.INSUFFICIENT

        # ── Construct adjusted TrustAssessment ──
        adjusted_trust = TrustAssessment(
            assessment_id=new_id("trust-recon"),
            forecast_id=trust_assessment.forecast_id,
            forecast_confidence=adjusted_trust_val,
            model_disagreement=trust_assessment.model_disagreement,
            distribution_shift_score=trust_assessment.distribution_shift_score,
            novelty_score=trust_assessment.novelty_score,
            historical_error=trust_assessment.historical_error,
            data_quality=trust_assessment.data_quality,
            composite_trust=adjusted_trust_val,
            trust_level=adjusted_trust_level,
            contributing_factors=(
                TrustFactor(
                    name="reconsideration_forecast_error",
                    value=forecast_error_penalty,
                    direction=Direction.DECREASES_TRUST,
                ),
                TrustFactor(
                    name="prior_data_quality",
                    value=trust_assessment.data_quality,
                    direction=Direction.INCREASES_TRUST,
                ),
            ),
        )

        # ── Re-run the existing pipeline with adjusted trust ──

        # 1. Extract signatures (same bridge, adjusted trust)
        revised_sigs = self.bridge.extract_signatures(
            current_state,
            pred_deltas,
            feature_names,
            trust_level=adjusted_trust_level,
            uncertainty=0.20,
        )

        # 2. Infer stage hypotheses
        revised_hyps = self.bridge.infer_stage_hypotheses(
            revised_sigs,
            trust_level=adjusted_trust_level,
        )
        revised_primary = revised_hyps[0]

        # 3. Build security assessment for priority engine
        class _DummyTraj:
            def __init__(self, t_id: str) -> None:
                self.trajectory_id = t_id

        revised_sec = self.bridge.build_security_assessment(
            _DummyTraj(f"traj-recon-{current_state.window_id}"),
            adjusted_trust,
            revised_sigs,
            revised_hyps,
        )

        # 4. Compute risk trajectory
        revised_risk_traj = self.bridge.compute_security_risk_trajectory(
            current_state,
            revised_hyps,
            adjusted_trust,
            revised_sigs,
            max_horizon=3,
        )

        # 5. Assess priority
        revised_prio = self.priority_engine.assess_priority(
            revised_sec,
            adjusted_trust,
            revised_primary,
        )

        # 6. Generate response recommendation
        revised_rec = self.rec_engine.generate_recommendation(
            revised_prio,
            revised_sec,
            revised_primary,
            adjusted_trust,
        )

        # ── Compare prior vs revised ──
        prior_risk = float(prior_event_data.get("current_risk_score", 0.0))
        revised_risk = float(revised_risk_traj.current_risk.score)
        risk_delta = revised_risk - prior_risk

        prior_stage = str(prior_event_data.get("primary_stage", "Unknown"))
        revised_stage = revised_primary.candidate_stage

        if abs(risk_delta) < 0.02 and prior_stage == revised_stage:
            revision_type = RevisionType.NO_CHANGE.value
        elif risk_delta < -0.02:
            revision_type = RevisionType.DOWNGRADE.value
        elif risk_delta > 0.02:
            revision_type = RevisionType.UPGRADE.value
        elif prior_stage != revised_stage:
            revision_type = RevisionType.LATERAL_SHIFT.value
        else:
            revision_type = RevisionType.NO_CHANGE.value

        revision_magnitude = min(1.0, abs(risk_delta))

        # ── Build revision reason from conflict evidence ──
        conflict_summary = "; ".join(c.explanation for c in conflicts[:3])
        revision_reason = (
            f"Forecast-observation conflict detected ({conflict_type.value}). "
            f"Trust adjusted from {trust_assessment.composite_trust:.2f} to {adjusted_trust_val:.2f} "
            f"(penalty {forecast_error_penalty:.3f} from mean scaled deviation {mean_scaled_dev:.2f}). "
            f"Pipeline re-executed with adjusted trust. "
            f"Conflicts: {conflict_summary}"
        )

        # ── Provenance hash ──
        prior_window = str(prior_event_data.get("event_id", ""))
        trigger_window = current_state.window_id
        conflict_hash_payload = "|".join(
            f"{c.feature_name}:{c.scaled_deviation:.4f}" for c in conflicts
        )
        prov_payload = f"{prior_window}:{trigger_window}:{conflict_hash_payload}"
        provenance_hash = hashlib.sha256(prov_payload.encode("utf-8")).hexdigest()

        recon_event = ReconsiderationEvent(
            event_id=new_id("recon"),
            trigger_window_id=trigger_window,
            prior_window_id=prior_window,
            prior_forecast_id=str(prior_event_data.get("event_id", "")),
            conflict_type=conflict_type.value,
            conflicts=tuple(conflicts),
            # Prior snapshot
            prior_stage=prior_stage,
            prior_stage_confidence=float(prior_event_data.get("stage_confidence", 0.0)),
            prior_risk_score=prior_risk,
            prior_priority_level=str(prior_event_data.get("priority_level", "INFO")),
            prior_strategy=str(prior_event_data.get("recommended_strategy", "MONITOR")),
            prior_trust_level=str(prior_event_data.get("trust_level", "HIGH")),
            prior_composite_trust=float(prior_event_data.get("composite_trust", 0.85)),
            # Revised (from actual pipeline re-execution)
            revised_stage=revised_stage,
            revised_stage_confidence=float(revised_primary.confidence),
            revised_risk_score=revised_risk,
            revised_priority_level=revised_prio.priority_level.value,
            revised_strategy=revised_rec.strategy.value,
            revised_trust_level=adjusted_trust_level.value,
            revised_composite_trust=adjusted_trust_val,
            # Revision characterization
            revision_type=revision_type,
            revision_magnitude=revision_magnitude,
            revision_reason=revision_reason,
            provenance_hash=provenance_hash,
            created_at=datetime.now(),
            requires_human=True,
        )

        return (recon_event, revised_risk_traj, revised_prio, revised_rec,
                revised_primary, revised_sigs, revised_hyps, adjusted_trust)

    def evaluate(
        self,
        current_state: NetworkState,
        prior_state: NetworkState,
        prior_event_data: dict[str, Any],
        prior_predicted_deltas_h1: dict[str, float],
        pred_deltas: np.ndarray,
        trust_assessment: TrustAssessment,
        feature_names: Sequence[str],
    ) -> tuple[ReconsiderationEvent | None, dict[str, Any] | None]:
        """Convenience method: assess conflict and execute revision if warranted.

        Returns (ReconsiderationEvent | None, revised_pipeline_outputs | None).
        revised_pipeline_outputs is a dict with keys:
            risk_trajectory, priority, recommendation, primary_hypothesis,
            signatures, hypotheses, trust
        """
        prior_forecast_id = str(prior_event_data.get("event_id", ""))

        conflict_type, conflicts = self.assess_conflict(
            prior_predicted_deltas_h1=prior_predicted_deltas_h1,
            current_state=current_state,
            prior_state=prior_state,
            feature_names=feature_names,
            prior_forecast_id=prior_forecast_id,
        )

        if conflict_type in (ConflictType.CONFIRMING, ConflictType.INSUFFICIENT):
            return None, None

        result = self.execute_revision(
            conflict_type=conflict_type,
            conflicts=conflicts,
            current_state=current_state,
            prior_event_data=prior_event_data,
            pred_deltas=pred_deltas,
            trust_assessment=trust_assessment,
            feature_names=feature_names,
        )

        if result is None:
            return None, None

        recon_event, risk_traj, prio, rec, primary_hyp, sigs, hyps, adjusted_trust = result

        revised_outputs = {
            "risk_trajectory": risk_traj,
            "priority": prio,
            "recommendation": rec,
            "primary_hypothesis": primary_hyp,
            "signatures": sigs,
            "hypotheses": hyps,
            "trust": adjusted_trust,
        }

        return recon_event, revised_outputs
