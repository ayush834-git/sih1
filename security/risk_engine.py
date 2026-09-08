"""
Security Risk Scoring Engine (SIH 26153).

Computes bounded, explainable future security-risk scores R(t+h) for h in {0, 1, 2, 3}
derived from behavioural signatures, stage hypothesis confidence, forecast trust,
and empirical uncertainty.

Explicitly represents the relative security-risk intensity of the predicted trajectory.
This is NOT a calibrated probability that an attack will occur.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Mapping, Sequence

from core.contracts import (
    EvidenceDirection,
    FeatureAvailability,
    NetworkState,
    TrustAssessment,
    TrustLevel,
    new_id,
)
from security.contracts import (
    BehaviouralSignature,
    EvidenceScope,
    EvidenceStrength,
    FutureSecurityRiskScore,
    SecurityRiskTrajectory,
    SignatureType,
    StageHypothesis,
)

STAGE_SEVERITY_WEIGHTS: Mapping[str, float] = {
    "Impact / Denial of Service": 0.85,
    "Collection / Exfiltration": 0.80,
    "Initial Access / Delivery": 0.60,
    "Reconnaissance": 0.40,
    "Unknown": 0.15,
}

HORIZON_DEFAULT_UNCERTAINTY: Mapping[int, float] = {
    0: 0.10,
    1: 0.20,
    2: 0.35,
    3: 0.50,
}


class SecurityRiskEngine:
    """
    Computes deterministic, bounded future security-risk scores R(t+h)
    for lookahead horizons h in {0, 1, 2, 3}.
    """
    def __init__(self, normalization_constant: float = 1.50) -> None:
        self.gamma = normalization_constant

    def compute_risk_score(
        self,
        current_state: NetworkState,
        stage_hypothesis: StageHypothesis,
        horizon_step: int = 0,
        horizon_seconds: float = 0.0,
        trust_val: float = 0.85,
        trust_level: TrustLevel = TrustLevel.HIGH,
        uncertainty: float | None = None,
        signatures: Sequence[BehaviouralSignature] | None = None,
    ) -> FutureSecurityRiskScore:
        """
        Compute a single bounded future security-risk score R(t+h).
        """
        stage = stage_hypothesis.candidate_stage
        severity = STAGE_SEVERITY_WEIGHTS.get(stage, 0.15)
        conf = float(stage_hypothesis.confidence)
        
        # Determine horizon uncertainty
        if uncertainty is None:
            unc = HORIZON_DEFAULT_UNCERTAINTY.get(horizon_step, min(1.0, 0.15 * (horizon_step + 1)))
        else:
            unc = min(1.0, max(0.0, float(uncertainty)))
            
        # Determine horizon trust
        if horizon_step == 0:
            h_trust = min(0.95, max(0.05, trust_val))
        else:
            # Trust naturally degrades with open-loop horizon lookahead
            h_trust = max(0.05, min(0.95, trust_val - 0.10 * (horizon_step - 1)))

        # Mathematical formulation: R(t+h) = clip(Severity * Conf * Trust * (1 - Uncertainty) * gamma, 0, 1)
        certainty_retention = max(0.0, 1.0 - unc)
        raw_score = severity * conf * h_trust * certainty_retention * self.gamma
        
        # Uncertainty / low-trust dampening
        if trust_level in (TrustLevel.LOW, TrustLevel.INSUFFICIENT) or h_trust < 0.40:
            raw_score *= 0.65  # Penalize low-trust speculative projections

        # Invariant: Unknown/Benign stage is strictly capped at low baseline risk (<= 0.20)
        if stage == "Unknown":
            raw_score = min(raw_score, 0.18)

        score = max(0.0, min(1.0, float(raw_score)))

        # Extract supporting and suppressing factors
        supporting_factors: list[str] = []
        suppressing_factors: list[str] = []

        if signatures:
            for s in signatures:
                if s.is_available and s.horizon_step == horizon_step and s.evidence_strength in (EvidenceStrength.HIGH, EvidenceStrength.MEDIUM):
                    supporting_factors.append(s.explanation)
                elif s.is_available and s.horizon_step == horizon_step and s.direction == EvidenceDirection.DOWN:
                    suppressing_factors.append(s.explanation)

        if not supporting_factors:
            if stage != "Unknown":
                supporting_factors.append(f"Stage hypothesis '{stage}' with confidence {conf:.2f}")
            else:
                supporting_factors.append("Traffic telemetry within nominal baseline parameters")

        # Suppressing factors
        if unc >= 0.30:
            suppressing_factors.append(f"Horizon uncertainty dispersion ({unc*100:.0f}%)")
        if trust_level in (TrustLevel.LOW, TrustLevel.INSUFFICIENT):
            suppressing_factors.append(f"Model trust is {trust_level.value}")
        if current_state.feature_availability.get("fan_out", FeatureAvailability.AVAILABLE) == FeatureAvailability.UNAVAILABLE:
            suppressing_factors.append("Host endpoint topology telemetry UNAVAILABLE (NetFlow CSV limitation)")

        for c_ev in stage_hypothesis.counter_evidence:
            suppressing_factors.append(c_ev)

        # Supporting signatures list
        supp_sigs = tuple(s.signature_type.value for s in (signatures or []) if s.is_available and s.horizon_step == horizon_step)
        if not supp_sigs and stage != "Unknown":
            supp_sigs = tuple(s.signature_type.value for s in stage_hypothesis.supporting_signatures)

        # Concise descriptive explanation
        horizon_label = "NOW" if horizon_step == 0 else f"+{int(horizon_seconds)}s"
        explanation = (
            f"SECURITY RISK @ {horizon_label}: Risk Score={score:.2f} (Stage: '{stage}', "
            f"Severity={severity:.2f}, Conf={conf:.2f}, Trust={h_trust:.2f}, Uncertainty={unc:.2f}). "
            f"Relative risk intensity is {'HIGH' if score >= 0.60 else ('MEDIUM' if score >= 0.30 else 'LOW')}."
        )

        # Deterministic SHA-256 provenance hash
        hash_payload = f"{current_state.window_id}:{stage}:{score:.4f}:{horizon_step}:{h_trust:.4f}:{unc:.4f}"
        prov_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        return FutureSecurityRiskScore(
            risk_id=new_id(f"risk-h{horizon_step}"),
            horizon_step=horizon_step,
            horizon_seconds=horizon_seconds,
            score=score,
            primary_stage=stage,
            stage_severity=severity,
            hypothesis_confidence=conf,
            forecast_trust=h_trust,
            uncertainty=unc,
            supporting_signatures=supp_sigs,
            counter_evidence=stage_hypothesis.counter_evidence,
            supporting_factors=tuple(supporting_factors),
            suppressing_factors=tuple(suppressing_factors),
            explanation=explanation,
            provenance_hash=prov_hash,
        )

    def compute_risk_trajectory(
        self,
        current_state: NetworkState,
        stage_hypotheses: Sequence[StageHypothesis],
        trust_assessment: TrustAssessment,
        signatures: Sequence[BehaviouralSignature] | None = None,
        max_horizon: int = 3,
    ) -> SecurityRiskTrajectory:
        """
        Computes the complete risk trajectory: R(t+0) [NOW], R(t+1) [+10s], R(t+2) [+20s], R(t+3) [+30s].
        """
        # Primary stage hypothesis for current state
        primary_hyp = next((h for h in stage_hypotheses if h.is_primary), stage_hypotheses[0])
        trust_val = float(trust_assessment.composite_trust)
        trust_level = trust_assessment.trust_level

        # Current risk R(t+0)
        curr_risk = self.compute_risk_score(
            current_state=current_state,
            stage_hypothesis=primary_hyp,
            horizon_step=0,
            horizon_seconds=0.0,
            trust_val=trust_val,
            trust_level=trust_level,
            uncertainty=0.10,
            signatures=signatures,
        )

        # Future risks R(t+1), R(t+2), R(t+3)
        future_risks: list[FutureSecurityRiskScore] = []
        for h in range(1, max_horizon + 1):
            h_seconds = float(current_state.window_duration_s * h)
            h_unc = HORIZON_DEFAULT_UNCERTAINTY.get(h, min(1.0, 0.15 * (h + 1)))
            
            # Check if there are horizon-specific signatures or stage updates
            h_sigs = [s for s in (signatures or []) if s.horizon_step == h]
            
            # If forecast predicts decaying/contradictory signals, confidence is dampened
            has_fc_down = any(s.direction == EvidenceDirection.DOWN for s in h_sigs)
            has_fc_up = any(s.direction == EvidenceDirection.UP for s in h_sigs)
            
            h_hyp = primary_hyp
            if has_fc_down and not has_fc_up:
                # Contradictory forecast at this horizon
                h_hyp = StageHypothesis(
                    hypothesis_id=new_id(f"hyp-contra-h{h}"),
                    candidate_stage=primary_hyp.candidate_stage,
                    supporting_signatures=primary_hyp.supporting_signatures,
                    counter_evidence=primary_hyp.counter_evidence + (f"Forecast at +{int(h_seconds)}s predicts rapid deceleration",),
                    confidence=max(0.30, primary_hyp.confidence * 0.50),
                    trust_level=TrustLevel.LOW,
                    alternative_explanations=primary_hyp.alternative_explanations,
                    is_primary=primary_hyp.is_primary,
                )

            h_risk = self.compute_risk_score(
                current_state=current_state,
                stage_hypothesis=h_hyp,
                horizon_step=h,
                horizon_seconds=h_seconds,
                trust_val=trust_val,
                trust_level=h_hyp.trust_level,
                uncertainty=h_unc,
                signatures=signatures,
            )
            future_risks.append(h_risk)

        return SecurityRiskTrajectory(
            trajectory_id=new_id("risk-traj"),
            current_risk=curr_risk,
            future_risks=tuple(future_risks),
            created_at=datetime.now(),
        )

