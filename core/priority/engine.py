"""Priority Assessment Engine (SIH 26153).

Deterministically assesses event priority by explicitly separating confidence, trust,
consequence, asset criticality, and actionability, without arbitrary ML probabilities.
High uncertainty acts as a dampener rather than an escalator.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from core.contracts import (
    EvidenceDirection,
    EvidenceItem,
    PriorityAssessment,
    PriorityLevel,
    SecurityAssessment,
    TrustAssessment,
    TrustLevel,
    new_id,
)
from security.contracts import EvidenceStrength, SignatureType, StageHypothesis


class PriorityEngine:
    """
    Evaluates SecurityAssessment and TrustAssessment into an interpretable PriorityAssessment.
    """
    def __init__(self, default_asset_criticality: float = 0.50) -> None:
        self.default_asset_criticality = default_asset_criticality

    def assess_priority(
        self,
        security_assessment: SecurityAssessment,
        trust_assessment: TrustAssessment,
        stage_hypothesis: StageHypothesis,
        asset_criticality: float | None = None,
    ) -> PriorityAssessment:
        """
        Compute an interpretable, multidimensional PriorityAssessment.
        """
        crit = self.default_asset_criticality if asset_criticality is None else asset_criticality
        stage = stage_hypothesis.candidate_stage
        conf = float(stage_hypothesis.confidence)
        trust_val = float(trust_assessment.composite_trust)
        
        # 1. Consequence Score (depends on candidate attack stage and potential impact)
        if stage == "Impact / Denial of Service":
            consequence = 0.85
        elif stage == "Collection / Exfiltration":
            consequence = 0.80
        elif stage == "Initial Access / Delivery":
            consequence = 0.60
        elif stage == "Reconnaissance":
            consequence = 0.40
        else:  # Unknown / Benign baseline
            consequence = 0.15

        # 2. Likelihood Score (Combines stage confidence with forecast trust)
        # Invariant: If trust is LOW/INSUFFICIENT or confidence is low, likelihood is heavily dampened
        likelihood = conf * (0.5 + 0.5 * trust_val)

        # 3. Proximity / Urgency Score (Based on whether evidence is immediate or speculative)
        has_current_sigs = any(
            item.contribution >= 0.70 for item in security_assessment.evidence_summary
        )
        if has_current_sigs:
            proximity = 0.80 if stage in ("Impact / Denial of Service", "Collection / Exfiltration") else 0.60
        else:
            proximity = 0.35 * trust_val  # Speculative forecast has lower proximity

        # 4. Attack Path Leverage
        if stage in ("Reconnaissance", "Initial Access / Delivery"):
            attack_path_leverage = 0.70  # Early intervention has high leverage
        elif stage in ("Collection / Exfiltration", "Impact / Denial of Service"):
            attack_path_leverage = 0.40  # Late stage has lower preventive leverage
        else:
            attack_path_leverage = 0.10

        # 5. Actionability Score (Are there reversible defensive measures available?)
        actionability = 0.80 if stage != "Unknown" else 0.20

        # 6. Composite Priority Calculation
        # Weighted combination: Consequence, Likelihood, Asset Criticality, Proximity
        # CRITICAL SAFETY INVARIANT: Uncertainty and low trust suppress composite priority.
        raw_composite = (
            0.35 * (consequence * crit) +
            0.30 * likelihood +
            0.20 * proximity +
            0.15 * (attack_path_leverage * actionability)
        )
        
        # Uncertainty penalty dampening
        if trust_assessment.trust_level in (TrustLevel.LOW, TrustLevel.INSUFFICIENT):
            raw_composite *= 0.65  # Severe dampening for low trust/speculative forecasts
            
        composite_priority = max(0.0, min(1.0, float(raw_composite)))

        # 7. Qualitative Priority Level Assignment
        if composite_priority >= 0.75 and trust_assessment.trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM):
            priority_level = PriorityLevel.CRITICAL
        elif composite_priority >= 0.55:
            priority_level = PriorityLevel.HIGH
        elif composite_priority >= 0.35:
            priority_level = PriorityLevel.MEDIUM
        elif composite_priority >= 0.20:
            priority_level = PriorityLevel.LOW
        else:
            priority_level = PriorityLevel.INFO

        # Invariant: If stage is Unknown, priority cannot exceed LOW/INFO
        if stage == "Unknown" and priority_level in (PriorityLevel.CRITICAL, PriorityLevel.HIGH, PriorityLevel.MEDIUM):
            priority_level = PriorityLevel.INFO
            composite_priority = min(composite_priority, 0.20)

        # 8. Reasoning Documentation
        reasoning = (
            f"Stage '{stage}' evaluated with consequence={consequence:.2f}, likelihood={likelihood:.2f} "
            f"(conf={conf:.2f}, trust={trust_val:.2f}), proximity={proximity:.2f}, criticality={crit:.2f}. "
            f"Resulting priority level is {priority_level.value} (composite={composite_priority:.3f})."
        )

        return PriorityAssessment(
            assessment_id=new_id("prio"),
            security_assessment_id=security_assessment.assessment_id,
            likelihood=likelihood,
            consequence=consequence,
            asset_criticality=crit,
            attack_path_leverage=attack_path_leverage,
            proximity=proximity,
            actionability=actionability,
            composite_priority=composite_priority,
            priority_level=priority_level,
            reasoning=reasoning,
        )
