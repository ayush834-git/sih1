"""Data contracts for Phase 3B: Disruption Modeling & Minimum-Sufficient Selection (SIH 26153).

Provides immutable data models representing:
- Evaluation of candidate interventions against future-risk safety constraints
- Operational disruption estimates based on structural topology & blast radius
- Minimum-sufficient intervention recommendation decisions
- Explicit classification of design parameters requiring empirical calibration

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Recommendation only — zero automated execution.
2. Sufficiency first, disruption second — does NOT automatically pick the strongest action.
3. Transparent design parameters — classified as INITIAL DESIGN PARAMETERS.
4. Fail-closed on missing topology or unsupported transformations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping

from core.blastradius.models import BlastRadiusStatus
from simulation.models import AssumptionRecord, InterventionStatus, InterventionType, SimulationResult


class RecommendationStatus(str, Enum):
    """Status of the minimum-sufficient intervention recommendation."""
    RECOMMENDED = "RECOMMENDED"                    # Minimum-sufficient intervention successfully identified.
    NO_SUFFICIENT_ACTION = "NO_SUFFICIENT_ACTION"  # No candidate intervention satisfies configured safety constraints.
    UNRESOLVED = "UNRESOLVED"                      # Decision unresolved due to unavailable topology or missing inputs.
    UNSUPPORTED = "UNSUPPORTED"                    # Candidate action cannot be evaluated or simulated defensibly.


@dataclass(frozen=True)
class RiskConstraintParameters:
    """
    Configurable safety envelope parameters governing intervention sufficiency.
    Both target_risk and peak_risk_ceiling are INITIAL DESIGN PARAMETERS requiring
    empirical benchmark calibration.
    """
    target_risk: float = 0.40  # INITIAL DESIGN PARAMETER — Maximum acceptable aggregate future risk J_risk
    peak_risk_ceiling: float = 0.60  # INITIAL DESIGN PARAMETER — Maximum acceptable peak future risk R_max
    horizon_weights: Mapping[int, float] = field(
        default_factory=lambda: {1: 0.3333, 2: 0.3333, 3: 0.3334}
    )

    def __post_init__(self) -> None:
        if not (0.0 <= self.target_risk <= 1.0):
            raise ValueError(f"target_risk must be in [0, 1], got {self.target_risk}")
        if not (0.0 <= self.peak_risk_ceiling <= 1.0):
            raise ValueError(f"peak_risk_ceiling must be in [0, 1], got {self.peak_risk_ceiling}")
        total_w = sum(self.horizon_weights.values())
        if abs(total_w - 1.0) > 0.05:
            raise ValueError(f"horizon_weights sum ({total_w}) must approximately equal 1.0")


@dataclass(frozen=True)
class DisruptionParameters:
    """
    Configurable parameters governing the operational disruption model J_disrupt(a, G).
    All weights and aggressiveness scores are INITIAL DESIGN PARAMETERS requiring calibration.
    """
    omega_direct: float = 0.50  # Weight on direct entity operational cost
    omega_cascade: float = 0.50  # Weight on downstream structural cascade cost
    aggressiveness_map: Mapping[InterventionType, float] = field(
        default_factory=lambda: {
            InterventionType.DO_NOTHING: 0.0,
            InterventionType.RATE_LIMIT_IP: 0.25,
            InterventionType.TEMPORARY_BLOCK_IP: 0.50,
            InterventionType.ISOLATE_SERVICE_ENDPOINT: 0.85,
        }
    )
    default_ttl_seconds: float = 10.0
    ttl_reference_seconds: float = 60.0
    default_ip_direct_cost: float = 0.20
    default_endpoint_direct_cost: float = 0.60

    def __post_init__(self) -> None:
        if not (0.0 <= self.omega_direct <= 1.0):
            raise ValueError(f"omega_direct must be in [0, 1], got {self.omega_direct}")
        if not (0.0 <= self.omega_cascade <= 1.0):
            raise ValueError(f"omega_cascade must be in [0, 1], got {self.omega_cascade}")


@dataclass(frozen=True)
class ActionEvaluation:
    """
    Comprehensive, explainable evaluation record for a single candidate intervention.
    Captures future aggregate risk, peak risk, constraint satisfaction, operational disruption,
    blast-radius basis, and rejection rationale.
    """
    action: InterventionType
    simulation_status: InterventionStatus
    aggregate_risk: float  # J_risk(a)
    peak_risk: float  # R_max(a)
    risk_target_satisfied: bool
    peak_ceiling_satisfied: bool
    is_sufficient: bool  # True strictly if both risk_target and peak_ceiling are satisfied
    disruption_estimate: float | None  # J_disrupt(a, G), or None if topology is unavailable
    disruption_breakdown: Mapping[str, float] = field(default_factory=dict)
    blast_radius_status: BlastRadiusStatus | None = None
    blast_radius_impact: float | None = None
    assumptions: tuple[AssumptionRecord, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    rejection_reasons: tuple[str, ...] = field(default_factory=tuple)
    simulation_result: SimulationResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "simulation_status": self.simulation_status.value,
            "aggregate_risk": round(self.aggregate_risk, 4),
            "peak_risk": round(self.peak_risk, 4),
            "risk_target_satisfied": self.risk_target_satisfied,
            "peak_ceiling_satisfied": self.peak_ceiling_satisfied,
            "is_sufficient": self.is_sufficient,
            "disruption_estimate": round(self.disruption_estimate, 4) if self.disruption_estimate is not None else None,
            "disruption_breakdown": {k: round(v, 4) for k, v in self.disruption_breakdown.items()},
            "blast_radius_status": self.blast_radius_status.value if self.blast_radius_status is not None else None,
            "blast_radius_impact": round(self.blast_radius_impact, 4) if self.blast_radius_impact is not None else None,
            "assumptions": [a.to_dict() for a in self.assumptions],
            "warnings": list(self.warnings),
            "rejection_reasons": list(self.rejection_reasons),
        }


@dataclass(frozen=True)
class DecisionResult:
    """
    Immutable audit record representing the minimum-sufficient intervention recommendation.

    Answers: 'Which candidate intervention is the least operationally disruptive
    among interventions satisfying the configured future-risk safety envelope?'
    """
    recommended_action: InterventionType | None
    recommendation_status: RecommendationStatus
    sufficient_candidates: tuple[InterventionType, ...]
    rejected_candidates: tuple[InterventionType, ...]
    action_evaluations: Mapping[str, ActionEvaluation]
    selected_risk: float | None
    selected_peak_risk: float | None
    selected_disruption: float | None
    lowest_risk_candidate: InterventionType | None  # Exposes lowest-risk option for human review if none sufficient
    target_risk: float
    peak_risk_ceiling: float
    unresolved_reason: str | None = None
    assumptions: tuple[AssumptionRecord, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    provenance_hash: str = field(default="")
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommended_action": self.recommended_action.value if self.recommended_action is not None else None,
            "recommendation_status": self.recommendation_status.value,
            "sufficient_candidates": [a.value for a in self.sufficient_candidates],
            "rejected_candidates": [a.value for a in self.rejected_candidates],
            "action_evaluations": {k: v.to_dict() for k, v in self.action_evaluations.items()},
            "selected_risk": round(self.selected_risk, 4) if self.selected_risk is not None else None,
            "selected_peak_risk": round(self.selected_peak_risk, 4) if self.selected_peak_risk is not None else None,
            "selected_disruption": round(self.selected_disruption, 4) if self.selected_disruption is not None else None,
            "lowest_risk_candidate": self.lowest_risk_candidate.value if self.lowest_risk_candidate is not None else None,
            "target_risk": round(self.target_risk, 4),
            "peak_risk_ceiling": round(self.peak_risk_ceiling, 4),
            "unresolved_reason": self.unresolved_reason,
            "assumptions": [a.to_dict() for a in self.assumptions],
            "warnings": list(self.warnings),
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }
