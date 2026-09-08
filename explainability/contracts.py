"""Typed contracts for Explainability and Feature-Contribution Layer (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping, Sequence

from core.contracts import Direction, TrustLevel, new_id


class EvidenceType(str, Enum):
    """Classification of evidence origin."""
    CURRENT = "CURRENT"      # Feature is currently changing or elevated in observed telemetry
    FORECAST = "FORECAST"    # Feature is predicted to change across future horizons
    BOTH = "BOTH"            # Observed telemetry change reinforced by forecasted continuation


class ContributionDirection(str, Enum):
    """Directional influence of a feature contribution."""
    POSITIVE = "POSITIVE"    # Drives the target/metric upwards (+)
    NEGATIVE = "NEGATIVE"    # Drives the target/metric downwards (-)
    NEUTRAL = "NEUTRAL"      # Negligible or zero impact (0)


@dataclass(frozen=True)
class LagContribution:
    """Mathematical breakdown of a single autoregressive lag."""
    lag_order: int           # 1 to p
    coefficient: float       # beta_{j, l}
    lag_value: float         # Historical delta value Delta x_j(t - l + 1)
    signed_contribution: float  # beta_{j, l} * Delta x_j(t - l + 1)
    relative_weight: float   # Relative percentage of total absolute lag sum

    def to_dict(self) -> dict[str, object]:
        return {
            "lag_order": self.lag_order,
            "coefficient": round(self.coefficient, 6),
            "lag_value": round(self.lag_value, 6),
            "signed_contribution": round(self.signed_contribution, 6),
            "relative_weight": round(self.relative_weight, 4),
        }


@dataclass(frozen=True)
class FeatureContribution:
    """Typed feature-level contribution to a forecast or security hypothesis."""
    feature_name: str
    signed_direction: ContributionDirection
    normalized_contribution: float   # Normalized importance in [0, 1] relative to top features
    raw_contribution: float          # Raw mathematical contribution or perturbation score
    current_value: float
    predicted_delta: float
    baseline_reference_value: float
    evidence_type: EvidenceType
    lag_breakdown: tuple[LagContribution, ...] = field(default_factory=tuple)
    description: str = ""
    is_available: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "feature_name": self.feature_name,
            "signed_direction": self.signed_direction.value,
            "normalized_contribution": round(self.normalized_contribution, 4),
            "raw_contribution": round(self.raw_contribution, 6),
            "current_value": round(self.current_value, 4),
            "predicted_delta": round(self.predicted_delta, 4),
            "baseline_reference_value": round(self.baseline_reference_value, 4),
            "evidence_type": self.evidence_type.value,
            "lag_breakdown": [lb.to_dict() for lb in self.lag_breakdown],
            "description": self.description,
            "is_available": self.is_available,
        }


@dataclass(frozen=True)
class ForecastExplanation:
    """Explanation of a specific target feature forecast from dynamics models."""
    explanation_id: str
    window_id: str
    timestamp: datetime
    model_name: str
    horizon: int
    target_feature: str
    predicted_delta: float
    current_value: float
    forecast_value: float
    baseline_reference_value: float
    top_features: tuple[FeatureContribution, ...]
    evidence_type: EvidenceType
    confidence: float
    trust_level: TrustLevel
    limitations: tuple[str, ...]
    provenance_hash: str

    def to_dict(self) -> dict[str, object]:
        return {
            "explanation_id": self.explanation_id,
            "window_id": self.window_id,
            "timestamp": self.timestamp.isoformat(),
            "model_name": self.model_name,
            "horizon": self.horizon,
            "target_feature": self.target_feature,
            "predicted_delta": round(self.predicted_delta, 4),
            "current_value": round(self.current_value, 4),
            "forecast_value": round(self.forecast_value, 4),
            "baseline_reference_value": round(self.baseline_reference_value, 4),
            "top_features": [f.to_dict() for f in self.top_features],
            "evidence_type": self.evidence_type.value,
            "confidence": round(self.confidence, 4),
            "trust_level": self.trust_level.value,
            "limitations": list(self.limitations),
            "provenance_hash": self.provenance_hash,
        }


@dataclass(frozen=True)
class SecurityHypothesisExplanation:
    """Explainability object for a stage hypothesis synthesized by the Security Bridge."""
    explanation_id: str
    window_id: str
    timestamp: datetime
    primary_stage: str
    confidence: float
    trust_level: TrustLevel
    supporting_evidence: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    top_contributing_features: tuple[FeatureContribution, ...]
    current_vs_forecast_breakdown: Mapping[str, str]
    limitations: tuple[str, ...]
    provenance_hash: str

    def to_dict(self) -> dict[str, object]:
        return {
            "explanation_id": self.explanation_id,
            "window_id": self.window_id,
            "timestamp": self.timestamp.isoformat(),
            "primary_stage": self.primary_stage,
            "confidence": round(self.confidence, 4),
            "trust_level": self.trust_level.value,
            "supporting_evidence": list(self.supporting_evidence),
            "counter_evidence": list(self.counter_evidence),
            "alternative_explanations": list(self.alternative_explanations),
            "top_contributing_features": [f.to_dict() for f in self.top_contributing_features],
            "current_vs_forecast_breakdown": dict(self.current_vs_forecast_breakdown),
            "limitations": list(self.limitations),
            "provenance_hash": self.provenance_hash,
        }
