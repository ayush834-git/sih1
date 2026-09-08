"""Internal typed contracts for the Behavioral Security Bridge (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping, Sequence

from core.contracts import (
    Direction,
    EvidenceDirection,
    FeatureAvailability,
    TrustLevel,
    new_id,
)


class SignatureType(str, Enum):
    RECONNAISSANCE_PORT_EXPLORATION = "RECONNAISSANCE_PORT_EXPLORATION"
    CONNECTION_FLOODING_RESOURCE_PRESSURE = "CONNECTION_FLOODING_RESOURCE_PRESSURE"
    EXFILTRATION_OUTBOUND_SURGE = "EXFILTRATION_OUTBOUND_SURGE"
    TIMING_BEHAVIOURAL_ANOMALY = "TIMING_BEHAVIOURAL_ANOMALY"
    LATERAL_FAN_OUT = "LATERAL_FAN_OUT"
    UNKNOWN = "UNKNOWN"


class EvidenceScope(str, Enum):
    CURRENT = "CURRENT"
    FORECAST = "FORECAST"


class EvidenceStrength(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class BehaviouralSignature:
    """A typed behavioural signature derived from current state or forecasted delta evolution."""
    signature_id: str
    signature_type: SignatureType
    scope: EvidenceScope
    horizon_step: int  # 0 for current, 1..H for forecast
    timestamp: datetime
    current_values: Mapping[str, float]
    predicted_deltas: Mapping[str, float]
    direction: EvidenceDirection
    supporting_features: tuple[str, ...]
    evidence_strength: EvidenceStrength
    uncertainty: float
    trust_level: TrustLevel
    explanation: str
    alternative_explanations: tuple[str, ...]
    is_available: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "signature_id": self.signature_id,
            "signature_type": self.signature_type.value,
            "scope": self.scope.value,
            "horizon_step": self.horizon_step,
            "timestamp": self.timestamp.isoformat(),
            "current_values": dict(self.current_values),
            "predicted_deltas": dict(self.predicted_deltas),
            "direction": self.direction.value,
            "supporting_features": list(self.supporting_features),
            "evidence_strength": self.evidence_strength.value,
            "uncertainty": self.uncertainty,
            "trust_level": self.trust_level.value,
            "explanation": self.explanation,
            "alternative_explanations": list(self.alternative_explanations),
            "is_available": self.is_available,
        }


@dataclass(frozen=True)
class StageHypothesis:
    """A ranked candidate stage hypothesis with evidence, counter-evidence, and trust."""
    hypothesis_id: str
    candidate_stage: str
    supporting_signatures: tuple[BehaviouralSignature, ...]
    counter_evidence: tuple[str, ...]
    confidence: float
    trust_level: TrustLevel
    alternative_explanations: tuple[str, ...]
    is_primary: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "candidate_stage": self.candidate_stage,
            "supporting_signatures": [s.signature_type.value for s in self.supporting_signatures],
            "counter_evidence": list(self.counter_evidence),
            "confidence": self.confidence,
            "trust_level": self.trust_level.value,
            "alternative_explanations": list(self.alternative_explanations),
            "is_primary": self.is_primary,
        }


@dataclass(frozen=True)
class AttackTechniqueHypothesis:
    """Mapping of behavioural signatures to candidate MITRE ATT&CK techniques with explicit limitations."""
    technique_id: str
    technique_name: str
    tactic_name: str
    supporting_signatures: tuple[str, ...]
    confidence: float
    rationale: str
    limitations: str
    is_available: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic_name": self.tactic_name,
            "supporting_signatures": list(self.supporting_signatures),
            "confidence": self.confidence,
            "rationale": self.rationale,
            "limitations": self.limitations,
            "is_available": self.is_available,
        }


@dataclass(frozen=True)
class FutureSecurityRiskScore:
    """
    A bounded, explainable future security-risk score R(t+h) for lookahead horizon h in {0, 1, 2, 3}.
    Represents the relative security-risk intensity of the predicted behavioural trajectory
    under current evidence, stage severity, model trust, and uncertainty.
    Explicitly NOT a calibrated attack probability.
    """
    risk_id: str
    horizon_step: int  # 0 for current (NOW), 1..H for future lookahead (+10s, +20s, +30s)
    horizon_seconds: float
    score: float  # Strictly bounded in [0.0, 1.0]
    primary_stage: str
    stage_severity: float
    hypothesis_confidence: float
    forecast_trust: float
    uncertainty: float
    supporting_signatures: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    supporting_factors: tuple[str, ...]
    suppressing_factors: tuple[str, ...]
    explanation: str
    provenance_hash: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"FutureSecurityRiskScore must be bounded in [0, 1], got {self.score}")
        if self.horizon_step < 0:
            raise ValueError(f"horizon_step must be >= 0, got {self.horizon_step}")

    def to_dict(self) -> dict[str, object]:
        return {
            "risk_id": self.risk_id,
            "horizon_step": self.horizon_step,
            "horizon_seconds": self.horizon_seconds,
            "score": round(self.score, 4),
            "primary_stage": self.primary_stage,
            "stage_severity": self.stage_severity,
            "hypothesis_confidence": self.hypothesis_confidence,
            "forecast_trust": self.forecast_trust,
            "uncertainty": self.uncertainty,
            "supporting_signatures": list(self.supporting_signatures),
            "counter_evidence": list(self.counter_evidence),
            "supporting_factors": list(self.supporting_factors),
            "suppressing_factors": list(self.suppressing_factors),
            "explanation": self.explanation,
            "provenance_hash": self.provenance_hash,
        }


@dataclass(frozen=True)
class SecurityRiskTrajectory:
    """A sequence of risk scores covering current state and multi-step future horizons."""
    trajectory_id: str
    current_risk: FutureSecurityRiskScore
    future_risks: tuple[FutureSecurityRiskScore, ...]  # Length H (e.g. h=1, 2, 3)
    created_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "trajectory_id": self.trajectory_id,
            "current_risk": self.current_risk.to_dict(),
            "future_risks": [r.to_dict() for r in self.future_risks],
            "created_at": self.created_at.isoformat(),
        }
