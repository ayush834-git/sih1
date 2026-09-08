"""Confidence -> Authority Policy Data Contracts (SIH 26153 Task 20).

Defines explicit authority levels, operational action classes, policy inputs,
and immutable authority decisions.

CORE PRINCIPLE:
HIGH RISK != HIGH AUTHORITY
Authority is derived from evidence quality (trust, uncertainty, topology completeness)
and conservative policy, NOT risk score alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Any, Mapping, Sequence

from core.blastradius.models import BlastRadiusStatus
from core.contracts import TrustLevel, new_id
from core.topology.models import TopologyAvailability


def _score(value: float, name: str) -> None:
    if not isfinite(value) or not (0.0 <= value <= 1.0):
        raise ValueError(f"{name} must be a finite score in [0, 1], got {value}")


class AuthorityLevel(str, Enum):
    """
    Explicit operational authority levels justified by current evidence.
    """
    OBSERVE = "OBSERVE"                             # System records/monitors event only.
    ALERT = "ALERT"                                 # System surfaces an operator alert.
    RECOMMEND = "RECOMMEND"                         # System generates an operational response recommendation.
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"  # Action may be proposed; explicit human approval mandatory.
    BLOCKED = "BLOCKED"                             # Requested action class is unauthorized under current evidence.


class ActionClass(str, Enum):
    """
    Operational action classes categorized by severity and autonomy prerequisites.
    """
    OBSERVE_ONLY = "OBSERVE_ONLY"                   # Passive telemetry recording / inspection.
    ALERT_OPERATOR = "ALERT_OPERATOR"               # Emitting SOC operator alert / notification.
    GENERATE_RECOMMENDATION = "GENERATE_RECOMMENDATION"  # Formulating defensive recommendation.
    PREPARE_REVERSIBLE_ACTION = "PREPARE_REVERSIBLE_ACTION"  # Staging reversible controls (e.g. drafted ACL).
    EXECUTE_REVERSIBLE_ACTION = "EXECUTE_REVERSIBLE_ACTION"  # Executing reversible containment (human-gated).
    EXECUTE_DESTRUCTIVE_ACTION = "EXECUTE_DESTRUCTIVE_ACTION"  # Permanent/destructive action (ALWAYS BLOCKED).


@dataclass(frozen=True)
class AuthorityPolicyInput:
    """
    Input evidence bundle evaluated by AuthorityPolicyEngine.
    Reuses existing project contracts (trust, uncertainty, topology, blast radius).
    NEVER synthesizes uncertainty as 1.0 - trust.
    """
    risk_score: float
    forecast_trust: float
    composite_trust: float
    uncertainty: float | None  # Reuses existing FutureSecurityRiskScore.uncertainty; None fails closed
    trust_level: TrustLevel
    stage_confidence: float
    topology_availability: TopologyAvailability
    horizon_step: int = 0
    horizon_uncertainties: Mapping[int, float] | None = None
    blast_radius_status: BlastRadiusStatus = BlastRadiusStatus.COMPLETE
    blast_radius_coverage: float | None = 1.0
    affected_node_count: int = 0
    critical_affected_node_count: int = 0
    weighted_structural_impact: float = 0.0
    requested_action_class: ActionClass | None = None
    is_reconsideration: bool = False

    @property
    def effective_uncertainty(self) -> float | None:
        """
        Reuses project's explicit uncertainty contract.
        If horizon-specific uncertainty is supplied, look up the target horizon step.
        If no explicit uncertainty is provided, returns None (fails closed).
        NEVER derives uncertainty = 1.0 - composite_trust.
        """
        if self.uncertainty is not None:
            return self.uncertainty
        if self.horizon_uncertainties is not None and self.horizon_step in self.horizon_uncertainties:
            return self.horizon_uncertainties[self.horizon_step]
        return None

    def is_valid(self) -> bool:
        """Verify all numerical bounds are finite and within [0, 1]."""
        try:
            _score(self.risk_score, "risk_score")
            _score(self.forecast_trust, "forecast_trust")
            _score(self.composite_trust, "composite_trust")
            _score(self.stage_confidence, "stage_confidence")
            _score(self.weighted_structural_impact, "weighted_structural_impact")
            eff_unc = self.effective_uncertainty
            if eff_unc is None:
                return False
            _score(eff_unc, "uncertainty")
            if self.blast_radius_coverage is not None:
                _score(self.blast_radius_coverage, "blast_radius_coverage")
            if self.affected_node_count < 0 or self.critical_affected_node_count < 0:
                return False
            return True
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> dict[str, Any]:
        eff_unc = self.effective_uncertainty
        return {
            "risk_score": round(self.risk_score, 4),
            "forecast_trust": round(self.forecast_trust, 4),
            "composite_trust": round(self.composite_trust, 4),
            "uncertainty": round(eff_unc, 4) if eff_unc is not None else None,
            "horizon_step": self.horizon_step,
            "horizon_uncertainties": (
                {str(k): round(v, 4) for k, v in self.horizon_uncertainties.items()}
                if self.horizon_uncertainties is not None
                else None
            ),
            "trust_level": self.trust_level.value,
            "stage_confidence": round(self.stage_confidence, 4),
            "topology_availability": self.topology_availability.value,
            "blast_radius_status": self.blast_radius_status.value,
            "blast_radius_coverage": round(self.blast_radius_coverage, 4) if self.blast_radius_coverage is not None else None,
            "affected_node_count": self.affected_node_count,
            "critical_affected_node_count": self.critical_affected_node_count,
            "weighted_structural_impact": round(self.weighted_structural_impact, 4),
            "requested_action_class": self.requested_action_class.value if self.requested_action_class else None,
            "is_reconsideration": self.is_reconsideration,
        }


@dataclass(frozen=True)
class AuthorityDecision:
    """
    First-class immutable decision output from AuthorityPolicyEngine.
    """
    decision_id: str
    authority_level: AuthorityLevel
    permitted_action_classes: tuple[ActionClass, ...]
    blocked_action_classes: tuple[ActionClass, ...]
    human_approval_required: bool
    policy_version: str = "authority-v1"
    reason_codes: tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""
    provenance_hash: str = field(default="")
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        if not self.decision_id:
            raise ValueError("decision_id is required")
        if not self.provenance_hash:
            perm_str = ",".join(a.value for a in sorted(self.permitted_action_classes, key=lambda x: x.value))
            block_str = ",".join(b.value for b in sorted(self.blocked_action_classes, key=lambda x: x.value))
            reasons_str = ",".join(sorted(self.reason_codes))
            canonical_repr = (
                f"{self.policy_version}|{self.authority_level.value}|"
                f"{perm_str}|{block_str}|{self.human_approval_required}|{reasons_str}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "authority_level": self.authority_level.value,
            "permitted_action_classes": [a.value for a in self.permitted_action_classes],
            "blocked_action_classes": [b.value for b in self.blocked_action_classes],
            "human_approval_required": self.human_approval_required,
            "policy_version": self.policy_version,
            "reason_codes": list(self.reason_codes),
            "explanation": self.explanation,
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorityDecision:
        return cls(
            decision_id=str(data["decision_id"]),
            authority_level=AuthorityLevel(data["authority_level"]),
            permitted_action_classes=tuple(ActionClass(a) for a in data.get("permitted_action_classes", [])),
            blocked_action_classes=tuple(ActionClass(b) for b in data.get("blocked_action_classes", [])),
            human_approval_required=bool(data.get("human_approval_required", True)),
            policy_version=str(data.get("policy_version", "authority-v1")),
            reason_codes=tuple(data.get("reason_codes", [])),
            explanation=str(data.get("explanation", "")),
            provenance_hash=str(data.get("provenance_hash", "")),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
        )
