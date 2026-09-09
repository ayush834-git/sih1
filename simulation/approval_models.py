"""Data contracts for Phase 3C: Human Approval + Existing Response Execution Boundary (SIH 26153).

Provides immutable data models representing:
- Human approval requests derived from Phase 3B minimum-sufficient recommendations
- Explicit human approval/rejection decisions bound to exact recommendation provenance
- Execution outcomes capturing authority status, approval status, and existing executor outcomes
- Strict separation between human rejection (HUMAN_REJECTED) and executor refusal (EXECUTION_REJECTED)
- Process-scoped at-most-once execution gating

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. RECOMMENDATION != APPROVAL != EXECUTION.
2. PREDICT -> SIMULATE -> SELECT MINIMUM SUFFICIENT ACTION -> HUMAN APPROVAL -> EXISTING RESPONSE EXECUTION.
3. Strict provenance binding: Decision hash must match ApprovalRequest.provenance_hash exactly.
4. Fail-closed on missing approval, expired TTL, provenance mismatch, or authority denial.
5. In-memory at-most-once guard is strictly process-scoped; no durable cross-restart persistence claimed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping

from core.response_execution.models import ExecutionRecord, ExecutionStatus
from simulation.decision_models import DecisionResult
from simulation.models import AssumptionRecord, InterventionType


class ExecutionGateStatus(str, Enum):
    """
    Explicit status for the human approval and execution boundary gate.
    Distinguishes human intent, temporal validity, provenance integrity, authority, and execution outcomes.
    """
    NOT_APPROVED = "NOT_APPROVED"                # Execution attempted without explicit human approval.
    EXPIRED = "EXPIRED"                          # Approval decision or execution timestamp exceeds configured TTL.
    PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"  # Approval hash or request_id does not strictly match request.
    AUTHORITY_DENIED = "AUTHORITY_DENIED"        # Existing authority policy prohibits action.
    UNSUPPORTED = "UNSUPPORTED"                  # Decision status not RECOMMENDED or action is non-executable.
    HUMAN_REJECTED = "HUMAN_REJECTED"            # Human reviewer explicitly rejected the recommendation.
    EXECUTION_REJECTED = "EXECUTION_REJECTED"    # Existing executor or adapter refused/failed execution.
    EXECUTED = "EXECUTED"                        # Successfully passed all gates and executed via existing executor.
    ALREADY_EXECUTED = "ALREADY_EXECUTED"        # Request was already executed in this process scope (at-most-once).


@dataclass(frozen=True)
class ApprovalConfig:
    """
    Configurable parameters governing the human approval gate.
    Classified as INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION.
    """
    default_ttl_seconds: float = 60.0  # INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION
    default_reviewer_reference: str = "operator-001"

    def __post_init__(self) -> None:
        if self.default_ttl_seconds <= 0:
            raise ValueError(f"default_ttl_seconds must be positive, got {self.default_ttl_seconds}")


@dataclass(frozen=True)
class ApprovalRequest:
    """
    Immutable audit record requesting explicit human approval for a recommended intervention.
    Strictly binds the decision result, target entity, recommended action, and expiration window.
    """
    request_id: str
    decision_result: DecisionResult
    recommended_action: InterventionType | None
    target_entity: str
    rationale: str
    risk_summary: Mapping[str, Any]
    disruption_summary: Mapping[str, Any]
    assumptions: tuple[AssumptionRecord, ...]
    warnings: tuple[str, ...]
    approval_required: bool = True
    expires_at: datetime = field(default_factory=datetime.now)
    created_at: datetime = field(default_factory=datetime.now)
    provenance_hash: str = field(default="")
    evidence_window_id: str = "win-000"

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id is required")
        if not self.target_entity:
            raise ValueError("target_entity is required")

        if not self.provenance_hash:
            canonical_repr = (
                f"{self.request_id}:"
                f"{self.target_entity}:"
                f"{self.recommended_action.value if self.recommended_action else 'NONE'}:"
                f"{self.decision_result.provenance_hash}:"
                f"{self.evidence_window_id}:"
                f"{self.expires_at.isoformat()}"
            )
            object.__setattr__(
                self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest()
            )

    def is_expired(self, current_time: datetime | None = None) -> bool:
        t = current_time or datetime.now()
        return t > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "decision_result": self.decision_result.to_dict(),
            "recommended_action": self.recommended_action.value if self.recommended_action else None,
            "target_entity": self.target_entity,
            "rationale": self.rationale,
            "risk_summary": dict(self.risk_summary),
            "disruption_summary": dict(self.disruption_summary),
            "assumptions": [a.to_dict() for a in self.assumptions],
            "warnings": list(self.warnings),
            "approval_required": self.approval_required,
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "provenance_hash": self.provenance_hash,
            "evidence_window_id": self.evidence_window_id,
        }


@dataclass(frozen=True)
class ApprovalDecision:
    """
    Immutable record of a human operator's explicit approval or rejection decision.
    Strictly bound to the target request_id and exact ApprovalRequest.provenance_hash.
    """
    request_id: str
    approved: bool
    reason: str
    reviewer_reference: str = "operator-001"
    decided_at: datetime = field(default_factory=datetime.now)
    provenance_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id is required")
        if not self.reviewer_reference:
            raise ValueError("reviewer_reference is required")
        if not self.provenance_hash:
            raise ValueError("provenance_hash is required on ApprovalDecision")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "approved": self.approved,
            "reason": self.reason,
            "reviewer_reference": self.reviewer_reference,
            "decided_at": self.decided_at.isoformat(),
            "provenance_hash": self.provenance_hash,
        }


@dataclass(frozen=True)
class ExecutionOutcome:
    """
    Immutable audit outcome of an execution attempt through the human approval gate.
    Captures full audit trail without replacing existing response execution models.
    """
    request_id: str
    action: InterventionType | None
    target: str
    approval_status: ExecutionGateStatus
    authority_status: str  # "PERMITTED", "DENIED", "NOT_EVALUATED"
    execution_status: ExecutionStatus | None
    response_identifier: str | None
    timestamp: datetime = field(default_factory=datetime.now)
    provenance_hash: str = field(default="")
    warnings: tuple[str, ...] = field(default_factory=tuple)
    error_message: str | None = None
    execution_record: ExecutionRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action": self.action.value if self.action else None,
            "target": self.target,
            "approval_status": self.approval_status.value,
            "authority_status": self.authority_status,
            "execution_status": self.execution_status.value if self.execution_status else None,
            "response_identifier": self.response_identifier,
            "timestamp": self.timestamp.isoformat(),
            "provenance_hash": self.provenance_hash,
            "warnings": list(self.warnings),
            "error_message": self.error_message,
            "execution_record": self.execution_record.to_dict() if self.execution_record else None,
        }
