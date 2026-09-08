"""Response Execution Data Contracts (SIH 26153 Task 21).

Provides first-class immutable contracts for:
- Reversible response actions
- Explicit human approvals
- Execution lifecycle status tracking
- Rollback governance and audit records

CORE SAFETY PRINCIPLE:
RECOMMENDATION != AUTHORIZATION != APPROVAL != EXECUTION != VERIFICATION
Destructive actions are PERMANENTLY BLOCKED.
Reversible execution strictly requires explicit human approval.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping

from core.authority.models import ActionClass
from core.contracts import new_id


class ExecutionStatus(str, Enum):
    """
    Explicit lifecycle states for response execution.
    CRITICAL DISTINCTION: EXECUTED != VERIFIED_SUCCESS.
    """
    PROPOSED = "PROPOSED"                                 # Action formulated from recommendation.
    AWAITING_APPROVAL = "AWAITING_APPROVAL"               # Awaiting mandatory operator approval.
    APPROVED = "APPROVED"                                 # Explicit human approval granted.
    REJECTED = "REJECTED"                                 # Explicit human rejection.
    EXECUTING = "EXECUTING"                               # Handed off to adapter for execution.
    EXECUTED = "EXECUTED"                                 # Adapter applied changes; outcome NOT yet verified.
    VERIFICATION_PENDING = "VERIFICATION_PENDING"         # Waiting for telemetry observation window.
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"                 # Post-action telemetry confirmed expected outcome.
    VERIFIED_MISMATCH = "VERIFIED_MISMATCH"               # Post-action telemetry conflicted with expectation.
    ROLLBACK_REQUESTED = "ROLLBACK_REQUESTED"             # Compensating action requested.
    ROLLED_BACK = "ROLLED_BACK"                           # Compensating action applied by adapter.
    FAILED = "FAILED"                                     # Adapter failed to apply action or rollback.
    BLOCKED = "BLOCKED"                                   # Action prohibited by authority, stale state, or policy.


class ReversibleActionType(str, Enum):
    """
    Explicitly supported safe reversible action types.
    Destructive actions cannot be represented in this set.
    """
    TEMP_RATE_LIMIT = "TEMP_RATE_LIMIT"                   # Temporary ingress traffic rate-limiting.
    DEMO_BLOCK = "DEMO_BLOCK"                             # Temporary simulated connection drop/block.
    DEMO_DISABLE_ENDPOINT = "DEMO_DISABLE_ENDPOINT"       # Temporary simulated service endpoint toggle.
    REVERSIBLE_CONFIG_TOGGLE = "REVERSIBLE_CONFIG_TOGGLE" # Temporary reversible defense posture switch.


class RollbackPolicy(str, Enum):
    """
    Governance policy for compensating rollback operations.
    Rollback is a first-class controlled action, never an implicit privileged bypass.
    """
    AUTOMATIC_COMPENSATING = "AUTOMATIC_COMPENSATING"     # Predefined compensating op auto-permitted on failure/mismatch.
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"     # Rollback requires distinct explicit human approval.


@dataclass(frozen=True)
class ResponseAction:
    """
    Immutable specification of a proposed or executed defensive action.
    Bound to the exact authority decision and observation window under which it was formulated.
    """
    action_id: str
    action_class: ActionClass
    target_node_id: str
    action_type: ReversibleActionType
    requested_parameters: Mapping[str, Any]
    expected_effect: str
    reversibility: bool
    compensating_action_type: str
    authority_decision_id: str
    evidence_window_id: str
    recommendation_id: str | None = None
    topology_snapshot_id: str | None = None
    blast_radius_assessment_id: str | None = None
    rollback_policy: RollbackPolicy = RollbackPolicy.AUTOMATIC_COMPENSATING
    expected_effect_window_s: float = 10.0
    created_at: datetime = field(default_factory=datetime.now)
    provenance_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.action_id:
            raise ValueError("action_id is required")
        if not self.target_node_id:
            raise ValueError("target_node_id is required")
        if not self.authority_decision_id:
            raise ValueError("authority_decision_id is required")
        if not self.evidence_window_id:
            raise ValueError("evidence_window_id is required")
        if not self.reversibility:
            raise ValueError("Executable ResponseAction must have reversibility=True")
        if self.action_class == ActionClass.EXECUTE_DESTRUCTIVE_ACTION:
            raise ValueError("EXECUTE_DESTRUCTIVE_ACTION cannot be represented as executable")
        if not self.compensating_action_type:
            raise ValueError("compensating_action_type is mandatory for reversible actions")

        if not self.provenance_hash:
            canonical_repr = (
                f"{self.action_id}|{self.action_class.value}|{self.target_node_id}|"
                f"{self.action_type.value}|{self.authority_decision_id}|{self.evidence_window_id}|"
                f"{self.compensating_action_type}|{self.rollback_policy.value}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_class": self.action_class.value,
            "target_node_id": self.target_node_id,
            "action_type": self.action_type.value,
            "requested_parameters": dict(self.requested_parameters),
            "expected_effect": self.expected_effect,
            "reversibility": self.reversibility,
            "compensating_action_type": self.compensating_action_type,
            "authority_decision_id": self.authority_decision_id,
            "evidence_window_id": self.evidence_window_id,
            "recommendation_id": self.recommendation_id,
            "topology_snapshot_id": self.topology_snapshot_id,
            "blast_radius_assessment_id": self.blast_radius_assessment_id,
            "rollback_policy": self.rollback_policy.value,
            "expected_effect_window_s": self.expected_effect_window_s,
            "created_at": self.created_at.isoformat(),
            "provenance_hash": self.provenance_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponseAction:
        return cls(
            action_id=str(data["action_id"]),
            action_class=ActionClass(data["action_class"]),
            target_node_id=str(data["target_node_id"]),
            action_type=ReversibleActionType(data["action_type"]),
            requested_parameters=dict(data.get("requested_parameters", {})),
            expected_effect=str(data.get("expected_effect", "")),
            reversibility=bool(data.get("reversibility", True)),
            compensating_action_type=str(data["compensating_action_type"]),
            authority_decision_id=str(data["authority_decision_id"]),
            evidence_window_id=str(data["evidence_window_id"]),
            recommendation_id=data.get("recommendation_id"),
            topology_snapshot_id=data.get("topology_snapshot_id"),
            blast_radius_assessment_id=data.get("blast_radius_assessment_id"),
            rollback_policy=RollbackPolicy(data.get("rollback_policy", RollbackPolicy.AUTOMATIC_COMPENSATING.value)),
            expected_effect_window_s=float(data.get("expected_effect_window_s", 10.0)),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            provenance_hash=str(data.get("provenance_hash", "")),
        )


@dataclass(frozen=True)
class HumanApproval:
    """
    Immutable record of an explicit human operator approval or rejection.
    Strictly bound to the target action_id, authority_decision_id, and evidence_window_id.
    Approval can NEVER be implied from high risk, high trust, or priority.
    """
    approval_id: str
    action_id: str
    authority_decision_id: str
    evidence_window_id: str
    approved: bool
    approver_reference: str  # e.g. "demo-operator" (explicit, simulated operator reference)
    approval_reason: str
    created_at: datetime = field(default_factory=datetime.now)
    provenance_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.approval_id:
            raise ValueError("approval_id is required")
        if not self.action_id:
            raise ValueError("action_id is required")
        if not self.authority_decision_id:
            raise ValueError("authority_decision_id is required")
        if not self.evidence_window_id:
            raise ValueError("evidence_window_id is required")
        if not self.approver_reference:
            raise ValueError("approver_reference is required")

        if not self.provenance_hash:
            canonical_repr = (
                f"{self.approval_id}|{self.action_id}|{self.authority_decision_id}|"
                f"{self.evidence_window_id}|{self.approved}|{self.approver_reference}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "action_id": self.action_id,
            "authority_decision_id": self.authority_decision_id,
            "evidence_window_id": self.evidence_window_id,
            "approved": self.approved,
            "approver_reference": self.approver_reference,
            "approval_reason": self.approval_reason,
            "created_at": self.created_at.isoformat(),
            "provenance_hash": self.provenance_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HumanApproval:
        return cls(
            approval_id=str(data["approval_id"]),
            action_id=str(data["action_id"]),
            authority_decision_id=str(data["authority_decision_id"]),
            evidence_window_id=str(data["evidence_window_id"]),
            approved=bool(data["approved"]),
            approver_reference=str(data["approver_reference"]),
            approval_reason=str(data.get("approval_reason", "")),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            provenance_hash=str(data.get("provenance_hash", "")),
        )


@dataclass(frozen=True)
class ExecutionRecord:
    """
    Immutable audit record of an execution or rollback attempt.
    """
    execution_id: str
    action_id: str
    authority_decision_id: str
    evidence_window_id: str
    status: ExecutionStatus
    applied_parameters: Mapping[str, Any]
    approval_id: str | None = None
    is_rollback: bool = False
    error_message: str | None = None
    executed_at: datetime = field(default_factory=datetime.now)
    provenance_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.execution_id:
            raise ValueError("execution_id is required")
        if not self.action_id:
            raise ValueError("action_id is required")
        if not self.authority_decision_id:
            raise ValueError("authority_decision_id is required")
        if not self.evidence_window_id:
            raise ValueError("evidence_window_id is required")

        if not self.provenance_hash:
            canonical_repr = (
                f"{self.execution_id}|{self.action_id}|{self.authority_decision_id}|"
                f"{self.evidence_window_id}|{self.status.value}|{self.is_rollback}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "action_id": self.action_id,
            "authority_decision_id": self.authority_decision_id,
            "evidence_window_id": self.evidence_window_id,
            "status": self.status.value,
            "applied_parameters": dict(self.applied_parameters),
            "approval_id": self.approval_id,
            "is_rollback": self.is_rollback,
            "error_message": self.error_message,
            "executed_at": self.executed_at.isoformat(),
            "provenance_hash": self.provenance_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionRecord:
        return cls(
            execution_id=str(data["execution_id"]),
            action_id=str(data["action_id"]),
            authority_decision_id=str(data["authority_decision_id"]),
            evidence_window_id=str(data["evidence_window_id"]),
            status=ExecutionStatus(data["status"]),
            applied_parameters=dict(data.get("applied_parameters", {})),
            approval_id=data.get("approval_id"),
            is_rollback=bool(data.get("is_rollback", False)),
            error_message=data.get("error_message"),
            executed_at=datetime.fromisoformat(data["executed_at"]) if "executed_at" in data else datetime.now(),
            provenance_hash=str(data.get("provenance_hash", "")),
        )
