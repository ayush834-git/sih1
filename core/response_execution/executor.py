"""Response Executor Engine (SIH 26153 Task 21).

Enforces:
- Strict separation: RECOMMENDATION != AUTHORIZATION != APPROVAL != EXECUTION != VERIFICATION
- Permanent blocking of destructive actions
- Authority decision compliance
- Exact binding: action_id + authority_decision_id + evidence_window_id
- Deterministic, auditable stale-authorization detection (no arbitrary drift thresholds)
- Idempotency
- First-class controlled rollback governance

CRITICAL INVARIANT:
High risk, high trust, high authority, or P0 priority CAN NEVER bypass human approval.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.contracts import new_id
from core.response_execution.adapters import DemoResponseAdapter, ResponseAdapter
from core.response_execution.models import (
    ExecutionRecord,
    ExecutionStatus,
    HumanApproval,
    ResponseAction,
    RollbackPolicy,
)
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability


class ResponseExecutor:
    """
    Safe execution coordinator evaluating authority decisions, human approvals,
    stale evidence bindings, and invoking reversible response adapters.
    """

    def __init__(self, adapter: ResponseAdapter | None = None) -> None:
        self.adapter = adapter if adapter is not None else DemoResponseAdapter()
        self._execution_history: dict[str, ExecutionRecord] = {}  # execution_id -> ExecutionRecord
        self._action_executions: dict[str, str] = {}              # action_id -> execution_id

    def get_execution_history(self) -> Sequence[ExecutionRecord]:
        return list(self._execution_history.values())

    def get_execution_for_action(self, action_id: str) -> ExecutionRecord | None:
        exec_id = self._action_executions.get(action_id)
        if exec_id:
            return self._execution_history.get(exec_id)
        return None

    def execute(
        self,
        action: ResponseAction,
        authority_decision: AuthorityDecision,
        approval: HumanApproval | None = None,
        current_topology: ServiceTopologyGraph | None = None,
        current_window_id: str | None = None,
    ) -> tuple[ExecutionRecord, str]:
        """
        Execute an authorized and approved ResponseAction through the safe adapter.
        Fails closed on any violation of conservative policy invariants.
        """
        exec_id = new_id("exec")

        # 1. Invariant: Destructive actions are PERMANENTLY BLOCKED
        if action.action_class == ActionClass.EXECUTE_DESTRUCTIVE_ACTION:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.BLOCKED,
                applied_parameters={},
                error_message="EXECUTE_DESTRUCTIVE_ACTION is permanently prohibited",
            )
            self._execution_history[exec_id] = record
            return record, "Blocked: Destructive actions are permanently prohibited"

        # 2. Invariant: Authority decision must not be BLOCKED
        if authority_decision.authority_level == AuthorityLevel.BLOCKED:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.BLOCKED,
                applied_parameters={},
                error_message="Authority decision is BLOCKED",
            )
            self._execution_history[exec_id] = record
            return record, "Blocked: Authority decision is BLOCKED"

        # 3. Invariant: Action class must be explicitly permitted by authority decision
        if action.action_class not in authority_decision.permitted_action_classes:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.BLOCKED,
                applied_parameters={},
                error_message=f"Action class '{action.action_class.value}' is not permitted by authority decision",
            )
            self._execution_history[exec_id] = record
            return record, f"Blocked: Action class '{action.action_class.value}' not permitted"

        # 4. Invariant: Deterministic Stale-Authorization Revalidation
        # If current telemetry window has advanced since authorization was granted, fail closed
        if current_window_id is not None and current_window_id != action.evidence_window_id:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.BLOCKED,
                applied_parameters={},
                approval_id=approval.approval_id if approval else None,
                error_message=(
                    f"STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE: Action evidence window "
                    f"'{action.evidence_window_id}' is superseded by current window '{current_window_id}'"
                ),
            )
            self._execution_history[exec_id] = record
            return record, "Blocked: Stale authorization superseded by new evidence"

        # 5. Invariant: Exact Authority Decision Binding
        if action.authority_decision_id != authority_decision.decision_id:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.BLOCKED,
                applied_parameters={},
                approval_id=approval.approval_id if approval else None,
                error_message=(
                    f"Action binding mismatch: action references authority decision '{action.authority_decision_id}' "
                    f"but evaluated decision is '{authority_decision.decision_id}'"
                ),
            )
            self._execution_history[exec_id] = record
            return record, "Blocked: Action authority_decision_id mismatch"

        # 6. Invariant: Human Approval Enforcement
        if authority_decision.human_approval_required:
            if approval is None:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    error_message="Mandatory human approval record was not provided",
                )
                self._execution_history[exec_id] = record
                return record, "Blocked: Human approval required but missing"

            if not approval.approved:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.REJECTED,
                    applied_parameters={},
                    approval_id=approval.approval_id,
                    error_message=f"Action explicitly rejected by approver '{approval.approver_reference}'",
                )
                self._execution_history[exec_id] = record
                return record, f"Rejected: Operator '{approval.approver_reference}' rejected action"

            if approval.action_id != action.action_id:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    approval_id=approval.approval_id,
                    error_message=f"Approval action_id mismatch: '{approval.action_id}' != '{action.action_id}'",
                )
                self._execution_history[exec_id] = record
                return record, "Blocked: Approval action_id mismatch"

            if approval.authority_decision_id != authority_decision.decision_id:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    approval_id=approval.approval_id,
                    error_message="Approval authority_decision_id mismatch",
                )
                self._execution_history[exec_id] = record
                return record, "Blocked: Approval authority_decision_id mismatch"

            if approval.evidence_window_id != action.evidence_window_id:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    approval_id=approval.approval_id,
                    error_message="Approval evidence_window_id mismatch",
                )
                self._execution_history[exec_id] = record
                return record, "Blocked: Approval evidence_window_id mismatch"

        # Topology Revalidation
        if current_topology is not None:
            avail = getattr(current_topology, "availability", TopologyAvailability.KNOWN)
            if avail == TopologyAvailability.UNAVAILABLE:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    approval_id=approval.approval_id if approval else None,
                    error_message="STALE_AUTHORIZATION_TOPOLOGY_UNAVAILABLE: Topology has become UNAVAILABLE",
                )
                self._execution_history[exec_id] = record
                return record, "Blocked: Topology is UNAVAILABLE"

            topo_snap_id = getattr(current_topology, "snapshot_id", None)
            if action.topology_snapshot_id is not None and topo_snap_id is not None:
                if topo_snap_id != action.topology_snapshot_id:
                    record = ExecutionRecord(
                        execution_id=exec_id,
                        action_id=action.action_id,
                        authority_decision_id=authority_decision.decision_id,
                        evidence_window_id=action.evidence_window_id,
                        status=ExecutionStatus.BLOCKED,
                        applied_parameters={},
                        approval_id=approval.approval_id if approval else None,
                        error_message="STALE_AUTHORIZATION_TOPOLOGY_SNAPSHOT_MISMATCH: Topology snapshot changed",
                    )
                    self._execution_history[exec_id] = record
                    return record, "Blocked: Topology snapshot mismatch"

            has_node = True
            if hasattr(current_topology, "has_node"):
                has_node = current_topology.has_node(action.target_node_id)
            elif hasattr(current_topology, "nodes"):
                has_node = any(n.node_id == action.target_node_id for n in getattr(current_topology, "nodes", ()))

            if (
                action.target_node_id
                and action.target_node_id not in ("Baseline telemetry stream", "unknown-root")
                and not has_node
            ):
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    approval_id=approval.approval_id if approval else None,
                    error_message=f"Target node '{action.target_node_id}' does not exist in active topology",
                )
                self._execution_history[exec_id] = record
                return record, f"Blocked: Target node '{action.target_node_id}' not in topology"

        # 7. Invariant: Idempotency
        prior_exec_id = self._action_executions.get(action.action_id)
        if prior_exec_id:
            prior_record = self._execution_history[prior_exec_id]
            if prior_record.status in (ExecutionStatus.EXECUTED, ExecutionStatus.VERIFICATION_PENDING, ExecutionStatus.VERIFIED_SUCCESS):
                return prior_record, f"Idempotent: Action '{action.action_id}' already executed"

        # 8. Adapter Reversible Execution
        success, applied_params, msg = self.adapter.execute(action)
        if not success:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.FAILED,
                applied_parameters=applied_params,
                approval_id=approval.approval_id if approval else None,
                error_message=msg,
            )
            self._execution_history[exec_id] = record
            self._action_executions[action.action_id] = exec_id
            return record, f"Execution failed: {msg}"

        record = ExecutionRecord(
            execution_id=exec_id,
            action_id=action.action_id,
            authority_decision_id=authority_decision.decision_id,
            evidence_window_id=action.evidence_window_id,
            status=ExecutionStatus.EXECUTED,
            applied_parameters=applied_params,
            approval_id=approval.approval_id if approval else None,
        )
        self._execution_history[exec_id] = record
        self._action_executions[action.action_id] = exec_id
        return record, f"Executed: {msg}"

    def rollback(
        self,
        action: ResponseAction,
        authority_decision: AuthorityDecision,
        approval: HumanApproval | None = None,
        reason: str = "",
    ) -> tuple[ExecutionRecord, str]:
        """
        Execute a controlled compensating rollback operation.
        Rollback is a first-class controlled action, never an implicit privileged bypass.
        """
        exec_id = new_id("exec-roll")

        # 1. Action Reversibility Guard
        if not action.reversibility or not action.compensating_action_type:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.FAILED,
                applied_parameters={},
                is_rollback=True,
                error_message="Action has no defined compensating rollback operation",
            )
            self._execution_history[exec_id] = record
            return record, "Rollback failed: Action is not reversible"

        # 2. Task 20 Authority Gate Compliance
        # Rollback cannot bypass authority: if current authority is BLOCKED, rollback cannot execute
        if authority_decision.authority_level == AuthorityLevel.BLOCKED:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.BLOCKED,
                applied_parameters={},
                is_rollback=True,
                error_message="ROLLBACK_BLOCKED_BY_AUTHORITY: Authority decision is BLOCKED",
            )
            self._execution_history[exec_id] = record
            return record, "Rollback blocked: Current authority is BLOCKED"

        # 3. Rollback Policy Enforcement
        if action.rollback_policy == RollbackPolicy.REQUIRE_HUMAN_APPROVAL:
            if approval is None or not approval.approved or approval.action_id != action.action_id:
                record = ExecutionRecord(
                    execution_id=exec_id,
                    action_id=action.action_id,
                    authority_decision_id=authority_decision.decision_id,
                    evidence_window_id=action.evidence_window_id,
                    status=ExecutionStatus.BLOCKED,
                    applied_parameters={},
                    is_rollback=True,
                    error_message="Rollback policy requires explicit human approval, none provided",
                )
                self._execution_history[exec_id] = record
                return record, "Rollback blocked: Human approval required for rollback"

        # 4. Invoke Adapter Compensating Operation
        success, applied_params, msg = self.adapter.rollback(action)
        if not success:
            record = ExecutionRecord(
                execution_id=exec_id,
                action_id=action.action_id,
                authority_decision_id=authority_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                status=ExecutionStatus.FAILED,
                applied_parameters=applied_params,
                approval_id=approval.approval_id if approval else None,
                is_rollback=True,
                error_message=msg,
            )
            self._execution_history[exec_id] = record
            return record, f"Rollback failed: {msg}"

        record = ExecutionRecord(
            execution_id=exec_id,
            action_id=action.action_id,
            authority_decision_id=authority_decision.decision_id,
            evidence_window_id=action.evidence_window_id,
            status=ExecutionStatus.ROLLED_BACK,
            applied_parameters=applied_params,
            approval_id=approval.approval_id if approval else None,
            is_rollback=True,
        )
        self._execution_history[exec_id] = record
        return record, f"Rolled back: {msg}"
