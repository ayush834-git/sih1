"""Human Approval Gate Subsystem (SIH 26153 Phase 3C).

Provides:
- Strict human-gated authorization boundary between predictive recommendation and existing response execution.
- Deterministic time-bounded expiration with injectable clock provider.
- Strict provenance binding (exact ApprovalRequest.provenance_hash matching).
- Clear separation between human rejection (HUMAN_REJECTED) and executor refusal (EXECUTION_REJECTED).
- In-memory process-scoped at-most-once execution guard (documented restart limitation).
- Direct handoff to EXISTING ResponseExecutor and DemoResponseAdapter.

CORE SAFETY PRINCIPLE:
PREDICT -> SIMULATE -> SELECT MINIMUM SUFFICIENT ACTION -> HUMAN APPROVAL -> EXISTING RESPONSE EXECUTION
ZERO automated response execution is permitted.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.contracts import new_id
from core.response_execution.executor import ResponseExecutor
from core.response_execution.models import (
    HumanApproval,
    ReversibleActionType,
    ResponseAction,
    RollbackPolicy,
    ExecutionStatus,
)
from core.topology.graph import ServiceTopologyGraph
from simulation.approval_models import (
    ApprovalConfig,
    ApprovalDecision,
    ApprovalRequest,
    ExecutionGateStatus,
    ExecutionOutcome,
)
from simulation.decision_models import DecisionResult, RecommendationStatus
from simulation.models import InterventionType

# Safe mapping from simulation InterventionType to existing ReversibleActionType
INTERVENTION_TO_ACTION_TYPE: Mapping[InterventionType, tuple[ReversibleActionType, str, dict[str, Any]]] = {
    InterventionType.RATE_LIMIT_IP: (
        ReversibleActionType.TEMP_RATE_LIMIT,
        "REMOVE_TEMP_RATE_LIMIT",
        {"rate_limit_bps": 5000.0, "duration_s": 30.0},
    ),
    InterventionType.TEMPORARY_BLOCK_IP: (
        ReversibleActionType.DEMO_BLOCK,
        "UNBLOCK",
        {"duration_s": 30.0},
    ),
    InterventionType.ISOLATE_SERVICE_ENDPOINT: (
        ReversibleActionType.DEMO_DISABLE_ENDPOINT,
        "ENABLE_ENDPOINT",
        {"duration_s": 30.0},
    ),
}


class HumanApprovalGate:
    """
    Human Approval and Execution Boundary Gate.
    Strictly gates predictive recommendations behind explicit human approval and existing authority policy.
    """

    def __init__(
        self,
        config: ApprovalConfig | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config or ApprovalConfig()
        self._clock: Callable[[], datetime] = clock or datetime.now
        # In-memory execution set: guarantees at-most-once execution within the active process scope.
        # LIMITATION: In-memory only; does not survive process restart without an external durable store.
        self._executed_request_ids: set[str] = set()

    def create_request(
        self,
        decision_result: DecisionResult,
        target_entity: str,
        ttl_seconds: float | None = None,
        evidence_window_id: str | None = None,
        rationale: str | None = None,
    ) -> ApprovalRequest:
        """
        Create an immutable ApprovalRequest from a Phase 3B DecisionResult.
        """
        req_id = new_id("appr-req")
        rec_act = decision_result.recommended_action
        ttl = ttl_seconds if ttl_seconds is not None else self.config.default_ttl_seconds
        created_at = self._clock()
        expires_at = created_at + timedelta(seconds=ttl)
        window_id = evidence_window_id or "win-000"

        # Construct structured summaries
        risk_summary = {
            "target_risk_threshold": decision_result.target_risk,
            "peak_risk_ceiling": decision_result.peak_risk_ceiling,
            "selected_risk": decision_result.selected_risk,
            "selected_peak_risk": decision_result.selected_peak_risk,
            "recommendation_status": decision_result.recommendation_status.value,
        }

        disruption_summary: dict[str, Any] = {
            "selected_disruption": decision_result.selected_disruption,
        }
        if rec_act and rec_act.value in decision_result.action_evaluations:
            eval_record = decision_result.action_evaluations[rec_act.value]
            disruption_summary["breakdown"] = dict(eval_record.disruption_breakdown)
            disruption_summary["blast_radius_impact"] = eval_record.blast_radius_impact

        if rationale is None:
            if decision_result.recommendation_status == RecommendationStatus.RECOMMENDED and rec_act:
                rationale = (
                    f"Recommended action: {rec_act.value}. "
                    f"Reason: minimum sufficient intervention with lowest operational disruption "
                    f"({decision_result.selected_disruption:.4f}) satisfying future-risk constraints "
                    f"(predicted risk={decision_result.selected_risk:.4f} <= {decision_result.target_risk:.4f}, "
                    f"peak risk={decision_result.selected_peak_risk:.4f} <= {decision_result.peak_risk_ceiling:.4f})."
                )
            else:
                rationale = (
                    f"No actionable recommendation: "
                    f"{decision_result.unresolved_reason or decision_result.recommendation_status.value}"
                )

        return ApprovalRequest(
            request_id=req_id,
            decision_result=decision_result,
            recommended_action=rec_act,
            target_entity=target_entity,
            rationale=rationale,
            risk_summary=risk_summary,
            disruption_summary=disruption_summary,
            assumptions=decision_result.assumptions,
            warnings=decision_result.warnings,
            approval_required=True,
            expires_at=expires_at,
            created_at=created_at,
            evidence_window_id=window_id,
        )

    def authorize_and_execute(
        self,
        request: ApprovalRequest,
        decision: ApprovalDecision | None,
        authority_decision: AuthorityDecision,
        executor: ResponseExecutor,
        topology: ServiceTopologyGraph | None = None,
        current_window_id: str | None = None,
        now: datetime | None = None,
    ) -> ExecutionOutcome:
        """
        Evaluate approval, authority, expiration, and provenance, and if all conditions are met,
        dispatch execution through the EXISTING ResponseExecutor.

        Fails closed on any defect or unapproved state.
        """
        exec_now = now or self._clock()

        # 1. Recommendation Validity Check
        if (
            request.decision_result.recommendation_status != RecommendationStatus.RECOMMENDED
            or request.recommended_action is None
            or request.recommended_action not in INTERVENTION_TO_ACTION_TYPE
        ):
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.UNSUPPORTED,
                authority_status="NOT_EVALUATED",
                execution_status=None,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=(
                    f"Decision status '{request.decision_result.recommendation_status.value}' "
                    f"or candidate action '{request.recommended_action}' cannot authorize operational execution."
                ),
            )

        # 2. Mandatory Human Approval Presence Check
        if decision is None:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.NOT_APPROVED,
                authority_status="NOT_EVALUATED",
                execution_status=None,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message="Mandatory human approval decision was not provided. Zero execution permitted.",
            )

        # 3. Strict Provenance Binding & Request Matching
        if decision.request_id != request.request_id:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.PROVENANCE_MISMATCH,
                authority_status="NOT_EVALUATED",
                execution_status=None,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=f"Approval request_id mismatch: '{decision.request_id}' != '{request.request_id}'.",
            )

        # CRITICAL REFINEMENT: Decision hash must strictly match ApprovalRequest.provenance_hash.
        # DecisionResult.provenance_hash alone is not permitted to authorize execution.
        if decision.provenance_hash != request.provenance_hash:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.PROVENANCE_MISMATCH,
                authority_status="NOT_EVALUATED",
                execution_status=None,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=(
                    f"Approval provenance_hash mismatch: decision hash '{decision.provenance_hash}' "
                    f"does not match exact ApprovalRequest provenance '{request.provenance_hash}'."
                ),
            )

        # 4. Expiration Checks (both Decision-Time and Execution-Time)
        if decision.decided_at > request.expires_at:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.EXPIRED,
                authority_status="NOT_EVALUATED",
                execution_status=None,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=(
                    f"Approval decision timestamp {decision.decided_at.isoformat()} "
                    f"exceeds request expiration {request.expires_at.isoformat()}."
                ),
            )

        if exec_now > request.expires_at:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.EXPIRED,
                authority_status="NOT_EVALUATED",
                execution_status=None,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=(
                    f"Execution invocation timestamp {exec_now.isoformat()} "
                    f"exceeds request expiration {request.expires_at.isoformat()}."
                ),
            )

        # 5. Explicit Human Rejection Check
        if not decision.approved:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.HUMAN_REJECTED,
                authority_status="NOT_EVALUATED",
                execution_status=ExecutionStatus.REJECTED,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=(
                    f"Human reviewer '{decision.reviewer_reference}' explicitly rejected execution: "
                    f"{decision.reason}"
                ),
            )

        # 6. Existing Authority Policy Check
        if (
            authority_decision.authority_level == AuthorityLevel.BLOCKED
            or ActionClass.EXECUTE_REVERSIBLE_ACTION not in authority_decision.permitted_action_classes
        ):
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.AUTHORITY_DENIED,
                authority_status="DENIED",
                execution_status=ExecutionStatus.BLOCKED,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message="Authority policy denied EXECUTE_REVERSIBLE_ACTION.",
            )

        # 7. Process-Scoped At-Most-Once Guard (Idempotency)
        if request.request_id in self._executed_request_ids:
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.ALREADY_EXECUTED,
                authority_status="PERMITTED",
                execution_status=ExecutionStatus.EXECUTED,
                response_identifier=None,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                error_message=(
                    f"Request '{request.request_id}' has already been executed in this process scope. "
                    "Repeated execution prohibited."
                ),
            )

        # 8. Dispatch Execution to Existing Response Executor
        action_mapping = INTERVENTION_TO_ACTION_TYPE[request.recommended_action]
        reversible_type, comp_action, default_params = action_mapping

        action_id = new_id("act")
        human_approval = HumanApproval(
            approval_id=new_id("appr"),
            action_id=action_id,
            authority_decision_id=authority_decision.decision_id,
            evidence_window_id=request.evidence_window_id,
            approved=True,
            approver_reference=decision.reviewer_reference,
            approval_reason=decision.reason,
            created_at=decision.decided_at,
        )

        topo_snap_id = getattr(topology, "snapshot_id", None) if topology else None
        response_action = ResponseAction(
            action_id=action_id,
            action_class=ActionClass.EXECUTE_REVERSIBLE_ACTION,
            target_node_id=request.target_entity,
            action_type=reversible_type,
            requested_parameters=dict(default_params),
            expected_effect=f"Mitigate risk via {request.recommended_action.value}",
            reversibility=True,
            compensating_action_type=comp_action,
            authority_decision_id=authority_decision.decision_id,
            evidence_window_id=request.evidence_window_id,
            recommendation_id=request.request_id,
            topology_snapshot_id=topo_snap_id,
            rollback_policy=RollbackPolicy.AUTOMATIC_COMPENSATING,
        )

        record, msg = executor.execute(
            action=response_action,
            authority_decision=authority_decision,
            approval=human_approval,
            current_topology=topology,
            current_window_id=current_window_id,
        )

        if record.status == ExecutionStatus.EXECUTED:
            self._executed_request_ids.add(request.request_id)
            return ExecutionOutcome(
                request_id=request.request_id,
                action=request.recommended_action,
                target=request.target_entity,
                approval_status=ExecutionGateStatus.EXECUTED,
                authority_status="PERMITTED",
                execution_status=ExecutionStatus.EXECUTED,
                response_identifier=record.execution_id,
                timestamp=exec_now,
                provenance_hash=request.provenance_hash,
                warnings=request.warnings,
                execution_record=record,
            )

        # Adapter or executor refused / failed execution
        return ExecutionOutcome(
            request_id=request.request_id,
            action=request.recommended_action,
            target=request.target_entity,
            approval_status=ExecutionGateStatus.EXECUTION_REJECTED,
            authority_status="PERMITTED",
            execution_status=record.status,
            response_identifier=record.execution_id,
            timestamp=exec_now,
            provenance_hash=request.provenance_hash,
            warnings=request.warnings,
            error_message=record.error_message or msg,
            execution_record=record,
        )
