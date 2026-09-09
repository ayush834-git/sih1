"""Unit and Safety Integration Tests for Phase 3C: Human Approval & Existing Response Execution Boundary.

Verifies:
1. TEST 1 — APPROVAL REQUIRED: No approval -> Zero execution (NOT_APPROVED).
2. TEST 2 — APPROVED RECOMMENDATION EXECUTES: Valid recommendation + approval + authority -> Exactly once via existing executor.
3. TEST 3 — EXPLICIT HUMAN REJECTION: Operator rejects -> Zero execution (HUMAN_REJECTED).
4. TEST 4 — EXPIRED APPROVAL (Execution-time check with injectable clock):
   - 4a: Approval before expiry + execution before expiry -> Allowed.
   - 4b: Approval before expiry + execution after expiry -> EXPIRED.
   - 4c: Approval after expiry -> EXPIRED.
5. TEST 5 — PROVENANCE MISMATCH & STRICT PROVENANCE BINDING:
   - 5a: Approval for A attempted on B -> PROVENANCE_MISMATCH.
   - 5b: Decision carrying only DecisionResult hash -> Rejected as PROVENANCE_MISMATCH.
6. TEST 6 — AUTHORITY DENIAL: Authority policy blocks or omits action -> Zero execution (AUTHORITY_DENIED).
7. TEST 7 — UNSUPPORTED RECOMMENDATION: Status UNSUPPORTED -> Zero execution (UNSUPPORTED).
8. TEST 8 — NO-SUFFICIENT-ACTION: Status NO_SUFFICIENT_ACTION -> Zero execution (UNSUPPORTED).
9. TEST 9 — UNRESOLVED DECISION: Status UNRESOLVED -> Zero execution (UNSUPPORTED).
10. TEST 10 — IN-MEMORY AT-MOST-ONCE EXECUTION (Process Scoped):
    - Repeated attempts with same request return ALREADY_EXECUTED without re-invoking adapter.
    - Demonstrates process-scoped restart limitation.
11. TEST 11 — EXISTING EXECUTOR CONTRACT: Uses ResponseExecutor abstraction; auditable history recorded.
12. TEST 12 — PHASE 3B INTEGRITY: DecisionResult, ActionEvaluation, simulation, and topology remain unmutated.
13. TEST 13 — APPROVAL EXPIRY CONFIGURATION: TTL is configurable and changes validity dynamically.
14. TEST 14 — STALE RECOMMENDATION: Newer decision cannot be authorized by older approval.
15. USER REQUIREMENT 4 — SEPARATION OF HUMAN_REJECTED vs EXECUTION_REJECTED:
    - Distinguishes human rejection from adapter failure / executor blocking.
16. USER REQUIREMENT 5 — EXECUTION BOUNDARY & ZERO PRODUCTION IMPACT:
    - Pure in-memory DemoResponseAdapter; zero OS/firewall modifications.
17. SAFETY TEST: End-to-end integration: forecast -> simulation -> selection -> NO APPROVAL -> ZERO EXECUTION.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta
import unittest

from pathlib import Path
import numpy as np

from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.contracts import (
    FeatureAvailability,
    NetworkState,
    Source,
    TrustAssessment,
    TrustLevel,
    new_id,
)
from core.response_execution.adapters import DemoResponseAdapter
from core.response_execution.executor import ResponseExecutor
from core.response_execution.models import ExecutionStatus
from core.topology.builder import build_minimal_demo_topology
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.rollout import MultiStepRolloutEngine
from runtime.train_authoritative_model import load_ar_model
from security.bridge import BehavioralSecurityBridge
from security.risk_engine import SecurityRiskEngine
from simulation.approval_gate import HumanApprovalGate
from simulation.approval_models import (
    ApprovalConfig,
    ApprovalDecision,
    ApprovalRequest,
    ExecutionGateStatus,
    ExecutionOutcome,
)
from simulation.decision_models import (
    ActionEvaluation,
    DecisionResult,
    RecommendationStatus,
    RiskConstraintParameters,
)
from simulation.disruption import DisruptionEstimator
from simulation.engine import InterventionSimulator
from simulation.models import (
    AssumptionClassification,
    AssumptionRecord,
    InterventionParameters,
    InterventionStatus,
    InterventionType,
)
from simulation.selector import MinimumSufficientSelector

ROOT_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT_DIR / "artifacts" / "models" / "ar5_authoritative"
from simulation.decision_models import (
    ActionEvaluation,
    DecisionResult,
    RecommendationStatus,
    RiskConstraintParameters,
)
from simulation.models import (
    AssumptionClassification,
    AssumptionRecord,
    InterventionStatus,
    InterventionType,
)
from simulation.selector import MinimumSufficientSelector


class TestPhase3CApprovalGate(unittest.TestCase):
    """Test suite for Phase 3C Human Approval and Response Execution Boundary."""

    def setUp(self) -> None:
        self.topology = build_minimal_demo_topology()
        self.adapter = DemoResponseAdapter()
        self.executor = ResponseExecutor(adapter=self.adapter)
        self.base_time = datetime(2026, 9, 8, 12, 0, 0)
        self.current_time = self.base_time

        def mock_clock() -> datetime:
            return self.current_time

        self.clock = mock_clock
        self.gate = HumanApprovalGate(config=ApprovalConfig(default_ttl_seconds=60.0), clock=self.clock)

    def _make_dummy_decision_result(
        self,
        status: RecommendationStatus = RecommendationStatus.RECOMMENDED,
        action: InterventionType | None = InterventionType.RATE_LIMIT_IP,
        risk: float = 0.25,
        peak_risk: float = 0.40,
        disruption: float = 0.35,
    ) -> DecisionResult:
        evals = {}
        if action is not None:
            evals[action.value] = ActionEvaluation(
                action=action,
                simulation_status=InterventionStatus.APPLIED,
                aggregate_risk=risk,
                peak_risk=peak_risk,
                risk_target_satisfied=True,
                peak_ceiling_satisfied=True,
                is_sufficient=True,
                disruption_estimate=disruption,
                disruption_breakdown={"direct_cost": 0.2, "cascade_cost": 0.15},
                assumptions=(
                    AssumptionRecord(
                        parameter_name="rate_limit_factor",
                        parameter_value=0.25,
                        classification=AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
                        description="Test assumption",
                        features_affected=("byte_rate",),
                    ),
                ),
                warnings=("Test warning",),
            )

        prov_hash = f"test-prov-{status.value}-{action.value if action else 'none'}"
        return DecisionResult(
            recommended_action=action,
            recommendation_status=status,
            sufficient_candidates=(action,) if action else (),
            rejected_candidates=(),
            action_evaluations=evals,
            selected_risk=risk if action else None,
            selected_peak_risk=peak_risk if action else None,
            selected_disruption=disruption if action else None,
            lowest_risk_candidate=action,
            target_risk=0.40,
            peak_risk_ceiling=0.60,
            unresolved_reason="Reason" if status != RecommendationStatus.RECOMMENDED else None,
            provenance_hash=prov_hash,
        )

    def _make_authority_decision(
        self,
        permitted: bool = True,
        authority_level: AuthorityLevel = AuthorityLevel.HUMAN_APPROVAL_REQUIRED,
    ) -> AuthorityDecision:
        permitted_classes = [
            ActionClass.OBSERVE_ONLY,
            ActionClass.ALERT_OPERATOR,
            ActionClass.GENERATE_RECOMMENDATION,
        ]
        if permitted:
            permitted_classes.extend([
                ActionClass.PREPARE_REVERSIBLE_ACTION,
                ActionClass.EXECUTE_REVERSIBLE_ACTION,
            ])
        blocked_classes = [ActionClass.EXECUTE_DESTRUCTIVE_ACTION]
        if not permitted:
            blocked_classes.append(ActionClass.EXECUTE_REVERSIBLE_ACTION)

        return AuthorityDecision(
            decision_id=new_id("auth-dec"),
            authority_level=authority_level if permitted else AuthorityLevel.BLOCKED,
            permitted_action_classes=tuple(permitted_classes),
            blocked_action_classes=tuple(blocked_classes),
            human_approval_required=True,
            policy_version="authority-v1",
            reason_codes=("STRONG_EVIDENCE_PERMITS_HUMAN_GATED_EXECUTION",) if permitted else ("BLOCKED_BY_POLICY",),
            explanation="Test authority decision",
        )

    # -------------------------------------------------------------------------
    # TEST 1 — APPROVAL REQUIRED
    # -------------------------------------------------------------------------
    def test_1_approval_required(self) -> None:
        """Given a valid RECOMMENDED decision: attempt execution without approval -> zero execution."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=None,  # NO APPROVAL
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.NOT_APPROVED)
        self.assertIsNone(outcome.execution_status)
        self.assertEqual(len(self.executor.get_execution_history()), 0)
        self.assertEqual(len(self.adapter.get_active_actions()), 0)

    # -------------------------------------------------------------------------
    # TEST 2 — APPROVED RECOMMENDATION EXECUTES
    # -------------------------------------------------------------------------
    def test_2_approved_recommendation_executes(self) -> None:
        """Given valid recommendation, valid approval, and valid authority -> executes via existing executor."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Verified minimum sufficient intervention",
            reviewer_reference="operator-001",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.EXECUTED)
        self.assertEqual(outcome.execution_status, ExecutionStatus.EXECUTED)
        self.assertIsNotNone(outcome.response_identifier)
        self.assertEqual(len(self.executor.get_execution_history()), 1)
        self.assertEqual(len(self.adapter.get_active_actions()), 1)
        self.assertIn("svc-api", self.adapter._rate_limits)

    # -------------------------------------------------------------------------
    # TEST 3 — EXPLICIT REJECTION
    # -------------------------------------------------------------------------
    def test_3_explicit_rejection(self) -> None:
        """Human explicitly rejects recommendation -> zero execution (HUMAN_REJECTED)."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=False,  # EXPLICIT REJECTION
            reason="Operationally inconvenient maintenance window",
            reviewer_reference="operator-001",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.HUMAN_REJECTED)
        self.assertEqual(outcome.execution_status, ExecutionStatus.REJECTED)
        self.assertEqual(len(self.executor.get_execution_history()), 0)
        self.assertEqual(len(self.adapter.get_active_actions()), 0)

    # -------------------------------------------------------------------------
    # TEST 4 — EXPIRED APPROVAL (Checked at Execution Time with Injectable Clock)
    # -------------------------------------------------------------------------
    def test_4a_approval_and_execution_before_expiry(self) -> None:
        """Approval before expiry + execution before expiry -> Allowed."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api", ttl_seconds=60.0)
        auth = self._make_authority_decision(permitted=True)

        # Decide at t + 10s (before expiry t + 60s)
        decide_time = self.base_time + timedelta(seconds=10)
        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Approved in time",
            decided_at=decide_time,
            provenance_hash=req.provenance_hash,
        )

        # Execute at t + 20s (before expiry)
        exec_time = self.base_time + timedelta(seconds=20)
        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
            now=exec_time,
        )
        self.assertEqual(outcome.approval_status, ExecutionGateStatus.EXECUTED)

    def test_4b_approval_before_expiry_execution_after_expiry(self) -> None:
        """Approval before expiry + execution called AFTER expiry -> EXPIRED (Zero execution)."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api", ttl_seconds=60.0)
        auth = self._make_authority_decision(permitted=True)

        # Approved at t + 10s (valid at decision time)
        decide_time = self.base_time + timedelta(seconds=10)
        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Approved in time",
            decided_at=decide_time,
            provenance_hash=req.provenance_hash,
        )

        # Executed at t + 70s (EXPIRED at execution time)
        exec_time = self.base_time + timedelta(seconds=70)
        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
            now=exec_time,
        )
        self.assertEqual(outcome.approval_status, ExecutionGateStatus.EXPIRED)
        self.assertIn("Execution invocation timestamp", outcome.error_message or "")
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    def test_4c_approval_after_expiry(self) -> None:
        """Approval decided after expiry -> EXPIRED (Zero execution)."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api", ttl_seconds=60.0)
        auth = self._make_authority_decision(permitted=True)

        # Decided at t + 65s (already expired)
        decide_time = self.base_time + timedelta(seconds=65)
        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Late approval",
            decided_at=decide_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
            now=decide_time,
        )
        self.assertEqual(outcome.approval_status, ExecutionGateStatus.EXPIRED)
        self.assertIn("Approval decision timestamp", outcome.error_message or "")
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # TEST 5 — PROVENANCE MISMATCH & STRICT PROVENANCE BINDING
    # -------------------------------------------------------------------------
    def test_5a_provenance_mismatch_different_request(self) -> None:
        """Approve recommendation A but attempt to execute with approval for B -> PROVENANCE_MISMATCH."""
        dec_res_a = self._make_dummy_decision_result(action=InterventionType.RATE_LIMIT_IP)
        dec_res_b = self._make_dummy_decision_result(action=InterventionType.TEMPORARY_BLOCK_IP)

        req_a = self.gate.create_request(dec_res_a, target_entity="svc-api")
        req_b = self.gate.create_request(dec_res_b, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        # Decision approves req_b
        decision_for_b = ApprovalDecision(
            request_id=req_b.request_id,
            approved=True,
            reason="Approved B",
            decided_at=self.current_time,
            provenance_hash=req_b.provenance_hash,
        )

        # Attempt to authorize req_a using approval for req_b
        outcome = self.gate.authorize_and_execute(
            request=req_a,
            decision=decision_for_b,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.PROVENANCE_MISMATCH)
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    def test_5b_decision_result_hash_alone_rejected_as_mismatch(self) -> None:
        """USER REQUIREMENT 1: Decision carrying only DecisionResult.provenance_hash is rejected as PROVENANCE_MISMATCH."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        # Purposely use dec_res.provenance_hash instead of req.provenance_hash
        decision_with_dec_res_hash = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Carrying only decision result hash",
            decided_at=self.current_time,
            provenance_hash=dec_res.provenance_hash,  # NOT req.provenance_hash
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision_with_dec_res_hash,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.PROVENANCE_MISMATCH)
        self.assertIn("does not match exact ApprovalRequest provenance", outcome.error_message or "")
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # TEST 6 — AUTHORITY DENIAL
    # -------------------------------------------------------------------------
    def test_6_authority_denial(self) -> None:
        """Existing authority policy rejects action -> zero execution (AUTHORITY_DENIED)."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth_denied = self._make_authority_decision(permitted=False)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Operator approves",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth_denied,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.AUTHORITY_DENIED)
        self.assertEqual(outcome.authority_status, "DENIED")
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # TEST 7 — UNSUPPORTED RECOMMENDATION
    # -------------------------------------------------------------------------
    def test_7_unsupported_recommendation(self) -> None:
        """DecisionResult is UNSUPPORTED -> approval cannot authorize execution."""
        dec_res = self._make_dummy_decision_result(status=RecommendationStatus.UNSUPPORTED, action=None)
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Attempting to approve unsupported action",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.UNSUPPORTED)
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # TEST 8 — NO-SUFFICIENT-ACTION
    # -------------------------------------------------------------------------
    def test_8_no_sufficient_action(self) -> None:
        """DecisionResult is NO_SUFFICIENT_ACTION -> approval cannot execute anything."""
        dec_res = self._make_dummy_decision_result(status=RecommendationStatus.NO_SUFFICIENT_ACTION, action=None)
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Attempting to approve when no sufficient action exists",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.UNSUPPORTED)
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # TEST 9 — UNRESOLVED DECISION
    # -------------------------------------------------------------------------
    def test_9_unresolved_decision(self) -> None:
        """DecisionResult is UNRESOLVED -> zero execution."""
        dec_res = self._make_dummy_decision_result(status=RecommendationStatus.UNRESOLVED, action=None)
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Attempting to approve unresolved state",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.UNSUPPORTED)
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # TEST 10 — IN-MEMORY AT-MOST-ONCE EXECUTION (Process Scoped)
    # -------------------------------------------------------------------------
    def test_10_in_memory_at_most_once_execution(self) -> None:
        """USER REQUIREMENT 3: Repeated execution in same process scope returns ALREADY_EXECUTED without duplicate execution."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Approved",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        # First execution attempt
        outcome1 = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )
        self.assertEqual(outcome1.approval_status, ExecutionGateStatus.EXECUTED)
        self.assertEqual(len(self.executor.get_execution_history()), 1)

        # Second execution attempt using exact same approved request
        outcome2 = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )
        self.assertEqual(outcome2.approval_status, ExecutionGateStatus.ALREADY_EXECUTED)
        self.assertIn("already been executed in this process scope", outcome2.error_message or "")
        # Executor history must NOT have incremented
        self.assertEqual(len(self.executor.get_execution_history()), 1)

    def test_10b_restart_limitation_documented(self) -> None:
        """USER REQUIREMENT 3: Document that a new gate instance (simulating restart) resets in-memory at-most-once set."""
        new_gate = HumanApprovalGate(config=ApprovalConfig(default_ttl_seconds=60.0), clock=self.clock)
        # Empty in-memory tracking set
        self.assertEqual(len(new_gate._executed_request_ids), 0)

    # -------------------------------------------------------------------------
    # TEST 11 — EXISTING EXECUTOR CONTRACT
    # -------------------------------------------------------------------------
    def test_11_existing_executor_contract(self) -> None:
        """Verify execution uses existing ResponseExecutor and records audit history."""
        dec_res = self._make_dummy_decision_result()
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Contract audit test",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.EXECUTED)
        history = self.executor.get_execution_history()
        self.assertEqual(len(history), 1)
        record = history[0]
        self.assertEqual(record.status, ExecutionStatus.EXECUTED)
        self.assertEqual(record.execution_id, outcome.response_identifier)
        self.assertIsNotNone(record.approval_id)

    # -------------------------------------------------------------------------
    # TEST 12 — PHASE 3B INTEGRITY
    # -------------------------------------------------------------------------
    def test_12_phase3b_integrity(self) -> None:
        """Verify approval and execution do not mutate DecisionResult or other inputs."""
        dec_res = self._make_dummy_decision_result()
        orig_dict = copy.deepcopy(dec_res.to_dict())

        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Integrity test",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        # Check that DecisionResult was completely unmutated
        self.assertEqual(dec_res.to_dict(), orig_dict)

    # -------------------------------------------------------------------------
    # TEST 13 — APPROVAL EXPIRY CONFIGURATION
    # -------------------------------------------------------------------------
    def test_13_approval_expiry_configuration(self) -> None:
        """Changing configured expiry changes whether a request is considered valid."""
        dec_res = self._make_dummy_decision_result()

        # Gate with 10s TTL
        gate_10s = HumanApprovalGate(config=ApprovalConfig(default_ttl_seconds=10.0), clock=self.clock)
        req_10s = gate_10s.create_request(dec_res, target_entity="svc-api")

        # Gate with 300s TTL
        gate_300s = HumanApprovalGate(config=ApprovalConfig(default_ttl_seconds=300.0), clock=self.clock)
        req_300s = gate_300s.create_request(dec_res, target_entity="svc-api")

        self.assertEqual((req_10s.expires_at - req_10s.created_at).total_seconds(), 10.0)
        self.assertEqual((req_300s.expires_at - req_300s.created_at).total_seconds(), 300.0)

        # Check validity at t + 30s
        check_time = self.base_time + timedelta(seconds=30)
        self.assertTrue(req_10s.is_expired(check_time))
        self.assertFalse(req_300s.is_expired(check_time))

    # -------------------------------------------------------------------------
    # TEST 14 — STALE RECOMMENDATION
    # -------------------------------------------------------------------------
    def test_14_stale_recommendation(self) -> None:
        """Old approval cannot authorize newer recommendation for the same target."""
        dec_res_1 = self._make_dummy_decision_result(action=InterventionType.RATE_LIMIT_IP, risk=0.30)
        req_1 = self.gate.create_request(dec_res_1, target_entity="svc-api")

        approval_1 = ApprovalDecision(
            request_id=req_1.request_id,
            approved=True,
            reason="Approved decision 1",
            decided_at=self.current_time,
            provenance_hash=req_1.provenance_hash,
        )

        # Newer decision produced for the same target
        dec_res_2 = self._make_dummy_decision_result(action=InterventionType.TEMPORARY_BLOCK_IP, risk=0.15)
        req_2 = self.gate.create_request(dec_res_2, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        # Attempt to authorize req_2 with approval_1
        outcome = self.gate.authorize_and_execute(
            request=req_2,
            decision=approval_1,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.PROVENANCE_MISMATCH)
        self.assertEqual(len(self.executor.get_execution_history()), 0)

    # -------------------------------------------------------------------------
    # USER REQUIREMENT 4 — SEPARATION OF HUMAN_REJECTED vs EXECUTION_REJECTED
    # -------------------------------------------------------------------------
    def test_human_rejected_vs_execution_rejected(self) -> None:
        """USER REQUIREMENT 4: Distinct statuses for human rejection vs executor refusal."""
        dec_res = self._make_dummy_decision_result()
        auth = self._make_authority_decision(permitted=True)

        # Path A: Human rejects -> HUMAN_REJECTED
        req_a = self.gate.create_request(dec_res, target_entity="svc-api")
        human_reject = ApprovalDecision(
            request_id=req_a.request_id,
            approved=False,
            reason="Rejecting for operational reasons",
            decided_at=self.current_time,
            provenance_hash=req_a.provenance_hash,
        )
        outcome_a = self.gate.authorize_and_execute(
            request=req_a,
            decision=human_reject,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )
        self.assertEqual(outcome_a.approval_status, ExecutionGateStatus.HUMAN_REJECTED)

        # Path B: Human approves, but adapter simulates failure -> EXECUTION_REJECTED
        req_b = self.gate.create_request(dec_res, target_entity="svc-api")
        human_approve = ApprovalDecision(
            request_id=req_b.request_id,
            approved=True,
            reason="Operator approves",
            decided_at=self.current_time,
            provenance_hash=req_b.provenance_hash,
        )
        self.adapter.set_execution_failure_simulation(True)
        outcome_b = self.gate.authorize_and_execute(
            request=req_b,
            decision=human_approve,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )
        self.assertEqual(outcome_b.approval_status, ExecutionGateStatus.EXECUTION_REJECTED)
        self.assertEqual(outcome_b.execution_status, ExecutionStatus.FAILED)
        self.assertNotEqual(outcome_a.approval_status, outcome_b.approval_status)
        self.adapter.set_execution_failure_simulation(False)

    # -------------------------------------------------------------------------
    # USER REQUIREMENT 5 — EXECUTION BOUNDARY & ZERO PRODUCTION NETWORK IMPACT
    # -------------------------------------------------------------------------
    def test_execution_boundary_zero_production_impact(self) -> None:
        """USER REQUIREMENT 5: Execution is strictly mediated by DemoResponseAdapter with in-memory changes only."""
        dec_res = self._make_dummy_decision_result(action=InterventionType.TEMPORARY_BLOCK_IP)
        req = self.gate.create_request(dec_res, target_entity="svc-api")
        auth = self._make_authority_decision(permitted=True)

        decision = ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reason="Demo block approved",
            decided_at=self.current_time,
            provenance_hash=req.provenance_hash,
        )

        outcome = self.gate.authorize_and_execute(
            request=req,
            decision=decision,
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        self.assertEqual(outcome.approval_status, ExecutionGateStatus.EXECUTED)
        # Verify in-memory state of DemoResponseAdapter
        self.assertIn("svc-api", self.adapter._blocked_targets)
        # Verify adapter is an instance of DemoResponseAdapter
        self.assertIsInstance(self.executor.adapter, DemoResponseAdapter)

    # -------------------------------------------------------------------------
    # CRITICAL SAFETY TEST: FORECAST -> SIMULATE -> RECOMMEND -> NO APPROVAL -> ZERO EXECUTION
    # -------------------------------------------------------------------------
    def test_safety_invariant_pipeline(self) -> None:
        """
        CRITICAL SAFETY TEST:
        NetworkState -> Forecast -> Risk -> Simulation -> Selection -> NO APPROVAL -> ZERO EXECUTION.
        """
        # 1. Authoritative models
        ar_model, scales = load_ar_model(MODEL_DIR)
        rollout_engine = MultiStepRolloutEngine(ar_model, CSV_AVAILABLE_FEATURES)
        bridge = BehavioralSecurityBridge(scales=scales)
        risk_engine = SecurityRiskEngine()
        simulator = InterventionSimulator(
            bridge=bridge,
            risk_engine=risk_engine,
            rollout_engine=rollout_engine,
            scales=scales,
        )
        selector = MinimumSufficientSelector(
            simulator=simulator,
            disruption_estimator=DisruptionEstimator(),
        )

        # 2. Attack State
        t_start = datetime(2026, 9, 8, 12, 0, 0)
        t_end = t_start + timedelta(seconds=10.0)
        state = NetworkState(
            window_id="attack_w001",
            timestamp_start=t_start,
            timestamp_end=t_end,
            window_duration_s=10.0,
            flow_count=200,
            byte_rate=400000.0,
            packet_rate=2500.0,
            mean_flow_duration=8.0,
            src_ip_diversity=15,
            dst_ip_diversity=40,
            src_port_diversity=50,
            dst_port_diversity=45,
            fan_out=None,
            internal_ratio=0.10,
            east_west_count=10,
            syn_count=90,
            ack_count=100,
            rst_count=10,
            syn_ratio=0.45,
            rst_ratio=0.05,
            iat_mean=0.02,
            iat_std=0.01,
            iat_skew=0.0,
            pkt_size_mean=600.0,
            pkt_size_std=180.0,
            byte_variance=2000.0,
            ttl_mean=64.0,
            ttl_variance=1.0,
            tcp_window_mean=65535.0,
            fragment_count=0,
            retransmit_count=0,
            payload_size_mean=500.0,
            source=Source.CSV,
            data_quality=1.0,
            is_empty=False,
            gap_before=False,
            gap_after=False,
            session_id="session-attack",
            provenance_hash="c" * 64,
            feature_availability={"fan_out": FeatureAvailability.UNAVAILABLE},
        )

        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 20.0

        # 3. Minimum-Sufficient Selection
        decision_result = selector.select(
            current_state=state,
            candidate_actions=(InterventionType.RATE_LIMIT_IP, InterventionType.TEMPORARY_BLOCK_IP),
            baseline_deltas=deltas,
            topology=self.topology,
            risk_constraints=RiskConstraintParameters(target_risk=0.50, peak_risk_ceiling=0.70),
        )

        self.assertEqual(decision_result.recommendation_status, RecommendationStatus.RECOMMENDED)
        self.assertIsNotNone(decision_result.recommended_action)

        # 4. Human Approval Gate Formulation
        approval_req = self.gate.create_request(
            decision_result=decision_result,
            target_entity="svc-api",
            evidence_window_id=state.window_id,
        )

        auth = self._make_authority_decision(permitted=True)

        # 5. ATTEMPT EXECUTION WITHOUT HUMAN APPROVAL
        outcome = self.gate.authorize_and_execute(
            request=approval_req,
            decision=None,  # NO HUMAN APPROVAL PROVIDED
            authority_decision=auth,
            executor=self.executor,
            topology=self.topology,
        )

        # CRITICAL SAFETY INVARIANT: ZERO EXECUTION
        self.assertEqual(outcome.approval_status, ExecutionGateStatus.NOT_APPROVED)
        self.assertIsNone(outcome.execution_status)
        self.assertEqual(len(self.executor.get_execution_history()), 0)
        self.assertEqual(len(self.adapter.get_active_actions()), 0)


if __name__ == "__main__":
    unittest.main()
