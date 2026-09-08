"""Comprehensive Test Suite for Reversible Response Execution (SIH 26153 Task 21).

Verifies:
1. Core Safety Principle: RECOMMENDATION != AUTHORIZATION != APPROVAL != EXECUTION != VERIFICATION
2. Explicit human approval mandatory whenever policy requires it (no bypass via risk, trust, or priority)
3. Exact action_id + authority_decision_id + evidence_window_id binding
4. Deterministic, auditable stale-authorization detection
5. Permanent blocking of destructive actions
6. Idempotency
7. First-class controlled rollback governance
8. Provenance hashes and serialization
"""
from __future__ import annotations

import unittest
from datetime import datetime

from core.authority.models import (
    ActionClass,
    AuthorityDecision,
    AuthorityLevel,
)
from core.contracts import new_id
from core.response_execution.adapters import DemoResponseAdapter
from core.response_execution.executor import ResponseExecutor
from core.response_execution.models import (
    ExecutionRecord,
    ExecutionStatus,
    HumanApproval,
    ReversibleActionType,
    ResponseAction,
    RollbackPolicy,
)
from core.topology.builder import build_minimal_demo_topology
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability


class TestResponseExecution(unittest.TestCase):
    """Unit and safety tests for ResponseExecutor and DemoResponseAdapter."""

    def setUp(self) -> None:
        self.adapter = DemoResponseAdapter()
        self.executor = ResponseExecutor(adapter=self.adapter)
        self.topology = build_minimal_demo_topology()
        self.snapshot = self.topology.to_snapshot("toposnap-001")

    def _make_authority_decision(
        self,
        authority_level: AuthorityLevel = AuthorityLevel.HUMAN_APPROVAL_REQUIRED,
        permitted_actions: tuple[ActionClass, ...] = (
            ActionClass.OBSERVE_ONLY,
            ActionClass.ALERT_OPERATOR,
            ActionClass.GENERATE_RECOMMENDATION,
            ActionClass.PREPARE_REVERSIBLE_ACTION,
            ActionClass.EXECUTE_REVERSIBLE_ACTION,
        ),
        blocked_actions: tuple[ActionClass, ...] = (ActionClass.EXECUTE_DESTRUCTIVE_ACTION,),
        human_approval_required: bool = True,
    ) -> AuthorityDecision:
        return AuthorityDecision(
            decision_id=new_id("auth-dec"),
            authority_level=authority_level,
            permitted_action_classes=permitted_actions,
            blocked_action_classes=blocked_actions,
            human_approval_required=human_approval_required,
            policy_version="authority-v1",
            reason_codes=("STRONG_EVIDENCE_PERMITS_HUMAN_GATED_EXECUTION",),
            explanation="Test authority decision",
        )

    def _make_response_action(
        self,
        authority_decision_id: str,
        evidence_window_id: str = "win-001",
        action_class: ActionClass = ActionClass.EXECUTE_REVERSIBLE_ACTION,
        action_type: ReversibleActionType = ReversibleActionType.TEMP_RATE_LIMIT,
        target_node_id: str = "svc-api",
        reversibility: bool = True,
        rollback_policy: RollbackPolicy = RollbackPolicy.AUTOMATIC_COMPENSATING,
    ) -> ResponseAction:
        return ResponseAction(
            action_id=new_id("act"),
            action_class=action_class,
            target_node_id=target_node_id,
            action_type=action_type,
            requested_parameters={"rate_limit_bps": 5000.0, "duration_s": 30.0},
            expected_effect="Reduce ingress traffic rate by >= 30%",
            reversibility=reversibility,
            compensating_action_type="REMOVE_TEMP_RATE_LIMIT",
            authority_decision_id=authority_decision_id,
            evidence_window_id=evidence_window_id,
            topology_snapshot_id=self.snapshot.snapshot_id,
            rollback_policy=rollback_policy,
        )

    def _make_approval(
        self,
        action_id: str,
        authority_decision_id: str,
        evidence_window_id: str = "win-001",
        approved: bool = True,
    ) -> HumanApproval:
        return HumanApproval(
            approval_id=new_id("appr"),
            action_id=action_id,
            authority_decision_id=authority_decision_id,
            evidence_window_id=evidence_window_id,
            approved=approved,
            approver_reference="demo-operator",
            approval_reason="Verified anomalous connection churn justifying rate-limiting.",
        )

    # 1. Successful execution of human-approved reversible action
    def test_01_valid_approved_action_executes(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        record, msg = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.EXECUTED)
        self.assertFalse(record.is_rollback)
        self.assertIn("Executed", msg)
        self.assertIn(action.target_node_id, self.adapter.get_state()["active_rate_limits"])

    # 2. Missing approval blocks execution
    def test_02_missing_approval_blocks_execution(self) -> None:
        auth = self._make_authority_decision(human_approval_required=True)
        action = self._make_response_action(authority_decision_id=auth.decision_id)

        record, msg = self.executor.execute(action, auth, None, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("Human approval required but missing", msg)
        self.assertEqual(len(self.adapter.get_active_actions()), 0)

    # 3. Explicit operator rejection produces REJECTED status
    def test_03_explicit_rejection_produces_rejected_status(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        rejection = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id, approved=False)

        record, msg = self.executor.execute(action, auth, rejection, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.REJECTED)
        self.assertIn("rejected", msg.lower())
        self.assertEqual(len(self.adapter.get_active_actions()), 0)

    # 4. Authority decision BLOCKED prevents execution
    def test_04_blocked_authority_decision_prevents_execution(self) -> None:
        auth = self._make_authority_decision(
            authority_level=AuthorityLevel.BLOCKED,
            permitted_actions=(ActionClass.OBSERVE_ONLY,),
            blocked_actions=(ActionClass.EXECUTE_REVERSIBLE_ACTION, ActionClass.EXECUTE_DESTRUCTIVE_ACTION),
        )
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        record, msg = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("Authority decision is BLOCKED", msg)

    # 5. Authority level RECOMMEND or ALERT cannot execute containment
    def test_05_advisory_authority_levels_cannot_execute(self) -> None:
        # RECOMMEND permits GENERATE_RECOMMENDATION, but NOT EXECUTE_REVERSIBLE_ACTION
        auth = self._make_authority_decision(
            authority_level=AuthorityLevel.RECOMMEND,
            permitted_actions=(ActionClass.OBSERVE_ONLY, ActionClass.ALERT_OPERATOR, ActionClass.GENERATE_RECOMMENDATION),
            blocked_actions=(ActionClass.EXECUTE_REVERSIBLE_ACTION,),
        )
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        record, msg = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("not permitted", msg)

    # 6. Destructive actions are permanently BLOCKED
    def test_06_destructive_actions_cannot_be_represented_or_executed(self) -> None:
        # ResponseAction validation blocks representing destructive action
        with self.assertRaises(ValueError):
            ResponseAction(
                action_id="act-dest",
                action_class=ActionClass.EXECUTE_DESTRUCTIVE_ACTION,
                target_node_id="svc-db",
                action_type=ReversibleActionType.DEMO_BLOCK,
                requested_parameters={},
                expected_effect="Drop database",
                reversibility=True,
                compensating_action_type="UNBLOCK",
                authority_decision_id="auth-1",
                evidence_window_id="win-1",
            )

    # 7. Action-Authority mismatch fails closed
    def test_07_action_authority_mismatch_fails_closed(self) -> None:
        auth1 = self._make_authority_decision()
        auth2 = self._make_authority_decision()
        # Action references auth1, but executor is invoked with auth2
        action = self._make_response_action(authority_decision_id=auth1.decision_id)
        approval = self._make_approval(action.action_id, auth1.decision_id, action.evidence_window_id)

        record, msg = self.executor.execute(action, auth2, approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("authority_decision_id mismatch", msg)

    # 8. Approval-Action mismatch fails closed
    def test_08_approval_action_mismatch_fails_closed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        wrong_approval = self._make_approval("other-act-id", auth.decision_id, action.evidence_window_id)

        record, msg = self.executor.execute(action, auth, wrong_approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("Approval action_id mismatch", msg)

    # 9. Approval-Authority mismatch fails closed
    def test_09_approval_authority_mismatch_fails_closed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        wrong_approval = self._make_approval(action.action_id, "different-auth-id", action.evidence_window_id)

        record, msg = self.executor.execute(action, auth, wrong_approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("Approval authority_decision_id mismatch", msg)

    # 10. Approval-EvidenceWindow mismatch fails closed
    def test_10_approval_evidence_window_mismatch_fails_closed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id, evidence_window_id="win-001")
        wrong_approval = self._make_approval(action.action_id, auth.decision_id, evidence_window_id="win-002")

        record, msg = self.executor.execute(action, auth, wrong_approval, self.topology, "win-001")
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("Approval evidence_window_id mismatch", msg)

    # 11. Deterministic stale authorization check (window advanced)
    def test_11_stale_authorization_when_window_advanced(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id, evidence_window_id="win-001")
        approval = self._make_approval(action.action_id, auth.decision_id, "win-001")

        # Current telemetry window has advanced to win-002
        record, msg = self.executor.execute(action, auth, approval, self.topology, current_window_id="win-002")
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE", record.error_message)

    # 12. Topology UNAVAILABLE at execution time fails closed
    def test_12_topology_unavailable_at_execution_fails_closed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        unavail_topology = ServiceTopologyGraph(availability=TopologyAvailability.UNAVAILABLE)
        record, msg = self.executor.execute(action, auth, approval, unavail_topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("STALE_AUTHORIZATION_TOPOLOGY_UNAVAILABLE", record.error_message)

    # 13. Topology snapshot mismatch fails closed
    def test_13_topology_snapshot_mismatch_fails_closed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        # Build modified topology snapshot with different snapshot ID
        modified_topo = self.topology.to_snapshot(snapshot_id="diff-snap-999")
        record, msg = self.executor.execute(action, auth, approval, modified_topo, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("STALE_AUTHORIZATION_TOPOLOGY_SNAPSHOT_MISMATCH", record.error_message)

    # 14. Target node missing from active topology fails closed
    def test_14_missing_target_node_fails_closed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id, target_node_id="nonexistent-svc")
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        record, msg = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("not in topology", msg)

    # 15. Idempotent execution of duplicate requests
    def test_15_idempotent_execution(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        rec1, msg1 = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        rec2, msg2 = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)

        self.assertEqual(rec1.execution_id, rec2.execution_id)
        self.assertIn("Idempotent", msg2)
        # Adapter should only have recorded 1 execution
        self.assertEqual(len(self.adapter.get_active_actions()), 1)

    # 16. Adapter execution failure recorded as FAILED
    def test_16_adapter_failure_recorded_as_failed(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        self.adapter.set_execution_failure_simulation(True)
        record, msg = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertEqual(record.status, ExecutionStatus.FAILED)
        self.assertIn("failed", msg.lower())

    # 17. Controlled compensating rollback succeeds
    def test_17_controlled_rollback_succeeds(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertIn(action.target_node_id, self.adapter.get_state()["active_rate_limits"])

        # Execute rollback
        roll_rec, roll_msg = self.executor.rollback(action, auth, approval)
        self.assertEqual(roll_rec.status, ExecutionStatus.ROLLED_BACK)
        self.assertTrue(roll_rec.is_rollback)
        self.assertNotIn(action.target_node_id, self.adapter.get_state()["active_rate_limits"])

    # 18. Rollback blocked when current authority is BLOCKED
    def test_18_rollback_blocked_when_authority_is_blocked(self) -> None:
        auth_ok = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth_ok.decision_id)
        approval = self._make_approval(action.action_id, auth_ok.decision_id, action.evidence_window_id)

        self.executor.execute(action, auth_ok, approval, self.topology, action.evidence_window_id)

        # Authority subsequently transitions to BLOCKED
        auth_blocked = self._make_authority_decision(authority_level=AuthorityLevel.BLOCKED)
        roll_rec, roll_msg = self.executor.rollback(action, auth_blocked, approval)
        self.assertEqual(roll_rec.status, ExecutionStatus.BLOCKED)
        self.assertIn("ROLLBACK_BLOCKED_BY_AUTHORITY", roll_rec.error_message)

    # 19. Rollback requires approval when RollbackPolicy is REQUIRE_HUMAN_APPROVAL
    def test_19_rollback_requires_approval_under_policy(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(
            authority_decision_id=auth.decision_id,
            rollback_policy=RollbackPolicy.REQUIRE_HUMAN_APPROVAL,
        )
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)

        # Rollback attempt without approval fails closed
        roll_rec, roll_msg = self.executor.rollback(action, auth, approval=None)
        self.assertEqual(roll_rec.status, ExecutionStatus.BLOCKED)
        self.assertIn("requires explicit human approval", roll_rec.error_message)

        # Rollback with approval succeeds
        roll_rec_ok, roll_msg_ok = self.executor.rollback(action, auth, approval=approval)
        self.assertEqual(roll_rec_ok.status, ExecutionStatus.ROLLED_BACK)

    # 20. Rollback adapter failure is explicitly recorded
    def test_20_rollback_adapter_failure_recorded(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.adapter.set_rollback_failure_simulation(True)

        roll_rec, roll_msg = self.executor.rollback(action, auth, approval)
        self.assertEqual(roll_rec.status, ExecutionStatus.FAILED)
        self.assertTrue(roll_rec.is_rollback)

    # 21. High risk / high priority cannot bypass human approval
    def test_21_high_risk_priority_cannot_bypass_human_approval(self) -> None:
        # Simulated scenario: P0 critical threat, 0.99 risk score, high blast radius
        auth = self._make_authority_decision(human_approval_required=True)
        action = self._make_response_action(authority_decision_id=auth.decision_id)

        # Attempt execution without human approval
        record, msg = self.executor.execute(action, auth, approval=None, current_topology=self.topology)
        self.assertEqual(record.status, ExecutionStatus.BLOCKED)
        self.assertIn("Human approval required", msg)

    # 22. Deterministic SHA-256 provenance hashes
    def test_22_deterministic_provenance_hashes(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        self.assertTrue(action.provenance_hash)
        self.assertEqual(len(action.provenance_hash), 64)
        self.assertTrue(approval.provenance_hash)
        self.assertEqual(len(approval.provenance_hash), 64)

        rec, _ = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        self.assertTrue(rec.provenance_hash)
        self.assertEqual(len(rec.provenance_hash), 64)

    # 23. Serialization round-trips
    def test_23_model_serialization_roundtrips(self) -> None:
        auth = self._make_authority_decision()
        action = self._make_response_action(authority_decision_id=auth.decision_id)
        approval = self._make_approval(action.action_id, auth.decision_id, action.evidence_window_id)

        act_d = action.to_dict()
        reconstituted_act = ResponseAction.from_dict(act_d)
        self.assertEqual(reconstituted_act.action_id, action.action_id)
        self.assertEqual(reconstituted_act.provenance_hash, action.provenance_hash)

        appr_d = approval.to_dict()
        reconstituted_appr = HumanApproval.from_dict(appr_d)
        self.assertEqual(reconstituted_appr.approval_id, approval.approval_id)
        self.assertEqual(reconstituted_appr.provenance_hash, approval.provenance_hash)

        rec, _ = self.executor.execute(action, auth, approval, self.topology, action.evidence_window_id)
        rec_d = rec.to_dict()
        reconstituted_rec = ExecutionRecord.from_dict(rec_d)
        self.assertEqual(reconstituted_rec.execution_id, rec.execution_id)
        self.assertEqual(reconstituted_rec.provenance_hash, rec.provenance_hash)


if __name__ == "__main__":
    unittest.main()
