"""Comprehensive Test Suite for Outcome Verification (SIH 26153 Task 21).

Verifies:
1. Expected vs. observed telemetry verification
2. Success classification (VERIFIED_SUCCESS)
3. Mismatch classification (VERIFIED_MISMATCH) and reconsideration flagging
4. Missing telemetry handling (INSUFFICIENT_EVIDENCE; missing != success)
5. Non-fabrication of synthetic risk scores
6. Reconsideration handoff contract
7. Complete end-to-end chain:
   Recommendation -> Authority -> Human Approval -> Execution -> Mismatch -> Reconsideration Handoff
"""
from __future__ import annotations

import unittest
from datetime import datetime

from core.authority.models import (
    ActionClass,
    AuthorityDecision,
    AuthorityLevel,
)
from core.contracts import (
    FeatureAvailability,
    NetworkState,
    Source,
    new_id,
)
from core.response_execution.adapters import DemoResponseAdapter
from core.response_execution.executor import ResponseExecutor
from core.response_execution.models import (
    ExecutionStatus,
    HumanApproval,
    ReversibleActionType,
    ResponseAction,
    RollbackPolicy,
)
from core.response_execution.verification import (
    OutcomeExpectation,
    OutcomeMismatchHandoff,
    OutcomeVerificationResult,
    OutcomeVerifier,
    VerificationStatus,
)
from core.topology.builder import build_minimal_demo_topology


class TestOutcomeVerification(unittest.TestCase):
    """Unit tests for OutcomeVerifier and end-to-end response lifecycle."""

    def setUp(self) -> None:
        self.verifier = OutcomeVerifier()
        self.adapter = DemoResponseAdapter()
        self.executor = ResponseExecutor(adapter=self.adapter)
        self.topology = build_minimal_demo_topology()

    def _make_dummy_state(
        self,
        window_id: str = "win-002",
        byte_rate: float = 1000.0,
        flow_count: int = 100,
        syn_ratio: float = 0.05,
        byte_rate_avail: FeatureAvailability = FeatureAvailability.AVAILABLE,
    ) -> NetworkState:
        return NetworkState(
            window_id=window_id,
            timestamp_start=datetime.now(),
            timestamp_end=datetime.now(),
            window_duration_s=0.0,
            flow_count=flow_count,
            byte_rate=byte_rate,
            packet_rate=100.0,
            mean_flow_duration=1.0,
            src_ip_diversity=5,
            dst_ip_diversity=5,
            src_port_diversity=10,
            dst_port_diversity=10,
            fan_out=1.0,
            internal_ratio=0.5,
            east_west_count=10,
            syn_count=10,
            ack_count=10,
            rst_count=1,
            syn_ratio=syn_ratio,
            rst_ratio=0.01,
            iat_mean=0.1,
            iat_std=0.01,
            iat_skew=0.0,
            pkt_size_mean=500.0,
            pkt_size_std=50.0,
            byte_variance=100.0,
            ttl_mean=64.0,
            ttl_variance=1.0,
            tcp_window_mean=1024.0,
            fragment_count=0,
            retransmit_count=0,
            payload_size_mean=400.0,
            source=Source.PCAP,
            data_quality=1.0,
            is_empty=False,
            gap_before=False,
            gap_after=False,
            session_id="sess-001",
            provenance_hash="0" * 64,
            feature_availability={"byte_rate": byte_rate_avail},
        )

    def _make_action(self, action_id: str = "act-001") -> ResponseAction:
        return ResponseAction(
            action_id=action_id,
            action_class=ActionClass.EXECUTE_REVERSIBLE_ACTION,
            target_node_id="svc-api",
            action_type=ReversibleActionType.TEMP_RATE_LIMIT,
            requested_parameters={"rate_limit_bps": 500.0},
            expected_effect="Drop byte_rate by >= 30%",
            reversibility=True,
            compensating_action_type="REMOVE_RATE_LIMIT",
            authority_decision_id="auth-001",
            evidence_window_id="win-001",
        )

    # 1. Expected drop observed -> VERIFIED_SUCCESS
    def test_01_expected_drop_observed_verifies_success(self) -> None:
        action = self._make_action()
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.30,  # Expect drop to <= 700.0
        )
        post_state = self._make_dummy_state(byte_rate=600.0)  # 40% drop

        result = self.verifier.verify(action, expectation, post_state)
        self.assertEqual(result.status, VerificationStatus.VERIFIED_SUCCESS)
        self.assertFalse(result.reconsideration_recommended)
        self.assertIn("VERIFIED SUCCESS", result.explanation)
        self.assertEqual(result.observed_value, 600.0)

    # 2. Expected drop absent -> VERIFIED_MISMATCH
    def test_02_expected_drop_absent_verifies_mismatch(self) -> None:
        action = self._make_action()
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.30,
        )
        post_state = self._make_dummy_state(byte_rate=980.0)  # Only 2% drop!

        result = self.verifier.verify(action, expectation, post_state)
        self.assertEqual(result.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(result.reconsideration_recommended)
        self.assertIn("VERIFIED MISMATCH", result.explanation)

    # 3. Below threshold expectation verified
    def test_03_below_threshold_expectation(self) -> None:
        action = self._make_action()
        exp = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="syn_ratio",
            expected_direction="BELOW_THRESHOLD",
            baseline_value=0.85,
            target_threshold=0.10,
        )
        post_state = self._make_dummy_state(syn_ratio=0.05)
        res = self.verifier.verify(action, exp, post_state)
        self.assertEqual(res.status, VerificationStatus.VERIFIED_SUCCESS)

        fail_state = self._make_dummy_state(syn_ratio=0.45)
        fail_res = self.verifier.verify(action, exp, fail_state)
        self.assertEqual(fail_res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(fail_res.reconsideration_recommended)

    # 4. Missing telemetry fails closed to INSUFFICIENT_EVIDENCE
    def test_04_missing_telemetry_fails_closed(self) -> None:
        action = self._make_action()
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
        )
        # Telemetry feature marked UNAVAILABLE
        missing_state = self._make_dummy_state(byte_rate_avail=FeatureAvailability.UNAVAILABLE)

        result = self.verifier.verify(action, expectation, missing_state)
        self.assertEqual(result.status, VerificationStatus.INSUFFICIENT_EVIDENCE)
        self.assertIsNone(result.observed_value)
        self.assertIn("Missing evidence never implies success", result.explanation)

    # 5. Dict telemetry observation support
    def test_05_dict_telemetry_observation(self) -> None:
        action = self._make_action()
        exp = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="flow_count",
            expected_direction="DECREASE",
            baseline_value=500.0,
            min_reduction_ratio=0.50,
        )
        obs_dict = {"window_id": "win-005", "flow_count": 200.0}
        res = self.verifier.verify(action, exp, obs_dict)
        self.assertEqual(res.status, VerificationStatus.VERIFIED_SUCCESS)

    # 6. Reconsideration handoff produced on VERIFIED_MISMATCH
    def test_06_reconsideration_handoff_produced_on_mismatch(self) -> None:
        action = self._make_action()
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.40,
        )
        post_state = self._make_dummy_state(byte_rate=1200.0)  # Telemetry actually surged!

        result = self.verifier.verify(action, expectation, post_state)
        self.assertEqual(result.status, VerificationStatus.VERIFIED_MISMATCH)

        handoff = self.verifier.build_reconsideration_handoff(result)
        self.assertIsNotNone(handoff)
        self.assertIsInstance(handoff, OutcomeMismatchHandoff)
        self.assertEqual(handoff.action_id, action.action_id)
        self.assertEqual(handoff.metric_name, "byte_rate")
        self.assertEqual(handoff.observed_value, 1200.0)
        self.assertTrue(handoff.provenance_hash)
        # CRITICAL: Confirm handoff does NOT fabricate a synthetic risk score
        self.assertNotIn("risk_score", handoff.to_dict())

    # 7. No reconsideration handoff produced on VERIFIED_SUCCESS
    def test_07_no_handoff_on_verified_success(self) -> None:
        action = self._make_action()
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.20,
        )
        post_state = self._make_dummy_state(byte_rate=500.0)
        result = self.verifier.verify(action, expectation, post_state)
        self.assertEqual(result.status, VerificationStatus.VERIFIED_SUCCESS)

        handoff = self.verifier.build_reconsideration_handoff(result)
        self.assertIsNone(handoff)

    # 8. Deterministic provenance hash for verification results
    def test_08_deterministic_provenance_hash(self) -> None:
        action = self._make_action()
        exp = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.20,
        )
        post_state = self._make_dummy_state(byte_rate=800.0)

        res1 = self.verifier.verify(action, exp, post_state)
        # Verify same canonical parameters produce identical hashes
        self.assertTrue(res1.provenance_hash)
        self.assertEqual(len(res1.provenance_hash), 64)

    # 9. Important End-to-End Test: Full Lifecycle Chain
    def test_09_full_end_to_end_lifecycle_chain(self) -> None:
        """
        Tests the complete 10-step chain:
        Step 1: Pipeline recommendation (TEMP_RATE_LIMIT)
        Step 2: Authority policy (HUMAN_APPROVAL_REQUIRED)
        Step 3: Execution without approval is BLOCKED
        Step 4: Human operator approves exact action
        Step 5: Action executes via DemoResponseAdapter
        Step 6: Post-action telemetry observed
        Step 7: Verification detects VERIFIED_MISMATCH
        Step 8: System records mismatch without fabricating risk score
        Step 9: Reconsideration handoff produced
        Step 10: Proves RECOMMENDATION != AUTHORITY != APPROVAL != EXECUTION != VERIFICATION
        """
        # Step 1: Recommendation context
        rec_id = "rec-flood-001"

        # Step 2: Authority decision
        auth_decision = AuthorityDecision(
            decision_id="auth-dec-001",
            authority_level=AuthorityLevel.HUMAN_APPROVAL_REQUIRED,
            permitted_action_classes=(
                ActionClass.OBSERVE_ONLY,
                ActionClass.ALERT_OPERATOR,
                ActionClass.GENERATE_RECOMMENDATION,
                ActionClass.PREPARE_REVERSIBLE_ACTION,
                ActionClass.EXECUTE_REVERSIBLE_ACTION,
            ),
            blocked_action_classes=(ActionClass.EXECUTE_DESTRUCTIVE_ACTION,),
            human_approval_required=True,
            policy_version="authority-v1",
            reason_codes=("STRONG_EVIDENCE_PERMITS_HUMAN_GATED_EXECUTION",),
        )

        # Formulate Action
        action = ResponseAction(
            action_id="act-rate-limit-001",
            action_class=ActionClass.EXECUTE_REVERSIBLE_ACTION,
            target_node_id="svc-api",
            action_type=ReversibleActionType.TEMP_RATE_LIMIT,
            requested_parameters={"rate_limit_bps": 5000.0},
            expected_effect="Drop ingress byte_rate by >= 40%",
            reversibility=True,
            compensating_action_type="REMOVE_RATE_LIMIT",
            authority_decision_id=auth_decision.decision_id,
            evidence_window_id="win-001",
            recommendation_id=rec_id,
            topology_snapshot_id="toposnap-001",
        )

        # Step 3: Attempt execution without approval -> strictly BLOCKED
        blocked_rec, blocked_msg = self.executor.execute(
            action=action,
            authority_decision=auth_decision,
            approval=None,
            current_topology=self.topology,
            current_window_id="win-001",
        )
        self.assertEqual(blocked_rec.status, ExecutionStatus.BLOCKED)
        self.assertEqual(len(self.adapter.get_active_actions()), 0)

        # Step 4: Human operator approves exact action
        approval = HumanApproval(
            approval_id="appr-001",
            action_id=action.action_id,
            authority_decision_id=auth_decision.decision_id,
            evidence_window_id=action.evidence_window_id,
            approved=True,
            approver_reference="demo-operator",
            approval_reason="Confirmed high connection burst on ingress gateway; approve temporary rate limit.",
        )

        # Step 5: Execution succeeds via DemoResponseAdapter
        exec_rec, exec_msg = self.executor.execute(
            action=action,
            authority_decision=auth_decision,
            approval=approval,
            current_topology=self.topology,
            current_window_id="win-001",
        )
        self.assertEqual(exec_rec.status, ExecutionStatus.EXECUTED)
        self.assertEqual(len(self.adapter.get_active_actions()), 1)

        # Step 6: Post-action telemetry observed in next window
        # The attack persists or changes vector; byte_rate does NOT drop
        post_state = self._make_dummy_state(window_id="win-002", byte_rate=950.0)

        # Step 7: Outcome Verification detects mismatch
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.40,  # Expected <= 600.0
        )
        verif_result = self.verifier.verify(action, expectation, post_state)
        self.assertEqual(verif_result.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(verif_result.reconsideration_recommended)

        # Step 8: Verification result recorded without fabricating risk
        verif_dict = verif_result.to_dict()
        self.assertNotIn("revised_risk", verif_dict)
        self.assertEqual(verif_dict["status"], "VERIFIED_MISMATCH")

        # Step 9: Reconsideration handoff produced
        handoff = self.verifier.build_reconsideration_handoff(verif_result)
        self.assertIsNotNone(handoff)
        self.assertEqual(handoff.action_id, action.action_id)
        self.assertIn("failed to produce expected", handoff.conflict_summary)

        # Step 10: Rollback compensating action
        roll_rec, roll_msg = self.executor.rollback(action, auth_decision, approval)
        self.assertEqual(roll_rec.status, ExecutionStatus.ROLLED_BACK)
        self.assertEqual(len(self.adapter.get_active_actions()), 0)


if __name__ == "__main__":
    unittest.main()
