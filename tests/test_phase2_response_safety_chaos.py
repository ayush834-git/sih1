"""Phase 2A — Response Safety Adversarial Audit & Chaos Tests (SIH 26153).

Deterministic tests validating conservative safety invariants across Path A:
- Test 1: No Approval -> REJECTED / BLOCKED, adapter not executed
- Test 2: Approval=false -> REJECTED, adapter not executed
- Test 3: Wrong Approval Binding -> FAIL CLOSED on action_id, auth_id, window_id mismatches
- Test 4: Stale Authorization -> FAIL CLOSED on telemetry progression (STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE)
- Test 5: Telemetry Changes After Approval -> Invalidation of stale state verified
- Test 6: Topology Change -> STALE_AUTHORIZATION_TOPOLOGY_SNAPSHOT_MISMATCH
- Test 7: Topology Unavailable -> STALE_AUTHORIZATION_TOPOLOGY_UNAVAILABLE (fail closed)
- Test 8: Destructive Action -> Permanently blocked via API (EXECUTE_DESTRUCTIVE_ACTION prohibited)
- Test 9: Nonexistent Target -> REJECTED when target is absent from active topology
- Test 10: Duplicate Execution -> Idempotency verified over 1x, 2x, 5x, 20x repeated executions
- Test 11: Verification Mismatch -> VERIFIED_MISMATCH, no fabricated success, reconsideration handoff produced
- Test 12: Rollback Governance -> Controlled compensating rollback, authority gating, verification
"""
from __future__ import annotations

import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.response_execution.adapters import DemoResponseAdapter
from core.response_execution.executor import ResponseExecutor
from core.response_execution.models import ExecutionStatus
from core.topology.builder import build_minimal_demo_topology
from core.topology.models import TopologyAvailability
from runtime.api import create_app
from runtime.demo_adapter import DemoAdapter
from runtime.state_store import RuntimeStateStore
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine


class TestPhase2ResponseSafetyAdversarial(unittest.TestCase):
    """Adversarial validation of Response Safety, Gating, and Outcome Verification."""

    def setUp(self) -> None:
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, scales = load_ar_model(model_dir)
        self.topology = build_minimal_demo_topology()
        self.topology.snapshot_id = "toposnap-canonical-demo-v1"
        self.engine = LiveDemoEngine(ar_model=ar_model, scales=scales, topology=self.topology)
        self.store = RuntimeStateStore(max_history_size=500)
        self.adapter = DemoAdapter(engine=self.engine, store=self.store, base_step_delay=0.01)
        self.app = create_app(adapter=self.adapter)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.post("/api/v1/demo/reset")

    # -------------------------------------------------------------------------
    # TEST 1 — NO APPROVAL
    # -------------------------------------------------------------------------
    def test_1_no_approval_rejected(self) -> None:
        """EXECUTE_REVERSIBLE_ACTION without approval MUST be blocked."""
        # Start demo and advance 1 step to have valid state
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        payload = {
            "action_type": "DEMO_BLOCK",
            "action_class": "EXECUTE_REVERSIBLE_ACTION",
            "target_node_id": "svc-api",
            "approval": None,
        }
        res = self.client.post("/api/v1/response/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertFalse(data["is_verified"])
        self.assertIn("Human approval required", data["message"])
        self.assertIn("Mandatory human approval record was not provided", data["error_message"])

    # -------------------------------------------------------------------------
    # TEST 2 — APPROVAL = FALSE
    # -------------------------------------------------------------------------
    def test_2_approval_false_rejected(self) -> None:
        """EXECUTE_REVERSIBLE_ACTION with approved=False MUST be rejected."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        payload = {
            "action_type": "DEMO_BLOCK",
            "action_class": "EXECUTE_REVERSIBLE_ACTION",
            "target_node_id": "svc-api",
            "approval": {
                "approval_id": "appr-reject-01",
                "approved": False,
                "approver_reference": "OPERATOR_01",
                "approval_reason": "Operator denied mitigation due to maintenance window",
            },
        }
        res = self.client.post("/api/v1/response/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], ExecutionStatus.REJECTED.value)
        self.assertFalse(data["is_verified"])
        self.assertIn("rejected action", data["message"].lower())
        self.assertEqual(data["approval_id"], "appr-reject-01")

    # -------------------------------------------------------------------------
    # TEST 3 — WRONG APPROVAL BINDING
    # -------------------------------------------------------------------------
    def test_3_wrong_approval_binding_fails_closed(self) -> None:
        """Tampered or mismatched action_id, authority_decision_id, or evidence_window_id fails closed."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        curr = self.client.get("/api/v1/state/current").json()
        current_win = curr["event_id"]
        auth_decision_id = curr["authority_policy"]["decision_id"]

        # 3a. Action ID mismatch
        res_mismatch_action = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-intended-001",
                "action_type": "DEMO_BLOCK",
                "action_class": "EXECUTE_REVERSIBLE_ACTION",
                "target_node_id": "svc-api",
                "authority_decision_id": auth_decision_id,
                "evidence_window_id": current_win,
                "approval": {
                    "approval_id": "appr-tampered-001",
                    "action_id": "act-unrelated-999",  # MISMATCH
                    "authority_decision_id": auth_decision_id,
                    "evidence_window_id": current_win,
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved",
                },
            },
        )
        self.assertEqual(res_mismatch_action.status_code, 200)
        data_a = res_mismatch_action.json()
        self.assertEqual(data_a["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("action_id mismatch", data_a["error_message"])

        # 3b. Authority Decision ID mismatch
        res_mismatch_auth = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-intended-002",
                "action_type": "DEMO_BLOCK",
                "action_class": "EXECUTE_REVERSIBLE_ACTION",
                "target_node_id": "svc-api",
                "authority_decision_id": auth_decision_id,
                "evidence_window_id": current_win,
                "approval": {
                    "approval_id": "appr-tampered-002",
                    "action_id": "act-intended-002",
                    "authority_decision_id": "auth-decision-tampered-XYZ",  # MISMATCH
                    "evidence_window_id": current_win,
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved",
                },
            },
        )
        self.assertEqual(res_mismatch_auth.status_code, 200)
        data_b = res_mismatch_auth.json()
        self.assertEqual(data_b["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("authority_decision_id mismatch", data_b["error_message"])

        # 3c. Evidence Window ID mismatch
        res_mismatch_win = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-intended-003",
                "action_type": "DEMO_BLOCK",
                "action_class": "EXECUTE_REVERSIBLE_ACTION",
                "target_node_id": "svc-api",
                "authority_decision_id": auth_decision_id,
                "evidence_window_id": current_win,
                "approval": {
                    "approval_id": "appr-tampered-003",
                    "action_id": "act-intended-003",
                    "authority_decision_id": auth_decision_id,
                    "evidence_window_id": "win-arbitrary-old-evidence",  # MISMATCH
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved",
                },
            },
        )
        self.assertEqual(res_mismatch_win.status_code, 200)
        data_c = res_mismatch_win.json()
        self.assertEqual(data_c["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("evidence_window_id mismatch", data_c["error_message"])

        # 3d. Missing required approval field (e.g., missing approved bool) -> 422 Unprocessable Entity
        res_invalid_field = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "approval": {
                    "approval_id": "appr-invalid",
                    # approved missing!
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved",
                },
            },
        )
        self.assertEqual(res_invalid_field.status_code, 422)

    # -------------------------------------------------------------------------
    # TEST 4 — STALE AUTHORIZATION
    # -------------------------------------------------------------------------
    def test_4_stale_authorization_rejected(self) -> None:
        """Advancing telemetry invalidates previous window authorization."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})

        # Step to step 0
        self.client.post("/api/v1/demo/step")
        st0 = self.client.get("/api/v1/state/current").json()
        win0 = st0["event_id"]
        auth0 = st0["authority_policy"]["decision_id"]

        # Advance telemetry to step 1 and step 2
        self.client.post("/api/v1/demo/step")
        self.client.post("/api/v1/demo/step")
        st2 = self.client.get("/api/v1/state/current").json()
        win2 = st2["event_id"]
        self.assertNotEqual(win0, win2)

        # Attempt to execute using old window0 authorization
        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "action_class": "EXECUTE_REVERSIBLE_ACTION",
                "target_node_id": "svc-api",
                "authority_decision_id": auth0,
                "evidence_window_id": win0,
                "approval": {
                    "approval_id": "appr-stale-001",
                    "action_id": "act-stale-001",
                    "authority_decision_id": auth0,
                    "evidence_window_id": win0,
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Old approval from window 0",
                },
                "action_id": "act-stale-001",
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertFalse(data["is_verified"])
        self.assertIn("STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE", data["error_message"])

    # -------------------------------------------------------------------------
    # TEST 5 — TELEMETRY CHANGES AFTER APPROVAL
    # -------------------------------------------------------------------------
    def test_5_telemetry_changes_after_approval(self) -> None:
        """Operator approves recommendation, but telemetry advances before execution happens."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")
        st1 = self.client.get("/api/v1/state/current").json()
        win1 = st1["event_id"]
        auth1 = st1["authority_policy"]["decision_id"]

        # Operator approved for win1
        approval = {
            "approval_id": "appr-valid-win1",
            "action_id": "act-win1-01",
            "authority_decision_id": auth1,
            "evidence_window_id": win1,
            "approved": True,
            "approver_reference": "OPERATOR_01",
            "approval_reason": "Operator approved action for window 1",
        }

        # Telemetry advances to next step before click arrives
        self.client.post("/api/v1/demo/step")

        # Click arrives with win1
        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-win1-01",
                "action_type": "DEMO_BLOCK",
                "target_node_id": "svc-api",
                "authority_decision_id": auth1,
                "evidence_window_id": win1,
                "approval": approval,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE", data["error_message"])

    # -------------------------------------------------------------------------
    # TEST 6 — TOPOLOGY CHANGE
    # -------------------------------------------------------------------------
    def test_6_topology_change_rejected(self) -> None:
        """Action referencing obsolete topology snapshot ID MUST be blocked."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "target_node_id": "svc-api",
                "topology_snapshot_id": "topo-obsolete-v0",  # mismatched topology snapshot
                "approval": {
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved against obsolete topology",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("STALE_AUTHORIZATION_TOPOLOGY_SNAPSHOT_MISMATCH", data["error_message"])

    # -------------------------------------------------------------------------
    # TEST 7 — TOPOLOGY UNAVAILABLE
    # -------------------------------------------------------------------------
    def test_7_topology_unavailable_fails_closed(self) -> None:
        """When topology availability is UNAVAILABLE, execution fails closed."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        # Invalidate topology availability
        self.topology.availability = TopologyAvailability.UNAVAILABLE

        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "target_node_id": "svc-api",
                "approval": {
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("STALE_AUTHORIZATION_TOPOLOGY_UNAVAILABLE", data["error_message"])

        # Restore topology for subsequent tests
        self.topology.availability = TopologyAvailability.KNOWN

    # -------------------------------------------------------------------------
    # TEST 8 — DESTRUCTIVE ACTION
    # -------------------------------------------------------------------------
    def test_8_destructive_action_permanently_blocked(self) -> None:
        """EXECUTE_DESTRUCTIVE_ACTION is permanently prohibited through API."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "PERMANENT_WIPE_FIREWALL",
                "action_class": "EXECUTE_DESTRUCTIVE_ACTION",
                "target_node_id": "svc-api",
                "approval": {
                    "approved": True,
                    "approver_reference": "SUPER_ADMIN",
                    "approval_reason": "Operator attempted destructive override",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertFalse(data["is_verified"])
        self.assertIn("EXECUTE_DESTRUCTIVE_ACTION is permanently prohibited", data["error_message"])

    # -------------------------------------------------------------------------
    # TEST 9 — NONEXISTENT TARGET
    # -------------------------------------------------------------------------
    def test_9_nonexistent_target_rejected(self) -> None:
        """Target node not present in active topology MUST be rejected."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "target_node_id": "phantom-node-xyz",
                "approval": {
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("does not exist in active topology", data["error_message"])

    # -------------------------------------------------------------------------
    # TEST 10 — DUPLICATE EXECUTION (IDEMPOTENCY)
    # -------------------------------------------------------------------------
    def test_10_duplicate_execution_idempotency(self) -> None:
        """Duplicate executions (1x, 2x, 5x, 20x) are strictly idempotent."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        req = {
            "action_id": "act-idempotency-test-01",
            "action_type": "DEMO_BLOCK",
            "target_node_id": "svc-api",
            "approval": {
                "approval_id": "appr-idempotent-01",
                "action_id": "act-idempotency-test-01",
                "approved": True,
                "approver_reference": "OPERATOR_01",
                "approval_reason": "Idempotent test approval",
            },
        }

        # 1st execution
        res1 = self.client.post("/api/v1/response/execute", json=req)
        self.assertEqual(res1.status_code, 200)
        data1 = res1.json()
        self.assertEqual(data1["status"], ExecutionStatus.EXECUTED.value)
        self.assertTrue(data1["is_verified"])
        first_exec_id = data1["execution_id"]

        # 2nd execution (duplicate)
        res2 = self.client.post("/api/v1/response/execute", json=req)
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertEqual(data2["execution_id"], first_exec_id)
        self.assertIn("Idempotent", data2["message"])

        # 5x executions
        for _ in range(3):
            res_repeat = self.client.post("/api/v1/response/execute", json=req)
            self.assertEqual(res_repeat.status_code, 200)
            self.assertEqual(res_repeat.json()["execution_id"], first_exec_id)

        # 20x executions
        for _ in range(15):
            res_repeat20 = self.client.post("/api/v1/response/execute", json=req)
            self.assertEqual(res_repeat20.status_code, 200)
            self.assertEqual(res_repeat20.json()["execution_id"], first_exec_id)

        # Verify execution history only has 1 record for this action
        history = self.client.get("/api/v1/response/history").json()
        matching = [r for r in history if r["action_id"] == "act-idempotency-test-01"]
        self.assertEqual(len(matching), 1)

    # -------------------------------------------------------------------------
    # TEST 11 — VERIFICATION MISMATCH
    # -------------------------------------------------------------------------
    def test_11_verification_mismatch_creates_reconsideration_handoff(self) -> None:
        """When post-action telemetry conflicts with expectation, report VERIFIED_MISMATCH."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        req = {
            "action_id": "act-verif-mismatch-01",
            "action_type": "DEMO_BLOCK",
            "target_node_id": "svc-api",
            "approval": {
                "approval_id": "appr-verif-01",
                "action_id": "act-verif-mismatch-01",
                "approved": True,
                "approver_reference": "OPERATOR_01",
                "approval_reason": "Approved for verification test",
            },
            "verification_expectation": {
                "metric_name": "byte_rate",
                "baseline_value": 1000.0,
                "expected_direction": "DECREASE",
                "min_reduction_ratio": 0.50,
                "tolerance": 0.05,
            },
            "observed_state": {
                "byte_rate": 1500.0,  # Observed INCREASE instead of DECREASE!
                "window_id": "win-obs-mismatch",
            },
        }

        res = self.client.post("/api/v1/response/execute", json=req)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], ExecutionStatus.EXECUTED.value)
        self.assertFalse(data["is_verified"])
        self.assertEqual(data["verification_status"], "VERIFIED_MISMATCH")
        self.assertIsNotNone(data["reconsideration_handoff"])

        handoff = data["reconsideration_handoff"]
        self.assertEqual(handoff["action_id"], "act-verif-mismatch-01")
        self.assertIn("failed to produce expected", handoff["conflict_summary"])
        self.assertTrue(len(handoff["provenance_hash"]) >= 32)

    # -------------------------------------------------------------------------
    # TEST 12 — ROLLBACK
    # -------------------------------------------------------------------------
    def test_12_controlled_rollback(self) -> None:
        """Reversible action can be rolled back under strict governance."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        # 1. Execute reversible action
        exec_req = {
            "action_id": "act-for-rollback-01",
            "action_type": "DEMO_BLOCK",
            "target_node_id": "svc-api",
            "compensating_action_type": "RESTORE_CONNECTION",
            "approval": {
                "approval_id": "appr-init-01",
                "action_id": "act-for-rollback-01",
                "approved": True,
                "approver_reference": "OPERATOR_01",
                "approval_reason": "Approved initial action",
            },
        }
        res_exec = self.client.post("/api/v1/response/execute", json=exec_req)
        self.assertEqual(res_exec.status_code, 200)
        self.assertEqual(res_exec.json()["status"], ExecutionStatus.EXECUTED.value)

        # 2. Execute controlled rollback with human approval
        roll_req = {
            "action_id": "act-for-rollback-01",
            "target_node_id": "svc-api",
            "compensating_action_type": "RESTORE_CONNECTION",
            "approval": {
                "approval_id": "appr-roll-01",
                "action_id": "act-for-rollback-01",
                "approved": True,
                "approver_reference": "OPERATOR_01",
                "approval_reason": "Operator initiating rollback",
            },
            "reason": "Host restored to nominal baseline",
        }
        res_roll = self.client.post("/api/v1/response/rollback", json=roll_req)
        self.assertEqual(res_roll.status_code, 200)
        data_roll = res_roll.json()

        self.assertEqual(data_roll["status"], ExecutionStatus.ROLLED_BACK.value)
        self.assertTrue(data_roll["is_rollback"])
        self.assertTrue(data_roll["is_verified"])
        self.assertIn("Compensating action", data_roll["message"])


if __name__ == "__main__":
    unittest.main()
