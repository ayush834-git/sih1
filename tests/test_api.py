"""Comprehensive tests for FastAPI runtime server endpoints (SIH 26153)."""
from __future__ import annotations

import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from core.topology.builder import build_minimal_demo_topology
from runtime.api import create_app
from runtime.demo_adapter import DemoAdapter
from runtime.state_store import RuntimeStateStore
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine


class ApiServerTests(unittest.TestCase):
    def setUp(self) -> None:
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, scales = load_ar_model(model_dir)
        self.engine = LiveDemoEngine(ar_model=ar_model, scales=scales, topology=build_minimal_demo_topology())
        self.store = RuntimeStateStore(max_history_size=500)
        self.adapter = DemoAdapter(engine=self.engine, store=self.store, base_step_delay=0.01)
        self.app = create_app(adapter=self.adapter)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.post("/api/v1/demo/reset")

    def test_1_health_endpoint(self) -> None:
        res = self.client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "predictive-defense-runtime")
        self.assertEqual(data["runtime"], "available")

    def test_2_initial_demo_status(self) -> None:
        res = self.client.get("/api/v1/demo/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "IDLE")
        self.assertEqual(data["current_step"], -1)
        self.assertEqual(data["total_steps"], 0)
        self.assertEqual(data["history_count"], 0)

    def test_3_start_demo_and_verify_status(self) -> None:
        res = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "RUNNING")
        self.assertEqual(data["scenario"], "demo_recon_15s")
        self.assertEqual(data["total_steps"], 16)
        self.assertTrue(data["session_id"].startswith("sess-"))

        # Verify status endpoint agrees
        st_res = self.client.get("/api/v1/demo/status")
        self.assertEqual(st_res.status_code, 200)
        st_data = st_res.json()
        self.assertEqual(st_data["session_id"], data["session_id"])
        self.assertEqual(st_data["status"], "RUNNING")
        self.assertEqual(st_data["current_step"], -1)

    def test_4_current_state_before_and_after_step(self) -> None:
        # Before step
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        s0_res = self.client.get("/api/v1/state/current")
        self.assertEqual(s0_res.status_code, 200)
        s0_data = s0_res.json()
        self.assertFalse(s0_data["has_event"])

        # Advance step 0
        step_res = self.client.post("/api/v1/demo/step")
        self.assertEqual(step_res.status_code, 200)
        step_data = step_res.json()
        self.assertTrue(step_data["has_event"])
        self.assertEqual(step_data["step_index"], 0)
        self.assertEqual(step_data["logical_time"], "T00 (000s)")

        # Verify current state endpoint matches step
        s1_res = self.client.get("/api/v1/state/current")
        self.assertEqual(s1_res.status_code, 200)
        s1_data = s1_res.json()
        self.assertTrue(s1_data["has_event"])
        self.assertEqual(s1_data["step_index"], 0)
        self.assertIn("dst_port_diversity", s1_data["features"])

    def test_5_forecast_endpoint(self) -> None:
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        fc_res = self.client.get("/api/v1/forecast/current")
        self.assertEqual(fc_res.status_code, 200)
        fc_data = fc_res.json()
        self.assertEqual(fc_data["step_index"], 0)
        self.assertEqual(fc_data["model_name"], "B4_AR_best(p=5)")
        self.assertIn("dst_port_diversity_delta", fc_data["predicted_deltas_h1"])
        self.assertIn("+10s", fc_data["future_risk_scores"])
        self.assertIsInstance(fc_data["forecast_feature_contributions"], list)

    def test_6_security_endpoint(self) -> None:
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        # Advance to T07 (Reconnaissance)
        for _ in range(8):
            self.client.post("/api/v1/demo/step")

        sec_res = self.client.get("/api/v1/security/current")
        self.assertEqual(sec_res.status_code, 200)
        sec_data = sec_res.json()
        self.assertEqual(sec_data["step_index"], 7)
        self.assertEqual(sec_data["primary_stage"], "Reconnaissance")
        self.assertGreater(len(sec_data["active_signatures"]), 0)
        self.assertIn("supporting_evidence", sec_data["security_explanation"])

    def test_7_decision_endpoint(self) -> None:
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        dec_res = self.client.get("/api/v1/decision/current")
        self.assertEqual(dec_res.status_code, 200)
        dec_data = dec_res.json()
        self.assertEqual(dec_data["step_index"], 0)
        self.assertTrue(dec_data["requires_human"])
        self.assertTrue(dec_data["is_reversible"])
        self.assertIn("relevant_roles", dec_data)
        self.assertIn("recommended_actions", dec_data)

    def test_8_history_endpoint_and_filtering(self) -> None:
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        for _ in range(5):
            self.client.post("/api/v1/demo/step")

        # Full history
        h_res = self.client.get("/api/v1/events")
        self.assertEqual(h_res.status_code, 200)
        h_data = h_res.json()
        self.assertEqual(h_data["total_count"], 5)
        self.assertEqual(len(h_data["events"]), 5)

        # Filter since step 2
        f_res = self.client.get("/api/v1/events?since_step=2")
        self.assertEqual(f_res.status_code, 200)
        f_data = f_res.json()
        self.assertEqual(f_data["total_count"], 3)
        self.assertEqual(f_data["events"][0]["step_index"], 2)

        # Limit to 2
        l_res = self.client.get("/api/v1/events?limit=2")
        self.assertEqual(l_res.status_code, 200)
        l_data = l_res.json()
        self.assertEqual(l_data["total_count"], 2)

    def test_9_pause_resume_and_reset(self) -> None:
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})

        # Pause
        p_res = self.client.post("/api/v1/demo/pause")
        self.assertEqual(p_res.status_code, 200)
        self.assertEqual(p_res.json()["status"], "PAUSED")

        # Resume
        r_res = self.client.post("/api/v1/demo/resume")
        self.assertEqual(r_res.status_code, 200)
        self.assertEqual(r_res.json()["status"], "RUNNING")

        # Reset
        res_res = self.client.post("/api/v1/demo/reset")
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["status"], "IDLE")

        st_res = self.client.get("/api/v1/demo/status")
        self.assertEqual(st_res.json()["status"], "IDLE")

    def test_10_error_handling(self) -> None:
        # Unknown scenario -> 400
        bad_sc_res = self.client.post("/api/v1/demo/start", json={"scenario": "non_existent_scenario"})
        self.assertEqual(bad_sc_res.status_code, 400)

        # Pause while IDLE -> 409
        bad_pause = self.client.post("/api/v1/demo/pause")
        self.assertEqual(bad_pause.status_code, 409)

        # Step while IDLE -> 409
        bad_step = self.client.post("/api/v1/demo/step")
        self.assertEqual(bad_step.status_code, 409)

        # Negative limit query -> 422
        bad_limit = self.client.get("/api/v1/events?limit=0")
        self.assertEqual(bad_limit.status_code, 422)

    def test_11_end_to_end_pipeline_integration(self) -> None:
        """E2E flow verifying real model, explainability, decision, and state progression."""
        # 1. Start demo
        start_res = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.assertEqual(start_res.status_code, 200)

        # 2. Advance 8 steps to peak attack
        for step in range(8):
            s_res = self.client.post("/api/v1/demo/step")
            self.assertEqual(s_res.status_code, 200)
            self.assertEqual(s_res.json()["step_index"], step)

        # 3. Read current state
        state_res = self.client.get("/api/v1/state/current")
        self.assertEqual(state_res.status_code, 200)
        state = state_res.json()
        self.assertEqual(state["step_index"], 7)
        self.assertEqual(state["primary_stage"], "Reconnaissance")
        self.assertGreater(state["current_risk_score"], 0.1)

        # 4. Verify explainability and forecast in state
        self.assertGreater(len(state["forecast_feature_contributions"]), 0)
        self.assertIn("primary_stage", state["security_explanation"])

        # 5. Read history
        hist_res = self.client.get("/api/v1/events")
        self.assertEqual(hist_res.status_code, 200)
        self.assertEqual(hist_res.json()["total_count"], 8)

    def test_12_speed_endpoint(self) -> None:
        """Verify dynamic speed adjustment endpoint."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 1.0})
        res = self.client.post("/api/v1/demo/speed", json={"speed": 2.5})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["speed"], 2.5)

        # Verify status endpoint reflects updated speed
        st_res = self.client.get("/api/v1/demo/status")
        self.assertEqual(st_res.status_code, 200)
        self.assertEqual(st_res.json()["speed"], 2.5)

    def test_13_response_execute_destructive_action_permanently_blocked(self) -> None:
        """Verify destructive actions are permanently blocked by ResponseExecutor."""
        payload = {
            "action_type": "DESTRUCTIVE_WIPE",
            "action_class": "EXECUTE_DESTRUCTIVE_ACTION",
            "target_node_id": "GATEWAY_NODE_4",
        }
        res = self.client.post("/api/v1/response/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "BLOCKED")
        self.assertIn("permanently prohibited", data["message"])
        self.assertFalse(data["is_verified"])

    def test_14_response_execute_requires_human_approval(self) -> None:
        """Verify executing without mandatory human approval fails closed (BLOCKED)."""
        payload = {
            "action_type": "DEMO_BLOCK",
            "action_class": "EXECUTE_REVERSIBLE_ACTION",
            "target_node_id": "GATEWAY_NODE_4",
            # No approval payload provided
        }
        res = self.client.post("/api/v1/response/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "BLOCKED")
        self.assertIn("Human approval required but missing", data["message"])

    def test_15_response_execute_with_human_approval_succeeds(self) -> None:
        """Verify approved reversible action succeeds and is verified when authorized."""
        # Start demo and advance to step 0 (baseline with high trust & confidence)
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        st = self.client.get("/api/v1/state/current").json()
        event_id = st.get("event_id") or "window-step-0"
        auth_dec_id = st.get("authority_policy", {}).get("decision_id") if st.get("authority_policy") else "dec-test"

        payload = {
            "action_type": "TEMP_RATE_LIMIT",
            "action_class": "EXECUTE_REVERSIBLE_ACTION",
            "target_node_id": "svc-api",
            "authority_decision_id": auth_dec_id,
            "evidence_window_id": event_id,
            "approval": {
                "approval_id": "appr-001",
                "approved": True,
                "approver_reference": "ANALYST_01",
                "approval_reason": "Observed reconnaissance progression exceeding risk threshold",
            },
        }
        res = self.client.post("/api/v1/response/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "EXECUTED")
        self.assertTrue(data["is_verified"])
        self.assertEqual(data["verification_status"], "VERIFIED_SUCCESS")

        # History endpoint shows recorded execution
        hist_res = self.client.get("/api/v1/response/history")
        self.assertEqual(hist_res.status_code, 200)
        records = hist_res.json()
        self.assertGreater(len(records), 0)
        self.assertEqual(records[-1]["action_id"], data["action_id"])

    def test_16_response_execute_stale_authorization_blocked(self) -> None:
        """Verify that if evidence window has advanced, stale authorization is blocked."""
        # Start demo and advance to step 0
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        st1 = self.client.get("/api/v1/state/current").json()
        event_id_1 = st1.get("event_id") or "window-0"
        auth_dec_1 = st1.get("authority_policy", {}).get("decision_id") if st1.get("authority_policy") else "dec-1"

        # Advance window to next step (step 1)
        self.client.post("/api/v1/demo/step")

        # Now attempt to execute using old stale event_id_1 from step 0
        payload = {
            "action_type": "TEMP_RATE_LIMIT",
            "action_class": "EXECUTE_REVERSIBLE_ACTION",
            "target_node_id": "svc-api",
            "authority_decision_id": auth_dec_1,
            "evidence_window_id": event_id_1,  # STALE!
            "approval": {
                "approval_id": "appr-002",
                "approved": True,
                "approver_reference": "ANALYST_01",
                "approval_reason": "Stale approval test",
            },
        }
        res = self.client.post("/api/v1/response/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "BLOCKED")
        self.assertIn("superseded by new evidence", data["message"].lower())


if __name__ == "__main__":
    unittest.main()
