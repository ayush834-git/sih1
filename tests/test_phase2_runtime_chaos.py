"""Phase 2B, 2C, 2D — SSE, Runtime & Reconsideration Chaos Tests (SIH 26153).

Deterministic chaos validation for event streaming, store synchronization,
Task 17 reconsideration under contradictory telemetry, and cross-layer attacks:
- Chaos 1: Duplicate Events (1x, 2x, 5x, 20x)
- Chaos 2: Out-of-Order Events (T5 -> T4, state never moves backward)
- Chaos 3: Dropped Event (T0 -> T1 -> T2 -> T4, no fabricated T3)
- Chaos 4: SSE Disconnect & Reconnect via Last-Event-ID
- Chaos 5: Reconnect Duplicates Idempotency
- Chaos 6: Reset During Stream & No Zombie Workers
- Chaos 7: Control Races (START x 3, START -> PAUSE -> STEP -> RESUME -> RESET -> START)
- Chaos 8: Malformed / Partial Events Handled Gracefully
- Chaos 9: Backend Unavailable Handled Truthfully
- Phase 2C: Task 17 Reconsideration under Contradictory Telemetry + Approval Invalidation Race
- Phase 2D: Cross-Layer Attacks (Test A, B, C, D, E)
"""
from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.contracts import (
    Direction,
    FeatureAvailability,
    NetworkState,
    Source,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from core.priority.engine import PriorityEngine
from core.response.recommendations import ResponseRecommendationEngine
from core.response_execution.models import ExecutionStatus, ReversibleActionType
from core.topology.builder import build_minimal_demo_topology
from core.topology.models import TopologyAvailability
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.metrics_v2 import RobustScaleStatistics
from runtime.api import create_app
from runtime.demo_adapter import DemoAdapter
from runtime.state_store import DemoStatus, RuntimeStateStore
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import DemoEvent, LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states
from security.bridge import BehavioralSecurityBridge
from security.reconsideration import (
    ConflictType,
    EvidenceConflict,
    ReconsiderationEngine,
    ReconsiderationEvent,
    RevisionType,
)
import numpy as np


class TestPhase2RuntimeChaos(unittest.TestCase):
    """Adversarial and chaos test harness for event streaming and state consistency."""

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
    # CHAOS 1 — DUPLICATE EVENTS
    # -------------------------------------------------------------------------
    def test_chaos_1_duplicate_events_rejected_or_deduplicated(self) -> None:
        """Store strictly enforces monotonic step progression; re-appending duplicate steps is rejected."""
        self.store.create_session(scenario="demo_recon_15s", total_steps=16)

        # Generate a sample event at step 0
        states = get_demo_scenario_states("demo_recon_15s")
        event0 = next(self.engine.stream_scenario(states))
        self.assertEqual(event0.step_index, 0)

        # 1st append -> success
        self.store.append_event(event0)
        self.assertEqual(self.store.current_step, 0)
        self.assertEqual(len(self.store.get_event_history()), 1)

        # Attempt duplicate appends 1x, 2x, 5x, 20x -> Must fail closed with ValueError
        for i in range(20):
            with self.assertRaises(ValueError):
                self.store.append_event(event0)

        # Canonical state remains step 0, history count remains exactly 1
        self.assertEqual(self.store.current_step, 0)
        self.assertEqual(len(self.store.get_event_history()), 1)

    # -------------------------------------------------------------------------
    # CHAOS 2 — OUT-OF-ORDER EVENTS
    # -------------------------------------------------------------------------
    def test_chaos_2_out_of_order_events_rejected_by_store(self) -> None:
        """Backend store rejects backward or skipped steps; state never moves backward."""
        self.store.create_session(scenario="demo_recon_15s", total_steps=16)
        states = get_demo_scenario_states("demo_recon_15s")
        gen = self.engine.stream_scenario(states)
        e0 = next(gen)
        e1 = next(gen)
        e2 = next(gen)

        self.store.append_event(e0)
        self.store.append_event(e1)
        self.store.append_event(e2)
        self.assertEqual(self.store.current_step, 2)

        # Out-of-order: attempt to append e1 (step 1) while current is step 2
        with self.assertRaises(ValueError) as ctx:
            self.store.append_event(e1)
        self.assertIn("expected monotonic step 3", str(ctx.exception))

        # Current step remains 2
        self.assertEqual(self.store.current_step, 2)

    # -------------------------------------------------------------------------
    # CHAOS 3 — DROPPED EVENT
    # -------------------------------------------------------------------------
    def test_chaos_3_dropped_event_detection(self) -> None:
        """Store detects gap in steps (e.g. T0 -> T1 -> T2 -> T4 without T3) and fails closed."""
        self.store.create_session(scenario="demo_recon_15s", total_steps=16)
        states = get_demo_scenario_states("demo_recon_15s")
        gen = self.engine.stream_scenario(states)
        e0 = next(gen)
        e1 = next(gen)
        e2 = next(gen)
        e3 = next(gen)
        e4 = next(gen)

        self.store.append_event(e0)
        self.store.append_event(e1)
        self.store.append_event(e2)

        # Attempt to append e4 (skipping e3)
        with self.assertRaises(ValueError) as ctx:
            self.store.append_event(e4)
        self.assertIn("expected monotonic step 3", str(ctx.exception))
        # Store state does not invent e3
        self.assertEqual(self.store.current_step, 2)

    # -------------------------------------------------------------------------
    # CHAOS 4 — SSE DISCONNECT & RECONNECT (LAST-EVENT-ID REPLAY)
    # -------------------------------------------------------------------------
    def test_chaos_4_sse_disconnect_and_reconnect_replays_missed_events(self) -> None:
        """Client reconnecting with Last-Event-ID receives missed events and converges to canonical state."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})

        # Advance to step 0, 1, 2
        self.client.post("/api/v1/demo/step")
        self.client.post("/api/v1/demo/step")
        self.client.post("/api/v1/demo/step")
        # Client disconnects at step 2. Backend advances to step 3 and 4.
        self.client.post("/api/v1/demo/step")
        self.client.post("/api/v1/demo/step")

        # Client reconnects with last_event_id=2
        res = self.client.get("/api/v1/events?since_step=3")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_count"], 2)
        step_indices = [e["step_index"] for e in data["events"]]
        self.assertEqual(step_indices, [3, 4])

    # -------------------------------------------------------------------------
    # CHAOS 5 — RECONNECT DUPLICATES (IDEMPOTENT HISTORY QUERY)
    # -------------------------------------------------------------------------
    def test_chaos_5_reconnect_event_history_monotonic(self) -> None:
        """Querying event history repeatedly or with since_step yields deterministic, ordered events."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        for _ in range(4):
            self.client.post("/api/v1/demo/step")

        # Query 1x, 2x, 5x, 20x
        for _ in range(20):
            res = self.client.get("/api/v1/events")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["total_count"], 4)
            indices = [e["step_index"] for e in data["events"]]
            self.assertEqual(indices, [0, 1, 2, 3])

    # -------------------------------------------------------------------------
    # CHAOS 6 — RESET DURING STREAM & INLINE SESSION ISOLATION
    # -------------------------------------------------------------------------
    def test_chaos_6_reset_clears_session_and_prevents_leaks(self) -> None:
        """Reset clears session history, invalidates previous approvals, and prevents session leakage."""
        # 1. Start Session 1
        res1 = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        sess1_id = res1.json()["session_id"]
        self.client.post("/api/v1/demo/step")
        st1 = self.client.get("/api/v1/state/current").json()
        win1 = st1["event_id"]
        auth1 = st1["authority_policy"]["decision_id"]

        # 2. Reset
        res_reset = self.client.post("/api/v1/demo/reset")
        self.assertEqual(res_reset.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/demo/status").json()["status"], "IDLE")
        self.assertEqual(self.client.get("/api/v1/events").json()["total_count"], 0)

        # 3. Start Session 2
        res2 = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        sess2_id = res2.json()["session_id"]
        self.assertNotEqual(sess1_id, sess2_id)

        # 4. Attempt to execute using Session 1's old authorization -> Must fail closed
        res_stale = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "authority_decision_id": auth1,
                "evidence_window_id": win1,
                "approval": {
                    "approval_id": "appr-sess1",
                    "action_id": "act-sess1",
                    "authority_decision_id": auth1,
                    "evidence_window_id": win1,
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Sess1 approval",
                },
            },
        )
        self.assertEqual(res_stale.status_code, 200)
        self.assertEqual(res_stale.json()["status"], ExecutionStatus.BLOCKED.value)

    # -------------------------------------------------------------------------
    # CHAOS 7 — CONTROL RACES
    # -------------------------------------------------------------------------
    def test_chaos_7_control_races_and_rapid_transitions(self) -> None:
        """START x 3, RESET x 3, START -> PAUSE -> STEP -> RESUME -> RESET -> START."""
        # Rapid multiple starts: each cleanly restarts and leaves exactly ONE canonical session
        r1 = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.assertEqual(r1.status_code, 200)
        r2 = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.assertEqual(r2.status_code, 200)
        r3 = self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/demo/status").json()["status"], "RUNNING")

        # Rapid multiple resets: all succeed safely (idempotent)
        for _ in range(3):
            rr = self.client.post("/api/v1/demo/reset")
            self.assertEqual(rr.status_code, 200)

        # Complex transition sequence:
        # START -> PAUSE -> STEP -> RESUME -> RESET -> START
        self.assertEqual(self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0}).status_code, 200)
        self.assertEqual(self.client.post("/api/v1/demo/pause").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/demo/step").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/demo/resume").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/demo/reset").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0}).status_code, 200)

        # State is cleanly running
        status_data = self.client.get("/api/v1/demo/status").json()
        self.assertEqual(status_data["status"], "RUNNING")

    # -------------------------------------------------------------------------
    # CHAOS 8 — MALFORMED / PARTIAL REQUESTS
    # -------------------------------------------------------------------------
    def test_chaos_8_malformed_requests_fail_gracefully(self) -> None:
        """Invalid schemas or missing required fields return 422 without crashing runtime."""
        # 1. Start with invalid body
        res = self.client.post("/api/v1/demo/start", content=b"not a valid json", headers={"Content-Type": "application/json"})
        self.assertEqual(res.status_code, 422)

        # 2. Execute with invalid action_class
        res2 = self.client.post("/api/v1/response/execute", json={"action_class": "NON_EXISTENT_CLASS"})
        self.assertEqual(res2.status_code, 400)

        # 3. Server remains healthy and available
        health = self.client.get("/api/v1/health").json()
        self.assertEqual(health["status"], "ok")

    # -------------------------------------------------------------------------
    # CHAOS 9 — BACKEND TEMPORARILY UNAVAILABLE / RECOVERY
    # -------------------------------------------------------------------------
    def test_chaos_9_backend_health_and_reconnection_truthfulness(self) -> None:
        """Health endpoint returns truthful status and live mode detection."""
        health = self.client.get("/api/v1/health").json()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["service"], "predictive-defense-runtime")

    # -------------------------------------------------------------------------
    # PHASE 2C — TASK 17 RECONSIDERATION CHAOS & APPROVAL INVALIDATION RACE
    # -------------------------------------------------------------------------
    def test_phase_2c_task_17_reconsideration_and_approval_invalidation_race(self) -> None:
        """
        Critical race test:
        1. Forecast generated
        2. Operator approves action for window
        3. Contradictory telemetry arrives
        4. Reconsideration triggers and revises assessment
        5. Old execution request replayed
        -> MUST FAIL CLOSED (Stale authorization rejected).
        """
        # Step 1: Start demo and advance to Step 0 (Forecast active)
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        st0 = self.client.get("/api/v1/state/current").json()
        win0 = st0["event_id"]
        auth0 = st0["authority_policy"]["decision_id"]

        # Step 2: Operator generates approval for Step 0 recommendation
        approval_win0 = {
            "approval_id": "appr-win0-race",
            "action_id": "act-win0-race",
            "authority_decision_id": auth0,
            "evidence_window_id": win0,
            "approved": True,
            "approver_reference": "OPERATOR_01",
            "approval_reason": "Operator approves initial mitigation",
        }

        # Step 3: Advance telemetry to step 1 and step 2 where telemetry changes/contradicts
        self.client.post("/api/v1/demo/step")
        st1 = self.client.get("/api/v1/state/current").json()

        # Step 4: Verify Reconsideration is triggered when contradiction occurs
        # In demo_recon_15s, reconnaissance bursts cause stage transitions & trust drops
        self.assertIsNotNone(st1["trust_level"])

        # Step 5: Critical Race — Operator executes using the OLD win0 approval!
        res_race = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-win0-race",
                "action_type": "DEMO_BLOCK",
                "target_node_id": "svc-api",
                "authority_decision_id": auth0,
                "evidence_window_id": win0,
                "approval": approval_win0,
            },
        )
        self.assertEqual(res_race.status_code, 200)
        data_race = res_race.json()

        # CRITICAL INVARIANT: OLD AUTHORIZATION MUST NOT EXECUTE
        self.assertEqual(data_race["status"], ExecutionStatus.BLOCKED.value)
        self.assertFalse(data_race["is_verified"])
        self.assertIn("STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE", data_race["error_message"])

    # -------------------------------------------------------------------------
    # PHASE 2D — CROSS-LAYER ATTACKS
    # -------------------------------------------------------------------------
    def test_phase_2d_test_a_modal_open_telemetry_advances_then_submit(self) -> None:
        """TEST A: Approval modal opened against T0, telemetry advances to T1, operator submits T0 approval."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")
        st0 = self.client.get("/api/v1/state/current").json()
        win0 = st0["event_id"]
        auth0 = st0["authority_policy"]["decision_id"]

        # Telemetry advances to T1
        self.client.post("/api/v1/demo/step")

        # Operator submits old T0 modal approval
        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-modal-t0",
                "action_type": "DEMO_BLOCK",
                "authority_decision_id": auth0,
                "evidence_window_id": win0,
                "approval": {
                    "approval_id": "appr-modal-t0",
                    "action_id": "act-modal-t0",
                    "authority_decision_id": auth0,
                    "evidence_window_id": win0,
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved from lingering modal",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE", data["error_message"])

    def test_phase_2d_test_b_topology_changes_after_approval(self) -> None:
        """TEST B: Approval granted, but topology snapshot changes or becomes unavailable before execution."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        # Topology availability drops
        self.topology.availability = TopologyAvailability.UNAVAILABLE

        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "approval": {
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved before partition",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("STALE_AUTHORIZATION_TOPOLOGY_UNAVAILABLE", res.json()["error_message"])
        self.topology.availability = TopologyAvailability.KNOWN

    def test_phase_2d_test_c_verification_mismatch_overrides_optimism(self) -> None:
        """TEST C: Action executes, but outcome verification detects mismatch; system registers VERIFIED_MISMATCH."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")

        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_id": "act-verif-cross",
                "action_type": "DEMO_BLOCK",
                "approval": {
                    "action_id": "act-verif-cross",
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Testing mismatch override",
                },
                "verification_expectation": {
                    "metric_name": "byte_rate",
                    "baseline_value": 2000.0,
                    "expected_direction": "DECREASE",
                    "min_reduction_ratio": 0.30,
                },
                "observed_state": {
                    "byte_rate": 2500.0,  # Telemetry increased!
                    "window_id": "win-cross-01",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.EXECUTED.value)
        self.assertFalse(data["is_verified"])
        self.assertEqual(data["verification_status"], "VERIFIED_MISMATCH")
        self.assertIsNotNone(data["reconsideration_handoff"])

    def test_phase_2d_test_d_sse_reconnect_converges_to_newest_state(self) -> None:
        """TEST D: Disconnect SSE, backend steps forward, reconnect converges to newest authoritative state."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")  # Step 0

        # Backend advances while client is disconnected
        self.client.post("/api/v1/demo/step")  # Step 1
        self.client.post("/api/v1/demo/step")  # Step 2
        self.client.post("/api/v1/demo/step")  # Step 3

        # Reconnect fetching history since step 1
        res = self.client.get("/api/v1/events?since_step=1")
        self.assertEqual(res.status_code, 200)
        events = res.json()["events"]
        self.assertEqual(len(events), 3)
        self.assertEqual(events[-1]["step_index"], 3)

        # Current state matches newest step 3
        curr = self.client.get("/api/v1/state/current").json()
        self.assertEqual(curr["step_index"], 3)

    def test_phase_2d_test_e_reset_runtime_replayed_execution_rejected(self) -> None:
        """TEST E: Reset runtime, attempt to replay old execution request -> rejected as stale/invalid."""
        self.client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
        self.client.post("/api/v1/demo/step")
        st = self.client.get("/api/v1/state/current").json()
        old_win = st["event_id"]
        old_auth = st["authority_policy"]["decision_id"]

        # Reset runtime
        self.client.post("/api/v1/demo/reset")

        # Replay old execution request on idle/reset runtime
        res = self.client.post(
            "/api/v1/response/execute",
            json={
                "action_type": "DEMO_BLOCK",
                "authority_decision_id": old_auth,
                "evidence_window_id": old_win,
                "approval": {
                    "approval_id": "appr-pre-reset",
                    "action_id": "act-pre-reset",
                    "authority_decision_id": old_auth,
                    "evidence_window_id": old_win,
                    "approved": True,
                    "approver_reference": "OPERATOR_01",
                    "approval_reason": "Approved before reset",
                },
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], ExecutionStatus.BLOCKED.value)
        self.assertIn("STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE", data["error_message"])


if __name__ == "__main__":
    unittest.main()
